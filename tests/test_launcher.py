"""Regression checks for host boundaries; no Docker daemon or image is used."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "launcher", REPOSITORY / "scripts/claude-docker.py"
)
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)


class LauncherBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="claude-launcher-test-")
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name).resolve()
        self.root = self.base / "deployment"
        (self.root / "scripts").mkdir(parents=True)
        (self.root / "config").mkdir()
        shutil.copyfile(
            REPOSITORY / "scripts/runtime-entrypoint.py",
            self.root / "scripts/runtime-entrypoint.py",
        )
        shutil.copyfile(
            REPOSITORY / "scripts/startup_config.py",
            self.root / "scripts/startup_config.py",
        )
        shutil.copyfile(
            REPOSITORY / "config/managed-settings.json",
            self.root / "config/managed-settings.json",
        )
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.settings = self.root / "settings.json"
        self.settings.write_text("{}")
        self.policy = self.root / "policy.json"
        self.policy.write_text("{}")
        self.startup = self.root / "startup.json"
        self.startup.write_text(json.dumps({"schemaVersion": 1, "trustedWorkspaces": [],
                                           "approvedCredentials": []}))
        self.key = self.root / "api-key"
        self.key.write_text("dummy-test-key")
        self.config = dict(launcher.DEFAULTS, WORKSPACE=str(self.workspace),
                           ANTHROPIC_BASE_URL="https://model.example.com",
                           MODEL_API_KEY_FILE=str(self.key),
                           SETTINGS_FILE=str(self.settings),
                           GATEWAY_POLICY_FILE=str(self.policy),
                           STARTUP_CONFIG_FILE=str(self.startup))
        self.root_patch = mock.patch.object(launcher, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def test_settings_cannot_redirect_state_or_disable_transport_boundaries(self):
        for name, value in (
            ("HOME", "/workspace"), ("CLAUDE_CONFIG_DIR", "/workspace/sessions"),
            ("XDG_STATE_HOME", "/workspace/state"), ("http_proxy", "http://elsewhere:80"),
            ("TZ", "Asia/Tokyo"),
            ("NODE_TLS_REJECT_UNAUTHORIZED", "0"), ("OTEL_EXPORTER_OTLP_ENDPOINT", "https://elsewhere"),
        ):
            with self.subTest(name=name):
                self.settings.write_text(json.dumps({"env": {name: value}}))
                with self.assertRaisesRegex(ValueError, "cannot override"):
                    launcher.validate(dict(self.config))

    def test_env_command_substitution_is_literal_and_never_executed(self):
        marker = self.base / "must-not-exist"
        for payload in (f"$(touch {marker})", f"`touch {marker}`"):
            with self.subTest(payload=payload):
                env_file = self.root / ".env"
                env_file.write_text(f"ANTHROPIC_MODEL='{payload}'\n")
                with mock.patch.dict(os.environ, {}, clear=True):
                    config = launcher.read_config(env_file)
                self.assertEqual(config["ANTHROPIC_MODEL"], payload)
                self.assertFalse(marker.exists())

    def test_timezone_defaults_to_los_angeles_and_can_be_configured(self):
        env_file = self.root / ".env"
        env_file.write_text("")
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(launcher.read_config(env_file)["TZ"], "America/Los_Angeles")
        env_file.write_text("TZ=UTC\n")
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(launcher.read_config(env_file)["TZ"], "UTC")
        with mock.patch.dict(os.environ, {"TZ": "Asia/Tokyo"}, clear=True):
            self.assertEqual(launcher.read_config(env_file)["TZ"], "Asia/Tokyo")

    def test_invalid_timezone_is_rejected_before_containers_start(self):
        for timezone in ("", "Mars/Olympus", "../etc/passwd", "/etc/passwd"):
            with self.subTest(timezone=timezone):
                with self.assertRaises(ValueError):
                    launcher.validate(dict(self.config, TZ=timezone))

    def test_resource_defaults_and_literal_overrides(self):
        expected = {
            "CLAUDE_MEMORY_LIMIT": "8g", "CLAUDE_PIDS_LIMIT": "1024",
            "CLAUDE_SHM_SIZE": "1g", "CLAUDE_HOME_TMPFS_SIZE": "2g",
            "CLAUDE_TMP_TMPFS_SIZE": "2g",
        }
        env_file = self.root / ".env"
        env_file.write_text("")
        with mock.patch.dict(os.environ, {}, clear=True):
            config = launcher.read_config(env_file)
        self.assertEqual({key: config[key] for key in expected}, expected)
        env_file.write_text("CLAUDE_MEMORY_LIMIT=8192M\nCLAUDE_PIDS_LIMIT=768\n")
        with mock.patch.dict(os.environ, {"CLAUDE_SHM_SIZE": "512m"}, clear=True):
            config = launcher.read_config(env_file)
        launcher.validate_resources(config)
        self.assertEqual(config["CLAUDE_MEMORY_LIMIT"], "8192m")
        self.assertEqual(config["CLAUDE_PIDS_LIMIT"], "768")
        self.assertEqual(config["CLAUDE_SHM_SIZE"], "512m")

    def test_invalid_or_unlimited_resource_values_rejected(self):
        for key in ("CLAUDE_MEMORY_LIMIT", "CLAUDE_SHM_SIZE",
                    "CLAUDE_HOME_TMPFS_SIZE", "CLAUDE_TMP_TMPFS_SIZE"):
            for value in ("", "0", "-1", "0g", "1.5g", "8gb", "50%", "8 g",
                          "8g,exec", "1g\n", "$(id)", "9999999999g"):
                with self.subTest(key=key, value=value):
                    with self.assertRaises(ValueError):
                        launcher.validate(dict(self.config, **{key: value}))
        for value in ("", "0", "-1", "1.5", "1024,foo", "1024\n", "65537"):
            with self.subTest(pids=value):
                with self.assertRaises(ValueError):
                    launcher.validate(dict(self.config, CLAUDE_PIDS_LIMIT=value))

    def test_tmpfs_and_shm_cannot_individually_exceed_memory_budget(self):
        for key in ("CLAUDE_SHM_SIZE", "CLAUDE_HOME_TMPFS_SIZE", "CLAUDE_TMP_TMPFS_SIZE"):
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, "must not exceed"):
                    launcher.validate(dict(self.config, **{key: "9g"}))
        # Independent upper bounds are not preallocated or added to the cgroup cap.
        self.assertEqual(launcher.validate(dict(self.config))["CLAUDE_MEMORY_LIMIT"], "8g")

    def test_sensitive_paths_inside_workspace_are_rejected_including_symlinks(self):
        inside = self.workspace / "private.json"
        inside.write_text("{}")
        link = self.root / "looks-outside.json"
        link.symlink_to(inside)
        for key in ("MODEL_API_KEY_FILE", "SETTINGS_FILE", "GATEWAY_POLICY_FILE",
                    "STARTUP_CONFIG_FILE"):
            for path in (inside, link):
                with self.subTest(key=key, path=path):
                    config = dict(self.config, **{key: str(path)})
                    with self.assertRaisesRegex(ValueError, "outside WORKSPACE"):
                        launcher.validate(config)

    def exercise_launch(self, fail_cleanup=False, remember=False, selection=None,
                        collection_error=False, remember_permission=False,
                        remember_ultracode=False):
        calls, launched = [], []
        original_preferences = json.loads(self.startup.read_text())
        remembering = remember or remember_permission or remember_ultracode
        if remembering:
            original_preferences.update(model="previous-model", effort="max",
                                        permissionMode="auto", ultracode=True,
                                        trustedWorkspaces=[str(self.workspace)])
            if remember:
                original_preferences["rememberModelEffort"] = True
            if remember_permission:
                original_preferences["rememberPermissionMode"] = True
            if remember_ultracode:
                original_preferences["rememberUltracode"] = True
            self.startup.write_text(json.dumps(original_preferences))
        labels = {
            "org.opencontainers.image.version": "2.1.304",
            "org.opencontainers.image.revision": "a" * 40,
            "org.opencontainers.image.created": "2026-10-20T00:00:00Z",
        }

        def fake_run(args, **kwargs):
            self.assertFalse(kwargs.get("shell", False))
            calls.append(list(args))
            result = "owned-cli-id\n" if args[:3] == ["docker", "ps", "-aq"] else ""
            status = int(fail_cleanup and "down" in args)
            return subprocess.CompletedProcess(args, status, stdout=result, stderr="")

        def fake_process(args, **kwargs):
            self.assertFalse(kwargs.get("shell", False))
            launched.append(list(args))
            staged = Path(kwargs["env"]["MODEL_API_KEY_FILE"])
            self.assertEqual(staged.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(staged.parent.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(staged.read_text(), "dummy-test-key")
            startup_path = Path(kwargs["env"]["STARTUP_STATE_FILE"])
            self.assertEqual(startup_path.parent, staged.parent)
            self.assertNotEqual(startup_path, self.startup)
            expected = {"trustWorkspace": remembering, "approveApiKey": False}
            if remembering:
                expected.update(model="previous-model", effort="max",
                                permissionMode="auto", ultracode=True)
            if remember:
                expected["rememberModelEffort"] = True
            if remember_permission:
                expected["rememberPermissionMode"] = True
            if remember_ultracode:
                expected["rememberUltracode"] = True
            self.assertEqual(json.loads(startup_path.read_text()), expected)
            return mock.Mock(wait=mock.Mock(return_value=0), poll=mock.Mock(return_value=0))

        with (
            mock.patch.object(launcher, "read_config", return_value=dict(self.config)),
            mock.patch.object(launcher, "image_record", return_value=("sha256:" + "b" * 64, labels)),
            mock.patch.object(launcher.subprocess, "run", side_effect=fake_run),
            mock.patch.object(launcher.subprocess, "Popen", side_effect=fake_process),
            mock.patch.object(launcher.signal, "signal"),
            mock.patch.object(launcher, "collect_selection", return_value=selection,
                              side_effect=ValueError("invalid exported selection")
                              if collection_error else None) as collect,
            mock.patch.object(launcher.sys, "argv", ["claude-docker.py", "--pull", "never"]),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            if fail_cleanup:
                with self.assertRaisesRegex(RuntimeError, "Inspect only this project"):
                    launcher.main()
            elif collection_error:
                with self.assertRaisesRegex(RuntimeError, "Could not save .*preferences"):
                    launcher.main()
            else:
                self.assertEqual(launcher.main(), 0)
        expected = dict(original_preferences)
        if remembering:
            collect.assert_called_once()
            if selection is not None:
                if remember:
                    expected["model"] = selection["model"]
                    if "effort" in selection:
                        expected["effort"] = selection["effort"]
                    else:
                        expected.pop("effort", None)
                if remember_permission and "permissionMode" in selection:
                    expected["permissionMode"] = selection["permissionMode"]
                if remember_ultracode and "ultracode" in selection:
                    expected["ultracode"] = selection["ultracode"]
        else:
            collect.assert_not_called()
        self.assertEqual(json.loads(self.startup.read_text()), expected)
        return calls, launched

    def test_cleanup_uses_unique_project_and_exact_name_and_label(self):
        projects = []
        for _ in range(2):
            calls, launched = self.exercise_launch()
            ps = next(args for args in calls if args[:3] == ["docker", "ps", "-aq"])
            label = next(arg for arg in ps if arg.startswith("label="))
            project = label.split("=", 2)[2]
            projects.append(project)
            self.assertRegex(project, r"^cc-isolated-[0-9a-f]{12}$")
            self.assertIn("name=^/" + project + "-cli$", ps)
            self.assertIn(["docker", "rm", "-f", "owned-cli-id"], calls)
            down = next(args for args in calls if "down" in args)
            self.assertEqual(down[down.index("--project-name") + 1], project)
            self.assertIn("--volumes", down)
            self.assertIn("--remove-orphans", down)
            self.assertTrue(all(args[args.index("--project-name") + 1] == project for args in launched))
            self.assertFalse(list((self.root / ".run").iterdir()))
        self.assertNotEqual(*projects)

    def test_remembered_selection_is_saved_and_temporary_resources_are_removed(self):
        selection = {"model": "chosen-model", "effort": "low"}
        calls, _ = self.exercise_launch(remember=True, selection=selection)
        preferences = json.loads(self.startup.read_text())
        self.assertEqual(preferences["model"], selection["model"])
        self.assertEqual(preferences["effort"], selection["effort"])
        self.assertEqual(preferences["trustedWorkspaces"], [str(self.workspace)])
        self.assertEqual(preferences["approvedCredentials"], [])
        self.assertEqual(self.startup.stat().st_mode & 0o777, 0o600)
        down = next(args for args in calls if "down" in args)
        self.assertIn("--volumes", down)
        self.assertFalse(list((self.root / ".run").iterdir()))

    def test_rejected_selection_preserves_preferences_and_still_cleans_resources(self):
        calls, _ = self.exercise_launch(remember=True, collection_error=True)
        preferences = json.loads(self.startup.read_text())
        self.assertEqual(preferences["model"], "previous-model")
        self.assertEqual(preferences["effort"], "max")
        self.assertTrue(any("down" in args and "--volumes" in args for args in calls))
        self.assertFalse(list((self.root / ".run").iterdir()))

    def test_permission_and_ultracode_memory_work_without_model_memory(self):
        selection = {"model": "another-model", "effort": "low",
                     "permissionMode": "plan", "ultracode": False}
        calls, _ = self.exercise_launch(remember_permission=True, remember_ultracode=True,
                                       selection=selection)
        preferences = json.loads(self.startup.read_text())
        self.assertEqual(preferences["model"], "previous-model")
        self.assertEqual(preferences["effort"], "max")
        self.assertEqual(preferences["permissionMode"], "plan")
        self.assertIs(preferences["ultracode"], False)
        self.assertEqual(preferences["trustedWorkspaces"], [str(self.workspace)])
        self.assertTrue(any("down" in args and "--volumes" in args for args in calls))
        self.assertFalse(list((self.root / ".run").iterdir()))

    def test_failed_cleanup_keeps_private_recovery_metadata(self):
        self.exercise_launch(fail_cleanup=True)
        sessions = list((self.root / ".run").iterdir())
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0].stat().st_mode & 0o777, 0o700)
        self.assertRegex((sessions[0] / "project.txt").read_text(), r"^cc-isolated-[0-9a-f]{12}\n$")


if __name__ == "__main__":
    unittest.main()
