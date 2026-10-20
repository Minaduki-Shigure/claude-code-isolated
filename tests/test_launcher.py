"""Regression checks for host boundaries; no Docker daemon or image is used."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

REPOSITORY = Path(__file__).resolve().parents[1]
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
            REPOSITORY / "config/managed-settings.json",
            self.root / "config/managed-settings.json",
        )
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.settings = self.root / "settings.json"
        self.settings.write_text("{}")
        self.policy = self.root / "policy.json"
        self.policy.write_text("{}")
        self.key = self.root / "api-key"
        self.key.write_text("dummy-test-key")
        self.config = dict(launcher.DEFAULTS, WORKSPACE=str(self.workspace),
                           ANTHROPIC_BASE_URL="https://model.example.com",
                           MODEL_API_KEY_FILE=str(self.key),
                           SETTINGS_FILE=str(self.settings),
                           GATEWAY_POLICY_FILE=str(self.policy))
        self.root_patch = mock.patch.object(launcher, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def test_settings_cannot_redirect_state_or_disable_transport_boundaries(self):
        for name, value in (
            ("HOME", "/workspace"), ("CLAUDE_CONFIG_DIR", "/workspace/sessions"),
            ("XDG_STATE_HOME", "/workspace/state"), ("http_proxy", "http://elsewhere:80"),
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

    def test_sensitive_paths_inside_workspace_are_rejected_including_symlinks(self):
        inside = self.workspace / "private.json"
        inside.write_text("{}")
        link = self.root / "looks-outside.json"
        link.symlink_to(inside)
        for key in ("MODEL_API_KEY_FILE", "SETTINGS_FILE", "GATEWAY_POLICY_FILE"):
            for path in (inside, link):
                with self.subTest(key=key, path=path):
                    config = dict(self.config, **{key: str(path)})
                    with self.assertRaisesRegex(ValueError, "outside WORKSPACE"):
                        launcher.validate(config)

    def exercise_launch(self, fail_cleanup=False):
        calls, launched = [], []
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
            return mock.Mock(wait=mock.Mock(return_value=0), poll=mock.Mock(return_value=0))

        with (
            mock.patch.object(launcher, "read_config", return_value=dict(self.config)),
            mock.patch.object(launcher, "image_record", return_value=("sha256:" + "b" * 64, labels)),
            mock.patch.object(launcher.subprocess, "run", side_effect=fake_run),
            mock.patch.object(launcher.subprocess, "Popen", side_effect=fake_process),
            mock.patch.object(launcher.signal, "signal"),
            mock.patch.object(launcher.sys, "argv", ["claude-docker.py", "--pull", "never"]),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            if fail_cleanup:
                with self.assertRaisesRegex(RuntimeError, "Inspect only this project"):
                    launcher.main()
            else:
                self.assertEqual(launcher.main(), 0)
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

    def test_failed_cleanup_keeps_private_recovery_metadata(self):
        self.exercise_launch(fail_cleanup=True)
        sessions = list((self.root / ".run").iterdir())
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0].stat().st_mode & 0o777, 0o700)
        self.assertRegex((sessions[0] / "project.txt").read_text(), r"^cc-isolated-[0-9a-f]{12}\n$")


if __name__ == "__main__":
    unittest.main()
