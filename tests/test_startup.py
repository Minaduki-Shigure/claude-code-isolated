"""Approval identity and disposable-state boundaries; no Docker or real keys."""
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
from types import SimpleNamespace
from unittest import mock
from pathlib import Path
import tempfile
import unittest

REPOSITORY = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "startup_config", REPOSITORY / "scripts/startup_config.py"
)
startup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(startup)


class StartupBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="claude-startup-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.path = self.root / "startup.json"
        self.key = "fixture-only-full-key-12345678901234567890"
        self.endpoint = "https://model.example.test/api"
        self.preferences = {
            "schemaVersion": 1,
            "trustedWorkspaces": [str(self.workspace)],
            "approvedCredentials": [{
                "baseUrl": self.endpoint,
                "authMode": "api-key",
                "keySha256": hashlib.sha256(self.key.encode()).hexdigest(),
            }],
            "permissionMode": "auto",
            "effort": "max",
            "ultracode": True,
        }

    def read(self, preferences):
        self.path.write_text(json.dumps(preferences))
        return startup.read_preferences(self.path)

    def resolve(self, preferences=None, **changes):
        values = dict(workspace=str(self.workspace), base_url=self.endpoint,
                      auth_mode="api-key", key=self.key)
        values.update(changes)
        return startup.resolve_startup(
            self.read(self.preferences if preferences is None else preferences), **values
        )

    def test_matching_identity_seeds_only_the_documented_state(self):
        state = self.resolve()
        self.assertEqual(state, {
            "trustWorkspace": True, "approveApiKey": True,
            "permissionMode": "auto", "effort": "max", "ultracode": True,
        })
        startup.validate_state(state)
        rendered = json.dumps(state)
        for private in (str(self.workspace), self.key, self.endpoint,
                        self.preferences["approvedCredentials"][0]["keySha256"]):
            self.assertNotIn(private, rendered)

    def test_workspace_trust_is_exact_and_never_inherited(self):
        child = self.workspace / "child"
        child.mkdir()
        sibling = self.root / "workspace-elsewhere"
        sibling.mkdir()
        for target in (child, sibling, self.root):
            with self.subTest(target=target):
                state = self.resolve(workspace=str(target))
                self.assertFalse(state["trustWorkspace"])
                self.assertTrue(state["approveApiKey"])

    def test_credential_approval_requires_endpoint_mode_and_full_key(self):
        changes = (
            {"base_url": "https://another.example.test/api"},
            {"base_url": "https://model.example.test/other-api"},
            {"base_url": self.endpoint + "/"},
            {"base_url": self.endpoint + "//"},
            {"auth_mode": "bearer"},
            # Claude stores a suffix internally; host approval must use full SHA256.
            {"key": "different-prefix-" + self.key[-20:]},
        )
        for change in changes:
            with self.subTest(change=list(change)):
                state = self.resolve(**change)
                self.assertFalse(state["approveApiKey"])
                self.assertTrue(state["trustWorkspace"])

    def test_no_approval_records_never_skip_prompts(self):
        state = self.resolve({"schemaVersion": 1, "trustedWorkspaces": [],
                              "approvedCredentials": []})
        self.assertFalse(state["trustWorkspace"])
        self.assertFalse(state["approveApiKey"])
        self.assertNotIn("permissionMode", state)
        self.assertNotIn("effort", state)
        self.assertNotIn("ultracode", state)

    def test_host_preferences_reject_unknown_fields_and_unsafe_types(self):
        invalid = (
            {"schemaVersion": True}, {"schemaVersion": 2},
            {"trustedWorkspaces": "*"}, {"trustedWorkspaces": ["relative/path"]},
            {"trustedWorkspaces": [False]}, {"approvedCredentials": {}},
            {"permissionMode": "bypassPermissions"}, {"permissionMode": True},
            {"effort": "ultracode"}, {"effort": 5},
            {"ultracode": "true"}, {"ultracode": 1},
            {"CLAUDE_CONFIG_DIR": "/workspace/state"}, {"projects": {}},
            {"env": {"HOME": "/workspace"}}, {"sessions": []},
        )
        for change in invalid:
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    self.read(dict(self.preferences, **change))

    def test_credential_records_have_strict_schema_and_digest(self):
        valid = self.preferences["approvedCredentials"][0]
        invalid = (
            dict(valid, keySha256="x" * 64), dict(valid, keySha256="a" * 63),
            dict(valid, keySha256=True), dict(valid, authMode="oauth"),
            dict(valid, baseUrl="http://model.example.test"),
            dict(valid, baseUrl="https://user:password@model.example.test"),
            dict(valid, apiKey="do-not-store-plaintext"),
            {k: v for k, v in valid.items() if k != "authMode"},
            "not-an-object",
        )
        for record in invalid:
            with self.subTest(record=record):
                with self.assertRaises(ValueError):
                    self.read(dict(self.preferences, approvedCredentials=[record]))

    def test_disposable_state_cannot_carry_arbitrary_config_or_approvals(self):
        valid = {"trustWorkspace": True, "approveApiKey": False}
        invalid = (
            {"trustWorkspace": "true"}, {"trustWorkspace": 1},
            {"approveApiKey": "yes"}, {"approveApiKey": 1},
            {"permissionMode": "bypassPermissions"}, {"effort": "ultracode"},
            {"ultracode": "on"}, {"ultracode": 1},
            {"trustedWorkspaces": ["/"]}, {"keySha256": "a" * 64},
            {"projects": {"/": {"hasTrustDialogAccepted": True}}},
            {"env": {"CLAUDE_CONFIG_DIR": "/workspace"}},
            {"customApiKeyResponses": {"approved": [self.key[-20:]]}},
        )
        for change in invalid:
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    startup.validate_state(dict(valid, **change))

    def test_remembered_model_and_effort_are_passed_to_disposable_state(self):
        state = self.resolve(dict(self.preferences, model="claude-opus-4-7",
                                  rememberModelEffort=True))
        self.assertEqual(state["model"], "claude-opus-4-7")
        self.assertTrue(state["rememberModelEffort"])
        self.assertEqual(state["effort"], "max")
        for value in ("true", 1, None):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    self.read(dict(self.preferences, rememberModelEffort=value))

    def test_selection_accepts_only_bounded_model_and_effort(self):
        for value in ({"model": "claude-opus-4-7"},
                      {"model": "provider/claude-opus-4-7[1m]", "effort": "max"}):
            self.assertEqual(startup.validate_selection(value), value)
        for value in (
            {}, [], None, {"model": ""}, {"model": True},
            {"model": "x" * 201}, {"model": "name\nother"},
            {"model": "$(touch /tmp/unsafe)"}, {"model": "--settings"},
            {"model": "claude-opus-4-7", "effort": "ultracode"},
            {"model": "claude-opus-4-7", "effort": None},
            {"model": "claude-opus-4-7", "env": {"HOME": "/workspace"}},
            {"model": "claude-opus-4-7", "approvedCredentials": []},
            {"model": "claude-opus-4-7", "permissionMode": "auto"},
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    startup.validate_selection(value)

    def test_selection_file_is_optional_bounded_and_never_follows_symlinks(self):
        outbox = self.root / "selection.json"
        self.assertIsNone(startup.read_selection(outbox))
        selection = {"model": "claude-opus-4-7", "effort": "high"}
        outbox.write_text(json.dumps(selection))
        self.assertEqual(startup.read_selection(outbox), selection)
        link = self.root / "selection-link.json"
        link.symlink_to(outbox)
        with self.assertRaises((ValueError, OSError)):
            startup.read_selection(link)
        with self.assertRaises((ValueError, OSError)):
            startup.read_selection(self.workspace)
        outbox.write_text(" " * 4097 + json.dumps(selection))
        with self.assertRaises(ValueError):
            startup.read_selection(outbox)
        # A writer can extend a regular file after fstat; actual reads stay bounded.
        metadata = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_size=1)
        with mock.patch("os.fstat", return_value=metadata):
            with self.assertRaises(ValueError):
                startup.read_selection(outbox)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "Requires POSIX FIFOs")
    def test_selection_fifo_is_rejected_without_waiting_for_a_writer(self):
        fifo = self.root / "selection-fifo"
        os.mkfifo(fifo, 0o600)
        program = ("import sys; sys.path.insert(0,sys.argv[1]); "
                   "from startup_config import read_selection\n"
                   "try: read_selection(sys.argv[2])\n"
                   "except (ValueError,OSError): sys.exit(23)\n")
        result = subprocess.run([sys.executable, "-c", program,
                                 str(REPOSITORY / "scripts"), str(fifo)],
                                capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 23, result.stderr.decode())

    def test_selection_save_is_atomic_private_and_preserves_approvals(self):
        original = dict(self.preferences, model="previous-model", rememberModelEffort=True)
        self.read(original)
        original_bytes = self.path.read_bytes()
        replace = os.replace
        replaced = []

        def checked_replace(source, destination):
            self.assertEqual(Path(destination), self.path)
            self.assertEqual(self.path.read_bytes(), original_bytes)
            self.assertEqual(Path(source).stat().st_mode & 0o777, 0o600)
            updated = json.loads(Path(source).read_text())
            self.assertEqual(updated, dict(original, model="chosen-model", effort="high"))
            replaced.append(source)
            return replace(source, destination)

        with mock.patch("os.replace", side_effect=checked_replace):
            self.assertTrue(startup.save_selection(self.path, {
                "model": "chosen-model", "effort": "high",
            }))
        self.assertEqual(len(replaced), 1)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(startup.read_preferences(self.path),
                         dict(original, model="chosen-model", effort="high"))
        self.assertFalse(list(self.root.glob(".startup-selection-*")))

    def test_selection_without_effort_clears_previous_effort_only(self):
        original = dict(self.preferences, rememberModelEffort=True)
        self.read(original)
        self.assertTrue(startup.save_selection(self.path, {"model": "another-model"}))
        expected = dict(original, model="another-model")
        expected.pop("effort")
        self.assertEqual(startup.read_preferences(self.path), expected)

    def test_disabled_remembering_or_failed_write_preserves_previous_file(self):
        for remember in (False, None):
            original = dict(self.preferences)
            if remember is not None:
                original["rememberModelEffort"] = remember
            self.read(original)
            before = self.path.read_bytes()
            self.assertFalse(startup.save_selection(self.path, {"model": "other-model"}))
            self.assertEqual(self.path.read_bytes(), before)
        self.read(dict(self.preferences, rememberModelEffort=True))
        before = self.path.read_bytes()
        with mock.patch("os.replace", side_effect=OSError("fixture replace failure")):
            with self.assertRaises(OSError):
                startup.save_selection(self.path, {"model": "other-model"})
        self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse(list(self.root.glob(".startup-selection-*")))

    def test_invalid_json_and_non_object_files_fail_closed(self):
        for contents in ("{", "[]", "null", '"startup"'):
            with self.subTest(contents=contents):
                self.path.write_text(contents)
                with self.assertRaises(ValueError):
                    startup.read_preferences(self.path)


if __name__ == "__main__":
    unittest.main()
