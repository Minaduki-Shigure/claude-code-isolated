"""Concurrent preference writers must never export runtime payloads."""
import importlib.util
import fcntl
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "preference_output", SCRIPTS / "preference_output.py"
)
output = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(output)


class PreferenceOutputTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="claude-output-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.state = self.root / "state"
        self.outbox = self.root / "outbox"
        self.state.mkdir()
        self.outbox.mkdir()
        self.patch = mock.patch.multiple(
            output, STATE_DIRECTORY=self.state, OUTPUT_DIRECTORY=self.outbox,
        )
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def selection(self):
        return json.loads((self.outbox / output.OUTPUT_NAME).read_text())

    def test_partial_updates_wait_for_model_and_preserve_false(self):
        self.assertFalse(output.write_selection({"permissionMode": "plan",
                                                 "ultracode": True}))
        self.assertEqual(list(self.outbox.iterdir()), [])
        self.assertTrue(output.write_selection({"model": "sonnet", "effort": "max"},
                                               clear_effort=True))
        output.write_selection({"ultracode": False})
        self.assertEqual(self.selection(), {
            "model": "sonnet", "effort": "max",
            "permissionMode": "plan", "ultracode": False,
        })
        output.write_selection({"model": "haiku"}, clear_effort=True)
        self.assertEqual(self.selection(), {
            "model": "haiku", "permissionMode": "plan", "ultracode": False,
        })
        self.assertEqual({p.name for p in self.outbox.iterdir()}, {"selection.json"})
        self.assertEqual({p.name for p in self.state.iterdir()},
                         {output.LOCK_NAME, output.PENDING_NAME})
        for directory in (self.state, self.outbox):
            for path in directory.iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_invalid_update_never_touches_existing_selection(self):
        output.write_selection({"model": "sonnet", "effort": "high"})
        before = (self.outbox / output.OUTPUT_NAME).read_bytes()
        invalid = [
            None, [], {"model": "../ key"}, {"model": "x" * 201},
            {"effort": "ultracode"}, {"permissionMode": "bypassPermissions"},
            {"ultracode": 0}, {"ultracode": "false"}, {"sessionId": "private"},
            {"model": "sonnet", "messages": ["private prompt"]},
        ]
        for update in invalid:
            with self.subTest(update=update):
                with self.assertRaises(ValueError):
                    output.write_selection(update)
                self.assertEqual((self.outbox / output.OUTPUT_NAME).read_bytes(), before)
        with self.assertRaises(ValueError):
            output.write_selection({"model": "sonnet"}, clear_effort=1)

    def test_corrupt_or_unbounded_pending_is_rejected(self):
        pending = self.state / output.PENDING_NAME
        for data in (b" " * 4097, b'{"sessionId":"private"}',
                     b'{"ultracode":true,"ultracode":false}', b"[]", b"{"):
            with self.subTest(data=data[:50]):
                pending.write_bytes(data)
                with self.assertRaises(ValueError):
                    output.write_selection({"model": "sonnet"})
                self.assertFalse((self.outbox / output.OUTPUT_NAME).exists())

    def test_symlinks_and_nonregular_files_are_never_followed(self):
        outside = self.root / "outside"
        outside.write_text('{"model":"original"}')
        for name in (output.LOCK_NAME, output.PENDING_NAME):
            path = self.state / name
            if path.exists():
                path.unlink()
            path.symlink_to(outside)
            with self.subTest(name=name):
                with self.assertRaises((OSError, ValueError)):
                    output.write_selection({"model": "sonnet"})
                self.assertEqual(outside.read_text(), '{"model":"original"}')
            path.unlink()
        pending = self.state / output.PENDING_NAME
        os.mkfifo(pending)
        with self.assertRaises(ValueError):
            output.write_selection({"model": "sonnet"})
        pending.unlink()
        (self.outbox / output.OUTPUT_NAME).symlink_to(outside)
        with self.assertRaises(ValueError):
            output.write_selection({"model": "sonnet"})
        self.assertEqual(outside.read_text(), '{"model":"original"}')

    def test_failed_replace_keeps_valid_output_and_removes_temporary_file(self):
        output.write_selection({"model": "sonnet", "effort": "high"})
        before = (self.outbox / output.OUTPUT_NAME).read_bytes()
        replace = os.replace

        def fail_output(source, destination, **kwargs):
            if destination == output.OUTPUT_NAME:
                raise OSError("fixture replacement failed")
            return replace(source, destination, **kwargs)

        with mock.patch.object(output.os, "replace", side_effect=fail_output):
            with self.assertRaises(OSError):
                output.write_selection({"ultracode": False})
        self.assertEqual((self.outbox / output.OUTPUT_NAME).read_bytes(), before)
        self.assertEqual({p.name for p in self.outbox.iterdir()}, {output.OUTPUT_NAME})
        output.write_selection({"permissionMode": "auto"})
        self.assertEqual(self.selection()["ultracode"], False)

    def test_busy_lock_has_a_bounded_wait_and_keeps_prior_output(self):
        output.write_selection({"model": "sonnet"})
        with open(self.state / output.LOCK_NAME, "r+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            started = time.monotonic()
            with mock.patch.object(output, "LOCK_WAIT_SECONDS", 0.02):
                with self.assertRaises(BlockingIOError):
                    output.write_selection({"permissionMode": "auto"})
            self.assertLess(time.monotonic() - started, 1)
            self.assertEqual(self.selection(), {"model": "sonnet"})

    def test_two_process_writers_do_not_lose_each_others_fields(self):
        code = """
import json, sys, time
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import preference_output as output
output.STATE_DIRECTORY = Path(sys.argv[2])
output.OUTPUT_DIRECTORY = Path(sys.argv[3])
while not Path(sys.argv[4]).exists():
    time.sleep(0.005)
for _ in range(25):
    output.write_selection(json.loads(sys.argv[5]), clear_effort=bool(int(sys.argv[6])))
"""
        barrier = self.root / "start"
        processes = []
        try:
            for update, clear in (({"model": "sonnet", "effort": "max"}, 1),
                                  ({"permissionMode": "plan", "ultracode": False}, 0)):
                processes.append(subprocess.Popen(
                    [sys.executable, "-B", "-c", code, str(SCRIPTS), str(self.state),
                     str(self.outbox), str(barrier), json.dumps(update), str(clear)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                ))
            barrier.touch()
            for process in processes:
                stdout, stderr = process.communicate(timeout=15)
                self.assertEqual(process.returncode, 0, stderr.decode())
                self.assertEqual(stdout, b"")
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait()
        self.assertEqual(self.selection(), {
            "model": "sonnet", "effort": "max",
            "permissionMode": "plan", "ultracode": False,
        })


if __name__ == "__main__":
    unittest.main()
