"""Native footer observation stays bounded and cannot invent missing values."""
import errno
import contextlib
import fcntl
import importlib.util
import os
from pathlib import Path
import re
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
SPEC = importlib.util.spec_from_file_location(
    "terminal_preferences", SCRIPTS / "terminal_preferences.py"
)
terminal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(terminal)


def frame(mode="auto", ultracode=True, effort="max"):
    label = {
        "default": "manual", "acceptEdits": "accept edits",
        "dontAsk": "don't ask",
    }.get(mode, mode)
    badge = f"◈ {effort}" + (" · ultracode" if ultracode else "") + " · /effort"
    return "\r\n".join([
        "Native fixture", badge, "─" * 80, "❯ ", "─" * 80,
        f"  ⏵⏵ {label} mode on (shift+tab to cycle)",
    ])


def draw(observer, content):
    observer.feed(("\x1b[2J\x1b[H" + content).encode())
    observer.sample()


class FooterRecognitionTests(unittest.TestCase):
    def observer(self):
        changes = []
        return terminal.FooterObserver(100, 24, changes.append), changes

    def test_only_complete_native_layout_exports_explicit_values(self):
        for mode in ("default", "auto", "acceptEdits", "plan", "dontAsk"):
            with self.subTest(mode=mode):
                observer, changes = self.observer()
                draw(observer, frame(mode, ultracode=True))
                self.assertEqual(changes, [{"permissionMode": mode, "ultracode": True}])
                draw(observer, frame(mode, ultracode=False))
                self.assertEqual(changes[-1], {"ultracode": False})
                # An unchanged redraw does not generate a second write.
                count = len(changes)
                observer.sample()
                self.assertEqual(len(changes), count)

    def test_ordinary_text_truncation_and_later_panels_do_not_overwrite(self):
        observer, changes = self.observer()
        draw(observer, frame("plan", ultracode=True))
        incomplete = frame().replace("/effort", "/effo").replace(
            "shift+tab to cycle)", "shift+tab to cyc"
        )
        for content in (
            "The user said auto mode on and ultracode is disabled.",
            "◈ max · /effort\r\n⏵⏵ auto mode on (shift+tab to cycle)",
            incomplete,
            frame("auto", False) + "\r\n\r\n\r\nAn unrelated modal is open",
            "─" * 80 + "\r\nordinary text\r\n" + "─" * 80
            + "\r\n⏵⏵ auto mode on (shift+tab to cycle)",
        ):
            with self.subTest(content=content[:40]):
                draw(observer, content)
                self.assertEqual(changes, [{"permissionMode": "plan", "ultracode": True}])

    def test_conflicting_footer_labels_do_not_guess_permission_mode(self):
        observer, changes = self.observer()
        content = frame("auto") + "\r\n⏸ plan mode on (shift+tab to cycle)"
        draw(observer, content)
        self.assertTrue(all("permissionMode" not in change for change in changes))

    def test_missing_effort_badge_does_not_invent_false(self):
        observer, changes = self.observer()
        draw(observer, frame("auto", True))
        draw(observer, frame("plan", False).replace("◈ max · /effort", ""))
        self.assertEqual(changes[-1], {"permissionMode": "plan"})
        self.assertTrue(observer.known["ultracode"])

    def test_small_and_extreme_terminal_sizes_disable_observation(self):
        for columns, rows in ((59, 24), (100, 9), (65535, 65535), (0, 0)):
            with self.subTest(size=(columns, rows)):
                changes = []
                observer = terminal.FooterObserver(columns, rows, changes.append)
                draw(observer, frame())
                self.assertEqual(changes, [])
                self.assertLessEqual(observer.screen.columns, 500)
                self.assertLessEqual(observer.screen.lines, 200)

    def test_parser_or_callback_failure_does_not_escape_into_session(self):
        observer, changes = self.observer()
        with mock.patch.object(observer.stream, "feed", side_effect=ValueError("fixture")):
            observer.feed(b"native bytes")
        observer.sample()
        self.assertTrue(observer.disabled)
        self.assertEqual(changes, [])
        observer = terminal.FooterObserver(
            100, 24, mock.Mock(side_effect=OSError("fixture export unavailable"))
        )
        draw(observer, frame())
        self.assertTrue(observer.disabled)


class TerminalResourceBoundaryTests(unittest.TestCase):
    def test_string_controls_never_expose_hidden_footer_text(self):
        fake = frame("plan", False)
        # BEL ends OSC only. Other string controls must wait for ST.
        for opening in ("\x1bP", "\x1bX", "\x1b^", "\x1b_",
                        "\x90", "\x98", "\x9e", "\x9f"):
            with self.subTest(opening=repr(opening)):
                guard = terminal.AnsiGuard()
                self.assertEqual(guard.feed(opening + "hidden\x07" + fake), "")
                self.assertEqual(guard.feed("\x1b"), "")
                self.assertEqual(guard.feed("\x1b\\" + "visible"), "visible")
        for opening in ("\x1b]", "\x9d"):
            guard = terminal.AnsiGuard()
            self.assertEqual(guard.feed(opening + "0;hidden\x9cvisible"), "visible")

    def test_unterminated_osc_and_huge_csi_keep_small_parser_state(self):
        guard = terminal.AnsiGuard()
        self.assertEqual(guard.feed("\x1b]0;"), "")
        for _ in range(32):
            self.assertEqual(guard.feed("x" * 32768), "")
            self.assertLessEqual(len(guard.pending), 128)
        self.assertEqual(guard.feed("\x07visible"), "visible")
        guard = terminal.AnsiGuard()
        self.assertEqual(guard.feed("\x1b["), "")
        for _ in range(32):
            self.assertEqual(guard.feed("9;" * 16384), "")
            self.assertLessEqual(len(guard.pending), 128)
        self.assertEqual(guard.feed("mvisible"), "visible")

    def test_malformed_nested_controls_cannot_reopen_unbounded_pyte_osc(self):
        observer = terminal.FooterObserver(100, 24, lambda _: None)
        observer.feed(b"\x1b[\x18\x1b]0;")
        for _ in range(8):
            observer.feed(b"x" * 32768)
        # The observer may safely disable itself, but pyte must never retain an
        # arbitrarily growing escape parameter after the guard has discarded it.
        parser = getattr(observer.stream, "_parser", None)
        parser_frame = getattr(parser, "gi_frame", None)
        if parser_frame is not None:
            for name, value in parser_frame.f_locals.items():
                if name in ("param", "current", "params"):
                    self.assertLessEqual(len(value), 4096, name)

    def test_combining_characters_saved_cursors_and_cells_are_bounded(self):
        observer = terminal.FooterObserver(100, 24, lambda _: None)
        observer.feed(("A" + "\u0301" * 32768).encode())
        observer.feed(("\x1b[2G\u0301" * 4096).encode())
        observer.feed(b"\x1b7" * 8192)
        observer.feed(b"\x1b[9999999;9999999H" * 128)
        self.assertLessEqual(len(observer.screen.savepoints), 4)
        self.assertLessEqual(len(observer.screen.buffer), observer.screen.lines)
        for row in observer.screen.buffer.values():
            self.assertLessEqual(len(row), observer.screen.columns)
            for cell in row.values():
                self.assertLessEqual(len(cell.data), 8)

    def test_noninteractive_launch_uses_original_command_without_observer(self):
        with mock.patch.object(terminal.os, "isatty", return_value=False), \
                mock.patch.object(terminal.subprocess, "call", return_value=7) as call, \
                mock.patch.object(terminal, "FooterObserver") as observer:
            self.assertEqual(terminal.run_pty(["claude", "-p", "fixture"], lambda _: None,
                                            env={"FIXTURE": "1"}), 7)
        call.assert_called_once_with(["claude", "-p", "fixture"], env={"FIXTURE": "1"})
        observer.assert_not_called()

    def test_tty_restore_failure_still_restores_handlers_and_closes_fds(self):
        child = mock.Mock(pid=999999, returncode=0)
        child.poll.return_value = 0
        closed, signals, flags = [], [], []

        def set_signal(number, handler):
            signals.append((number, handler))
            return "previous"

        def set_flags(fd, action, *args):
            if action == terminal.fcntl.F_GETFL:
                return 0
            flags.append((fd, args[0]))
            return 0

        replacements = {
            "os.isatty": lambda fd: True,
            "termios.tcgetattr": lambda fd: [],
            "fcntl.ioctl": lambda *a: struct.pack("HHHH", 24, 80, 0, 0),
            "fcntl.fcntl": set_flags,
            "os.openpty": lambda: (100, 101),
            "os.close": closed.append,
            "subprocess.Popen": lambda *a, **kw: child,
            "signal.signal": set_signal,
            "tty.setraw": lambda fd: None,
            "select.select": lambda *a: ([100], [], []),
            "os.read": lambda *a: b"",
        }
        with contextlib.ExitStack() as stack:
            for path, replacement in replacements.items():
                owner, name = path.split(".")
                stack.enter_context(mock.patch.object(
                    getattr(terminal, owner), name, replacement))
            stack.enter_context(mock.patch.object(
                terminal.termios, "tcsetattr",
                side_effect=OSError(errno.EIO, "fixture hung-up TTY")))
            self.assertEqual(terminal.run_pty(["fixture"], lambda _: None), 0)
        self.assertEqual(closed, [101, 100])
        self.assertEqual(len(signals), 8)
        self.assertEqual(flags[-3:], [(0, 0), (1, 0), (100, 0)])

    @unittest.skipUnless(hasattr(os, "fork"), "Requires POSIX PTYs")
    def test_exited_child_does_not_wait_for_grandchild_holding_slave(self):
        # Both process groups belong only to this fixture. No Docker, real
        # workspace, CLI configuration, or inherited application environment.
        program = """
import os, signal, time
readiness, ready = os.pipe()
if os.fork() == 0:
    os.close(readiness)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    os.write(ready, b"1")
    os.close(ready)
    time.sleep(30)
    os._exit(0)
os.close(ready)
os.read(readiness, 1)
os.close(readiness)
print("fixture-held-slave-group=" + str(os.getpid()), flush=True)
os._exit(0)
"""
        wrapper = """
import sys
sys.path.insert(0, sys.argv[1])
from terminal_preferences import run_pty
raise SystemExit(run_pty([sys.executable, "-B", "-c", sys.argv[2]], lambda _: None))
"""
        master, slave = os.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
        process = None
        observed = bytearray()
        group = None
        started = time.monotonic()
        try:
            with tempfile.TemporaryDirectory(prefix="claude-pty-exit-test-") as cwd:
                process = subprocess.Popen(
                    [sys.executable, "-B", "-c", wrapper, str(SCRIPTS), program],
                    stdin=slave, stdout=slave, stderr=slave, cwd=cwd,
                    start_new_session=True,
                    env={"PATH": os.defpath, "LANG": "C.UTF-8",
                         "PYTHONPATH": str(Path(terminal.pyte.__file__).parent.parent)},
                )
                os.close(slave)
                slave = None
                while time.monotonic() - started < 5:
                    readable, _, _ = select.select([master], [], [], 0.05)
                    if readable:
                        try:
                            data = os.read(master, 4096)
                        except OSError as error:
                            if error.errno != errno.EIO:
                                raise
                            data = b""
                        observed.extend(data)
                        self.assertLessEqual(len(observed), 8192)
                        match = re.search(rb"fixture-held-slave-group=(\d+)", observed)
                        if match:
                            group = int(match.group(1))
                    if process.poll() is not None:
                        break
                self.assertIsNotNone(group, "Fixture never reached its controlled fork")
                self.assertEqual(process.poll(), 0, "PTY waited for the inherited slave")
                self.assertLess(time.monotonic() - started, 4)
                # The holder really survived the session leader's exit; passing
                # because it died to SIGHUP would miss the original regression.
                os.killpg(group, 0)
        finally:
            for identifier in (group, process.pid if process is not None else None):
                if identifier is not None:
                    try:
                        os.killpg(identifier, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            if process is not None:
                process.wait(timeout=5)
            os.close(master)
            if slave is not None:
                os.close(slave)


if __name__ == "__main__":
    unittest.main()
