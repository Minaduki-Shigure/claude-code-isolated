#!/usr/bin/env python3
"""Exercise real interactive Claude in the harness's disposable offline fixture."""
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time
import uuid


def main():
    # Never run this UI automation with a user's endpoint or credential.
    assert os.environ["ANTHROPIC_BASE_URL"] == "https://model.example.com"
    assert os.environ["ANTHROPIC_API_KEY"] == "offline-test-key-no-account-no-billing"
    state = Path(os.environ["CLAUDE_CONFIG_DIR"])
    config = state / ".claude.json"
    assert config.is_file(), "Effective global state file is missing"
    assert json.loads(config.read_text()).get("hasCompletedOnboarding") is True
    token = "INTERACTIVE_SESSION_MARKER_" + uuid.uuid4().hex
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
    # A positional initial prompt still uses the normal interactive TTY path.
    # Do not use -p or the print-only --no-session-persistence option here.
    command = [
        "/usr/local/bin/claude", "Reply with the test result. " + token,
        "--setting-sources", "user", "--no-chrome",
        "--model", os.environ["ANTHROPIC_MODEL"], "--tools", "",
    ]
    child = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave,
                             start_new_session=True, close_fds=True)
    os.close(slave)
    output = bytearray()
    deadline = time.monotonic() + 90
    sent_exit = False
    trusted = False
    approved_key = False
    ansi = re.compile(r"\x1b\][^\x07]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-_]")
    text = ""
    recent = ""
    try:
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.2)[0]:
                try:
                    block = os.read(master, 65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not block:
                    break
                output.extend(block)
                if b"\x1b[6n" in block:
                    os.write(master, b"\x1b[1;1R")
                text = ansi.sub("", output.decode(errors="replace")).replace("\r", "")
                # Ink can render spaces using cursor movement escape sequences.
                compact = re.sub(r"\s+", "", text)
                assert "UnabletoconnecttoAnthropicservices" not in compact
                assert "Failedtoconnecttoapi.anthropic.com" not in compact
                recent = compact[-12000:]
            if not trusted and "Yes,Itrustthisfolder" in recent:
                # Trust only this harness's empty disposable /workspace. The
                # production launcher does not pre-accept workspace trust.
                time.sleep(0.2)
                os.write(master, b"\x1b[B")
                time.sleep(0.2)
                os.write(master, b"\r")
                trusted = True
            if not approved_key and "DoyouwanttousethisAPIkey?" in recent:
                # The fixed fake key assertion above guards this confirmation.
                time.sleep(0.2)
                os.write(master, b"\x1b[A")
                time.sleep(0.2)
                os.write(master, b"\r")
                approved_key = True
            if not sent_exit and "ISOLATION_MOCK_SUCCESS" in recent:
                time.sleep(0.5)
                os.write(master, b"/exit")
                # Separate Enter from text to avoid terminal paste detection.
                time.sleep(0.2)
                os.write(master, b"\r")
                sent_exit = True
            if child.poll() is not None:
                break
        assert sent_exit, "Interactive model response did not complete"
        child.wait(timeout=10)
        assert child.returncode == 0, f"Interactive exit status: {child.returncode}"
        for directory in (Path("/workspace"), Path("/config")):
            for file in directory.rglob("*"):
                if file.is_file() and not file.is_symlink():
                    assert token.encode() not in file.read_bytes(), f"Persistent session data: {file}"
        for file in Path.home().rglob("*"):
            if file.is_file() and (file.suffix == ".jsonl" or file.name == "history.jsonl"):
                assert token.encode() not in file.read_bytes(), f"Interactive transcript saved: {file}"
        (state / "interactive-session-probe").write_text("must-disappear")
        print(json.dumps({"checks": [
            "interactive-effective-onboarding-state",
            "interactive-real-cli-model-response",
            "interactive-exits-cleanly",
            "interactive-no-persistent-transcript",
            "interactive-transcript-saving-disabled",
        ]}))
    except Exception as error:
        # This probe handles only the synthetic fixture's prompt and fixed key.
        print(json.dumps({"failure": str(error), "interactive_output_tail": text[-4000:],
                          "sent_exit": sent_exit, "trusted": trusted,
                          "approved_key": approved_key, "exit_code": child.poll()}),
              file=sys.stderr)
        raise
    finally:
        if child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
        os.close(master)


if __name__ == "__main__":
    main()
