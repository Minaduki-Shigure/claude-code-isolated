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
import selectors
import signal
import struct
import subprocess
import sys
import termios
import time
import uuid


LAUNCH = ["python3", "/opt/claude-isolation/launch-claude.py"]
SELECTION = Path("/var/lib/claude-preferences/selection.json")


def sdk_preferences(startup):
    """Read applied values; do not supply test-side preference overrides."""
    command = [*LAUNCH, "-p",
        "--input-format", "stream-json", "--output-format", "stream-json",
        "--verbose", "--tools", "",
    ]
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True)
    result = {}
    buffers = {"stdout": b"", "stderr": b""}
    selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ, "stdout")
    selector.register(child.stderr, selectors.EVENT_READ, "stderr")

    def send(value):
        child.stdin.write((json.dumps(value) + "\n").encode())
        child.stdin.flush()

    send({"type": "control_request", "request_id": "initialize",
          "request": {"subtype": "initialize"}})
    deadline = time.monotonic() + 45
    try:
        while time.monotonic() < deadline:
            for key, _event in selector.select(timeout=0.2):
                block = os.read(key.fileobj.fileno(), 65536)
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                buffers[key.data] += block
                if key.data != "stdout":
                    continue
                while b"\n" in buffers["stdout"]:
                    line, buffers["stdout"] = buffers["stdout"].split(b"\n", 1)
                    frame = json.loads(line)
                    if frame.get("type") == "control_response":
                        response = frame["response"]
                        assert response["subtype"] == "success", response
                        if response["request_id"] == "initialize":
                            send({"type": "control_request", "request_id": "settings",
                                  "request": {"subtype": "get_settings"}})
                        elif response["request_id"] == "settings":
                            value = response["response"]
                            assert not value.get("errors"), value.get("errors")
                            result["applied"] = value["applied"]
                            effective = value["effective"]
                            assert effective["permissions"]["defaultMode"] == "auto"
                            assert effective["skipAutoPermissionPrompt"] is True
                            assert effective["ultracode"] is True
                            send({"type": "user", "message": {"role": "user",
                                  "content": "Return the offline preference test result."},
                                  "parent_tool_use_id": None, "session_id": ""})
                    elif frame.get("type") == "system" and frame.get("subtype") == "init":
                        result["permissionMode"] = frame["permissionMode"]
                    elif frame.get("type") == "result":
                        assert not frame.get("is_error"), frame
                        assert "ISOLATION_MOCK_SUCCESS" in frame.get("result", ""), frame
                        assert result["permissionMode"] == "auto", result
                        applied = result["applied"]
                        assert applied["model"] == startup["model"], applied
                        assert applied["effort"] == startup["effort"], applied
                        assert applied["ultracode"] is True, applied
                        assert applied["ultracodeRequested"] is True, applied
                        assert applied["ultracodeAvailable"] is True, applied
                        return result
            if child.poll() is not None:
                break
        raise AssertionError("SDK preference probe failed: " +
                             buffers["stderr"].decode(errors="replace")[-1000:])
    finally:
        child.stdin.close()
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)
        selector.close()


def dynamic_preferences():
    """Exercise native commands, including Max's otherwise session-only value."""
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
    child = subprocess.Popen([*LAUNCH, "--tools", ""], stdin=slave, stdout=slave,
                             stderr=slave, start_new_session=True, close_fds=True)
    os.close(slave)
    output = bytearray()
    ansi = re.compile(r"\x1b\][^\x07]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-_]")

    def text():
        return re.sub(r"\s+", "", ansi.sub("", output.decode(errors="replace")))

    def pump(seconds=0.05):
        if select.select([master], [], [], seconds)[0]:
            try:
                block = os.read(master, 65536)
            except OSError as error:
                if error.errno == errno.EIO:
                    return
                raise
            output.extend(block)
            if b"\x1b[6n" in block:
                os.write(master, b"\x1b[1;1R")

    def until(predicate, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            pump()
            assert child.poll() is None, text()[-2000:]
        raise AssertionError("Interactive selection timed out: " + text()[-2000:])

    def selected():
        return json.loads(SELECTION.read_text()) if SELECTION.exists() else None

    def command(value):
        previous = len(text())
        os.write(master, value.encode())
        time.sleep(0.15)
        os.write(master, b"\r")
        return previous

    try:
        until(lambda: "ClaudeCode" in text() and SELECTION.exists())
        original_model = selected()["model"]
        previous = command("/model")
        until(lambda: "Selectmodel" in text()[previous:])
        # Select the next visible native menu entry, then exercise a specific
        # older model via the same command's supported free-form argument.
        os.write(master, b"\x1b[B")
        time.sleep(0.15)
        os.write(master, b"\r")
        until(lambda: selected()["model"] != original_model)
        previous = command("/model claude-opus-4-8")
        until(lambda: "SetmodeltoOpus4.8" in text()[previous:])
        until(lambda: selected().get("model") == "claude-opus-4-8")
        previous = command("/effort")
        until(lambda: "TabtotoggleUltracode" in text()[previous:])
        for _ in range(4):
            os.write(master, b"\x1b[D")
            time.sleep(0.05)
        os.write(master, b"\r")
        until(lambda: "Seteffortleveltolow" in text()[previous:])
        until(lambda: selected().get("effort") == "low")
        previous = command("/effort")
        until(lambda: "TabtotoggleUltracode" in text()[previous:])
        for _ in range(4):
            os.write(master, b"\x1b[C")
            time.sleep(0.05)
        os.write(master, b"\r")
        until(lambda: "Seteffortleveltomax" in text()[previous:])
        # Exit as soon as native UI confirms Max, without waiting for the
        # asynchronous status-line snapshot or adding a refresh grace period.
        command("/exit")
        deadline = time.monotonic() + 8
        while child.poll() is None and time.monotonic() < deadline:
            pump()
        child.wait(timeout=2)
        assert child.returncode == 0
        result = selected()
        assert result == {"model": "claude-opus-4-8", "effort": "max"}, result
        state = Path(os.environ["CLAUDE_CONFIG_DIR"])
        stored = json.loads((state / "settings.json").read_text())
        assert stored["modelSettings"]["claude-opus-4-8"]["effortLevel"] == "low"
        return result
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=3)
        os.close(master)


def main():
    # Never run this UI automation with a user's endpoint or credential.
    assert os.environ["ANTHROPIC_BASE_URL"] == "https://model.example.com"
    assert os.environ["ANTHROPIC_API_KEY"] == "offline-test-key-no-account-no-billing"
    state = Path(os.environ["CLAUDE_CONFIG_DIR"])
    config = state / ".claude.json"
    assert config.is_file(), "Effective global state file is missing"
    app_state = json.loads(config.read_text())
    assert app_state.get("hasCompletedOnboarding") is True
    startup_path = Path("/config/startup.json")
    startup_bytes = startup_path.read_bytes()
    startup = json.loads(startup_bytes)
    # Unmanaged user hooks and status-line commands must remain blocked even
    # though the single managed preference exporter is enabled.
    user_settings_path = state / "settings.json"
    user_settings = json.loads(user_settings_path.read_text())
    user_settings["hooks"] = {"SessionStart": [{"hooks": [{
        "type": "command", "command": "touch /tmp/unmanaged-hook-executed"}]}]}
    user_settings["statusLine"] = {
        "type": "command", "command": "touch /tmp/unmanaged-statusline-executed"}
    user_settings_path.write_text(json.dumps(user_settings))
    preapproved = startup["trustWorkspace"] and startup["approveApiKey"]
    approved = app_state.get("customApiKeyResponses", {}).get("approved", [])
    trusted_project = app_state.get("projects", {}).get("/workspace", {})
    if preapproved:
        assert trusted_project.get("hasTrustDialogAccepted") is True
        assert os.environ["ANTHROPIC_API_KEY"][-20:] in approved
        assert not (state / "preference-session-probe").exists()
        assert not (state / "cache/preference-cache-probe").exists()
    else:
        assert not trusted_project.get("hasTrustDialogAccepted")
        assert os.environ["ANTHROPIC_API_KEY"][-20:] not in approved
    token = "INTERACTIVE_SESSION_MARKER_" + uuid.uuid4().hex
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
    # A positional initial prompt still uses the normal interactive TTY path.
    # Do not use -p or the print-only --no-session-persistence option here.
    command = [*LAUNCH, "Reply with the test result. " + token, "--tools", ""]
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
                assert not preapproved, "Approved workspace unexpectedly required confirmation"
                # Trust only this harness's empty disposable /workspace. The
                # production launcher does not pre-accept workspace trust.
                time.sleep(0.2)
                os.write(master, b"\x1b[B")
                time.sleep(0.2)
                os.write(master, b"\r")
                trusted = True
            if not approved_key and "DoyouwanttousethisAPIkey?" in recent:
                assert not preapproved, "Approved API key unexpectedly required confirmation"
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
        if preapproved:
            assert not trusted and not approved_key
        else:
            assert trusted and approved_key, "Unapproved startup must still ask for confirmation"
        for directory in (Path("/workspace"), Path("/config")):
            for file in directory.rglob("*"):
                if file.is_file() and not file.is_symlink():
                    assert token.encode() not in file.read_bytes(), f"Persistent session data: {file}"
        for file in Path.home().rglob("*"):
            if file.is_file() and (file.suffix == ".jsonl" or file.name == "history.jsonl"):
                assert token.encode() not in file.read_bytes(), f"Interactive transcript saved: {file}"
        (state / "interactive-session-probe").write_text("must-disappear")
        assert startup_path.read_bytes() == startup_bytes
        assert token.encode() not in startup_bytes
        assert os.environ["ANTHROPIC_API_KEY"].encode() not in startup_bytes
        checks = [
            "interactive-effective-onboarding-state",
            "interactive-real-cli-model-response",
            "interactive-exits-cleanly",
            "interactive-no-persistent-transcript",
            "interactive-transcript-saving-disabled",
        ]
        result = {"checks": checks}
        if preapproved:
            result["applied_preferences"] = sdk_preferences(startup)
            assert SELECTION.exists()
            initial = json.loads(SELECTION.read_text())
            assert initial == {"model": startup["model"], "effort": startup["effort"]}, initial
            if "--exercise-selection" in sys.argv:
                result["selection"] = dynamic_preferences()
                checks.extend(["interactive-last-model-selection-exported",
                               "native-model-and-effort-menus-export-selection",
                               "interactive-low-to-session-only-max-exported",
                               "interactive-fast-exit-retains-last-effort"])
            (state / "preference-session-probe").write_text("must-disappear")
            (state / "cache").mkdir(exist_ok=True)
            (state / "cache/preference-cache-probe").write_text("must-disappear")
            checks.extend(["approved-startup-needs-no-confirmation",
                           "runtime-applies-auto-mode",
                           "runtime-applies-max-effort",
                           "runtime-applies-ultracode",
                           "preference-state-readonly-no-key-or-prompt",
                           "previous-preference-session-and-cache-not-present"])
        else:
            checks.append("unapproved-startup-still-requires-confirmation")
            assert not SELECTION.exists()
            checks.append("remember-disabled-does-not-export-preferences")
        assert not Path("/tmp/unmanaged-hook-executed").exists()
        assert not Path("/tmp/unmanaged-statusline-executed").exists()
        checks.append("unmanaged-hooks-and-statusline-blocked")
        for file in SELECTION.parent.iterdir():
            assert file.name == "selection.json", file.name
            value = json.loads(file.read_text())
            assert set(value) <= {"model", "effort"}, value
            assert token.encode() not in file.read_bytes()
            assert os.environ["ANTHROPIC_API_KEY"].encode() not in file.read_bytes()
        checks.append("preference-outbox-only-model-and-effort")
        print(json.dumps(result))
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
