#!/usr/bin/env python3
"""Test preference persistence with the production launcher and a real host PTY.

Uses disposable configuration, an empty workspace, and a fake credential only.
Both images must already exist locally at registry digests. No build, pull, or
model prompt is issued; the only interactive input is built-in slash commands.
"""

import argparse
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import tty


ROOT = Path(__file__).resolve().parents[1]
DIGEST_IMAGE = re.compile(r"^[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}$")
PROJECT = re.compile(r"Starting isolated project (cc-isolated-[0-9a-f]{12})")
ANSI = re.compile(r"\x1b\][^\x07]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-_]")
FAKE_KEY = "preference-smoke-fake-key-no-account-no-billing"
INITIAL = {"model": "claude-opus-5-5", "effort": "high"}
FINAL = {"model": "claude-opus-4-8", "effort": "max"}
CONFIRMATIONS = ("Yes,Itrustthisfolder", "DoyouwanttousethisAPIkey?")
READ_SELECTION = r"""
import json, os, stat, sys
try:
    fd = os.open('/var/lib/claude-preferences/selection.json',
                 os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
except FileNotFoundError:
    sys.exit(3)
with os.fdopen(fd, 'rb') as stream:
    metadata = os.fstat(stream.fileno())
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 4096:
        raise ValueError('selection must be a small regular file')
    data = stream.read(4097)
    if len(data) > 4096:
        raise ValueError('selection is too large')
print(json.dumps(json.loads(data)))
"""


def run(args, *, timeout=20):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                            text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{' '.join(args[:4])} failed: {result.stderr[-1200:]}")
    return result.stdout


def resource_ids(kind, project):
    commands = {
        "container": ["docker", "ps", "-aq"],
        "network": ["docker", "network", "ls", "-q"],
        "volume": ["docker", "volume", "ls", "-q"],
    }
    return run([*commands[kind], "--filter",
                "label=com.docker.compose.project=" + project]).split()


def assert_clean(project):
    for kind in ("container", "network", "volume"):
        if resource_ids(kind, project):
            raise AssertionError(f"owned {kind} resources remain for {project}")
    if list((ROOT / ".run").glob(project + "-*")):
        raise AssertionError("owned staged configuration remains for " + project)


def emergency_cleanup(project):
    """Only called for this process's reported random project after a failure."""
    if not re.fullmatch(r"cc-isolated-[0-9a-f]{12}", project):
        raise AssertionError("refusing cleanup without an exact owned project")
    for kind, command in (
        ("container", ["docker", "rm", "-f"]),
        ("network", ["docker", "network", "rm"]),
        ("volume", ["docker", "volume", "rm"]),
    ):
        owned = resource_ids(kind, project)
        if owned:
            run([*command, *owned], timeout=30)
    for path in (ROOT / ".run").glob(project + "-*"):
        if path.is_symlink():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)
    assert_clean(project)


class InteractiveLauncher:
    def __init__(self, config, env, projects):
        master, slave = pty.openpty()
        self.master = master
        self.output = bytearray()
        self.lock = threading.Lock()
        self.stop_reader = threading.Event()
        self.reader_error = None
        self.project = None
        self.container = None
        self.projects = projects
        tty.setraw(slave)
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
        try:
            self.process = subprocess.Popen(
                [sys.executable, str(ROOT / "scripts/claude-docker.py"),
                 "--env-file", str(config), "--pull", "never"],
                stdin=slave, stdout=slave, stderr=slave, env=env,
                start_new_session=True, close_fds=True)
        except BaseException:
            os.close(master)
            raise
        finally:
            os.close(slave)
        self.reader = threading.Thread(target=self.drain, daemon=True)
        self.reader.start()

    def drain(self):
        # Continuously drain while docker exec/wait runs so a full PTY never
        # blocks the TUI or the production launcher's cleanup subprocesses.
        tail = b""
        try:
            while not self.stop_reader.is_set():
                if not select.select([self.master], [], [], 0.1)[0]:
                    continue
                try:
                    block = os.read(self.master, 65536)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        return
                    raise
                if not block:
                    return
                with self.lock:
                    self.output.extend(block)
                    if len(self.output) > 2 * 1024 * 1024:
                        raise AssertionError("interactive output exceeded 2 MiB")
                query = tail + block
                for _ in range(query.count(b"\x1b[6n")):
                    os.write(self.master, b"\x1b[1;1R")
                tail = query[-3:]
        except BaseException as exc:
            self.reader_error = exc

    def text(self):
        with self.lock:
            value = bytes(self.output).decode(errors="replace")
        return re.sub(r"\s+", "", ANSI.sub("", value))

    def check_ui(self):
        if self.reader_error:
            raise RuntimeError("PTY reader failed: " + str(self.reader_error))
        text = self.text()
        for marker in CONFIRMATIONS:
            if marker in text:
                raise AssertionError("approved startup unexpectedly requested confirmation")
        if ("UnabletoconnecttoAnthropicservices" in text or
                "Failedtoconnecttoapi.anthropic.com" in text):
            raise AssertionError("interactive onboarding attempted an official endpoint")
        if self.process.poll() is not None:
            raise AssertionError("launcher exited before command completion: " + text[-1500:])

    def wait_project(self):
        deadline = time.monotonic() + 75
        while time.monotonic() < deadline:
            self.check_ui()
            with self.lock:
                matches = set(PROJECT.findall(self.output.decode(errors="replace")))
            if len(matches) > 1:
                raise AssertionError("launcher reported multiple projects")
            if matches:
                self.project = matches.pop()
                self.projects.append(self.project)
                return
            time.sleep(0.1)
        raise TimeoutError("launcher did not report its owned project")

    def snapshot(self):
        if self.container is None:
            owned = run(["docker", "ps", "-q", "--filter",
                         "label=com.docker.compose.project=" + self.project,
                         "--filter", "name=^/" + self.project + "-cli$"]).split()
            if not owned:
                return None
            if len(owned) != 1:
                raise AssertionError("expected exactly one owned CLI container")
            self.container = owned[0]
        result = subprocess.run(
            ["docker", "exec", self.container, "python3", "-c", READ_SELECTION],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
        if result.returncode == 3:
            return None
        if result.returncode:
            raise RuntimeError("reading owned preference snapshot failed: " + result.stderr[-1000:])
        if len(result.stdout) > 4096:
            raise AssertionError("preference snapshot exceeded 4 KiB")
        value = json.loads(result.stdout)
        if not isinstance(value, dict) or set(value) != {"model", "effort"}:
            raise AssertionError("snapshot contains unexpected persistent fields")
        return value

    def wait_snapshot(self, expected, *, timeout=25):
        deadline = time.monotonic() + timeout
        previous = None
        while time.monotonic() < deadline:
            self.check_ui()
            previous = self.snapshot()
            if previous == expected:
                return
            time.sleep(0.2)
        raise AssertionError(f"snapshot did not become {expected}; last={previous}; "
                             + self.text()[-1500:])

    def command(self, value):
        if value not in ("/model claude-opus-4-8", "/effort low", "/effort max", "/exit"):
            raise AssertionError("test input must be an approved built-in slash command")
        self.check_ui()
        os.write(self.master, value.encode())
        # Text and Enter must be separate writes to avoid paste detection.
        time.sleep(0.2)
        os.write(self.master, b"\r")

    def exit(self):
        self.command("/exit")
        try:
            code = self.process.wait(timeout=75)
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("launcher failed to exit and clean up") from exc
        self.reader.join(timeout=2)
        if code != 0:
            raise AssertionError(f"launcher exited with {code}: " + self.text()[-1500:])
        if any(marker in self.text() for marker in CONFIRMATIONS):
            raise AssertionError("approved session unexpectedly required confirmation")
        assert_clean(self.project)

    def close(self, failed):
        try:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=65)
                except subprocess.TimeoutExpired:
                    # start_new_session gives this launcher its own group.
                    os.killpg(self.process.pid, signal.SIGKILL)
                    self.process.wait(timeout=10)
            if failed and self.project:
                emergency_cleanup(self.project)
        finally:
            self.stop_reader.set()
            self.reader.join(timeout=2)
            os.close(self.master)


def check_host_config(startup, expected, workspace):
    if json.loads(startup.read_text()) != expected:
        raise AssertionError("host startup preferences changed outside model/effort")
    if stat.S_IMODE(startup.stat().st_mode) != 0o600:
        raise AssertionError("host startup preferences must have mode 0600")
    if set(workspace.iterdir()) != {workspace / ".claude"} or any((workspace / ".claude").iterdir()):
        raise AssertionError("session files were left in the disposable workspace")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-image", required=True)
    parser.add_argument("--gateway-image", required=True)
    parser.add_argument("--host-proxy-host", default="host.docker.internal")
    parser.add_argument("--host-proxy-port", type=int, default=6152)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    for image in (args.runtime_image, args.gateway_image):
        if not DIGEST_IMAGE.fullmatch(image):
            parser.error("use registry images pinned to sha256 digests")
    if not re.fullmatch(r"[a-zA-Z0-9._-]+", args.host_proxy_host):
        parser.error("host proxy must be a hostname or IPv4 address")
    if not 1 <= args.host_proxy_port <= 65535:
        parser.error("host proxy port out of range")
    summary = {
        "runtime_image": args.runtime_image, "gateway_image": args.gateway_image,
        "host_proxy": f"{args.host_proxy_host}:{args.host_proxy_port}",
        "model_prompts_sent": 0, "projects": [], "checks": [], "passed": False,
    }
    try:
        run(["docker", "info", "--format", "{{.ServerVersion}}"])
        for image in (args.runtime_image, args.gateway_image):
            run(["docker", "image", "inspect", image, "--format", "{{.Id}}"])
        with tempfile.TemporaryDirectory(prefix="claude-preferences-smoke-") as td:
            temporary = Path(td).resolve()
            workspace = temporary / "workspace"
            workspace.mkdir(mode=0o777)
            (workspace / ".claude").mkdir(mode=0o777)
            os.chmod(workspace, 0o777)
            os.chmod(workspace / ".claude", 0o777)
            key = temporary / "fake-api-key"
            key.write_text(FAKE_KEY)
            settings = temporary / "settings.json"
            settings.write_text("{}\n")
            startup = temporary / "startup.json"
            original = {
                "schemaVersion": 1, "trustedWorkspaces": [str(workspace)],
                "approvedCredentials": [{
                    "baseUrl": "https://example.com", "authMode": "api-key",
                    "keySha256": hashlib.sha256(FAKE_KEY.encode()).hexdigest(),
                }],
                "permissionMode": "auto", "ultracode": True,
                "rememberModelEffort": True, **INITIAL,
            }
            startup.write_text(json.dumps(original, indent=2) + "\n")
            values = {
                "WORKSPACE": str(workspace), "ANTHROPIC_BASE_URL": "https://example.com",
                "ANTHROPIC_MODEL": "", "MODEL_AUTH_MODE": "api-key",
                "MODEL_API_KEY_FILE": str(key), "SETTINGS_FILE": str(settings),
                "STARTUP_CONFIG_FILE": str(startup), "TZ": "America/Los_Angeles",
                "HOST_PROXY_HOST": args.host_proxy_host,
                "HOST_PROXY_PORT": str(args.host_proxy_port),
                "CLAUDE_IMAGE": args.runtime_image, "GATEWAY_IMAGE": args.gateway_image,
                "GATEWAY_POLICY_FILE": str(ROOT / "gateway/policy.json"),
            }
            config = temporary / "smoke.env"
            config.write_text("\n".join(f"{name}={value}" for name, value in values.items()) + "\n")
            for path in (key, startup, config):
                os.chmod(path, 0o600)
            # Bound directly into the UID 1000 container; the private
            # temporary parent protects this non-secret settings file.
            os.chmod(settings, 0o644)
            # Preserve only OS/Docker connectivity, never caller API/model env.
            inherited = ("PATH", "HOME", "TMPDIR", "TEMP", "TMP", "USER", "LOGNAME",
                         "LANG", "LC_ALL", "DOCKER_CONFIG", "DOCKER_CONTEXT",
                         "DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH",
                         "SSH_AUTH_SOCK", "XDG_RUNTIME_DIR")
            env = {name: os.environ[name] for name in inherited if name in os.environ}
            env.update(values)
            env["TERM"] = "xterm-256color"
            expected = {**original, **FINAL}
            for iteration in (1, 2):
                session = InteractiveLauncher(config, env, summary["projects"])
                failed = True
                try:
                    session.wait_project()
                    session.wait_snapshot(INITIAL if iteration == 1 else FINAL, timeout=75)
                    if iteration == 1:
                        check_host_config(startup, original, workspace)
                        for command, selection in (
                            ("/model claude-opus-4-8", {"model": FINAL["model"], "effort": "high"}),
                            ("/effort low", {"model": FINAL["model"], "effort": "low"}),
                            ("/effort max", FINAL),
                        ):
                            session.command(command)
                            session.wait_snapshot(selection)
                        summary["checks"].append("native-statusline-tracks-model-low-and-session-only-max")
                    session.exit()
                    check_host_config(startup, expected, workspace)
                    if settings.read_text() != "{}\n" or key.read_text() != FAKE_KEY:
                        raise AssertionError("readonly input configuration changed")
                    summary["checks"].extend([
                        f"launch-{iteration}-accepts-slash-commands-without-confirmations",
                        f"launch-{iteration}-persists-only-model-and-effort-mode-0600",
                        f"launch-{iteration}-removes-owned-resources-and-staging",
                        f"launch-{iteration}-leaves-no-workspace-session-files",
                    ])
                    failed = False
                finally:
                    session.close(failed)
                print(f"PASS preference launcher PTY: launch {iteration}", flush=True)
            summary["checks"].append("second-launch-restores-last-model-and-max-without-overrides")
            summary["passed"] = True
    except BaseException as exc:
        summary["error"] = str(exc)
        raise
    finally:
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
