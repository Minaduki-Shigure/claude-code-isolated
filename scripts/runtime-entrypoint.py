#!/usr/bin/env python3
"""Initialize disposable state, expose the policy UDS on loopback, run Claude."""
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit
from startup_config import validate_state
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

IPC = Path("/run/claude-ipc")
HOME_DIR = Path("/home/node")
POLICY = Path("/etc/claude-code/managed-settings.json")
RESERVED_ENV = {
    "TZ", "HOME", "CLAUDE_CONFIG_DIR", "TMPDIR", "TMP", "TEMP", "CLAUDE_CODE_TMPDIR",
    "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME",
    "HISTFILE", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO",
    "NODE_TLS_REJECT_UNAUTHORIZED", "PATH", "LD_PRELOAD", "NODE_OPTIONS",
}


def relay(client):
    upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        upstream.connect(str(IPC / "proxy.sock"))
        client.setblocking(False)
        upstream.setblocking(False)
        peers = {client: upstream, upstream: client}
        pending = {client: bytearray(), upstream: bytearray()}
        readable = set(peers)
        with selectors.DefaultSelector() as selector:
            while readable or any(pending.values()):
                for s in peers:
                    flags = (selectors.EVENT_READ if s in readable and len(pending[peers[s]]) < 262144 else 0)
                    if pending[s]:
                        flags |= selectors.EVENT_WRITE
                    try:
                        selector.unregister(s)
                    except KeyError:
                        pass
                    if flags:
                        selector.register(s, flags)
                events = selector.select(timeout=300)
                if not events:
                    break
                for key, event in events:
                    s = key.fileobj
                    if event & selectors.EVENT_READ:
                        data = s.recv(65536)
                        if data:
                            pending[peers[s]].extend(data)
                        else:
                            readable.discard(s)
                    if event & selectors.EVENT_WRITE and pending[s]:
                        n = s.send(pending[s])
                        del pending[s][:n]
                    if peers[s] not in readable and not pending[s]:
                        try:
                            s.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
    except (OSError, ValueError):
        pass
    finally:
        client.close()
        upstream.close()


def serve(listener):
    while True:
        try:
            client, _ = listener.accept()
        except OSError:
            return
        threading.Thread(target=relay, args=(client,), daemon=True).start()


def main():
    if os.getuid() != 1000:
        raise RuntimeError("The runtime must run as uid 1000")
    timezone = os.environ.get("TZ", "America/Los_Angeles")
    try:
        ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise RuntimeError("TZ must name an installed IANA timezone") from exc
    base_url = os.environ.get("ANTHROPIC_BASE_URL", "")
    parsed = urlsplit(base_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise RuntimeError("ANTHROPIC_BASE_URL must be an HTTPS URL without credentials, query or fragment")
    if parsed.port not in (None, 443):
        raise RuntimeError("Model endpoints must use HTTPS port 443")
    for _ in range(300):
        if (IPC / "ready").is_file() and (IPC / "ca.pem").is_file() and (IPC / "proxy.sock").is_socket():
            break
        time.sleep(0.1)
    else:
        raise RuntimeError("Policy gateway is unavailable; refusing to start")

    state = HOME_DIR / ".claude"
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    settings = json.loads(Path("/config/settings.json").read_text())
    if not isinstance(settings, dict) or not isinstance(settings.get("env", {}), dict):
        raise RuntimeError("User settings must be an object with an optional env object")
    for name in settings.get("env", {}):
        if name.upper() in RESERVED_ENV or name.upper().startswith(("ANTHROPIC_", "OTEL_", "CLAUDE_CODE_", "DISABLE_", "ENABLE_")):
            raise RuntimeError(f"User settings cannot override isolation environment variable {name}")
    startup = validate_state(json.loads(Path("/config/startup.json").read_text()))
    if "permissionMode" in startup:
        permissions = settings.setdefault("permissions", {})
        if not isinstance(permissions, dict):
            raise RuntimeError("User permissions must be an object")
        permissions["defaultMode"] = startup["permissionMode"]
        if startup["permissionMode"] == "auto":
            settings["skipAutoPermissionPrompt"] = True
    if "ultracode" in startup:
        settings["ultracode"] = startup["ultracode"]
    (state / "settings.json").write_text(json.dumps(settings))
    # CLAUDE_CONFIG_DIR also relocates the global .claude.json app-state file.
    # Seed onboarding in that effective directory; it remains on HOME tmpfs.
    app_state = {"hasCompletedOnboarding": True}
    if startup["trustWorkspace"]:
        app_state["projects"] = {"/workspace": {"hasTrustDialogAccepted": True}}
    policy = json.loads(POLICY.read_text())
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": str(HOME_DIR),
        "USER": "node",
        "LOGNAME": "node",
        "LANG": "C.UTF-8",
        "TZ": timezone,
        "TERM": os.environ.get("TERM", "xterm-256color"),
        "TMPDIR": "/tmp",
        "CLAUDE_CODE_TMPDIR": "/tmp/claude",
        "CLAUDE_CONFIG_DIR": str(state),
        "XDG_CONFIG_HOME": str(HOME_DIR / ".config"),
        "XDG_CACHE_HOME": str(HOME_DIR / ".cache"),
        "XDG_STATE_HOME": str(HOME_DIR / ".local/state"),
        "XDG_DATA_HOME": str(HOME_DIR / ".local/share"),
        "HISTFILE": "/dev/null",
        "ANTHROPIC_BASE_URL": base_url,
        "HTTP_PROXY": "http://127.0.0.1:18080",
        "HTTPS_PROXY": "http://127.0.0.1:18080",
        "http_proxy": "http://127.0.0.1:18080",
        "https_proxy": "http://127.0.0.1:18080",
        "NO_PROXY": "",
        "no_proxy": "",
    }
    # Start from a clean environment. Do not copy arbitrary host OTEL endpoints.
    env.update(policy.get("env", {}))
    ca_path = HOME_DIR / "ca-bundle.pem"
    ca_path.write_bytes(Path("/etc/ssl/certs/ca-certificates.crt").read_bytes() + b"\n" + (IPC / "ca.pem").read_bytes())
    for key in ("NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO"):
        env[key] = str(ca_path)
    key = Path("/run/secrets/model_api_key").read_text().strip()
    if not key or any(c in key for c in "\r\n\x00"):
        raise RuntimeError("Credential file must contain one nonempty line")
    auth = os.environ.get("MODEL_AUTH_MODE", "bearer")
    if auth not in ("bearer", "api-key"):
        raise RuntimeError("MODEL_AUTH_MODE must be bearer or api-key")
    env["ANTHROPIC_AUTH_TOKEN" if auth == "bearer" else "ANTHROPIC_API_KEY"] = key
    if auth == "api-key" and startup["approveApiKey"]:
        # Claude stores only its expected key suffix in ephemeral app state.
        # Host approval is bound to the full key hash AND endpoint/auth mode.
        app_state["customApiKeyResponses"] = {"approved": [key[-20:]], "rejected": []}
    (state / ".claude.json").write_text(json.dumps(app_state))
    if os.environ.get("ANTHROPIC_MODEL"):
        env["ANTHROPIC_MODEL"] = os.environ["ANTHROPIC_MODEL"]

    args = sys.argv[1:]
    if args[:1] == ["--exec"]:
        command = args[1:]
        if not command:
            raise RuntimeError("--exec requires a command")
    elif args[:1] == ["--shell"]:
        command = ["bash", "--noprofile", "--norc"] + args[1:]
    else:
        command = ["python3", "/opt/claude-isolation/launch-claude.py"] + args
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 18080))
    listener.listen(64)
    threading.Thread(target=serve, args=(listener,), daemon=True).start()
    child = subprocess.Popen(command, env=env)
    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(sig, lambda s, _f: child.send_signal(s) if child.poll() is None else None)
    try:
        code = child.wait()
        return code if code >= 0 else 128 - code
    finally:
        listener.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"Claude isolation: {exc}", file=sys.stderr)
        sys.exit(78)
