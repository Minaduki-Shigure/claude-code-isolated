#!/usr/bin/env python3
"""Exercise published digest-pinned images, without building any local image."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]
DIGEST_IMAGE = re.compile(r"^[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}$")
MODEL = "claude-sonnet-4-5-20250929"
PREFERENCE_MODEL = "claude-opus-5-5"

RESOURCE_PROBE = r'''
import json, os, pathlib, tempfile, threading, time
checks = []
cgroup = pathlib.Path("/sys/fs/cgroup")
assert (cgroup / "cgroup.controllers").is_file(), "cgroup v2 is required"
for filename, expected, label in (
    ("memory.max", 8 * 1024 ** 3, "memory-limit-8g"),
    ("memory.swap.max", 0, "container-swap-disabled"),
    ("pids.max", 1024, "process-thread-limit-1024"),
):
    actual = int((cgroup / filename).read_text().strip())
    assert actual == expected, (filename, actual, expected)
    checks.append(label)

def memory_events():
    return dict((name, int(value)) for name, value in
                (line.split() for line in (cgroup / "memory.events").read_text().splitlines()))

before_events = memory_events()
for directory, expected, label in (
    ("/dev/shm", 1024 ** 3, "shared-memory-capacity-1g"),
    ("/home/node", 4 * 1024 ** 3, "home-tmpfs-capacity-4g"),
    ("/tmp", 4 * 1024 ** 3, "temporary-files-capacity-4g"),
):
    stats = os.statvfs(directory)
    actual = stats.f_blocks * stats.f_frsize
    assert actual == expected, (directory, actual, expected)
    checks.append(label)

# Cross the former 64 MiB shared-memory limit with bounded, non-sparse writes.
# The file is removed on every Python exception, without filling the mount.
with tempfile.NamedTemporaryFile(prefix="resource-probe-", dir="/dev/shm") as shared:
    shared_path = pathlib.Path(shared.name)
    block = b"S" * (1024 ** 2)
    for _ in range(96):
        shared.write(block)
    shared.flush()
    file_stats = os.fstat(shared.fileno())
    assert file_stats.st_size == 96 * 1024 ** 2
    assert file_stats.st_blocks * 512 >= file_stats.st_size, "shared-memory file is sparse"
    shared.seek(-len(block), os.SEEK_END)
    assert shared.read() == block
checks.append("shared-memory-96m-written-and-read")
assert not shared_path.exists(), "shared-memory probe file was not removed"
checks.append("shared-memory-probe-file-removed")

# Hold 300 threads concurrently to cross the old 256-task limit. The small
# stack and bounded waits avoid a memory stress test or surviving test threads.
threading.stack_size(256 * 1024)
ready = threading.Semaphore(0)
release = threading.Event()
threads = []
def worker():
    ready.release()
    release.wait(timeout=30)
try:
    for _ in range(300):
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        threads.append(thread)
    deadline = time.monotonic() + 15
    for _ in threads:
        assert ready.acquire(timeout=max(0, deadline - time.monotonic())), "thread startup timed out"
    assert all(thread.is_alive() for thread in threads)
    assert int((cgroup / "pids.current").read_text()) >= 301
    checks.append("300-concurrent-threads-started")
finally:
    release.set()
    deadline = time.monotonic() + 10
    for thread in threads:
        thread.join(timeout=max(0, deadline - time.monotonic()))
assert not any(thread.is_alive() for thread in threads), "probe threads were not joined"
checks.append("300-probe-threads-joined")
after_events = memory_events()
for name in ("oom", "oom_kill"):
    assert after_events.get(name, 0) == before_events.get(name, 0), (name, before_events, after_events)
checks.append("resource-probe-no-oom-events")
print(json.dumps({"checks": checks}))
'''

NETWORK_PROBE = r'''
import calendar, fcntl, json, os, pathlib, socket, ssl, struct, subprocess, time
checks = []
def check(name, value, detail=""):
    if not value:
        raise AssertionError(name + (": " + detail[:300] if detail else ""))
    checks.append(name)
time.tzset()
check("timezone-pacific-winter", time.strftime("%Z %z", time.localtime(
    calendar.timegm((2026, 1, 15, 12, 0, 0)))) == "PST -0800")
check("timezone-pacific-summer", time.strftime("%Z %z", time.localtime(
    calendar.timegm((2026, 7, 15, 12, 0, 0)))) == "PDT -0700")
# Some LinuxKit kernels expose DOWN fallback tunnel devices even with Docker
# network_mode=none. Inspect actual interfaces/flags and routing, not filenames.
interfaces = dict((name, index) for index, name in socket.if_nameindex())
check("loopback-interface-present", "lo" in interfaces)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
    for name in interfaces:
        flags = struct.unpack_from("H", fcntl.ioctl(
            control.fileno(), 0x8913, struct.pack("256s", name.encode())), 16)[0]
        check("interface-not-externally-up:" + name,
              bool(flags & 0x8) if name == "lo" else not bool(flags & 0x1))
routes4 = pathlib.Path("/proc/net/route").read_text().splitlines()[1:]
check("no-ipv4-routes", not any(line.strip() for line in routes4))
routes6 = pathlib.Path("/proc/net/ipv6_route")
check("no-nonloopback-ipv6-routes", not routes6.exists() or
      all(line.split()[-1] == "lo" for line in routes6.read_text().splitlines()
          if line.strip()))
status = dict(line.split(":", 1) for line in pathlib.Path("/proc/self/status").read_text().splitlines() if ":" in line)
check("runtime-no-effective-or-bounding-capabilities",
      int(status["CapEff"], 16) == 0 and int(status["CapBnd"], 16) == 0)
check("runtime-no-new-privileges", status["NoNewPrivs"].strip() == "1")
check("no-host-home-or-docker-socket", not any(pathlib.Path(p).exists()
      for p in ("/var/run/docker.sock", "/run/docker.sock", "/Users", "/host")))
try:
    vsock = socket.socket(getattr(socket, "AF_VSOCK", 40), socket.SOCK_STREAM)
except OSError:
    check("vsock-creation-denied", True)
else:
    vsock.close()
    check("vsock-creation-denied", False)
for label, family, host, port in [
    ("direct-ipv4", socket.AF_INET, "1.1.1.1", 443),
    ("direct-ipv6", socket.AF_INET6, "2606:4700:4700::1111", 443),
    ("direct-host-proxy", socket.AF_INET, "TEST_FIXTURE_IP_PLACEHOLDER", 18081),
    ("direct-private-host", socket.AF_INET, "192.168.65.2", 80),
]:
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect((host, port))
    except OSError:
        check(label + "-blocked", True)
    else:
        check(label + "-blocked", False)
    finally:
        s.close()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.sendto(b"\x00" * 12, ("1.1.1.1", 53))
except OSError:
    check("direct-dns-udp-blocked", True)
else:
    check("direct-dns-udp-blocked", False)
finally:
    s.close()

def curl(url, extra=()):
    p = subprocess.run(["curl", "--silent", "--show-error", "--max-time", "15",
                        "--noproxy", "", "--write-out", "\n%{http_code}", *extra, url],
                       text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    body, _, code = p.stdout.rpartition("\n")
    return p.returncode, code, body, p.stderr
for scheme in ("http", "https"):
    rc, code, body, err = curl(scheme + "://allowed.example.com/")
    check(scheme + "-allowed-through-upstream", rc == 0 and code == "200"
          and "OFFLINE_ALLOWED_TARGET" in body, err)
for host in [
    "api.anthropic.com", "console.anthropic.com", "www.anthropic.com",
    "claude.ai", "claude.com", "files.claudeusercontent.com",
    "claudemcpcontent.com", "http-intake.logs.us5.datadoghq.com",
    "browser-intake-us5-datadoghq.com", "sentry.io", "statsig.com",
    "API.ANTHROPIC.COM.", "127.0.0.1", "169.254.169.254",
    "160.79.104.7", "[2607:6bc0::1]", "private.example.com",
    "mixed.example.com", "metadata.example.com", "official-ip.example.com",
    "ipv6-official.example.com", "ipv6-private.example.com",
    "cname-official.example.com",
]:
    rc, code, body, err = curl("http://" + host + "/")
    check("blocked:" + host, code == "403", f"status={code} rc={rc} {err} {body}")
for url in [
    "http://github.com/anthropics/claude-code",
    "https://github.com/AnThRoPiCs/claude-code",
    "https://github.com/%61nthropics/claude-code",
    "http://api.github.com/repos/anthropics/claude-code",
    "http://raw.githubusercontent.com/anthropics/claude-code/main/README.md",
    "http://registry.npmjs.org/@anthropic-ai/claude-code",
    "http://registry.npmjs.org/%40anthropic-ai%2fclaude-code",
    "http://storage.googleapis.com/claude-code-dist-fixture/releases/latest",
]:
    rc, code, body, err = curl(url)
    check("official-shared-host-path-blocked:" + url, code == "403",
          f"status={code} rc={rc} {err} {body}")
rc, code, body, err = curl("https://allowed.example.com/redirect-official", ["--location"])
check("redirect-to-official-blocked", rc != 0 and "403" in err,
      f"status={code} rc={rc} {err}")
rc, code, body, err = curl("https://wrongcert.example.com/")
check("upstream-certificate-verification-enforced", code == "502",
      f"status={code} rc={rc} {err} {body}")
rc, code, body, err = curl("https://allowed.example.com:8443/")
check("nonstandard-connect-port-blocked", rc != 0 and "403" in err)

def raw_proxy(payload):
    s = socket.create_connection(("127.0.0.1", 18080), timeout=5)
    s.sendall(payload)
    response = b""
    while b"\r\n\r\n" not in response:
        part = s.recv(4096)
        if not part:
            break
        response += part
    s.close()
    return response
outer_mismatch = raw_proxy(
    b"GET http://allowed.example.com/ HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
# net/http canonicalizes absolute-form Host from the request target. A 200 here
# is safe only because the upstream audit independently proves canonical Host.
check("absolute-url-host-mismatch-normalized-or-blocked",
      b" 403 " in outer_mismatch or b" 200 " in outer_mismatch)
check("websocket-upgrade-blocked", b" 403 " in raw_proxy(
    b"GET http://allowed.example.com/ HTTP/1.1\r\nHost: allowed.example.com\r\n"
    b"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n"))

def tunnel(sni, request=None):
    s = socket.create_connection(("127.0.0.1", 18080), timeout=5)
    s.sendall(b"CONNECT allowed.example.com:443 HTTP/1.1\r\n"
              b"Host: allowed.example.com:443\r\n\r\n")
    response = b""
    while b"\r\n\r\n" not in response:
        response += s.recv(1)
    check("connect-accepted-for-tls", b" 200 " in response)
    ctx = ssl.create_default_context(cafile=os.environ["SSL_CERT_FILE"])
    if sni is None:
        ctx.check_hostname = False
    try:
        tls = ctx.wrap_socket(s, server_hostname=sni)
        if request is not None:
            tls.sendall(request)
            result = tls.recv(4096)
        else:
            result = b"TLS_HANDSHAKE_SUCCEEDED"
        tls.close()
        return result
    except (ssl.SSLError, OSError):
        s.close()
        return b"TLS_REJECTED"
check("mismatched-sni-blocked", tunnel("api.anthropic.com") == b"TLS_REJECTED")
check("missing-sni-blocked", tunnel(None) == b"TLS_REJECTED")
check("https-host-mismatch-blocked", b" 403 " in tunnel("allowed.example.com",
      b"GET / HTTP/1.1\r\nHost: api.anthropic.com\r\nConnection: close\r\n\r\n"))
check("https-absolute-url-mismatch-blocked", b" 403 " in tunnel("allowed.example.com",
      b"GET https://api.anthropic.com/ HTTP/1.1\r\nHost: allowed.example.com\r\n"
      b"Connection: close\r\n\r\n"))
check("nested-connect-blocked", b" 403 " in tunnel("allowed.example.com",
      b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n"))
print(json.dumps({"checks": checks}))
'''

MEMORY_POLICY_PROBE = r'''
import json, os, pathlib, selectors, subprocess, time
state = pathlib.Path(os.environ["CLAUDE_CONFIG_DIR"])
settings = json.loads((state / "settings.json").read_text())
assert settings["autoMemoryEnabled"] is True
assert settings["autoMemoryDirectory"] == "/workspace/auto-memory-redirect"
assert os.environ["CLAUDE_CODE_DISABLE_AUTO_MEMORY"] == "1"
checks = []
for label, overrides in (
    ("user", None),
    ("command-line", {
        "autoMemoryEnabled": True,
        "autoMemoryDirectory": "/workspace/auto-memory-cli-redirect",
        "env": {"CLAUDE_CODE_DISABLE_AUTO_MEMORY": "0"},
    }),
):
    command = ["python3", "/opt/claude-isolation/launch-claude.py",
               "-p", "--input-format", "stream-json",
               "--output-format", "stream-json", "--verbose", "--tools", ""]
    if overrides is not None:
        command += ["--settings", json.dumps(overrides)]
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ, "stdout")
    selector.register(child.stderr, selectors.EVENT_READ, "stderr")
    buffers = {"stdout": b"", "stderr": b""}
    verified = False
    def send(request_id, subtype):
        # Control frames only: no user message or model request is needed.
        child.stdin.write((json.dumps({
            "type": "control_request", "request_id": request_id,
            "request": {"subtype": subtype},
        }) + "\n").encode())
        child.stdin.flush()
    send("initialize", "initialize")
    try:
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline and not verified:
            for event, _ in selector.select(timeout=0.2):
                block = os.read(event.fileobj.fileno(), 65536)
                if not block:
                    selector.unregister(event.fileobj)
                    continue
                buffers[event.data] += block
                assert len(buffers[event.data]) <= 262144, "unexpected control output size"
                if event.data != "stdout":
                    continue
                while b"\n" in buffers["stdout"]:
                    line, buffers["stdout"] = buffers["stdout"].split(b"\n", 1)
                    frame = json.loads(line)
                    if frame.get("type") != "control_response":
                        continue
                    response = frame["response"]
                    assert response["subtype"] == "success", "native settings request failed"
                    if response["request_id"] == "initialize":
                        send("settings", "get_settings")
                    elif response["request_id"] == "settings":
                        value = response["response"]
                        assert not value.get("errors"), "native settings validation failed"
                        effective = value["effective"]
                        assert effective["autoMemoryEnabled"] is False
                        assert effective["autoMemoryDirectory"] == "/home/node/.claude/memory"
                        assert effective["env"]["CLAUDE_CODE_DISABLE_AUTO_MEMORY"] == "1"
                        verified = True
            if child.poll() is not None and not verified:
                break
        assert verified, "native memory policy verification timed out: " + label
        checks.extend([
            label + "-cannot-enable-auto-memory",
            label + "-cannot-redirect-auto-memory-to-workspace",
            label + "-cannot-disable-memory-isolation-env",
        ])
    finally:
        child.stdin.close()
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        selector.close()
for name in ("auto-memory-redirect", "auto-memory-cli-redirect"):
    assert not (pathlib.Path("/workspace") / name).exists(), name
checks.append("native-memory-policy-checks-create-no-workspace-memory")
print(json.dumps({"checks": checks}))
'''

MODEL_PROBE = r'''
import hashlib, json, os, pathlib, subprocess, uuid
home = pathlib.Path.home()
settings = pathlib.Path(os.environ["CLAUDE_CONFIG_DIR"]) / "settings.json"
assert json.loads(settings.read_text())["env"]["ISOLATION_SETTINGS_SENTINEL"] == "persistent-config"
token = "PRIVATE_SESSION_MARKER_" + uuid.uuid4().hex
command = ["python3", "/opt/claude-isolation/launch-claude.py",
           "-p", "--no-session-persistence", "--output-format", "json",
           "--tools", "Bash",
           "--allowedTools", "Bash", "--max-turns", "3",
           "Offline integration test " + token]
p = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE, text=True, timeout=120)
if p.returncode:
    raise AssertionError("Claude print-mode failed: " + p.stderr[-2000:] + p.stdout[-2000:])
lines = [line for line in p.stdout.splitlines() if line.strip().startswith("{")]
result = json.loads(lines[-1])
assert not result.get("is_error"), result
assert "ISOLATION_MOCK_SUCCESS" in result.get("result", ""), result
assert pathlib.Path("/workspace/model-tool-result.txt").read_text().strip() == "ISOLATION_MOCK_SUCCESS"
for base in (pathlib.Path("/workspace"), pathlib.Path("/config")):
    for file in base.rglob("*"):
        if file.is_file() and not file.is_symlink():
            assert token.encode() not in file.read_bytes(), str(file)
for file in home.rglob("*"):
    if file.is_file() and (file.suffix == ".jsonl" or file.name == "history.jsonl"):
        assert token.encode() not in file.read_bytes(), str(file)
for name in ("session-probe", ".claude/cache-probe", ".claude/projects/session-probe"):
    file = home / name
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text("must-disappear")
pathlib.Path("/tmp/session-probe").write_text("must-disappear")
pathlib.Path("/workspace/.claude/session-probe").write_text("must-disappear")
pathlib.Path("/workspace/persist-probe").write_text("must-remain")
for name in (
    "/home/node/.claude/memory/MEMORY.md",
    "/home/node/.claude/projects/-workspace/memory/MEMORY.md",
    "/home/node/.claude/agent-memory/isolation-memory-probe/MEMORY.md",
    "/workspace/.claude/agent-memory/isolation-memory-probe/MEMORY.md",
    "/workspace/.claude/agent-memory-local/isolation-memory-probe/MEMORY.md",
):
    file = pathlib.Path(name)
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text("MEMORY_ISOLATION_MARKER_must_disappear")
    assert file.read_text() == "MEMORY_ISOLATION_MARKER_must_disappear"
print(json.dumps({"checks": ["real-claude-streaming-tool-and-final", "no-transcript-in-persistent-mounts",
                            "print-mode-transcript-disabled",
                            "auto-and-subagent-memory-probes-written-to-ephemeral-paths"],
                  "session_id": result.get("session_id")}))
'''

RECREATE_PROBE = r'''
import json, os, pathlib
home = pathlib.Path.home()
for name in ("session-probe", ".claude/cache-probe", ".claude/projects/session-probe"):
    assert not (home / name).exists(), name
state = pathlib.Path(os.environ["CLAUDE_CONFIG_DIR"])
assert not (state / "interactive-session-probe").exists()
assert not (state / "preference-session-probe").exists()
assert not (state / "cache/preference-cache-probe").exists()
assert not list(state.rglob("*.jsonl"))
assert not pathlib.Path("/tmp/session-probe").exists()
assert not pathlib.Path("/workspace/.claude/session-probe").exists()
assert pathlib.Path("/workspace/persist-probe").read_text() == "must-remain"
for name in (
    "/home/node/.claude/memory/MEMORY.md",
    "/home/node/.claude/projects/-workspace/memory/MEMORY.md",
    "/home/node/.claude/agent-memory/isolation-memory-probe/MEMORY.md",
    "/workspace/.claude/agent-memory/isolation-memory-probe/MEMORY.md",
    "/workspace/.claude/agent-memory-local/isolation-memory-probe/MEMORY.md",
):
    assert not pathlib.Path(name).exists(), name
for name in ("auto-memory-redirect", "auto-memory-cli-redirect"):
    assert not (pathlib.Path("/workspace") / name).exists(), name
settings = pathlib.Path(os.environ["CLAUDE_CONFIG_DIR"]) / "settings.json"
assert json.loads(settings.read_text())["env"]["ISOLATION_SETTINGS_SENTINEL"] == "persistent-config"
print(json.dumps({"checks": ["home-state-not-persistent", "tmp-not-persistent",
                            "project-claude-state-not-persistent",
                            "workspace-persists", "configuration-persists",
                            "interactive-state-not-persistent", "no-jsonl-after-recreate",
                            "preference-session-and-cache-not-persistent",
                            "auto-memory-index-not-persistent",
                            "subagent-user-project-local-memory-not-persistent",
                            "redirected-auto-memory-never-created"]}))
'''


def command(args, *, timeout=180, check=True, env=None):
    result = subprocess.run(args, text=True, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, env=env)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(args[:5])}\n"
                           f"{result.stderr[-4000:]}\n{result.stdout[-4000:]}")
    return result


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def certs(directory):
    config = directory / "openssl.cnf"
    config.write_text("""[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = Offline isolation integration fixture
[ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,digitalSignature,keyEncipherment,keyCertSign
extendedKeyUsage = serverAuth
subjectAltName = @names
[names]
DNS.1 = cloudflare-dns.com
DNS.2 = model.example.com
DNS.3 = allowed.example.com
DNS.4 = fixture.example.com
DNS.5 = github.com
""")
    command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-config", str(config), "-keyout", str(directory / "key.pem"),
             "-out", str(directory / "cert.pem")])
    # The fixture runs with all capabilities dropped, so UID0 cannot bypass
    # the GitHub runner's ownership on a 0600 bind-mounted key. This disposable
    # test key stays beneath the harness's 0700 temporary parent on the host.
    os.chmod(directory / "key.pem", 0o644)


def json_lines(output):
    for line in reversed(output.splitlines()):
        try:
            obj = json.loads(line)
            if isinstance(obj, dict) and "checks" in obj:
                return obj
        except json.JSONDecodeError:
            continue
    raise AssertionError("probe did not return its verification JSON")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-image", required=True)
    parser.add_argument("--gateway-image", required=True)
    parser.add_argument("--output", type=Path, help="Optional JSON verification report")
    args = parser.parse_args()
    for image in (args.runtime_image, args.gateway_image):
        if not DIGEST_IMAGE.fullmatch(image):
            parser.error("images must be registry references pinned to sha256 digests")
    for tool in ("docker", "openssl"):
        if not shutil.which(tool):
            parser.error(f"required executable missing: {tool}")
    command(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=20)
    for image in (args.runtime_image, args.gateway_image):
        command(["docker", "pull", image], timeout=600)

    project = "cc-isolation-test-" + uuid.uuid4().hex[:12]
    created_containers = []
    checks = []
    summary = {"project": project, "runtime_image": args.runtime_image,
               "gateway_image": args.gateway_image, "checks": checks, "passed": False}
    with tempfile.TemporaryDirectory(prefix="claude-isolation-test-") as temporary:
        tmp = Path(temporary)
        workspace = tmp / "workspace"
        workspace.mkdir()
        (workspace / ".claude").mkdir()
        (workspace / ".claude/underlying-config.json").write_text('{"must":"remain-unmodified"}')
        audit_dir = tmp / "audit"
        audit_dir.mkdir()
        os.chmod(audit_dir, 0o777)
        cert_dir = tmp / "certs"
        cert_dir.mkdir()
        certs(cert_dir)
        settings = tmp / "settings.json"
        write_json(settings, {
            "env": {"ISOLATION_SETTINGS_SENTINEL": "persistent-config"},
            # Deliberately challenge the production managed policy.
            "autoMemoryEnabled": True,
            "autoMemoryDirectory": "/workspace/auto-memory-redirect",
        })
        settings_hash = hashlib.sha256(settings.read_bytes()).hexdigest()
        startup_default = tmp / "startup-default.json"
        write_json(startup_default, {"trustWorkspace": False, "approveApiKey": False})
        startup_approved = tmp / "startup-approved.json"
        write_json(startup_approved, {"trustWorkspace": True, "approveApiKey": True,
                                    "permissionMode": "auto", "effort": "max",
                                    "ultracode": True, "model": PREFERENCE_MODEL,
                                    "rememberModelEffort": True, "rememberPermissionMode": True,
                                    "rememberUltracode": True})
        startup_hash = hashlib.sha256(startup_approved.read_bytes()).hexdigest()
        managed = json.loads((ROOT / "config/managed-settings.json").read_text())
        managed["allowedProviders"] = ["customEndpoint"]
        managed.setdefault("env", {})["ANTHROPIC_BASE_URL"] = "https://model.example.com"
        managed_path = tmp / "managed-settings.json"
        write_json(managed_path, managed)
        key = tmp / "model-api-key"
        key.write_text("offline-test-key-no-account-no-billing")
        os.chmod(key, 0o600)
        # Docker Linux bind mounts preserve host ownership. Only this disposable
        # workspace and fake credential need to be accessible to runtime UID1000.
        os.chmod(workspace, 0o777)
        os.chmod(workspace / ".claude", 0o777)
        os.chmod(key, 0o644)
        override = tmp / "override.json"
        write_json(override, {
            "services": {
                "fixture": {
                    "image": args.runtime_image, "user": "0:0",
                    "entrypoint": ["python3", "/fixture/fixture_server.py"],
                    "command": ["--port", "18081", "--cert", "/certs/cert.pem",
                                "--key", "/certs/key.pem", "--audit", "/audit/requests.jsonl"],
                    "read_only": True, "cap_drop": ["ALL"],
                    "security_opt": ["no-new-privileges:true"],
                    "logging": {"driver": "none"},
                    "networks": ["proxy"],
                    "volumes": [
                        f"{ROOT / 'tests/fixture_server.py'}:/fixture/fixture_server.py:ro",
                        f"{cert_dir}:/certs:ro", f"{audit_dir}:/audit:rw"],
                },
                "gateway": {
                    "environment": {"SSL_CERT_FILE": "/fixture-ca/cert.pem"},
                    "volumes": [f"{cert_dir / 'cert.pem'}:/fixture-ca/cert.pem:ro"],
                },
            },
            "networks": {"proxy": {"internal": True}},
        })
        env = dict(os.environ)
        env.update({
            "COMPOSE_DISABLE_ENV_FILE": "1",
            "TZ": "America/Los_Angeles",
            # Pin the regression profile rather than inheriting host overrides.
            "CLAUDE_MEMORY_LIMIT": "8g", "CLAUDE_PIDS_LIMIT": "1024",
            "CLAUDE_SHM_SIZE": "1g", "CLAUDE_HOME_TMPFS_SIZE": "4g",
            "CLAUDE_TMP_TMPFS_SIZE": "4g",
            "CLAUDE_IMAGE": args.runtime_image, "GATEWAY_IMAGE": args.gateway_image,
            "WORKSPACE": str(workspace), "SETTINGS_FILE": str(settings),
            "STARTUP_STATE_FILE": str(startup_default),
            "MANAGED_SETTINGS_FILE": str(managed_path), "MODEL_API_KEY_FILE": str(key),
            "ANTHROPIC_BASE_URL": "https://model.example.com", "ANTHROPIC_MODEL": MODEL,
            "MODEL_AUTH_MODE": "api-key", "HOST_PROXY_HOST": "127.0.0.1",
            "HOST_PROXY_PORT": "18081",
            "GATEWAY_POLICY_FILE": str(ROOT / "gateway/policy.json"),
        })
        compose = ["docker", "compose", "--project-name", project,
                   "-f", str(ROOT / "compose.yaml"), "-f", str(override)]

        def dc(*parts, timeout=180, check=True):
            return command([*compose, *parts], timeout=timeout, check=check, env=env)

        def probe(code, label, extra_env=()):
            name = project + "-" + label
            created_containers.append(name)
            response = dc("run", "--no-deps", "--name", name, "-T", *extra_env,
                          "claude", "--exec", "python3", "-c", code, timeout=180)
            result = json_lines(response.stdout)
            checks.extend(result["checks"])
            print(f"PASS {label}: {len(result['checks'])} checks", flush=True)
            return name, result

        try:
            dc("up", "-d", "fixture")
            fixture_id = dc("ps", "-q", "fixture").stdout.strip()
            inspect = json.loads(command(["docker", "inspect", fixture_id]).stdout)[0]
            fixture_ip = inspect["NetworkSettings"]["Networks"][project + "_proxy"]["IPAddress"]
            env["HOST_PROXY_HOST"] = fixture_ip
            ready = False
            for _attempt in range(30):
                health = command(["docker", "exec", fixture_id, "python3", "-c",
                                  "import urllib.request; "
                                  "assert all(urllib.request.urlopen('http://127.0.0.1:'+"
                                  "str(port)+'/__health',timeout=1).status == 200 "
                                  "for port in (18081,18082))"],
                                 timeout=5, check=False)
                if health.returncode == 0:
                    ready = True
                    break
                time.sleep(0.2)
            if not ready:
                state = json.loads(command(["docker", "inspect", fixture_id]).stdout)[0]["State"]
                raise AssertionError("offline fixture did not become ready: " + json.dumps({
                    key: state.get(key) for key in ("Status", "Running", "ExitCode", "Error")
                }))
            dc("up", "-d", "--wait", "--wait-timeout", "45", "gateway", timeout=70)
            gateway_id = dc("ps", "-q", "gateway").stdout.strip()
            gateway_status = command(["docker", "exec", gateway_id, "sh", "-c",
                'for p in /proc/[0-9]*; do '
                'if [ "$(cat "$p/comm" 2>/dev/null)" = "claude-egress" ]; then '
                'cat "$p/status"; exit 0; fi; done; exit 1']).stdout
            gs = dict(line.split(":", 1) for line in gateway_status.splitlines() if ":" in line)
            assert gs["Uid"].split() == ["1000"] * 4
            assert int(gs["CapEff"], 16) == 0 and int(gs["CapBnd"], 16) == 0
            assert gs["NoNewPrivs"].strip() == "1"
            checks.append("gateway-worker-nonroot-no-capabilities-no-new-privileges")
            firewall_probe = """
import socket
ip = %r
s=socket.create_connection((ip,18081),timeout=3);s.close()
try:
    s=socket.create_connection((ip,18082),timeout=3)
except OSError:
    pass
else:
    s.close()
    raise AssertionError("gateway can reach an unauthorized live destination port")
""" % fixture_ip
            firewall_name = project + "-firewall-probe"
            created_containers.append(firewall_name)
            command(["docker", "run", "--rm", "--name", firewall_name,
                     "--network", "container:" + gateway_id,
                     "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                     "--user", "1000:1000", "--read-only", "--entrypoint", "python3",
                     args.runtime_image, "-c", firewall_probe], timeout=15)
            checks.append("gateway-firewall-allows-only-configured-proxy-port")
            network_name, _ = probe(NETWORK_PROBE.replace(
                "TEST_FIXTURE_IP_PLACEHOLDER", fixture_ip), "network")
            info = json.loads(command(["docker", "inspect", network_name]).stdout)[0]
            host = info["HostConfig"]
            assert host["NetworkMode"] == "none"
            assert host["ReadonlyRootfs"] and not host["Privileged"]
            assert "ALL" in host["CapDrop"]
            assert any("no-new-privileges" in value for value in host["SecurityOpt"])
            assert host["LogConfig"]["Type"] == "none"
            assert host["Memory"] == 8 * 1024 ** 3
            assert host["MemorySwap"] == host["Memory"]
            assert host["PidsLimit"] == 1024
            assert host["ShmSize"] == 1024 ** 3
            assert info["Config"]["User"] in ("1000:1000", "1000", "node")
            mounts = {item["Destination"]: item for item in info["Mounts"]}
            assert mounts["/workspace"]["RW"]
            assert not mounts["/run/claude-ipc"]["RW"]
            assert mounts["/var/lib/claude-preferences"]["Type"] == "volume"
            assert not any("docker.sock" in item.get("Source", "") for item in info["Mounts"])
            writable_bind_mounts = [item["Destination"] for item in info["Mounts"]
                                    if item["Type"] == "bind" and item["RW"]]
            assert writable_bind_mounts == ["/workspace"], writable_bind_mounts
            for directory in ("/home/node", "/tmp", "/run", "/workspace/.claude"):
                assert directory in host["Tmpfs"], (directory, host["Tmpfs"])
            checks.extend(["compose-net-none", "nonroot-readonly-dropped-capabilities",
                           "no-new-privileges", "docker-logging-disabled",
                           "only-workspace-writable-host-bind", "session-state-on-tmpfs"])
            probe(RESOURCE_PROBE, "resources")
            probe(MEMORY_POLICY_PROBE, "memory-policy")
            _, result = probe(MODEL_PROBE, "model")
            summary["mock_session_id"] = result.get("session_id")
            probe((ROOT / "tests/interactive_probe.py").read_text(), "interactive")
            probe(RECREATE_PROBE, "recreate")
            env["STARTUP_STATE_FILE"] = str(startup_approved)
            env["ANTHROPIC_MODEL"] = PREFERENCE_MODEL
            try:
                _, preferences = probe(
                    "import sys\nsys.argv.append('--exercise-selection')\n" +
                    (ROOT / "tests/interactive_probe.py").read_text(),
                                       "preferences")
                selection = preferences["selection"]
                assert selection == {"model": "claude-opus-4-8", "effort": "max",
                                     "permissionMode": "acceptEdits", "ultracode": False}
                startup_restored = tmp / "startup-restored.json"
                restored = json.loads(startup_approved.read_text())
                restored.update(selection)
                write_json(startup_restored, restored)
                env["STARTUP_STATE_FILE"] = str(startup_restored)
                _, recreated_preferences = probe(
                    (ROOT / "tests/interactive_probe.py").read_text(), "preferences-recreate")
                assert recreated_preferences["applied_preferences"]["applied"]["model"] == selection["model"]
                assert recreated_preferences["applied_preferences"]["applied"]["effort"] == selection["effort"]
                assert recreated_preferences["applied_preferences"]["permissionMode"] == selection["permissionMode"]
                assert recreated_preferences["applied_preferences"]["applied"]["ultracodeRequested"] == selection["ultracode"]
                summary["applied_preferences"] = recreated_preferences["applied_preferences"]
                summary["last_selection"] = selection
                checks.extend(["persistent-preferences-reapplied-after-recreate",
                               "last-interactive-model-and-max-restored",
                               "last-interactive-permission-mode-and-ultracode-off-restored"])
                probe(RECREATE_PROBE, "preferences-state-recreate")
            finally:
                env["STARTUP_STATE_FILE"] = str(startup_default)
                env["ANTHROPIC_MODEL"] = MODEL
            assert hashlib.sha256(startup_approved.read_bytes()).hexdigest() == startup_hash
            for preference_file in (startup_default, startup_approved, startup_restored):
                data = preference_file.read_bytes()
                assert key.read_bytes() not in data
                assert b"SESSION_MARKER_" not in data
            checks.append("persistent-startup-json-unchanged-no-secret-or-prompt")
            assert hashlib.sha256(settings.read_bytes()).hexdigest() == settings_hash
            checks.append("persistent-settings-not-modified")
            assert not (workspace / ".claude/session-probe").exists()
            for directory in ("auto-memory-redirect", "auto-memory-cli-redirect",
                              ".claude/agent-memory", ".claude/agent-memory-local"):
                assert not (workspace / directory).exists(), directory
            assert (workspace / ".claude/underlying-config.json").read_text() == '{"must":"remain-unmodified"}'
            checks.append("masked-project-state-not-written-to-host")
            checks.append("no-auto-or-subagent-memory-written-to-host-workspace")
            events = [json.loads(line) for line in (audit_dir / "requests.jsonl").read_text().splitlines()]
            allowed_hosts = {"", "127.0.0.1", "cloudflare-dns.com", "model.example.com",
                             "allowed.example.com"}
            unexpected = [event for event in events if event["kind"] == "request"
                          and event["host"] not in allowed_hosts]
            assert not unexpected, unexpected
            # Even the fake upstream receives numeric destinations only.
            for event in events:
                if event["kind"] == "connect":
                    assert event["authority"] in (
                        "1.1.1.1:443", "93.184.216.34:443", "93.184.216.34:80",
                        "[2606:2800:220:1:248:1893:25c8:1946]:443",
                        "[2606:2800:220:1:248:1893:25c8:1946]:80",
                    ), event
            assert any(event["kind"] == "model_turn" and event["tool_turn"] for event in events)
            assert any(event["kind"] == "model_turn" and event["has_tool_result"] for event in events)
            assert any(event["kind"] == "request" and event.get("streaming")
                       and event["host"] == "model.example.com" for event in events)
            assert any(event["kind"] == "request" and event.get("model") == PREFERENCE_MODEL
                       and event.get("effort") == "max" for event in events)
            assert any(event["kind"] == "request" and event.get("model") == "claude-opus-4-8"
                       and event.get("effort") == "max" for event in events)
            checks.extend(["numeric-upstream-destination-pinning",
                           "no-official-or-telemetry-request-reaches-upstream",
                           "real-cli-tool-result-returned-to-model",
                           "max-effort-reaches-model-api",
                           "restored-model-and-effort-reach-model-api"])
            dc("stop", "fixture", timeout=30)
            probe(r'''
import json, subprocess
p=subprocess.run(["curl","--silent","--show-error","--max-time","10","--noproxy","",
                  "https://allowed.example.com/"],capture_output=True,text=True)
assert p.returncode != 0 or "OFFLINE_ALLOWED_TARGET" not in p.stdout
print(json.dumps({"checks":["upstream-outage-fails-closed"]}))
''', "outage")
            summary["passed"] = True
        finally:
            for name in created_containers:
                command(["docker", "rm", "-f", name], timeout=20, check=False)
            dc("down", "--volumes", "--remove-orphans", timeout=45, check=False)
            preferences_volume = command(["docker", "volume", "inspect", project + "_preferences"],
                                         timeout=15, check=False)
            assert preferences_volume.returncode != 0, "Temporary preference volume survived cleanup"
            checks.append("preference-outbox-volume-removed-with-project")
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                write_json(args.output, summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
