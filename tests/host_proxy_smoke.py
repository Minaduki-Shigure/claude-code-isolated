#!/usr/bin/env python3
"""Bounded local smoke test through the real host proxy; never builds or pulls."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
DIGEST_IMAGE = re.compile(r"^[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}$")
PROJECT = re.compile(r"Starting isolated project (cc-isolated-[0-9a-f]{12})")

PROBE = r'''
import fcntl, json, os, pathlib, socket, struct, subprocess
checks = []
def check(name, condition, detail=""):
    if not condition:
        raise AssertionError(name + (": " + detail[:250] if detail else ""))
    checks.append(name)
def curl(url, extra=()):
    result = subprocess.run(
        ["curl", "--silent", "--show-error", "--max-time", "20",
         "--noproxy", "", "--write-out", "\n%{http_code}", *extra, url],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=25)
    body, _, status = result.stdout.rpartition("\n")
    return result.returncode, status, body, result.stderr
rc, status, body, err = curl("https://example.com/")
check("real-host-proxy-https-example", rc == 0 and status == "200"
      and "Example Domain" in body, f"rc={rc} status={status} {err}")
rc, status, body, err = curl("http://example.com/")
check("real-host-proxy-http-example", rc == 0 and status.startswith(("2", "3")),
      f"rc={rc} status={status} {err}")
for host in ("api.anthropic.com", "claude.ai", "claude.com",
             "http-intake.logs.us5.datadoghq.com",
             "browser-intake-us5-datadoghq.com", "sentry.io",
             "160.79.104.7", "[2607:6bc0::1]"):
    rc, status, body, err = curl("http://" + host + "/")
    check("policy-denial:" + host, status == "403",
          f"rc={rc} status={status} {err}")
rc, status, body, err = curl("https://api.anthropic.com/")
check("official-https-connect-denied", rc != 0 and "403" in err,
      f"rc={rc} status={status} {err}")
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
for host, family in (("1.1.1.1", socket.AF_INET),
                     ("2606:4700:4700::1111", socket.AF_INET6)):
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.connect((host, 443))
    except OSError:
        check("direct-socket-blocked:" + host, True)
    else:
        check("direct-socket-blocked:" + host, False)
    finally:
        sock.close()
clean_env = {key: value for key, value in os.environ.items()
             if "proxy" not in key.lower()}
result = subprocess.run(
    ["curl", "--silent", "--show-error", "--max-time", "5", "--noproxy", "*",
     "--resolve", "example.com:443:93.184.216.34", "https://example.com/"],
    env=clean_env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=8)
check("cleared-proxy-cannot-connect", result.returncode != 0)
print(json.dumps({"checks": checks}), flush=True)
'''

TERM_PROBE = (
    "import time; print('HOST_PROXY_TERM_READY', flush=True); time.sleep(300)"
)


def run(args, *, timeout=30):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                            text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{' '.join(args[:4])} failed: {result.stderr[-1500:]}")
    return result.stdout


def project_from(stderr):
    matches = PROJECT.findall(stderr)
    if len(matches) != 1:
        raise AssertionError("launcher did not report exactly one owned project")
    return matches[0]


def assert_clean(project):
    for args in (
        ["docker", "ps", "-aq", "--filter", "label=com.docker.compose.project=" + project],
        ["docker", "network", "ls", "-q", "--filter", "label=com.docker.compose.project=" + project],
        ["docker", "volume", "ls", "-q", "--filter", "label=com.docker.compose.project=" + project],
    ):
        if run(args).strip():
            raise AssertionError("owned Docker resources remain for " + project)
    if list((ROOT / ".run").glob(project + "-*")):
        raise AssertionError("owned staged config/credential directory remains for " + project)


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
            parser.error("use registry image references pinned to sha256 digests")
    if not re.fullmatch(r"[a-zA-Z0-9._-]+", args.host_proxy_host):
        parser.error("host proxy must be a hostname or IPv4 address")
    if not 1 <= args.host_proxy_port <= 65535:
        parser.error("host proxy port out of range")
    run(["docker", "info", "--format", "{{.ServerVersion}}"])
    for image in (args.runtime_image, args.gateway_image):
        run(["docker", "image", "inspect", image, "--format", "{{.Id}}"])
    summary = {
        "runtime_image": args.runtime_image, "gateway_image": args.gateway_image,
        "host_proxy": f"{args.host_proxy_host}:{args.host_proxy_port}",
        "live_origins": ["http://example.com/", "https://example.com/"],
        "checks": [], "projects": [], "passed": False,
    }
    try:
        with tempfile.TemporaryDirectory(prefix="claude-host-proxy-smoke-") as td:
            temporary = Path(td)
            workspace = temporary / "workspace"
            workspace.mkdir()
            (workspace / ".claude").mkdir()
            os.chmod(workspace, 0o777)
            os.chmod(workspace / ".claude", 0o777)
            key = temporary / "fake-api-key"
            key.write_text("offline-smoke-key-no-account-no-billing")
            os.chmod(key, 0o600)
            settings = temporary / "settings.json"
            settings.write_text("{}\n")
            startup = temporary / "startup.json"
            startup.write_text('{"schemaVersion":1,"trustedWorkspaces":[],"approvedCredentials":[]}\n')
            config = temporary / "smoke.env"
            values = {
                "WORKSPACE": str(workspace),
                "ANTHROPIC_BASE_URL": "https://example.com",
                "MODEL_AUTH_MODE": "api-key", "MODEL_API_KEY_FILE": str(key),
                "SETTINGS_FILE": str(settings), "STARTUP_CONFIG_FILE": str(startup),
                "TZ": "America/Los_Angeles",
                "HOST_PROXY_HOST": args.host_proxy_host,
                "HOST_PROXY_PORT": str(args.host_proxy_port),
                "CLAUDE_IMAGE": args.runtime_image, "GATEWAY_IMAGE": args.gateway_image,
            }
            config.write_text("\n".join(f"{key}={value}" for key, value in values.items()) + "\n")
            launcher = [sys.executable, str(ROOT / "scripts/claude-docker.py"),
                        "--env-file", str(config), "--pull", "never", "--",
                        "--exec", "python3", "-c"]
            # Explicit values override a caller's unrelated deployment env.
            env = dict(os.environ)
            env.update(values)
            env["GATEWAY_POLICY_FILE"] = str(ROOT / "gateway/policy.json")
            for label, probe in (("network", PROBE), ("term", TERM_PROBE)):
                stdout_path = temporary / (label + ".stdout")
                stderr_path = temporary / (label + ".stderr")
                with stdout_path.open("w") as stdout, stderr_path.open("w") as stderr:
                    process = subprocess.Popen([*launcher, probe], stdin=subprocess.DEVNULL,
                                               stdout=stdout, stderr=stderr, env=env)
                    try:
                        if label == "network":
                            status = process.wait(timeout=150)
                        else:
                            deadline = time.monotonic() + 75
                            while time.monotonic() < deadline:
                                if "HOST_PROXY_TERM_READY" in stdout_path.read_text():
                                    break
                                if process.poll() is not None:
                                    raise AssertionError("TERM target exited before readiness")
                                time.sleep(0.2)
                            else:
                                raise TimeoutError("TERM target did not become ready")
                            process.terminate()
                            status = process.wait(timeout=65)
                    finally:
                        if process.poll() is None:
                            process.terminate()
                            try:
                                process.wait(timeout=65)
                            except subprocess.TimeoutExpired:
                                process.kill()
                                process.wait(timeout=10)
                output = stdout_path.read_text()
                errors = stderr_path.read_text()
                project = project_from(errors)
                summary["projects"].append(project)
                assert_clean(project)
                if label == "network":
                    if status != 0:
                        raise AssertionError("live proxy smoke failed:\n" + errors[-2500:]
                                             + "\n" + output[-2500:])
                    result = next((json.loads(line) for line in output.splitlines()
                                   if line.startswith('{"checks":')), None)
                    if not result:
                        raise AssertionError("network probe did not report its checks")
                    summary["checks"].extend(result["checks"])
                    summary["checks"].append("normal-exit-removes-owned-resources-and-staged-key")
                else:
                    if status != 130:
                        raise AssertionError(f"launcher TERM exit was {status}, expected 130")
                    summary["checks"].append("term-removes-owned-resources-and-staged-key")
                print(f"PASS real host proxy: {label}", flush=True)
            summary["passed"] = True
    except (AssertionError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
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
    except (AssertionError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
