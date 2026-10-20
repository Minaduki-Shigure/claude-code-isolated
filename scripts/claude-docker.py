#!/usr/bin/env python3
"""Pull tested images and own exactly one disposable Compose project."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
import importlib.util

sys.path.insert(0, str(Path(__file__).resolve().parent))
from startup_config import read_preferences, resolve_startup, save_selection, should_remember, validate_selection
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

ROOT = Path(__file__).resolve().parent.parent
ALLOWED = {
    "WORKSPACE", "ANTHROPIC_BASE_URL", "ANTHROPIC_MODEL", "MODEL_AUTH_MODE",
    "MODEL_API_KEY_FILE", "HOST_PROXY_HOST", "HOST_PROXY_PORT",
    "CLAUDE_IMAGE", "GATEWAY_IMAGE", "SETTINGS_FILE", "GATEWAY_POLICY_FILE",
    "STARTUP_CONFIG_FILE", "TZ",
}
DEFAULTS = {
    "HOST_PROXY_HOST": "host.docker.internal", "HOST_PROXY_PORT": "6152",
    "TZ": "America/Los_Angeles",
    "MODEL_AUTH_MODE": "bearer", "ANTHROPIC_MODEL": "",
    "CLAUDE_IMAGE": "ghcr.io/minaduki-shigure/claude-code-isolated:latest",
    "GATEWAY_IMAGE": "ghcr.io/minaduki-shigure/claude-code-isolated-gateway:latest",
    "SETTINGS_FILE": str(ROOT / "config/settings.json"),
    "STARTUP_CONFIG_FILE": str(ROOT / "config/startup.example.json"),
    "GATEWAY_POLICY_FILE": str(ROOT / "gateway/policy.json"),
}


def read_config(path):
    result = dict(DEFAULTS)
    local_startup = ROOT / "config/startup.json"
    if local_startup.is_file():
        result["STARTUP_CONFIG_FILE"] = str(local_startup)
    for number, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"Invalid config line {number}")
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if key not in ALLOWED:
            raise ValueError(f"Unsupported config key {key}; credentials belong in the credential file")
        if len(value) > 1 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if "\x00" in value or "\r" in value or "\n" in value:
            raise ValueError(f"Invalid config value for {key}")
        result[key] = value
    # Only documented non-secret fields can be overridden by the caller.
    for key in ALLOWED:
        if key in os.environ:
            result[key] = os.environ[key]
    return result


def inside(path, root):
    return path == root or root in path.parents


def validate(config):
    for key in ("WORKSPACE", "ANTHROPIC_BASE_URL", "MODEL_API_KEY_FILE"):
        if not config.get(key):
            raise ValueError(f"{key} is required")
    try:
        ZoneInfo(config["TZ"])
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError("TZ must be an installed IANA timezone, such as America/Los_Angeles") from exc
    workspace = Path(config["WORKSPACE"]).expanduser().resolve(strict=True)
    if not workspace.is_dir() or workspace == Path("/") or workspace == Path.home():
        raise ValueError("WORKSPACE must be a project directory, never / or your home")
    if inside(ROOT, workspace):
        raise ValueError("WORKSPACE must not contain this deployment directory and its policies")
    config["WORKSPACE"] = str(workspace)
    for key in ("MODEL_API_KEY_FILE", "SETTINGS_FILE", "GATEWAY_POLICY_FILE", "STARTUP_CONFIG_FILE"):
        p = Path(config[key]).expanduser().resolve(strict=True)
        if not p.is_file():
            raise ValueError(f"{key} must be a regular file")
        if inside(p, workspace):
            raise ValueError(f"{key} must be outside WORKSPACE")
        config[key] = str(p)
    parsed = urlsplit(config["ANTHROPIC_BASE_URL"])
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.port not in (None, 443):
        raise ValueError("Model API must use HTTPS port 443 without embedded credentials, query or fragment")
    if config["MODEL_AUTH_MODE"] not in ("bearer", "api-key"):
        raise ValueError("MODEL_AUTH_MODE must be bearer or api-key")
    if not re.fullmatch(r"[a-zA-Z0-9._-]+", config["HOST_PROXY_HOST"]):
        raise ValueError("Invalid HOST_PROXY_HOST")
    if not config["HOST_PROXY_PORT"].isdigit() or not 1 <= int(config["HOST_PROXY_PORT"]) <= 65535:
        raise ValueError("Invalid HOST_PROXY_PORT")
    for key in ("CLAUDE_IMAGE", "GATEWAY_IMAGE"):
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9./_:@-]+", config[key]):
            raise ValueError(f"Invalid image reference {key}")
    settings = json.loads(Path(config["SETTINGS_FILE"]).read_text())
    if not isinstance(settings, dict) or not isinstance(settings.get("env", {}), dict):
        raise ValueError("User settings must be an object with an optional env object")
    spec = importlib.util.spec_from_file_location("runtime_policy", ROOT / "scripts/runtime-entrypoint.py")
    runtime_policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime_policy)
    for name in settings.get("env", {}):
        if name.upper() in runtime_policy.RESERVED_ENV or name.upper().startswith(("ANTHROPIC_", "OTEL_", "CLAUDE_CODE_", "DISABLE_", "ENABLE_")):
            raise ValueError(f"User settings cannot override isolation environment variable {name}")
    json.loads(Path(config["GATEWAY_POLICY_FILE"]).read_text())
    read_preferences(config["STARTUP_CONFIG_FILE"])
    return config


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def image_record(reference):
    record = json.loads(run(["docker", "image", "inspect", reference], capture_output=True, text=True).stdout)[0]
    return record["Id"], record.get("Config", {}).get("Labels", {}) or {}


def collect_selection(project, image):
    # This helper has no network, credential, workspace or host configuration.
    code = ("import sys,json; sys.path.insert(0,'/opt/claude-isolation'); "
            "from startup_config import read_selection; "
            "print(json.dumps(read_selection('/outbox/selection.json')))")
    result = run(["docker", "run", "--rm", "--name", project + "-preferences",
                  "--label", "com.docker.compose.project=" + project,
                  "--label", "com.docker.compose.service=preferences-reader",
                  "--network", "none", "--read-only", "--log-driver", "none", "--pull", "never",
                  "--user", "1000:1000",
                  "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                  "--mount", "type=volume,source=" + project + "_preferences,target=/outbox,readonly",
                  "--entrypoint", "python3", image, "-c", code],
                 capture_output=True, text=True, timeout=20)
    value = json.loads(result.stdout)
    return None if value is None else validate_selection(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=ROOT / ".env")
    parser.add_argument("--pull", choices=("always", "never"), default="always")
    parser.add_argument("--preflight-only", action="store_true")
    options, command = parser.parse_known_args()
    if command[:1] == ["--"]:
        command.pop(0)
    config = validate(read_config(options.env_file))
    run(["docker", "info", "--format", "{{.ServerVersion}}"], stdout=subprocess.DEVNULL)
    run(["docker", "compose", "version"], stdout=subprocess.DEVNULL)
    if options.preflight_only:
        print("Docker is available; configuration paths and endpoint are valid. No containers started.")
        return 0
    if options.pull == "always":
        for name in ("CLAUDE_IMAGE", "GATEWAY_IMAGE"):
            run(["docker", "pull", config[name]])
    records = [image_record(config[k]) for k in ("CLAUDE_IMAGE", "GATEWAY_IMAGE")]
    for label in ("org.opencontainers.image.version", "org.opencontainers.image.revision", "org.opencontainers.image.created"):
        values = [r[1].get(label) for r in records]
        if not all(values) or values[0] != values[1]:
            raise ValueError(f"Images are not from the same tested release ({label}); retry pulling or pin a matching build tag")
    # Exact local content IDs prevent a mutable tag from changing mid-session.
    config["CLAUDE_IMAGE"], config["GATEWAY_IMAGE"] = records[0][0], records[1][0]
    parent = ROOT / ".run"
    parent.mkdir(mode=0o700, exist_ok=True)
    os.chmod(parent, 0o700)
    project = "cc-isolated-" + uuid.uuid4().hex[:12]
    session = Path(tempfile.mkdtemp(prefix=project + "-", dir=parent))
    compose = ["docker", "compose", "--project-name", project, "--env-file", "/dev/null", "-f", str(ROOT / "compose.yaml")]
    child = None
    started = False
    cli_started = False
    startup = {}
    env = dict(os.environ)
    env.update(config)
    try:
        policy = json.loads((ROOT / "config/managed-settings.json").read_text())
        policy["allowedProviders"] = ["customEndpoint"]
        policy["env"]["ANTHROPIC_BASE_URL"] = config["ANTHROPIC_BASE_URL"]
        managed = session / "managed-settings.json"
        managed.write_text(json.dumps(policy, indent=2) + "\n")
        os.chmod(managed, 0o644)
        # Private parent directory protects the staged credential on the host.
        # The readable file mode permits non-root Docker users on macOS/Linux.
        credential = session / "model-api-key"
        value = Path(config["MODEL_API_KEY_FILE"]).read_bytes()
        if not value.strip() or b"\x00" in value or b"\n" in value.strip() or b"\r" in value.strip():
            raise ValueError("API credential must contain one nonempty line")
        credential.write_bytes(value)
        os.chmod(credential, 0o644)
        env["MODEL_API_KEY_FILE"] = str(credential)
        env["MANAGED_SETTINGS_FILE"] = str(managed)
        # Only scoped approvals and requested preferences enter the container.
        # Host paths and credential fingerprints stay in the host-only config.
        startup = resolve_startup(read_preferences(config["STARTUP_CONFIG_FILE"]),
                                  config["WORKSPACE"], config["ANTHROPIC_BASE_URL"],
                                  config["MODEL_AUTH_MODE"], value.decode())
        startup_path = session / "startup-state.json"
        startup_path.write_text(json.dumps(startup, indent=2) + "\n")
        os.chmod(startup_path, 0o644)
        env["STARTUP_STATE_FILE"] = str(startup_path)
        # Compose interpolates environment values once, not as shell code.
        run(compose + ["config", "--quiet"], env=env)
        (session / "project.txt").write_text(project + "\n")
        print(f"Starting isolated project {project}", file=sys.stderr)
        print(f"Version: {records[0][1]['org.opencontainers.image.version']}", file=sys.stderr)
        print("Project .claude/ is temporarily masked; workspace files remain persistent.", file=sys.stderr)

        def interrupted(sig, _frame):
            if child is not None and child.poll() is None:
                child.send_signal(sig)
            raise KeyboardInterrupt

        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            signal.signal(sig, interrupted)
        started = True
        child = subprocess.Popen(compose + ["up", "-d", "--no-build", "--wait", "--wait-timeout", "45", "gateway"], env=env)
        status = child.wait()
        child = None
        if status:
            raise RuntimeError("Gateway startup failed; refusing to start Claude")
        cli_args = compose + ["run", "--rm", "--no-deps", "--name", project + "-cli"]
        if not sys.stdin.isatty():
            cli_args += ["-T"]
        cli_args += ["claude"] + command
        cli_started = True
        child = subprocess.Popen(cli_args, env=env)
        return child.wait()
    except KeyboardInterrupt:
        return 130
    finally:
        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            signal.signal(sig, signal.SIG_IGN)
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        preference_error = None
        if cli_started and should_remember(startup):
            try:
                selection = collect_selection(project, config["CLAUDE_IMAGE"])
                if selection is not None:
                    save_selection(config["STARTUP_CONFIG_FILE"], selection)
            except (ValueError, OSError, subprocess.SubprocessError) as exc:
                # Preserve previous preferences; cleanup must still run.
                preference_error = type(exc).__name__
        cleaned = True
        if started:
            # Stop the tracked Compose client before removing its resources.
            # Only a container with BOTH this random project label and name is
            # eligible; no global prune or fixed shared project is used.
            try:
                owned = subprocess.run([
                    "docker", "ps", "-aq",
                    "--filter", "label=com.docker.compose.project=" + project,
                    "--filter", "name=^/" + project + "-cli$",
                ], capture_output=True, text=True, timeout=15, check=True).stdout.split()
                if owned:
                    subprocess.run(["docker", "rm", "-f", *owned], timeout=20, check=True)
                result = subprocess.run(compose + [
                    "down", "--volumes", "--remove-orphans", "--timeout", "5",
                ], env=env, timeout=45, check=False)
                cleaned = result.returncode == 0
            except (OSError, subprocess.SubprocessError):
                cleaned = False
        if cleaned:
            shutil.rmtree(session)
        else:
            print(f"Cleanup incomplete for {project}; private recovery files retained at {session}", file=sys.stderr)
            raise RuntimeError("Inspect only this project before retrying; no other containers were touched")
        if preference_error:
            raise RuntimeError("Could not save startup preferences (" + preference_error + "); previous preferences were preserved")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, RuntimeError, OSError, subprocess.CalledProcessError) as exc:
        print(f"Claude isolation: {exc}", file=sys.stderr)
        sys.exit(1)
