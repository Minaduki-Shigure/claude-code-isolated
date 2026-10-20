"""Strict, declarative startup preferences; never persist Claude runtime state."""
import hashlib
import hmac
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

PREFERENCE_KEYS = {"schemaVersion", "trustedWorkspaces", "approvedCredentials",
                   "permissionMode", "effort", "ultracode", "model", "rememberModelEffort"}
STATE_KEYS = {"trustWorkspace", "approveApiKey", "permissionMode", "effort", "ultracode", "model", "rememberModelEffort"}
MODES = {"default", "auto"}
EFFORTS = {"low", "medium", "high", "xhigh", "max"}


def endpoint(value):
    if not isinstance(value, str):
        raise ValueError("Startup credential baseUrl must be an HTTPS URL")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or
            parsed.password or parsed.query or parsed.fragment or parsed.port not in (None, 443)):
        raise ValueError("Startup credential baseUrl must use HTTPS port 443 without credentials")
    # Keep the path: approvals for two gateways on the same host are distinct.
    return "https://" + parsed.hostname.lower() + parsed.path


def validate_model(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@+\[\]-]{0,199}", value):
        raise ValueError("Startup model must be a bounded model identifier")


def validate_options(value):
    if "model" in value:
        validate_model(value["model"])
    if "rememberModelEffort" in value and type(value["rememberModelEffort"]) is not bool:
        raise ValueError("Startup rememberModelEffort must be boolean")
    if "permissionMode" in value and (not isinstance(value["permissionMode"], str) or value["permissionMode"] not in MODES):
        raise ValueError("Startup permissionMode must be default or auto")
    if "effort" in value and (not isinstance(value["effort"], str) or value["effort"] not in EFFORTS):
        raise ValueError("Startup effort must be low, medium, high, xhigh or max")
    if "ultracode" in value and type(value["ultracode"]) is not bool:
        raise ValueError("Startup ultracode must be boolean")


def validate_preferences(value):
    if not isinstance(value, dict) or set(value) - PREFERENCE_KEYS:
        raise ValueError("Unsupported startup preference keys")
    if type(value.get("schemaVersion")) is not int or value["schemaVersion"] != 1:
        raise ValueError("Startup schemaVersion must be 1")
    workspaces = value.get("trustedWorkspaces", [])
    if not isinstance(workspaces, list):
        raise ValueError("Startup trustedWorkspaces must be a list")
    for path in workspaces:
        if not isinstance(path, str) or "\x00" in path or not Path(path).is_absolute():
            raise ValueError("Trusted workspace entries must be absolute paths")
        # Keep approvals bound to the originally resolved directory. Repointing a
        # symlink or editing WORKSPACE must not transfer trust to another path.
        if str(Path(path).resolve()) != path:
            raise ValueError("Trusted workspace entries must be canonical paths")
    credentials = value.get("approvedCredentials", [])
    if not isinstance(credentials, list):
        raise ValueError("Startup approvedCredentials must be a list")
    for credential in credentials:
        if not isinstance(credential, dict) or set(credential) != {"baseUrl", "authMode", "keySha256"}:
            raise ValueError("Credential approvals require only baseUrl, authMode and keySha256")
        endpoint(credential["baseUrl"])
        if credential["authMode"] not in ("api-key", "bearer"):
            raise ValueError("Invalid startup credential authMode")
        if not isinstance(credential["keySha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", credential["keySha256"]):
            raise ValueError("Startup credential keySha256 must be a SHA-256 hex digest")
    validate_options(value)
    return value


def read_preferences(path):
    path = Path(path)
    if path.stat().st_size > 65536:
        raise ValueError("Startup preferences exceed 64 KiB")
    return validate_preferences(json.loads(path.read_text()))


def resolve_startup(preferences, workspace, base_url, auth_mode, key):
    validate_preferences(preferences)
    normalized_key = key.strip()
    if not normalized_key or any(c in normalized_key for c in "\r\n\x00"):
        raise ValueError("API credential must contain one nonempty line")
    digest = hashlib.sha256(normalized_key.encode()).hexdigest()
    approved = any(endpoint(c["baseUrl"]) == endpoint(base_url)
                   and c["authMode"] == auth_mode
                   and hmac.compare_digest(c["keySha256"], digest)
                   for c in preferences.get("approvedCredentials", []))
    state = {
        "trustWorkspace": str(Path(workspace).resolve()) in preferences.get("trustedWorkspaces", []),
        "approveApiKey": auth_mode == "api-key" and approved,
    }
    state.update({name: preferences[name] for name in ("permissionMode", "effort", "ultracode", "model", "rememberModelEffort")
                  if name in preferences})
    return validate_state(state)


def validate_state(value):
    if not isinstance(value, dict) or set(value) - STATE_KEYS:
        raise ValueError("Unsupported runtime startup keys")
    for name in ("trustWorkspace", "approveApiKey"):
        if type(value.get(name)) is not bool:
            raise ValueError(f"Runtime startup {name} must be boolean")
    validate_options(value)
    return value


def validate_selection(value):
    """Only these two bounded preference values may cross back to the host."""
    if not isinstance(value, dict) or set(value) - {"model", "effort"}:
        raise ValueError("Unsupported exported preference keys")
    validate_model(value.get("model"))
    validate_options(value)
    return value


def read_selection(path):
    import os
    import stat
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 4096:
            raise ValueError("Exported preferences must be a small regular file")
        data = stream.read(4097)
        if len(data) > 4096:
            raise ValueError("Exported preferences exceed 4 KiB")
        return validate_selection(json.loads(data))


def save_selection(path, selection):
    """Merge only model/effort; serialize concurrent launcher exits atomically."""
    import fcntl
    import os
    import tempfile
    validate_selection(selection)
    path = Path(path)
    lock_fd = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        preferences = read_preferences(path)
        if not preferences.get("rememberModelEffort", False):
            return False
        preferences["model"] = selection["model"]
        if "effort" in selection:
            preferences["effort"] = selection["effort"]
        else:
            preferences.pop("effort", None)
        validate_preferences(preferences)
        fd, temporary = tempfile.mkstemp(prefix=".startup-selection-", dir=path.parent)
        try:
            with os.fdopen(fd, "w") as stream:
                json.dump(preferences, stream, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return True
