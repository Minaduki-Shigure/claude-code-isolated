"""Merge only bounded preferences; runtime state and locks stay in tmpfs."""
import fcntl
import json
import os
from pathlib import Path
import secrets
import stat
import time

from startup_config import validate_options, validate_selection

STATE_DIRECTORY = Path("/home/node/.claude")
OUTPUT_DIRECTORY = Path("/var/lib/claude-preferences")
LOCK_NAME = ".preference-output.lock"
PENDING_NAME = ".preference-output.pending.json"
OUTPUT_NAME = "selection.json"
MAX_BYTES = 4096
LOCK_WAIT_SECONDS = 0.25
FIELDS = {"model", "effort", "permissionMode", "ultracode"}


def _validate_update(value):
    if not isinstance(value, dict) or set(value) - FIELDS:
        raise ValueError("Unsupported preference output keys")
    validate_options(value)
    return dict(value)


def _regular_file(metadata):
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_BYTES
            or metadata.st_nlink != 1 or metadata.st_uid != os.geteuid()):
        raise ValueError("Preference output must be a small owned regular file")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate preference output keys")
        result[key] = value
    return result


def _read_pending(directory_fd):
    try:
        fd = os.open(PENDING_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory_fd)
    except FileNotFoundError:
        return {}
    with os.fdopen(fd, "rb") as stream:
        _regular_file(os.fstat(stream.fileno()))
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("Preference output exceeds 4 KiB")
    return _validate_update(json.loads(data, object_pairs_hook=_unique_object))


def _open_directory(path):
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def _acquire_lock(fd):
    deadline = time.monotonic() + LOCK_WAIT_SECONDS
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BlockingIOError("Preference output lock is busy") from None
            time.sleep(min(0.005, remaining))


def _atomic_write(directory_fd, name, data):
    # Replacing a path never follows its target. Reject unexpected existing
    # objects as well, so corruption cannot silently become a successful export.
    try:
        _regular_file(os.stat(name, dir_fd=directory_fd, follow_symlinks=False))
    except FileNotFoundError:
        pass
    temporary = f".{name}.{secrets.token_hex(16)}.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=directory_fd)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, name, src_dir_fd=directory_fd,
                   dst_dir_fd=directory_fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass


def write_selection(update, clear_effort=False):
    """Serialize partial writers and export only a complete, strict selection.

    Missing mode/ultracode values preserve the most recently observed values.
    A status-line update may explicitly clear an unsupported effort level.
    Exceptions contain no payload and are handled by the observing caller.
    """
    update = _validate_update(update)
    if type(clear_effort) is not bool:
        raise ValueError("clear_effort must be boolean")
    state_fd = _open_directory(STATE_DIRECTORY)
    try:
        lock_fd = os.open(
            LOCK_NAME, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600, dir_fd=state_fd,
        )
        with os.fdopen(lock_fd, "r+b") as lock:
            _regular_file(os.fstat(lock.fileno()))
            _acquire_lock(lock.fileno())
            os.fchmod(lock.fileno(), 0o600)
            selection = _read_pending(state_fd)
            selection.update(update)
            if clear_effort and "effort" not in update:
                selection.pop("effort", None)
            _validate_update(selection)
            data = (json.dumps(selection, separators=(",", ":")) + "\n").encode()
            if len(data) > MAX_BYTES:
                raise ValueError("Preference output exceeds 4 KiB")
            _atomic_write(state_fd, PENDING_NAME, data)
            if "model" not in selection:
                return False
            validate_selection(selection)
            output_fd = _open_directory(OUTPUT_DIRECTORY)
            try:
                _atomic_write(output_fd, OUTPUT_NAME, data)
            finally:
                os.close(output_fd)
            return True
    finally:
        os.close(state_fd)
