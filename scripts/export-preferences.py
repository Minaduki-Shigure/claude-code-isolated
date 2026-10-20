#!/usr/bin/env python3
"""Export only the two permitted status-line fields to the disposable outbox."""
import json
import os
from pathlib import Path
import sys
import tempfile

from startup_config import validate_selection, validate_state


def main():
    startup_path = Path("/config/startup.json")
    if startup_path.stat().st_size > 65536:
        return
    startup = validate_state(json.loads(startup_path.read_text()))
    if not startup.get("rememberModelEffort", False):
        return
    # The native status-line payload can include transcript paths and workspace
    # metadata. Never retain, print, or forward that payload.
    payload = sys.stdin.buffer.read(65537)
    if len(payload) > 65536:
        return
    value = json.loads(payload)
    selection = {"model": value["model"]["id"]}
    effort = (value.get("effort") or {}).get("level")
    if effort is not None:
        selection["effort"] = effort
    validate_selection(selection)
    directory = Path("/var/lib/claude-preferences")
    fd, temporary = tempfile.mkstemp(prefix=".selection-", dir=directory)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(selection, stream, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, directory / "selection.json")
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        # A malformed status-line update must not expose its contents or disrupt
        # the interactive CLI; the host separately validates every exported file.
        pass
