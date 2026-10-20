#!/usr/bin/env python3
"""Read native model/effort and export only bounded preference values."""
import json
from pathlib import Path
import sys

from preference_output import write_selection
from startup_config import should_remember, validate_selection, validate_state


def main():
    startup_path = Path("/config/startup.json")
    if startup_path.stat().st_size > 65536:
        return
    startup = validate_state(json.loads(startup_path.read_text()))
    if not should_remember(startup):
        return
    # The native status-line payload can include transcript paths and workspace
    # metadata. Never retain, print, or forward that payload. A model ID also
    # anchors snapshots when only permission mode or ultracode is remembered.
    payload = sys.stdin.buffer.read(65537)
    if len(payload) > 65536:
        return
    value = json.loads(payload)
    selection = {"model": value["model"]["id"]}
    effort = (value.get("effort") or {}).get("level")
    if effort is not None:
        selection["effort"] = effort
    validate_selection(selection)
    write_selection(selection, clear_effort=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        # A malformed status-line update must not expose its contents or disrupt
        # the interactive CLI; the host separately validates every exported file.
        pass
