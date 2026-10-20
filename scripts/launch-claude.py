#!/usr/bin/env python3
"""Apply initial preferences without locking the interactive model or effort."""
import json
import os
from pathlib import Path
import sys

from startup_config import validate_model, validate_state


def main():
    path = Path("/config/startup.json")
    if path.stat().st_size > 65536:
        raise ValueError("Runtime startup preferences exceed 64 KiB")
    startup = validate_state(json.loads(path.read_text()))
    environment = dict(os.environ)
    fallback = environment.pop("ANTHROPIC_MODEL", None)
    environment.pop("CLAUDE_CODE_EFFORT_LEVEL", None)
    command = ["/usr/local/bin/claude", "--setting-sources", "user", "--no-chrome"]
    model = startup.get("model", fallback)
    if model:
        validate_model(model)
        command.extend(["--model", model])
    if "effort" in startup:
        command.extend(["--effort", startup["effort"]])
    # Native option parsing uses the last occurrence, so explicit caller flags
    # still take precedence over these initial preferences.
    command.extend(sys.argv[1:])
    remember_ui = startup.get("rememberPermissionMode", False) or startup.get("rememberUltracode", False)
    print_mode = any(arg in ("-p", "--print") or arg.startswith("--print=") for arg in sys.argv[1:])
    if remember_ui and not print_mode and sys.stdin.isatty() and sys.stdout.isatty():
        from preference_output import write_selection
        from terminal_preferences import run_pty

        def changed(values):
            selected = {}
            for name, flag in (("permissionMode", "rememberPermissionMode"),
                               ("ultracode", "rememberUltracode")):
                if startup.get(flag, False) and name in values:
                    selected[name] = values[name]
            if selected:
                try:
                    write_selection(selected)
                except (OSError, ValueError, TypeError):
                    pass

        return run_pty(command, changed, env=environment)
    os.execve(command[0], command, environment)


if __name__ == "__main__":
    sys.exit(main())
