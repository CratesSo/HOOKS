#!/usr/bin/env python3
"""Pre-tool guard for shell commands.

Reads Codex hook JSON from stdin. Blocks a small set of destructive shell
patterns and otherwise exits 0.
"""

from __future__ import annotations

import json
import re
import sys

BLOCKED_PATTERNS = [
    (r"\brm\s+-rf\s+/(?:\s|$)", "refuses recursive deletion of filesystem root"),
    (r"\bsudo\s+rm\s+-rf\b", "refuses privileged recursive deletion"),
    (r"\bmkfs(?:\.[a-z0-9]+)?\b", "refuses filesystem formatting commands"),
    (r"\bdd\b.*\bof=/dev/", "refuses raw writes to block devices"),
    (r"\bchmod\s+-R\s+777\b", "refuses broad world-writable chmod"),
    (r"\b(shred|srm)\b", "refuses destructive secure deletion commands"),
]


def read_payload() -> dict:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def find_command(value) -> str:
    if isinstance(value, dict):
        for key in ("command", "cmd", "input"):
            candidate = value.get(key)
            if isinstance(candidate, str):
                return candidate
        for candidate in value.values():
            found = find_command(candidate)
            if found:
                return found
    elif isinstance(value, list):
        for candidate in value:
            found = find_command(candidate)
            if found:
                return found
    return ""


def main() -> int:
    payload = read_payload()
    command = find_command(payload)
    for pattern, reason in BLOCKED_PATTERNS:
        if re.search(pattern, command):
            print(f"Blocked shell command: {reason}.", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
