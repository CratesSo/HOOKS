#!/usr/bin/env python3
"""Stop hook that reminds users about dirty Git state.

The hook is best-effort and warning-only. It checks the current working
directory from the hook payload when available, otherwise the process cwd.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def read_payload() -> dict:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def find_cwd(value) -> Path:
    if isinstance(value, dict):
        for key in ("cwd", "working_dir", "workdir"):
            candidate = value.get(key)
            if isinstance(candidate, str):
                return Path(candidate)
        for item in value.values():
            found = find_cwd(item)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = find_cwd(item)
            if found:
                return found
    return Path.cwd()


def main() -> int:
    cwd = find_cwd(read_payload())
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain=v1"],
            cwd=cwd,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
    except (FileNotFoundError, NotADirectoryError, subprocess.SubprocessError, OSError):
        return 0
    if result.returncode == 0 and result.stdout.strip():
        print("Warning: Git working tree has uncommitted changes.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
