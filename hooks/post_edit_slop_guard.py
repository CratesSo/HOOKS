#!/usr/bin/env python3
"""Post-edit guard for common generated-code artifacts.

This is intentionally conservative: it reports warnings only and does not block
edits.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

WARN_EXTENSIONS = {".pyc", ".pyo", ".log", ".tmp", ".bak"}
WARN_NAMES = {".DS_Store"}


def read_payload() -> dict:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def collect_paths(value) -> list[str]:
    paths: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in {"path", "file", "filename"} and isinstance(item, str):
                paths.append(item)
            else:
                paths.extend(collect_paths(item))
    elif isinstance(value, list):
        for item in value:
            paths.extend(collect_paths(item))
    return paths


def main() -> int:
    payload = read_payload()
    warnings: list[str] = []
    for raw_path in collect_paths(payload):
        path = Path(raw_path)
        if path.name in WARN_NAMES or path.suffix in WARN_EXTENSIONS:
            warnings.append(raw_path)
    if warnings:
        print("Warning: edited generated or temporary-looking files: " + ", ".join(sorted(set(warnings))), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
