#!/usr/bin/env python3
"""Post-tool guard for shell output.

Warns when shell output appears to contain common secret formats. The hook does
not print the secret value.
"""

from __future__ import annotations

import json
import re
import sys

SECRET_PATTERNS = [
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}")),
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("generic secret assignment", re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[=:]\s*['\"]?[^\s'\"]{12,}")),
]


def read_text() -> str:
    raw = sys.stdin.read()
    if not raw.strip():
        return ""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return raw
    return json.dumps(data, ensure_ascii=False)


def main() -> int:
    text = read_text()
    hits = [name for name, pattern in SECRET_PATTERNS if pattern.search(text)]
    if hits:
        print("Warning: shell output may contain sensitive data: " + ", ".join(hits), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
