#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
template="$repo_root/hooks.json.template"
hooks_dir="$repo_root"
codex_dir="${HOME}/.codex"
target="$codex_dir/hooks.json"
python3_path="$(command -v python3 || true)"

if [[ ! -f "$template" || ! -d "$repo_root/hooks" ]]; then
	echo "error: run this installer from a cloned HOOKS repository" >&2
	exit 1
fi

for script in bash_pre_guard.py bash_post_guard.py post_edit_slop_guard.py stop_slop_guard.py; do
	if [[ ! -f "$repo_root/hooks/$script" ]]; then
		echo "error: missing hook script: hooks/$script" >&2
		exit 1
	fi
done

if [[ -z "$python3_path" ]]; then
	echo "error: python3 is required but was not found on PATH" >&2
	exit 1
fi

mkdir -p "$codex_dir"

backup=""
if [[ -f "$target" ]]; then
	backup="$target.bak-$(date +%Y%m%d-%H%M%S)"
	cp "$target" "$backup"
fi

python3 - "$template" "$target" "$hooks_dir" "$python3_path" <<'PY'
from pathlib import Path
import json
import sys

template = Path(sys.argv[1])
target = Path(sys.argv[2])
hooks_dir = sys.argv[3]
python3_path = sys.argv[4]
text = template.read_text().replace("__HOOKS_DIR__", hooks_dir).replace("__PYTHON3__", python3_path)
json.loads(text)
target.write_text(text)
PY

if [[ -n "$backup" ]]; then
	echo "Backed up existing hooks config: $backup"
fi

echo "Installed Codex hooks config: $target"
