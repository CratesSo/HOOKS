#!/usr/bin/env python3
from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

from slop_shared import (
    MAX_FILE_BYTES,
    SKIP_PARTS as SHARED_SKIP_PARTS,
    build_search_path,
    relative_path,
    run_captured,
    which,
)


HOOK = Path(__file__).resolve().parent / "post_edit_slop_guard.py"
SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".rs", ".sh", ".bash", ".zsh"}
SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx"}
JS_DEF_RE = re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+(?P<name>[A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{")
IDENT_RE = re.compile(r"\b[A-Za-z_$][\w$]*\b")
LITERAL_RE = re.compile(r'(["\']).*?\1|\b\d+(?:\.\d+)?\b')
SKIP_PARTS = SHARED_SKIP_PARTS | {
    "venv",
    ".next",
    ".nuxt",
    ".turbo",
    ".cache",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
}
TOOLS = ("semgrep", "ast-grep", "shellcheck", "shfmt")
MAX_BLOCKERS = 80
MAX_WARNINGS = 240
MAX_ERRORS = 20
WARNINGS_PER_FILE = 25
HOOK_TIMEOUT_SECONDS = 20
PROGRESS_EVERY = 30


def repo_root() -> Path:
    result = run_captured(["git", "rev-parse", "--show-toplevel"], Path.cwd())
    if result.returncode == 0 and result.stdout.strip():
        return Path(result.stdout.strip()).resolve()
    return Path.cwd().resolve()


def is_junk(path: Path, root: Path) -> bool:
    try:
        rel = path.resolve().relative_to(root)
    except ValueError:
        rel = path
    return any(part in SKIP_PARTS for part in rel.parts)


def git_paths(root: Path) -> list[Path] | None:
    result = run_captured(["git", "ls-files", "--cached", "--others", "--exclude-standard"], root)
    if result.returncode != 0:
        return None
    return [root / line for line in result.stdout.splitlines() if line]


def walk_paths(root: Path) -> list[Path]:
    paths: list[Path] = []
    for directory, names, files in os.walk(root):
        base = Path(directory)
        names[:] = [name for name in names if name not in SKIP_PARTS]
        paths.extend(base / name for name in files)
    return paths


def candidate_paths(root: Path) -> tuple[list[Path], int]:
    raw_paths = git_paths(root) or walk_paths(root)
    candidates: list[Path] = []
    skipped = 0
    for path in raw_paths:
        if is_junk(path, root) or path.suffix not in SUFFIXES:
            skipped += 1
            continue
        try:
            if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
                skipped += 1
                continue
        except OSError:
            skipped += 1
            continue
        candidates.append(path.resolve())
    return sorted(set(candidates)), skipped


def append_capped(items: list[str], text: str, cap: int) -> None:
    if len(items) >= cap:
        return
    items.extend(line for line in text.splitlines() if line.strip())
    del items[cap:]


class NameNormalizer(ast.NodeTransformer):
    def visit_arg(self, node: ast.arg) -> ast.arg:
        node.arg = "_"
        return node

    def visit_Attribute(self, node: ast.Attribute) -> ast.Attribute:
        self.generic_visit(node)
        node.attr = "_"
        return node

    def visit_Name(self, node: ast.Name) -> ast.Name:
        node.id = "_"
        return node

    def visit_Constant(self, node: ast.Constant) -> ast.Constant:
        node.value = type(node.value).__name__
        return node


def is_test_path(path: Path) -> bool:
    name = path.name.lower()
    return any(part.lower() in {"test", "tests", "__tests__"} for part in path.parts) or any(
        marker in name for marker in (".test.", ".spec.", "_test.")
    )


def python_pass_through(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    if len(node.body) != 1 or not isinstance(node.body[0], ast.Return):
        return False
    value = node.body[0].value
    return isinstance(value, ast.Call)


def python_fingerprints(path: Path) -> list[tuple[str, int, str]]:
    try:
        tree = ast.parse(path.read_text())
    except (OSError, SyntaxError, UnicodeDecodeError):
        return []

    fingerprints: list[tuple[str, int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end_line = getattr(node, "end_lineno", node.lineno)
        if end_line - node.lineno < 3 or python_pass_through(node):
            continue
        body = ast.Module(body=node.body, type_ignores=[])
        NameNormalizer().visit(body)
        fingerprints.append(("py:" + ast.dump(body, annotate_fields=False, include_attributes=False), node.lineno, node.name))
    return fingerprints


def js_body(lines: list[str], start: int) -> list[str]:
    body: list[str] = []
    depth = 0
    for line in lines[start:]:
        depth += line.count("{") - line.count("}")
        if depth <= 0:
            break
        body.append(line.strip())
    return body


def js_fingerprints(path: Path) -> list[tuple[str, int, str]]:
    try:
        lines = path.read_text().splitlines()
    except (OSError, UnicodeDecodeError):
        return []

    fingerprints: list[tuple[str, int, str]] = []
    for index, line in enumerate(lines):
        match = JS_DEF_RE.match(line)
        if match is None:
            continue
        body = [part for part in js_body(lines, index) if part and not part.startswith("//")]
        if len(body) < 3:
            continue
        compact = " ".join(body)
        if re.fullmatch(r"return\s+[A-Za-z_$][\w$\.]*\([^;]*\);?", compact):
            continue
        normalized = IDENT_RE.sub("_", LITERAL_RE.sub("_", compact))
        fingerprints.append(("js:" + normalized, index + 1, match.group("name")))
    return fingerprints


def duplicate_function_warnings(files: list[Path], root: Path) -> list[str]:
    groups: dict[str, list[tuple[Path, int, str]]] = defaultdict(list)
    for path in files:
        if path.suffix not in SOURCE_SUFFIXES or is_test_path(path):
            continue
        fingerprints = python_fingerprints(path) if path.suffix == ".py" else js_fingerprints(path)
        for fingerprint, line, name in fingerprints:
            groups[fingerprint].append((path, line, name))

    warnings: list[str] = []
    for matches in groups.values():
        file_count = len({path for path, _, _ in matches})
        if file_count < 3:
            continue
        for path, line, name in matches:
            warnings.append(
                f"{relative_path(path, root)}:L{line}: warn duplicate helper shape `{name}` "
                f"appears in {file_count} files; extract one canonical helper or inline."
            )
    return sorted(warnings)


def scan_file(path: Path, root: Path, env: dict[str, str]):
    payload = {
        "cwd": str(root),
        "hook_event_name": "PostToolUse",
        "tool_input": {"file_path": str(path)},
        "session_id": "slop-scan",
        "turn_id": "manual-scan",
        "model": "manual",
        "slop_scan_full_file_warnings": True,
        "slop_scan_max_warnings": WARNINGS_PER_FILE,
    }
    try:
        return run_captured(
            [sys.executable, str(HOOK)],
            Path.cwd(),
            env=env,
            input_text=json.dumps(payload),
            timeout=HOOK_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            [sys.executable, str(HOOK)],
            124,
            "",
            f"{relative_path(path, root)}: hook timed out after {HOOK_TIMEOUT_SECONDS}s",
        )


def main() -> int:
    root = repo_root()
    if not HOOK.exists():
        print(f"slop-scan: missing hook script: {HOOK}", file=sys.stderr)
        return 2

    env = dict(os.environ)
    env["PATH"] = build_search_path(root)
    missing_tools = [tool for tool in TOOLS if which(tool, root) is None]

    files, skipped = candidate_paths(root)
    blockers: list[str] = []
    warnings: list[str] = []
    errors: list[str] = []
    blocker_count = 0
    warning_count = 0
    error_count = 0

    print(
        f"slop-scan: scanning {len(files)} files; progress every {PROGRESS_EVERY}; "
        f"per-file timeout {HOOK_TIMEOUT_SECONDS}s",
        file=sys.stderr,
        flush=True,
    )
    with tempfile.TemporaryDirectory(prefix="slop-scan-") as tmp:
        env["HOOK_METRICS_DB_PATH"] = str(Path(tmp) / "hook_metrics.db")
        for index, path in enumerate(files, start=1):
            result = scan_file(path, root, env)
            if result.returncode == 2:
                blocker_count += 1
                append_capped(blockers, result.stderr, MAX_BLOCKERS)
            elif result.returncode == 0 and result.stderr:
                warning_count += 1
                append_capped(warnings, result.stderr, MAX_WARNINGS)
            elif result.returncode != 0:
                error_count += 1
                append_capped(errors, f"{path}: hook exited {result.returncode}\n{result.stderr}", MAX_ERRORS)
            if index % PROGRESS_EVERY == 0 or index == len(files):
                print(f"{index}/{len(files)} scanned", file=sys.stderr, flush=True)
        duplicate_warnings = duplicate_function_warnings(files, root)
        if duplicate_warnings:
            warning_count += len(duplicate_warnings)
            append_capped(warnings, "\n".join(duplicate_warnings), MAX_WARNINGS)

    print("SLOP SCAN")
    print(f"root: {root}")
    print(f"files scanned: {len(files)}")
    print(f"files skipped: {skipped}")
    print(f"blocker count: {blocker_count}")
    print(f"warning count: {warning_count}")
    print(f"runner error count: {error_count}")
    print(f"missing tools: {', '.join(missing_tools) if missing_tools else 'none'}")
    print()

    if blockers:
        print("BLOCKERS")
        print("\n".join(blockers))
        print()
    if warnings:
        print("WARNINGS")
        print("\n".join(warnings))
        print()
    if errors:
        print("RUNNER ERRORS")
        print("\n".join(errors))
        print()

    print("Coverage: Semgrep uses the local hooky rules for Python and JS/TS only.")
    print("Coverage: Rust and shell checks come from ast-grep, shellcheck, and shfmt through the hook script.")
    print("Note: slop-scan checks advisory warnings across clean tracked files too.")
    return 1 if blockers or errors else 0


if __name__ == "__main__":
    raise SystemExit(main())