#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from slop_shared import (
    MAX_FILE_BYTES,
    SKIP_PARTS,
    build_search_path,
    relative_path,
    required_tool_missing_message,
    run_captured,
    which,
)

MAX_FINDINGS = 4
MAX_WARNINGS = 4
HOOKS_DIR = Path(__file__).resolve().parent
SEMGREP_RULES = HOOKS_DIR / "semgrep_slop_rules.yml"
SHELL_SUFFIXES = {".sh", ".bash", ".zsh"}
SEMGREP_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx"}
PLACEHOLDER_SECRET_RE = re.compile(r"(your-secret-key-here|changeme|replace-me|dummy-secret|placeholder)", re.IGNORECASE)
DEBUG_ARTIFACT_RE = re.compile(r"\b(print|console\.log)\s*\([^)]*(debug|todo|trace)", re.IGNORECASE)
NOOP_TIMING_RE = re.compile(r"\b(time\.sleep\(0\)|setTimeout\([^,]+,\s*0\))")
TS_ANY_RE = re.compile(r"\b(?:as\s+any|:\s*any\b)")
NESTED_JS_TERNARY_RE = re.compile(r"(?<!\?)\?(?![.?]).*(?<!\?)\?(?![.?]).*:")


def load_payload() -> dict[str, object]:
    try:
        return json.load(sys.stdin)
    except json.JSONDecodeError:
        return {}


def patch_file_paths(command: str) -> list[str]:
    paths: list[str] = []
    for line in command.splitlines():
        match = re.match(r"\*\*\* (?:Add|Update) File: (.+)$", line)
        if match is not None:
            paths.append(match.group(1))
    return paths


def extract_file_paths(payload: dict[str, object]) -> list[Path]:
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return []
    raw_paths = [tool_input.get("file_path"), tool_input.get("path")]
    command = tool_input.get("command")
    if isinstance(command, str):
        raw_paths.extend(patch_file_paths(command))
    paths: list[Path] = []
    seen: set[Path] = set()
    for raw_path in raw_paths:
        if not isinstance(raw_path, str):
            continue
        path = Path(raw_path).expanduser()
        if not path.is_absolute():
            cwd = payload.get("cwd")
            if isinstance(cwd, str) and cwd:
                path = Path(cwd).expanduser() / path
        path = path.resolve()
        if path in seen or not path.exists() or not path.is_file():
            continue
        if any(part in SKIP_PARTS for part in path.parts):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        seen.add(path)
        paths.append(path)
    return paths


def project_root(file_path: Path, payload: dict[str, object]) -> Path:
    for directory in (file_path.parent, *file_path.parent.parents):
        if (directory / ".git").exists():
            return directory.resolve()
    cwd = payload.get("cwd")
    if isinstance(cwd, str) and cwd:
        root = Path(cwd).expanduser()
        if root.exists():
            return root.resolve()
    return file_path.parent.resolve()


def run_command(command: list[str], root: Path) -> subprocess.CompletedProcess[str] | None:
    binary = which(command[0], root)
    if binary is None:
        return None
    env = dict(os.environ)
    env["PATH"] = build_search_path(root)
    if command[0] == "semgrep":
        with tempfile.TemporaryDirectory(prefix="hooks-semgrep-") as log_dir:
            env["SEMGREP_LOG_FILE"] = str(Path(log_dir) / "semgrep.log")
            return run_captured([binary, *command[1:]], root, env=env)
    return run_captured([binary, *command[1:]], root, env=env)


def git_diff_added_lines(file_path: Path, root: Path) -> list[tuple[int, str]]:
    result = run_command(["git", "diff", "--no-ext-diff", "--unified=0", "--", str(file_path)], root)
    if result is None or result.returncode not in {0, 1}:
        return []
    if not result.stdout:
        rel = relative_path(file_path, root)
        tracked = run_command(["git", "ls-files", "--error-unmatch", "--", rel], root)
        if tracked is not None and tracked.returncode != 0:
            return [(line_number, line) for line_number, line in enumerate(file_path.read_text().splitlines(), 1)]
        return []
    lines: list[tuple[int, str]] = []
    current_line = 0
    for raw_line in result.stdout.splitlines():
        if raw_line.startswith("@@"):
            match = re.search(r"\+(\d+)(?:,(\d+))?", raw_line)
            current_line = int(match.group(1)) if match else 0
            continue
        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            lines.append((current_line, raw_line[1:]))
            current_line += 1
        elif raw_line.startswith(" "):
            current_line += 1
    return lines


def all_file_lines(file_path: Path) -> list[tuple[int, str]]:
    try:
        return [(line_number, line) for line_number, line in enumerate(file_path.read_text().splitlines(), 1)]
    except OSError:
        return []


def warning_key(warning: str) -> str:
    return warning.split(": warn ", 1)[-1]


def line_slop_warning(file_path: Path, root: Path, line_number: int, line: str) -> str | None:
    target = relative_path(file_path, root)
    if "re.compile" in line:
        return None
    secret_match = PLACEHOLDER_SECRET_RE.search(line)
    if secret_match:
        return f"{target}:L{line_number}: warn placeholder `{secret_match.group(0)}`; remove or read config."
    if DEBUG_ARTIFACT_RE.search(line):
        return f"{target}:L{line_number}: warn debug print/log; remove or use repo logger."
    if NOOP_TIMING_RE.search(line):
        return f"{target}:L{line_number}: warn no-op timing; delete unless measured."
    if file_path.suffix in {".ts", ".tsx"} and TS_ANY_RE.search(line):
        return f"{target}:L{line_number}: warn `any`; add real type or narrow."
    stripped = line.strip()
    if file_path.suffix == ".py" and stripped.count(" if ") >= 2 and " else " in stripped:
        return f"{target}:L{line_number}: warn nested ternary; use explicit branches."
    if file_path.suffix in {".js", ".jsx", ".ts", ".tsx"} and NESTED_JS_TERNARY_RE.search(stripped):
        return f"{target}:L{line_number}: warn nested ternary; use explicit branches."
    return None


def diff_warn_findings(file_path: Path, root: Path, *, full_file: bool = False, max_warnings: int = MAX_WARNINGS) -> list[str]:
    added_lines = all_file_lines(file_path) if full_file else git_diff_added_lines(file_path, root)
    if not added_lines:
        return []
    warnings: list[str] = []
    seen: set[str] = set()
    for line_number, line in added_lines:
        if len(warnings) >= max_warnings:
            break
        warning = line_slop_warning(file_path, root, line_number, line)
        if warning and warning_key(warning) not in seen:
            warnings.append(warning)
            seen.add(warning_key(warning))
    return warnings


def shellcheck_findings(file_path: Path, root: Path) -> list[str]:
    missing = required_tool_missing_message("shellcheck")
    if missing:
        return [missing]
    result = run_command(["shellcheck", "--exclude=SC2148", "--format=json1", str(file_path)], root)
    if result is None or result.returncode == 0:
        return []
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return ["shellcheck: failed to parse shell script cleanly."]
    comments = payload.get("comments")
    if not isinstance(comments, list):
        return []
    lines: list[str] = []
    target = relative_path(file_path, root)
    for comment in comments:
        if len(lines) >= MAX_FINDINGS:
            break
        if not isinstance(comment, dict):
            continue
        line = comment.get("line")
        code = comment.get("code")
        message = comment.get("message")
        if isinstance(line, int) and isinstance(code, int) and isinstance(message, str):
            lines.append(f"{target}:L{line}: shellcheck SC{code} {message.splitlines()[0].strip()}")
    return lines


def shfmt_findings(file_path: Path, root: Path) -> list[str]:
    missing = required_tool_missing_message("shfmt")
    if missing:
        return [missing]
    result = run_command(["shfmt", "-d", str(file_path)], root)
    if result is None or result.returncode == 0:
        return []
    return [f"{relative_path(file_path, root)}: shfmt would rewrite this shell file."]


def semgrep_findings(file_path: Path, root: Path) -> list[str]:
    if file_path.suffix not in SEMGREP_SUFFIXES:
        return []
    missing = required_tool_missing_message("semgrep")
    if missing:
        return [missing]
    result = run_command(["semgrep", "scan", "--quiet", "--config", str(SEMGREP_RULES), "--json", str(file_path)], root)
    if result is None:
        return []
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    results = payload.get("results")
    if not isinstance(results, list):
        return []
    lines: list[str] = []
    target = relative_path(file_path, root)
    for item in results:
        if len(lines) >= MAX_FINDINGS:
            break
        if not isinstance(item, dict):
            continue
        start = item.get("start")
        extra = item.get("extra")
        line = start.get("line") if isinstance(start, dict) else None
        message = extra.get("message") if isinstance(extra, dict) else None
        if isinstance(line, int) and isinstance(message, str):
            lines.append(f"{target}:L{line}: semgrep {message.splitlines()[0].strip()}")
    return lines


def collect_findings(file_path: Path, root: Path) -> list[str]:
    findings: list[str] = []
    if file_path.suffix in SHELL_SUFFIXES:
        findings.extend(shfmt_findings(file_path, root))
        if len(findings) < MAX_FINDINGS:
            findings.extend(shellcheck_findings(file_path, root))
        return findings[:MAX_FINDINGS]
    findings.extend(semgrep_findings(file_path, root))
    return findings[:MAX_FINDINGS]


def slop_guard_result(file_path: Path, payload: dict[str, object]) -> tuple[int, str]:
    root = project_root(file_path.resolve(), payload)
    file_path = file_path.resolve()
    findings = collect_findings(file_path, root)
    full_file_warnings = payload.get("slop_scan_full_file_warnings") is True
    max_warnings = payload.get("slop_scan_max_warnings", MAX_WARNINGS)
    if not isinstance(max_warnings, int) or max_warnings < 1:
        max_warnings = MAX_WARNINGS
    warnings = [] if findings else diff_warn_findings(file_path, root, full_file=full_file_warnings, max_warnings=max_warnings)
    if not findings and not warnings:
        return 0, ""
    target = relative_path(file_path, root)
    if findings:
        lines = [f"slop block {target}:"]
        lines.extend(f"- {finding}" for finding in findings)
        return 2, "\n".join(lines) + "\n"
    lines = [f"slop warning {target}: revise."]
    lines.extend(f"- {warning}" for warning in warnings)
    return 0, "\n".join(lines) + "\n"


def main() -> int:
    payload = load_payload()
    file_paths = extract_file_paths(payload)
    if not file_paths:
        return 0
    final_exit_code = 0
    for file_path in file_paths:
        exit_code, message = slop_guard_result(file_path, payload)
        if message:
            sys.stderr.write(message)
        final_exit_code = max(final_exit_code, exit_code)
    return final_exit_code


if __name__ == "__main__":
    raise SystemExit(main())
