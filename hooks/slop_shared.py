from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

HOOKS_ROOT = Path(__file__).resolve().parent.parent
MAX_FILE_BYTES = 200_000
TOOL_BIN_DIR = Path(
    os.environ.get(
        "HOOKY_SLOP_TOOL_BIN",
        str(HOOKS_ROOT / ".tools" / "bin"),
    )
)
REQUIRED_ANALYZERS = {"ast-grep", "semgrep", "shellcheck", "shfmt"}
PATH_PREFIXES = [
    str(TOOL_BIN_DIR),
    str(Path.home() / ".local" / "bin"),
    str(Path.home() / "Library" / "Python" / "3.9" / "bin"),
    str(Path.home() / ".local" / "node" / "node-v22.22.1-darwin-arm64" / "bin"),
    "/opt/homebrew/bin",
    "/usr/local/bin",
]
SKIP_PARTS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "node_modules",
    "dist",
    "build",
    "coverage",
    "vendor",
    "target",
    "DerivedData",
}


def build_search_path(root: Path) -> str:
    local_bins = [str(directory / "node_modules" / ".bin") for directory in (root, *root.parents)]
    return os.pathsep.join([*local_bins, *PATH_PREFIXES, os.environ.get("PATH", "")])


def which(name: str, root: Path) -> str | None:
    return shutil.which(name, path=build_search_path(root))


def required_tool_missing_message(name: str) -> str | None:
    if name not in REQUIRED_ANALYZERS:
        return None
    if which(name, Path.cwd()) is not None:
        return None
    return f"required analyzer missing: {name}; install it on PATH or set HOOKY_SLOP_TOOL_BIN"


def relative_path(path: Path, root: Path) -> str:
    try:
        return os.path.relpath(path, start=root)
    except ValueError:
        return str(path)


def run_captured(
    command: list[str],
    cwd: Path,
    *,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
