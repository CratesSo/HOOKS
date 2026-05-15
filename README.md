# HOOKS

Portable Codex hook configuration and guard scripts.

This repo publishes a small, public-safe Codex hooks setup. It installs local guard hooks for shell commands, shell output, file edits, and session stop checks.

## What is included

- `hooks.json.template`: Codex hook config rendered by the installer.
- `hooks/`: Python guard scripts, slop scan rules, and shared scanner helpers.
- `scripts/install.sh`: installer that renders the template into `~/.codex/hooks.json`.

The published config intentionally excludes private machine state, Codex trusted hook hashes, MCP configuration, logs, sessions, caches, and `context-mode` hooks.
It also excludes Hooky's private metrics database plumbing.

## Install

Install the analyzer tools used by the edit and scan hooks:

```sh
brew install semgrep ast-grep shellcheck shfmt
```

If you keep those binaries outside your normal `PATH`, set `HOOKY_SLOP_TOOL_BIN` to the directory that contains them.
The installer renders hook commands with the `python3` found on your `PATH`.

Clone the repo and run the installer:

```sh
git clone https://github.com/CratesSo/HOOKS.git
cd HOOKS
./scripts/install.sh
```

The installer:

1. Verifies it is running from a cloned HOOKS repo.
2. Creates `~/.codex` if needed.
3. Backs up an existing `~/.codex/hooks.json` to `~/.codex/hooks.json.bak-YYYYMMDD-HHMMSS`.
4. Writes a rendered `~/.codex/hooks.json` with absolute paths to this clone's `hooks/` scripts.

Codex may ask you to trust the installed hooks the next time they run.

## Restore or uninstall

To restore a backup:

```sh
cp ~/.codex/hooks.json.bak-YYYYMMDD-HHMMSS ~/.codex/hooks.json
```

To uninstall these hooks without restoring another config:

```sh
rm ~/.codex/hooks.json
```

## Notes

These hooks are intentionally conservative and public-safe. They are not a sandbox, security boundary, or substitute for reviewing commands and file changes. They provide lightweight warnings or blocks for common risky patterns.
