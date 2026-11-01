#!/bin/sh
# agentfence installer: curl -fsSL https://raw.githubusercontent.com/hamarshehmhmd/agentfence/main/install.sh | sh
# 1. installs the agentfence CLI (uv tool > pipx > private venv in ~/.local/share/agentfence)
# 2. registers user-level hooks for Claude Code (~/.claude/settings.json) and Cursor (~/.cursor/hooks.json)
#    if those tools are present. Existing settings are merged, never replaced. Safe to re-run.
# Env: AGENTFENCE_REF=<git ref> (default main)  AGENTFENCE_NO_HOOKS=1 (skip step 2)
set -eu
REF="${AGENTFENCE_REF:-main}"
SRC="git+https://github.com/hamarshehmhmd/agentfence@${REF}"
say() { printf 'agentfence-install: %s\n' "$*"; }
die() { say "error: $*" >&2; exit 1; }

PY=""
for c in python3.13 python3.12 python3.11 python3; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
    PY="$c"; break
  fi
done

if command -v uv >/dev/null 2>&1; then
  say "installing with uv tool ($SRC)"
  uv tool install --force "$SRC" >/dev/null 2>&1 || die "uv tool install failed"
  BIN="$(uv tool dir --bin 2>/dev/null || echo "$HOME/.local/bin")"
elif command -v pipx >/dev/null 2>&1; then
  say "installing with pipx ($SRC)"
  pipx install --force "$SRC" >/dev/null
  BIN="${PIPX_BIN_DIR:-$HOME/.local/bin}"
else
  [ -n "$PY" ] || die "need Python >= 3.11 (or uv / pipx) on PATH"
  command -v git >/dev/null 2>&1 || die "need git to install from GitHub"
  VENV="$HOME/.local/share/agentfence/venv"
  say "installing into $VENV with $PY"
  "$PY" -m venv "$VENV"
  "$VENV/bin/python" -m pip install -q --upgrade "$SRC"
  BIN="$HOME/.local/bin"
  mkdir -p "$BIN"
  ln -sf "$VENV/bin/agentfence" "$BIN/agentfence"
fi

EXE="$BIN/agentfence"
[ -x "$EXE" ] || EXE="$(command -v agentfence || true)"
[ -n "$EXE" ] && [ -x "$EXE" ] || die "install finished but the agentfence command was not found"
say "installed $("$EXE" --version) at $EXE"

if [ "${AGENTFENCE_NO_HOOKS:-0}" != "1" ]; then
  hooked=0
  if [ -d "$HOME/.claude" ] || command -v claude >/dev/null 2>&1; then
    "$EXE" install claude --user --exe "$EXE" | sed 's/^/agentfence-install: /'; hooked=1
  fi
  if [ -d "$HOME/.cursor" ] || command -v cursor >/dev/null 2>&1 || command -v cursor-agent >/dev/null 2>&1; then
    "$EXE" install cursor --user --exe "$EXE" | sed 's/^/agentfence-install: /'; hooked=1
  fi
  [ "$hooked" = 1 ] || say "no Claude Code or Cursor config found; later run: agentfence install claude --user (or cursor)"
fi

case ":$PATH:" in *":$BIN:"*) ;; *) say "note: add $BIN to your PATH";; esac
say "done. try: agentfence check -- \"rm -rf ~\""
