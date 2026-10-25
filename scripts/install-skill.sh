#!/usr/bin/env bash
# Installs the sign-pdf skill from this checkout for local agents:
#   Claude Code  ~/.claude/skills/sign-pdf
#   Codex (and other Agent Skills readers)  ~/.agents/skills/sign-pdf
# Usage: scripts/install-skill.sh [--claude] [--codex]   (default: both)
# Claude Code users can instead install the plugin: /plugin install firma --marketplace e98cuenc/firma-cli
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
src="$root/plugins/firma/skills/sign-pdf"
targets=()
for arg in "$@"; do
    case "$arg" in
        --claude) targets+=("$HOME/.claude/skills") ;;
        --codex) targets+=("$HOME/.agents/skills") ;;
        *) echo "usage: $0 [--claude] [--codex]" >&2; exit 1 ;;
    esac
done
[ ${#targets[@]} -gt 0 ] || targets=("$HOME/.claude/skills" "$HOME/.agents/skills")

for dir in "${targets[@]}"; do
    mkdir -p "$dir"
    rm -rf "$dir/sign-pdf"
    cp -R "$src" "$dir/sign-pdf"
    echo "installed skill to $dir/sign-pdf"
done
command -v firma >/dev/null 2>&1 || echo "note: the firma binary is not on your PATH; run $src/scripts/install.sh"
