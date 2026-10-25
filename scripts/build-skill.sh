#!/usr/bin/env bash
# Packages the sign-pdf Agent Skill as a zip with the skill folder at its root (the layout
# claude.ai and other agents expect).
#
# Usage: scripts/build-skill.sh [OUT.zip] [PLATFORM=BINARY ...]
#   PLATFORM is macos-universal, x86_64-linux, aarch64-linux or x86_64-windows. Bundled binaries let
#   the skill work without installing anything, e.g. in sandboxes without network access.
# Example: scripts/build-skill.sh dist/sign-pdf-skill.zip x86_64-linux=target/x86_64-unknown-linux-musl/release/firma
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
src="$root/plugins/firma/skills/sign-pdf"
out="${1:-$root/dist/sign-pdf-skill.zip}"
shift || true
case "$out" in /*) ;; *) out="$PWD/$out" ;; esac

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
cp -R "$src" "$stage/sign-pdf"

for spec in "$@"; do
    platform="${spec%%=*}"
    binary="${spec#*=}"
    case "$platform" in
        macos-universal | x86_64-linux | aarch64-linux) name=firma ;;
        x86_64-windows) name=firma.exe ;;
        *) echo "unknown platform: $platform" >&2; exit 1 ;;
    esac
    mkdir -p "$stage/sign-pdf/bin/$platform"
    cp "$binary" "$stage/sign-pdf/bin/$platform/$name"
    chmod 755 "$stage/sign-pdf/bin/$platform/$name"
done

mkdir -p "$(dirname "$out")"
rm -f "$out"
(cd "$stage" && zip -qr -X "$out" sign-pdf)
echo "built $out"
unzip -Z1 "$out" | sed 's/^/  /'
