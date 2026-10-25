#!/bin/sh
# Prints the path of a usable firma binary: the one on the PATH, or the one bundled with this skill.
# Exits with status 1 if there is none (then run install.sh, after asking the user).
set -eu
if command -v firma >/dev/null 2>&1; then
    command -v firma
    exit 0
fi
here="$(cd "$(dirname "$0")/.." && pwd)"
case "$(uname -s)-$(uname -m)" in
    Darwin-*) bin="$here/bin/macos-universal/firma" ;;
    Linux-x86_64 | Linux-amd64) bin="$here/bin/x86_64-linux/firma" ;;
    Linux-aarch64 | Linux-arm64) bin="$here/bin/aarch64-linux/firma" ;;
    MINGW* | MSYS* | CYGWIN*) bin="$here/bin/x86_64-windows/firma.exe" ;;
    *) bin="" ;;
esac
if [ -n "$bin" ] && [ -f "$bin" ]; then
    chmod +x "$bin" 2>/dev/null || true
    echo "$bin"
    exit 0
fi
echo "firma is not installed and no bundled binary fits this platform" >&2
exit 1
