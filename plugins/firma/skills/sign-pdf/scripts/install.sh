#!/bin/sh
# Installs the latest firma release for macOS or Linux into ~/.local/bin (or $FIRMA_INSTALL_DIR),
# verifying the archive against the release's SHA256SUMS.txt.
set -eu
repo="${FIRMA_REPO:-e98cuenc/firma-cli}"
dest="${FIRMA_INSTALL_DIR:-$HOME/.local/bin}"
case "$(uname -s)-$(uname -m)" in
    Darwin-*) name=macos-universal ;;
    Linux-x86_64 | Linux-amd64) name=x86_64-linux ;;
    Linux-aarch64 | Linux-arm64) name=aarch64-linux ;;
    *) echo "unsupported platform: $(uname -s) $(uname -m)" >&2; exit 1 ;;
esac
base="https://github.com/$repo/releases/latest/download"
archive="firma-$name.tar.gz"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -o "$tmp/$archive" "$base/$archive"
curl -fsSL -o "$tmp/SHA256SUMS.txt" "$base/SHA256SUMS.txt"
expected="$(awk -v f="$archive" '$2 == f || $2 == "*"f { print $1 }' "$tmp/SHA256SUMS.txt")"
if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$tmp/$archive" | cut -d' ' -f1)"
else
    actual="$(shasum -a 256 "$tmp/$archive" | cut -d' ' -f1)"
fi
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
    echo "checksum mismatch for $archive; not installing" >&2
    exit 1
fi

tar -xzf "$tmp/$archive" -C "$tmp" firma
mkdir -p "$dest"
cp "$tmp/firma" "$dest/firma.new"
chmod 755 "$dest/firma.new"
mv "$dest/firma.new" "$dest/firma"
echo "installed $("$dest/firma" --version) to $dest/firma"
case ":$PATH:" in
    *":$dest:"*) ;;
    *) echo "note: $dest is not on your PATH" ;;
esac
