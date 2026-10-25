#!/usr/bin/env bash
# Smoke test: creates a test certificate, adds a user and signs a PDF.
# Usage: scripts/smoke-test.sh [path/to/firma]
# Requires openssl and python3 (or python). Works on macOS, Linux and Windows (Git Bash).
set -euo pipefail

FIRMA="${1:-target/release/firma}"
[ -x "$FIRMA" ] || [ -x "$FIRMA.exe" ] || { echo "binary not found: $FIRMA" >&2; exit 1; }
FIRMA="$(cd "$(dirname "$FIRMA")" && pwd)/$(basename "$FIRMA")"
SCRIPTS="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export FIRMA_HOME="$WORK/home" FIRMA_PASSWORD=smoke-test
export MSYS_NO_PATHCONV=1 # Git Bash on Windows: keep "/CN=..." from being rewritten as a path
PY="$(command -v python3 || command -v python)"

cd "$WORK"
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 2 -subj "/CN=Smoke CA" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout u.key -out u.csr -subj "/CN=Smoke User" 2>/dev/null
openssl x509 -req -in u.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out u.crt -days 1 2>/dev/null
openssl pkcs12 -export -inkey u.key -in u.crt -certfile ca.crt -out u.p12 -passout "pass:$FIRMA_PASSWORD"

"$PY" "$SCRIPTS/test-pdf.py" doc.pdf

"$FIRMA" --version
"$FIRMA" user add smoke --cert u.p12
"$FIRMA" user list
"$FIRMA" sign doc.pdf -u smoke -o signed.pdf --at 1:bottom-right --stamp --reason "Smoke test"

grep -aq "/ETSI.CAdES.detached" signed.pdf
grep -aq "/ByteRange" signed.pdf
grep -aq "/Matrix" signed.pdf # appearance rotated for the /Rotate 90 page
echo "OK: signed.pdf created ($(wc -c < signed.pdf) bytes)"
