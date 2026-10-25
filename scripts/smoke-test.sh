#!/usr/bin/env bash
# Smoke test: creates a test certificate, adds a user and signs a PDF.
# Usage: scripts/smoke-test.sh [path/to/firma]
# Requires openssl and python3 (or python). Works on macOS, Linux and Windows (Git Bash).
set -euo pipefail

FIRMA="${1:-target/release/firma}"
[ -x "$FIRMA" ] || [ -x "$FIRMA.exe" ] || { echo "binary not found: $FIRMA" >&2; exit 1; }
FIRMA="$(cd "$(dirname "$FIRMA")" && pwd)/$(basename "$FIRMA")"
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

# Minimal one-page PDF (rotated 90°) with a correct xref table.
"$PY" - <<'EOF'
objs = [
    b"<< /Type /Catalog /Pages 2 0 R >>",
    b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Rotate 90 >>",
]
out = bytearray(b"%PDF-1.7\n")
offsets = []
for i, o in enumerate(objs, 1):
    offsets.append(len(out))
    out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
xref = len(out)
out += b"xref\n0 %d\n0000000000 65535 f\r\n" % (len(objs) + 1)
for off in offsets:
    out += b"%010d 00000 n\r\n" % off
out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
open("doc.pdf", "wb").write(bytes(out))
EOF

"$FIRMA" --version
"$FIRMA" user add smoke --cert u.p12
"$FIRMA" user list
"$FIRMA" sign doc.pdf -u smoke -o signed.pdf --at 1:bottom-right --stamp --reason "Smoke test"

grep -aq "/ETSI.CAdES.detached" signed.pdf
grep -aq "/ByteRange" signed.pdf
grep -aq "/Matrix" signed.pdf # appearance rotated for the /Rotate 90 page
echo "OK: signed.pdf created ($(wc -c < signed.pdf) bytes)"
