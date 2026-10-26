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
# Windows Python needs Windows paths (MSYS_NO_PATHCONV stops Git Bash from converting them).
native() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s\n' "$1"; fi; }

cd "$WORK"
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 2 -subj "/CN=Smoke CA" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout u.key -out u.csr -subj "/CN=Smoke User" 2>/dev/null
openssl x509 -req -in u.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out u.crt -days 1 2>/dev/null
openssl pkcs12 -export -inkey u.key -in u.crt -certfile ca.crt -out u.p12 -passout "pass:$FIRMA_PASSWORD"

"$PY" "$(native "$SCRIPTS/test-pdf.py")" doc.pdf

"$FIRMA" --version
"$FIRMA" user add smoke --cert u.p12
"$FIRMA" user list
"$FIRMA" sign doc.pdf -u smoke -o signed.pdf --at 1:bottom-right --stamp --reason "Smoke test"

grep -aq "/ETSI.CAdES.detached" signed.pdf
grep -aq "/ByteRange" signed.pdf
grep -aq "/Matrix" signed.pdf # appearance rotated for the /Rotate 90 page

# A second signature on the same document: listed by the dry run, and not allowed on top of the first.
"$FIRMA" sign signed.pdf -u smoke -o signed2.pdf --stamp-at 1:20,150:50x20
[ "$("$FIRMA" sign signed2.pdf -u smoke --dry-run | grep -c "signed: ")" = 2 ]
if "$FIRMA" sign signed2.pdf -u smoke -o signed3.pdf --stamp-at 1:30,160:50x20 2>/dev/null; then
  echo "signed on top of an existing signature" >&2
  exit 1
fi
# Other formats: CAdES (attached and detached), XAdES and FacturaE.
printf 'smoke test\n' > note.txt
"$FIRMA" sign note.txt -u smoke
"$FIRMA" sign note.txt -u smoke --detached -o note-detached.csig
openssl cms -verify -inform DER -in note.txt.csig -CAfile ca.crt -purpose any -out note-out.txt
cmp note.txt note-out.txt
openssl cms -verify -inform DER -in note-detached.csig -content note.txt -binary -CAfile ca.crt -purpose any -out /dev/null
printf '<?xml version="1.0" encoding="UTF-8"?>\n<doc xmlns="urn:smoke"><item>caf\303\251</item></doc>\n' > data.xml
"$FIRMA" sign data.xml -u smoke
grep -q "<ds:Signature " data_signed.xsig
printf '<fe:Facturae xmlns:fe="http://www.facturae.gob.es/formato/Versiones/Facturaev3_2_2.xml"><FileHeader/></fe:Facturae>\n' > invoice.xml
"$FIRMA" sign invoice.xml -u smoke | grep -q "FacturaE"
grep -q "politica_de_firma_formato_facturae_v3_1" invoice_signed.xsig
if "$FIRMA" sign note.txt -u smoke --stamp -o x.csig 2>/dev/null; then
  echo "accepted a PDF-only option for CAdES" >&2
  exit 1
fi
echo "OK: signed.pdf created ($(wc -c < signed.pdf) bytes), and CAdES, XAdES and FacturaE files"
