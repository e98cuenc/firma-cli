#!/usr/bin/env bash
# PKCS#11 test: a throw-away SoftHSM token with an RSA key, an EC key and a key that asks for the
# PIN at every signature (like the DNIe's), then signs a PDF, a file (CAdES) and an invoice with each.
# Usage: scripts/pkcs11-test.sh [path/to/firma]
# Requires SoftHSM 2 (softhsm2-util), OpenSC (pkcs11-tool), openssl and python3.
# Not for the static Linux release build: it cannot load PKCS#11 modules.
set -euo pipefail

FIRMA="${1:-target/release/firma}"
[ -x "$FIRMA" ] || { echo "binary not found: $FIRMA" >&2; exit 1; }
FIRMA="$(cd "$(dirname "$FIRMA")" && pwd)/$(basename "$FIRMA")"
SCRIPTS="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

MODULE="${SOFTHSM_MODULE:-}"
for m in /opt/homebrew/lib/softhsm/libsofthsm2.so /usr/local/lib/softhsm/libsofthsm2.so \
         /usr/lib/softhsm/libsofthsm2.so /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so; do
  [ -z "$MODULE" ] && [ -f "$m" ] && MODULE="$m"
done
[ -n "$MODULE" ] || { echo "SoftHSM module not found (set SOFTHSM_MODULE)" >&2; exit 1; }

cd "$WORK"
mkdir tokens
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$WORK" > softhsm2.conf
export SOFTHSM2_CONF="$WORK/softhsm2.conf" FIRMA_HOME="$WORK/home" FIRMA_PKCS11_MODULE="$MODULE"
softhsm2-util --init-token --free --label "Test card" --pin 1234 --so-pin 5678 >/dev/null
p11() { pkcs11-tool --module "$MODULE" --token-label "Test card" --login --pin 1234 "$@" >/dev/null 2>&1; }

openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 2 -subj "/CN=Card CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
printf 'keyUsage=critical,digitalSignature,nonRepudiation\n' > leaf.ext
# id name key-type extra-pkcs11-tool-flags
while read -r id name type flags; do
  if [ "$type" = rsa ]; then openssl genrsa -out "$name.key" 2048 2>/dev/null
  else openssl ecparam -name prime256v1 -genkey -noout -out "$name.key"; fi
  openssl req -new -key "$name.key" -out "$name.csr" -subj "/CN=Card User $name" 2>/dev/null
  openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -out "$name.crt" -days 1 -extfile leaf.ext 2>/dev/null
  openssl pkcs8 -topk8 -nocrypt -in "$name.key" -outform DER -out "$name.p8"
  openssl x509 -in "$name.crt" -outform DER -out "$name.der"
  # shellcheck disable=SC2086
  p11 --write-object "$name.p8" --type privkey --id "$id" $flags
  p11 --write-object "$name.der" --type cert --id "$id"
done <<'EOF'
01 rsa rsa
02 ec ec
03 always rsa --always-auth
EOF

PY="$(command -v python3 || command -v python)"
"$PY" "$SCRIPTS/test-pdf.py" doc.pdf
printf 'pkcs11 test\n' > note.txt
printf '<fe:Facturae xmlns:fe="http://www.facturae.gob.es/formato/Versiones/Facturaev3_2_2.xml"><FileHeader/></fe:Facturae>\n' > invoice.xml
echo 1234 > pin.txt

"$FIRMA" certs --pkcs11
[ "$("$FIRMA" certs --pkcs11 | grep -c "Card User")" = 3 ]
for name in rsa ec always; do
  "$FIRMA" user add "$name" --pkcs11 "Card User $name" >/dev/null
  "$FIRMA" sign doc.pdf -u "$name" -o "$name.pdf" --stamp --password-file pin.txt
  "$FIRMA" sign note.txt -u "$name" -o "$name.csig" --password-file pin.txt
  "$FIRMA" sign invoice.xml -u "$name" -o "$name.xsig" --password-file pin.txt
  openssl cms -verify -inform DER -in "$name.csig" -CAfile ca.crt -purpose any -out /dev/null
done

echo 0000 > bad.txt
if "$FIRMA" sign note.txt -u rsa -o bad.csig --password-file bad.txt 2>err.txt; then
  echo "signed with a wrong PIN" >&2
  exit 1
fi
grep -q "wrong PIN" err.txt
echo "OK: signed with RSA, EC and always-authenticate keys on a PKCS#11 token"
