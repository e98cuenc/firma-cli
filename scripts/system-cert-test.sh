#!/usr/bin/env bash
# Tests certificates in the system store: imports a test certificate into a throwaway macOS
# keychain or the Windows certificate store (current user), signs through the system with it,
# and checks that the release binary refuses to sign without Touch ID / Windows Hello.
# Usage: scripts/system-cert-test.sh [path/to/firma]   (from the repository root; needs cargo,
# openssl and python3)
set -euo pipefail

FIRMA="${1:-target/release/firma}"
FIRMA="$(cd "$(dirname "$FIRMA")" && pwd)/$(basename "$FIRMA")"
WORK="$(mktemp -d)"
export MSYS_NO_PATHCONV=1 FIRMA_HOME="$WORK/home" FIRMA_TEST_SYSTEM_CERT="Firma System Test"
PY="$(command -v python3 || command -v python)"

# macOS `security import` only reads PKCS#12 files with the legacy algorithms.
legacy=()
if [ "$(uname -s)" = Darwin ] && openssl version | grep -q "^OpenSSL 3"; then legacy=(-legacy); fi
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/u.key" -out "$WORK/u.crt" -days 2 \
  -subj "/CN=$FIRMA_TEST_SYSTEM_CERT" 2>/dev/null
openssl pkcs12 -export ${legacy[@]+"${legacy[@]}"} -inkey "$WORK/u.key" -in "$WORK/u.crt" -out "$WORK/u.p12" -passout pass:test
"$PY" "$(dirname "$0")/test-pdf.py" "$WORK/doc.pdf"

case "$(uname -s)" in
  Darwin)
    # Debug builds (tests) read $FIRMA_TEST_KEYCHAIN instead of the user's keychains.
    KC="$WORK/test.keychain"
    trap 'security delete-keychain "$KC" 2>/dev/null; rm -rf "$WORK"' EXIT
    security create-keychain -p test "$KC"
    security unlock-keychain -p test "$KC"
    security set-keychain-settings "$KC"
    security import "$WORK/u.p12" -k "$KC" -P test -A
    FIRMA_TEST_KEYCHAIN="$KC" cargo test --locked -- --ignored system
    ;;
  MINGW* | MSYS* | CYGWIN*)
    trap 'certutil -user -delstore My "$FIRMA_TEST_SYSTEM_CERT" >/dev/null 2>&1; rm -rf "$WORK"' EXIT
    # Default import, then into a legacy CryptoAPI provider (as some old tools do).
    for csp in "" "Microsoft Enhanced RSA and AES Cryptographic Provider"; do
      echo "== import ${csp:-(default provider)}"
      certutil -user -f -p test ${csp:+-csp "$csp"} -importpfx My "$(cygpath -w "$WORK/u.p12")" NoRoot >/dev/null
      cargo test --locked -- --ignored system

      "$FIRMA" certs | grep "$FIRMA_TEST_SYSTEM_CERT"
      rm -rf "$FIRMA_HOME"
      "$FIRMA" user add sys --system-cert "firma system test"
      "$FIRMA" sign "$WORK/doc.pdf" -u sys --stamp --dry-run | grep "approval:.*Windows Hello"
      # Windows Hello is not set up on CI: the release binary must refuse to sign.
      if "$FIRMA" sign "$WORK/doc.pdf" -u sys --stamp -o "$WORK/signed.pdf" 2>"$WORK/err.txt"; then
        echo "signed without Windows Hello" >&2
        exit 1
      fi
      cat "$WORK/err.txt"
      grep -q "Windows Hello" "$WORK/err.txt"
      [ ! -e "$WORK/signed.pdf" ]
      certutil -user -delstore My "$FIRMA_TEST_SYSTEM_CERT" >/dev/null
    done
    ;;
  *)
    echo "no system certificate store on $(uname -s)"
    ;;
esac
echo "OK: system certificate store"
