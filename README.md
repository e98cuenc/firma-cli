# firma

Command-line PAdES signing for PDFs — an alternative to Spain's AutoFirma.
A single self-contained binary written in pure Rust: no Java, no OpenSSL, no external libraries
(it only links against the operating system's own libraries).

- Several users, each with their own certificate (`.p12`/`.pfx`) and handwritten signature (image or vector).
- Visible signature in one or more places, on any page, including rotated pages.
- AutoFirma-style text stamp ("Digitally signed by …") so anyone can see the document is signed.
- PAdES B-B, B-T (RFC 3161 time-stamp) and B-LT (embedded OCSP/CRL revocation data).
- Imports the signature you saved in macOS Preview, as vector graphics.

## Install

Download the archive for your platform from the [releases](../../releases) page and put `firma`
(`firma.exe` on Windows) somewhere on your `PATH`.

Or build it from source (Rust ≥ 1.87):

```sh
cargo install --locked --path .        # installs into ~/.cargo/bin
```

| Platform | Release artifact | Notes |
|---|---|---|
| macOS | `firma-<version>-macos-universal.tar.gz` | Universal binary (Apple Silicon + Intel) |
| Linux | `firma-<version>-x86_64-linux.tar.gz`, `…-aarch64-linux.tar.gz` | Fully static (musl) |
| Windows | `firma-<version>-x86_64-windows.zip` | Static CRT, no Visual C++ runtime needed |

Release builds are produced by GitHub Actions (`.github/workflows/build.yml`) when a `v*` tag is pushed:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

`scripts/smoke-test.sh [path/to/firma]` creates a throw-away certificate and signs a PDF. CI runs it on every platform.

## Users

Each user has a certificate and, optionally, a handwritten signature. Everything is stored as plain files in
`~/.config/firma/users/<name>/` (`%APPDATA%\firma\users\<name>\` on Windows, or `$FIRMA_HOME`).
Files are mode 0600:

```text
user.toml          holder, issuer and expiry date
certificate.p12    as-is, encrypted with its own password (the password is never stored)
signature.png      handwritten signature as an image, or
signature.pdf      vector handwritten signature imported from Preview
```

```sh
firma user add ana --cert ana.p12 --image signature.png --remove-background
firma user signature ana --preview            # opens Preview: place your signature, ⌘S, Enter
firma user signature ana --from-pdf signed_in_preview.pdf
firma user cert ana renewed.p12               # after renewing the certificate
firma user list | info ana | remove ana
```

### Signature from Preview

macOS keeps Preview's signatures in a private AnnotationKit keychain that only Apple apps can read, so they
cannot be read directly. `--preview` creates a template PDF and opens it in Preview. You place your saved
signature there and save with ⌘S. `firma` then extracts the annotation as **vector** graphics, with the
original stroke and colour.

## Signing

```sh
firma sign contract.pdf -u ana                                  # invisible signature
firma sign contract.pdf -u ana --at last:bottom-right           # with the handwritten signature
firma sign contract.pdf -u ana --at all:bottom-center --stamp   # signature + text on every page
firma sign contract.pdf -u ana --stamp                          # text stamp only
firma sign contract.pdf -u ana --at 1:120,40:70x30 --stamp-at 1:top-right \
      --reason "Approval" --location Madrid -o contract_signed.pdf
```

- `--at PAGE:POSITION[:WIDTHxHEIGHT]` (repeatable) places the handwritten signature. Sizes are in mm, with
  the origin at the bottom-left of the page **as displayed**. On rotated pages the box is placed and drawn upright.
  PAGE is `1`, `-1`, `first`, `last` or `all`. POSITION is `X,Y`, `bottom-right`, `top-left`,
  `bottom-center`, `center`, etc.
- `--stamp` adds the text "Digitally signed by … on … with a certificate issued by …", like AutoFirma does.
  Without `--at`, the stamp goes at the bottom-left of the last page. `--stamp-at` adds text-only boxes.
- `--text` customizes the stamp. Available variables: `{name} {id} {issuer} {date} {time} {reason} {location}`.
  `\n` inserts a line break. For example, an AutoFirma-like Spanish stamp:
  `--text 'Firmado por {name} el {date} con un certificado emitido por {issuer}'`.
- The password is prompted in the terminal. It can also come from `$FIRMA_PASSWORD` or `--password-file`.

All boxes belong to a single signature. The PDF is modified through an incremental update, so existing
signatures stay valid. The format is PAdES (`ETSI.CAdES.detached`, with signing-certificate-v2).
`--pkcs7` uses `adbe.pkcs7.detached` instead. RSA, EC P-256 and EC P-384 keys are supported, as are both
modern (AES) and legacy (3DES/RC2) PKCS#12 files.

## Levels: time-stamp and revocation data

```sh
firma sign contract.pdf -u ana --level t     # PAdES B-T: with a time-stamp
firma sign contract.pdf -u ana --level lt    # PAdES B-LT: time-stamp + revocation data
firma config --level lt                      # make it the default
firma config --tsa http://timestamp.digicert.com
```

| Level | Adds |
|---|---|
| `b` (default) | Basic signature, no network access |
| `t` | RFC 3161 time-stamp over the signature. The chain is completed through AIA and embedded in the signature |
| `lt` | Everything in `t`, plus a `/DSS` dictionary with the full chain, OCSP responses and CRLs for the signer and the TSA |

- The default TSA is Izenpe's (`http://tsa.izenpe.com`). It is qualified, on the EU trusted list, and free to use.
  Change it with `--tsa`, `$FIRMA_TSA` or `firma config --tsa`.
- With `lt`, if any certificate in the signer's chain is **revoked**, or its status cannot be obtained, signing
  is aborted and no file is written. Failures for the TSA's chain only print a warning.
- OCSP from the certificate's AIA is tried first, then the CRL. Only http/https URLs are supported (no LDAP).
- Honours `HTTPS_PROXY`/`HTTP_PROXY`. Preferences are stored in `config.toml` in the data directory.

## Limitations

- No B-LTA (document time-stamp for long-term archival).
- Encrypted PDFs cannot be signed.
- TSAs that require authentication are not supported.
