# firma

Command-line PAdES signing for PDFs — an alternative to Spain's AutoFirma.
A single self-contained binary written in pure Rust: no Java, no OpenSSL, no external libraries
(it only links against the operating system's own libraries).

- Several users, each with their own certificate and handwritten signature (image or vector). The certificate can
  be a `.p12`/`.pfx` file or one already in the **macOS Keychain** or the **Windows certificate store**: then no
  password is typed, the key never leaves the system, and each signature is approved with Touch ID / Windows Hello.
- Visible signature in one or more places, on any page, including rotated pages.
- AutoFirma-style text stamp ("Digitally signed by …") so anyone can see the document is signed.
- PAdES B-B, B-T (RFC 3161 time-stamp), B-LT (embedded OCSP/CRL revocation data) and B-LTA
  (document time-stamp for long-term archival).
- Signs encrypted PDFs (RC4, AES-128, AES-256), respecting their permissions.
- Imports the signature you saved in macOS Preview, as vector graphics.

## Agent skill (Claude, Codex, …)

The repo also ships `sign-pdf`, an [Agent Skill](https://agentskills.io) that lets an AI agent sign documents
with `firma` on your behalf. It finds or installs the binary, checks the request with `firma sign --dry-run`,
shows you a summary and asks for confirmation before signing. It never handles your passwords: you run the
final command yourself, or point it to a password file only you can read. With a certificate in the Keychain /
Windows certificate store the agent can run the command after you confirm, and you approve the signature with
Touch ID / Windows Hello in a dialog that names the document.

| Agent | Install |
|---|---|
| Claude Code | `/plugin install firma --marketplace e98cuenc/firma-cli` |
| Claude.ai / Claude Desktop | Download `sign-pdf-skill.zip` from the releases and upload it in Customize > Skills (it bundles the binaries, so it also works in sandboxes without network access) |
| Codex and other Agent Skills readers | Unzip `sign-pdf-skill.zip` into `~/.agents/skills/` |
| Any of the above, from a checkout | `scripts/install-skill.sh` (copies it to `~/.claude/skills` and `~/.agents/skills`) |

The skill's source is in `plugins/firma/skills/sign-pdf`. CI builds `sign-pdf-skill.zip` with the binaries for every
platform, smoke-tests the bundled Linux binary, and attaches the zip to each release.
`scripts/build-skill.sh` builds the zip locally.

## Install

Download the archive for your platform from the [releases](../../releases) page and put `firma`
(`firma.exe` on Windows) somewhere on your `PATH`.

Or build it from source (Rust ≥ 1.87):

```sh
cargo install --locked --path .        # installs into ~/.cargo/bin
```

| Platform | Release artifact | Notes |
|---|---|---|
| macOS | `firma-macos-universal.tar.gz` | Universal binary (Apple Silicon + Intel) |
| Linux | `firma-x86_64-linux.tar.gz`, `firma-aarch64-linux.tar.gz` | Fully static (musl) |
| Windows | `firma-x86_64-windows.zip` | Static CRT, no Visual C++ runtime needed |

Or use the installers, which check the release's SHA-256 sums:
`plugins/firma/skills/sign-pdf/scripts/install.sh` (macOS/Linux, into `~/.local/bin`) or `install.ps1` (Windows).

Release builds are produced by GitHub Actions (`.github/workflows/build.yml`) when a `v*` tag is pushed:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

`scripts/smoke-test.sh [path/to/firma]` creates a throw-away certificate and signs a PDF. CI runs it on every platform,
and `scripts/system-cert-test.sh` on macOS and Windows (a throw-away keychain / the runner's certificate store).

## Users

Each user has a certificate and, optionally, a handwritten signature. Everything is stored as plain files in
`~/.config/firma/users/<name>/` (`%APPDATA%\firma\users\<name>\` on Windows, or `$FIRMA_HOME`).
Files are mode 0600:

```text
user.toml          holder, issuer, expiry date (and the fingerprint of a system certificate)
certificate.p12    as-is, encrypted with its own password (the password is never stored); not
                   present when the certificate is in the Keychain / Windows certificate store
signature.png      handwritten signature as an image, or
signature.pdf      vector handwritten signature imported from Preview
```

```sh
firma user add ana --cert ana.p12 --image signature.png --remove-background
firma user add ana --system-cert "ana garcia"  # a certificate in the Keychain / Windows store
firma user signature ana --preview            # opens Preview: place your signature, ⌘S, Enter
firma user signature ana --from-pdf signed_in_preview.pdf
firma user cert ana --cert renewed.p12        # after renewing the certificate
firma user list | info ana | remove ana
```

### Certificates in the Keychain / Windows certificate store

If the certificate is already installed on the computer (imported by double-clicking the `.p12`, by the FNMT
website, by AutoFirma…), use it from there instead of a file:

```sh
firma certs                                     # certificates with a private key in the system store
firma user add ana --system-cert 8B59669F       # by SHA-1 fingerprint (or its first 8+ digits)
firma user add ana --system-cert "sanchez ruiz" # or part of the holder's name / ID, if unambiguous
firma user cert ana --system-cert 8B59669F      # move an existing user to it (deletes firma's .p12 copy)
```

- macOS: the identities (certificate + private key) in your keychains. Windows: the current user's "Personal"
  store; keys are used through CNG, including those imported into legacy CryptoAPI providers.
- The private key never leaves the system and `firma` never sees a password. The system signs for it, and may
  show its own dialog the first time ("firma wants to sign using key…" on macOS; **Always Allow** is fine,
  because of the next point; the PIN dialog of a smart card).
- Before each signature, `firma` asks for **Touch ID** (macOS, falling back to your account password) or
  **Windows Hello** (PIN, fingerprint or face). The dialog names the document and the signer, so nothing
  can sign as you, and no agent can sign on your behalf, without you there. It can be turned off with
  `firma user presence-check ana off`, which itself asks for Touch ID / Windows Hello once. (A program that
  can edit your files could still change `user.toml`; the check protects against misuse of the command,
  not against malware running as you.)
- Linux has no such store: use `.p12` files there.

Saved signatures are trimmed to the ink: white or transparent margins of an image, and the empty space around
a vector signature, are removed. A box given with `--at PAGE:X,Y:WxH` is therefore filled by the strokes
themselves (keeping their proportions, centred).

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
- The password of a `.p12` is prompted in the terminal. It can also come from `$FIRMA_PASSWORD` or
  `--password-file`. With a system certificate there is no password; Touch ID / Windows Hello is asked instead.
- `--dry-run` validates everything (user, pages, positions, level) and prints what would be signed and how it will
  be approved, without asking for any password or writing anything.
- Encrypted PDFs are supported. The new objects are encrypted with the document's own key, and the document's
  permissions are respected (adding annotations must be allowed). If the PDF needs a password to open, it is
  prompted, or read from `$FIRMA_PDF_PASSWORD` or `--pdf-password-file`.

All boxes belong to a single signature. The PDF is modified through an incremental update, so existing
signatures stay valid. The format is PAdES (`ETSI.CAdES.detached`, with signing-certificate-v2).
`--pkcs7` uses `adbe.pkcs7.detached` instead. RSA, EC P-256 and EC P-384 keys are supported, as are both
modern (AES) and legacy (3DES/RC2) PKCS#12 files.

## Levels: time-stamps and revocation data

```sh
firma sign contract.pdf -u ana --level t     # PAdES B-T: with a time-stamp
firma sign contract.pdf -u ana --level lt    # PAdES B-LT: time-stamp + revocation data
firma sign contract.pdf -u ana --level lta   # PAdES B-LTA: B-LT + document time-stamp
firma config --level lt                      # make it the default
firma config --tsa http://timestamp.digicert.com
```

| Level | Adds |
|---|---|
| `b` (default) | Basic signature, no network access |
| `t` | RFC 3161 time-stamp over the signature. The chain is completed through AIA and embedded in the signature |
| `lt` | Everything in `t`, plus a `/DSS` dictionary with the full chain, OCSP responses and CRLs for the signer and the TSA |
| `lta` | Everything in `lt`, plus a document time-stamp (`/DocTimeStamp`, `ETSI.RFC3161`) over the whole file, and the validation data for that time-stamp |

- The default TSA is Izenpe's (`http://tsa.izenpe.com`). It is qualified, on the EU trusted list, and free to use.
  Change it with `--tsa`, `$FIRMA_TSA` or `firma config --tsa`.
- TSAs that require HTTP Basic authentication: `--tsa-user` (or `firma config --tsa-user`). The password comes from
  `$FIRMA_TSA_PASSWORD` or `--tsa-password-file`, or is prompted; it is never written to the config file.
  Credentials are only sent to `https://` TSA URLs (set `FIRMA_ALLOW_INSECURE_AUTH=1` to override).
  `--tsa-policy OID` (or `firma config --tsa-policy`) requests a specific TSA policy.
- Every time-stamp token is checked before it is used. It must cover the requested data and nonce, its signed
  attributes must be consistent, the signature must verify with the certificate in the token, and that
  certificate must carry the time-stamping extended key usage. Whether the TSA itself is trusted (its chain
  up to a root you trust) is decided by whoever validates the signed PDF, as with any signature.
- With `lt`, if any certificate in the signer's chain is **revoked**, or its status cannot be obtained, signing
  is aborted and no file is written. Failures for the TSA's chain only print a warning.
- OCSP from the certificate's AIA is tried first, then the CRL. Only http/https URLs are supported (no LDAP).
- Revocation data is verified, not just downloaded. An OCSP response must be signed by the issuing CA or by a
  delegated responder it issued (with the OCSPSigning EKU), match the certificate's full CertID, and be current.
  A CRL must be signed by the issuer and not be expired. Intermediate certificates are only accepted if their
  signature over the child certificate verifies.
- URLs taken from certificates (AIA, OCSP, CRL) may not point to loopback, private, link-local or other non-public
  addresses. This protects against SSRF, and the check also covers redirects and DNS rebinding. Set
  `FIRMA_ALLOW_PRIVATE_NETWORK=1` for an internal corporate CA.
- Honours `HTTPS_PROXY`/`HTTP_PROXY`. Preferences are stored in `config.toml` in the data directory.

## Limitations

- Revocation data is only fetched over http/https. LDAP CRL distribution points are skipped (most CAs
  also publish an http one).
- Certificate-based PDF encryption (public-key security handler) is not supported, only passwords.
