# firma

Command-line electronic signatures (PAdES for PDFs, CAdES, XAdES and FacturaE invoices), an alternative to Spain's AutoFirma.
A single self-contained binary written in pure Rust: no Java, no OpenSSL, no external libraries
(it only links against the operating system's own libraries).

- Several users, each with their own certificate and handwritten signature (image or vector). The certificate can
  be a `.p12`/`.pfx` file or one already in the **macOS Keychain** or the **Windows certificate store**: then no
  password is typed, the key never leaves the system, and each signature is approved with Touch ID / Windows Hello.
- Visible signature in one or more places, on any page, including rotated pages.
- AutoFirma-style text stamp ("Digitally signed by …") so anyone can see the document is signed.
- Other files too: CAdES (`.csig`) for any file, enveloped XAdES for XML documents, and FacturaE electronic
  invoices (XAdES-EPES with the FacturaE policy), at levels B-B and B-T.
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
| Linux | `firma-x86_64-linux.tar.gz`, `firma-aarch64-linux.tar.gz` | Fully static (musl): runs anywhere, but cannot use smart cards |
| Linux | `firma-x86_64-linux-gnu.tar.gz`, `firma-aarch64-linux-gnu.tar.gz` | Linked against glibc 2.35+ (Ubuntu 22.04, Debian 12, Fedora 36 or newer): can use smart cards (PKCS#11) |
| Windows | `firma-x86_64-windows.zip` | Static CRT, no Visual C++ runtime needed |

Or use the installers, which check the release's SHA-256 sums:
`plugins/firma/skills/sign-pdf/scripts/install.sh` (macOS/Linux, into `~/.local/bin`) or `install.ps1` (Windows).
On Linux, `install.sh` picks the glibc build when the system has glibc 2.35 or newer, and the static one otherwise
(`FIRMA_LINUX_BUILD=gnu` or `static` chooses).

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
- Linux has no such store: use `.p12` files or a smart card (below) there.

### Smart cards and tokens (PKCS#11): DNIe, USB tokens

A certificate on a smart card (the Spanish **DNIe**, FNMT or Camerfirma cards), a USB token or an HSM is used
through its PKCS#11 module, such as OpenSC's or the official DNIe module:

```sh
firma certs --pkcs11                            # certificates on the cards in the readers
firma user add ana --pkcs11 12345678Z           # by ID, part of the holder's name, or SHA-1 fingerprint
firma user add ana --pkcs11 8B59669F --pkcs11-module /usr/lib/libpkcs11-dnie.so
firma sign contract.pdf -u ana                  # asks for the card's PIN
```

- The module is OpenSC's or the DNIe one if installed in the usual place, else `--pkcs11-module` or
  `$FIRMA_PKCS11_MODULE`. It is saved with the user.
- A DNIe holds two certificates for the same person: authentication and signing. A name or ID picks the
  signing one (the one with the nonRepudiation key usage); `firma certs --pkcs11` shows which is which.
- The key never leaves the card. The PIN is asked at each signature, in a prompt that names the document and
  the signer (or read from `--password-file` / `$FIRMA_PASSWORD`), or typed on the reader's PIN pad if it has
  one. Keys that require the PIN for every signature, like the DNIe's signing key, get it again right before
  signing. A wrong PIN fails without retrying, and firma warns when the card is close to locking.
- On macOS and Windows a card whose driver puts it in the Keychain / Windows certificate store (the DNIe
  minidriver on Windows, for example) also works with `--system-cert`.
- On Linux, use the `-linux-gnu` release builds (or `cargo install`): the fully static ones cannot load
  PKCS#11 modules, as a static binary cannot load shared libraries.

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

### Several signatures on one document

Each `firma sign` adds one signature in an incremental update, so the document can be signed again, by the same
person or by others, and earlier signatures stay valid:

```sh
firma sign contract.pdf -u ana --at last:20,40:60x25 -o contract_ana.pdf
firma sign contract_ana.pdf -u luis --at last:110,40:60x25 -o contract_signed.pdf
```

- `--dry-run` lists the signatures already there, with their boxes in the same `X,Y:WxH` form `--at` takes, so a
  free spot is easy to pick. A box that would cover an earlier signature is refused (`--allow-overlap` allows it).
- If the PDF was prepared with empty signature fields (e.g. "Applicant's signature"), the dry run lists them and
  `--field NAME` signs into one: its box gets the handwritten signature (or the stamp, with `--stamp` or if the user
  has none).
- A document **certified** by its author is respected: "no changes" forbids any signature, and "form filling and
  signing" only allows signing its existing fields with `--field`.

All boxes of one `firma sign` belong to a single signature. The PDF is modified through an incremental update, so existing
signatures stay valid. The format is PAdES (`ETSI.CAdES.detached`, with signing-certificate-v2).
`--pkcs7` uses `adbe.pkcs7.detached` instead. RSA, EC P-256 and EC P-384 keys are supported, as are both
modern (AES) and legacy (3DES/RC2) PKCS#12 files.

## Other formats: CAdES, XAdES and FacturaE

`firma sign` picks the format from the file (`--format auto`, the default), or takes it from `--format`:

```sh
firma sign contract.docx -u ana                # CAdES → contract.docx.csig, the document inside it
firma sign contract.docx -u ana --detached     # CAdES without the document (keep both files)
firma sign data.xml -u ana                     # XAdES, enveloped → data_signed.xsig
firma sign invoice.xml -u ana --level t        # FacturaE (root element Facturae) → invoice_signed.xsig
```

| Format | For | Signature |
|---|---|---|
| `pades` | PDFs | Inside the PDF (everything above) |
| `cades` | Any file | CMS `SignedData` with signing-time and signing-certificate-v2; the file inside it (AutoFirma's default), or outside with `--detached` |
| `xades` | XML documents | `ds:Signature` at the end of the root element, XAdES 1.3.2 with `SigningCertificateV2` and the document's MIME type. The document is digested with the enveloped-signature transform and C14N, so other signatures already in it stay valid |
| `facturae` | FacturaE 3.x invoices | Like `xades`, plus the FacturaE signature policy v3.1 (XAdES-EPES), signer role `emisor` and `SigningCertificate` |

- Levels `b` and `t` (a time-stamp over the signature, as in PAdES). `lt` and `lta` are for PDFs only: asking for them
  is an error, and a configured default above `t` signs at `t` with a note.
- The PDF options (`--at`, `--stamp`, `--field`, `--reason`, …) are refused for the other formats.
- XML must be UTF-8 (or plain ASCII) and have no DTD (`<!DOCTYPE>`): firma never expands entities. A file that
  starts with `<?xml` but cannot be read as XML is refused in `auto` mode; `--format cades` signs it as a file.

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
- PKCS#11 tokens are tested with SoftHSM (RSA, EC and always-authenticate keys), not with a physical DNIe.
- CAdES, XAdES and FacturaE stop at level B-T (no LT/LTA), and there is no co-signing of an existing CAdES file
  or counter-signing. XAdES is enveloped only (no detached or enveloping XAdES).
