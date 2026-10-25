# firma CLI reference

All commands accept `--home DIR` (data directory). The default is `$FIRMA_HOME`, then `~/.config/firma`,
then `%APPDATA%\firma` on Windows. `firma <command> --help` shows the full help.

## Users

```sh
firma user add NAME (--cert CERT.p12 | --system-cert QUERY) [--image IMG [--remove-background] | --preview | --from-pdf PDF [--index N]] [--password-file F]
firma user signature NAME (--image IMG [--remove-background] | --preview | --from-pdf PDF [--index N])
firma user cert NAME (--cert NEW.p12 | --system-cert QUERY) [--password-file F]  # renewed certificate, or move to the system store
firma user presence-check NAME on|off                # Touch ID / Windows Hello before each signature (off asks for it once)
firma certs                                          # certificates with a private key in the Keychain / Windows store
firma user list                                      # alias: ls
firma user info NAME
firma user remove NAME [--yes]                       # alias: rm; deletes the certificate copy
```

- `--image` takes a PNG or JPEG. `--remove-background` makes white transparent.
- Saved signatures (images and Preview's vector ones) are trimmed to the ink, with no empty margins. So an `--at`
  box is filled by the strokes themselves; the signature keeps its proportions and is centred, so it fills the box
  exactly when the box has the same proportions.
- `--preview` (macOS only, interactive): opens a template in Preview. The user places their saved signature,
  saves with ⌘S and presses Enter. The signature is imported as vector graphics.
- `--from-pdf`: imports a signature annotation from a PDF the user signed in Preview.
- `--system-cert QUERY` uses a certificate in the macOS Keychain or the Windows certificate store (not on Linux):
  QUERY is its SHA-1 fingerprint (8+ hex digits are enough) or part of the holder's name or ID. No password is
  involved; the key stays in the system. Signing asks for Touch ID / Windows Hello unless the user turned it off.

## Signing

```sh
firma sign INPUT.pdf -u NAME [options]
```

| Option | Meaning |
|---|---|
| `-o, --output FILE` | Output file (default `INPUT_signed.pdf`) |
| `-f, --force` | Overwrite the output |
| `--at PAGE:POS[:WxH]` | Visible signature box, repeatable |
| `-s, --stamp` | Add the "Digitally signed by …" text (inside the `--at` boxes, or alone at `last:bottom-left`) |
| `--stamp-at PAGE:POS[:WxH]` | Text-only stamp box, repeatable (implies `--stamp`) |
| `--text TEMPLATE` | Stamp text. Variables: `{name} {id} {issuer} {date} {time} {reason} {location}`; `\n` = new line |
| `--reason`, `--location`, `--contact` | Stored in the signature |
| `--level b\|t\|lt\|lta` | PAdES level (default from `firma config`, else `b`) |
| `--tsa URL` | Time-stamping authority (default `http://tsa.izenpe.com`) |
| `--tsa-user USER`, `--tsa-password-file F`, `--tsa-policy OID` | Authenticated TSA (credentials are only sent over https) |
| `--field NAME` | Sign into this existing empty signature field (listed by `--dry-run`) instead of `--at` boxes |
| `--allow-overlap` | Allow boxes on top of earlier signatures (refused by default) |
| `--pdf-password-file F` | Password of an encrypted PDF |
| `--password-file F` | Certificate password (`.p12` users only) |
| `--pkcs7` | `adbe.pkcs7.detached` instead of `ETSI.CAdES.detached` |
| `--reserve BYTES` | Space reserved for the signature (rarely needed) |
| `--dry-run` | Validate and describe (including the `approval:` the signature will need), without signing or asking for passwords |

Positions:
- PAGE: `1`, `2`, …, `-1` (last), `first`, `last`, `all`.
- POS: `bottom-right`, `bottom-left`, `bottom-center`, `top-right`, `top-left`, `top-center`, `center`, or
  `X,Y` in mm from the bottom-left corner of the page as displayed (rotated pages are handled).
- Default sizes: 60x25 mm for `--at`, 80x18 mm for `--stamp-at`.

Several signatures: run `firma sign` again on the signed output, once per signer (or per signature). Earlier
signatures stay valid. `--dry-run` lists them (`signed:` lines, with boxes as `page N at X,Y:WxH`), the empty fields
(`empty field:`), and whether the author certified the document.

Levels:

| Level | Contents | Network |
|---|---|---|
| `b` | Basic PAdES signature | no |
| `t` | + RFC 3161 signature time-stamp | TSA |
| `lt` | + DSS with the chain and OCSP/CRL data; aborts if the certificate is revoked | TSA, OCSP/CRL |
| `lta` | + document time-stamp for long-term archival | TSA, OCSP/CRL |

## Preferences

```sh
firma config                                  # show
firma config --level lt --tsa https://… --tsa-user USER --tsa-policy OID
```

## Environment variables

| Variable | Use |
|---|---|
| `FIRMA_HOME` | Data directory |
| `FIRMA_PASSWORD`, `FIRMA_PDF_PASSWORD`, `FIRMA_TSA_PASSWORD` | Passwords. Meant for the user's own scripts; an agent must not set them |
| `FIRMA_TSA` | Default TSA URL |
| `FIRMA_ALLOW_PRIVATE_NETWORK=1` | Allow OCSP/CRL/AIA URLs on private networks (internal corporate CA) |
| `FIRMA_ALLOW_INSECURE_AUTH=1` | Allow TSA credentials over plain http |
| `HTTPS_PROXY`, `HTTP_PROXY` | Proxy |
