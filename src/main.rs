mod ber;
mod cert;
mod cms;
mod keystore;
mod net;
mod pdf;
mod preview;
mod revocation;
mod store;
mod tsa;
mod verify;

use std::fs;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};

use cert::Credential;
use pdf::sign::{GraphicSource, Placement, SignOptions, SubFilter};
use store::{write_private, Config, SignatureKind, Store, User};

/// Izenpe's qualified TSA (on the EU trusted list), free to use.
const DEFAULT_TSA: &str = "http://tsa.izenpe.com";
const DEFAULT_TEXT: &str = "Digitally signed by {name} on {date} at {time} with a certificate issued by {issuer}";

/// Electronic signature of PDFs (PAdES) from the command line, an alternative to AutoFirma.
#[derive(Parser)]
#[command(name = "firma", version)]
struct Cli {
    /// Data directory (default: $FIRMA_HOME, ~/.config/firma, or %APPDATA%\firma on Windows)
    #[arg(long, global = true, value_name = "DIR")]
    home: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Manage users (certificate + handwritten signature)
    #[command(subcommand)]
    User(UserCmd),
    /// Sign a PDF
    Sign(Box<SignArgs>),
    /// List the certificates with a private key in the macOS Keychain / Windows certificate store
    Certs,
    /// Show or change preferences (default PAdES level and TSA)
    Config {
        /// Default PAdES level
        #[arg(long, value_enum)]
        level: Option<Level>,
        /// Default TSA (RFC 3161 URL)
        #[arg(long)]
        tsa: Option<String>,
        /// User for TSAs that require authentication (its password goes in $FIRMA_TSA_PASSWORD
        /// or --tsa-password-file, never in the config file)
        #[arg(long)]
        tsa_user: Option<String>,
        /// TSA policy OID to request
        #[arg(long)]
        tsa_policy: Option<String>,
    },
}

/// PAdES signature level.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Level {
    /// B-B: basic signature
    B,
    /// B-T: with a signature time-stamp
    T,
    /// B-LT: time-stamp plus embedded revocation data (OCSP/CRL)
    Lt,
    /// B-LTA: B-LT plus a document time-stamp for long-term archival
    Lta,
}

impl Level {
    fn parse(s: &str) -> Result<Self> {
        Level::from_str(s, true).map_err(|_| anyhow::anyhow!("invalid level '{s}' (b, t, lt or lta)"))
    }

    fn name(self) -> &'static str {
        match self {
            Level::B => "PAdES B-B",
            Level::T => "PAdES B-T",
            Level::Lt => "PAdES B-LT",
            Level::Lta => "PAdES B-LTA",
        }
    }
}

#[derive(Subcommand)]
enum UserCmd {
    /// Add a user with their certificate (a .p12/.pfx file, or one in the system store)
    Add {
        name: String,
        #[command(flatten)]
        cert: CertArgs,
        /// Do not ask for Touch ID / Windows Hello before each signature with a system certificate
        /// (asks for it once now, to confirm)
        #[arg(long, requires = "system_cert")]
        no_presence_check: bool,
        #[command(flatten)]
        signature: SignatureArgs,
        #[command(flatten)]
        password: PasswordArgs,
    },
    /// Change a user's handwritten signature (the visible one)
    Signature {
        name: String,
        #[command(flatten)]
        signature: SignatureArgs,
    },
    /// Replace a user's certificate (e.g. after renewing it, or to move it to the system store)
    Cert {
        name: String,
        #[command(flatten)]
        cert: CertArgs,
        #[command(flatten)]
        password: PasswordArgs,
    },
    /// Turn on or off the Touch ID / Windows Hello check before each signature with a system
    /// certificate (turning it off asks for it once, to confirm)
    PresenceCheck { name: String, state: OnOff },
    /// List users
    #[command(visible_alias = "ls")]
    List,
    /// Show a user's details
    Info { name: String },
    /// Delete a user and all their files
    #[command(visible_alias = "rm")]
    Remove {
        name: String,
        /// Do not ask for confirmation
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum OnOff {
    On,
    Off,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct CertArgs {
    /// PKCS#12 certificate (.p12 / .pfx) with the private key; firma keeps a copy
    #[arg(long, short = 'c', value_name = "FILE")]
    cert: Option<PathBuf>,
    /// A certificate in the macOS Keychain / Windows certificate store, by SHA-1 fingerprint or
    /// part of the holder's name (see `firma certs`). The key stays there and no password is needed
    #[arg(long, value_name = "QUERY")]
    system_cert: Option<String>,
}

#[derive(Args)]
struct SignatureArgs {
    /// Image of the handwritten signature (PNG or JPEG)
    #[arg(long, short = 'i', conflicts_with_all = ["preview", "from_pdf"])]
    image: Option<PathBuf>,
    /// Make the white background of the image transparent
    #[arg(long, requires = "image")]
    remove_background: bool,
    /// Open Preview so you can place your saved signature, then import it (vector)
    #[arg(long, conflicts_with = "from_pdf")]
    preview: bool,
    /// Import the signature from a PDF where you placed it with Preview
    #[arg(long, value_name = "PDF")]
    from_pdf: Option<PathBuf>,
    /// Which annotation to use if the PDF has several
    #[arg(long, requires = "from_pdf")]
    index: Option<usize>,
}

#[derive(Args)]
struct PasswordArgs {
    /// File containing the certificate password (otherwise $FIRMA_PASSWORD, or it is prompted)
    #[arg(long, value_name = "FILE")]
    password_file: Option<PathBuf>,
}

#[derive(Args)]
struct SignArgs {
    /// PDF to sign
    input: PathBuf,
    /// User who signs
    #[arg(long, short = 'u')]
    user: String,
    /// Output PDF (default: <input>_signed.pdf)
    #[arg(long, short = 'o')]
    output: Option<PathBuf>,
    /// Where to put the visible signature; repeatable.
    /// Format PAGE:POSITION[:WIDTHxHEIGHT] (mm, origin at the bottom-left of the page as displayed).
    /// PAGE: 1, 2, -1, first, last, all. POSITION: X,Y or bottom-right, bottom-left,
    /// bottom-center, top-..., center. E.g. last:bottom-right, 1:120,40:70x30
    #[arg(long = "at", value_name = "POS")]
    at: Vec<Placement>,
    /// Add the "Digitally signed by…" text stamp, like AutoFirma does
    #[arg(long, short = 's')]
    stamp: bool,
    /// Boxes with only the text stamp (implies --stamp); repeatable
    #[arg(long, value_name = "POS")]
    stamp_at: Vec<Placement>,
    /// Sign into this existing empty signature field of the PDF (see the dry run) instead of
    /// adding new boxes. Its box gets the handwritten signature, or the stamp if there is none
    #[arg(long, value_name = "NAME", conflicts_with_all = ["at", "stamp_at"])]
    field: Option<String>,
    /// Allow boxes on top of existing signature boxes (which would hide them)
    #[arg(long)]
    allow_overlap: bool,
    /// Stamp text. Variables: {name} {id} {issuer} {date} {time} {reason} {location}
    #[arg(long, value_name = "TEMPLATE")]
    text: Option<String>,
    /// Reason for signing
    #[arg(long)]
    reason: Option<String>,
    /// Signing location
    #[arg(long)]
    location: Option<String>,
    /// Signer contact information
    #[arg(long)]
    contact: Option<String>,
    /// Use adbe.pkcs7.detached instead of PAdES (ETSI.CAdES.detached)
    #[arg(long)]
    pkcs7: bool,
    /// PAdES level: b, t (time-stamp), lt (+ revocation data) or lta (+ document time-stamp).
    /// Default: from `firma config`, or b
    #[arg(long, value_enum)]
    level: Option<Level>,
    /// Time-stamping authority (RFC 3161 URL); default: from `firma config`, $FIRMA_TSA, or Izenpe
    #[arg(long, value_name = "URL")]
    tsa: Option<String>,
    /// User for a TSA that requires HTTP authentication (default: from `firma config`)
    #[arg(long, value_name = "USER")]
    tsa_user: Option<String>,
    /// File with the TSA password (otherwise $FIRMA_TSA_PASSWORD, or it is prompted)
    #[arg(long, value_name = "FILE")]
    tsa_password_file: Option<PathBuf>,
    /// TSA policy OID to request (default: from `firma config`)
    #[arg(long, value_name = "OID")]
    tsa_policy: Option<String>,
    /// File with the password of an encrypted PDF (otherwise $FIRMA_PDF_PASSWORD, or it is prompted)
    #[arg(long, value_name = "FILE")]
    pdf_password_file: Option<PathBuf>,
    /// Bytes reserved for the CMS signature (default 16384, or 65536 with a time-stamp)
    #[arg(long)]
    reserve: Option<usize>,
    /// Overwrite the output if it already exists
    #[arg(long, short = 'f')]
    force: bool,
    /// Check everything and print what would be signed, without signing (no password needed)
    #[arg(long)]
    dry_run: bool,
    #[command(flatten)]
    password: PasswordArgs,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let store = Store::open(cli.home)?;
    match cli.cmd {
        Cmd::User(c) => user_cmd(&store, c),
        Cmd::Sign(a) => sign_cmd(&store, *a),
        Cmd::Certs => {
            let certs = keystore::list()?;
            if certs.is_empty() {
                println!("No certificates with a private key in the {}.", keystore::STORE);
            }
            let users = store.list()?;
            for c in certs {
                let used: Vec<&str> = users
                    .iter()
                    .filter(|u| u.meta.system_cert.as_deref() == Some(c.sha1.as_str()))
                    .map(|u| u.meta.name.as_str())
                    .collect();
                let used = if used.is_empty() { String::new() } else { format!("  [user {}]", used.join(", ")) };
                println!("{}{used}", keystore::describe(&c));
            }
            Ok(())
        }
        Cmd::Config { level, tsa, tsa_user, tsa_policy } => {
            let mut config = store.config()?;
            if level.is_none() && tsa.is_none() && tsa_user.is_none() && tsa_policy.is_none() {
                println!("{}", store.config_path().display());
                println!("  level:      {}", config.level.as_deref().unwrap_or("b"));
                println!("  tsa:        {}", config.tsa.as_deref().unwrap_or(DEFAULT_TSA));
                println!("  tsa-user:   {}", config.tsa_user.as_deref().unwrap_or("(none)"));
                println!("  tsa-policy: {}", config.tsa_policy.as_deref().unwrap_or("(none)"));
                return Ok(());
            }
            if let Some(p) = &tsa_policy {
                p.parse::<der::asn1::ObjectIdentifier>().map_err(|_| anyhow::anyhow!("invalid OID '{p}'"))?;
            }
            // An empty value clears the setting.
            let set = |v: Option<String>, slot: &mut Option<String>| {
                if let Some(v) = v {
                    *slot = (!v.is_empty()).then_some(v);
                }
            };
            set(tsa_user, &mut config.tsa_user);
            set(tsa_policy, &mut config.tsa_policy);
            if let Some(l) = level {
                config.level = Some(format!("{l:?}").to_lowercase());
            }
            if let Some(t) = tsa {
                config.tsa = Some(t);
            }
            store.save_config(&config)?;
            println!("Preferences saved to {}", store.config_path().display());
            Ok(())
        }
    }
}

fn user_cmd(store: &Store, cmd: UserCmd) -> Result<()> {
    match cmd {
        UserCmd::Add { name, cert, no_presence_check, signature, password } => {
            if store.user(&name).is_ok() {
                bail!("user '{name}' already exists");
            }
            let source = cert_source(&cert, &password)?;
            if no_presence_check {
                confirm_presence_off(&name)?;
            }
            let mut user = store.create_user(&name)?;
            let result = (|| {
                set_cert(&mut user, source)?;
                if no_presence_check {
                    user.meta.presence_check = Some(false);
                    user.save_meta()?;
                }
                set_signature(&user, &signature)
            })();
            if result.is_err() {
                let _ = fs::remove_dir_all(&user.dir);
            }
            result?;
            println!("User '{name}' created in {}", user.dir.display());
            print_user(&user);
            Ok(())
        }
        UserCmd::Signature { name, signature } => {
            let user = store.user(&name)?;
            if !set_signature(&user, &signature)? {
                bail!("pass --image, --preview or --from-pdf");
            }
            Ok(())
        }
        UserCmd::Cert { name, cert, password } => {
            let mut user = store.user(&name)?;
            let source = cert_source(&cert, &password)?;
            set_cert(&mut user, source)?;
            print_user(&user);
            Ok(())
        }
        UserCmd::PresenceCheck { name, state } => {
            let mut user = store.user(&name)?;
            if user.meta.system_cert.is_none() {
                bail!("user '{name}' uses a .p12 file, which is protected by its password instead");
            }
            match state {
                OnOff::On => user.meta.presence_check = None,
                OnOff::Off => {
                    confirm_presence_off(&name)?;
                    user.meta.presence_check = Some(false);
                }
            }
            user.save_meta()?;
            print_user(&user);
            Ok(())
        }
        UserCmd::List => {
            let users = store.list()?;
            if users.is_empty() {
                println!("No users yet. Create one with `firma user add NAME --cert cert.p12`");
            }
            for u in users {
                let sig = match u.signature() {
                    Some((SignatureKind::Image, _)) => "signature: image",
                    Some((SignatureKind::Vector, _)) => "signature: vector",
                    None => "no signature",
                };
                let store = if u.meta.system_cert.is_some() { format!(", {}", keystore::STORE) } else { String::new() };
                println!("{:<16} {}  (expires {}, {sig}{store})", u.meta.name, u.meta.holder, u.meta.expires);
            }
            Ok(())
        }
        UserCmd::Info { name } => {
            print_user(&store.user(&name)?);
            Ok(())
        }
        UserCmd::Remove { name, yes } => {
            let user = store.user(&name)?;
            let what = match user.meta.system_cert {
                Some(_) => format!("from {} (the certificate stays in the {})", user.dir.display(), keystore::STORE),
                None => format!("and their certificate from {}", user.dir.display()),
            };
            if !yes && !confirm(&format!("Delete user '{name}' {what}? [y/N] "))? {
                println!("Cancelled.");
                return Ok(());
            }
            store.remove(&name)?;
            println!("User '{name}' deleted.");
            Ok(())
        }
    }
}

/// A certificate given to `user add` / `user cert`, already checked.
enum CertSource {
    P12(Vec<u8>, cert::CertInfo),
    System(keystore::Identity),
}

fn cert_source(args: &CertArgs, password: &PasswordArgs) -> Result<CertSource> {
    if let Some(query) = &args.system_cert {
        let id = keystore::find(query)?;
        // Make sure the key can be used (and its type is supported) before saving anything.
        Credential::system(&id.sha1)?;
        return Ok(CertSource::System(id));
    }
    let path = args.cert.as_ref().expect("clap requires --cert or --system-cert");
    let p12 = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let password = read_password(password, &format!("Password for {}: ", path.display()))?;
    let info = Credential::load(&p12, &password)?.info();
    Ok(CertSource::P12(p12, info))
}

fn set_cert(user: &mut User, source: CertSource) -> Result<()> {
    let info = match source {
        CertSource::P12(p12, info) => {
            write_private(&user.cert_path(), &p12)?;
            user.meta.system_cert = None;
            user.meta.presence_check = None;
            info
        }
        CertSource::System(id) => {
            // No copy of the certificate is kept: the system store has it.
            if user.cert_path().exists() {
                fs::remove_file(user.cert_path())?;
                println!("Removed firma's copy of the .p12; the certificate stays in the {}.", keystore::STORE);
            }
            // Turning the check off was approved for one certificate only.
            if user.meta.system_cert.as_deref() != Some(id.sha1.as_str()) && user.meta.presence_check.is_some() {
                user.meta.presence_check = None;
                println!("The {} check is on again for the new certificate.", keystore::PRESENCE);
            }
            user.meta.system_cert = Some(id.sha1);
            id.info
        }
    };
    update_meta(user, &info)
}

/// Turning off the presence check for a system certificate needs the user there, so that a
/// script or agent cannot do it on its own.
fn confirm_presence_off(name: &str) -> Result<()> {
    keystore::verify_presence(&format!("stop asking for {} when signing as {name}", keystore::PRESENCE))
}

fn update_meta(user: &mut User, info: &cert::CertInfo) -> Result<()> {
    let info = info.clone();
    user.meta.holder = info.holder;
    user.meta.issuer = info.issuer;
    user.meta.expires = info.not_after.with_timezone(&chrono::Local).format("%Y-%m-%d").to_string();
    user.save_meta()
}

fn print_user(u: &User) {
    println!("  name:        {}", u.meta.name);
    println!("  holder:      {}", u.meta.holder);
    println!("  issuer:      {}", u.meta.issuer);
    println!("  expires:     {}", u.meta.expires);
    match &u.meta.system_cert {
        Some(sha1) => {
            println!("  certificate: {} ({sha1})", keystore::STORE);
            let check = if u.meta.presence_check() { "before each signature" } else { "off" };
            println!("  {:<12} {check}", format!("{}:", keystore::PRESENCE));
        }
        None => println!("  certificate: {}", u.cert_path().display()),
    }
    match u.signature() {
        Some((k, p)) => println!(
            "  signature:   {} ({})",
            p.display(),
            if k == SignatureKind::Image { "image" } else { "vector" }
        ),
        None => println!("  signature:   (none)"),
    }
}

/// Returns `false` if no signature source was given.
fn set_signature(user: &User, args: &SignatureArgs) -> Result<bool> {
    let png = user.image_path();
    let vec = user.vector_path();
    if let Some(img) = &args.image {
        write_private(&png, &import_image(img, args.remove_background)?)?;
        let _ = fs::remove_file(&vec);
        println!("Signature saved to {}", png.display());
    } else if let Some(pdf) = &args.from_pdf {
        let data = fs::read(pdf).with_context(|| format!("reading {}", pdf.display()))?;
        write_private(&vec, &preview::extract(&data, args.index)?)?;
        let _ = fs::remove_file(&png);
        println!("Vector signature saved to {}", vec.display());
    } else if args.preview {
        let tpl = user.dir.join("preview-template.pdf");
        write_private(&tpl, &preview::template()?)?;
        open_in_preview(&tpl)?;
        println!("Preview is open. Place your signature in the box, save with ⌘S and press Enter here.");
        let _ = std::io::stdin().lock().read_line(&mut String::new());
        let data = fs::read(&tpl)?;
        let extracted = preview::extract(&data, None);
        let _ = fs::remove_file(&tpl);
        write_private(&vec, &extracted?)?;
        let _ = fs::remove_file(&png);
        println!("Vector signature saved to {}", vec.display());
    } else {
        return Ok(false);
    }
    Ok(true)
}

#[cfg(target_os = "macos")]
fn open_in_preview(path: &Path) -> Result<()> {
    let status = std::process::Command::new("/usr/bin/open").arg("-a").arg("Preview").arg(path).status()?;
    if !status.success() {
        bail!("could not open Preview");
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn open_in_preview(_path: &Path) -> Result<()> {
    bail!("--preview is only available on macOS; use --from-pdf with a PDF signed in Preview")
}

/// Normalizes the image: optionally removes the light background and crops empty margins.
fn import_image(path: &Path, remove_bg: bool) -> Result<Vec<u8>> {
    let mut img = image::open(path).with_context(|| format!("could not open image {}", path.display()))?.to_rgba8();
    if remove_bg {
        for px in img.pixels_mut() {
            let [r, g, b, a] = px.0;
            let min = r.min(g).min(b);
            // Smooth ramp between 200 (opaque) and 245 (transparent) to avoid hard edges.
            let keep = ((245.0 - min as f32) / 45.0).clamp(0.0, 1.0);
            px.0[3] = (a as f32 * keep) as u8;
        }
    }
    // Crop to the ink: transparent and near-white pixels (paper) are margin.
    let (w, h) = img.dimensions();
    let (mut x0, mut y0, mut x1, mut y1) = (w, h, 0, 0);
    for (x, y, px) in img.enumerate_pixels() {
        let [r, g, b, a] = px.0;
        if a > 8 && r.min(g).min(b) < 245 {
            x0 = x0.min(x);
            y0 = y0.min(y);
            x1 = x1.max(x);
            y1 = y1.max(y);
        }
    }
    if x1 < x0 {
        bail!("the image is empty (no ink, only a transparent or white background)");
    }
    let img = image::imageops::crop_imm(&img, x0, y0, x1 - x0 + 1, y1 - y0 + 1).to_image();
    let mut out = std::io::Cursor::new(Vec::new());
    img.write_to(&mut out, image::ImageFormat::Png)?;
    Ok(out.into_inner())
}

fn sign_cmd(store: &Store, a: SignArgs) -> Result<()> {
    let user = store.user(&a.user)?;
    let input = fs::read(&a.input).with_context(|| format!("reading {}", a.input.display()))?;
    let output = a.output.clone().unwrap_or_else(|| {
        let stem = a.input.file_stem().unwrap_or_default().to_string_lossy();
        a.input.with_file_name(format!("{stem}_signed.pdf"))
    });
    if output.exists() && !a.force {
        bail!("{} already exists (use --force to overwrite it)", output.display());
    }

    if a.dry_run {
        return dry_run(store, &user, &input, &output, &a);
    }

    let pdf_password = match pdf_password(&a.pdf_password_file)? {
        Some(p) => Some(p),
        None if pdf::source::Source::needs_password(&input) => Some(prompt_secret("PDF password: ", "--pdf-password-file or $FIRMA_PDF_PASSWORD")?),
        None => None,
    };
    let pdf_password = pdf_password.as_deref();

    let mut cred = match &user.meta.system_cert {
        Some(sha1) => Credential::system(sha1)?,
        None => {
            let p12 = fs::read(user.cert_path()).context("the user has no certificate")?;
            let password = read_password(&a.password, &format!("Certificate password for '{}': ", a.user))?;
            Credential::load(&p12, &password)?
        }
    };
    let info = cred.info();
    let now = chrono::Utc::now();
    if now > info.not_after {
        bail!("{}'s certificate expired on {}", info.holder, info.not_after.format("%Y-%m-%d"));
    }
    if now < info.not_before {
        bail!("{}'s certificate is not valid until {}", info.holder, info.not_before.format("%Y-%m-%d"));
    }
    if user.meta.system_cert.is_some() && user.meta.presence_check() {
        // The dialog names the document by its full path, so the user knows what they approve.
        let path = fs::canonicalize(&a.input).unwrap_or_else(|_| a.input.clone());
        let reason = format!("sign “{}” as {}", dialog_text(&path.to_string_lossy()), dialog_text(&info.holder));
        keystore::verify_presence(&reason)?;
    }

    let signature = user.signature();
    // A field with no handwritten signature to put in it shows the stamp.
    let stamp = a.stamp || !a.stamp_at.is_empty() || a.text.is_some() || (a.field.is_some() && signature.is_none());
    if !a.at.is_empty() && signature.is_none() && !stamp {
        bail!("user '{}' has no handwritten signature; add one with `firma user signature` or use --stamp", a.user);
    }
    let mut stamp_at = a.stamp_at.clone();
    if stamp && a.at.is_empty() && stamp_at.is_empty() && a.field.is_none() {
        stamp_at.push("last:bottom-left".parse()?);
    }

    let config: Config = store.config()?;
    let level = match (a.level, &config.level) {
        (Some(l), _) => l,
        (None, Some(l)) => Level::parse(l)?,
        (None, None) => Level::B,
    };
    let tsa = if level >= Level::T { Some(tsa_settings(&a, &config)?) } else { None };

    let date = chrono::Local::now();
    let stamp_text = stamp.then(|| {
        a.text
            .as_deref()
            .unwrap_or(DEFAULT_TEXT)
            .replace("{name}", &info.holder)
            .replace("{id}", info.id.as_deref().unwrap_or(""))
            .replace("{issuer}", &info.issuer)
            .replace("{date}", &date.format("%Y-%m-%d").to_string())
            .replace("{time}", &date.format("%H:%M").to_string())
            .replace("{reason}", a.reason.as_deref().unwrap_or(""))
            .replace("{location}", a.location.as_deref().unwrap_or(""))
            .replace("\\n", "\n")
    });

    let opts = SignOptions {
        placements: a.at.clone(),
        stamp_placements: stamp_at,
        stamp_text,
        reason: a.reason.clone(),
        location: a.location.clone(),
        contact: a.contact.clone(),
        subfilter: if a.pkcs7 { SubFilter::Pkcs7 } else { SubFilter::Pades },
        reserve: a.reserve.unwrap_or(if level >= Level::T { 65536 } else { 16384 }),
        date,
        field: a.field.clone(),
        allow_overlap: a.allow_overlap,
    };
    let graphic = signature.as_ref().map(|(k, p)| match k {
        SignatureKind::Image => GraphicSource::Image(p),
        SignatureKind::Vector => GraphicSource::Vector(p),
    });

    // With network access (B-T and up) the chain is completed through AIA and embedded in the
    // signature: many .p12 files only contain the end-entity certificate.
    if level >= Level::T {
        let chain = revocation::build_chain(&cred.cert_der, &cred.chain_der)?;
        for der in chain.into_iter().skip(1) {
            if !cred.chain_der.contains(&der) {
                cred.chain_der.push(der);
            }
        }
    }

    // Signature time-stamp (B-T and up): requested over the signature value.
    let tsa_token: std::cell::RefCell<Option<tsa::Token>> = Default::default();
    let timestamp = |signature: &[u8]| -> Result<Vec<u8>> {
        let tsa = tsa.as_ref().unwrap();
        let token = tsa.stamp(signature).with_context(|| format!("time-stamp from {}", tsa.url))?;
        let der = token.der.clone();
        *tsa_token.borrow_mut() = Some(token);
        Ok(der)
    };
    let timestamper: Option<pdf::sign::Timestamper> = tsa.is_some().then_some(&timestamp);
    let signed = pdf::sign::sign_pdf(&input, pdf_password, &cred, graphic, &opts, timestamper)?;
    let mut out = signed.pdf;
    let token = tsa_token.into_inner();

    let mut details = Vec::new();
    if let Some(t) = &token {
        details.push(format!("time-stamp {}", t.time.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S")));
    }
    if level >= Level::Lt {
        // If any certificate in the chain is revoked, abort without writing anything.
        let mut v = revocation::Validation::default();
        let mut pool = cred.chain_der.clone();
        if let Some(t) = &token {
            pool.extend(t.certs.iter().cloned());
        }
        revocation::collect(&mut v, &cred.cert_der, &pool, true)?;
        if let Some(t) = &token {
            revocation::collect(&mut v, &t.signer, &pool, false)?;
        }
        details.push(format!("{} certificates, {} OCSP, {} CRL", v.certs.len(), v.ocsps.len(), v.crls.len()));
        out = pdf::sign::append_dss(&out, pdf_password, &signed.contents, &v)?;
    }
    if level == Level::Lta {
        // Document time-stamp over everything so far, then its own validation data so that the
        // archive time-stamp can be validated later too.
        let tsa = tsa.as_ref().unwrap();
        let doc_token: std::cell::RefCell<Option<tsa::Token>> = Default::default();
        let ts = pdf::sign::add_doc_timestamp(&out, pdf_password, 32768, |digest| {
            let token = tsa
                .stamp_digest(cert::Digest::Sha256, digest)
                .with_context(|| format!("document time-stamp from {}", tsa.url))?;
            let der = token.der.clone();
            *doc_token.borrow_mut() = Some(token);
            Ok(der)
        })?;
        out = ts.pdf;
        let token = doc_token.into_inner().expect("document time-stamp");
        let mut v = revocation::Validation::default();
        revocation::collect(&mut v, &token.signer, &token.certs, false)?;
        out = pdf::sign::append_dss(&out, pdf_password, &ts.contents, &v)?;
        details.push(format!("document time-stamp {}", token.time.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S")));
    }

    fs::write(&output, out).with_context(|| format!("writing {}", output.display()))?;
    let details = if details.is_empty() { String::new() } else { format!(": {}", details.join(", ")) };
    println!("Signed by {} → {} ({}{details})", info.holder, output.display(), level.name());
    Ok(())
}

/// `firma sign --dry-run`: validates the request and describes it, without touching the certificate.
fn dry_run(store: &Store, user: &User, input: &[u8], output: &Path, a: &SignArgs) -> Result<()> {
    if let Some(sha1) = &user.meta.system_cert {
        if !keystore::list()?.iter().any(|c| &c.sha1 == sha1) {
            bail!("{}'s certificate is no longer in the {} (see `firma certs`)", a.user, keystore::STORE);
        }
    }
    let config = store.config()?;
    let level = match (a.level, &config.level) {
        (Some(l), _) => l,
        (None, Some(l)) => Level::parse(l)?,
        (None, None) => Level::B,
    };
    let signature = user.signature();
    // A field with no handwritten signature to put in it shows the stamp.
    let stamp = a.stamp || !a.stamp_at.is_empty() || a.text.is_some() || (a.field.is_some() && signature.is_none());
    if !a.at.is_empty() && signature.is_none() && !stamp {
        bail!("user '{}' has no handwritten signature; add one with `firma user signature` or use --stamp", a.user);
    }
    let mut stamp_at = a.stamp_at.clone();
    if stamp && a.at.is_empty() && stamp_at.is_empty() && a.field.is_none() {
        stamp_at.push("last:bottom-left".parse()?);
    }

    println!("Dry run: nothing has been signed.");
    println!("  signer:      {} ({}), certificate by {}, expires {}", a.user, user.meta.holder, user.meta.issuer, user.meta.expires);
    println!("  input:       {}", a.input.display());
    println!("  output:      {}{}", output.display(), if output.exists() { " (exists, --force given)" } else { "" });
    println!("  level:       {}", level.name());
    let approval = match &user.meta.system_cert {
        Some(_) if user.meta.presence_check() => {
            format!("{} ({}); the dialog names the document", keystore::PRESENCE, keystore::STORE)
        }
        Some(_) => format!("none ({}, presence check off)", keystore::STORE),
        None if a.password.password_file.is_some() => "certificate password from --password-file".to_string(),
        None => "certificate password, typed in the terminal".to_string(),
    };
    println!("  approval:    {approval}");
    if level >= Level::T {
        let tsa = tsa_settings_no_secret(a, &config);
        println!("  TSA:         {tsa}");
    }

    let password = pdf_password(&a.pdf_password_file)?;
    if password.is_none() && pdf::source::Source::needs_password(input) {
        println!("  PDF:         encrypted; its password will be asked (or use --pdf-password-file)");
        return Ok(());
    }
    let src = pdf::source::Source::open(input, password.as_deref())?;
    println!(
        "  PDF:         {} page(s){}",
        src.doc.get_pages().len(),
        if src.doc.encryption_state.is_some() { ", encrypted" } else { "" }
    );
    // What is already there: earlier signatures, empty fields, the author's certification.
    let root = src.root_id()?;
    let existing = pdf::fields::signature_fields(&src.doc, root);
    let place = |f: &pdf::fields::SigField| {
        let boxes: Vec<String> = f
            .widgets
            .iter()
            .map(|w| {
                let [x, y, bw, bh] = pdf::sign::displayed_mm(&src.doc, w.page, w.rect);
                format!("page {} at {x:.0},{y:.0}:{bw:.0}x{bh:.0}", w.page_num)
            })
            .collect();
        if boxes.is_empty() { "invisible".to_string() } else { boxes.join("; ") }
    };
    if let Some(p) = pdf::fields::certification(&src.doc, root) {
        let what = match p {
            1 => "no changes allowed",
            2 => "only form filling and signing its existing fields",
            _ => "form filling, signing and annotations allowed",
        };
        println!("  certified:   by its author ({what})");
    }
    if existing.iter().any(|f| f.signed) {
        println!("  note:        earlier signatures are listed as recorded in the file, not verified");
    }
    for f in &existing {
        if f.timestamp {
            println!("  time-stamp:  {} ({})", f.name, place(f));
        } else if f.signed {
            let by = f.signer.as_ref().map(|s| format!(" by \"{s}\"")).unwrap_or_default();
            println!("  signed:      {}{by} ({})", f.name, place(f));
        } else {
            println!("  empty field: {} ({}); sign into it with --field {}", f.name, place(f), shell_quote(&f.name));
        }
    }
    pdf::sign::check_certification(&src.doc, root, a.field.is_some())?;
    if let Some(name) = &a.field {
        let f = pdf::sign::empty_field(&existing, name)?;
        println!("  into field:  {} ({})", f.name, place(f));
    } else {
        let report = pdf::sign::overlap_report(&src.doc, root, &a.at, &stamp_at)?;
        if !report.is_empty() {
            if !a.allow_overlap {
                bail!(
                    "the new signature would cover existing signature boxes:\n  {}\nmove it or pass --allow-overlap",
                    report.join("\n  ")
                );
            }
            println!("  overlaps:    {} (--allow-overlap)", report.join("; "));
        }
    }

    let describe = |label: &str, boxes: Vec<pdf::sign::BoxPreview>| {
        for (page, rotate, (w, h)) in boxes {
            let rot = if rotate != 0 { format!(" (page rotated {rotate}°)") } else { String::new() };
            println!("  {label:<12} page {page}, {w:.0}x{h:.0} mm{rot}");
        }
    };
    describe("signature:", pdf::sign::preview_boxes(&src.doc, &a.at, pdf::sign::DEFAULT_SIGNATURE_SIZE)?);
    describe("stamp:", pdf::sign::preview_boxes(&src.doc, &stamp_at, pdf::sign::DEFAULT_STAMP_SIZE)?);
    if a.at.is_empty() && stamp_at.is_empty() && a.field.is_none() {
        println!("  visible:     no (invisible signature)");
    }
    if stamp {
        let now = chrono::Local::now();
        let text = a
            .text
            .as_deref()
            .unwrap_or(DEFAULT_TEXT)
            .replace("{name}", &user.meta.holder)
            .replace("{issuer}", &user.meta.issuer)
            .replace("{date}", &now.format("%Y-%m-%d").to_string())
            .replace("{time}", &now.format("%H:%M").to_string())
            .replace("{reason}", a.reason.as_deref().unwrap_or(""))
            .replace("{location}", a.location.as_deref().unwrap_or(""));
        println!("  stamp text:  {text}");
    }
    Ok(())
}

/// The TSA as a display string (URL and user), without reading any password.
fn tsa_settings_no_secret(a: &SignArgs, config: &Config) -> String {
    let url = a.tsa.clone().or(config.tsa.clone()).or_else(|| std::env::var("FIRMA_TSA").ok()).unwrap_or_else(|| DEFAULT_TSA.to_string());
    match a.tsa_user.clone().or(config.tsa_user.clone()) {
        Some(u) => format!("{url} (user {u})"),
        None => url,
    }
}

fn tsa_settings(a: &SignArgs, config: &Config) -> Result<tsa::Tsa> {
    let url = a
        .tsa
        .clone()
        .or(config.tsa.clone())
        .or_else(|| std::env::var("FIRMA_TSA").ok())
        .unwrap_or_else(|| DEFAULT_TSA.to_string());
    let user = a.tsa_user.clone().or(config.tsa_user.clone());
    if user.is_some() && url == DEFAULT_TSA {
        bail!("a TSA user is configured but no TSA URL: set one with --tsa or `firma config --tsa`");
    }
    let password = match (&user, &a.tsa_password_file) {
        (_, Some(f)) => Some(read_secret_file(f)?),
        (Some(u), None) => Some(match std::env::var("FIRMA_TSA_PASSWORD") {
            Ok(p) => p,
            Err(_) => prompt_secret(&format!("TSA password for {u}: "), "--tsa-password-file or $FIRMA_TSA_PASSWORD")?,
        }),
        (None, None) => None,
    };
    let policy = match a.tsa_policy.clone().or(config.tsa_policy.clone()) {
        Some(p) => Some(p.parse().map_err(|_| anyhow::anyhow!("invalid TSA policy OID '{p}'"))?),
        None => None,
    };
    Ok(tsa::Tsa { url, user, password, policy })
}

fn pdf_password(file: &Option<PathBuf>) -> Result<Option<String>> {
    if let Some(f) = file {
        return Ok(Some(read_secret_file(f)?));
    }
    Ok(std::env::var("FIRMA_PDF_PASSWORD").ok())
}

fn read_secret_file(f: &Path) -> Result<String> {
    let s = fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?;
    Ok(s.trim_end_matches(['\r', '\n']).to_string())
}

fn read_password(args: &PasswordArgs, prompt: &str) -> Result<String> {
    if let Some(f) = &args.password_file {
        return read_secret_file(f);
    }
    if let Ok(p) = std::env::var("FIRMA_PASSWORD") {
        return Ok(p);
    }
    prompt_secret(prompt, "--password-file or $FIRMA_PASSWORD")
}

/// Asks for a secret on the terminal. Without one (e.g. when run by an AI agent or a script),
/// explains how else to provide it.
fn prompt_secret(prompt: &str, alternatives: &str) -> Result<String> {
    rpassword::prompt_password(prompt).map_err(|e| {
        anyhow::anyhow!("cannot ask for the password: no terminal available ({e}); provide it with {alternatives}")
    })
}

/// A name from a PDF as one literal shell argument (POSIX shells; PowerShell on Windows).
fn shell_quote(s: &str) -> String {
    if cfg!(windows) {
        format!("'{}'", s.replace('\'', "''"))
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// Text for a system dialog: no control characters or quotes that could fake its wording.
fn dialog_text(s: &str) -> String {
    s.chars().filter(|c| !c.is_control() && !matches!(c, '"' | '“' | '”')).collect()
}

fn confirm(prompt: &str) -> Result<bool> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(matches!(line.trim().to_lowercase().as_str(), "y" | "yes"))
}
