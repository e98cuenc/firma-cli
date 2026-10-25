mod cert;
mod cms;
mod net;
mod pdf;
mod preview;
mod revocation;
mod store;
mod tsa;

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
    Sign(SignArgs),
    /// Show or change preferences (default PAdES level and TSA)
    Config {
        /// Default PAdES level
        #[arg(long, value_enum)]
        level: Option<Level>,
        /// Default TSA (RFC 3161 URL)
        #[arg(long)]
        tsa: Option<String>,
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
}

impl Level {
    fn parse(s: &str) -> Result<Self> {
        Level::from_str(s, true).map_err(|_| anyhow::anyhow!("invalid level '{s}' (b, t or lt)"))
    }

    fn name(self) -> &'static str {
        match self {
            Level::B => "PAdES B-B",
            Level::T => "PAdES B-T",
            Level::Lt => "PAdES B-LT",
        }
    }
}

#[derive(Subcommand)]
enum UserCmd {
    /// Add a user with their certificate (.p12/.pfx)
    Add {
        name: String,
        /// PKCS#12 certificate (.p12 / .pfx) with the private key
        #[arg(long, short = 'c')]
        cert: PathBuf,
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
    /// Replace a user's certificate (e.g. after renewing it)
    Cert {
        name: String,
        cert: PathBuf,
        #[command(flatten)]
        password: PasswordArgs,
    },
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
    /// PAdES level: b, t (time-stamp) or lt (time-stamp + revocation). Default: from `firma config`, or b
    #[arg(long, value_enum)]
    level: Option<Level>,
    /// Time-stamping authority (RFC 3161 URL); default: from `firma config`, $FIRMA_TSA, or Izenpe
    #[arg(long, value_name = "URL")]
    tsa: Option<String>,
    /// Bytes reserved for the CMS signature (default 16384, or 65536 with a time-stamp)
    #[arg(long)]
    reserve: Option<usize>,
    /// Overwrite the output if it already exists
    #[arg(long, short = 'f')]
    force: bool,
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
        Cmd::Sign(a) => sign_cmd(&store, a),
        Cmd::Config { level, tsa } => {
            let mut config = store.config()?;
            if level.is_none() && tsa.is_none() {
                println!("{}", store.config_path().display());
                println!("  level: {}", config.level.as_deref().unwrap_or("b"));
                println!("  tsa:   {}", config.tsa.as_deref().unwrap_or(DEFAULT_TSA));
                return Ok(());
            }
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
        UserCmd::Add { name, cert, signature, password } => {
            let p12 = fs::read(&cert).with_context(|| format!("reading {}", cert.display()))?;
            let password = read_password(&password, &format!("Password for {}: ", cert.display()))?;
            let cred = Credential::load(&p12, &password)?;
            let mut user = store.create_user(&name)?;
            let result = (|| {
                write_private(&user.cert_path(), &p12)?;
                update_meta(&mut user, &cred)?;
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
            let p12 = fs::read(&cert).with_context(|| format!("reading {}", cert.display()))?;
            let password = read_password(&password, &format!("Password for {}: ", cert.display()))?;
            let cred = Credential::load(&p12, &password)?;
            write_private(&user.cert_path(), &p12)?;
            update_meta(&mut user, &cred)?;
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
                println!("{:<16} {}  (expires {}, {sig})", u.meta.name, u.meta.holder, u.meta.expires);
            }
            Ok(())
        }
        UserCmd::Info { name } => {
            print_user(&store.user(&name)?);
            Ok(())
        }
        UserCmd::Remove { name, yes } => {
            let user = store.user(&name)?;
            if !yes && !confirm(&format!("Delete user '{name}' and their certificate from {}? [y/N] ", user.dir.display()))? {
                println!("Cancelled.");
                return Ok(());
            }
            store.remove(&name)?;
            println!("User '{name}' deleted.");
            Ok(())
        }
    }
}

fn update_meta(user: &mut User, cred: &Credential) -> Result<()> {
    let info = cred.info();
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
    println!("  certificate: {}", u.cert_path().display());
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
    let (w, h) = img.dimensions();
    let (mut x0, mut y0, mut x1, mut y1) = (w, h, 0, 0);
    for (x, y, px) in img.enumerate_pixels() {
        if px.0[3] > 8 {
            x0 = x0.min(x);
            y0 = y0.min(y);
            x1 = x1.max(x);
            y1 = y1.max(y);
        }
    }
    if x1 < x0 {
        bail!("the image is empty (fully transparent)");
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

    let p12 = fs::read(user.cert_path()).context("the user has no certificate")?;
    let password = read_password(&a.password, &format!("Certificate password for '{}': ", a.user))?;
    let mut cred = Credential::load(&p12, &password)?;
    let info = cred.info();
    let now = chrono::Utc::now();
    if now > info.not_after {
        bail!("{}'s certificate expired on {}", info.holder, info.not_after.format("%Y-%m-%d"));
    }
    if now < info.not_before {
        bail!("{}'s certificate is not valid until {}", info.holder, info.not_before.format("%Y-%m-%d"));
    }

    let signature = user.signature();
    let stamp = a.stamp || !a.stamp_at.is_empty() || a.text.is_some();
    if !a.at.is_empty() && signature.is_none() && !stamp {
        bail!("user '{}' has no handwritten signature; add one with `firma user signature` or use --stamp", a.user);
    }
    let mut stamp_at = a.stamp_at.clone();
    if stamp && a.at.is_empty() && stamp_at.is_empty() {
        stamp_at.push("last:bottom-left".parse()?);
    }

    let config: Config = store.config()?;
    let level = match (a.level, &config.level) {
        (Some(l), _) => l,
        (None, Some(l)) => Level::parse(l)?,
        (None, None) => Level::B,
    };
    let tsa_url = a
        .tsa
        .clone()
        .or(config.tsa.clone())
        .or_else(|| std::env::var("FIRMA_TSA").ok())
        .unwrap_or_else(|| DEFAULT_TSA.to_string());

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
    };
    let graphic = signature.as_ref().map(|(k, p)| match k {
        SignatureKind::Image => GraphicSource::Image(p),
        SignatureKind::Vector => GraphicSource::Vector(p),
    });

    // With network access (B-T, B-LT) the chain is completed through AIA and embedded in the
    // signature: many .p12 files only contain the end-entity certificate.
    if level >= Level::T {
        let chain = revocation::build_chain(&cred.cert_der, &cred.chain_der)?;
        for der in chain.into_iter().skip(1) {
            if !cred.chain_der.contains(&der) {
                cred.chain_der.push(der);
            }
        }
    }

    // Time-stamp (B-T and B-LT): requested over the signature value.
    let tsa_token: std::cell::RefCell<Option<tsa::Token>> = Default::default();
    let timestamp = |signature: &[u8]| -> Result<Vec<u8>> {
        let token = tsa::request(&tsa_url, signature).with_context(|| format!("time-stamp from {tsa_url}"))?;
        let der = token.der.clone();
        *tsa_token.borrow_mut() = Some(token);
        Ok(der)
    };
    let timestamper: Option<pdf::sign::Timestamper> = (level >= Level::T).then_some(&timestamp);
    let signed = pdf::sign::sign_pdf(&input, &cred, graphic, &opts, timestamper)?;
    let mut out = signed.pdf;
    let token = tsa_token.into_inner();

    let mut details = Vec::new();
    if let Some(t) = &token {
        details.push(format!("time-stamp {}", t.time.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S")));
    }
    if level == Level::Lt {
        // If any certificate in the chain is revoked, abort without writing anything.
        let mut v = revocation::Validation::default();
        let mut pool = cred.chain_der.clone();
        if let Some(t) = &token {
            pool.extend(t.certs.iter().cloned());
        }
        revocation::collect(&mut v, &cred.cert_der, &pool, true)?;
        if let Some(signer) = token.as_ref().and_then(|t| t.signer.as_ref()) {
            revocation::collect(&mut v, signer, &pool, false)?;
        }
        details.push(format!("{} certificates, {} OCSP, {} CRL", v.certs.len(), v.ocsps.len(), v.crls.len()));
        out = pdf::sign::append_dss(&out, &signed.contents, &v)?;
    }

    fs::write(&output, out).with_context(|| format!("writing {}", output.display()))?;
    let details = if details.is_empty() { String::new() } else { format!(": {}", details.join(", ")) };
    println!("Signed by {} → {} ({}{details})", info.holder, output.display(), level.name());
    Ok(())
}

fn read_password(args: &PasswordArgs, prompt: &str) -> Result<String> {
    if let Some(f) = &args.password_file {
        let s = fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?;
        return Ok(s.trim_end_matches(['\r', '\n']).to_string());
    }
    if let Ok(p) = std::env::var("FIRMA_PASSWORD") {
        return Ok(p);
    }
    Ok(rpassword::prompt_password(prompt)?)
}

fn confirm(prompt: &str) -> Result<bool> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(matches!(line.trim().to_lowercase().as_str(), "y" | "yes"))
}
