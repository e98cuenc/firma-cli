//! Certificates on PKCS#11 tokens: smart cards such as the Spanish DNIe (through OpenSC or the
//! official DNIe module), USB tokens and HSMs. firma loads the token's PKCS#11 module, the key
//! never leaves the token, and the token's PIN approves each signature.
//!
//! Keys that ask for the PIN at every signature (CKA_ALWAYS_AUTHENTICATE, like the DNIe's signing
//! key) get it again right before signing, without asking the user twice.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error, RvError};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use der::Decode;
use x509_cert::Certificate;

use crate::cert::{cert_info, Digest, KeyAlg};
use crate::keystore::{self, Identity};

/// Where OpenSC and the official DNIe module usually install their PKCS#11 module.
const MODULES: &[&str] = if cfg!(target_os = "macos") {
    &[
        "/Library/OpenSC/lib/opensc-pkcs11.so",
        "/opt/homebrew/lib/opensc-pkcs11.so",
        "/usr/local/lib/opensc-pkcs11.so",
        "/Library/Libpkcs11-dnie/lib/libpkcs11-dnie.so",
    ]
} else if cfg!(windows) {
    &[
        r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll",
        r"C:\Windows\System32\opensc-pkcs11.dll",
    ]
} else {
    &[
        "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
        "/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so",
        "/usr/lib64/opensc-pkcs11.so",
        "/usr/lib/opensc-pkcs11.so",
        "/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so",
        "/usr/lib/libpkcs11-dnie.so",
    ]
};

/// The module to use: the one given, else $FIRMA_PKCS11_MODULE, else an installed OpenSC or DNIe
/// module. Returned as an absolute path, so that it can be saved with the user.
pub fn module(given: Option<&Path>) -> Result<PathBuf> {
    let path = match given.map(Path::to_path_buf).or_else(|| std::env::var_os("FIRMA_PKCS11_MODULE").map(PathBuf::from)) {
        Some(p) => p,
        None => MODULES.iter().map(PathBuf::from).find(|p| p.exists()).with_context(|| {
            format!(
                "no PKCS#11 module found (looked for OpenSC and the DNIe module in {}); \
                 install OpenSC or pass --pkcs11-module",
                MODULES.join(", ")
            )
        })?,
    };
    if !path.is_file() {
        bail!("PKCS#11 module {} not found", path.display());
    }
    // Absolute, but through any symlink: package managers keep the link stable across upgrades.
    Ok(std::path::absolute(&path)?)
}

fn open(module: &Path) -> Result<Pkcs11> {
    let ctx = Pkcs11::new(module).map_err(|e| {
        let hint = if cfg!(target_env = "musl") {
            " (this firma build is fully static and cannot load PKCS#11 modules; install the \
             firma-*-linux-gnu release build instead, or build it with `cargo install`)"
        } else {
            ""
        };
        anyhow!("could not load the PKCS#11 module {}: {e}{hint}", module.display())
    })?;
    match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) | Err(Error::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => Ok(ctx),
        Err(e) => Err(anyhow!("could not initialize the PKCS#11 module {}: {e}", module.display())),
    }
}

/// A certificate on a token.
#[derive(Clone)]
pub struct TokenCert {
    pub id: Identity,
    /// Token label, e.g. "DNI electrónico".
    pub token: String,
    /// Meant for signatures (nonRepudiation): the DNIe's FIRMA certificate, not AUTENTICACIÓN.
    pub signing: bool,
}

struct Found {
    slot: Slot,
    token: String,
    der: Vec<u8>,
    ckid: Vec<u8>,
}

fn certificates(ctx: &Pkcs11) -> Result<Vec<Found>> {
    let mut out = Vec::new();
    for slot in ctx.get_slots_with_token()? {
        // Slots with an unrecognized card or an uninitialized token are skipped, not fatal.
        let Ok(info) = ctx.get_token_info(slot) else { continue };
        if !info.token_initialized() {
            continue;
        }
        let token = info.label().trim().to_string();
        let Ok(session) = ctx.open_ro_session(slot) else { continue };
        for obj in session.find_objects(&[Attribute::Class(ObjectClass::CERTIFICATE)])? {
            let attrs = session.get_attributes(obj, &[AttributeType::Value, AttributeType::Id])?;
            let (mut der, mut ckid) = (Vec::new(), Vec::new());
            for a in attrs {
                match a {
                    Attribute::Value(v) => der = v,
                    Attribute::Id(v) => ckid = v,
                    _ => {}
                }
            }
            if !der.is_empty() {
                out.push(Found { slot, token: token.clone(), der, ckid });
            }
        }
    }
    Ok(out)
}

/// The certificates on the tokens the module can see (no PIN needed).
pub fn list(module: &Path) -> Result<Vec<TokenCert>> {
    let ctx = open(module)?;
    let mut out: Vec<TokenCert> = Vec::new();
    for f in certificates(&ctx)? {
        let Ok(cert) = Certificate::from_der(&f.der) else { continue };
        let sha1 = keystore::fingerprint(&f.der);
        if out.iter().any(|c| c.id.sha1 == sha1) {
            continue;
        }
        out.push(TokenCert { id: Identity { sha1, info: cert_info(&cert) }, token: f.token, signing: non_repudiation(&cert) });
    }
    out.sort_by(|a, b| a.id.info.holder.cmp(&b.id.info.holder));
    Ok(out)
}

/// The one certificate matching `query` (fingerprint, or part of the holder's name or ID). When
/// several match, the one meant for signatures wins: a DNIe holds an authentication and a
/// signing certificate for the same person.
pub fn find(module: &Path, query: &str) -> Result<TokenCert> {
    let all = list(module)?;
    if all.is_empty() {
        bail!("no certificates on any token seen by {} (is the card in the reader?)", module.display());
    }
    let ids = keystore::select(all.iter().map(|c| c.id.clone()).collect(), query, chrono::Utc::now());
    let mut matches: Vec<TokenCert> = all.into_iter().filter(|c| ids.iter().any(|i| i.sha1 == c.id.sha1)).collect();
    if matches.len() > 1 && matches.iter().filter(|c| c.signing).count() == 1 {
        matches.retain(|c| c.signing);
    }
    match matches.len() {
        0 => bail!("no certificate on the token matches '{query}' (see `firma certs --pkcs11`)"),
        1 => Ok(matches.remove(0)),
        _ => {
            let lines: Vec<String> = matches.iter().map(describe).collect();
            bail!("'{query}' matches several certificates; pass the SHA-1 fingerprint instead:\n{}", lines.join("\n"))
        }
    }
}

pub fn describe(c: &TokenCert) -> String {
    let usage = if c.signing { "signing" } else { "not for signing" };
    format!("{}  [{}, {usage}]", keystore::describe(&c.id), c.token)
}

fn non_repudiation(cert: &Certificate) -> bool {
    use x509_cert::ext::pkix::{KeyUsage, KeyUsages};
    let Some(exts) = &cert.tbs_certificate.extensions else { return false };
    exts.iter()
        .find(|e| e.extn_id == der::asn1::ObjectIdentifier::new_unwrap("2.5.29.15"))
        .and_then(|e| KeyUsage::from_der(e.extn_value.as_bytes()).ok())
        .is_some_and(|ku| ku.0.contains(KeyUsages::NonRepudiation))
}

/// What the PIN prompt gets to know about the token.
pub struct PinRequest<'a> {
    pub token: &'a str,
    /// A warning to show first, e.g. that one wrong PIN more locks the card.
    pub warning: Option<&'static str>,
}

/// A private key on a token, logged in and ready to sign.
pub struct TokenKey {
    session: Session,
    key: ObjectHandle,
    pub alg: KeyAlg,
    mechanisms: Vec<MechanismType>,
    /// Kept only for keys that need it again at each signature.
    pin: Option<AuthPin>,
    always_auth: bool,
}

/// Logs in to the token holding the certificate `sha1` and returns its key, the certificate and
/// the other certificates on the token (usually the issuing CA's). `pin` is asked only if the
/// token has no PIN pad of its own.
pub fn load(
    module: &Path,
    sha1: &str,
    pin: impl FnOnce(&PinRequest) -> Result<String>,
) -> Result<(TokenKey, Vec<u8>, Vec<Vec<u8>>)> {
    let ctx = open(module)?;
    let all = certificates(&ctx)?;
    let found = all
        .iter()
        .find(|f| keystore::fingerprint(&f.der) == sha1)
        .with_context(|| format!("the certificate {sha1} is not on any token (is the card in the reader?)"))?;
    let chain: Vec<Vec<u8>> =
        all.iter().filter(|f| f.slot == found.slot && f.der != found.der).map(|f| f.der.clone()).collect();
    let cert = Certificate::from_der(&found.der).map_err(|e| anyhow!("unreadable certificate: {e}"))?;
    let alg = KeyAlg::of(&cert)?;

    let info = ctx.get_token_info(found.slot)?;
    if info.user_pin_locked() {
        bail!("the PIN of {} is locked; unlock it before signing", found.token);
    }
    let session = ctx.open_ro_session(found.slot)?;
    let pin = if info.protected_authentication_path() {
        eprintln!("Enter the PIN on the card reader.");
        login(&session, UserType::User, None, &found.token)?;
        None
    } else {
        let warning = if info.user_pin_final_try() {
            Some("one more wrong PIN locks the card")
        } else if info.user_pin_count_low() {
            Some("a wrong PIN was entered recently; the card locks after a few failures")
        } else {
            None
        };
        let p = AuthPin::from(pin(&PinRequest { token: &found.token, warning })?);
        login(&session, UserType::User, Some(&p), &found.token)?;
        Some(p)
    };

    let key = private_key(&session, &found.ckid)?;
    let always_auth = session
        .get_attributes(key, &[AttributeType::AlwaysAuthenticate])
        .ok()
        .is_some_and(|a| a.iter().any(|a| matches!(a, Attribute::AlwaysAuthenticate(true))));
    let mechanisms = ctx.get_mechanism_list(found.slot)?;
    let key = TokenKey { session, key, alg, mechanisms, pin: if always_auth { pin } else { None }, always_auth };
    Ok((key, found.der.clone(), chain))
}

fn login(session: &Session, user: UserType, pin: Option<&AuthPin>, token: &str) -> Result<()> {
    match session.login(user, pin) {
        Ok(()) | Err(Error::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(()),
        Err(Error::Pkcs11(RvError::PinIncorrect, _)) => bail!("wrong PIN for {token}"),
        Err(Error::Pkcs11(RvError::PinLocked, _)) => bail!("the PIN of {token} is locked"),
        Err(e) => Err(anyhow!("could not log in to {token}: {e}")),
    }
}

/// The private key with the certificate's CKA_ID; a token with a single key and no matching ID
/// gets that one (the signature is checked against the certificate anyway).
fn private_key(session: &Session, ckid: &[u8]) -> Result<ObjectHandle> {
    if !ckid.is_empty() {
        let keys = session.find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY), Attribute::Id(ckid.to_vec())])?;
        if let Some(k) = keys.first() {
            return Ok(*k);
        }
    }
    let keys = session.find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)])?;
    match keys.as_slice() {
        [k] => Ok(*k),
        [] => bail!("the token has no private key for this certificate"),
        _ => bail!("the token has several private keys and none has the certificate's ID"),
    }
}

impl TokenKey {
    /// Signs `data` with `digest` (the credential's). Returns RSA PKCS#1 v1.5 or DER ECDSA.
    pub fn sign(&self, data: &[u8], digest: Digest) -> Result<Vec<u8>> {
        let has = |m: MechanismType| self.mechanisms.contains(&m);
        // We hash and the token signs the digest (what every token supports). A key that wants the
        // PIN at each signature needs it between C_SignInit and C_Sign, which only the multi-part
        // functions allow, so there the token hashes the data itself.
        let (hashing, raw, input) = match (self.alg, digest) {
            (KeyAlg::Rsa, Digest::Sha256) => (
                has(MechanismType::SHA256_RSA_PKCS).then_some(Mechanism::Sha256RsaPkcs),
                Mechanism::RsaPkcs,
                [SHA256_DIGEST_INFO, &digest.hash(&[data])].concat(),
            ),
            (KeyAlg::Rsa, Digest::Sha384) => (
                has(MechanismType::SHA384_RSA_PKCS).then_some(Mechanism::Sha384RsaPkcs),
                Mechanism::RsaPkcs,
                [SHA384_DIGEST_INFO, &digest.hash(&[data])].concat(),
            ),
            (_, Digest::Sha256) => {
                (has(MechanismType::ECDSA_SHA256).then_some(Mechanism::EcdsaSha256), Mechanism::Ecdsa, digest.hash(&[data]))
            }
            (_, Digest::Sha384) => {
                (has(MechanismType::ECDSA_SHA384).then_some(Mechanism::EcdsaSha384), Mechanism::Ecdsa, digest.hash(&[data]))
            }
        };
        let sig = match (self.always_auth, hashing) {
            (false, _) => self.session.sign(&raw, self.key, &input)?,
            (true, Some(mech)) => {
                self.session.sign_init(&mech, self.key)?;
                login(&self.session, UserType::ContextSpecific, self.pin.as_ref(), "the token")?;
                self.session.sign_update(data)?;
                self.session.sign_final()?
            }
            (true, None) => bail!(
                "the token asks for the PIN at every signature but cannot hash the data itself \
                 (no {:?} mechanism with SHA-2)",
                self.alg
            ),
        };
        keystore::ecdsa_raw_to_der(self.alg, &sig)
    }
}

/// DigestInfo prefixes (RFC 8017, section 9.2) for RSA PKCS#1 v1.5 over a precomputed digest.
const SHA256_DIGEST_INFO: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
];
const SHA384_DIGEST_INFO: &[u8] = &[
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
];
