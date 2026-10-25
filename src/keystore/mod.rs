//! Certificates whose private key lives in the operating system: the macOS Keychain or the
//! Windows certificate store (current user, "Personal"). The key never leaves the system, which
//! signs for us; no password goes through firma.
//!
//! Signing with one of them first asks for the user's presence (Touch ID / Windows Hello) with
//! the document name in the dialog, unless the user turned that off.

use anyhow::{anyhow, bail, Result};
use der::Decode;
use x509_cert::Certificate;

use crate::cert::{cert_info, CertInfo, KeyAlg};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as os;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as os;

#[cfg(not(any(target_os = "macos", windows)))]
mod os {
    use anyhow::{bail, Result};

    pub struct Key;

    pub fn certificates() -> Result<Vec<Vec<u8>>> {
        bail!("system certificates are only available on macOS and Windows; use a .p12/.pfx file")
    }

    pub fn load(_sha1: &[u8; 20]) -> Result<(Key, Vec<u8>, Vec<Vec<u8>>)> {
        certificates().map(|_| unreachable!())
    }

    pub fn sign(_key: &Key, _alg: crate::cert::KeyAlg, _digest: &[u8]) -> Result<Vec<u8>> {
        certificates().map(|_| unreachable!())
    }

    pub fn verify_presence(_reason: &str) -> Result<()> {
        certificates().map(|_| ())
    }
}

/// Where the certificates come from, for messages.
pub const STORE: &str = if cfg!(target_os = "macos") {
    "macOS Keychain"
} else if cfg!(windows) {
    "Windows certificate store"
} else {
    "system certificate store"
};

/// How the user proves they are there, for messages.
pub const PRESENCE: &str = if cfg!(target_os = "macos") {
    "Touch ID"
} else if cfg!(windows) {
    "Windows Hello"
} else {
    "presence check"
};

pub struct SystemKey {
    pub alg: KeyAlg,
    inner: os::Key,
}

impl SystemKey {
    /// Signs a digest made with `alg.digest()`. Returns RSA PKCS#1 v1.5 or DER ECDSA signatures.
    pub fn sign(&self, digest: &[u8]) -> Result<Vec<u8>> {
        os::sign(&self.inner, self.alg, digest)
    }
}

/// A certificate with a private key in the system store.
#[derive(Clone)]
pub struct Identity {
    /// SHA-1 fingerprint in uppercase hex, as Keychain Access and certmgr show it.
    pub sha1: String,
    pub info: CertInfo,
}

pub fn list() -> Result<Vec<Identity>> {
    let mut out: Vec<Identity> = Vec::new();
    for der in os::certificates()? {
        let Ok(cert) = Certificate::from_der(&der) else { continue };
        let sha1 = fingerprint(&der);
        if !out.iter().any(|i| i.sha1 == sha1) {
            out.push(Identity { sha1, info: cert_info(&cert) });
        }
    }
    out.sort_by(|a, b| a.info.holder.cmp(&b.info.holder).then(b.info.not_after.cmp(&a.info.not_after)));
    Ok(out)
}

/// The one certificate matching `query`: a SHA-1 fingerprint (or its first 8+ digits), or
/// part of the holder's name or ID among the unexpired ones.
pub fn find(query: &str) -> Result<Identity> {
    let mut matches = select(list()?, query, chrono::Utc::now());
    match matches.len() {
        0 => bail!("no certificate with a private key in the {STORE} matches '{query}' (see `firma certs`)"),
        1 => Ok(matches.remove(0)),
        _ => {
            let lines: Vec<String> = matches.iter().map(describe).collect();
            bail!("'{query}' matches several certificates; pass the SHA-1 fingerprint instead:\n{}", lines.join("\n"))
        }
    }
}

fn select(all: Vec<Identity>, query: &str, now: chrono::DateTime<chrono::Utc>) -> Vec<Identity> {
    let hex: String = query.chars().filter(|c| !matches!(c, ' ' | ':')).collect::<String>().to_uppercase();
    if hex.len() >= 8 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        let by_hash: Vec<Identity> = all.iter().filter(|i| i.sha1.starts_with(&hex)).cloned().collect();
        if !by_hash.is_empty() {
            return by_hash;
        }
    }
    let q = fold(query);
    all.into_iter()
        .filter(|i| i.info.not_after > now)
        .filter(|i| fold(&i.info.holder).contains(&q) || i.info.id.as_deref().is_some_and(|id| fold(id) == q))
        .collect()
}

/// Lowercase without accents, so that "perez" finds "PÉREZ".
fn fold(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .filter(|c| !('\u{300}'..='\u{36f}').contains(c)) // combining accents
        .map(|c| match c {
            'á' | 'à' | 'ä' | 'â' | 'ã' => 'a',
            'é' | 'è' | 'ë' | 'ê' => 'e',
            'í' | 'ì' | 'ï' | 'î' => 'i',
            'ó' | 'ò' | 'ö' | 'ô' | 'õ' => 'o',
            'ú' | 'ù' | 'ü' | 'û' => 'u',
            'ñ' => 'n',
            'ç' => 'c',
            c => c,
        })
        .collect()
}

pub fn describe(i: &Identity) -> String {
    let expired = if i.info.not_after < chrono::Utc::now() { " EXPIRED" } else { "" };
    format!(
        "{}  {}  ({}, expires {}{expired})",
        i.sha1,
        i.info.holder,
        i.info.issuer,
        i.info.not_after.with_timezone(&chrono::Local).format("%Y-%m-%d")
    )
}

/// The key, certificate and chain (without the certificate itself) of the identity `sha1`.
pub fn load(sha1: &str) -> Result<(SystemKey, Vec<u8>, Vec<Vec<u8>>)> {
    let bytes = hex_decode(sha1).ok_or_else(|| anyhow!("invalid certificate fingerprint '{sha1}'"))?;
    let (inner, cert_der, chain) = os::load(&bytes)?;
    let cert = Certificate::from_der(&cert_der).map_err(|e| anyhow!("unreadable certificate: {e}"))?;
    Ok((SystemKey { alg: KeyAlg::of(&cert)?, inner }, cert_der, chain))
}

/// Asks the user to confirm with Touch ID / Windows Hello (or their account password).
/// `reason` completes "firma is trying to …" in the dialog.
pub fn verify_presence(reason: &str) -> Result<()> {
    // Only in debug builds, for automated tests: release builds always ask.
    #[cfg(debug_assertions)]
    if std::env::var_os("FIRMA_TEST_SKIP_PRESENCE").is_some() {
        eprintln!("(test) presence check skipped: {reason}");
        return Ok(());
    }
    os::verify_presence(reason)
}

pub fn fingerprint(der: &[u8]) -> String {
    use sha1::Digest as _;
    sha1::Sha1::digest(der).iter().map(|b| format!("{b:02X}")).collect()
}

fn hex_decode(s: &str) -> Option<[u8; 20]> {
    if s.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// ECDSA signatures as raw r‖s (what Windows returns) to the DER form CMS uses.
#[cfg_attr(not(windows), allow(dead_code))]
fn ecdsa_raw_to_der(alg: KeyAlg, raw: &[u8]) -> Result<Vec<u8>> {
    Ok(match alg {
        KeyAlg::P256 => p256::ecdsa::Signature::from_slice(raw)?.to_der().as_bytes().to_vec(),
        KeyAlg::P384 => p384::ecdsa::Signature::from_slice(raw)?.to_der().as_bytes().to_vec(),
        KeyAlg::Rsa => raw.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(sha1: &str, holder: &str, id: &str, expires: i64) -> Identity {
        let t = |s| chrono::DateTime::from_timestamp(s, 0).unwrap();
        Identity {
            sha1: sha1.into(),
            info: CertInfo {
                holder: holder.into(),
                issuer: "AC FNMT Usuarios".into(),
                id: Some(id.into()),
                not_before: t(0),
                not_after: t(expires),
            },
        }
    }

    fn sample() -> Vec<Identity> {
        vec![
            ident("E0E9EB8BBF63FFC9419E65AA862303A89BFD68AC", "CUENCA ABELA JOAQUIN - 45564809S", "45564809S", 2000),
            ident("C0D23E57DDE95C9C16137B3DA8C718F6679924BC", "CUENCA ABELA JOAQUIN - 45564809S", "45564809S", 500),
            ident("8B59669FBFF8F639B8B461354729EEC509B58C17", "SANCHEZ RUIZ ROCIO - 74839369Z", "74839369Z", 2000),
        ]
    }

    fn sha1s(v: Vec<Identity>) -> Vec<String> {
        v.into_iter().map(|i| i.sha1[..4].to_string()).collect()
    }

    #[test]
    fn selects_by_fingerprint_name_or_id() {
        let now = chrono::DateTime::from_timestamp(1000, 0).unwrap();
        assert_eq!(sha1s(select(sample(), "e0e9eb8b", now)), ["E0E9"]);
        assert_eq!(sha1s(select(sample(), "C0:D2:3E:57", now)), ["C0D2"], "expired, but asked by fingerprint");
        assert_eq!(sha1s(select(sample(), "cuenca", now)), ["E0E9"], "the expired one is skipped");
        assert_eq!(sha1s(select(sample(), "74839369z", now)), ["8B59"]);
        let early = chrono::DateTime::from_timestamp(100, 0).unwrap();
        assert_eq!(sha1s(select(sample(), "cuenca", early)), ["E0E9", "C0D2"]);
        assert!(select(sample(), "nobody", now).is_empty());
        assert_eq!(sha1s(select(sample(), "sánchez", now)), ["8B59"]);
        assert_eq!(fold("PE\u{301}REZ"), "perez");
    }

    #[test]
    fn hex_round_trip() {
        let f = fingerprint(b"x");
        assert_eq!(hex_decode(&f).map(|b| b.iter().map(|b| format!("{b:02X}")).collect::<String>()), Some(f));
        assert!(hex_decode("zz").is_none());
    }

    /// Signs through the system store with the certificate matching $FIRMA_TEST_SYSTEM_CERT
    /// (scripts/system-cert-test.sh imports one): `cargo test -- --ignored system`
    #[test]
    #[ignore]
    fn signs_with_system_certificate() {
        let query = std::env::var("FIRMA_TEST_SYSTEM_CERT").expect("set FIRMA_TEST_SYSTEM_CERT");
        let id = find(&query).unwrap();
        let cred = crate::cert::Credential::system(&id.sha1).unwrap();
        // `sign` checks the signature against the certificate's public key.
        assert!(!cred.sign(b"firma").unwrap().is_empty());
    }

    #[test]
    fn raw_ecdsa_becomes_der() {
        let raw = [[0u8; 31].as_slice(), &[1], &[0u8; 31], &[2]].concat();
        let der = ecdsa_raw_to_der(KeyAlg::P256, &raw).unwrap();
        assert_eq!(der, [0x30, 6, 2, 1, 1, 2, 1, 2]);
    }
}
