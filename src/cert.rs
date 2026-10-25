//! Certificate loading (PKCS#12 or the system store) and low-level signing.

use anyhow::{anyhow, bail, Context, Result};
use der::asn1::ObjectIdentifier;
use der::{Decode, Tagged};
use p12_keystore::Pkcs12Archive;
use signature::Signer as _;
use x509_cert::name::Name;
use x509_cert::Certificate;

const OID_CN: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const OID_SERIAL_NUMBER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.5");
const OID_ORG: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");

pub enum Key {
    Rsa(Box<rsa::RsaPrivateKey>),
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    /// Held by the operating system (macOS Keychain, Windows certificate store): it never
    /// leaves it, the system signs for us.
    System(crate::keystore::SystemKey),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlg {
    Rsa,
    P256,
    P384,
}

const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_EC: &str = "1.2.840.10045.2.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_P384: &str = "1.3.132.0.34";

impl KeyAlg {
    /// The key type of a certificate's public key.
    pub fn of(cert: &Certificate) -> Result<Self> {
        let alg = &cert.tbs_certificate.subject_public_key_info.algorithm;
        match alg.oid.to_string().as_str() {
            OID_RSA => Ok(KeyAlg::Rsa),
            OID_EC => {
                let curve = alg.parameters.as_ref().and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
                match curve.map(|c| c.to_string()).as_deref() {
                    Some(OID_P256) => Ok(KeyAlg::P256),
                    Some(OID_P384) => Ok(KeyAlg::P384),
                    _ => bail!("unsupported EC curve (P-256 and P-384 are supported)"),
                }
            }
            other => bail!("unsupported key type {other} (RSA, EC P-256 and EC P-384 are supported)"),
        }
    }

    pub fn digest(self) -> Digest {
        match self {
            KeyAlg::P384 => Digest::Sha384,
            _ => Digest::Sha256,
        }
    }
}

#[derive(Clone, Copy)]
pub enum Digest {
    Sha256,
    Sha384,
}

impl Digest {
    pub fn oid(self) -> ObjectIdentifier {
        match self {
            Digest::Sha256 => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"),
            Digest::Sha384 => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2"),
        }
    }

    pub fn hash(self, parts: &[&[u8]]) -> Vec<u8> {
        use sha2::Digest as _;
        match self {
            Digest::Sha256 => {
                let mut h = sha2::Sha256::new();
                parts.iter().for_each(|p| h.update(p));
                h.finalize().to_vec()
            }
            Digest::Sha384 => {
                let mut h = sha2::Sha384::new();
                parts.iter().for_each(|p| h.update(p));
                h.finalize().to_vec()
            }
        }
    }
}

pub struct Credential {
    pub key: Key,
    pub cert: Certificate,
    pub cert_der: Vec<u8>,
    /// Other certificates in the PKCS#12 (trust chain).
    pub chain_der: Vec<Vec<u8>>,
}

#[derive(Clone)]
pub struct CertInfo {
    pub holder: String,
    pub issuer: String,
    /// Subject serialNumber (in Spanish certificates usually the national ID, NIF).
    pub id: Option<String>,
    pub not_before: chrono::DateTime<chrono::Utc>,
    pub not_after: chrono::DateTime<chrono::Utc>,
}

impl Credential {
    pub fn load(p12: &[u8], password: &str) -> Result<Self> {
        let archive = match Pkcs12Archive::from_pkcs12(p12, password) {
            Ok(a) => a,
            // BER-encoded files (Java/BouncyCastle exports) are rebuilt as DER first.
            Err(_) if crate::ber::is_ber(p12) => {
                let der = crate::ber::pkcs12_to_der(p12, password).context("could not open the PKCS#12")?;
                Pkcs12Archive::from_pkcs12(&der, password)
                    .map_err(|e| anyhow!("could not open the PKCS#12 (BER-encoded): {e}"))?
            }
            Err(e) => bail!("could not open the PKCS#12 (wrong password or unsupported format?): {e}"),
        };
        let mut keys = Vec::new();
        for bag in &archive.keys {
            keys.push(parse_key(bag.key.as_der())?);
        }
        if keys.is_empty() {
            bail!("the PKCS#12 contains no private key");
        }
        let certs: Vec<(Vec<u8>, Certificate)> = archive
            .certs
            .iter()
            .map(|b| {
                let der = b.cert.as_der().to_vec();
                Certificate::from_der(&der).map(|c| (der, c)).map_err(|e| anyhow!("unreadable certificate: {e}"))
            })
            .collect::<Result<_>>()?;

        // Match key and certificate by comparing the public key.
        for key in keys {
            let pk = public_key_bits(&key)?;
            if let Some(pos) = certs.iter().position(|(_, c)| {
                c.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes() == pk.as_slice()
            }) {
                let (cert_der, cert) = certs[pos].clone();
                let chain_der = certs
                    .iter()
                    .enumerate()
                    .filter(|(i, (d, _))| *i != pos && *d != cert_der)
                    .map(|(_, (d, _))| d.clone())
                    .collect();
                return Ok(Self { key, cert, cert_der, chain_der });
            }
        }
        bail!("no certificate in the PKCS#12 matches its private key")
    }

    /// A certificate whose private key is in the system store (`sha1` is its fingerprint).
    pub fn system(sha1: &str) -> Result<Self> {
        let (key, cert_der, chain_der) = crate::keystore::load(sha1)?;
        let cert = Certificate::from_der(&cert_der).map_err(|e| anyhow!("unreadable certificate: {e}"))?;
        Ok(Self { key: Key::System(key), cert, cert_der, chain_der })
    }

    pub fn info(&self) -> CertInfo {
        cert_info(&self.cert)
    }

    fn alg(&self) -> KeyAlg {
        match &self.key {
            Key::Rsa(_) => KeyAlg::Rsa,
            Key::P256(_) => KeyAlg::P256,
            Key::P384(_) => KeyAlg::P384,
            Key::System(k) => k.alg,
        }
    }

    pub fn digest(&self) -> Digest {
        self.alg().digest()
    }

    /// Signature algorithm identifier (OID, whether it takes a NULL parameter).
    pub fn signature_algorithm(&self) -> (ObjectIdentifier, bool) {
        match self.alg() {
            KeyAlg::Rsa => (ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"), true),
            KeyAlg::P256 => (ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"), false),
            KeyAlg::P384 => (ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3"), false),
        }
    }

    /// Signs `data` (hashed internally with the `digest()` algorithm).
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(match &self.key {
            Key::Rsa(k) => {
                let sk = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new((**k).clone());
                let sig: rsa::pkcs1v15::Signature = sk.try_sign(data)?;
                signature::SignatureEncoding::to_vec(&sig)
            }
            Key::P256(k) => {
                let sk = p256::ecdsa::SigningKey::from(k);
                let sig: p256::ecdsa::Signature = sk.try_sign(data)?;
                sig.to_der().as_bytes().to_vec()
            }
            Key::P384(k) => {
                let sk = p384::ecdsa::SigningKey::from(k);
                let sig: p384::ecdsa::Signature = sk.try_sign(data)?;
                sig.to_der().as_bytes().to_vec()
            }
            Key::System(k) => {
                let sig = k.sign(&self.digest().hash(&[data]))?;
                // The key is out of our sight: check it really belongs to the certificate.
                let (oid, null) = self.signature_algorithm();
                let alg = spki::AlgorithmIdentifierOwned { oid, parameters: null.then(der::Any::null) };
                crate::verify::signature(&self.cert.tbs_certificate.subject_public_key_info, &alg, None, data, &sig)
                    .context("the system's private key does not match the certificate")?;
                sig
            }
        })
    }
}

pub fn cert_info(cert: &Certificate) -> CertInfo {
    let tbs = &cert.tbs_certificate;
    let subject_cn = name_attr(&tbs.subject, OID_CN);
    let org = name_attr(&tbs.subject, OID_ORG);
    CertInfo {
        holder: subject_cn.or_else(|| org.clone()).unwrap_or_else(|| tbs.subject.to_string()),
        issuer: name_attr(&tbs.issuer, OID_CN)
            .or_else(|| name_attr(&tbs.issuer, OID_ORG))
            .unwrap_or_else(|| tbs.issuer.to_string()),
        id: name_attr(&tbs.subject, OID_SERIAL_NUMBER).map(|s| strip_id_prefix(&s)),
        not_before: to_chrono(tbs.validity.not_before.to_unix_duration()),
        not_after: to_chrono(tbs.validity.not_after.to_unix_duration()),
    }
}

fn parse_key(pkcs8: &[u8]) -> Result<Key> {
    use rsa::pkcs8::DecodePrivateKey;
    if let Ok(k) = rsa::RsaPrivateKey::from_pkcs8_der(pkcs8) {
        return Ok(Key::Rsa(Box::new(k)));
    }
    if let Ok(k) = p256::SecretKey::from_pkcs8_der(pkcs8) {
        return Ok(Key::P256(k));
    }
    if let Ok(k) = p384::SecretKey::from_pkcs8_der(pkcs8) {
        return Ok(Key::P384(k));
    }
    bail!("unsupported private key type (RSA, EC P-256 and EC P-384 are supported)")
}

fn public_key_bits(key: &Key) -> Result<Vec<u8>> {
    use rsa::pkcs8::EncodePublicKey;
    let spki_der = match key {
        Key::Rsa(k) => k.to_public_key().to_public_key_der()?.into_vec(),
        Key::P256(k) => k.public_key().to_public_key_der()?.into_vec(),
        Key::P384(k) => k.public_key().to_public_key_der()?.into_vec(),
        Key::System(_) => bail!("system keys are matched by the system"),
    };
    let spki = spki::SubjectPublicKeyInfoRef::from_der(&spki_der).context("SPKI")?;
    Ok(spki.subject_public_key.raw_bytes().to_vec())
}

fn name_attr(name: &Name, oid: ObjectIdentifier) -> Option<String> {
    for rdn in name.0.iter() {
        for atv in rdn.0.iter() {
            if atv.oid == oid {
                return Some(decode_dir_string(&atv.value));
            }
        }
    }
    None
}

fn decode_dir_string(value: &der::Any) -> String {
    let bytes = value.value();
    if value.tag() == der::Tag::BmpString {
        let units: Vec<u16> = bytes.chunks(2).map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])).collect();
        return String::from_utf16_lossy(&units);
    }
    String::from_utf8_lossy(bytes).into_owned()
}

/// "IDCES-12345678Z" → "12345678Z"
fn strip_id_prefix(s: &str) -> String {
    for p in ["IDCES-", "PASES-", "VATES-"] {
        if let Some(rest) = s.strip_prefix(p) {
            return rest.to_string();
        }
    }
    s.to_string()
}

fn to_chrono(d: std::time::Duration) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(d.as_secs() as i64, 0).unwrap_or_default()
}

