//! Certificate loading (PKCS#12) and low-level signing.

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
        let archive = Pkcs12Archive::from_pkcs12(p12, password).map_err(|e| {
            anyhow!("could not open the PKCS#12 (wrong password or unsupported format?): {e}")
        })?;
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

    pub fn info(&self) -> CertInfo {
        let tbs = &self.cert.tbs_certificate;
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

    pub fn digest(&self) -> Digest {
        match self.key {
            Key::P384(_) => Digest::Sha384,
            _ => Digest::Sha256,
        }
    }

    /// Signature algorithm identifier (OID, whether it takes a NULL parameter).
    pub fn signature_algorithm(&self) -> (ObjectIdentifier, bool) {
        match self.key {
            Key::Rsa(_) => (ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"), true),
            Key::P256(_) => (ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"), false),
            Key::P384(_) => (ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3"), false),
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
        })
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

