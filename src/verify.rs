//! Signature verification for certificates, CRLs, OCSP responses and time-stamp tokens.

use anyhow::{anyhow, bail, Context, Result};
use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_cert::Certificate;

const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const P256: &str = "1.2.840.10045.3.1.7";
const P384: &str = "1.3.132.0.34";
const OID_EKU: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    /// Digest algorithm by OID (as found in AlgorithmIdentifier.algorithm).
    pub fn from_oid(oid: &ObjectIdentifier) -> Result<Self> {
        Ok(match oid.to_string().as_str() {
            "1.3.14.3.2.26" => Hash::Sha1,
            "2.16.840.1.101.3.4.2.1" => Hash::Sha256,
            "2.16.840.1.101.3.4.2.2" => Hash::Sha384,
            "2.16.840.1.101.3.4.2.3" => Hash::Sha512,
            other => bail!("unsupported digest algorithm {other}"),
        })
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest as _;
        match self {
            Hash::Sha1 => sha1::Sha1::digest(data).to_vec(),
            Hash::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Hash::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Hash::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }
}

enum Scheme {
    RsaPkcs1,
    Ecdsa,
}

/// Maps a signature AlgorithmIdentifier to (scheme, hash). `rsaEncryption` alone (common in CMS)
/// takes the hash from `digest_hint`.
fn scheme(alg: &AlgorithmIdentifierOwned, digest_hint: Option<Hash>) -> Result<(Scheme, Hash)> {
    let need_hint = || digest_hint.ok_or_else(|| anyhow!("rsaEncryption signature without a digest algorithm"));
    Ok(match alg.oid.to_string().as_str() {
        RSA_ENCRYPTION => (Scheme::RsaPkcs1, need_hint()?),
        "1.2.840.113549.1.1.5" => (Scheme::RsaPkcs1, Hash::Sha1),
        "1.2.840.113549.1.1.11" => (Scheme::RsaPkcs1, Hash::Sha256),
        "1.2.840.113549.1.1.12" => (Scheme::RsaPkcs1, Hash::Sha384),
        "1.2.840.113549.1.1.13" => (Scheme::RsaPkcs1, Hash::Sha512),
        "1.2.840.10045.4.1" => (Scheme::Ecdsa, Hash::Sha1),
        "1.2.840.10045.4.3.2" => (Scheme::Ecdsa, Hash::Sha256),
        "1.2.840.10045.4.3.3" => (Scheme::Ecdsa, Hash::Sha384),
        "1.2.840.10045.4.3.4" => (Scheme::Ecdsa, Hash::Sha512),
        "1.2.840.113549.1.1.10" => bail!("RSASSA-PSS signatures are not supported"),
        other => bail!("unsupported signature algorithm {other}"),
    })
}

/// Verifies `sig` over `msg` with the public key `spki`.
pub fn signature(
    spki: &SubjectPublicKeyInfoOwned,
    alg: &AlgorithmIdentifierOwned,
    digest_hint: Option<Hash>,
    msg: &[u8],
    sig: &[u8],
) -> Result<()> {
    let (scheme, hash) = scheme(alg, digest_hint)?;
    let digest = hash.digest(msg);
    match scheme {
        Scheme::RsaPkcs1 => {
            if spki.algorithm.oid.to_string() != RSA_ENCRYPTION {
                bail!("RSA signature but the key is not RSA");
            }
            use rsa::pkcs8::DecodePublicKey;
            let key = rsa::RsaPublicKey::from_public_key_der(&spki.to_der()?)?;
            let padding = match hash {
                Hash::Sha1 => rsa::Pkcs1v15Sign::new::<sha1::Sha1>(),
                Hash::Sha256 => rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
                Hash::Sha384 => rsa::Pkcs1v15Sign::new::<sha2::Sha384>(),
                Hash::Sha512 => rsa::Pkcs1v15Sign::new::<sha2::Sha512>(),
            };
            key.verify(padding, &digest, sig).map_err(|_| anyhow!("invalid RSA signature"))
        }
        Scheme::Ecdsa => {
            use ecdsa::signature::hazmat::PrehashVerifier;
            if spki.algorithm.oid.to_string() != EC_PUBLIC_KEY {
                bail!("ECDSA signature but the key is not EC");
            }
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
                .map(|o| o.to_string())
                .unwrap_or_default();
            let point = spki.subject_public_key.raw_bytes();
            let ok = match curve.as_str() {
                P256 => p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
                    .and_then(|k| k.verify_prehash(&digest, &p256::ecdsa::Signature::from_der(sig)?))
                    .is_ok(),
                P384 => p384::ecdsa::VerifyingKey::from_sec1_bytes(point)
                    .and_then(|k| k.verify_prehash(&digest, &p384::ecdsa::Signature::from_der(sig)?))
                    .is_ok(),
                other => bail!("unsupported EC curve {other}"),
            };
            if !ok {
                bail!("invalid ECDSA signature");
            }
            Ok(())
        }
    }
}

/// The raw DER bytes of the first element inside the outer SEQUENCE of `der`
/// (the to-be-signed part of a certificate, CRL or BasicOCSPResponse). Using the original
/// bytes avoids depending on a re-encoding being byte-identical.
pub fn first_element(der: &[u8]) -> Result<&[u8]> {
    let (_, outer_len, outer_hdr) = header(der)?;
    let inner = der.get(outer_hdr..outer_hdr + outer_len).context("truncated DER")?;
    let (_, len, hdr) = header(inner)?;
    inner.get(..hdr + len).context("truncated DER")
}

/// (tag, content length, header length)
fn header(der: &[u8]) -> Result<(u8, usize, usize)> {
    let tag = *der.first().context("empty DER")?;
    let first = *der.get(1).context("truncated DER")?;
    if first < 0x80 {
        return Ok((tag, first as usize, 2));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 {
        bail!("unsupported DER length");
    }
    let bytes = der.get(2..2 + n).context("truncated DER")?;
    let len = bytes.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize);
    Ok((tag, len, 2 + n))
}

/// Verifies that `issuer` signed `cert` (`cert_der` must be the DER of `cert`).
pub fn cert_signed_by(cert_der: &[u8], cert: &Certificate, issuer: &Certificate) -> Result<()> {
    if cert.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        bail!("issuer name mismatch");
    }
    signature(
        &issuer.tbs_certificate.subject_public_key_info,
        &cert.signature_algorithm,
        None,
        first_element(cert_der)?,
        cert.signature.raw_bytes(),
    )
}

/// Whether the certificate's extended key usage includes `purpose`.
pub fn has_eku(cert: &Certificate, purpose: &str) -> bool {
    cert.tbs_certificate
        .extensions
        .iter()
        .flatten()
        .filter(|e| e.extn_id == OID_EKU)
        .filter_map(|e| ExtendedKeyUsage::from_der(e.extn_value.as_bytes()).ok())
        .any(|eku| eku.0.iter().any(|o| o.to_string() == purpose))
}

pub const EKU_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
pub const EKU_OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_element_short_and_long_lengths() {
        // SEQUENCE { SEQUENCE { INTEGER 5 }, NULL }
        let der = [0x30, 0x07, 0x30, 0x03, 0x02, 0x01, 0x05, 0x05, 0x00];
        assert_eq!(first_element(&der).unwrap(), &[0x30, 0x03, 0x02, 0x01, 0x05]);
        let mut long = vec![0x30, 0x81, 0x85, 0x04, 0x81, 0x80];
        long.extend([0u8; 0x80]);
        long.extend([0x05, 0x00, 0x05, 0x00]);
        assert_eq!(first_element(&long).unwrap().len(), 0x83);
        assert!(first_element(&[0x30, 0x05, 0x30]).is_err());
    }
}
