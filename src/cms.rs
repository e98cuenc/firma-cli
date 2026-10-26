//! Builds CMS/CAdES signatures: the detached one embedded in a PDF, and CAdES files.
//!
//! Signed attributes (PAdES B-B): content-type, message-digest and
//! signing-certificate-v2. No signing-time: in PAdES the date goes in /M.
//! CAdES B-B adds signing-time.

use anyhow::{anyhow, Result};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignatureValue, SignedAttributes,
    SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use der::asn1::{Any, ObjectIdentifier, OctetString, SetOfVec};
use der::{Decode, Encode};
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::Attribute;
use x509_cert::Certificate;

use crate::cert::{Credential, Digest};

const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const ID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const ID_SIGNING_CERT_V2: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
const ID_SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");

/// Time-stamper: receives the signature value and returns a DER TimeStampToken.
pub type Timestamper<'a> = &'a dyn Fn(&[u8]) -> Result<Vec<u8>>;

const ID_SIGNATURE_TIMESTAMP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");

/// Returns the DER `ContentInfo` ready to go into /Contents.
///
/// If `timestamp` is given, it is called with the signature value and the token it returns
/// (a DER TimeStampToken) is added as an unsigned attribute (PAdES B-T).
pub fn sign_detached(
    cred: &Credential,
    document_digest: &[u8],
    timestamp: Option<Timestamper>,
) -> Result<Vec<u8>> {
    build(cred, document_digest, None, None, timestamp)
}

/// A CAdES signature of `content` (B-B, or B-T with `timestamp`), with the content inside it
/// (`attached`, AutoFirma's default) or detached.
pub fn sign_cades(
    cred: &Credential,
    content: &[u8],
    attached: bool,
    date: std::time::SystemTime,
    timestamp: Option<Timestamper>,
) -> Result<Vec<u8>> {
    let digest = cred.digest().hash(&[content]);
    let time = x509_cert::time::Time::try_from(date).map_err(|e| anyhow!("signing time: {e}"))?;
    build(cred, &digest, Some(time), attached.then_some(content), timestamp)
}

fn build(
    cred: &Credential,
    document_digest: &[u8],
    signing_time: Option<x509_cert::time::Time>,
    content: Option<&[u8]>,
    timestamp: Option<Timestamper>,
) -> Result<Vec<u8>> {
    let digest = cred.digest();
    let digest_alg = AlgorithmIdentifierOwned { oid: digest.oid(), parameters: None };

    let mut attrs = vec![
        attribute(ID_CONTENT_TYPE, Any::encode_from(&ID_DATA)?)?,
        attribute(ID_MESSAGE_DIGEST, Any::encode_from(&OctetString::new(document_digest)?)?)?,
        attribute(ID_SIGNING_CERT_V2, Any::from_der(&signing_certificate_v2(&cred.cert_der, &cred.cert)?)?)?,
    ];
    if let Some(t) = signing_time {
        attrs.push(attribute(ID_SIGNING_TIME, Any::encode_from(&t)?)?);
    }
    let signed_attrs: SignedAttributes = SetOfVec::try_from(attrs)?;
    let signature = cred.sign(&signed_attrs.to_der()?)?;

    let unsigned_attrs = match timestamp {
        Some(ts) => {
            let token = ts(&signature)?;
            Some(SetOfVec::try_from(vec![attribute(ID_SIGNATURE_TIMESTAMP, Any::from_der(&token)?)?])?)
        }
        None => None,
    };

    let (sig_oid, null_params) = cred.signature_algorithm();
    let signer_info = SignerInfo {
        version: CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: cred.cert.tbs_certificate.issuer.clone(),
            serial_number: cred.cert.tbs_certificate.serial_number.clone(),
        }),
        digest_alg: digest_alg.clone(),
        signed_attrs: Some(signed_attrs),
        signature_algorithm: AlgorithmIdentifierOwned {
            oid: sig_oid,
            parameters: null_params.then(Any::null),
        },
        signature: SignatureValue::new(signature)?,
        unsigned_attrs,
    };

    let mut certs = vec![CertificateChoices::Certificate(cred.cert.clone())];
    for der in &cred.chain_der {
        certs.push(CertificateChoices::Certificate(Certificate::from_der(der)?));
    }

    let signed_data = SignedData {
        version: CmsVersion::V1,
        digest_algorithms: DigestAlgorithmIdentifiers::try_from(vec![digest_alg])?,
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: ID_DATA,
            econtent: content.map(|c| Any::encode_from(&OctetString::new(c)?)).transpose()?,
        },
        certificates: Some(CertificateSet::try_from(certs).map_err(|e| anyhow!("{e}"))?),
        crls: None,
        signer_infos: SignerInfos::try_from(vec![signer_info])?,
    };
    let ci = ContentInfo { content_type: ID_SIGNED_DATA, content: Any::encode_from(&signed_data)? };
    Ok(ci.to_der()?)
}

fn attribute(oid: ObjectIdentifier, value: Any) -> Result<Attribute> {
    Ok(Attribute { oid, values: SetOfVec::try_from(vec![value])? })
}

/// SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 }
/// ESSCertIDv2 ::= SEQUENCE { hashAlgorithm DEFAULT sha256, certHash OCTET STRING, issuerSerial }
fn signing_certificate_v2(cert_der: &[u8], cert: &Certificate) -> Result<Vec<u8>> {
    let hash = Digest::Sha256.hash(&[cert_der]);
    // IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber }
    // GeneralNames ::= SEQUENCE OF GeneralName; directoryName is [4] EXPLICIT Name
    let issuer = cert.tbs_certificate.issuer.to_der()?;
    let serial = cert.tbs_certificate.serial_number.to_der()?;
    let general_names = tlv(0x30, &tlv(0xA4, &issuer));
    let issuer_serial = tlv(0x30, &[general_names, serial].concat());
    let ess_cert_id = tlv(0x30, &[tlv(0x04, &hash), issuer_serial].concat());
    Ok(tlv(0x30, &tlv(0x30, &ess_cert_id)))
}

pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}
