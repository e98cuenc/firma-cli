//! Enveloped XAdES signatures of XML documents (XAdES B-B and B-T), and FacturaE invoices
//! (XAdES-EPES with the FacturaE signature policy v3.1).
//!
//! The ds:Signature goes at the end of the root element. The document reference uses the
//! enveloped-signature transform and inclusive C14N, so it digests the document exactly as it
//! was; SignedInfo, SignedProperties and the time-stamped SignatureValue use exclusive C14N.

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use der::Encode;

use crate::cert::{Credential, Digest, KeyAlg};
use crate::cms::Timestamper;
use crate::xml::{self, Mode};

const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";
const C14N: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const SIGNED_PROPERTIES: &str = "http://uri.etsi.org/01903#SignedProperties";

const FACTURAE_POLICY: &str =
    "http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf";
const FACTURAE_POLICY_NAME: &str = "Política de Firma FacturaE v3.1";
/// SHA-1 of the policy document, as published with it.
const FACTURAE_POLICY_SHA1: &str = "Ohixl6upD6av8N7pEvDABhEL6hM=";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Xades,
    Facturae,
}

/// Root element of an XML document (local name, namespace), or an error if it is not XML that
/// firma can sign.
pub fn root(input: &[u8]) -> Result<(String, String)> {
    Ok(xml::canonicalize(text(input)?, Mode::Inclusive)?.root)
}

/// Whether a root element is a FacturaE invoice.
pub fn is_facturae((local, ns): &(String, String)) -> bool {
    local == "Facturae" && ns.to_ascii_lowercase().contains("facturae")
}

fn text(input: &[u8]) -> Result<&str> {
    let input = input.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(input);
    if input.starts_with(b"\xFF\xFE") || input.starts_with(b"\xFE\xFF") {
        bail!("UTF-16 XML documents are not supported (convert it to UTF-8)");
    }
    let s = std::str::from_utf8(input).context("the XML document is not UTF-8")?;
    // A document declared in another encoding is only read as UTF-8 when it is plain ASCII.
    if !s.is_ascii() {
        if let Some(enc) = declared_encoding(s) {
            if !enc.eq_ignore_ascii_case("utf-8") && !enc.eq_ignore_ascii_case("utf8") {
                bail!("XML documents in {enc} are not supported (convert it to UTF-8)");
            }
        }
    }
    Ok(s)
}

fn declared_encoding(s: &str) -> Option<&str> {
    let decl = &s[..s.find("?>")?];
    if !decl.trim_start().starts_with("<?xml") {
        return None;
    }
    let rest = decl[decl.find("encoding")? + 8..].trim_start().strip_prefix('=')?.trim_start();
    let quote = rest.chars().next()?;
    rest[1..].split(quote).next()
}

/// Signs `input` and returns the document with the signature inside its root element.
pub fn sign(
    cred: &Credential,
    input: &[u8],
    profile: Profile,
    date: chrono::DateTime<chrono::Local>,
    timestamp: Option<Timestamper>,
) -> Result<Vec<u8>> {
    let doc = text(input)?;
    let canonical = xml::canonicalize(doc, Mode::Inclusive)?;
    if profile == Profile::Facturae && !is_facturae(&canonical.root) {
        bail!("not a FacturaE invoice (its root element is {}, not Facturae)", canonical.root.0);
    }
    let root_end = canonical.root_end.context("the root element is empty (<root/>); nothing to sign into")?;
    let offset = input.len() - doc.len(); // byte order mark

    let digest = cred.digest();
    let (digest_uri, sig_uri) = algorithms(cred)?;
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let id = format!("Signature-{}", unique_id());

    // Signed properties.
    let cert_digest = b64(&digest.hash(&[&cred.cert_der]));
    let tbs = &cred.cert.tbs_certificate;
    let signing_cert = match profile {
        // The FacturaE policy predates SigningCertificateV2.
        Profile::Facturae => format!(
            "<xades:SigningCertificate><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm=\"{digest_uri}\"></ds:DigestMethod>\
             <ds:DigestValue>{cert_digest}</ds:DigestValue></xades:CertDigest><xades:IssuerSerial>\
             <ds:X509IssuerName>{}</ds:X509IssuerName><ds:X509SerialNumber>{}</ds:X509SerialNumber>\
             </xades:IssuerSerial></xades:Cert></xades:SigningCertificate>",
            xml::escape(&tbs.issuer.to_string()),
            rsa::BigUint::from_bytes_be(tbs.serial_number.as_bytes()),
        ),
        Profile::Xades => format!(
            "<xades:SigningCertificateV2><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm=\"{digest_uri}\"></ds:DigestMethod>\
             <ds:DigestValue>{cert_digest}</ds:DigestValue></xades:CertDigest>\
             <xades:IssuerSerialV2>{}</xades:IssuerSerialV2></xades:Cert></xades:SigningCertificateV2>",
            b64(&issuer_serial(&cred.cert)?),
        ),
    };
    let (policy, role, description) = match profile {
        Profile::Facturae => (
            format!(
                "<xades:SignaturePolicyIdentifier><xades:SignaturePolicyId><xades:SigPolicyId>\
                 <xades:Identifier>{FACTURAE_POLICY}</xades:Identifier><xades:Description>{FACTURAE_POLICY_NAME}</xades:Description>\
                 </xades:SigPolicyId><xades:SigPolicyHash><ds:DigestMethod Algorithm=\"{DS}sha1\"></ds:DigestMethod>\
                 <ds:DigestValue>{FACTURAE_POLICY_SHA1}</ds:DigestValue></xades:SigPolicyHash></xades:SignaturePolicyId>\
                 </xades:SignaturePolicyIdentifier>"
            ),
            "<xades:SignerRole><xades:ClaimedRoles><xades:ClaimedRole>emisor</xades:ClaimedRole></xades:ClaimedRoles></xades:SignerRole>",
            "<xades:Description>Factura electrónica</xades:Description>",
        ),
        Profile::Xades => (String::new(), "", ""),
    };
    let signed_props = xml::canonicalize(
        &format!(
            "<xades:SignedProperties xmlns:ds=\"{DS}\" xmlns:xades=\"{XADES}\" Id=\"{id}-SignedProperties\">\
             <xades:SignedSignatureProperties><xades:SigningTime>{}</xades:SigningTime>{signing_cert}{policy}{role}\
             </xades:SignedSignatureProperties><xades:SignedDataObjectProperties>\
             <xades:DataObjectFormat ObjectReference=\"#{id}-Reference\">{description}<xades:MimeType>text/xml</xades:MimeType>\
             </xades:DataObjectFormat></xades:SignedDataObjectProperties></xades:SignedProperties>",
            date.format("%Y-%m-%dT%H:%M:%S%:z"),
        ),
        Mode::Exclusive,
    )?
    .text;

    // SignedInfo: the document and the signed properties.
    let signed_info = xml::canonicalize(
        &format!(
            "<ds:SignedInfo xmlns:ds=\"{DS}\"><ds:CanonicalizationMethod Algorithm=\"{EXC_C14N}\"></ds:CanonicalizationMethod>\
             <ds:SignatureMethod Algorithm=\"{sig_uri}\"></ds:SignatureMethod>\
             <ds:Reference Id=\"{id}-Reference\" URI=\"\"><ds:Transforms><ds:Transform Algorithm=\"{ENVELOPED}\"></ds:Transform>\
             <ds:Transform Algorithm=\"{C14N}\"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm=\"{digest_uri}\"></ds:DigestMethod>\
             <ds:DigestValue>{}</ds:DigestValue></ds:Reference>\
             <ds:Reference Type=\"{SIGNED_PROPERTIES}\" URI=\"#{id}-SignedProperties\"><ds:Transforms>\
             <ds:Transform Algorithm=\"{EXC_C14N}\"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm=\"{digest_uri}\"></ds:DigestMethod>\
             <ds:DigestValue>{}</ds:DigestValue></ds:Reference></ds:SignedInfo>",
            b64(&digest.hash(&[canonical.text.as_bytes()])),
            b64(&digest.hash(&[signed_props.as_bytes()])),
        ),
        Mode::Exclusive,
    )?
    .text;

    let value = xml_signature_value(cred, &cred.sign(signed_info.as_bytes())?)?;
    let signature_value = xml::canonicalize(
        &format!("<ds:SignatureValue xmlns:ds=\"{DS}\" Id=\"{id}-SignatureValue\">{}</ds:SignatureValue>", b64(&value)),
        Mode::Exclusive,
    )?
    .text;

    // B-T: time-stamp over the canonicalized SignatureValue element.
    let unsigned = match timestamp {
        Some(ts) => format!(
            "<xades:UnsignedProperties><xades:UnsignedSignatureProperties><xades:SignatureTimeStamp Id=\"{id}-SignatureTimeStamp\">\
             <ds:CanonicalizationMethod Algorithm=\"{EXC_C14N}\"></ds:CanonicalizationMethod>\
             <xades:EncapsulatedTimeStamp>{}</xades:EncapsulatedTimeStamp></xades:SignatureTimeStamp>\
             </xades:UnsignedSignatureProperties></xades:UnsignedProperties>",
            b64(&ts(signature_value.as_bytes())?),
        ),
        None => String::new(),
    };

    let certs: String = std::iter::once(&cred.cert_der)
        .chain(&cred.chain_der)
        .map(|der| format!("<ds:X509Certificate>{}</ds:X509Certificate>", b64(der)))
        .collect();
    let signature = format!(
        "<ds:Signature xmlns:ds=\"{DS}\" Id=\"{id}\">{signed_info}{signature_value}\
         <ds:KeyInfo><ds:X509Data>{certs}</ds:X509Data></ds:KeyInfo>\
         <ds:Object><xades:QualifyingProperties xmlns:xades=\"{XADES}\" Target=\"#{id}\">{signed_props}{unsigned}\
         </xades:QualifyingProperties></ds:Object></ds:Signature>"
    );

    let at = offset + root_end;
    let mut out = Vec::with_capacity(input.len() + signature.len() + 64);
    out.extend_from_slice(&input[..at]);
    out.extend_from_slice(xml::ascii(&signature).as_bytes());
    out.extend_from_slice(&input[at..]);
    Ok(out)
}

fn algorithms(cred: &Credential) -> Result<(&'static str, &'static str)> {
    let alg = KeyAlg::of(&cred.cert)?;
    let digest = match cred.digest() {
        Digest::Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
        Digest::Sha384 => "http://www.w3.org/2001/04/xmldsig-more#sha384",
    };
    let signature = match alg {
        KeyAlg::Rsa => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        KeyAlg::P256 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
        KeyAlg::P384 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
    };
    Ok((digest, signature))
}

/// XML-DSig wants ECDSA signatures as r‖s, not DER.
fn xml_signature_value(cred: &Credential, sig: &[u8]) -> Result<Vec<u8>> {
    Ok(match KeyAlg::of(&cred.cert)? {
        KeyAlg::Rsa => sig.to_vec(),
        KeyAlg::P256 => p256::ecdsa::Signature::from_der(sig)?.to_bytes().to_vec(),
        KeyAlg::P384 => p384::ecdsa::Signature::from_der(sig)?.to_bytes().to_vec(),
    })
}

/// IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber } (RFC 5035), for IssuerSerialV2.
fn issuer_serial(cert: &x509_cert::Certificate) -> Result<Vec<u8>> {
    use crate::cms::tlv;
    let issuer = cert.tbs_certificate.issuer.to_der()?;
    let serial = cert.tbs_certificate.serial_number.to_der()?;
    Ok(tlv(0x30, &[tlv(0x30, &tlv(0xA4, &issuer)), serial].concat()))
}

fn unique_id() -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let seed = format!("{}-{}", now.as_nanos(), std::process::id());
    Digest::Sha256.hash(&[seed.as_bytes()])[..8].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_facturae_and_encodings() {
        let f = br#"<?xml version="1.0" encoding="UTF-8"?><fe:Facturae xmlns:fe="http://www.facturae.gob.es/formato/Versiones/Facturaev3_2_2.xml"><x/></fe:Facturae>"#;
        assert!(is_facturae(&root(f).unwrap()));
        assert!(!is_facturae(&root(b"<a/>").unwrap()));
        assert!(root("<?xml version='1.0' encoding='ISO-8859-1'?><a>\u{f1}</a>".as_bytes()).is_err());
        assert!(root(b"<?xml version='1.0' encoding='ISO-8859-1'?><a>n</a>").is_ok());
        assert_eq!(declared_encoding("<?xml version=\"1.0\" encoding = 'utf-8' ?><a/>"), Some("utf-8"));
    }
}
