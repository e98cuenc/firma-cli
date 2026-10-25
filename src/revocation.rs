//! Long-term validation data (PAdES B-LT): full chain, OCSP responses and CRLs.

use anyhow::{anyhow, bail, Context, Result};
use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::asn1::{ObjectIdentifier, OctetString};
use der::{Decode, Encode};
use spki::AlgorithmIdentifierOwned;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::{AuthorityInfoAccessSyntax, AuthorityKeyIdentifier, CrlDistributionPoints, SubjectKeyIdentifier};
use x509_cert::Certificate;
use x509_ocsp::{BasicOcspResponse, CertId, CertStatus, OcspRequest, OcspResponse, OcspResponseStatus, Request, TbsRequest};

const OID_AIA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");
const OID_OCSP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1");
const OID_CA_ISSUERS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.2");
const OID_OCSP_BASIC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");
const OID_CRL_DP: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.31");
const OID_AKI: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");
const OID_SKI: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");

#[derive(Default)]
pub struct Validation {
    pub certs: Vec<Vec<u8>>,
    pub ocsps: Vec<Vec<u8>>,
    pub crls: Vec<Vec<u8>>,
}

impl Validation {
    fn add(list: &mut Vec<Vec<u8>>, item: Vec<u8>) {
        if !list.contains(&item) {
            list.push(item);
        }
    }
}

enum Status {
    Good,
    Revoked(String),
}

/// Collects revocation information for the chain of `leaf`.
///
/// With `strict`, a revoked certificate or one without revocation information is an error;
/// without it (e.g. for the TSA) only a warning is printed.
pub fn collect(out: &mut Validation, leaf: &[u8], pool: &[Vec<u8>], strict: bool) -> Result<()> {
    let chain = build_chain(leaf, pool)?;
    for der in &chain {
        Validation::add(&mut out.certs, der.clone());
    }
    for pair in chain.windows(2) {
        let (cert, issuer) = (Certificate::from_der(&pair[0])?, Certificate::from_der(&pair[1])?);
        let name = subject_cn(&cert);
        match check(out, &cert, &issuer) {
            Ok(Status::Good) => {}
            Ok(Status::Revoked(when)) => bail!("certificate \"{name}\" is REVOKED ({when})"),
            Err(e) if strict => {
                return Err(e.context(format!("could not get revocation status for \"{name}\"")));
            }
            Err(e) => eprintln!("warning: no revocation data for \"{name}\": {e:#}"),
        }
    }
    Ok(())
}

/// Chain from `leaf` up to the (self-signed) root, downloading missing intermediates via AIA.
pub fn build_chain(leaf: &[u8], pool: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    let mut pool: Vec<Vec<u8>> = pool.to_vec();
    let mut chain = vec![leaf.to_vec()];
    for _ in 0..10 {
        let cur = Certificate::from_der(chain.last().unwrap())?;
        if is_self_signed(&cur) {
            return Ok(chain);
        }
        let issuer = match find_issuer(&cur, &pool) {
            Some(i) => i,
            None => {
                let mut fetched = Vec::new();
                for url in aia_urls(&cur, OID_CA_ISSUERS) {
                    match crate::net::get(&url).and_then(|d| parse_certs(&d)) {
                        Ok(certs) => fetched.extend(certs),
                        Err(e) => eprintln!("warning: {e:#}"),
                    }
                }
                pool.extend(fetched);
                match find_issuer(&cur, &pool) {
                    Some(i) => i,
                    None => {
                        eprintln!("warning: issuer of \"{}\" not found; incomplete chain", subject_cn(&cur));
                        return Ok(chain);
                    }
                }
            }
        };
        if chain.contains(&issuer) {
            return Ok(chain);
        }
        chain.push(issuer);
    }
    Ok(chain)
}

fn find_issuer(cert: &Certificate, pool: &[Vec<u8>]) -> Option<Vec<u8>> {
    let aki = ext::<AuthorityKeyIdentifier>(cert, OID_AKI).and_then(|a| a.key_identifier).map(|k| k.as_bytes().to_vec());
    let candidates: Vec<(&Vec<u8>, Certificate)> = pool
        .iter()
        .filter_map(|d| Certificate::from_der(d).ok().map(|c| (d, c)))
        .filter(|(_, c)| c.tbs_certificate.subject == cert.tbs_certificate.issuer)
        .collect();
    if let Some(aki) = &aki {
        if let Some((d, _)) = candidates.iter().find(|(_, c)| {
            ext::<SubjectKeyIdentifier>(c, OID_SKI).is_some_and(|s| s.0.as_bytes() == aki.as_slice())
        }) {
            return Some((*d).clone());
        }
    }
    candidates.first().map(|(d, _)| (*d).clone())
}

fn is_self_signed(c: &Certificate) -> bool {
    c.tbs_certificate.subject == c.tbs_certificate.issuer
}

fn check(out: &mut Validation, cert: &Certificate, issuer: &Certificate) -> Result<Status> {
    let mut errors = Vec::new();
    for url in aia_urls(cert, OID_OCSP) {
        match ocsp(out, cert, issuer, &url) {
            Ok(s) => return Ok(s),
            Err(e) => errors.push(format!("OCSP {url}: {e:#}")),
        }
    }
    for url in crl_urls(cert) {
        match crl(out, cert, &url) {
            Ok(s) => return Ok(s),
            Err(e) => errors.push(format!("CRL {url}: {e:#}")),
        }
    }
    if errors.is_empty() {
        bail!("the certificate lists neither an OCSP responder nor a CRL");
    }
    Err(anyhow!(errors.join("; ")))
}

fn ocsp(out: &mut Validation, cert: &Certificate, issuer: &Certificate, url: &str) -> Result<Status> {
    use sha1::Digest as _;
    let cert_id = CertId {
        hash_algorithm: AlgorithmIdentifierOwned { oid: OID_SHA1, parameters: Some(der::Any::null()) },
        issuer_name_hash: OctetString::new(sha1::Sha1::digest(cert.tbs_certificate.issuer.to_der()?).to_vec())?,
        issuer_key_hash: OctetString::new(
            sha1::Sha1::digest(issuer.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes()).to_vec(),
        )?,
        serial_number: cert.tbs_certificate.serial_number.clone(),
    };
    let req = OcspRequest {
        tbs_request: TbsRequest {
            version: Default::default(),
            requestor_name: None,
            request_list: vec![Request { req_cert: cert_id, single_request_extensions: None }],
            request_extensions: None,
        },
        optional_signature: None,
    };
    let resp_der = crate::net::post(url, "application/ocsp-request", &req.to_der()?)?;
    let resp = OcspResponse::from_der(&resp_der).context("malformed OCSP response")?;
    if resp.response_status != OcspResponseStatus::Successful {
        bail!("the responder answered {:?}", resp.response_status);
    }
    let bytes = resp.response_bytes.context("empty OCSP response")?;
    if bytes.response_type != OID_OCSP_BASIC {
        bail!("unsupported OCSP response type");
    }
    let basic = BasicOcspResponse::from_der(bytes.response.as_bytes())?;
    let single = basic
        .tbs_response_data
        .responses
        .iter()
        .find(|r| r.cert_id.serial_number == cert.tbs_certificate.serial_number)
        .context("the OCSP response does not cover this certificate")?;
    let status = match &single.cert_status {
        CertStatus::Good(_) => Status::Good,
        CertStatus::Revoked(info) => Status::Revoked(format!("since {}", fmt_time(info.revocation_time.0.to_unix_duration()))),
        CertStatus::Unknown(_) => bail!("the OCSP responder does not know the certificate"),
    };
    Validation::add(&mut out.ocsps, resp_der);
    for c in basic.certs.iter().flatten() {
        Validation::add(&mut out.certs, c.to_der()?);
    }
    Ok(status)
}

fn crl(out: &mut Validation, cert: &Certificate, url: &str) -> Result<Status> {
    let der = crate::net::get(url)?;
    let list = CertificateList::from_der(&der).context("malformed CRL (DER expected)")?;
    if list.tbs_cert_list.issuer != cert.tbs_certificate.issuer {
        bail!("the CRL belongs to a different issuer");
    }
    let revoked = list
        .tbs_cert_list
        .revoked_certificates
        .iter()
        .flatten()
        .find(|r| r.serial_number == cert.tbs_certificate.serial_number)
        .map(|r| format!("since {}", fmt_time(r.revocation_date.to_unix_duration())));
    Validation::add(&mut out.crls, der);
    Ok(match revoked {
        Some(when) => Status::Revoked(when),
        None => Status::Good,
    })
}

fn ext<'a, T: Decode<'a>>(cert: &'a Certificate, oid: ObjectIdentifier) -> Option<T> {
    cert.tbs_certificate
        .extensions
        .as_ref()?
        .iter()
        .find(|e| e.extn_id == oid)
        .and_then(|e| T::from_der(e.extn_value.as_bytes()).ok())
}

fn uri(name: &GeneralName) -> Option<String> {
    match name {
        GeneralName::UniformResourceIdentifier(u) => Some(u.to_string()),
        _ => None,
    }
}

fn aia_urls(cert: &Certificate, method: ObjectIdentifier) -> Vec<String> {
    ext::<AuthorityInfoAccessSyntax>(cert, OID_AIA)
        .map(|aia| aia.0.iter().filter(|a| a.access_method == method).filter_map(|a| uri(&a.access_location)).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .filter(|u: &String| u.to_ascii_lowercase().starts_with("http"))
        .collect()
}

fn crl_urls(cert: &Certificate) -> Vec<String> {
    let Some(dps) = ext::<CrlDistributionPoints>(cert, OID_CRL_DP) else { return Vec::new() };
    dps.0
        .iter()
        .filter_map(|dp| match &dp.distribution_point {
            Some(DistributionPointName::FullName(names)) => Some(names.iter().filter_map(uri).collect::<Vec<_>>()),
            _ => None,
        })
        .flatten()
        .filter(|u| u.to_ascii_lowercase().starts_with("http"))
        .collect()
}

/// A bare DER certificate or a PKCS#7 "certs-only" bundle (.p7c).
fn parse_certs(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    if Certificate::from_der(data).is_ok() {
        return Ok(vec![data.to_vec()]);
    }
    let ci = ContentInfo::from_der(data).context("issuer certificate in an unknown format")?;
    let sd = SignedData::from_der(&ci.content.to_der()?)?;
    Ok(sd
        .certificates
        .iter()
        .flat_map(|s| s.0.iter())
        .filter_map(|c| match c {
            CertificateChoices::Certificate(c) => c.to_der().ok(),
            _ => None,
        })
        .collect())
}

fn subject_cn(c: &Certificate) -> String {
    c.tbs_certificate.subject.to_string()
}

fn fmt_time(d: std::time::Duration) -> String {
    chrono::DateTime::from_timestamp(d.as_secs() as i64, 0)
        .map(|t| t.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_default()
}
