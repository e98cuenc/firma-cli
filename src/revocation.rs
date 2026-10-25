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
use x509_ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspRequest, OcspResponse, OcspResponseStatus, Request, ResponderId, TbsRequest,
};

use crate::net::{self, Origin};
use crate::verify;

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
    let top = Certificate::from_der(chain.last().unwrap())?;
    if !is_self_signed(&top) {
        // Without the issuer, the revocation status of the last certificate cannot be checked.
        let msg = format!("incomplete certificate chain: the issuer of \"{}\" was not found", subject_cn(&top));
        if strict {
            bail!("{msg}");
        }
        eprintln!("warning: {msg}");
    }
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
        let cur_der = chain.last().unwrap().clone();
        let cur = Certificate::from_der(&cur_der)?;
        if is_self_signed(&cur) {
            return Ok(chain);
        }
        let issuer = match find_issuer(&cur_der, &cur, &pool) {
            Some(i) => i,
            None => {
                let mut fetched = Vec::new();
                for url in aia_urls(&cur, OID_CA_ISSUERS) {
                    match net::get(Origin::Certificate, &url).and_then(|d| parse_certs(&d)) {
                        Ok(certs) => fetched.extend(certs),
                        Err(e) => eprintln!("warning: {e:#}"),
                    }
                }
                pool.extend(fetched);
                match find_issuer(&cur_der, &cur, &pool) {
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

/// An issuer for `cert` from `pool` whose signature over `cert` actually verifies.
fn find_issuer(cert_der: &[u8], cert: &Certificate, pool: &[Vec<u8>]) -> Option<Vec<u8>> {
    let aki = ext::<AuthorityKeyIdentifier>(cert, OID_AKI).and_then(|a| a.key_identifier).map(|k| k.as_bytes().to_vec());
    let candidates: Vec<(&Vec<u8>, Certificate)> = pool
        .iter()
        .filter_map(|d| Certificate::from_der(d).ok().map(|c| (d, c)))
        .filter(|(_, c)| verify::cert_signed_by(cert_der, cert, c).is_ok())
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
        match crl(out, cert, issuer, &url) {
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
    let cert_id = CertId {
        hash_algorithm: AlgorithmIdentifierOwned { oid: OID_SHA1, parameters: Some(der::Any::null()) },
        issuer_name_hash: OctetString::new(verify::Hash::Sha1.digest(&cert.tbs_certificate.issuer.to_der()?))?,
        issuer_key_hash: OctetString::new(verify::Hash::Sha1.digest(
            issuer.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes(),
        ))?,
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
    let resp_der = net::post(Origin::Certificate, url, "application/ocsp-request", &req.to_der()?, None)?;
    let resp = OcspResponse::from_der(&resp_der).context("malformed OCSP response")?;
    if resp.response_status != OcspResponseStatus::Successful {
        bail!("the responder answered {:?}", resp.response_status);
    }
    let bytes = resp.response_bytes.context("empty OCSP response")?;
    if bytes.response_type != OID_OCSP_BASIC {
        bail!("unsupported OCSP response type");
    }
    let basic_der = bytes.response.as_bytes();
    let basic = BasicOcspResponse::from_der(basic_der)?;
    check_ocsp_signature(&basic, basic_der, issuer)?;
    let single = basic
        .tbs_response_data
        .responses
        .iter()
        .find(|r| cert_id_matches(&r.cert_id, cert, issuer))
        .context("the OCSP response does not cover this certificate")?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    if single.this_update.0.to_unix_duration() > now + CLOCK_SKEW {
        bail!("the OCSP response is dated in the future");
    }
    match &single.next_update {
        Some(n) if n.0.to_unix_duration() + CLOCK_SKEW < now => bail!("the OCSP response has expired"),
        Some(_) => {}
        // Without nextUpdate the response must be fresh, or an old "good" answer could be replayed.
        None if single.this_update.0.to_unix_duration() + MAX_OCSP_AGE < now => {
            bail!("the OCSP response is too old (no nextUpdate and thisUpdate over 24 h ago)")
        }
        None => {}
    }
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

fn crl(out: &mut Validation, cert: &Certificate, issuer: &Certificate, url: &str) -> Result<Status> {
    let der = net::get(Origin::Certificate, url)?;
    let list = CertificateList::from_der(&der).context("malformed CRL (DER expected)")?;
    if list.tbs_cert_list.issuer != cert.tbs_certificate.issuer {
        bail!("the CRL belongs to a different issuer");
    }
    verify::signature(
        &issuer.tbs_certificate.subject_public_key_info,
        &list.signature_algorithm,
        None,
        verify::first_element(&der)?,
        list.signature.raw_bytes(),
    )
    .context("invalid CRL signature")?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    if list.tbs_cert_list.next_update.is_some_and(|n| n.to_unix_duration() + CLOCK_SKEW < now) {
        bail!("the CRL has expired");
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

const CLOCK_SKEW: std::time::Duration = std::time::Duration::from_secs(300);
const MAX_OCSP_AGE: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

/// Whether an OCSP CertID refers to `cert` issued by `issuer` (any supported hash).
fn cert_id_matches(id: &CertId, cert: &Certificate, issuer: &Certificate) -> bool {
    let Ok(hash) = verify::Hash::from_oid(&id.hash_algorithm.oid) else { return false };
    let Ok(name) = cert.tbs_certificate.issuer.to_der() else { return false };
    let key = issuer.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes();
    id.serial_number == cert.tbs_certificate.serial_number
        && id.issuer_name_hash.as_bytes() == hash.digest(&name).as_slice()
        && id.issuer_key_hash.as_bytes() == hash.digest(key).as_slice()
}

/// The response must be signed by the issuing CA itself, or by a delegated responder that the
/// CA issued with the OCSPSigning extended key usage.
fn check_ocsp_signature(basic: &BasicOcspResponse, basic_der: &[u8], issuer: &Certificate) -> Result<()> {
    let tbs = verify::first_element(basic_der)?;
    let verify_with = |c: &Certificate| {
        verify::signature(
            &c.tbs_certificate.subject_public_key_info,
            &basic.signature_algorithm,
            None,
            tbs,
            basic.signature.raw_bytes(),
        )
    };
    let matches_responder = |c: &Certificate| match &basic.tbs_response_data.responder_id {
        ResponderId::ByName(name) => &c.tbs_certificate.subject == name,
        ResponderId::ByKey(hash) => {
            let key = c.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes();
            verify::Hash::Sha1.digest(key).as_slice() == hash.as_bytes()
        }
    };
    if matches_responder(issuer) {
        return verify_with(issuer).context("invalid OCSP response signature");
    }
    for responder in basic.certs.iter().flatten().filter(|c| matches_responder(c)) {
        let der = responder.to_der()?;
        if verify::cert_signed_by(&der, responder, issuer).is_ok() && verify::has_eku(responder, verify::EKU_OCSP_SIGNING) {
            return verify_with(responder).context("invalid OCSP response signature");
        }
    }
    bail!("the OCSP response is not signed by the issuer or an authorized responder")
}
