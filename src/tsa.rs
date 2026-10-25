//! RFC 3161 time-stamps (PAdES B-T).

use anyhow::{anyhow, bail, Context, Result};
use cmpv2::status::PkiStatus;
use cms::cert::CertificateChoices;
use cms::signed_data::{SignedData, SignerIdentifier};
use der::asn1::{Int, OctetString};
use der::{Decode, Encode};
use spki::AlgorithmIdentifier;
use x509_tsp::{MessageImprint, TimeStampReq, TimeStampResp, TspVersion, TstInfo};

use crate::cert::Digest;

pub struct Token {
    /// TimeStampToken (ContentInfo) in DER.
    pub der: Vec<u8>,
    /// Certificates included in the token (the TSA's).
    pub certs: Vec<Vec<u8>>,
    /// Certificate the TSA signed with, if included.
    pub signer: Option<Vec<u8>>,
    pub time: chrono::DateTime<chrono::Utc>,
}

/// Asks the TSA for a time-stamp over `data` (in PAdES, the signature value).
pub fn request(url: &str, data: &[u8]) -> Result<Token> {
    let digest = Digest::Sha256;
    let imprint = digest.hash(&[data]);
    let nonce = nonce();
    let req = TimeStampReq {
        version: TspVersion::V1,
        message_imprint: MessageImprint {
            hash_algorithm: AlgorithmIdentifier { oid: digest.oid(), parameters: None },
            hashed_message: OctetString::new(imprint.clone())?,
        },
        req_policy: None,
        nonce: Some(Int::new(&nonce)?),
        cert_req: true,
        extensions: None,
    };
    let resp_der = crate::net::post(url, "application/timestamp-query", &req.to_der()?)?;
    let resp = TimeStampResp::from_der(&resp_der).map_err(|e| anyhow!("invalid TSA response: {e}"))?;
    if !matches!(resp.status.status, PkiStatus::Accepted | PkiStatus::GrantedWithMods) {
        bail!("the TSA rejected the request ({:?})", resp.status.status);
    }
    let token = resp.time_stamp_token.context("the TSA returned no token")?;

    let sd = SignedData::from_der(&token.content.to_der()?).context("malformed time-stamp token")?;
    let content = sd.encap_content_info.econtent.as_ref().context("time-stamp token without TSTInfo")?;
    let tst = TstInfo::from_der(content.value())?;
    if tst.message_imprint.hashed_message.as_bytes() != imprint.as_slice() {
        bail!("the time-stamp does not match this signature");
    }
    if tst.nonce.as_ref().map(|n| n.as_bytes()) != Some(Int::new(&nonce)?.as_bytes()) {
        bail!("the time-stamp nonce does not match");
    }
    let mut certs = Vec::new();
    let mut signer = None;
    let sid = sd.signer_infos.0.iter().next().map(|si| &si.sid);
    for c in sd.certificates.iter().flat_map(|set| set.0.iter()) {
        if let CertificateChoices::Certificate(c) = c {
            if let Some(SignerIdentifier::IssuerAndSerialNumber(ias)) = sid {
                if ias.issuer == c.tbs_certificate.issuer && ias.serial_number == c.tbs_certificate.serial_number {
                    signer = Some(c.to_der()?);
                }
            }
            certs.push(c.to_der()?);
        }
    }
    let secs = tst.gen_time.to_unix_duration().as_secs() as i64;
    Ok(Token {
        der: token.to_der()?,
        certs,
        signer,
        time: chrono::DateTime::from_timestamp(secs, 0).unwrap_or_default(),
    })
}

fn nonce() -> Vec<u8> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let seed = format!("{}-{}", now.as_nanos(), std::process::id());
    let mut n = Digest::Sha256.hash(&[seed.as_bytes()])[..8].to_vec();
    n[0] &= 0x7F; // positive INTEGER
    n
}
