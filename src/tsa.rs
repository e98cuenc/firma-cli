//! RFC 3161 time-stamps (PAdES B-T signature time-stamps and B-LTA document time-stamps).

use anyhow::{anyhow, bail, Context, Result};
use cmpv2::status::PkiStatus;
use cms::cert::CertificateChoices;
use cms::signed_data::{SignedData, SignerIdentifier};
use der::asn1::{Int, ObjectIdentifier, OctetString};
use der::{Decode, Encode};
use spki::AlgorithmIdentifier;
use x509_cert::Certificate;
use x509_tsp::{MessageImprint, TimeStampReq, TimeStampResp, TspVersion, TstInfo};

use crate::cert::Digest;
use crate::net::{self, Auth, Origin};
use crate::verify::{self, Hash};

const ID_CT_TSTINFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const ID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

/// How to reach the time-stamping authority.
pub struct Tsa {
    pub url: String,
    pub user: Option<String>,
    pub password: Option<String>,
    /// TSA policy to request (reqPolicy), if the TSA needs one.
    pub policy: Option<ObjectIdentifier>,
}

pub struct Token {
    /// TimeStampToken (ContentInfo) in DER.
    pub der: Vec<u8>,
    /// Certificates included in the token (the TSA's).
    pub certs: Vec<Vec<u8>>,
    /// Certificate the TSA signed with.
    pub signer: Vec<u8>,
    pub time: chrono::DateTime<chrono::Utc>,
}

impl Tsa {
    /// Time-stamp over `data` (in PAdES B-T, the signature value).
    pub fn stamp(&self, data: &[u8]) -> Result<Token> {
        self.stamp_digest(Digest::Sha256, &Digest::Sha256.hash(&[data]))
    }

    /// Time-stamp over an already computed digest (document time-stamps).
    pub fn stamp_digest(&self, digest: Digest, imprint: &[u8]) -> Result<Token> {
        let nonce = nonce();
        let req = TimeStampReq {
            version: TspVersion::V1,
            message_imprint: MessageImprint {
                hash_algorithm: AlgorithmIdentifier { oid: digest.oid(), parameters: None },
                hashed_message: OctetString::new(imprint)?,
            },
            req_policy: self.policy,
            nonce: Some(Int::new(&nonce)?),
            cert_req: true,
            extensions: None,
        };
        let auth = match (&self.user, &self.password) {
            (Some(user), password) => {
                // Basic credentials are only obfuscated, never encrypted: require TLS.
                let insecure_ok = std::env::var("FIRMA_ALLOW_INSECURE_AUTH").is_ok_and(|v| v == "1");
                if !self.url.to_ascii_lowercase().starts_with("https://") && !insecure_ok {
                    bail!(
                        "refusing to send the TSA password over plain http to {} \
                         (use an https:// TSA URL, or set FIRMA_ALLOW_INSECURE_AUTH=1)",
                        self.url
                    );
                }
                Some(Auth { user, password: password.as_deref().unwrap_or("") })
            }
            (None, Some(_)) => bail!("a TSA password was given without a TSA user"),
            (None, None) => None,
        };
        let resp_der = net::post(Origin::User, &self.url, "application/timestamp-query", &req.to_der()?, auth.as_ref())?;
        let resp = TimeStampResp::from_der(&resp_der).map_err(|e| anyhow!("invalid TSA response: {e}"))?;
        if !matches!(resp.status.status, PkiStatus::Accepted | PkiStatus::GrantedWithMods) {
            bail!("the TSA rejected the request ({:?})", resp.status.status);
        }
        let token = resp.time_stamp_token.context("the TSA returned no token")?;
        let token_der = token.to_der()?;
        let checked = check_token(&token_der, imprint, Some(&nonce))?;
        if let Some(policy) = self.policy {
            if checked.policy != policy {
                bail!("the TSA used policy {} instead of the requested {policy}", checked.policy);
            }
        }
        Ok(Token { der: token_der, certs: checked.certs, signer: checked.signer, time: checked.time })
    }
}

struct Checked {
    certs: Vec<Vec<u8>>,
    signer: Vec<u8>,
    time: chrono::DateTime<chrono::Utc>,
    policy: ObjectIdentifier,
}

/// Verifies a TimeStampToken: it covers `imprint` (and `nonce`), its signed attributes match the
/// TSTInfo, the TSA's signature is valid and the signing certificate is meant for time-stamping.
fn check_token(token_der: &[u8], imprint: &[u8], nonce: Option<&[u8]>) -> Result<Checked> {
    let ci = cms::content_info::ContentInfo::from_der(token_der).context("malformed time-stamp token")?;
    let sd = SignedData::from_der(&ci.content.to_der()?).context("malformed time-stamp token")?;
    if sd.encap_content_info.econtent_type != ID_CT_TSTINFO {
        bail!("the time-stamp token does not contain a TSTInfo");
    }
    let content = sd.encap_content_info.econtent.as_ref().context("time-stamp token without TSTInfo")?;
    let tst_der = content.value();
    let tst = TstInfo::from_der(tst_der)?;
    if tst.message_imprint.hashed_message.as_bytes() != imprint {
        bail!("the time-stamp does not match this signature");
    }
    if let Some(nonce) = nonce {
        if tst.nonce.as_ref().map(|n| n.as_bytes()) != Some(Int::new(nonce)?.as_bytes()) {
            bail!("the time-stamp nonce does not match");
        }
    }

    let certs: Vec<(Vec<u8>, Certificate)> = sd
        .certificates
        .iter()
        .flat_map(|set| set.0.iter())
        .filter_map(|c| match c {
            CertificateChoices::Certificate(c) => Some((c.to_der().ok()?, c.clone())),
            _ => None,
        })
        .collect();
    let si = sd.signer_infos.0.iter().next().context("time-stamp token without a signer")?;
    let (signer_der, signer) = certs
        .iter()
        .find(|(_, c)| match &si.sid {
            SignerIdentifier::IssuerAndSerialNumber(ias) => {
                ias.issuer == c.tbs_certificate.issuer && ias.serial_number == c.tbs_certificate.serial_number
            }
            SignerIdentifier::SubjectKeyIdentifier(ski) => {
                use sha1::Digest as _;
                let key = c.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes();
                sha1::Sha1::digest(key).as_slice() == ski.0.as_bytes()
            }
        })
        .context("the time-stamp token does not include the TSA certificate")?;

    // Signed attributes: content-type must be TSTInfo and message-digest must match it.
    let attrs = si.signed_attrs.as_ref().context("time-stamp token without signed attributes")?;
    let attr = |oid: ObjectIdentifier| attrs.iter().find(|a| a.oid == oid).and_then(|a| a.values.iter().next());
    let ct = attr(ID_CONTENT_TYPE).context("time-stamp token without content-type")?.decode_as::<ObjectIdentifier>()?;
    if ct != ID_CT_TSTINFO {
        bail!("time-stamp token content-type mismatch");
    }
    let md = attr(ID_MESSAGE_DIGEST).context("time-stamp token without message-digest")?.decode_as::<OctetString>()?;
    let digest_alg = Hash::from_oid(&si.digest_alg.oid)?;
    if md.as_bytes() != digest_alg.digest(tst_der).as_slice() {
        bail!("time-stamp token message-digest mismatch");
    }
    verify::signature(
        &signer.tbs_certificate.subject_public_key_info,
        &si.signature_algorithm,
        Some(digest_alg),
        &attrs.to_der()?,
        si.signature.as_bytes(),
    )
    .context("invalid time-stamp token signature")?;
    if !verify::has_eku(signer, verify::EKU_TIME_STAMPING) {
        bail!("the TSA certificate is not meant for time-stamping (missing EKU)");
    }

    let secs = tst.gen_time.to_unix_duration().as_secs() as i64;
    Ok(Checked {
        certs: certs.iter().map(|(d, _)| d.clone()).collect(),
        signer: signer_der.clone(),
        time: chrono::DateTime::from_timestamp(secs, 0).unwrap_or_default(),
        policy: tst.policy,
    })
}

fn nonce() -> Vec<u8> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let seed = format!("{}-{}", now.as_nanos(), std::process::id());
    let mut n = Digest::Sha256.hash(&[seed.as_bytes()])[..8].to_vec();
    n[0] &= 0x7F; // positive INTEGER
    n
}
