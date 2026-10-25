//! BER-encoded PKCS#12 files (as written by Java / BouncyCastle tools: indefinite lengths and
//! OCTET STRINGs split into chunks). The PKCS#12 parser only accepts DER, so such files are
//! rebuilt as an equivalent DER PKCS#12 after verifying their MAC over the original bytes.

use anyhow::{bail, Context, Result};

use crate::cms::tlv;

const SEQUENCE: u8 = 0x30;
const OCTET_STRING: u8 = 0x04;
const OCTET_STRING_CONSTRUCTED: u8 = 0x24;
const OID: u8 = 0x06;
const CONTEXT_0_CONSTRUCTED: u8 = 0xA0;
const CONTEXT_0_PRIMITIVE: u8 = 0x80;
const OID_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];

/// Whether `data` starts with an indefinite-length (BER-only) SEQUENCE.
pub fn is_ber(data: &[u8]) -> bool {
    data.len() > 2 && data[0] == SEQUENCE && data[1] == 0x80
}

/// One parsed element: tag, whether constructed, and either its raw content (primitive) or children.
struct Element {
    tag: u8,
    content: Vec<u8>,
    children: Vec<Element>,
}

impl Element {
    fn constructed(&self) -> bool {
        self.tag & 0x20 != 0
    }
}

/// Parses one BER element at `pos`, returning it and the position after it.
fn parse(data: &[u8], pos: usize, depth: usize) -> Result<(Element, usize)> {
    if depth > 64 {
        bail!("ASN.1 nesting too deep");
    }
    let tag = *data.get(pos).context("truncated ASN.1")?;
    if tag & 0x1f == 0x1f {
        bail!("high-tag-number ASN.1 tags are not supported");
    }
    let first = *data.get(pos + 1).context("truncated ASN.1")?;
    let mut p = pos + 2;
    let len = if first == 0x80 {
        None
    } else if first < 0x80 {
        Some(first as usize)
    } else {
        let n = (first & 0x7f) as usize;
        if n > 4 {
            bail!("ASN.1 length too large");
        }
        let bytes = data.get(p..p + n).context("truncated ASN.1")?;
        p += n;
        Some(bytes.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize))
    };
    let constructed = tag & 0x20 != 0;
    match len {
        Some(len) => {
            let end = p.checked_add(len).filter(|e| *e <= data.len()).context("truncated ASN.1")?;
            let mut el = Element { tag, content: Vec::new(), children: Vec::new() };
            if constructed {
                while p < end {
                    let (child, next) = parse(data, p, depth + 1)?;
                    el.children.push(child);
                    p = next;
                }
                if p != end {
                    bail!("malformed ASN.1 lengths");
                }
            } else {
                el.content = data[p..end].to_vec();
            }
            Ok((el, end))
        }
        None => {
            if !constructed {
                bail!("indefinite length on a primitive ASN.1 element");
            }
            let mut el = Element { tag, content: Vec::new(), children: Vec::new() };
            loop {
                if data.get(p..p + 2) == Some(&[0, 0]) {
                    return Ok((el, p + 2));
                }
                let (child, next) = parse(data, p, depth + 1)?;
                el.children.push(child);
                p = next;
            }
        }
    }
}

/// Concatenated content of a (possibly constructed) string element.
fn string_bytes(el: &Element) -> Vec<u8> {
    if el.constructed() {
        el.children.iter().flat_map(string_bytes).collect()
    } else {
        el.content.clone()
    }
}

/// Re-encodes `el` in DER: definite lengths and primitive OCTET STRINGs. Inside an
/// EncryptedContentInfo (OID, AlgorithmIdentifier, [0] IMPLICIT OCTET STRING) the constructed
/// `[0]` holds string chunks and becomes a primitive `[0]`; elsewhere `[0]` is an explicit tag.
fn to_der(el: &Element) -> Vec<u8> {
    if el.tag == OCTET_STRING_CONSTRUCTED {
        return tlv(OCTET_STRING, &string_bytes(el));
    }
    if !el.constructed() {
        return tlv(el.tag, &el.content);
    }
    let encrypted_content_info = el.tag == SEQUENCE
        && el.children.len() == 3
        && el.children[0].tag == OID
        && el.children[1].tag == SEQUENCE
        && el.children[2].tag == CONTEXT_0_CONSTRUCTED
        && el.children[2].children.iter().all(|c| c.tag == OCTET_STRING || c.tag == OCTET_STRING_CONSTRUCTED);
    let mut content = Vec::new();
    for (i, child) in el.children.iter().enumerate() {
        if encrypted_content_info && i == 2 {
            content.extend(tlv(CONTEXT_0_PRIMITIVE, &string_bytes(child)));
        } else {
            content.extend(to_der(child));
        }
    }
    tlv(el.tag, &content)
}

/// Parses a complete BER value and re-encodes it in DER.
fn normalize(data: &[u8]) -> Result<Vec<u8>> {
    let (el, end) = parse(data, 0, 0)?;
    if end != data.len() {
        bail!("trailing data after ASN.1 value");
    }
    Ok(to_der(&el))
}

/// Rebuilds a BER PKCS#12 as DER. The MAC (computed over the original BER bytes of the
/// AuthenticatedSafe) is verified here and then left out, since re-encoding invalidates it.
pub fn pkcs12_to_der(data: &[u8], password: &str) -> Result<Vec<u8>> {
    let (pfx, _) = parse(data, 0, 0).context("malformed PKCS#12")?;
    let [version, auth_safe, rest @ ..] = pfx.children.as_slice() else { bail!("malformed PKCS#12") };
    // authSafe ContentInfo: { OID data, [0] EXPLICIT OCTET STRING }
    let [ct, explicit] = auth_safe.children.as_slice() else { bail!("malformed PKCS#12 authSafe") };
    if ct.content != OID_DATA || explicit.children.len() != 1 {
        bail!("unsupported PKCS#12 (public-key integrity mode)");
    }
    let auth_safe_bytes = string_bytes(&explicit.children[0]);
    match rest.first() {
        Some(mac_data) => verify_mac(&to_der(mac_data), password, &auth_safe_bytes)?,
        None => bail!("BER PKCS#12 without a MAC is not supported"),
    }

    // AuthenticatedSafe ::= SEQUENCE OF ContentInfo; plain-data ContentInfos carry a SafeContents
    // in an OCTET STRING, which may be BER too.
    let (safe, _) = parse(&auth_safe_bytes, 0, 0).context("malformed PKCS#12 AuthenticatedSafe")?;
    let mut infos = Vec::new();
    for info in &safe.children {
        match info.children.as_slice() {
            [ct, explicit] if ct.content == OID_DATA && explicit.children.len() == 1 => {
                let safe_contents = normalize(&string_bytes(&explicit.children[0]))?;
                let explicit = tlv(CONTEXT_0_CONSTRUCTED, &tlv(OCTET_STRING, &safe_contents));
                infos.push(tlv(SEQUENCE, &[to_der(ct), explicit].concat()));
            }
            _ => infos.push(to_der(info)),
        }
    }
    let auth_safe_der = tlv(SEQUENCE, &infos.concat());
    let auth_safe = tlv(
        SEQUENCE,
        &[tlv(OID, OID_DATA), tlv(CONTEXT_0_CONSTRUCTED, &tlv(OCTET_STRING, &auth_safe_der))].concat(),
    );
    Ok(tlv(SEQUENCE, &[to_der(version), auth_safe].concat()))
}

/// PKCS#12 MacData ::= SEQUENCE { mac DigestInfo, macSalt OCTET STRING, iterations INTEGER DEFAULT 1 }
fn verify_mac(mac_data_der: &[u8], password: &str, data: &[u8]) -> Result<()> {
    use hmac::Mac;
    let (mac_data, _) = parse(mac_data_der, 0, 0)?;
    let (digest_info, salt, iterations) = match mac_data.children.as_slice() {
        [d, s] => (d, &s.content, 1u64),
        [d, s, i] => (d, &s.content, i.content.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64)),
        _ => bail!("malformed PKCS#12 MAC"),
    };
    if iterations == 0 || iterations > 10_000_000 {
        bail!("unreasonable PKCS#12 MAC iteration count");
    }
    let [alg, expected] = digest_info.children.as_slice() else { bail!("malformed PKCS#12 MAC") };
    let oid = &alg.children.first().context("malformed PKCS#12 MAC")?.content;
    let ok = match oid.as_slice() {
        [0x2B, 0x0E, 0x03, 0x02, 0x1A] => {
            let key = kdf::<sha1::Sha1>(password, salt, iterations, 20, 64);
            let mut m = hmac::Hmac::<sha1::Sha1>::new_from_slice(&key)?;
            m.update(data);
            m.verify_slice(&expected.content).is_ok()
        }
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] => {
            let key = kdf::<sha2::Sha256>(password, salt, iterations, 32, 64);
            let mut m = hmac::Hmac::<sha2::Sha256>::new_from_slice(&key)?;
            m.update(data);
            m.verify_slice(&expected.content).is_ok()
        }
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02] => {
            let key = kdf::<sha2::Sha384>(password, salt, iterations, 48, 128);
            let mut m = hmac::Hmac::<sha2::Sha384>::new_from_slice(&key)?;
            m.update(data);
            m.verify_slice(&expected.content).is_ok()
        }
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03] => {
            let key = kdf::<sha2::Sha512>(password, salt, iterations, 64, 128);
            let mut m = hmac::Hmac::<sha2::Sha512>::new_from_slice(&key)?;
            m.update(data);
            m.verify_slice(&expected.content).is_ok()
        }
        _ => bail!("unsupported PKCS#12 MAC algorithm"),
    };
    if !ok {
        bail!("wrong password, or the file is corrupted (PKCS#12 MAC mismatch)");
    }
    Ok(())
}

/// PKCS#12 key derivation (RFC 7292 appendix B.2) with ID 3 (MAC key), for n ≤ hash size.
fn kdf<D: sha2::Digest>(password: &str, salt: &[u8], iterations: u64, n: usize, v: usize) -> Vec<u8> {
    let mut pw: Vec<u8> = password.encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
    pw.extend([0, 0]);
    let fill = |s: &[u8]| -> Vec<u8> {
        if s.is_empty() {
            return Vec::new();
        }
        let len = v * s.len().div_ceil(v);
        s.iter().cycle().take(len).copied().collect()
    };
    let i = [fill(salt), fill(&pw)].concat();
    let mut a = D::new().chain_update(vec![3u8; v]).chain_update(&i).finalize().to_vec();
    for _ in 1..iterations {
        a = D::digest(&a).to_vec();
    }
    a.truncate(n);
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_indefinite_and_chunked() {
        // SEQUENCE(indef) { OCTET STRING(constructed, indef) { "ab", "c" } }
        let ber = [0x30, 0x80, 0x24, 0x80, 0x04, 0x02, b'a', b'b', 0x04, 0x01, b'c', 0, 0, 0, 0];
        assert_eq!(normalize(&ber).unwrap(), vec![0x30, 0x05, 0x04, 0x03, b'a', b'b', b'c']);
        assert!(normalize(&[0x30, 0x80, 0x04, 0x01]).is_err());
    }

    #[test]
    fn encrypted_content_becomes_implicit_primitive() {
        // SEQUENCE { OID, SEQUENCE {}, [0] constructed { OCTET STRING "xy" } }
        let ber = [0x30, 0x80, 0x06, 0x01, 0x2A, 0x30, 0x00, 0xA0, 0x80, 0x04, 0x02, b'x', b'y', 0, 0, 0, 0];
        assert_eq!(
            normalize(&ber).unwrap(),
            vec![0x30, 0x09, 0x06, 0x01, 0x2A, 0x30, 0x00, 0x80, 0x02, b'x', b'y']
        );
    }
}
