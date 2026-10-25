//! Minimal HTTP for TSA, OCSP, CRL and intermediate certificate downloads.
//!
//! URLs come from two places with different trust:
//! - [`Origin::User`]: URLs the user configured (the TSA). Fetched as is.
//! - [`Origin::Certificate`]: URLs found inside certificates (AIA, OCSP, CRL), which may come from
//!   untrusted parties (e.g. the certificates a TSA puts in its token). To avoid SSRF these are
//!   not allowed to reach loopback, private, link-local or otherwise non-public addresses. The
//!   check runs in the DNS resolver, so it also covers redirects and DNS rebinding. Set
//!   `FIRMA_ALLOW_PRIVATE_NETWORK=1` to lift it (e.g. for an internal corporate CA).

use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use anyhow::{bail, Context, Result};

const MAX_BODY: u64 = 32 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    User,
    Certificate,
}

/// HTTP Basic credentials.
pub struct Auth<'a> {
    pub user: &'a str,
    pub password: &'a str,
}

fn agent(origin: Origin) -> ureq::Agent {
    let builder = ureq::AgentBuilder::new().timeout(Duration::from_secs(20)).try_proxy_from_env(true);
    // Through a proxy, the proxy (not us) resolves the destination, so the guard cannot apply.
    if origin == Origin::Certificate && !private_network_allowed() && !proxy_configured() {
        return builder.resolver(public_only_resolver).build();
    }
    builder.build()
}

fn private_network_allowed() -> bool {
    std::env::var("FIRMA_ALLOW_PRIVATE_NETWORK").is_ok_and(|v| v == "1")
}

fn proxy_configured() -> bool {
    ["ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY", "all_proxy", "https_proxy", "http_proxy"]
        .iter()
        .any(|k| std::env::var(k).is_ok_and(|v| !v.is_empty()))
}

fn public_only_resolver(netloc: &str) -> io::Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = netloc.to_socket_addrs()?.collect();
    let public: Vec<SocketAddr> = addrs.iter().copied().filter(|a| is_public(a.ip())).collect();
    if public.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{netloc} resolves to a non-public address (set FIRMA_ALLOW_PRIVATE_NETWORK=1 to allow it)"),
        ));
    }
    Ok(public)
}

/// Whether `ip` is a globally routable unicast address.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (64..128).contains(&o[1])) // 100.64.0.0/10 (CGNAT)
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // 198.18.0.0/15 (benchmarking)
                || o[0] >= 240) // reserved
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let s = v6.segments();
            let o = v6.octets();
            let embedded = |a: usize| IpAddr::V4(std::net::Ipv4Addr::new(o[a], o[a + 1], o[a + 2], o[a + 3]));
            // IPv4-compatible ::a.b.c.d and NAT64 64:ff9b::/96 carry the IPv4 address in the low 32 bits.
            if (s[..6] == [0; 6] && !v6.is_loopback() && !v6.is_unspecified()) || s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                return is_public(embedded(12));
            }
            // 6to4 2002::/16 carries it right after the prefix.
            if s[0] == 0x2002 {
                return is_public(embedded(2));
            }
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (s[0] & 0xffc0) == 0xfec0 // site-local fec0::/10 (deprecated)
                || (s[0] == 0x2001 && s[1] == 0x0db8)) // documentation
        }
    }
}

fn check_scheme(url: &str) -> Result<()> {
    let lower = url.to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        bail!("unsupported URL (only http/https): {url}");
    }
    Ok(())
}

fn body(resp: ureq::Response, url: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    resp.into_reader().take(MAX_BODY + 1).read_to_end(&mut out).with_context(|| format!("reading response from {url}"))?;
    if out.len() as u64 > MAX_BODY {
        bail!("response too large from {url}");
    }
    Ok(out)
}

pub fn post(origin: Origin, url: &str, content_type: &str, data: &[u8], auth: Option<&Auth>) -> Result<Vec<u8>> {
    check_scheme(url)?;
    let mut req = agent(origin).post(url).set("Content-Type", content_type);
    if let Some(a) = auth {
        use base64::Engine as _;
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", a.user, a.password));
        req = req.set("Authorization", &format!("Basic {token}"));
    }
    let resp = req.send_bytes(data).map_err(|e| match e {
        ureq::Error::Status(401, _) => anyhow::anyhow!("{url} rejected the credentials (HTTP 401)"),
        e => anyhow::Error::new(e),
    });
    body(resp.with_context(|| format!("request to {url}"))?, url)
}

pub fn get(origin: Origin, url: &str) -> Result<Vec<u8>> {
    check_scheme(url)?;
    let resp = agent(origin).get(url).call().with_context(|| format!("downloading {url}"))?;
    body(resp, url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_addresses() {
        for ip in ["8.8.8.8", "2a00:1450:4003:80e::200e", "193.144.0.1", "64:ff9b::808:808", "2002:808:808::"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "0.0.0.0", "100.64.0.1",
            "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "224.0.0.1",
            "::127.0.0.1", "64:ff9b::a9fe:a9fe", "2002:7f00:1::", "fec0::1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn resolver_blocks_loopback() {
        assert!(public_only_resolver("127.0.0.1:80").is_err());
        assert!(public_only_resolver("localhost:80").is_err());
    }
}
