//! Minimal HTTP for TSA, OCSP, CRL and intermediate certificate downloads.

use std::io::Read;
use std::time::Duration;

use anyhow::{bail, Context, Result};

const MAX_BODY: u64 = 32 * 1024 * 1024;

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(Duration::from_secs(20)).try_proxy_from_env(true).build()
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

pub fn post(url: &str, content_type: &str, data: &[u8]) -> Result<Vec<u8>> {
    check_scheme(url)?;
    let resp = agent()
        .post(url)
        .set("Content-Type", content_type)
        .send_bytes(data)
        .with_context(|| format!("request to {url}"))?;
    body(resp, url)
}

pub fn get(url: &str) -> Result<Vec<u8>> {
    check_scheme(url)?;
    let resp = agent().get(url).call().with_context(|| format!("downloading {url}"))?;
    body(resp, url)
}
