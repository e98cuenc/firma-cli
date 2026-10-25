//! macOS: identities in the Keychain (Security.framework) and Touch ID (LocalAuthentication).

use anyhow::{anyhow, bail, Result};
use security_framework::certificate::SecCertificate;
use security_framework::identity::SecIdentity;
use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
use security_framework::key::{Algorithm, SecKey};
use security_framework::policy::SecPolicy;
use security_framework::trust::SecTrust;

use crate::cert::KeyAlg;

const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_USER_CANCELED: isize = -128;

pub struct Key(SecKey);

fn identities() -> Result<Vec<SecIdentity>> {
    let mut opts = ItemSearchOptions::new();
    opts.class(ItemClass::identity()).limit(Limit::All).load_refs(true);
    // Tests use a throwaway keychain instead of the user's.
    #[cfg(debug_assertions)]
    let _keychain;
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os("FIRMA_TEST_KEYCHAIN") {
        _keychain = [security_framework::os::macos::keychain::SecKeychain::open(path)?];
        opts.keychains(&_keychain);
    }
    let results = match opts.search() {
        Ok(r) => r,
        Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => return Ok(Vec::new()),
        Err(e) => bail!("could not read the macOS Keychain: {e}"),
    };
    Ok(results
        .into_iter()
        .filter_map(|r| match r {
            SearchResult::Ref(Reference::Identity(id)) => Some(id),
            _ => None,
        })
        .collect())
}

pub fn certificates() -> Result<Vec<Vec<u8>>> {
    Ok(identities()?.iter().filter_map(|id| id.certificate().ok()).map(|c| c.to_der()).collect())
}

pub fn load(sha1: &[u8; 20]) -> Result<(Key, Vec<u8>, Vec<Vec<u8>>)> {
    use sha1::Digest as _;
    for id in identities()? {
        let Ok(cert) = id.certificate() else { continue };
        let der = cert.to_der();
        if sha1::Sha1::digest(&der).as_slice() == sha1 {
            let key = id.private_key().map_err(|e| anyhow!("could not get the private key from the Keychain: {e}"))?;
            return Ok((Key(key), der, chain(&cert)));
        }
    }
    bail!("the certificate is no longer in the macOS Keychain (see `firma certs`)")
}

/// The issuers of `cert` known to the system (keychains and system roots), without the network.
fn chain(cert: &SecCertificate) -> Vec<Vec<u8>> {
    let Ok(mut trust) = SecTrust::create_with_certificates(&[cert.clone()], &[SecPolicy::create_x509()]) else {
        return Vec::new();
    };
    let _ = trust.set_network_fetch_allowed(false);
    // The chain is built even when it is not trusted; only the certificates matter here.
    let _ = trust.evaluate_with_error();
    #[allow(deprecated)]
    (1..trust.certificate_count()).filter_map(|i| trust.certificate_at_index(i)).map(|c| c.to_der()).collect()
}

pub fn sign(key: &Key, alg: KeyAlg, digest: &[u8]) -> Result<Vec<u8>> {
    let algorithm = match alg {
        KeyAlg::Rsa => Algorithm::RSASignatureDigestPKCS1v15SHA256,
        KeyAlg::P256 => Algorithm::ECDSASignatureDigestX962SHA256,
        KeyAlg::P384 => Algorithm::ECDSASignatureDigestX962SHA384,
    };
    key.0.create_signature(algorithm, digest).map_err(|e| {
        if e.code() == ERR_SEC_USER_CANCELED {
            anyhow!("cancelled: the Keychain did not allow using the key")
        } else {
            anyhow!("the macOS Keychain could not sign: {}", e.description())
        }
    })
}

pub fn verify_presence(reason: &str) -> Result<()> {
    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    // Touch ID (or Apple Watch), falling back to the account password.
    let policy = LAPolicy::DeviceOwnerAuthentication;
    let context = unsafe { LAContext::new() };
    unsafe { context.canEvaluatePolicy_error(policy) }
        .map_err(|e| anyhow!("Touch ID is not available: {}", e.localizedDescription()))?;
    let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();
    let reply = RcBlock::new(move |ok: Bool, error: *mut NSError| {
        let result = if ok.as_bool() {
            Ok(())
        } else {
            // SAFETY: on failure LocalAuthentication passes a valid NSError (or null).
            Err(unsafe { error.as_ref() }.map(|e| e.localizedDescription().to_string()).unwrap_or_default())
        };
        let _ = tx.send(result);
    });
    unsafe { context.evaluatePolicy_localizedReason_reply(policy, &NSString::from_str(reason), &reply) };
    match rx.recv() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(msg)) => bail!("not confirmed with Touch ID: {msg}"),
        Err(_) => bail!("Touch ID did not answer"),
    }
}
