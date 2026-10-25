//! Windows: certificates in the current user's "Personal" store (CryptoAPI), keys through CNG
//! (software keys, TPM, smart cards and DNIe alike) and Windows Hello.

use anyhow::{anyhow, bail, Result};
use windows::core::{w, BOOL, HSTRING};
use windows::Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability};
use windows::Win32::Security::Cryptography::{
    CertCloseStore, CertEnumCertificatesInStore, CertFindCertificateInStore, CertFreeCertificateChain,
    CertFreeCertificateContext, CertGetCertificateChain, CertGetCertificateContextProperty, CertOpenSystemStoreW,
    CryptAcquireCertificatePrivateKey, NCryptFreeObject, NCryptSignHash, BCRYPT_PKCS1_PADDING_INFO,
    BCRYPT_SHA256_ALGORITHM, CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, CERT_CHAIN_CONTEXT, CERT_CHAIN_PARA, CERT_CONTEXT,
    CERT_FIND_SHA1_HASH, CERT_KEY_PROV_INFO_PROP_ID, CERT_KEY_SPEC, CERT_NCRYPT_KEY_SPEC, CRYPT_ACQUIRE_COMPARE_KEY_FLAG,
    CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, CRYPT_INTEGER_BLOB, HCERTSTORE, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE,
    NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_PAD_PKCS1_FLAG, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};
use windows::Win32::System::Console::GetConsoleWindow;
use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
use windows_future::IAsyncOperation;

use crate::cert::KeyAlg;

pub struct Key {
    handle: NCRYPT_KEY_HANDLE,
    owned: bool,
}

impl Drop for Key {
    fn drop(&mut self) {
        if self.owned {
            let _ = unsafe { NCryptFreeObject(self.handle.into()) };
        }
    }
}

/// The current user's "Personal" (MY) store.
struct Store(HCERTSTORE);

impl Store {
    fn open() -> Result<Self> {
        let h = unsafe { CertOpenSystemStoreW(None, w!("MY")) }
            .map_err(|e| anyhow!("could not open the Windows certificate store: {e}"))?;
        Ok(Self(h))
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        let _ = unsafe { CertCloseStore(Some(self.0), 0) };
    }
}

fn der_of(ctx: *const CERT_CONTEXT) -> Vec<u8> {
    // SAFETY: a valid context points to its encoded certificate.
    unsafe { std::slice::from_raw_parts((*ctx).pbCertEncoded, (*ctx).cbCertEncoded as usize).to_vec() }
}

fn has_private_key(ctx: *const CERT_CONTEXT) -> bool {
    let mut size = 0u32;
    unsafe { CertGetCertificateContextProperty(ctx, CERT_KEY_PROV_INFO_PROP_ID, None, &mut size) }.is_ok()
}

pub fn certificates() -> Result<Vec<Vec<u8>>> {
    let store = Store::open()?;
    let mut out = Vec::new();
    let mut ctx: *mut CERT_CONTEXT = std::ptr::null_mut();
    loop {
        // Passing the previous context frees it.
        ctx = unsafe { CertEnumCertificatesInStore(store.0, (!ctx.is_null()).then_some(ctx as *const _)) };
        if ctx.is_null() {
            break;
        }
        if has_private_key(ctx) {
            out.push(der_of(ctx));
        }
    }
    Ok(out)
}

pub fn load(sha1: &[u8; 20]) -> Result<(Key, Vec<u8>, Vec<Vec<u8>>)> {
    let store = Store::open()?;
    let blob = CRYPT_INTEGER_BLOB { cbData: 20, pbData: sha1.as_ptr() as *mut u8 };
    let ctx = unsafe {
        CertFindCertificateInStore(
            store.0,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SHA1_HASH,
            Some(&blob as *const _ as *const _),
            None,
        )
    };
    if ctx.is_null() {
        bail!("the certificate is no longer in the Windows certificate store (see `firma certs`)");
    }
    let result = (|| {
        let mut handle = HCRYPTPROV_OR_NCRYPT_KEY_HANDLE::default();
        let mut spec = CERT_KEY_SPEC::default();
        let mut owned = BOOL::default();
        unsafe {
            CryptAcquireCertificatePrivateKey(
                ctx,
                CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_COMPARE_KEY_FLAG,
                None,
                &mut handle,
                Some(&mut spec),
                Some(&mut owned),
            )
        }
        .map_err(|e| anyhow!("could not get the private key from the Windows certificate store: {e}"))?;
        if spec != CERT_NCRYPT_KEY_SPEC {
            bail!("the private key is not available through CNG");
        }
        let key = Key { handle: NCRYPT_KEY_HANDLE(handle.0), owned: owned.as_bool() };
        Ok((key, der_of(ctx), chain(ctx, &store)))
    })();
    let _ = unsafe { CertFreeCertificateContext(Some(ctx)) };
    result
}

/// The issuers of the certificate known to Windows, without going to the network.
fn chain(ctx: *const CERT_CONTEXT, store: &Store) -> Vec<Vec<u8>> {
    let para = CERT_CHAIN_PARA { cbSize: std::mem::size_of::<CERT_CHAIN_PARA>() as u32, ..Default::default() };
    let mut chain: *mut CERT_CHAIN_CONTEXT = std::ptr::null_mut();
    let built = unsafe {
        CertGetCertificateChain(
            None,
            ctx,
            None,
            Some(store.0),
            &para,
            CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL,
            None,
            &mut chain,
        )
    };
    let mut out = Vec::new();
    if built.is_ok() && !chain.is_null() {
        // SAFETY: a built chain context has cChain simple chains, each with cElement elements.
        unsafe {
            if (*chain).cChain > 0 {
                let simple = *(*chain).rgpChain;
                for i in 1..(*simple).cElement as usize {
                    let element = *(*simple).rgpElement.add(i);
                    out.push(der_of((*element).pCertContext));
                }
            }
            CertFreeCertificateChain(chain);
        }
    }
    out
}

pub fn sign(key: &Key, alg: KeyAlg, digest: &[u8]) -> Result<Vec<u8>> {
    let padding = BCRYPT_PKCS1_PADDING_INFO { pszAlgId: BCRYPT_SHA256_ALGORITHM };
    let (info, flags) = match alg {
        KeyAlg::Rsa => (Some(&padding as *const _ as *const core::ffi::c_void), NCRYPT_PAD_PKCS1_FLAG),
        _ => (None, NCRYPT_FLAGS(0)),
    };
    let fail = |e: windows::core::Error| anyhow!("Windows could not sign with the key: {}", e.message());
    let mut len = 0u32;
    unsafe { NCryptSignHash(key.handle, info, digest, None, &mut len, flags) }.map_err(fail)?;
    let mut sig = vec![0u8; len as usize];
    unsafe { NCryptSignHash(key.handle, info, digest, Some(&mut sig), &mut len, flags) }.map_err(fail)?;
    sig.truncate(len as usize);
    super::ecdsa_raw_to_der(alg, &sig)
}

pub fn verify_presence(reason: &str) -> Result<()> {
    let available = UserConsentVerifier::CheckAvailabilityAsync()
        .and_then(|op| op.join())
        .map_err(|e| anyhow!("Windows Hello is not available: {}", e.message()))?;
    if available != UserConsentVerifierAvailability::Available {
        bail!("Windows Hello is not set up on this computer (set up a PIN or fingerprint in Settings → Accounts → Sign-in options)");
    }
    let message = HSTRING::from(reason);
    // Desktop apps must say which window the dialog belongs to: the console's.
    let interop = windows::core::factory::<UserConsentVerifier, IUserConsentVerifierInterop>()?;
    let result = unsafe {
        let hwnd = GetConsoleWindow();
        interop.RequestVerificationForWindowAsync::<IAsyncOperation<UserConsentVerificationResult>>(hwnd, &message)
    }
    .and_then(|op| op.join())
    .map_err(|e| anyhow!("Windows Hello failed: {}", e.message()))?;
    match result {
        UserConsentVerificationResult::Verified => Ok(()),
        UserConsentVerificationResult::Canceled => bail!("cancelled in Windows Hello"),
        other => bail!("not confirmed with Windows Hello ({other:?})"),
    }
}
