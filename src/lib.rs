//! firma as a library: the same modules the `firma` command uses, for programs that need its
//! certificates, signatures or Keychain / Windows store access (with Touch ID / Windows Hello).

pub mod ber;
pub mod cert;
pub mod cms;
pub mod keystore;
pub mod net;
pub mod pdf;
pub mod pkcs11;
pub mod preview;
pub mod revocation;
pub mod store;
pub mod tsa;
pub mod verify;
pub mod xades;
pub mod xml;
