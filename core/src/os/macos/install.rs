use super::{KEYCHAIN_ACCOUNT, KEYCHAIN_SERVICE};
use crate::mitm::CertificateAuthority;
use rama::error::BoxError;
use rama::net::apple::networkextension::system_keychain;
use rcgen::SigningKey;
use tracing::{info, warn};

/// Minted once and kept in the system keychain, so trust survives restarts. A CA
/// that cannot sign for every screened host is replaced, since it can no longer
/// screen them.
pub fn certificate_authority(
    hosts: &[&str],
    signer: &dyn SigningKey,
) -> Result<CertificateAuthority, BoxError> {
    if let Some(blob) = system_keychain::load_secret(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)? {
        let stored = std::str::from_utf8(&blob).ok();
        match stored.and_then(|b| CertificateAuthority::from_blob(b, hosts, signer)) {
            Some(ca) => {
                // Idempotent, and the keychain item can outlive the certificate.
                system_keychain::install_system_ca(&ca.crt.to_der()?)?;
                info!(?hosts, "restored the CA from the system keychain");
                return Ok(ca);
            }
            None => warn!("stored CA does not match the screened hosts, minting a new one"),
        }
    }
    let ca = CertificateAuthority::generate(hosts, signer)?;
    system_keychain::store_secret(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, ca.to_blob().as_bytes())?;
    system_keychain::install_system_ca(&ca.crt.to_der()?)?;
    info!(?hosts, "minted a name-constrained CA held in the secure enclave");
    Ok(ca)
}
