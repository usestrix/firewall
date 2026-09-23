use super::enclave::EnclaveKey;
use super::{KEYCHAIN_ACCOUNT, KEYCHAIN_SERVICE};
use crate::mitm::CertificateAuthority;
use rama::error::BoxError;
use rama::net::apple::networkextension::system_keychain;
use tracing::info;

/// Removes what only root can: the CA and its enclave key. Trust settings need an
/// authorization dialog, so the installer drops those itself.
pub fn certificate_authority(ca: &CertificateAuthority) -> Result<(), BoxError> {
    system_keychain::uninstall_system_ca(&ca.crt.to_der()?)?;
    system_keychain::delete_secret(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)?;
    EnclaveKey::delete()?;
    info!("removed the CA from the system keychain");
    Ok(())
}
