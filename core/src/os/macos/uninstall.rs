use super::enclave::EnclaveKey;
use super::{CA_FILE, KEYCHAIN_ACCOUNT, KEYCHAIN_SERVICE};
use crate::mitm::CertificateAuthority;
use rama::error::BoxError;
use rama::net::apple::networkextension::system_keychain;
use std::io::ErrorKind;
use tracing::info;

/// Installed by the pkg.
const ENV_AGENT: &str = "/Library/LaunchAgents/ai.strix.firewall.env.plist";

/// Removes what only root can: the CA, its enclave key and exported copy, and the env
/// agent. Trust settings need an authorization dialog, so the installer drops those itself.
pub fn certificate_authority(ca: &CertificateAuthority) -> Result<(), BoxError> {
    system_keychain::uninstall_system_ca(&ca.crt.to_der()?)?;
    system_keychain::delete_secret(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)?;
    EnclaveKey::delete()?;
    for path in [CA_FILE, ENV_AGENT] {
        match std::fs::remove_file(path) {
            Err(error) if error.kind() != ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
    }
    info!("removed the CA from the system keychain");
    Ok(())
}
