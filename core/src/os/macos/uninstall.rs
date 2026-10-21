use super::enclave::EnclaveKey;
use super::{CA_FILE, KEYCHAIN_ACCOUNT, KEYCHAIN_SERVICE};
use crate::mitm::COMMON_NAME;
use rama::error::BoxError;
use rama::net::apple::networkextension::system_keychain;
use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
use security_framework::os::macos::keychain::SecKeychain;
use security_framework_sys::base::errSecItemNotFound;
use std::io::ErrorKind;
use tracing::info;

/// Installed by the pkg.
const ENV_AGENT: &str = "/Library/LaunchAgents/com.usestrix.firewall.env.plist";

/// Removes what only root can: every CA the extension minted, its enclave key and exported
/// copy, and the env agent. Trust settings need an authorization dialog, so the app drops those.
pub fn uninstall() -> Result<(), BoxError> {
    let deleted = ItemSearchOptions::new()
        .class(ItemClass::certificate())
        .keychains(&[SecKeychain::open("/Library/Keychains/System.keychain")?])
        .label(COMMON_NAME)
        .limit(Limit::All)
        .delete();
    let mut removed = match deleted {
        Ok(()) => true,
        Err(error) if error.code() == errSecItemNotFound => false,
        Err(error) => return Err(error.into()),
    };
    if system_keychain::load_secret(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)?.is_some() {
        system_keychain::delete_secret(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)?;
        removed = true;
    }
    EnclaveKey::delete()?;
    for path in [CA_FILE, ENV_AGENT] {
        match std::fs::remove_file(path) {
            Ok(()) => removed = true,
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    if removed {
        info!("removed the CA from the system keychain");
    } else {
        info!("nothing to uninstall");
    }
    Ok(())
}
