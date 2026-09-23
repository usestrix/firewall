use super::{CA_FILE, KEYCHAIN_ACCOUNT, KEYCHAIN_SERVICE};
use crate::mitm::CertificateAuthority;
use rama::error::BoxError;
use rama::net::apple::networkextension::system_keychain;
use rcgen::SigningKey;
use std::path::Path;
use tracing::{info, warn};

/// Kept in the System keychain so trust survives restarts; replaced if the hosts change.
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
                export_pem(&ca);
                return Ok(ca);
            }
            None => warn!("stored CA does not match the screened hosts, minting a new one"),
        }
    }
    let ca = CertificateAuthority::generate(hosts, signer)?;
    system_keychain::store_secret(
        KEYCHAIN_SERVICE,
        KEYCHAIN_ACCOUNT,
        ca.to_blob(hosts).as_bytes(),
    )?;
    system_keychain::install_system_ca(&ca.crt.to_der()?)?;
    info!(?hosts, "minted a name-constrained CA held in the secure enclave");
    export_pem(&ca);
    Ok(ca)
}

/// For clients that read no keychain; screening still works for the rest if this fails.
fn export_pem(ca: &CertificateAuthority) {
    let dir = Path::new(CA_FILE).parent().expect("CA_FILE has a directory");
    let written = std::fs::create_dir_all(dir).and_then(|()| std::fs::write(CA_FILE, &ca.pem));
    if let Err(error) = written {
        warn!(%error, path = CA_FILE, "could not export the CA");
    }
}
