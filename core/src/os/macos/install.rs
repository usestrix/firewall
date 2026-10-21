use super::enclave::EnclaveKey;
use super::{CA_FILE, KEYCHAIN_ACCOUNT, KEYCHAIN_SERVICE, SYSTEM_KEYCHAIN};
use crate::mitm::{CertificateAuthority, MANAGED_COMMON_NAME};
use rama::error::BoxError;
use rama::net::apple::networkextension::system_keychain;
use rama::tls::boring::core::x509::X509;
use rcgen::SigningKey;
use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::policy::SecPolicy;
use security_framework::trust::SecTrust;
use security_framework_sys::base::errSecItemNotFound;
use std::path::Path;
use tracing::{info, warn};

/// A CA an MDM enrolled over ACME. The MDM trusts its issuer, so the user is never asked to.
pub fn managed_certificate_authority(
) -> Result<Option<(EnclaveKey, CertificateAuthority)>, BoxError> {
    let found = ItemSearchOptions::new()
        .class(ItemClass::identity())
        .keychains(&[SecKeychain::open(SYSTEM_KEYCHAIN)?])
        .load_refs(true)
        .limit(Limit::All)
        .search();
    let results = match found {
        Ok(results) => results,
        Err(error) if error.code() == errSecItemNotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    for result in results {
        let SearchResult::Ref(Reference::Identity(identity)) = result else { continue };
        let crt = identity.certificate()?;
        if crt.subject_summary() != MANAGED_COMMON_NAME {
            continue;
        }
        let key = EnclaveKey::new(identity.private_key()?)?;
        let trust = SecTrust::create_with_certificates(&[crt], &[SecPolicy::create_x509()])?;
        trust.evaluate_with_error().map_err(|e| format!("the managed CA is not trusted: {e}"))?;
        let mut pem = String::new();
        for crt in trust.chain() {
            pem.push_str(std::str::from_utf8(&X509::from_der(&crt.to_der())?.to_pem()?)?);
        }
        let ca = CertificateAuthority::new(pem)?;
        info!("using the CA enrolled by MDM");
        export_pem(&ca);
        return Ok(Some((key, ca)));
    }
    Ok(None)
}

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
