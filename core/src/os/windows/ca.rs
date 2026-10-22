use super::*;
use crate::mitm::{CertificateAuthority, COMMON_NAME, ORGANIZATION};
use rama::tls::boring::core::nid::Nid;
use rama::tls::boring::core::x509::X509;
use rcgen::SigningKey;
use schannel::cert_context::CertContext;
use schannel::cert_store::{CertAdd, CertStore};
use std::io;
use std::path::Path;
use tracing::warn;
use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows::Win32::Security::*;

/// SYSTEM and admins write, users only read, so no one else can plant a CA for node.
const DATA_DIR_ACL: &str = concat!(
    "O:BA",               // owner: Administrators
    "D:P",                // protected: ignore ProgramData's rules, which let any user create files
    "(A;OICI;FA;;;SY)",   // allow SYSTEM full control, inherited by files (OI) and subfolders (CI)
    "(A;OICI;FA;;;BA)",   // allow Administrators full control
    "(A;OICI;FRFX;;;BU)", // allow Users read and execute only
);

/// Trusted machine-wide so restarts keep it; replaced if the hosts change.
pub fn load_or_create_ca(
    hosts: &[&str],
    signer: &dyn SigningKey,
) -> Result<CertificateAuthority, BoxError> {
    let stored = read_registry_string(REGISTRY_KEY, "ca")?;
    let ca = match stored.and_then(|blob| CertificateAuthority::from_blob(&blob, hosts, signer)) {
        Some(ca) => ca,
        None => {
            warn!(?hosts, "minting a new CA");
            let ca = CertificateAuthority::generate(hosts, signer)?;
            LOCAL_MACHINE
                .create(REGISTRY_KEY)?
                .set_string("ca", ca.to_blob(hosts))?;
            ca
        }
    };
    // Idempotent, and the registry value can outlive the certificate.
    let der = ca.crt.to_der()?;
    let mut store = CertStore::open_local_machine("Root")?;
    store.add_cert(&CertContext::new(&der)?, CertAdd::ReplaceExisting)?;
    remove_our_cas_except(Some(&der))?;
    // For clients that read no trust store; screening still works for the rest if this fails.
    let exported = secure_data_dir().and_then(|dir| std::fs::write(dir.join("ca.pem"), &ca.pem));
    if let Err(error) = exported {
        warn!(%error, "could not export the CA");
    }
    Ok(ca)
}

/// Created on first use, its owner and ACL reset every time. One a user made first, or a link,
/// is replaced: its owner could grant itself access again, and a link would redirect our writes.
pub(super) fn secure_data_dir() -> io::Result<PathBuf> {
    let dir = data_dir();
    match std::fs::symlink_metadata(&dir) {
        Ok(meta) if meta.file_type().is_symlink() => std::fs::remove_dir(&dir)?,
        Ok(_) if !owned_by_admins(&dir)? => {
            warn!(dir = %dir.display(), "replacing a data folder not created by an admin");
            std::fs::remove_dir_all(&dir)?
        }
        _ => {}
    }
    std::fs::create_dir_all(&dir)?;
    let info = OWNER_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION
        | PROTECTED_DACL_SECURITY_INFORMATION;
    let path = HSTRING::from(dir.as_path());
    let acl = security_descriptor(DATA_DIR_ACL)?;
    unsafe { SetFileSecurityW(&path, info, PSECURITY_DESCRIPTOR(acl.0)).ok()? };
    Ok(dir)
}

/// By SYSTEM or the Administrators group, as what an elevated process creates is.
fn owned_by_admins(path: &Path) -> windows::core::Result<bool> {
    let (mut owner, mut descriptor) = (PSID::default(), PSECURITY_DESCRIPTOR::default());
    unsafe {
        GetNamedSecurityInfoW(
            &HSTRING::from(path),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            &mut descriptor,
        )
        .ok()?
    };
    let admins = [WinBuiltinAdministratorsSid, WinLocalSystemSid];
    let owned = admins
        .into_iter()
        .any(|sid| unsafe { IsWellKnownSid(owner, sid) }.as_bool());
    // `owner` points into the descriptor, so it is freed last.
    unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    Ok(owned)
}

/// Drops every CA of ours from LocalMachine\Root but `keep`.
pub(super) fn remove_our_cas_except(keep: Option<&[u8]>) -> Result<(), BoxError> {
    for cert in CertStore::open_local_machine("Root")?.certs() {
        if keep != Some(cert.to_der()) && is_our_ca(cert.to_der()) {
            cert.delete()?;
        }
    }
    Ok(())
}

fn is_our_ca(der: &[u8]) -> bool {
    let Ok(crt) = X509::from_der(der) else {
        return false;
    };
    let name = |nid| {
        let entry = crt.subject_name().entries_by_nid(nid).next()?;
        Some(entry.data().as_utf8().ok()?.to_string())
    };
    name(Nid::COMMONNAME).as_deref() == Some(COMMON_NAME)
        && name(Nid::ORGANIZATIONNAME).as_deref() == Some(ORGANIZATION)
}
