use super::*;
use crate::mitm::{CertificateAuthority, COMMON_NAME, ORGANIZATION};
use rama::tls::boring::core::nid::Nid;
use rama::tls::boring::core::x509::X509;
use rcgen::SigningKey;
use std::io;
use std::path::Path;
use tracing::warn;
use windows::core::w;
use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows::Win32::Security::Cryptography::*;
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
    let store = RootStore::open()?;
    unsafe {
        CertAddEncodedCertificateToStore(
            Some(store.0),
            X509_ASN_ENCODING,
            &der,
            CERT_STORE_ADD_REPLACE_EXISTING,
            None,
        )?
    };
    remove_our_cas_except(Some(&der))?;
    // For clients that read no trust store; screening still works for the rest if this fails.
    let exported = secure_data_dir().and_then(|dir| std::fs::write(dir.join("ca.pem"), &ca.pem));
    if let Err(error) = exported {
        warn!(%error, "could not export the CA");
    }
    Ok(ca)
}

/// LocalMachine\Root, closed on drop.
struct RootStore(HCERTSTORE);

impl RootStore {
    fn open() -> windows::core::Result<Self> {
        let flags =
            CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_LOCAL_MACHINE) | CERT_STORE_OPEN_EXISTING_FLAG;
        // The system provider ignores the encoding type and takes the store name as its parameter.
        let store = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                CERT_QUERY_ENCODING_TYPE(0),
                None,
                flags,
                Some(w!("ROOT").as_ptr().cast()),
            )?
        };
        Ok(RootStore(store))
    }
}

impl Drop for RootStore {
    fn drop(&mut self) {
        let _ = unsafe { CertCloseStore(Some(self.0), 0) };
    }
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
    with_security_descriptor(DATA_DIR_ACL, |acl| unsafe {
        SetFileSecurityW(&path, info, acl).ok()
    })?;
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
    let store = RootStore::open()?;
    let mut cert: *const CERT_CONTEXT = std::ptr::null();
    loop {
        // Frees the previous context.
        cert = unsafe { CertEnumCertificatesInStore(store.0, Some(cert)) };
        let Some(context) = (unsafe { cert.as_ref() }) else {
            return Ok(());
        };
        let der = unsafe {
            std::slice::from_raw_parts(context.pbCertEncoded, context.cbCertEncoded as usize)
        };
        if keep != Some(der) && is_our_ca(der) {
            // Deleting frees the context, which enumeration still needs, so delete a copy.
            let copy = unsafe { CertDuplicateCertificateContext(Some(cert)) };
            if let Err(error) = unsafe { CertDeleteCertificateFromStore(copy) } {
                let _ = unsafe { CertFreeCertificateContext(Some(cert)) };
                return Err(error.into());
            }
        }
    }
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
