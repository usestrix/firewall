use super::*;
use crate::mitm::{CertificateAuthority, COMMON_NAME, ORGANIZATION};
use rama::tls::boring::core::nid::Nid;
use rama::tls::boring::core::x509::X509;
use rcgen::SigningKey;
use std::io;
use tracing::warn;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::*;
use windows_sys::Win32::Security::Cryptography::*;
use windows_sys::Win32::Security::*;

/// SYSTEM and admins write, users only read, so no one else can plant a CA for node.
const DATA_DIR_ACL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)";

/// Trusted machine-wide so restarts keep it; replaced if the hosts change.
pub fn certificate_authority(
    hosts: &[&str],
    signer: &dyn SigningKey,
) -> Result<CertificateAuthority, BoxError> {
    let stored = registry_get(REGISTRY_KEY, "ca")?;
    let ca = match stored.and_then(|blob| CertificateAuthority::from_blob(&blob, hosts, signer)) {
        Some(ca) => ca,
        None => {
            warn!(?hosts, "minting a new CA");
            let ca = CertificateAuthority::generate(hosts, signer)?;
            LOCAL_MACHINE.create(REGISTRY_KEY)?.set_string("ca", ca.to_blob(hosts))?;
            ca
        }
    };
    // Idempotent, and the registry value can outlive the certificate.
    let der = ca.crt.to_der()?;
    let store = RootStore::open()?;
    let (encoding, flags) = (X509_ASN_ENCODING, CERT_STORE_ADD_REPLACE_EXISTING);
    let len = der.len() as u32;
    let added = unsafe {
        CertAddEncodedCertificateToStore(store.0, encoding, der.as_ptr(), len, flags, ptr::null_mut())
    };
    if added == 0 {
        return Err(io::Error::last_os_error().into());
    }
    distrust(Some(&der))?;
    // For clients that read no trust store; screening still works for the rest if this fails.
    if let Err(error) = data_dir_ready().and_then(|dir| std::fs::write(dir.join("ca.pem"), &ca.pem)) {
        warn!(%error, "could not export the CA");
    }
    Ok(ca)
}

/// LocalMachine\Root, closed on drop.
struct RootStore(HCERTSTORE);

impl RootStore {
    fn open() -> io::Result<Self> {
        let flags = CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG;
        let name = wide("ROOT");
        let store = unsafe { CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, flags, name.as_ptr().cast()) };
        match store.is_null() {
            true => Err(io::Error::last_os_error()),
            false => Ok(RootStore(store)),
        }
    }
}

impl Drop for RootStore {
    fn drop(&mut self) {
        unsafe { CertCloseStore(self.0, 0) };
    }
}

/// Created on first use, its ACL reset every time.
pub(super) fn data_dir_ready() -> io::Result<PathBuf> {
    let dir = data_dir();
    std::fs::create_dir_all(&dir)?;
    let mut acl = ptr::null_mut();
    let sddl = wide(DATA_DIR_ACL);
    let parsed = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut acl, ptr::null_mut())
    };
    if parsed == 0 {
        return Err(io::Error::last_os_error());
    }
    let info = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    let set = unsafe { SetFileSecurityW(wide(&dir.display().to_string()).as_ptr(), info, acl) };
    let error = io::Error::last_os_error();
    unsafe { LocalFree(acl) };
    if set == 0 {
        return Err(error);
    }
    Ok(dir)
}

/// Drops every CA of ours from LocalMachine\Root but `keep`.
pub(super) fn distrust(keep: Option<&[u8]>) -> Result<(), BoxError> {
    let store = RootStore::open()?;
    let mut cert = ptr::null();
    loop {
        cert = unsafe { CertEnumCertificatesInStore(store.0, cert) };
        let Some(context) = (unsafe { cert.as_ref() }) else { return Ok(()) };
        let der = unsafe { std::slice::from_raw_parts(context.pbCertEncoded, context.cbCertEncoded as usize) };
        if keep != Some(der) && is_ours(der) {
            // Deleting frees the context, which enumeration still needs, so delete a copy.
            if unsafe { CertDeleteCertificateFromStore(CertDuplicateCertificateContext(cert)) } == 0 {
                let error = io::Error::last_os_error();
                unsafe { CertFreeCertificateContext(cert) };
                return Err(error.into());
            }
        }
    }
}

fn is_ours(der: &[u8]) -> bool {
    let Ok(crt) = X509::from_der(der) else { return false };
    let name = |nid| {
        let entry = crt.subject_name().entries_by_nid(nid).next()?;
        Some(entry.data().as_utf8().ok()?.to_string())
    };
    name(Nid::COMMONNAME).as_deref() == Some(COMMON_NAME)
        && name(Nid::ORGANIZATIONNAME).as_deref() == Some(ORGANIZATION)
}
