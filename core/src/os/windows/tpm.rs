use super::wide;
use rama::error::BoxError;
use rama::tls::boring::core::bn::BigNum;
use rama::tls::boring::core::ecdsa::EcdsaSig;
use rama::tls::boring::core::sha::sha256;
use rcgen::{Error, PublicKeyData, SignatureAlgorithm, SigningKey, PKCS_ECDSA_P256_SHA256};
use std::io;
use std::ptr;
use tracing::warn;
use windows_sys::core::{HRESULT, PCWSTR};
use windows_sys::Win32::Foundation::NTE_BAD_KEYSET;
use windows_sys::Win32::Security::Cryptography::*;

const KEY_NAME: &str = "Strix Firewall CA";
/// The TPM, then software for machines without one.
const PROVIDERS: [PCWSTR; 2] = [MS_PLATFORM_CRYPTO_PROVIDER, MS_KEY_STORAGE_PROVIDER];

/// The private key never leaves the TPM, or, without one, a non-exportable machine key.
#[derive(Default)]
pub struct TpmKey {
    key: usize,
    provider: usize,
    /// The uncompressed point, which is what rcgen writes into a SubjectPublicKeyInfo.
    public: Vec<u8>,
}

// NCrypt handles may be used from any thread.
unsafe impl Send for TpmKey {}
unsafe impl Sync for TpmKey {}

impl TpmKey {
    /// A machine key, so the service and an elevated installer share it.
    pub fn load_or_create() -> Result<Self, BoxError> {
        let flags = NCRYPT_MACHINE_KEY_FLAG;
        if let Some(key) = PROVIDERS.into_iter().find_map(|p| open(p, KEY_NAME, flags).transpose()) {
            return Ok(key?);
        }
        let key = create(false, KEY_NAME, flags).or_else(|error| {
            warn!(%error, "no TPM key, falling back to a software key");
            create(true, KEY_NAME, flags)
        });
        Ok(key?)
    }

    pub fn delete() -> Result<(), BoxError> {
        for provider in PROVIDERS {
            if let Some(key) = open(provider, KEY_NAME, NCRYPT_MACHINE_KEY_FLAG)? {
                key.destroy()?;
            }
        }
        Ok(())
    }

    /// Deletes the key itself, not just this handle to it.
    fn destroy(mut self) -> io::Result<()> {
        check(unsafe { NCryptDeleteKey(std::mem::take(&mut self.key), 0) })
    }
}

impl Drop for TpmKey {
    fn drop(&mut self) {
        for handle in [self.key, self.provider].into_iter().filter(|&h| h != 0) {
            unsafe { NCryptFreeObject(handle) };
        }
    }
}

impl PublicKeyData for TpmKey {
    fn der_bytes(&self) -> &[u8] {
        &self.public
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

impl SigningKey for TpmKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let digest = sha256(msg);
        let (mut raw, mut len) = ([0u8; 64], 0);
        let flags = NCRYPT_SILENT_FLAG;
        check(unsafe {
            NCryptSignHash(self.key, ptr::null(), digest.as_ptr(), 32, raw.as_mut_ptr(), 64, &mut len, flags)
        })
        .map_err(|_| Error::RemoteKeyError)?;
        // NCrypt returns r || s; an X.509 signature holds DER SEQUENCE { r, s }.
        let (r, s) = raw[..len as usize].split_at(len as usize / 2);
        let sig = BigNum::from_slice(r)
            .and_then(|r| EcdsaSig::from_private_components(r, BigNum::from_slice(s)?))
            .and_then(|sig| sig.to_der());
        sig.map_err(|_| Error::RemoteKeyError)
    }
}

/// `None` if the provider is absent or holds no such key.
fn open(provider: PCWSTR, name: &str, flags: u32) -> io::Result<Option<TpmKey>> {
    let mut key = TpmKey::default();
    if check(unsafe { NCryptOpenStorageProvider(&mut key.provider, provider, 0) }).is_err() {
        return Ok(None);
    }
    let name = wide(name);
    match unsafe { NCryptOpenKey(key.provider, &mut key.key, name.as_ptr(), 0, flags | NCRYPT_SILENT_FLAG) } {
        NTE_BAD_KEYSET => Ok(None),
        status => {
            check(status)?;
            key.public = public_point(key.key)?;
            Ok(Some(key))
        }
    }
}

fn create(software: bool, name: &str, flags: u32) -> io::Result<TpmKey> {
    let mut key = TpmKey::default();
    check(unsafe { NCryptOpenStorageProvider(&mut key.provider, PROVIDERS[software as usize], 0) })?;
    let (algorithm, name) = (NCRYPT_ECDSA_P256_ALGORITHM, wide(name));
    check(unsafe { NCryptCreatePersistedKey(key.provider, &mut key.key, algorithm, name.as_ptr(), 0, flags) })?;
    // TPM keys cannot be exported at all; a software key must be told not to allow it.
    if software {
        let policy = 0u32.to_ne_bytes();
        check(unsafe {
            NCryptSetProperty(key.key, NCRYPT_EXPORT_POLICY_PROPERTY, policy.as_ptr(), 4, NCRYPT_PERSIST_FLAG)
        })?;
    }
    check(unsafe { NCryptFinalizeKey(key.key, NCRYPT_SILENT_FLAG) })?;
    key.public = public_point(key.key)?;
    Ok(key)
}

/// 0x04 || X || Y, from a BCRYPT_ECCKEY_BLOB header followed by X and Y.
fn public_point(key: usize) -> io::Result<Vec<u8>> {
    let (mut blob, mut len) = ([0u8; 8 + 64], 0);
    let format = BCRYPT_ECCPUBLIC_BLOB;
    check(unsafe { NCryptExportKey(key, 0, format, ptr::null(), blob.as_mut_ptr(), 72, &mut len, 0) })?;
    if blob[..4] != BCRYPT_ECDSA_PUBLIC_P256_MAGIC.to_le_bytes() || len != 72 {
        return Err(io::Error::other("key is not an ECDSA P-256 key"));
    }
    Ok([&[0x04], &blob[8..]].concat())
}

fn check(status: HRESULT) -> io::Result<()> {
    match status {
        0 => Ok(()),
        status => Err(io::Error::from_raw_os_error(status)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mitm::CertificateAuthority;

    /// Per-user keys; the TPM one is skipped on machines without a TPM.
    #[test]
    fn keys_sign_a_verifiable_ca() {
        for software in [true, false] {
            let name = format!("Strix Firewall test {:016x}", rand::random::<u64>());
            let key = match create(software, &name, 0) {
                Ok(key) => key,
                Err(error) if !software => return eprintln!("skipping, no TPM key: {error}"),
                Err(error) => panic!("create a software key: {error}"),
            };
            let ca = CertificateAuthority::generate(&["registry.npmjs.org"], &key);
            let spki = key.subject_public_key_info();
            key.destroy().expect("delete the test key");
            let ca = ca.expect("mint a ca");
            let public = ca.crt.public_key().expect("ca public key");
            assert!(ca.crt.verify(&public).expect("verify the ca"));
            assert_eq!(public.public_key_to_der().unwrap(), spki);
        }
    }
}
