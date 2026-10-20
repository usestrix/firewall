use super::wide;
use rama::error::BoxError;
use rama::tls::boring::core::bn::BigNum;
use rama::tls::boring::core::ecdsa::EcdsaSig;
use rama::tls::boring::core::sha::sha256;
use rcgen::{Error, PublicKeyData, SignatureAlgorithm, SigningKey, PKCS_ECDSA_P256_SHA256};
use std::io;
use std::ptr;
use windows_sys::core::HRESULT;
use windows_sys::Win32::Foundation::NTE_BAD_KEYSET;
use windows_sys::Win32::Security::Cryptography::*;

const KEY_NAME: &str = "Strix Firewall CA";

/// The private key never leaves the TPM.
#[derive(Default)]
pub struct CaKey {
    key: usize,
    provider: usize,
    /// The uncompressed point, which is what rcgen writes into a SubjectPublicKeyInfo.
    public: Vec<u8>,
}

// NCrypt handles may be used from any thread.
unsafe impl Send for CaKey {}
unsafe impl Sync for CaKey {}

impl CaKey {
    /// A machine key, so the service and an elevated installer share it.
    pub fn load_or_create() -> Result<Self, BoxError> {
        let flags = NCRYPT_MACHINE_KEY_FLAG;
        let key = match open_tpm_key(KEY_NAME, flags)? {
            Some(key) => key,
            None => create_tpm_key(KEY_NAME, flags)?,
        };
        Ok(key)
    }

    /// A per-user key under a random name, which needs no elevation; `delete_from_tpm` it after.
    pub fn create_test_key() -> io::Result<Self> {
        create_tpm_key(&format!("Strix Firewall test {:016x}", rand::random::<u64>()), 0)
    }

    /// Deletes the key itself, not just this handle to it.
    pub fn delete_from_tpm(mut self) -> io::Result<()> {
        check(unsafe { NCryptDeleteKey(std::mem::take(&mut self.key), 0) })
    }
}

impl Drop for CaKey {
    fn drop(&mut self) {
        for handle in [self.key, self.provider].into_iter().filter(|&h| h != 0) {
            unsafe { NCryptFreeObject(handle) };
        }
    }
}

impl PublicKeyData for CaKey {
    fn der_bytes(&self) -> &[u8] {
        &self.public
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

impl SigningKey for CaKey {
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

/// `None` if the TPM holds no such key.
fn open_tpm_key(name: &str, flags: u32) -> io::Result<Option<CaKey>> {
    let mut key = CaKey::default();
    check(unsafe { NCryptOpenStorageProvider(&mut key.provider, MS_PLATFORM_CRYPTO_PROVIDER, 0) })?;
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

fn create_tpm_key(name: &str, flags: u32) -> io::Result<CaKey> {
    let mut key = CaKey::default();
    check(unsafe { NCryptOpenStorageProvider(&mut key.provider, MS_PLATFORM_CRYPTO_PROVIDER, 0) })?;
    let (algorithm, name) = (NCRYPT_ECDSA_P256_ALGORITHM, wide(name));
    check(unsafe { NCryptCreatePersistedKey(key.provider, &mut key.key, algorithm, name.as_ptr(), 0, flags) })?;
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

