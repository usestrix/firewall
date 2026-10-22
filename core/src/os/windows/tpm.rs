use rama::error::BoxError;
use rama::tls::boring::core::bn::BigNum;
use rama::tls::boring::core::ecdsa::EcdsaSig;
use rama::tls::boring::core::sha::sha256;
use rcgen::{Error, PublicKeyData, SignatureAlgorithm, SigningKey, PKCS_ECDSA_P256_SHA256};
use windows::core::{Owned, Result as WinResult, HSTRING};
use windows::Win32::Foundation::{NTE_BAD_KEY, NTE_BAD_KEYSET};
use windows::Win32::Security::Cryptography::*;

const KEY_NAME: &str = "Strix Firewall CA";

/// A P-256 key held by the TPM. Signing asks the TPM to sign, so the private key never leaves it.
pub struct CaKey {
    // Fields drop in order, so the key handle closes before its provider's.
    key_handle: Owned<NCRYPT_KEY_HANDLE>,
    _provider_handle: Owned<NCRYPT_PROV_HANDLE>,
    /// 0x04 || X || Y, the form rcgen writes into a certificate's SubjectPublicKeyInfo.
    public_point: Vec<u8>,
}

impl CaKey {
    /// A machine key, so the service and an elevated installer share it.
    pub fn load_or_create() -> Result<Self, BoxError> {
        match open_key(KEY_NAME, NCRYPT_MACHINE_KEY_FLAG)? {
            Some(key) => Ok(key),
            None => Ok(create_key(KEY_NAME, NCRYPT_MACHINE_KEY_FLAG)?),
        }
    }

    pub(super) fn delete_machine_key() -> Result<(), BoxError> {
        if let Some(key) = open_key(KEY_NAME, NCRYPT_MACHINE_KEY_FLAG)? {
            key.delete_from_tpm()?;
        }
        Ok(())
    }

    /// A per-user key under a random name, which needs no elevation; `delete_from_tpm` it after.
    pub fn create_test_key() -> WinResult<Self> {
        let name = format!("Strix Firewall test {:016x}", rand::random::<u64>());
        create_key(&name, NCRYPT_FLAGS(0))
    }

    /// Deletes the key from the TPM, not just this handle to it.
    pub fn delete_from_tpm(mut self) -> WinResult<()> {
        // NCryptDeleteKey also frees the handle, so the Owned mustn't free it again.
        let key_handle = std::mem::take(&mut *self.key_handle);
        unsafe { NCryptDeleteKey(key_handle, 0) }
    }

    /// Takes both handles and reads the key's public point once, for rcgen.
    fn from_handles(
        provider_handle: Owned<NCRYPT_PROV_HANDLE>,
        key_handle: Owned<NCRYPT_KEY_HANDLE>,
    ) -> WinResult<Self> {
        // A BCRYPT_ECCKEY_BLOB header, then X and Y.
        const HEADER_LEN: usize = size_of::<BCRYPT_ECCKEY_BLOB>();
        let mut blob = [0u8; HEADER_LEN + 64];
        let mut blob_len = 0;
        unsafe {
            NCryptExportKey(
                *key_handle,
                None,
                BCRYPT_ECCPUBLIC_BLOB,
                None,
                Some(&mut blob),
                &mut blob_len,
                NCRYPT_FLAGS(0),
            )?
        };
        let (header, x_and_y) = blob.split_at(HEADER_LEN);
        let is_p256 = header[..4] == BCRYPT_ECDSA_PUBLIC_P256_MAGIC.to_le_bytes();
        if !is_p256 || blob_len as usize != blob.len() {
            return Err(windows::core::Error::new(NTE_BAD_KEY, "key is not an ECDSA P-256 key"));
        }
        let public_point = [&[0x04], x_and_y].concat();
        Ok(CaKey { key_handle, _provider_handle: provider_handle, public_point })
    }
}

impl PublicKeyData for CaKey {
    fn der_bytes(&self) -> &[u8] {
        &self.public_point
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

impl SigningKey for CaKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let mut r_and_s = [0u8; 64];
        let mut signature_len = 0;
        let signed = unsafe {
            NCryptSignHash(
                *self.key_handle,
                None,
                &sha256(msg),
                Some(&mut r_and_s),
                &mut signature_len,
                NCRYPT_SILENT_FLAG,
            )
        };
        signed.map_err(|_| Error::RemoteKeyError)?;
        // NCrypt returns r || s, each half the length; X.509 wants DER SEQUENCE { r, s }.
        let (r, s) = r_and_s[..signature_len as usize].split_at(signature_len as usize / 2);
        let der = BigNum::from_slice(r)
            .and_then(|r| EcdsaSig::from_private_components(r, BigNum::from_slice(s)?))
            .and_then(|signature| signature.to_der());
        der.map_err(|_| Error::RemoteKeyError)
    }
}

/// `None` if the TPM holds no key by that name.
/// `scope` is `NCRYPT_MACHINE_KEY_FLAG`, or empty for the current user's keys.
fn open_key(name: &str, scope: NCRYPT_FLAGS) -> WinResult<Option<CaKey>> {
    let provider_handle = open_tpm_provider()?;
    let mut key_handle = NCRYPT_KEY_HANDLE::default();
    let opened = unsafe {
        NCryptOpenKey(
            *provider_handle,
            &mut key_handle,
            &HSTRING::from(name),
            CERT_KEY_SPEC::default(), // legacy, unused by the TPM provider
            scope | NCRYPT_SILENT_FLAG,
        )
    };
    match opened {
        Err(error) if error.code() == NTE_BAD_KEYSET => Ok(None),
        Err(error) => Err(error),
        Ok(()) => CaKey::from_handles(provider_handle, unsafe { Owned::new(key_handle) }).map(Some),
    }
}

/// Generates the key inside the TPM, which never lets it out.
fn create_key(name: &str, scope: NCRYPT_FLAGS) -> WinResult<CaKey> {
    let provider_handle = open_tpm_provider()?;
    let mut key_handle = NCRYPT_KEY_HANDLE::default();
    unsafe {
        NCryptCreatePersistedKey(
            *provider_handle,
            &mut key_handle,
            NCRYPT_ECDSA_P256_ALGORITHM,
            &HSTRING::from(name),
            CERT_KEY_SPEC::default(), // legacy, unused by the TPM provider
            scope,
        )?
    };
    let key_handle = unsafe { Owned::new(key_handle) };
    // Until finalized the key is only a handle; this generates and stores it.
    unsafe { NCryptFinalizeKey(*key_handle, NCRYPT_SILENT_FLAG)? };
    CaKey::from_handles(provider_handle, key_handle)
}

/// The Microsoft Platform Crypto Provider, which keeps its keys in the TPM.
fn open_tpm_provider() -> WinResult<Owned<NCRYPT_PROV_HANDLE>> {
    let mut provider_handle = NCRYPT_PROV_HANDLE::default();
    unsafe { NCryptOpenStorageProvider(&mut provider_handle, MS_PLATFORM_CRYPTO_PROVIDER, 0)? };
    Ok(unsafe { Owned::new(provider_handle) })
}
