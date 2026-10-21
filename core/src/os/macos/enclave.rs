use super::KEYCHAIN_SERVICE;
use core_foundation::base::TCFType;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::error::CFError;
use core_foundation::string::CFString;
use rama::error::BoxError;
use rama::net::apple::networkextension::system_keychain;
use rcgen::{Error, PublicKeyData, SignatureAlgorithm, SigningKey, PKCS_ECDSA_P256_SHA256};
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework_sys::access_control::kSecAccessControlPrivateKeyUsage;
use security_framework_sys::item::*;
use security_framework_sys::key::SecKeyCreateWithData;
use std::ptr;

const KEYCHAIN_ACCOUNT: &str = "enclave-key";
/// The token object ID: the key's blob, sealed to this Mac's enclave. Not in any SDK header.
const TOKEN_OBJECT_ID: &str = "toid";

/// The private key never leaves the Secure Enclave, so not even root can export it.
pub struct EnclaveKey {
    key: SecKey,
    /// The uncompressed point, which is what rcgen writes into a SubjectPublicKeyInfo.
    public: Vec<u8>,
}

impl EnclaveKey {
    /// A root daemon cannot keep an enclave key in either keychain, so the System
    /// keychain holds the blob instead and the key is rebuilt from it.
    pub fn load_or_create() -> Result<Self, BoxError> {
        let key = match system_keychain::load_secret(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)? {
            Some(blob) => load(&blob)?,
            None => create()?,
        };
        let public = key
            .public_key()
            .and_then(|public| public.external_representation())
            .ok_or("secure enclave key has no exportable public half")?;
        Ok(EnclaveKey { key, public: public.to_vec() })
    }

    pub fn delete() -> Result<(), BoxError> {
        Ok(system_keychain::delete_secret(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)?)
    }
}

impl PublicKeyData for EnclaveKey {
    fn der_bytes(&self) -> &[u8] {
        &self.public
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

impl SigningKey for EnclaveKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        // X962 is ASN.1 DER SEQUENCE { r, s }, which is what an X.509 signature holds.
        self.key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, msg)
            .map_err(|_| Error::RemoteKeyError)
    }
}

fn create() -> Result<SecKey, BoxError> {
    // Usable from the first unlock after boot, and only on this machine.
    let access = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
        kSecAccessControlPrivateKeyUsage,
    )?;
    let mut options = GenerateKeyOptions::default();
    options
        .set_key_type(KeyType::ec_sec_prime_random())
        .set_token(Token::SecureEnclave)
        .set_access_control(access);
    let key = SecKey::new(&options)
        .map_err(|e| format!("secure enclave key generation failed: {e}"))?;

    let blob = key
        .attributes()
        .find(CFString::from_static_string(TOKEN_OBJECT_ID).as_CFTypeRef())
        .map(|blob| unsafe { CFData::wrap_under_get_rule(*blob as _) })
        .ok_or("secure enclave key has no token object id")?;
    system_keychain::store_secret(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, &blob)?;
    Ok(key)
}

fn load(blob: &[u8]) -> Result<SecKey, BoxError> {
    let attributes = unsafe {
        CFDictionary::from_CFType_pairs(&[
            (
                CFString::wrap_under_get_rule(kSecAttrTokenID),
                CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrKeyType),
                CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrKeyClass),
                CFString::wrap_under_get_rule(kSecAttrKeyClassPrivate).into_CFType(),
            ),
            (CFString::from_static_string(TOKEN_OBJECT_ID), CFData::from_buffer(blob).into_CFType()),
        ])
    };
    let mut error = ptr::null_mut();
    let key = unsafe {
        SecKeyCreateWithData(
            CFData::from_buffer(&[]).as_concrete_TypeRef(),
            attributes.as_concrete_TypeRef(),
            &mut error,
        )
    };
    if key.is_null() {
        let error = unsafe { CFError::wrap_under_create_rule(error) };
        return Err(format!("secure enclave key could not be rebuilt: {error}").into());
    }
    Ok(unsafe { SecKey::wrap_under_create_rule(key) })
}
