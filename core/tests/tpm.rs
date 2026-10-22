#![cfg(windows)]

use firewall::mitm::CertificateAuthority;
use firewall::os::windows::CaKey;
use rcgen::PublicKeyData;

/// Skipped on machines without a TPM.
#[test]
fn key_signs_a_verifiable_ca() {
    let key = match CaKey::create_test_key() {
        Ok(key) => key,
        Err(error) => return eprintln!("skipping, no TPM key: {error}"),
    };
    let ca = CertificateAuthority::generate(&["registry.npmjs.org"], &key);
    let spki = key.subject_public_key_info();
    key.delete_from_tpm().expect("delete the test key");
    let ca = ca.expect("mint a ca");
    let public = ca.crt.public_key().expect("ca public key");
    assert!(ca.crt.verify(&public).expect("verify the ca"));
    assert_eq!(public.public_key_to_der().unwrap(), spki);
}
