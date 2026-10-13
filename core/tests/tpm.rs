#![cfg(windows)]

use firewall::mitm::CertificateAuthority;
use firewall::os::windows::CaKey;
use rcgen::PublicKeyData;

/// The TPM key is skipped on machines without a TPM.
#[test]
fn keys_sign_a_verifiable_ca() {
    for software in [true, false] {
        let key = match CaKey::create_test_key(software) {
            Ok(key) => key,
            Err(error) if !software => return eprintln!("skipping, no TPM key: {error}"),
            Err(error) => panic!("create a software key: {error}"),
        };
        let ca = CertificateAuthority::generate(&["registry.npmjs.org"], &key);
        let spki = key.subject_public_key_info();
        key.delete_from_tpm().expect("delete the test key");
        let ca = ca.expect("mint a ca");
        let public = ca.crt.public_key().expect("ca public key");
        assert!(ca.crt.verify(&public).expect("verify the ca"));
        assert_eq!(public.public_key_to_der().unwrap(), spki);
    }
}
