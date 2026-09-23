use firewall::mitm;
use rcgen::KeyPair;

/// Off macOS the key is simply held in memory; where it lives is the caller's business.
fn signer() -> KeyPair {
    KeyPair::generate().expect("generate a key")
}

/// The name constraint is what scopes a machine-wide trust anchor, and only if critical.
#[test]
fn minted_ca_is_name_constrained() {
    let hosts = ["registry.npmjs.org", "pypi.org"];
    let ca = mitm::CertificateAuthority::generate(&hosts, &signer()).expect("mint a ca");

    let der = ca.crt.to_der().expect("re-encode the certificate");
    // SEQUENCE { OID 2.5.29.30, BOOLEAN TRUE, ... }
    let critical_name_constraints = [0x06, 0x03, 0x55, 0x1d, 0x1e, 0x01, 0x01, 0xff];
    assert!(der.windows(8).any(|w| w == critical_name_constraints));

    for host in hosts {
        assert!(der.windows(host.len()).any(|w| w == host.as_bytes()), "{host} missing");
    }
}

/// A stored CA must survive a restart, but never be reused for a different host set.
#[test]
fn stored_ca_round_trips_and_rejects_a_changed_host_set() {
    let hosts = ["registry.npmjs.org", "pypi.org"];
    let signer = signer();
    let ca = mitm::CertificateAuthority::generate(&hosts, &signer);
    let blob = ca.expect("mint a ca").to_blob();

    let restored = mitm::CertificateAuthority::from_blob(&blob, &hosts, &signer);
    assert_eq!(restored.expect("restore the ca").to_blob(), blob);
    assert!(mitm::CertificateAuthority::from_blob(&blob, &["npmjs.org"], &signer).is_none());
}

/// The stored certificate names a public key; a signer holding a different one would
/// issue leaves that chain to nothing.
#[test]
fn stored_ca_is_rejected_when_the_signing_key_changed() {
    let hosts = ["registry.npmjs.org", "pypi.org"];
    let ca = mitm::CertificateAuthority::generate(&hosts, &signer());
    let blob = ca.expect("mint a ca").to_blob();

    assert!(mitm::CertificateAuthority::from_blob(&blob, &hosts, &signer()).is_none());
}
