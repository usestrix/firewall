use firewall::mitm;

/// The name constraint is what scopes a machine-wide trust anchor, and only if critical.
#[test]
fn minted_ca_is_name_constrained() {
    let hosts = ["registry.npmjs.org", "pypi.org"];
    let ca = mitm::CertificateAuthority::generate(&hosts).expect("mint a ca");

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
    let blob = mitm::CertificateAuthority::generate(&hosts).expect("mint a ca").to_blob();

    let restored = mitm::CertificateAuthority::from_blob(&blob, &hosts).expect("restore the ca");
    assert_eq!(restored.to_blob(), blob);
    assert!(mitm::CertificateAuthority::from_blob(&blob, &["registry.npmjs.org"]).is_none());
}
