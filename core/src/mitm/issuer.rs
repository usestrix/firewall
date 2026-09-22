use rama::crypto::cert::boring::issue_leaf_certificate;
use rama::crypto::cert::{
    CertificateIdentity, CertificateSubject, LeafCertConfig, LeafCertRequest,
};
use rama::error::BoxError;
use rama::net::address::Domain;
use rama::tls::boring::core::pkey::{PKey, Private};
use rama::tls::boring::core::x509::X509;
use rama::tls::boring::proxy::cert_issuer::{BoringMitmCertIssuer, MitmIssuedCert};
use rama::utils::collections::non_empty_vec;

/// Issues leaves naming only the screened hosts the origin covers. Mirroring the
/// origin's own names instead asserts names outside the CA's permitted subtrees,
/// which every verifier rejects.
#[derive(Clone)]
pub struct ConstrainedCertIssuer {
    ca_crt: X509,
    ca_key: PKey<Private>,
    hosts: Vec<&'static str>,
}

impl ConstrainedCertIssuer {
    pub(super) fn new(ca_crt: X509, ca_key: PKey<Private>, hosts: Vec<&'static str>) -> Self {
        Self { ca_crt, ca_key, hosts }
    }
}

impl BoringMitmCertIssuer for ConstrainedCertIssuer {
    type Error = BoxError;

    async fn issue_mitm_x509_cert(&self, original: X509) -> Result<MitmIssuedCert, Self::Error> {
        let identities: Vec<_> = self
            .hosts
            .iter()
            .copied()
            .filter(|host| original.check_host(host).unwrap_or(false))
            .map(|host| CertificateIdentity::Dns(Domain::from_static(host)))
            .collect();

        let Some(CertificateIdentity::Dns(domain)) = identities.first() else {
            return Err("origin covers no screened host".into());
        };
        let subject =
            CertificateSubject { common_name: Some(domain.to_string()), organisation_name: None };
        let request = LeafCertRequest {
            config: LeafCertConfig { subject, ..Default::default() },
            identities,
        };

        let (crt, key) = issue_leaf_certificate(&request, &self.ca_crt, &self.ca_key)?;
        Ok(MitmIssuedCert {
            crt_chain: non_empty_vec![crt, self.ca_crt.clone()],
            key,
            ocsp_staple: None,
        })
    }
}
