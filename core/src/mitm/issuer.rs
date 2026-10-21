use super::ca::CaSigner;
use rama::error::BoxError;
use rama::tls::boring::core::pkey::PKey;
use rama::tls::boring::core::x509::X509;
use rama::tls::boring::proxy::cert_issuer::{BoringMitmCertIssuer, MitmIssuedCert};
use rama::utils::collections::non_empty_vec;
use rcgen::{CertificateParams, CrlDistributionPoint, DistinguishedName, DnType, Issuer, KeyPair};

/// Leaves name only screened hosts; any other name falls outside the CA's constraint.
#[derive(Clone)]
pub struct ConstrainedCertIssuer {
    ca_crt: X509,
    signer: CaSigner,
    hosts: Vec<&'static str>,
    crl: Option<String>,
}

impl ConstrainedCertIssuer {
    pub(super) fn new(
        ca_crt: X509,
        signer: CaSigner,
        hosts: Vec<&'static str>,
        crl: Option<String>,
    ) -> Self {
        Self { ca_crt, signer, hosts, crl }
    }
}

impl BoringMitmCertIssuer for ConstrainedCertIssuer {
    type Error = BoxError;

    async fn issue_mitm_x509_cert(&self, original: X509) -> Result<MitmIssuedCert, Self::Error> {
        let names: Vec<String> = self
            .hosts
            .iter()
            .filter(|host| original.check_host(host).unwrap_or(false))
            .map(|host| (*host).to_owned())
            .collect();

        let Some(common_name) = names.first().cloned() else {
            return Err("origin covers no screened host".into());
        };

        let mut subject = DistinguishedName::new();
        subject.push(DnType::CommonName, common_name);
        let mut leaf = CertificateParams::new(names)?;
        leaf.distinguished_name = subject;
        if let Some(crl) = &self.crl {
            leaf.crl_distribution_points = vec![CrlDistributionPoint { uris: vec![crl.clone()] }];
        }

        // The TLS server needs the leaf key in memory, so it can't be the platform key.
        let leaf_key = KeyPair::generate()?;
        let ca_der = self.ca_crt.to_der()?;
        let issuer = Issuer::from_ca_cert_der(&ca_der.into(), &*self.signer)?;
        let crt = X509::from_der(leaf.signed_by(&leaf_key, &issuer)?.der())?;
        let key = PKey::private_key_from_pem(leaf_key.serialize_pem().as_bytes())?;

        Ok(MitmIssuedCert {
            crt_chain: non_empty_vec![crt, self.ca_crt.clone()],
            key,
            ocsp_staple: None,
        })
    }
}
