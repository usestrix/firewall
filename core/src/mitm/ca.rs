use rama::error::BoxError;
use rama::tls::boring::core::x509::X509;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, GeneralSubtree, IsCa,
    KeyUsagePurpose, NameConstraints, SigningKey,
};
use std::sync::Arc;

/// Held in the Secure Enclave on macOS, in memory elsewhere.
pub type CaSigner = Arc<dyn SigningKey + Send + Sync>;

pub struct CertificateAuthority {
    pub crt: X509,
    pub pem: String,
}

impl CertificateAuthority {
    /// The name constraint is critical, so a verifier that cannot enforce it rejects the chain.
    pub fn generate(hosts: &[&str], signer: &dyn SigningKey) -> Result<Self, BoxError> {
        let pem = params(hosts).self_signed(&signer)?.pem();
        Self::new(pem)
    }

    /// Keychain form: the hosts line, then the PEM. Holds no key.
    pub fn to_blob(&self, hosts: &[&str]) -> String {
        format!("{}\n{}", hosts.join(","), self.pem)
    }

    /// `None` if the stored hosts differ from `hosts` or the certificate is for another key.
    pub fn from_blob(blob: &str, hosts: &[&str], signer: &dyn SigningKey) -> Option<Self> {
        let (stored, pem) = blob.split_once('\n')?;
        if stored != hosts.join(",") {
            return None;
        }
        let ca = Self::new(pem.to_owned()).ok()?;
        let held = ca.crt.public_key().ok()?.public_key_to_der().ok()?;
        (held == signer.subject_public_key_info()).then_some(ca)
    }

    fn new(pem: String) -> Result<Self, BoxError> {
        Ok(Self { crt: X509::from_pem(pem.as_bytes())?, pem })
    }
}

/// Also used by the issuer, whose issuer name must match the CA's subject.
pub fn params(hosts: &[&str]) -> CertificateParams {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "Strix Firewall");
    name.push(DnType::OrganizationName, "Strix");

    let mut params = CertificateParams::default();
    params.distinguished_name = name;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: hosts
            .iter()
            .map(|h| GeneralSubtree::DnsName((*h).to_owned()))
            .collect(),
        excluded_subtrees: Vec::new(),
    });
    params
}
