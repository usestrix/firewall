use rama::error::BoxError;
use rama::tls::boring::core::x509::X509;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, GeneralSubtree, IsCa,
    KeyUsagePurpose, NameConstraints, SigningKey,
};
use std::sync::Arc;

/// Signs the CA and every leaf under it. Where the key lives is the platform's
/// business: the Secure Enclave on macOS, memory anywhere else.
pub type CaSigner = Arc<dyn SigningKey + Send + Sync>;

/// The private half never leaves whatever holds it; only `pem` is ever handed out.
pub struct CertificateAuthority {
    pub crt: X509,
    /// What the installer hands to each package manager.
    pub pem: String,
    /// The screened hosts, comma-joined, exactly as `to_blob` writes them.
    hosts: String,
}

impl CertificateAuthority {
    /// Mint a CA that can only sign for `hosts`. The name constraint is critical, so a
    /// verifier that cannot enforce it rejects the chain instead of ignoring the limit.
    pub fn generate(hosts: &[&str], signer: &dyn SigningKey) -> Result<Self, BoxError> {
        let pem = params(hosts).self_signed(&signer)?.pem();
        Self::new(pem, hosts.join(","))
    }

    /// Keychain form: the screened hosts, then the certificate. No key, so this is
    /// only as sensitive as the certificate everyone already trusts.
    pub fn to_blob(&self) -> String {
        format!("{}\n{}", self.hosts, self.pem)
    }

    /// Rejects a stored CA whose name constraints no longer cover exactly `hosts`.
    pub fn from_blob(blob: &str, hosts: &[&str], signer: &dyn SigningKey) -> Option<Self> {
        let (stored, pem) = blob.split_once('\n')?;
        if stored != hosts.join(",") {
            return None;
        }
        let ca = Self::new(pem.to_owned(), stored.to_owned()).ok()?;
        // A certificate the signer cannot sign for issues leaves nothing will chain to.
        let held = ca.crt.public_key().ok()?.public_key_to_der().ok()?;
        (held == signer.subject_public_key_info()).then_some(ca)
    }

    fn new(pem: String, hosts: String) -> Result<Self, BoxError> {
        Ok(Self { crt: X509::from_pem(pem.as_bytes())?, pem, hosts })
    }
}

/// Shared by minting and by issuing, which needs the same subject and key usages
/// to name itself as the issuer.
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
