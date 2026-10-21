use rama::error::BoxError;
use rama::tls::boring::core::x509::X509;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DistinguishedName,
    DnType, GeneralSubtree, IsCa, Issuer, KeyIdMethod, KeyUsagePurpose, NameConstraints,
    SerialNumber, SigningKey,
};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

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

    /// The first certificate is the CA; any after it are its chain, for clients that read no keychain.
    pub fn new(pem: String) -> Result<Self, BoxError> {
        Ok(Self { crt: X509::from_pem(pem.as_bytes())?, pem })
    }
}

/// Empty, for verifiers that fail closed without one, such as schannel under cargo.
/// Signed fresh for each fetch; a week's validity outlasts any verifier's cache.
pub fn crl(hosts: &[&str], signer: &dyn SigningKey) -> Result<Vec<u8>, BoxError> {
    let now = OffsetDateTime::now_utc();
    let list = CertificateRevocationListParams {
        this_update: now - Duration::hours(1),
        next_update: now + Duration::days(7),
        crl_number: SerialNumber::from(now.unix_timestamp() as u64),
        issuing_distribution_point: None,
        revoked_certs: Vec::new(),
        key_identifier_method: KeyIdMethod::Sha256,
    };
    let ca = params(hosts);
    Ok(list.signed_by(&Issuer::from_params(&ca, signer))?.der().to_vec())
}

pub const COMMON_NAME: &str = "Strix Firewall";
/// Of a CA an MDM enrolls instead, which must not match `COMMON_NAME`: uninstall deletes those.
pub const MANAGED_COMMON_NAME: &str = "Strix Firewall Managed";

fn params(hosts: &[&str]) -> CertificateParams {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, COMMON_NAME);
    name.push(DnType::OrganizationName, "Strix");

    let mut params = CertificateParams::default();
    params.distinguished_name = name;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    // rcgen signs a CRL only for a CA that may.
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: hosts
            .iter()
            .map(|h| GeneralSubtree::DnsName((*h).to_owned()))
            .collect(),
        excluded_subtrees: Vec::new(),
    });
    params
}
