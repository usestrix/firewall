use rama::error::BoxError;
use rama::tls::boring::core::pkey::{PKey, Private};
use rama::tls::boring::core::x509::X509;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, GeneralSubtree, IsCa, KeyPair,
    KeyUsagePurpose, NameConstraints, PKCS_ECDSA_P256_SHA256,
};

/// Minted on the device; the key never leaves it and never ships with us.
pub struct CertificateAuthority {
    pub crt: X509,
    pub key: PKey<Private>,
    /// What the installer hands to each package manager.
    pub pem: String,
    key_pem: String,
    /// The screened hosts, comma-joined, exactly as `to_blob` writes them.
    hosts: String,
}

impl CertificateAuthority {
    /// Mint a CA that can only sign for `hosts`. The name constraint is critical, so a
    /// verifier that cannot enforce it rejects the chain instead of ignoring the limit.
    pub fn generate(hosts: &[&str]) -> Result<Self, BoxError> {
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

        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let key_pem = key.serialize_pem();
        let pem = params.self_signed(&key)?.pem();
        Self::from_pems(key_pem, pem, hosts.join(","))
    }

    /// Keychain form: the screened hosts, then the key and certificate PEMs.
    pub fn to_blob(&self) -> String {
        format!("{}\n{}{}", self.hosts, self.key_pem, self.pem)
    }

    /// Rejects a stored CA whose name constraints no longer cover exactly `hosts`.
    pub fn from_blob(blob: &str, hosts: &[&str]) -> Option<Self> {
        let (stored, pems) = blob.split_once('\n')?;
        if stored != hosts.join(",") {
            return None;
        }
        let (key_pem, pem) = pems.split_at(pems.find("-----BEGIN CERTIFICATE-----")?);
        Self::from_pems(key_pem.to_owned(), pem.to_owned(), stored.to_owned()).ok()
    }

    fn from_pems(key_pem: String, pem: String, hosts: String) -> Result<Self, BoxError> {
        Ok(Self {
            crt: X509::from_pem(pem.as_bytes())?,
            key: PKey::private_key_from_pem(key_pem.as_bytes())?,
            pem,
            key_pem,
            hosts,
        })
    }
}
