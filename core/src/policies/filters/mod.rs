pub mod age;
pub mod denylist;
pub mod org;
pub mod osv;

use super::registries::{Package, Registry};
use crate::config::AllowedPackage;
use crate::Firewall;
use std::future::Future;
use std::pin::Pin;

/// Some registry APIs turn away requests without a user agent.
pub(crate) const AGENT: &str = "strix-firewall";

pub type VerdictFuture<'a> = Pin<Box<dyn Future<Output = Verdict> + Send + 'a>>;

/// `Unknown` means the filter could not check the package.
pub enum Verdict {
    Allow,
    Deny(String),
    Unknown(String),
}

pub trait Filter: Send + Sync {
    fn name(&self) -> &'static str;
    fn check<'a>(&'a self, registry: &'static Registry, pkg: &'a Package) -> VerdictFuture<'a>;
}

/// Asks every filter. A `Deny` wins; failing that, the first filter that could not tell.
/// An allowed package skips only the age check, so malware is never let through.
pub async fn consult(
    firewall: &Firewall,
    registry: &'static Registry,
    pkg: &Package,
) -> Option<(&'static str, Verdict)> {
    let lifted = allowed(firewall, registry, pkg)
        || firewall.age_check_lifted(registry.eco, |entry| matches_entry(registry, pkg, entry));
    let mut unsure = None;
    for filter in firewall.filters() {
        if lifted && filter.name() == "age" {
            continue;
        }
        match filter.check(registry, pkg).await {
            Verdict::Allow => continue,
            Verdict::Deny(reason) => return Some((filter.name(), Verdict::Deny(reason))),
            unknown if unsure.is_none() => unsure = Some((filter.name(), unknown)),
            _ => continue,
        }
    }
    unsure
}

fn allowed(firewall: &Firewall, registry: &Registry, pkg: &Package) -> bool {
    let Some(entries) = firewall.config.allow.get(registry.eco) else {
        return false;
    };
    entries.iter().any(|entry| matches_entry(registry, pkg, entry))
}

fn matches_entry(registry: &Registry, pkg: &Package, entry: &AllowedPackage) -> bool {
    matches(registry, pkg, &entry.name, entry.version.as_deref())
}

/// A missing version matches every version.
fn matches(registry: &Registry, pkg: &Package, name: &str, version: Option<&str>) -> bool {
    let name_matches = match registry.normalize {
        Some(normalize) => normalize(name) == pkg.name,
        None => name == pkg.name,
    };
    // Go writes a leading v that the parsed version drops, and PEP 440 ignores one.
    let version = version.map(|v| v.strip_prefix('v').unwrap_or(v));
    name_matches && (version.is_none() || version == pkg.version.as_deref())
}
