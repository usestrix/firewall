pub mod denylist;
pub mod osv;

use super::registries::{Package, Registry};
use crate::Firewall;
use std::future::Future;
use std::pin::Pin;

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
pub async fn consult(
    firewall: &Firewall,
    registry: &'static Registry,
    pkg: &Package,
) -> Option<(&'static str, Verdict)> {
    let mut unsure = None;
    for filter in firewall.filters() {
        match filter.check(registry, pkg).await {
            Verdict::Allow => continue,
            Verdict::Deny(reason) => return Some((filter.name(), Verdict::Deny(reason))),
            unknown if unsure.is_none() => unsure = Some((filter.name(), unknown)),
            _ => continue,
        }
    }
    unsure
}
