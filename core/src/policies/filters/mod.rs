mod osv;

use super::registries::{Package, Registry};
use std::future::Future;
use std::pin::Pin;

pub type Answer<'a> = Pin<Box<dyn Future<Output = Verdict> + Send + 'a>>;

/// What one filter makes of a package. `Unknown` means it could not tell.
pub enum Verdict {
    Allow,
    Deny(String),
    Unknown(String),
}

pub trait Filter: Sync {
    fn name(&self) -> &'static str;
    fn allow<'a>(&'a self, registry: &'static Registry, pkg: &'a Package) -> Answer<'a>;
}

pub static FILTERS: &[&dyn Filter] = &[&osv::Osv];

/// Asks each filter in turn and stops at the first one with something to say.
pub async fn consult(
    registry: &'static Registry,
    pkg: &Package,
) -> Option<(&'static str, Verdict)> {
    for filter in FILTERS {
        match filter.allow(registry, pkg).await {
            Verdict::Allow => continue,
            objection => return Some((filter.name(), objection)),
        }
    }
    None
}
