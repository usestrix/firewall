pub mod denylist;
pub mod osv;

use super::registries::{Package, Registry};
use crate::state::FirewallState;
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
    fn allow<'a>(
        &'a self,
        state: &'a FirewallState,
        registry: &'static Registry,
        pkg: &'a Package,
    ) -> Answer<'a>;
}

pub static FILTERS: &[&dyn Filter] = &[&denylist::Denylist, &osv::Osv];

/// Asks every filter. A `Deny` wins; failing that, the first filter that could not tell.
pub async fn consult(
    state: &FirewallState,
    registry: &'static Registry,
    pkg: &Package,
) -> Option<(&'static str, Verdict)> {
    let mut unsure = None;
    for filter in FILTERS {
        match filter.allow(state, registry, pkg).await {
            Verdict::Allow => continue,
            Verdict::Deny(reason) => return Some((filter.name(), Verdict::Deny(reason))),
            unknown if unsure.is_none() => unsure = Some((filter.name(), unknown)),
            _ => continue,
        }
    }
    unsure
}
