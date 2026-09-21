pub mod filters;
pub mod registries;

pub use registries::Package;

use crate::state::FirewallState;
use filters::{consult, Verdict};

pub struct Target {
    pub eco: &'static str,
    pub upstream: String,
    pub rewrite: Option<(String, String)>,
}

pub enum Check {
    NoPackage,
    Allowed(Package),
    Unverified { pkg: Package, filter: &'static str, error: String },
}

pub enum Decision {
    Unroutable,
    Allow { target: Target, check: Check },
    Block { eco: &'static str, pkg: Package, filter: &'static str, reason: String },
}

pub async fn decide(request_target: &str, state: &FirewallState) -> Decision {
    let path = request_target.split_once('?').map_or(request_target, |(path, _)| path);
    let Some((registry, rest)) = state.match_path(path) else {
        return Decision::Unroutable;
    };

    let resolved = state.resolve(registry, rest);
    let target = Target {
        eco: registry.eco,
        upstream: format!("{}{}", registry.upstream, rest),
        rewrite: resolved.rewrite.map(|(from, to)| (from.to_string(), state.config.local_url(to))),
    };

    let eco = registry.eco;
    let check = match resolved.pkg {
        None => Check::NoPackage,
        Some(pkg) => match consult(state, registry, &pkg).await {
            None => Check::Allowed(pkg),
            Some((filter, Verdict::Deny(reason))) => {
                return Decision::Block { eco, pkg, filter, reason }
            }
            Some((filter, Verdict::Unknown(e))) if !state.config.fail_open => {
                let reason = format!("could not be checked by {filter} ({e})");
                return Decision::Block { eco, pkg, filter, reason };
            }
            Some((filter, Verdict::Unknown(error))) => Check::Unverified { pkg, filter, error },
            Some((_, Verdict::Allow)) => Check::Allowed(pkg),
        },
    };

    Decision::Allow { target, check }
}

pub async fn screen(url: &str, state: &FirewallState) -> Option<String> {
    let (registry, rest) = state.match_upstream(url)?;
    let pkg = state.resolve(registry, rest).pkg?;
    match consult(state, registry, &pkg).await {
        Some((_, Verdict::Deny(reason))) => {
            Some(format!("{} {} {reason}", registry.eco, pkg.label()))
        }
        _ => None,
    }
}
