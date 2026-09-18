pub mod filters;
pub mod registries;

pub use registries::Package;

use crate::Config;
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

pub async fn decide(request_target: &str, cfg: &Config) -> Decision {
    let path = request_target.split_once('?').map_or(request_target, |(path, _)| path);
    let Some((registry, rest)) = registries::match_path(path) else {
        return Decision::Unroutable;
    };

    let resolved = registries::resolve(registry, rest);
    let target = Target {
        eco: registry.eco,
        upstream: format!("{}{}", registry.upstream, rest),
        rewrite: resolved.rewrite.map(|(from, to)| (from.to_string(), cfg.local_url(to))),
    };

    let eco = registry.eco;
    let check = match resolved.pkg {
        None => Check::NoPackage,
        Some(pkg) => match consult(registry, &pkg).await {
            None => Check::Allowed(pkg),
            Some((filter, Verdict::Deny(reason))) => {
                return Decision::Block { eco, pkg, filter, reason }
            }
            Some((filter, Verdict::Unknown(e))) if !cfg.fail_open => {
                let reason = format!("could not be checked by {filter} ({e})");
                return Decision::Block { eco, pkg, filter, reason };
            }
            Some((filter, Verdict::Unknown(error))) => Check::Unverified { pkg, filter, error },
            Some((_, Verdict::Allow)) => Check::Allowed(pkg),
        },
    };

    Decision::Allow { target, check }
}

/// The alias path sees upstream URLs, so registries match on where they point, not our prefix.
pub async fn screen(url: &str) -> Option<String> {
    let (registry, rest) = registries::match_upstream(url)?;
    let pkg = registries::resolve(registry, rest).pkg?;
    match consult(registry, &pkg).await {
        Some((_, Verdict::Deny(reason))) => {
            Some(format!("{} {} {reason}", registry.eco, pkg.label()))
        }
        _ => None,
    }
}
