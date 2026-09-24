pub mod filters;
pub mod registries;

pub use registries::Package;

use crate::Firewall;
use filters::{consult, Verdict};
use tracing::info;

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

pub async fn decide(request_target: &str, firewall: &Firewall) -> Decision {
    let path = request_target.split_once('?').map_or(request_target, |(path, _)| path);
    let Some((registry, rest)) = firewall.match_on(path, |r| r.prefix) else {
        return Decision::Unroutable;
    };

    let resolved = firewall.resolve(registry, rest);
    let target = Target {
        eco: registry.eco,
        upstream: format!("{}{}", registry.upstream, rest),
        rewrite: resolved
            .rewrite
            .map(|(from, to)| (from.to_string(), firewall.config.local_url(to))),
    };

    let eco = registry.eco;
    let check = match resolved.pkg {
        None => Check::NoPackage,
        Some(pkg) => match consult(firewall, registry, &pkg).await {
            None => Check::Allowed(pkg),
            Some((filter, Verdict::Deny(reason))) => {
                return Decision::Block { eco, pkg, filter, reason }
            }
            Some((filter, Verdict::Unknown(e))) if !firewall.config.fail_open => {
                let reason = format!("could not be checked by {filter} ({e})");
                return Decision::Block { eco, pkg, filter, reason };
            }
            Some((filter, Verdict::Unknown(error))) => Check::Unverified { pkg, filter, error },
            Some((_, Verdict::Allow)) => Check::Allowed(pkg),
        },
    };

    Decision::Allow { target, check }
}

pub async fn screen(url: &str, firewall: &Firewall) -> Option<String> {
    let path = url.split_once('?').map_or(url, |(path, _)| path);
    let (registry, rest) = firewall.match_on(path, |r| r.upstream)?;
    let Some(pkg) = firewall.resolve(registry, rest).pkg else {
        info!(eco = registry.eco, %url, "no pattern names a package here");
        return None;
    };
    info!(eco = registry.eco, pkg = %pkg.label(), %url, "screening");
    match consult(firewall, registry, &pkg).await {
        Some((_, Verdict::Deny(reason))) => {
            Some(format!("{} {reason}", pkg.label()))
        }
        _ => None,
    }
}
