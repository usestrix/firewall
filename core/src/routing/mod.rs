pub mod osv;
pub mod registries;

pub use registries::Package;

use crate::Config;
use osv::Verdict;

pub struct Target {
    pub eco: &'static str,
    pub upstream: String,
    pub rewrite: Option<(String, String)>,
}

pub enum Check {
    NoPackage,
    Clean(Package),
    Unverified(Package, String),
}

pub enum Reason {
    Malicious(Vec<String>),
    Unverified(String),
}

pub enum Decision {
    Unroutable,
    Allow { target: Target, check: Check },
    Block { eco: &'static str, pkg: Package, reason: Reason },
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

    let check = match resolved.pkg {
        None => Check::NoPackage,
        Some(pkg) => match osv::check(registry.osv, &pkg).await {
            Verdict::Clean => Check::Clean(pkg),
            Verdict::Malicious(ids) => return block(registry, pkg, Reason::Malicious(ids)),
            Verdict::Unknown(e) if !cfg.fail_open => {
                return block(registry, pkg, Reason::Unverified(e))
            }
            Verdict::Unknown(e) => Check::Unverified(pkg, e),
        },
    };

    Decision::Allow { target, check }
}

/// The alias path sees upstream URLs, so registries match on where they point, not our prefix.
pub async fn screen(url: &str) -> Option<String> {
    let (registry, rest) = registries::match_upstream(url)?;
    let pkg = registries::resolve(registry, rest).pkg?;
    match osv::check(registry.osv, &pkg).await {
        Verdict::Malicious(ids) => Some(format!(
            "{} {} is flagged malicious ({})",
            registry.eco,
            pkg.label(),
            ids.join(", ")
        )),
        _ => None,
    }
}

fn block(registry: &'static registries::Registry, pkg: Package, reason: Reason) -> Decision {
    Decision::Block { eco: registry.osv, pkg, reason }
}
