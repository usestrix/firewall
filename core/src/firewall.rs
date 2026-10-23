use crate::config::{AllowedPackage, FirewallConfig};
use crate::policies::filters::age::Age;
use crate::policies::filters::denylist::Denylist;
use crate::policies::filters::osv::Osv;
use crate::policies::filters::Filter;
use crate::policies::registries::*;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

pub struct Firewall {
    pub config: FirewallConfig,
    registries: Vec<&'static Registry>,
    patterns: HashMap<&'static str, Vec<Regex>>,
    filters: Vec<Box<dyn Filter>>,
    /// Each lift expires at its time, or lasts until the firewall stops. Never saved.
    age_lifted: Mutex<Vec<(String, AllowedPackage, Option<Instant>)>>,
}

impl Default for Firewall {
    fn default() -> Self {
        Firewall::new(FirewallConfig::default())
    }
}

impl Firewall {
    pub fn new(config: FirewallConfig) -> Self {
        let registries = with_mirrors(&config.registries);
        let mut patterns = HashMap::new();
        for registry in &registries {
            let compiled = registry.patterns.iter().map(|p| Regex::new(p.re).expect(p.re));
            patterns.insert(registry.prefix, compiled.collect());
        }
        let ecosystems = registries.iter().map(|r| r.osv_name);
        let denylist = Denylist::new(config.denylist.clone(), ecosystems);
        let mut filters: Vec<Box<dyn Filter>> = vec![Box::new(denylist), Box::new(Osv)];
        if config.min_age_hours > 0 {
            filters.push(Box::new(Age::new(config.min_age_hours)));
        }
        Firewall { config, registries, patterns, filters, age_lifted: Mutex::default() }
    }

    pub fn match_on<'a>(
        &self,
        url: &'a str,
        key: fn(&Registry) -> &'static str,
    ) -> Option<(&'static Registry, &'a str)> {
        self.registries.iter().find_map(|r| url.strip_prefix(key(r)).map(|rest| (*r, rest)))
    }

    pub fn hosts(&self) -> Vec<&'static str> {
        let mut hosts: Vec<&'static str> = Vec::new();
        for registry in &self.registries {
            let host = registry.host();
            if !hosts.contains(&host) {
                hosts.push(host);
            }
        }
        hosts
    }

    pub fn is_https_url(&self, url: &str) -> bool {
        let host = host_of(url);
        self.registries.iter().any(|r| r.upstream.starts_with("https://") && r.host() == host)
    }

    pub fn is_index_url(&self, url: &str) -> bool {
        self.registries.iter().any(|r| r.index && r.host() == host_of(url))
    }

    /// The URL at the first mirror of the built-in registry it is on, if one is configured.
    pub fn mirrored(&self, url: String) -> String {
        for (upstream, mirror) in self.mirrors() {
            if let Some(rest) = url.strip_prefix(upstream) {
                return format!("{mirror}{rest}");
            }
        }
        url
    }

    /// Each built-in upstream with a mirror, paired with its first one.
    pub fn mirrors(&self) -> Vec<(&'static str, &str)> {
        let mut mirrors = Vec::new();
        for registry in BUILT_IN {
            let first = self.config.registries.get(registry.name()).and_then(|m| m.first());
            if let Some(mirror) = first {
                mirrors.push((registry.upstream, mirror.as_str()));
            }
        }
        mirrors
    }

    pub fn resolve(&self, registry: &'static Registry, rest: &str) -> Resolved {
        resolve(registry, rest, &self.patterns[registry.prefix])
    }

    pub fn filters(&self) -> &[Box<dyn Filter>] {
        &self.filters
    }

    pub fn lift_age_check(&self, eco: &str, package: AllowedPackage, until: Option<Instant>) {
        let mut lifted = self.age_lifted.lock().unwrap_or_else(|e| e.into_inner());
        lifted.retain(|(_, _, until)| until.is_none_or(|until| until > Instant::now()));
        lifted.push((eco.to_owned(), package, until));
    }

    pub fn age_check_lifted(&self, eco: &str, matches: impl Fn(&AllowedPackage) -> bool) -> bool {
        let lifted = self.age_lifted.lock().unwrap_or_else(|e| e.into_inner());
        lifted.iter().any(|(e, package, until)| {
            e == eco && until.is_none_or(|until| until > Instant::now()) && matches(package)
        })
    }
}

/// The built-ins, then a copy of one per mirror. Leaked, as a `Registry` is `'static` everywhere.
fn with_mirrors(mirrors: &HashMap<String, Vec<String>>) -> Vec<&'static Registry> {
    let mut registries = BUILT_IN.to_vec();
    for built_in in BUILT_IN {
        for upstream in mirrors.get(built_in.name()).into_iter().flatten() {
            let upstream = upstream.clone().leak();
            registries.push(Box::leak(Box::new(Registry { upstream, ..(*built_in).clone() })));
        }
    }
    registries
}
