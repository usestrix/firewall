use crate::config::FirewallConfig;
use crate::policies::filters::age::Age;
use crate::policies::filters::denylist::Denylist;
use crate::policies::filters::osv::Osv;
use crate::policies::filters::Filter;
use crate::policies::registries::*;
use regex::Regex;
use std::collections::HashMap;

pub struct Firewall {
    pub config: FirewallConfig,
    registries: Vec<&'static Registry>,
    patterns: HashMap<&'static str, Vec<Regex>>,
    filters: Vec<Box<dyn Filter>>,
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
        Firewall { config, registries, patterns, filters }
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

    pub fn resolve(&self, registry: &'static Registry, rest: &str) -> Resolved {
        resolve(registry, rest, &self.patterns[registry.prefix])
    }

    pub fn filters(&self) -> &[Box<dyn Filter>] {
        &self.filters
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
