use crate::config::FirewallConfig;
use crate::policies::filters::denylist::Denylist;
use crate::policies::filters::osv::Osv;
use crate::policies::filters::Filter;
use crate::policies::registries::*;
use regex::Regex;
use std::collections::HashMap;

/// A running firewall: its config, the registries it screens, the compiled form of
/// their patterns, and the denylists it has fetched so far. Shared by every request.
pub struct Firewall {
    pub config: FirewallConfig,
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
        let mut patterns = HashMap::new();
        for registry in &config.registries {
            let compiled = registry.patterns.iter().map(|p| Regex::new(p.re).expect(p.re));
            patterns.insert(registry.prefix, compiled.collect());
        }
        let ecosystems = config.registries.iter().map(|r| r.osv_name);
        let denylist = Denylist::new(config.denylist.clone(), config.denylist.token(), ecosystems);
        let filters: Vec<Box<dyn Filter>> = vec![Box::new(denylist), Box::new(Osv)];
        Firewall { config, patterns, filters }
    }

    pub fn match_path<'a>(&self, path: &'a str) -> Option<(&'static Registry, &'a str)> {
        self.config
            .registries
            .iter()
            .find_map(|r| path.strip_prefix(r.prefix).map(|rest| (*r, rest)))
    }

    /// The alias path sees upstream URLs, so registries match on where they point.
    pub fn match_upstream<'a>(&self, url: &'a str) -> Option<(&'static Registry, &'a str)> {
        self.config
            .registries
            .iter()
            .find_map(|r| url.strip_prefix(r.upstream).map(|rest| (*r, rest)))
    }

    /// Every host we screen: what the proxy rewrites and what the extension claims.
    pub fn hosts(&self) -> Vec<&'static str> {
        let mut hosts: Vec<&'static str> = Vec::new();
        for registry in &self.config.registries {
            let host = registry.host();
            if !hosts.contains(&host) {
                hosts.push(host);
            }
        }
        hosts
    }

    pub fn is_index_url(&self, url: &str) -> bool {
        self.config.registries.iter().any(|r| r.index && r.host() == host_of(url))
    }

    pub fn resolve(&self, registry: &'static Registry, rest: &str) -> Resolved {
        resolve(registry, rest, &self.patterns[registry.prefix])
    }

    pub fn filters(&self) -> &[Box<dyn Filter>] {
        &self.filters
    }
}
