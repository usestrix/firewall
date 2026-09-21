use crate::config::FirewallConfig;
use crate::policies::filters::denylist::List;
use crate::policies::registries::*;
use regex::Regex;
use std::collections::HashMap;
use tokio::sync::OnceCell;

/// A running firewall: its config, the registries it screens, the compiled form of
/// their patterns, and the denylists it has fetched so far. Shared by every request.
pub struct FirewallState {
    pub config: FirewallConfig,
    patterns: HashMap<&'static str, Vec<Regex>>,
    denylists: HashMap<&'static str, OnceCell<List>>,
}

impl Default for FirewallState {
    fn default() -> Self {
        FirewallState::new(FirewallConfig::default())
    }
}

impl FirewallState {
    pub fn new(config: FirewallConfig) -> Self {
        let mut patterns = HashMap::new();
        let mut denylists = HashMap::new();
        for registry in &config.registries {
            let compiled = registry.patterns.iter().map(|p| Regex::new(p.re).expect(p.re));
            patterns.insert(registry.prefix, compiled.collect());
            denylists.entry(registry.osv_name).or_insert_with(OnceCell::new);
        }
        FirewallState { config, patterns, denylists }
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

    /// Every host we alias, so the forward proxy knows which https:// links to point back at itself.
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

    /// An ecosystem's list, filled by the first request that needs it. Registries
    /// sharing an ecosystem share the cell, and so share the one download.
    pub fn denylist(&self, eco: &'static str) -> &OnceCell<List> {
        &self.denylists[eco]
    }
}
