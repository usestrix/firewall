mod cargo;
mod gem;
mod go;
mod npm;
mod pypi;

use cargo::*;
use gem::*;
use go::*;
use npm::*;
use percent_encoding::percent_decode_str;
use pypi::*;
use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

#[derive(Clone)]
pub struct Package {
    pub name: String,
    pub version: Option<String>,
}

impl Package {
    pub fn label(&self) -> String {
        match &self.version {
            Some(v) => format!("{}@{}", self.name, v),
            None => self.name.clone(),
        }
    }
}

/// Tried in order against the path left after the prefix; `name` and `version` are the captures we read.
pub struct Pattern {
    pub re: &'static str,
    /// Registry URLs in an index response, repointed at our prefixes so the download comes back through us.
    pub rewrite: Option<(&'static str, &'static str)>,
}

/// Keyed both ways: the mirror matches on `prefix`, the alias proxy on `upstream`.
pub struct Registry {
    pub prefix: &'static str,
    pub eco: &'static str,
    /// OSV names ecosystems differently to us: "crates.io", not "cargo".
    pub osv_name: &'static str,
    pub upstream: &'static str,
    /// Responses are link lists we may rewrite; package bytes must be passed through untouched.
    pub index: bool,
    pub patterns: &'static [Pattern],
}

impl Registry {
    pub fn host(&self) -> &'static str {
        host_of(self.upstream)
    }
}

/// The host of an https:// URL, with the path dropped.
pub fn host_of(url: &str) -> &str {
    let rest = url.trim_start_matches("https://");
    rest.split_once('/').map_or(rest, |(host, _)| host)
}

pub struct Resolved {
    pub pkg: Option<Package>,
    pub rewrite: Option<(&'static str, &'static str)>,
}

pub static REGISTRIES: &[&Registry] =
    &[&NPM, &PYPI_FILES, &PYPI, &CARGO_DL, &CARGO_INDEX, &CRATES_API, &GEM, &GO];

static COMPILED: LazyLock<HashMap<&'static str, Vec<Regex>>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    for registry in REGISTRIES {
        let res = registry.patterns.iter().map(|p| Regex::new(p.re).expect(p.re)).collect();
        map.insert(registry.prefix, res);
    }
    map
});

pub fn match_path(path: &str) -> Option<(&'static Registry, &str)> {
    REGISTRIES.iter().find_map(|r| path.strip_prefix(r.prefix).map(|rest| (*r, rest)))
}

pub fn match_upstream(url: &str) -> Option<(&'static Registry, &str)> {
    REGISTRIES.iter().find_map(|r| url.strip_prefix(r.upstream).map(|rest| (*r, rest)))
}

/// Every host we alias, so the forward proxy knows which https:// links to point back at itself.
pub fn hosts() -> Vec<&'static str> {
    let mut hosts: Vec<&'static str> = Vec::new();
    for registry in REGISTRIES {
        let host = registry.host();
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    hosts
}

pub fn is_index_url(url: &str) -> bool {
    REGISTRIES.iter().any(|r| r.index && r.host() == host_of(url))
}

pub fn resolve(registry: &'static Registry, rest: &str) -> Resolved {
    for (pattern, re) in registry.patterns.iter().zip(&COMPILED[registry.prefix]) {
        let Some(caps) = re.captures(rest) else { continue };
        let pkg = caps.name("name").map(|n| Package {
            name: url_decode(n.as_str()),
            version: caps.name("version").map(|v| url_decode(v.as_str())),
        });
        return Resolved { pkg, rewrite: pattern.rewrite };
    }
    Resolved { pkg: None, rewrite: None }
}

fn url_decode(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}
