mod cargo;
mod gem;
mod go;
mod npm;
mod pypi;

use cargo::*;
use gem::*;
use go::*;
use npm::*;
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
        let rest = self.upstream.trim_start_matches("https://");
        rest.split_once('/').map_or(rest, |(host, _)| host)
    }
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

pub fn is_index(host: &str) -> bool {
    REGISTRIES.iter().any(|r| r.index && r.host() == host)
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
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v as char);
                i += 3;
                continue;
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(path: &str) -> (Option<String>, Option<String>, bool) {
        let (registry, rest) = match_path(path).expect("no registry matched");
        let resolved = resolve(registry, rest);
        let (name, version) = match resolved.pkg {
            Some(p) => (Some(p.name), p.version),
            None => (None, None),
        };
        (name, version, resolved.rewrite.is_some())
    }

    #[test]
    fn every_pattern_compiles() {
        assert_eq!(COMPILED.len(), REGISTRIES.len());
    }

    #[test]
    fn hosts_come_from_upstreams() {
        assert!(hosts().contains(&"files.pythonhosted.org"));
        assert!(is_index("pypi.org"));
        assert!(!is_index("files.pythonhosted.org"));
    }

    #[test]
    fn cargo_paths() {
        assert_eq!(at("/cargo/index/ru/st/rustdecimal"), (Some("rustdecimal".into()), None, false));
        assert_eq!(at("/cargo/index/3/s/syn"), (Some("syn".into()), None, false));
        assert_eq!(at("/cargo/index/config.json"), (None, None, true));
        assert_eq!(
            at("/cargo-dl/left-pad/1.0.1/download"),
            (Some("left-pad".into()), Some("1.0.1".into()), false)
        );
    }

    #[test]
    fn npm_paths() {
        assert_eq!(at("/npm/left-pad"), (Some("left-pad".into()), None, true));
        assert_eq!(at("/npm/@scope%2fpkg"), (Some("@scope/pkg".into()), None, true));
        assert_eq!(
            at("/npm/left-pad/-/left-pad-1.0.1.tgz"),
            (Some("left-pad".into()), Some("1.0.1".into()), false)
        );
        assert_eq!(
            at("/npm/@scope/pkg/-/pkg-2.0.0-beta.1.tgz"),
            (Some("@scope/pkg".into()), Some("2.0.0-beta.1".into()), false)
        );
    }

    #[test]
    fn pypi_paths() {
        assert_eq!(at("/pypi/simple/urllib3/"), (Some("urllib3".into()), None, true));
        assert_eq!(at("/pypi-files/packages/ab/cd/ef/urllib3-2.0.7.tar.gz"), (None, None, false));
    }
}
