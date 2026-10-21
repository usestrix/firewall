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
#[derive(Debug)]
pub struct Pattern {
    pub re: &'static str,
    /// Registry URLs in an index response, repointed at our prefixes so the download comes back through us.
    pub rewrite: Option<(&'static str, &'static str)>,
}

/// Requests to the local server match on `prefix`; intercepted URLs match on `upstream`.
#[derive(Debug)]
pub struct Registry {
    pub prefix: &'static str,
    pub eco: &'static str,
    /// OSV names ecosystems differently to us: "crates.io", not "cargo".
    pub osv_name: &'static str,
    pub upstream: &'static str,
    /// Responses are link lists we may rewrite; package bytes must be passed through untouched.
    pub index: bool,
    /// PyPI escapes a name into a filename and Go escapes its capitals; advisories do neither.
    pub normalize: Option<fn(&str) -> String>,
    pub patterns: &'static [Pattern],
    pub published: Option<Published>,
}

/// A URL to fetch and a JSON pointer to the timestamp in its reply.
#[derive(Debug)]
pub struct Published {
    pub url: &'static str,
    pub pointer: &'static str,
    pub escape: Option<fn(&str) -> String>,
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

pub static BUILT_IN: &[&Registry] =
    &[&NPM, &PYPI_FILES, &PYPI, &CARGO_DL, &CARGO_INDEX, &CRATES_API, &GEM, &GO];

pub fn resolve(registry: &'static Registry, rest: &str, patterns: &[Regex]) -> Resolved {
    for (pattern, re) in registry.patterns.iter().zip(patterns) {
        let Some(caps) = re.captures(rest) else {
            continue;
        };
        let pkg = caps.name("name").map(|n| {
            let name = url_decode(n.as_str());
            Package {
                name: match registry.normalize {
                    Some(normalize) => normalize(&name),
                    None => name,
                },
                version: caps.name("version").map(|v| url_decode(v.as_str())),
            }
        });
        return Resolved { pkg, rewrite: pattern.rewrite };
    }
    Resolved { pkg: None, rewrite: None }
}

fn url_decode(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}
