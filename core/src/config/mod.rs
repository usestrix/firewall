use crate::policies::registries::{host_of, BUILT_IN};
use directories::ProjectDirs;
use rama::net::uri::Uri;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::num::{NonZeroU16, NonZeroU64};
use std::path::{Path, PathBuf};

pub const DEFAULT_PORT: u16 = 8080;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FirewallConfig {
    pub port: NonZeroU16,
    /// Allow a package when a filter could not check it.
    pub fail_open: bool,
    /// 0 turns the age check off.
    pub min_age_hours: u64,
    pub denylist: DenylistSource,
    /// Packages exempt from the age check, by ecosystem: `{"npm": [{"name": "left-pad"}]}`.
    pub allow: HashMap<String, Vec<AllowedPackage>>,
    pub telemetry: bool,
    /// Mirrors laid out like a built-in registry, by its name: `{"npm": ["https://npm.example.com/"]}`.
    pub registries: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedPackage {
    pub name: String,
    /// Every version when absent.
    pub version: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DenylistSource {
    /// One file per ecosystem lives under here, named the way OSV names it, in lowercase.
    pub base: String,
    /// Polled for a new commit, which re-fetches every list in use.
    pub revision: String,
    pub poll_secs: NonZeroU64,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        FirewallConfig {
            port: NonZeroU16::new(DEFAULT_PORT).unwrap(),
            fail_open: true,
            min_age_hours: 24,
            denylist: DenylistSource::default(),
            allow: HashMap::new(),
            telemetry: true,
            registries: HashMap::new(),
        }
    }
}

impl Default for DenylistSource {
    fn default() -> Self {
        DenylistSource {
            base: "https://raw.githubusercontent.com/usestrix/firewall-blocklist/main".into(),
            revision: "https://api.github.com/repos/usestrix/firewall-blocklist/commits/main"
                .into(),
            poll_secs: NonZeroU64::new(10).unwrap(),
        }
    }
}

impl FirewallConfig {
    pub fn load() -> std::io::Result<Self> {
        let mut paths: Vec<PathBuf> = path().into_iter().collect();
        paths.extend(crate::os::system_config());
        Self::load_from(&paths)
    }

    /// Later files win key by key, but allow lists add up.
    /// A bad file is an error, so the policy is never quietly relaxed.
    pub fn load_from(paths: &[PathBuf]) -> std::io::Result<Self> {
        let mut merged = Map::new();
        for path in paths {
            let text = match std::fs::read_to_string(path) {
                Ok(text) => text,
                Err(e) if e.kind() == ErrorKind::NotFound => continue,
                Err(e) => return Err(Error::new(e.kind(), format!("{}: {e}", path.display()))),
            };
            let invalid = |e| Error::new(ErrorKind::InvalidData, format!("{}: {e}", path.display()));
            let layer: Value = serde_json::from_str(&text).map_err(invalid)?;
            let config = FirewallConfig::deserialize(&layer).map_err(invalid)?;
            check(&config).map_err(|e| Error::new(ErrorKind::InvalidData, format!("{}: {e}", path.display())))?;
            let Value::Object(layer) = layer else {
                unreachable!("a config parses only from an object");
            };
            merge(&mut merged, layer);
        }
        Ok(serde_json::from_value(Value::Object(merged)).expect("each layer parsed on its own"))
    }

    pub fn local_url(&self, path: &str) -> String {
        crate::local_url(self.port.get(), path)
    }
}

pub fn path() -> Option<PathBuf> {
    let dirs = ProjectDirs::from("com", "usestrix", "firewall")?;
    Some(dirs.config_dir().join("config.json"))
}

fn merge(base: &mut Map<String, Value>, top: Map<String, Value>) {
    for (key, value) in top {
        match (base.get_mut(&key), value) {
            (Some(Value::Object(base)), Value::Object(top)) => merge(base, top),
            (Some(Value::Array(base)), Value::Array(top)) => base.extend(top),
            (_, value) => {
                base.insert(key, value);
            }
        }
    }
}

/// Adds an `allow` entry to the file, leaving the rest of it as written.
pub fn allow(path: &Path, eco: &str, name: &str, version: Option<&str>) -> std::io::Result<()> {
    let invalid = |e: String| Error::new(ErrorKind::InvalidData, format!("{}: {e}", path.display()));
    let mut config = match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).map_err(|e| invalid(e.to_string()))?,
        Err(e) if e.kind() == ErrorKind::NotFound => json!({}),
        Err(e) => return Err(e),
    };
    if !config.is_object() {
        return Err(invalid("not an object".into()));
    }
    let entry = json!({ "name": name, "version": version });
    let entries = &mut config["allow"][eco];
    if entries.is_null() {
        *entries = Value::Array(Vec::new());
    }
    let Some(entries) = entries.as_array_mut() else {
        return Err(invalid(format!("allow.{eco} is not a list")));
    };
    if !entries.contains(&entry) {
        entries.push(entry);
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(&config)?)
}

/// What serde's types cannot say.
fn check(config: &FirewallConfig) -> Result<(), String> {
    // `Duration::hours` panics past this.
    if config.min_age_hours > time::Duration::MAX.whole_hours() as u64 {
        return Err(format!("{} hours is too long", config.min_age_hours));
    }
    for eco in config.allow.keys() {
        if !BUILT_IN.iter().any(|r| r.eco == eco) {
            return Err(format!("unknown ecosystem {eco:?} in allow"));
        }
    }
    for url in [&config.denylist.base, &config.denylist.revision] {
        if parse_url(url, &["http", "https"]).is_none() {
            return Err(format!("{url:?} is not an http(s) URL"));
        }
    }
    for (name, mirrors) in &config.registries {
        if !BUILT_IN.iter().any(|r| r.name() == name) {
            return Err(format!("no built-in registry is named {name}"));
        }
        if let Some(url) = mirrors.iter().find(|url| !is_mirror(url)) {
            return Err(format!("{url}: a mirror is an https:// URL ending in /"));
        }
    }
    Ok(())
}

/// No port or userinfo, as `host_of` is what gets intercepted.
fn is_mirror(url: &str) -> bool {
    let Some(uri) = parse_url(url, &["https"]) else { return false };
    let bare_host = uri.host_str().is_some_and(|host| host == host_of(url));
    bare_host && uri.query().is_none() && uri.fragment().is_none() && url.ends_with('/')
}

fn parse_url(url: &str, schemes: &[&str]) -> Option<Uri> {
    let uri = Uri::parse(url).ok()?;
    let has_host = uri.host_str().is_some_and(|host| !host.is_empty());
    (has_host && schemes.contains(&uri.scheme_str()?)).then_some(uri)
}
