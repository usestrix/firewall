use crate::policies::registries::{Registry, BUILT_IN};
use directories::ProjectDirs;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;

pub const DEFAULT_PORT: u16 = 8080;

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FirewallConfig {
    pub port: u16,
    /// Allow a package when a filter could not check it.
    pub fail_open: bool,
    /// 0 turns the age check off.
    pub min_age_hours: u64,
    pub denylist: DenylistSource,
    /// Packages never screened, by ecosystem: `{"npm": [{"name": "left-pad"}]}`.
    pub allow: HashMap<String, Vec<AllowedPackage>>,
    pub telemetry: bool,
    /// Not describable in the file yet, so this is always the built-in table.
    #[serde(skip)]
    pub registries: Vec<&'static Registry>,
}

#[derive(Debug, Deserialize)]
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
    pub poll_secs: u64,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        FirewallConfig {
            port: DEFAULT_PORT,
            fail_open: true,
            min_age_hours: 0,
            denylist: DenylistSource::default(),
            allow: HashMap::new(),
            telemetry: true,
            registries: BUILT_IN.to_vec(),
        }
    }
}

impl Default for DenylistSource {
    fn default() -> Self {
        DenylistSource {
            base: "https://raw.githubusercontent.com/usestrix/firewall-blocklist/main".into(),
            revision: "https://api.github.com/repos/usestrix/firewall-blocklist/commits/main"
                .into(),
            poll_secs: 10,
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
            FirewallConfig::deserialize(&layer).map_err(invalid)?;
            let Value::Object(layer) = layer else {
                unreachable!("a config parses only from an object");
            };
            merge(&mut merged, layer);
        }
        Ok(serde_json::from_value(Value::Object(merged)).expect("each layer parsed on its own"))
    }

    pub fn local_url(&self, path: &str) -> String {
        crate::local_url(self.port, path)
    }

    /// Without building a `Firewall`, which needs a runtime.
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
