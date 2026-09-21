use crate::policies::registries::{Registry, BUILT_IN};
use directories::ProjectDirs;
use serde::Deserialize;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;

pub const DEFAULT_PORT: u16 = 8080;

/// What the firewall reads from its config file. Every field has a default, so a
/// missing file means the same as an empty one.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FirewallConfig {
    pub port: u16,
    /// Allow a package when a filter could not check it.
    pub fail_open: bool,
    pub denylist: Denylist,
    /// Not describable in the file yet, so this is always the built-in table.
    #[serde(skip)]
    pub registries: Vec<&'static Registry>,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Denylist {
    /// One file per ecosystem lives under here, named the way OSV names it, in lowercase.
    pub base: String,
    /// Environment variable holding a token, for a source that asks for one.
    pub token: String,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        FirewallConfig {
            port: DEFAULT_PORT,
            fail_open: true,
            denylist: Denylist::default(),
            registries: BUILT_IN.to_vec(),
        }
    }
}

impl Default for Denylist {
    fn default() -> Self {
        Denylist {
            base: "https://raw.githubusercontent.com/usestrix/malicious-packages/packages".into(),
            token: "FIREWALL_GITHUB_TOKEN".into(),
        }
    }
}

impl FirewallConfig {
    /// Defaults when there is no file; an unreadable or unparseable one is an error,
    /// because falling back quietly could relax the policy the file was written to set.
    pub fn load() -> std::io::Result<Self> {
        let Some(path) = path() else {
            return Ok(Self::default());
        };
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(Error::new(e.kind(), format!("{}: {e}", path.display()))),
        };
        serde_json::from_str(&text)
            .map_err(|e| Error::new(ErrorKind::InvalidData, format!("{}: {e}", path.display())))
    }

    pub fn local_url(&self, path: &str) -> String {
        crate::local_url(self.port, path)
    }
}

pub fn path() -> Option<PathBuf> {
    let dirs = ProjectDirs::from("com", "usestrix", "firewall")?;
    Some(dirs.config_dir().join("config.json"))
}
