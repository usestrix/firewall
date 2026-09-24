use crate::policies::registries::{Registry, BUILT_IN};
use directories::ProjectDirs;
use serde::Deserialize;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;

pub const DEFAULT_PORT: u16 = 8080;
const TOKEN_ENV: &str = "FIREWALL_GITHUB_TOKEN";

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FirewallConfig {
    pub port: u16,
    /// Allow a package when a filter could not check it.
    pub fail_open: bool,
    pub denylist: DenylistSource,
    pub telemetry: bool,
    /// Not describable in the file yet, so this is always the built-in table.
    #[serde(skip)]
    pub registries: Vec<&'static Registry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DenylistSource {
    /// One file per ecosystem lives under here, named the way OSV names it, in lowercase.
    pub base: String,
    /// Falls back to `FIREWALL_GITHUB_TOKEN`, so a token need not be written to disk.
    pub token: Option<String>,
    /// Polled for a new commit, which re-fetches every list in use.
    pub revision: String,
    pub poll_secs: u64,
}

impl DenylistSource {
    pub fn token(&self) -> Option<String> {
        self.token.clone().or_else(|| std::env::var(TOKEN_ENV).ok())
    }
}

impl Default for FirewallConfig {
    fn default() -> Self {
        FirewallConfig {
            port: DEFAULT_PORT,
            fail_open: true,
            denylist: DenylistSource::default(),
            telemetry: true,
            registries: BUILT_IN.to_vec(),
        }
    }
}

impl Default for DenylistSource {
    fn default() -> Self {
        DenylistSource {
            base: "https://raw.githubusercontent.com/usestrix/malicious-packages/packages".into(),
            token: None,
            revision: "https://api.github.com/repos/usestrix/malicious-packages/commits/packages"
                .into(),
            poll_secs: 10,
        }
    }
}

impl FirewallConfig {
    /// A missing file means defaults; a bad one is an error, so the policy is never quietly relaxed.
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
    let dirs = ProjectDirs::from("ai", "strix", "firewall")?;
    Some(dirs.config_dir().join("config.json"))
}
