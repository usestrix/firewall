pub mod aliasing;
pub mod proxy;
pub mod routing;

use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_PORT: u16 = 8080;

pub struct Config {
    pub port: u16,
    pub fail_open: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config { port: DEFAULT_PORT, fail_open: true }
    }
}

impl Config {
    pub fn local_url(&self, path: &str) -> String {
        local_url(self.port, path)
    }
}

pub fn local_url(port: u16, path: &str) -> String {
    format!("http://127.0.0.1:{port}{path}")
}

pub fn hms() -> String {
    let s = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format!("{:02}:{:02}:{:02}", (s / 3600) % 24, (s / 60) % 60, s % 60)
}
