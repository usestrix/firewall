pub mod aliasing;
pub mod proxy;
pub mod routing;

use tracing_subscriber::{fmt, EnvFilter};

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

/// Logs go to stderr so stdout stays free for the program's own output.
pub fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).with_target(false).with_writer(std::io::stderr).init();
}
