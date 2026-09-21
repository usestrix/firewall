pub mod aliasing;
pub mod config;
pub mod policies;
pub mod proxy;
pub mod state;

pub use config::{FirewallConfig, DEFAULT_PORT};
pub use state::FirewallState;

use tracing_subscriber::{fmt, EnvFilter};

pub fn local_url(port: u16, path: &str) -> String {
    format!("http://127.0.0.1:{port}{path}")
}

/// Logs go to stderr so stdout stays free for the program's own output.
pub fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).with_target(false).with_writer(std::io::stderr).init();
}
