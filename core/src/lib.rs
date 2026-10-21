pub mod aliasing;
pub mod blocks;
pub mod config;
pub mod firewall;
pub mod http;
pub mod mitm;
pub mod os;
pub mod policies;
pub mod proxy;
pub mod telemetry;

pub use self::firewall::Firewall;
pub use config::{FirewallConfig, DEFAULT_PORT};

use tracing_subscriber::{fmt, EnvFilter};

/// One worker per core; rama's builder defaults to a single thread and rejects zero.
pub(crate) fn runtime() -> std::io::Result<rama::rt::blocking::Runtime> {
    let workers = std::thread::available_parallelism().map_or(1, |n| n.get());
    rama::rt::blocking::Runtime::builder().with_worker_threads(workers).try_build()
}

pub fn local_url(port: u16, path: &str) -> String {
    format!("http://127.0.0.1:{port}{path}")
}

pub fn init_logging(default_level: &str) {
    fmt().with_env_filter(log_filter(default_level)).with_target(false).with_writer(std::io::stderr).init();
}

pub(crate) fn log_filter(default_level: &str) -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level))
}
