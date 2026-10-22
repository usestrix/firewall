//! Started by the Windows service manager. It logs to a file, having no console.

#[cfg(windows)]
fn main() {
    if let Err(e) = firewall::os::windows::run_service() {
        tracing::error!("could not run the service: {e}");
        firewall::telemetry::error("service");
        firewall::telemetry::flush();
        std::process::exit(1)
    }
}

/// The service is Windows-only.
#[cfg(not(windows))]
fn main() {}
