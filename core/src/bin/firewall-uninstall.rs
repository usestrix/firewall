//! Run as root by the macOS app's uninstall.

#[cfg(target_os = "macos")]
fn main() {
    firewall::init_logging("info");
    if let Err(e) = firewall::os::macos::uninstall() {
        tracing::error!("could not uninstall: {e}");
        firewall::telemetry::error("uninstall");
        firewall::telemetry::flush();
        std::process::exit(1)
    }
}

/// Only macOS installs anything system-wide.
#[cfg(not(target_os = "macos"))]
fn main() {}
