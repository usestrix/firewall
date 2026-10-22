//! Started by the Windows service manager. It logs to a file, having no console.

#[cfg(windows)]
fn main() {
    // Run by the MSI as it removes the firewall.
    if std::env::args().nth(1).as_deref() == Some("uninstall") {
        firewall::init_logging("info");
        if let Err(e) = firewall::os::windows::uninstall() {
            fail("uninstall", &format!("could not uninstall: {e}"))
        }
    } else if let Err(e) = firewall::os::windows::run_service() {
        fail("service", &format!("could not run the service: {e}"))
    }
}

#[cfg(windows)]
fn fail(kind: &'static str, message: &str) -> ! {
    tracing::error!("{message}");
    firewall::telemetry::error(kind);
    firewall::telemetry::flush();
    std::process::exit(1)
}

/// The service is Windows-only.
#[cfg(not(windows))]
fn main() {}
