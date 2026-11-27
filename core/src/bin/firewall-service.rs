//! Started by the Windows service manager. It logs to a file, having no console.

#[cfg(windows)]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    // Run by the MSI as it removes the firewall.
    if args.get(1).map(String::as_str) == Some("uninstall") {
        firewall::init_logging("info");
        if let Err(e) = firewall::os::windows::uninstall() {
            fail("uninstall", &format!("could not uninstall: {e}"))
        }
    } else if args.len() == 3 && args[1] == "api-key" {
        firewall::init_logging("info");
        if let Err(e) = firewall::os::windows::set_api_key(&args[2]) {
            fail("config", &format!("could not save the API key: {e}"))
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
