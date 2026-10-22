//! The notification-area icon, started at sign-in. A GUI app, so no console opens with it.
#![windows_subsystem = "windows"]

#[cfg(windows)]
fn main() -> Result<(), rama::error::BoxError> {
    firewall::os::windows::run_tray()
}

/// The tray is Windows-only.
#[cfg(not(windows))]
fn main() {}
