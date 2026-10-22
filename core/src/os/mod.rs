#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;

#[cfg(target_os = "macos")]
pub use macos::{system_config, uninstall};
#[cfg(windows)]
pub use windows::system_config;

/// Elsewhere nothing is installed system-wide.
#[cfg(not(target_os = "macos"))]
pub fn uninstall() -> Result<(), rama::error::BoxError> {
    Ok(())
}

#[cfg(not(any(target_os = "macos", windows)))]
pub fn system_config() -> Option<std::path::PathBuf> {
    None
}
