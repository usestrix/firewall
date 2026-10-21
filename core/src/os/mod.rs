#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "macos")]
pub use macos::uninstall;

/// Elsewhere nothing is installed system-wide.
#[cfg(not(target_os = "macos"))]
pub fn uninstall() -> Result<(), rama::error::BoxError> {
    Ok(())
}
