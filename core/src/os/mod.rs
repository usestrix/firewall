#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;

#[cfg(target_os = "macos")]
pub use macos::system_config;
#[cfg(windows)]
pub use windows::system_config;

#[cfg(not(any(target_os = "macos", windows)))]
pub fn system_config() -> Option<std::path::PathBuf> {
    None
}
