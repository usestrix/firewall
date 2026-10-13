//! The hosts file sends each registry host to its own loopback address, where a
//! LocalSystem service screens it as the macOS extension does.

mod ca;
mod service;
mod tpm;

pub use service::run as service;
pub use tpm::TpmKey;

use rama::error::BoxError;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::ptr;
use windows_registry::LOCAL_MACHINE;
use windows_result::HRESULT;
use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;

const SERVICE_NAME: &str = "StrixFirewall";
/// Admin-only, so it holds the CA as the System keychain does on macOS.
const REGISTRY_KEY: &str = r"SOFTWARE\Strix Firewall";
/// Serves the CRL our leaves point at; schannel fails closed without one.
const CRL_ADDRESS: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

/// Admin-only; holds the exported CA and the service log.
fn data_dir() -> PathBuf {
    known_dir("ProgramData", r"C:\ProgramData").join("Strix Firewall")
}

fn known_dir(var: &str, default: &str) -> PathBuf {
    std::env::var_os(var).map_or_else(|| default.into(), PathBuf::from)
}

/// From 127.0.0.3, leaving 127.0.0.1 to whatever else serves locally.
fn redirects(hosts: &[&'static str]) -> Vec<(Ipv4Addr, &'static str)> {
    (3..).zip(hosts).map(|(i, host)| (Ipv4Addr::new(127, 0, 0, i), *host)).collect()
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn registry_get(key: &str, value: &str) -> Result<Option<String>, BoxError> {
    found(LOCAL_MACHINE.open(key).and_then(|key| key.get_string(value)))
}

/// `None` for a missing key or value.
fn found<T>(result: windows_registry::Result<T>) -> Result<Option<T>, BoxError> {
    match result {
        Err(error) if error.code() == HRESULT::from_win32(ERROR_FILE_NOT_FOUND) => Ok(None),
        result => Ok(Some(result?)),
    }
}
