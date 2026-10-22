//! The hosts file sends each registry host to its own loopback address, where a
//! LocalSystem service screens it as the macOS extension does.

mod ca;
mod pipe;
mod service;
mod tpm;
mod tray;
mod uninstall;

pub use service::run as run_service;
pub use tpm::CaKey;
pub use tray::run as run_tray;
pub use uninstall::uninstall;

use rama::error::BoxError;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use windows::core::{Owned, GUID, HSTRING};
use windows::Win32::Foundation::{LocalFree, ERROR_FILE_NOT_FOUND, HLOCAL};
use windows::Win32::Security::Authorization::*;
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows::Win32::UI::Shell::*;
use windows_registry::LOCAL_MACHINE;

const SERVICE_NAME: &str = "StrixFirewall";
/// Admin-only, so it holds the CA as the System keychain does on macOS.
const REGISTRY_KEY: &str = r"SOFTWARE\Strix Firewall";
/// Serves the CRL our leaves point at; schannel fails closed without one.
const CRL_ADDRESS: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

/// Admin-only; holds the exported CA, the service log and the config.
fn data_dir() -> PathBuf {
    known_folder(&FOLDERID_ProgramData).join("Strix Firewall")
}

/// Admin-only, so users cannot relax what the service screens.
fn config_file() -> PathBuf {
    data_dir().join("config.json")
}

pub fn system_config() -> Option<PathBuf> {
    Some(config_file())
}

/// In the folder Windows reads it from, normally %SystemRoot%\System32\drivers\etc.
fn hosts_file() -> PathBuf {
    let key = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";
    let configured = LOCAL_MACHINE
        .open(key)
        .and_then(|key| key.get_hstring("DataBasePath"));
    let dir = match configured {
        Ok(dir) => expand_environment(&dir),
        Err(_) => known_folder(&FOLDERID_System).join(r"drivers\etc"),
    };
    dir.join("hosts")
}

/// Windows always has its known folders.
fn known_folder(id: &GUID) -> PathBuf {
    let path = unsafe { SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None) }.expect("a known folder");
    let dir = PathBuf::from(unsafe { path.to_hstring() }.to_os_string());
    unsafe { CoTaskMemFree(Some(path.0 as *const _)) };
    dir
}

fn expand_environment(path: &HSTRING) -> PathBuf {
    let len = unsafe { ExpandEnvironmentStringsW(path, None) };
    let mut expanded = vec![0; len as usize];
    let len = unsafe { ExpandEnvironmentStringsW(path, Some(&mut expanded)) };
    // Less the terminating null.
    PathBuf::from(String::from_utf16_lossy(
        &expanded[..(len as usize).saturating_sub(1)],
    ))
}

/// From 127.0.0.3, leaving 127.0.0.1 to whatever else serves locally.
fn loopback_addresses(hosts: &[&'static str]) -> Vec<(Ipv4Addr, &'static str)> {
    (3..)
        .zip(hosts)
        .map(|(i, host)| (Ipv4Addr::new(127, 0, 0, i), *host))
        .collect()
}

/// Points each host at its listener, replacing the lines we wrote before; with none, only removes
/// them. Bytes, as the file needn't be UTF-8, and every other line is kept as it was.
fn write_hosts_entries(hosts: &[&'static str]) -> std::io::Result<()> {
    const TAG: &str = " # Strix Firewall";
    let old = std::fs::read(hosts_file())?;
    let ours = |line: &&[u8]| line.trim_ascii_end().ends_with(TAG.as_bytes());
    let lines = old.split_inclusive(|&byte| byte == b'\n');
    let mut new: Vec<u8> = lines
        .filter(|line| !ours(line))
        .flatten()
        .copied()
        .collect();
    if !new.is_empty() && !new.ends_with(b"\n") {
        new.extend_from_slice(b"\r\n");
    }
    for (address, host) in loopback_addresses(hosts) {
        new.extend_from_slice(format!("{address} {host}{TAG}\r\n").as_bytes());
    }
    std::fs::write(hosts_file(), new)
}

/// Parses `sddl`; freed on drop.
fn security_descriptor(sddl: &str) -> windows::core::Result<Owned<HLOCAL>> {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &HSTRING::from(sddl),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )?
    };
    Ok(unsafe { Owned::new(HLOCAL(descriptor.0)) })
}

fn read_registry_string(key: &str, value: &str) -> Result<Option<String>, BoxError> {
    none_if_missing(
        LOCAL_MACHINE
            .open(key)
            .and_then(|key| key.get_string(value)),
    )
}

/// `None` for a missing key or value.
fn none_if_missing<T>(result: windows_registry::Result<T>) -> Result<Option<T>, BoxError> {
    match result {
        Err(error) if error.code() == ERROR_FILE_NOT_FOUND.to_hresult() => Ok(None),
        result => Ok(Some(result?)),
    }
}
