//! The hosts file sends each registry host to its own loopback address, where a
//! LocalSystem service screens it as the macOS extension does.

mod ca;
mod install;
mod service;
mod tpm;
mod uninstall;

pub use install::install;
pub use service::run as service;
pub use tpm::TpmKey;
pub use uninstall::uninstall;

use rama::error::BoxError;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::ptr;
use windows_registry::LOCAL_MACHINE;
use windows_result::HRESULT;
use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{LocalFree, ERROR_FILE_NOT_FOUND, LPARAM};
use windows_sys::Win32::Security::Authorization::*;
use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
};

const SERVICE_NAME: &str = "StrixFirewall";
/// Admin-only, so it holds the CA as the System keychain does on macOS.
const REGISTRY_KEY: &str = r"SOFTWARE\Strix Firewall";
const ENVIRONMENT_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
const BEGIN: &str = "# BEGIN Strix Firewall";
const END: &str = "# END Strix Firewall";
/// Serves the CRL our leaves point at; schannel fails closed without one.
const CRL_ADDRESS: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

/// Admin-only; holds the exported CA and the service log.
fn data_dir() -> PathBuf {
    known_dir("ProgramData", r"C:\ProgramData").join("Strix Firewall")
}

/// The service binary, copied where only admins can replace it.
fn service_exe() -> PathBuf {
    known_dir("ProgramFiles", r"C:\Program Files").join(r"Strix Firewall\firewall.exe")
}

fn hosts_file() -> PathBuf {
    known_dir("SystemRoot", r"C:\Windows").join(r"System32\drivers\etc\hosts")
}

fn known_dir(var: &str, default: &str) -> PathBuf {
    std::env::var_os(var).map_or_else(|| default.into(), PathBuf::from)
}

/// For clients that read no trust store. SSL_CERT_FILE would replace OpenSSL's bundle.
fn environment() -> [(&'static str, String); 2] {
    let ca = data_dir().join("ca.pem");
    [("NODE_EXTRA_CA_CERTS", ca.display().to_string()), ("UV_SYSTEM_CERTS", "1".into())]
}

/// From 127.0.0.3, leaving 127.0.0.1 to whatever else serves locally.
fn redirects(hosts: &[&'static str]) -> Vec<(Ipv4Addr, &'static str)> {
    (3..).zip(hosts).map(|(i, host)| (Ipv4Addr::new(127, 0, 0, i), *host)).collect()
}

/// Points each host at its listener, or with none removes our block.
fn write_hosts(hosts: &[&'static str]) -> std::io::Result<()> {
    let mut contents = without_block(&std::fs::read_to_string(hosts_file())?);
    if !hosts.is_empty() {
        if !contents.is_empty() && !contents.ends_with('\n') {
            contents.push_str("\r\n");
        }
        contents += &format!("{BEGIN}\r\n");
        for (address, host) in redirects(hosts) {
            contents += &format!("{address} {host}\r\n");
        }
        contents += &format!("{END}\r\n");
    }
    std::fs::write(hosts_file(), contents)
}

/// `contents` without our block.
fn without_block(contents: &str) -> String {
    let Some((before, rest)) = contents.split_once(BEGIN) else { return contents.into() };
    let Some((_, after)) = rest.split_once(END) else { return contents.into() };
    before.to_owned() + after.strip_prefix("\r\n").unwrap_or(after)
}

/// Parses `sddl` for `apply`, which returns zero on failure.
fn with_descriptor(sddl: &str, apply: impl FnOnce(PSECURITY_DESCRIPTOR) -> BOOL) -> std::io::Result<()> {
    let (mut descriptor, sddl) = (ptr::null_mut(), wide(sddl));
    let parsed = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut descriptor, ptr::null_mut())
    };
    if parsed == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let applied = apply(descriptor);
    let error = std::io::Error::last_os_error();
    unsafe { LocalFree(descriptor) };
    match applied {
        0 => Err(error),
        _ => Ok(()),
    }
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

/// So new processes pick up the machine environment without a sign-out.
fn broadcast_environment() {
    let environment = wide("Environment");
    let lparam = environment.as_ptr() as LPARAM;
    unsafe {
        SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, lparam, SMTO_ABORTIFHUNG, 5000, ptr::null_mut())
    };
}
