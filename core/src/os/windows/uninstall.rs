use super::ca::remove_our_cas_except;
use super::tpm::CaKey;
use super::*;
use std::io::ErrorKind;
use std::path::Path;
use tracing::info;
use windows::core::{Owned, PWSTR};
use windows::Win32::Foundation::MAX_PATH;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::Threading::*;

/// Run by the MSI after it deletes the service, which would restore the hosts entries. Does
/// nothing for what is already gone.
pub fn uninstall() -> Result<(), BoxError> {
    write_hosts_entries(&[])?;
    end_trays()?;
    remove_our_cas_except(None)?;
    none_if_missing(LOCAL_MACHINE.remove_tree(REGISTRY_KEY))?;
    CaKey::delete_machine_key()?;
    let entries = match std::fs::read_dir(data_dir()) {
        Err(error) if error.kind() == ErrorKind::NotFound => Vec::new(),
        entries => entries?.collect::<Result<Vec<_>, _>>()?,
    };
    for path in entries.into_iter().map(|entry| entry.path()) {
        // The admin's config stays for a reinstall, as on macOS.
        if path != config_file() {
            remove_path(&path)?;
        }
    }
    // Fails while the config is in it.
    let _ = std::fs::remove_dir(data_dir());
    info!("removed the CA, its key and the data folder");
    Ok(())
}

/// A file or a folder, if it is there.
fn remove_path(path: &Path) -> std::io::Result<()> {
    let removed = match path.is_dir() {
        true => std::fs::remove_dir_all(path),
        false => std::fs::remove_file(path),
    };
    match removed {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        removed => removed,
    }
}

/// Ends the tray in every session, so its binary can be removed.
fn end_trays() -> Result<(), BoxError> {
    let tray = std::env::current_exe()?.with_file_name("firewall.exe");
    let snapshot = unsafe { Owned::new(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?) };
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut listed = unsafe { Process32FirstW(*snapshot, &mut entry) };
    while listed.is_ok() {
        // Processes we may not open are not ours.
        let _ = end_if_tray(entry.th32ProcessID, &tray);
        listed = unsafe { Process32NextW(*snapshot, &mut entry) };
    }
    Ok(())
}

/// Ends the process if it runs the installed firewall.exe, which the service never does.
fn end_if_tray(pid: u32, tray: &Path) -> windows::core::Result<()> {
    let access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE;
    let process = unsafe { Owned::new(OpenProcess(access, false, pid)?) };
    let mut image = [0u16; MAX_PATH as usize];
    let mut len = image.len() as u32;
    let path = PWSTR(image.as_mut_ptr());
    unsafe { QueryFullProcessImageNameW(*process, PROCESS_NAME_WIN32, path, &mut len)? };
    let image = String::from_utf16_lossy(&image[..len as usize]);
    if image.eq_ignore_ascii_case(&tray.display().to_string()) {
        unsafe { TerminateProcess(*process, 0)? };
        unsafe { WaitForSingleObject(*process, 5000) };
    }
    Ok(())
}
