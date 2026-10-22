use super::ca::remove_our_cas_except;
use super::tpm::CaKey;
use super::*;
use std::io::ErrorKind;
use std::path::Path;
use tracing::info;

/// Run by the MSI after it deletes the service, which would restore the hosts entries. Does
/// nothing for what is already gone.
pub fn uninstall() -> Result<(), BoxError> {
    write_hosts_entries(&[])?;
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
