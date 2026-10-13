use super::ca::distrust;
use super::tpm::TpmKey;
use super::*;
use std::io::ErrorKind;
use std::time::{Duration, Instant};
use tracing::info;
use windows_service::service::{ServiceAccess, ServiceState};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Foundation::*;

/// Reverses `install` in the opposite order, and does nothing for what is already gone.
pub fn uninstall() -> Result<(), BoxError> {
    // Stop redirecting first, so nothing reaches the service as it goes.
    std::fs::write(hosts_file(), without_block(&std::fs::read_to_string(hosts_file())?))?;
    stop_service(true)?;
    for (name, value) in environment() {
        if registry_get(ENVIRONMENT_KEY, name)? == Some(value) {
            LOCAL_MACHINE.create(ENVIRONMENT_KEY)?.remove_value(name)?;
        }
    }
    broadcast_environment();
    distrust(None)?;
    found(LOCAL_MACHINE.remove_tree(REGISTRY_KEY))?;
    TpmKey::delete()?;
    for dir in [data_dir(), service_exe().parent().expect("service_exe has a directory").into()] {
        match std::fs::remove_dir_all(dir) {
            Err(error) if error.kind() != ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
    }
    info!("removed the firewall, its CA and its key");
    Ok(())
}

/// Waits until it has stopped, so its binary can be replaced; `delete` also unregisters it.
pub(super) fn stop_service(delete: bool) -> Result<(), BoxError> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    let is = |error: &windows_service::Error, code: u32| {
        matches!(error, windows_service::Error::Winapi(e) if e.raw_os_error() == Some(code as i32))
    };
    let service = match manager.open_service(SERVICE_NAME, access) {
        Err(error) if is(&error, ERROR_SERVICE_DOES_NOT_EXIST) => return Ok(()),
        service => service?,
    };
    match service.stop() {
        Err(error) if is(&error, ERROR_SERVICE_NOT_ACTIVE) => {}
        stopped => _ = stopped?,
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while service.query_status()?.current_state != ServiceState::Stopped {
        if Instant::now() > deadline {
            return Err("the service did not stop".into());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    match delete.then(|| service.delete()) {
        Some(Err(error)) if !is(&error, ERROR_SERVICE_MARKED_FOR_DELETE) => Err(error.into()),
        _ => Ok(()),
    }
}

