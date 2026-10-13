use super::ca::certificate_authority;
use super::tpm::TpmKey;
use super::uninstall::stop_service;
use super::*;
use crate::FirewallConfig;
use std::time::{Duration, Instant};
use tracing::info;
use windows_service::service::*;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
use windows_sys::Win32::System::Services::SetServiceObjectSecurity;

/// The defaults, except that interactive users may also start, stop and pause it, as the tray does.
const SERVICE_ACL: &str = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)\
    (A;;CCLCSWRPWPDTLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";

/// Needs an elevated shell. The service points the hosts file at itself once it listens.
pub fn install() -> Result<(), BoxError> {
    let hosts = FirewallConfig::default().hosts();
    stop_service(false)?;
    let (current, exe) = (std::env::current_exe()?, service_exe());
    if current != exe {
        std::fs::create_dir_all(exe.parent().expect("service_exe has a directory"))?;
        std::fs::copy(current, &exe)?;
    }
    certificate_authority(&hosts, &TpmKey::load_or_create()?)?;
    for (name, value) in environment() {
        LOCAL_MACHINE.create(ENVIRONMENT_KEY)?.set_string(name, value)?;
    }
    broadcast_environment();
    start_service()?;
    info!(?hosts, "registry downloads are now screened");
    Ok(())
}

fn start_service() -> Result<(), BoxError> {
    let access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let manager = ServiceManager::local_computer(None::<&str>, access)?;
    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: "Strix Firewall".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: service_exe(),
        launch_arguments: vec!["service".into()],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let access = ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::START
        | ServiceAccess::QUERY_STATUS
        | ServiceAccess::WRITE_DAC;
    let service = match manager.open_service(SERVICE_NAME, access) {
        Ok(service) => service.change_config(&info).map(|()| service)?,
        Err(_) => manager.create_service(&info, access)?,
    };
    service.set_description("Screens package downloads for known malware")?;
    with_descriptor(SERVICE_ACL, |acl| unsafe {
        SetServiceObjectSecurity(service.raw_handle(), DACL_SECURITY_INFORMATION, acl)
    })?;
    // Registry hosts lead nowhere while it is down, so bring it back.
    let restart = ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(5) };
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(3600)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart; 3]),
    })?;
    service.set_failure_actions_on_non_crash_failures(true)?;
    service.start::<&str>(&[])?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match service.query_status()?.current_state {
            ServiceState::Running => return Ok(()),
            ServiceState::Stopped => return Err("the service stopped, see firewall.log".into()),
            _ if Instant::now() > deadline => return Err("the service did not start".into()),
            _ => std::thread::sleep(Duration::from_millis(250)),
        }
    }
}
