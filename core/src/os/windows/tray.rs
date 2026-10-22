//! The notification-area icon, started at sign-in as the menu bar app is on macOS.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::System::Console::{FreeConsole, GetConsoleProcessList};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::CreateMutexW;
use windows::Win32::UI::Shell::*;
use windows::Win32::UI::WindowsAndMessaging::*;
use windows_service::service::{Service, ServiceAccess, ServiceState};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

const WM_TRAY_ICON: u32 = WM_APP;
const MENU_PAUSE: usize = 1;
const MENU_RESTART: usize = 2;
const MENU_LOG: usize = 3;
const MENU_QUIT: usize = 4;
static ACTION_RUNNING: AtomicBool = AtomicBool::new(false);
static TASKBAR_CREATED: OnceLock<u32> = OnceLock::new();

/// Started by Explorer or at sign-in rather than from a terminal, runs the tray instead of
/// printing help.
pub fn run_tray_if_launched() {
    if std::env::args_os().len() == 1 && detach_console() {
        std::process::exit(run_tray().map_or(1, |()| 0))
    }
}

/// Frees a console that no terminal shares, as when Explorer or the Run key starts us.
fn detach_console() -> bool {
    let mut processes = [0; 2];
    unsafe { GetConsoleProcessList(&mut processes) == 1 && FreeConsole().is_ok() }
}

/// Runs until Quit, once per session.
fn run_tray() -> Result<(), BoxError> {
    // Held until we exit.
    let _mutex = unsafe { CreateMutexW(None, false, w!(r"Local\StrixFirewallTray"))? };
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        return Ok(());
    }
    let class = w!("StrixFirewallTray");
    let instance = unsafe { GetModuleHandleW(PCWSTR::null())? }.into();
    let window_class = WNDCLASSW {
        lpfnWndProc: Some(window_proc),
        hInstance: instance,
        lpszClassName: class,
        ..Default::default()
    };
    // Hidden rather than message-only, which would miss TaskbarCreated.
    let window = unsafe {
        RegisterClassW(&window_class);
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class,
            PCWSTR::null(),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            None,
            None,
            Some(instance),
            None,
        )?
    };
    update_icon(window, NIM_ADD);
    unsafe { SetTimer(Some(window), 1, 2000, None) };
    let mut message = MSG::default();
    while unsafe { GetMessageW(&mut message, None, 0, 0) }.0 > 0 {
        unsafe { DispatchMessageW(&message) };
    }
    Ok(())
}

unsafe extern "system" fn window_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let taskbar_created =
        *TASKBAR_CREATED.get_or_init(|| unsafe { RegisterWindowMessageW(w!("TaskbarCreated")) });
    match message {
        WM_TIMER => update_icon(window, NIM_MODIFY),
        WM_TRAY_ICON if matches!(lparam.0 as u32, WM_LBUTTONUP | WM_RBUTTONUP) => on_click(window),
        WM_DESTROY => {
            update_icon(window, NIM_DELETE);
            unsafe { PostQuitMessage(0) };
        }
        // Explorer restarted, taking our icon with it.
        _ if message == taskbar_created => update_icon(window, NIM_ADD),
        _ => return unsafe { DefWindowProcW(window, message, wparam, lparam) },
    }
    LRESULT(0)
}

fn update_icon(window: HWND, action: NOTIFY_ICON_MESSAGE) {
    let state = service_state();
    let icon = if state == Some(ServiceState::Running) {
        IDI_SHIELD
    } else {
        IDI_WARNING
    };
    let size = unsafe { GetSystemMetrics(SM_CXSMICON) };
    let icon = unsafe { LoadImageW(None, icon, IMAGE_ICON, size, size, LR_SHARED) };
    let mut data = NOTIFYICONDATAW {
        cbSize: size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: window,
        uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP,
        uCallbackMessage: WM_TRAY_ICON,
        hIcon: HICON(icon.unwrap_or_default().0),
        ..Default::default()
    };
    let tip = format!("Strix Firewall: {}", status_text(state));
    data.szTip
        .iter_mut()
        .zip(tip.encode_utf16())
        .for_each(|(slot, unit)| *slot = unit);
    let _ = unsafe { Shell_NotifyIconW(action, &data) };
}

fn on_click(window: HWND) {
    let state = service_state();
    let screening = state == Some(ServiceState::Running);
    let control = match state.is_some() && !ACTION_RUNNING.load(Ordering::SeqCst) {
        true => MF_STRING,
        false => MF_GRAYED,
    };
    let items = [
        (MF_GRAYED, 0, status_text(state)),
        (MF_SEPARATOR, 0, ""),
        (
            control,
            MENU_PAUSE,
            if screening { "Pause" } else { "Resume" },
        ),
        (control, MENU_RESTART, "Restart"),
        (MF_STRING, MENU_LOG, "Open logs"),
        (MF_SEPARATOR, 0, ""),
        (MF_STRING, MENU_QUIT, "Quit"),
    ];
    let Ok(chosen) = show_menu(window, &items) else {
        return;
    };
    let action: fn() -> Result<(), BoxError> = match chosen {
        MENU_PAUSE if screening => || Ok(open_service()?.pause().map(drop)?),
        MENU_PAUSE if state == Some(ServiceState::Paused) => {
            || Ok(open_service()?.resume().map(drop)?)
        }
        MENU_PAUSE => || start_and_wait(&open_service()?),
        MENU_RESTART => || {
            let service = open_service()?;
            stop_and_wait(&service)?;
            start_and_wait(&service)
        },
        MENU_LOG => {
            let log = HSTRING::from(data_dir().as_path());
            let none = PCWSTR::null();
            unsafe { ShellExecuteW(Some(window), w!("open"), &log, none, none, SW_SHOWNORMAL) };
            return;
        }
        MENU_QUIT => {
            let _ = unsafe { DestroyWindow(window) };
            return;
        }
        _ => return,
    };
    ACTION_RUNNING.store(true, Ordering::SeqCst);
    std::thread::spawn(move || {
        if let Err(error) = action() {
            let text = HSTRING::from(error.to_string());
            unsafe { MessageBoxW(None, &text, w!("Strix Firewall"), MB_ICONERROR) };
        }
        ACTION_RUNNING.store(false, Ordering::SeqCst);
    });
}

/// The chosen item's id, or 0 for none.
fn show_menu(
    window: HWND,
    items: &[(MENU_ITEM_FLAGS, usize, &str)],
) -> windows::core::Result<usize> {
    let menu = unsafe { CreatePopupMenu()? };
    for (flags, id, text) in items {
        unsafe { AppendMenuW(menu, *flags, *id, &HSTRING::from(*text))? };
    }
    let mut point = POINT::default();
    let chosen = unsafe {
        GetCursorPos(&mut point)?;
        // Or the menu stays open after a click elsewhere.
        let _ = SetForegroundWindow(window);
        let flags = TPM_RETURNCMD | TPM_RIGHTBUTTON;
        TrackPopupMenu(menu, flags, point.x, point.y, None, window, None)
    };
    unsafe { DestroyMenu(menu)? };
    Ok(chosen.0 as usize)
}

/// `None` when the service is not installed.
fn service_state() -> Option<ServiceState> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).ok()?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)
        .ok()?;
    Some(service.query_status().ok()?.current_state)
}

fn status_text(state: Option<ServiceState>) -> &'static str {
    match state {
        Some(ServiceState::Running) => "Screening downloads",
        Some(ServiceState::Paused) => "Paused",
        _ => "Not running",
    }
}

fn open_service() -> Result<Service, BoxError> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let access = ServiceAccess::START
        | ServiceAccess::STOP
        | ServiceAccess::PAUSE_CONTINUE
        | ServiceAccess::QUERY_STATUS;
    Ok(manager.open_service(SERVICE_NAME, access)?)
}

/// Waits until it serves.
fn start_and_wait(service: &Service) -> Result<(), BoxError> {
    service.start::<&str>(&[])?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match service.query_status()?.current_state {
            ServiceState::Running => return Ok(()),
            ServiceState::Stopped => return Err("the service stopped, see firewall.*.log".into()),
            _ if Instant::now() > deadline => return Err("the service did not start".into()),
            _ => std::thread::sleep(Duration::from_millis(250)),
        }
    }
}

fn stop_and_wait(service: &Service) -> Result<(), BoxError> {
    let not_active = Some(ERROR_SERVICE_NOT_ACTIVE.0 as i32);
    match service.stop() {
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == not_active => {}
        stopped => _ = stopped?,
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while service.query_status()?.current_state != ServiceState::Stopped {
        if Instant::now() > deadline {
            return Err("the service did not stop".into());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Ok(())
}
