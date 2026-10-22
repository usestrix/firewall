//! The notification-area icon, started at sign-in as the menu bar app is on macOS.

use super::*;
use muda::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use std::io::Cursor;
use tray_icon::{Icon, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::System::Threading::CreateMutexW;
use windows::Win32::UI::Shell::*;
use windows::Win32::UI::WindowsAndMessaging::*;
use windows_registry::CURRENT_USER;
use windows_service::service::{Service, ServiceAccess, ServiceState};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

const MENU_PAUSE: &str = "pause";
const MENU_LOG: &str = "log";
const MENU_QUIT: &str = "quit";
const LOGO: &[u8] = include_bytes!("tray.png");

/// Runs until Quit, once per session.
pub fn run() -> Result<(), BoxError> {
    // Held until we exit.
    let _mutex = unsafe { CreateMutexW(None, false, w!(r"Local\StrixFirewallTray"))? };
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        return Ok(());
    }
    let status = MenuItem::new("", false, None);
    let pause = MenuItem::with_id(MENU_PAUSE, "", false, None);
    let menu = Menu::with_items(&[
        &status,
        &PredefinedMenuItem::separator(),
        &pause,
        &MenuItem::with_id(MENU_LOG, "Open log", true, None),
        &PredefinedMenuItem::separator(),
        &MenuItem::with_id(MENU_QUIT, "Quit", true, None),
    ])?;
    let (logo, logo_size) = logo_mask()?;
    let icon = TrayIconBuilder::new().with_menu(Box::new(menu)).build()?;
    let window = HWND(icon.window_handle());
    let mut tray = Tray {
        icon,
        logo,
        logo_size,
        drawn: None,
        status,
        pause,
        state: None,
    };
    tray.update();
    unsafe { SetTimer(None, 0, 2000, None) };
    let mut message = MSG::default();
    while unsafe { GetMessageW(&mut message, None, 0, 0) }.0 > 0 {
        unsafe { DispatchMessageW(&message) };
        // WM_CLOSE, as the MSI sends, destroys the icon's window.
        if !unsafe { IsWindow(Some(window)) }.as_bool() {
            break;
        }
        // Ours, not the icon window's own hover timer.
        if message.message == WM_TIMER && message.hwnd.is_invalid() {
            tray.update();
        }
        while let Ok(event) = TrayIconEvent::receiver().try_recv() {
            // The menu opens on release, so this keeps it current.
            if let TrayIconEvent::Click {
                button_state: MouseButtonState::Down,
                ..
            } = event
            {
                tray.update();
            }
        }
        while let Ok(event) = MenuEvent::receiver().try_recv() {
            if event.id == MENU_QUIT {
                return Ok(());
            }
            tray.on_menu(event.id.as_ref());
        }
    }
    Ok(())
}

struct Tray {
    icon: TrayIcon,
    /// The logo's alpha channel; it is square.
    logo: Vec<u8>,
    logo_size: u32,
    /// Whether the taskbar was light and the service screening when the icon was last set.
    drawn: Option<(bool, bool)>,
    status: MenuItem,
    pause: MenuItem,
    /// As the menu last showed it.
    state: Option<ServiceState>,
}

impl Tray {
    fn update(&mut self) {
        self.state = service_state();
        let screening = self.state == Some(ServiceState::Running);
        let light = light_taskbar();
        if self.drawn != Some((light, screening)) {
            let rgba = logo_rgba(&self.logo, light, screening);
            if let Ok(icon) = Icon::from_rgba(rgba, self.logo_size, self.logo_size) {
                let _ = self.icon.set_icon(Some(icon));
            }
            self.drawn = Some((light, screening));
        }
        let text = status_text(self.state);
        let tip = format!("Strix Firewall: {text}");
        let _ = self.icon.set_tooltip(Some(tip));
        self.status.set_text(text);
        let pause = if screening { "Pause" } else { "Resume" };
        self.pause.set_text(pause);
        self.pause.set_enabled(self.state.is_some());
    }

    fn on_menu(&self, id: &str) {
        let state = self.state;
        let screening = state == Some(ServiceState::Running);
        let action: fn() -> Result<(), BoxError> = match id {
            MENU_PAUSE if screening => || Ok(open_service()?.pause().map(drop)?),
            MENU_PAUSE if state == Some(ServiceState::Paused) => {
                || Ok(open_service()?.resume().map(drop)?)
            }
            MENU_PAUSE => || Ok(open_service()?.start::<&str>(&[])?),
            MENU_LOG => {
                let log = HSTRING::from(data_dir().join("firewall.log").as_path());
                let none = PCWSTR::null();
                unsafe { ShellExecuteW(None, w!("open"), &log, none, none, SW_SHOWNORMAL) };
                return;
            }
            _ => return,
        };
        if let Err(error) = action() {
            let text = HSTRING::from(error.to_string());
            unsafe { MessageBoxW(None, &text, w!("Strix Firewall"), MB_ICONERROR) };
        }
    }
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

fn light_taskbar() -> bool {
    let personalize = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";
    let Ok(key) = CURRENT_USER.open(personalize) else {
        return false;
    };
    key.get_u32("SystemUsesLightTheme").is_ok_and(|light| light == 1)
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
    let access = ServiceAccess::START | ServiceAccess::PAUSE_CONTINUE;
    Ok(manager.open_service(SERVICE_NAME, access)?)
}

/// The alpha channel of the RGBA logo, and its width.
fn logo_mask() -> Result<(Vec<u8>, u32), BoxError> {
    let mut reader = png::Decoder::new(Cursor::new(LOGO)).read_info()?;
    let mut rgba = vec![0; reader.output_buffer_size().ok_or("logo too large")?];
    let info = reader.next_frame(&mut rgba)?;
    let mut alpha = Vec::with_capacity(rgba.len() / 4);
    for pixel in rgba.chunks(4) {
        alpha.push(pixel[3]);
    }
    Ok((alpha, info.width))
}

/// White on a dark taskbar and black on a light one, as macOS draws a template image; dimmed
/// when not screening.
fn logo_rgba(mask: &[u8], light: bool, screening: bool) -> Vec<u8> {
    let shade = if light { 0 } else { 255 };
    let mut rgba = Vec::with_capacity(mask.len() * 4);
    for &alpha in mask {
        let alpha = if screening { alpha } else { alpha / 2 };
        rgba.extend([shade, shade, shade, alpha]);
    }
    rgba
}
