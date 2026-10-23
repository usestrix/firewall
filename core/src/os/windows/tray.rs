//! The notification-area icon, started at sign-in as the menu bar app is on macOS.

use super::pipe::PIPE;
use super::*;
use muda::{IsMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
use serde::Deserialize;
use std::io::{BufRead, BufReader, Cursor, Write};
use std::os::windows::io::AsRawHandle;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Duration;
use tray_icon::{Icon, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use windows::core::{w, HRESULT, PCWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows::Win32::System::Threading::*;
use windows::Win32::UI::Controls::*;
use windows::Win32::UI::Shell::*;
use windows::Win32::UI::WindowsAndMessaging::*;
use windows_registry::CURRENT_USER;
use windows_service::service::{Service, ServiceAccess, ServiceState, ServiceStatus};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

const MENU_PAUSE: &str = "pause";
const MENU_RESTART: &str = "restart";
const MENU_LOG: &str = "log";
const MENU_QUIT: &str = "quit";
/// Also the service's requests, and `allow` the elevated `firewall-tray` command.
const ALLOW: &str = "allow";
const ALLOW_ONCE: &str = "allow-once";
const LOGO: &[u8] = include_bytes!("tray.png");
/// Where blocked packages are listed, below Open logs.
const BLOCKED_AT: usize = 5;
const BLOCKED_KEPT: usize = 10;

/// Runs until Quit, once per session.
pub fn run() -> Result<(), BoxError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let [verb, id, label @ ..] = &args[..] {
        if verb == ALLOW {
            // Run by `run_elevated`, so the service can tell an admin asked.
            let trusted = ask_service(&format!("{ALLOW} {id}"))
                .and_then(|reply| answered(&format!("Trusted {}", label.join(" ")), &reply));
            if let Err(error) = trusted {
                show_error(error);
                std::process::exit(1);
            }
            return Ok(());
        }
    }
    // Held until we exit.
    let _mutex = unsafe { CreateMutexW(None, false, w!(r"Local\StrixFirewallTray"))? };
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        return Ok(());
    }
    let status = MenuItem::new("", false, None);
    let pause = MenuItem::with_id(MENU_PAUSE, "", false, None);
    let blocked_separator = PredefinedMenuItem::separator();
    let menu = Menu::with_items(&[
        &status,
        &PredefinedMenuItem::separator(),
        &pause,
        &MenuItem::with_id(MENU_RESTART, "Restart", true, None),
        &MenuItem::with_id(MENU_LOG, "Open logs", true, None),
        &PredefinedMenuItem::separator(),
        &MenuItem::with_id(MENU_QUIT, "Quit", true, None),
    ])?;
    let (logo, logo_size) = logo_mask()?;
    let icon = TrayIconBuilder::new()
        .with_menu(Box::new(menu.clone()))
        .build()?;
    let window = HWND(icon.window_handle());
    let mut tray = Tray {
        icon,
        logo,
        logo_size,
        drawn: None,
        status,
        pause,
        state: None,
        menu,
        blocked_separator,
        blocked: Vec::new(),
        allowed: channel(),
    };
    tray.update();
    // The service holds a new package's download only while it is asked this often.
    unsafe { SetTimer(None, 0, 500, None) };
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
            tray.collect_blocks();
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
    menu: Menu,
    blocked_separator: PredefinedMenuItem,
    /// The most recent, as the menu lists them.
    blocked: Vec<BlockedPackage>,
    /// Allowed from another thread, so no longer listed.
    allowed: (Sender<BlockedPackage>, Receiver<BlockedPackage>),
}

#[derive(Clone, PartialEq, Deserialize)]
struct BlockedPackage {
    id: u64,
    eco: String,
    name: String,
    version: Option<String>,
    filter: String,
    reason: String,
}

impl BlockedPackage {
    fn label(&self) -> String {
        match &self.version {
            Some(version) => format!("{} {version} ({})", self.name, self.eco),
            None => format!("{} ({})", self.name, self.eco),
        }
    }

    /// The denylist and OSV only flag packages known to be malicious; the age check only holds
    /// back new ones.
    fn malicious(&self) -> bool {
        self.filter != "age"
    }

    /// Malware is never allowed, and a new package only by version.
    fn trustable(&self) -> bool {
        !self.malicious() && self.version.is_some()
    }
}

impl Tray {
    fn update(&mut self) {
        self.state = service_status().map(|status| status.current_state);
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

    /// The service hands each block over once, so whichever tray asks first shows it.
    fn collect_blocks(&mut self) {
        let allowed: Vec<_> = self.allowed.1.try_iter().collect();
        if !allowed.is_empty() {
            self.blocked.retain(|blocked| !allowed.contains(blocked));
            self.list_blocked();
        }
        if self.state != Some(ServiceState::Running) {
            return;
        }
        let Ok(reply) = ask_service("blocks") else {
            return;
        };
        let Ok(packages) = serde_json::from_str::<Vec<BlockedPackage>>(&reply) else {
            return;
        };
        let mut new = Vec::new();
        for package in packages {
            if !self.blocked.contains(&package) {
                self.blocked.push(package.clone());
                new.push(package);
            }
        }
        if new.is_empty() {
            return;
        }
        let excess = self.blocked.len().saturating_sub(BLOCKED_KEPT);
        self.blocked.drain(..excess);
        self.list_blocked();
        // Off the UI thread, so the menu keeps working while they are open.
        let allowed = self.allowed.0.clone();
        std::thread::spawn(move || {
            for package in new {
                if let Some(trust) = alert(&package) {
                    allow(package, trust, &allowed);
                }
            }
        });
    }

    fn list_blocked(&self) {
        while self.menu.items().len() > BLOCKED_AT + 2 {
            self.menu.remove_at(BLOCKED_AT);
        }
        let _ = self.menu.insert(&self.blocked_separator, BLOCKED_AT);
        for (i, package) in self.blocked.iter().enumerate() {
            let verb = if package.malicious() {
                "Blocked"
            } else {
                "Held back"
            };
            let reason = if package.malicious() {
                format!("Malicious: {}", package.reason)
            } else {
                package.reason.clone()
            };
            let reason = MenuItem::new(reason, false, None);
            let trustable = package.trustable();
            let once = MenuItem::with_id(format!("{ALLOW_ONCE}:{i}"), "Allow Once", trustable, None);
            let always = MenuItem::with_id(format!("{ALLOW}:{i}"), "Trust this version", trustable, None);
            let items: &[&dyn IsMenuItem] = if package.malicious() {
                &[&reason]
            } else {
                &[&reason, &once, &always]
            };
            let label = format!("{verb} {}", package.label());
            if let Ok(item) = Submenu::with_items(label, true, items) {
                let _ = self.menu.insert(&item, BLOCKED_AT + 1 + i);
            }
        }
    }

    fn on_menu(&self, id: &str) {
        if let Some((verb @ (ALLOW | ALLOW_ONCE), i)) = id.split_once(':') {
            let trust = verb == ALLOW;
            let package = i.parse().ok().and_then(|i: usize| self.blocked.get(i));
            if let Some(package) = package.cloned() {
                let allowed = self.allowed.0.clone();
                std::thread::spawn(move || allow(package, trust, &allowed));
            }
            return;
        }
        let state = self.state;
        let screening = state == Some(ServiceState::Running);
        let action: fn() -> Result<(), BoxError> = match id {
            MENU_PAUSE if screening => || Ok(open_service()?.pause().map(drop)?),
            MENU_PAUSE if state == Some(ServiceState::Paused) => {
                || Ok(open_service()?.resume().map(drop)?)
            }
            MENU_PAUSE => || Ok(open_service()?.start::<&str>(&[])?),
            MENU_RESTART => {
                // Off the UI thread, since stopping takes a while.
                std::thread::spawn(|| restart().unwrap_or_else(show_error));
                return;
            }
            MENU_LOG => {
                let log = HSTRING::from(data_dir().as_path());
                let none = PCWSTR::null();
                unsafe { ShellExecuteW(None, w!("open"), &log, none, none, SW_SHOWNORMAL) };
                return;
            }
            _ => return,
        };
        action().unwrap_or_else(show_error);
    }
}

const ALLOW_ONCE_BUTTON: i32 = 100;
const TRUST_BUTTON: i32 = 101;
/// `firewall.rc`'s icon, embedded by `build.rs`.
const STRIX_ICON: PCWSTR = PCWSTR(1 as _);

/// `Some(true)` if the user chose to trust it, `Some(false)` to allow it once.
/// A task dialog, as a message box can't have both buttons.
fn alert(package: &BlockedPackage) -> Option<bool> {
    let text = format!("{} {}.", package.label(), package.reason);
    let (title, text, icon) = if package.malicious() {
        let title = format!("Blocked malware: {}", package.label());
        let text = text
            + "\n\nIt was not installed. Don't install it from another source. If you didn't expect this "
            + "package, a dependency may be compromised; tell your security team.";
        (title, text, TD_ERROR_ICON)
    } else {
        ("Held back a new package".to_owned(), text, STRIX_ICON)
    };
    let button = |id, text| TASKDIALOG_BUTTON { nButtonID: id, pszButtonText: text };
    let allow = [button(ALLOW_ONCE_BUTTON, w!("Allow Once")), button(TRUST_BUTTON, w!("Trust this version"))];
    let buttons: &[_] = if package.trustable() { &allow } else { &[] };
    let (title, text) = (HSTRING::from(title), HSTRING::from(text));
    let dialog = TASKDIALOGCONFIG {
        cbSize: size_of::<TASKDIALOGCONFIG>() as u32,
        // Where `STRIX_ICON` is loaded from; the `TD_` icons are Windows'.
        hInstance: unsafe { GetModuleHandleW(None) }.ok()?.into(),
        dwCommonButtons: TDCBF_CLOSE_BUTTON,
        pszWindowTitle: w!("Strix Firewall"),
        Anonymous1: TASKDIALOGCONFIG_0 { pszMainIcon: icon },
        pszMainInstruction: PCWSTR(title.as_ptr()),
        pszContent: PCWSTR(text.as_ptr()),
        cButtons: buttons.len() as u32,
        pButtons: buttons.as_ptr(),
        pfCallback: Some(on_dialog),
        ..Default::default()
    };
    let mut chosen = 0;
    unsafe { TaskDialogIndirect(&dialog, Some(&raw mut chosen), None, None) }.ok()?;
    match chosen {
        ALLOW_ONCE_BUTTON => Some(false),
        TRUST_BUTTON => Some(true),
        _ => None,
    }
}

/// Asks for the foreground, as `MB_SETFOREGROUND` did; Windows may still leave it behind.
unsafe extern "system" fn on_dialog(
    window: HWND,
    event: TASKDIALOG_NOTIFICATIONS,
    _: WPARAM,
    _: LPARAM,
    _: isize,
) -> HRESULT {
    if event == TDN_CREATED {
        let _ = unsafe { SetForegroundWindow(window) };
    }
    S_OK
}

/// Trusting writes the config for every user, so it goes through a UAC prompt.
/// The elevated process shows its own errors and late replies.
fn allow(package: BlockedPackage, trust: bool, allowed: &Sender<BlockedPackage>) {
    let allowed_it = if trust {
        run_elevated(&[ALLOW, &package.id.to_string(), &package.label()])
            .map(|code| code == Some(0))
    } else {
        let title = format!("Allowed {} for the next minute", package.label());
        ask_service(&format!("{ALLOW_ONCE} {}", package.id))
            .and_then(|reply| answered(&title, &reply))
            .map(|()| true)
    };
    match allowed_it {
        Ok(true) => {
            let _ = allowed.send(package);
        }
        Ok(false) => {}
        Err(error) => show_error(error),
    }
}

/// Tells the user, under `title`, when the install had already stopped waiting.
fn answered(title: &str, reply: &str) -> Result<(), BoxError> {
    match reply {
        "ok" => Ok(()),
        "late" => {
            let text = "The install had already stopped waiting for it. Run it again to finish.";
            let (title, text) = (HSTRING::from(title), HSTRING::from(text));
            unsafe { MessageBoxW(None, &text, &title, MB_ICONINFORMATION | MB_SETFOREGROUND) };
            Ok(())
        }
        other => Err(other.into()),
    }
}

/// This program as an admin, waiting for its exit code; `None` if the user said no.
fn run_elevated(args: &[&str]) -> Result<Option<u32>, BoxError> {
    let exe = HSTRING::from(std::env::current_exe()?.as_path());
    let parameters = HSTRING::from(args.join(" "));
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(exe.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    if let Err(error) = unsafe { ShellExecuteExW(&mut info) } {
        if error.code() == ERROR_CANCELLED.to_hresult() {
            return Ok(None);
        }
        return Err(error.into());
    }
    let process = unsafe { Owned::new(info.hProcess) };
    unsafe { WaitForSingleObject(*process, INFINITE) };
    let mut code = 1;
    unsafe { GetExitCodeProcess(*process, &mut code)? };
    Ok(Some(code))
}

/// One request per connection, as the service answers.
fn ask_service(request: &str) -> Result<String, BoxError> {
    let mut pipe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(PIPE)?;
    // Any program can create the pipe if it gets there before the service.
    let mut server = 0;
    unsafe { GetNamedPipeServerProcessId(HANDLE(pipe.as_raw_handle()), &mut server)? };
    if service_status().and_then(|status| status.process_id) != Some(server) {
        return Err("Another program is posing as the firewall service.".into());
    }
    pipe.write_all(format!("{request}\n").as_bytes())?;
    let mut reply = String::new();
    BufReader::new(pipe).read_line(&mut reply)?;
    Ok(reply.trim_end().to_owned())
}

fn show_error(error: BoxError) {
    let text = match error.source() {
        Some(source) => format!("{error}: {source}"),
        None => error.to_string(),
    };
    let text = HSTRING::from(text);
    unsafe { MessageBoxW(None, &text, w!("Strix Firewall"), MB_ICONERROR) };
}

/// `None` when the service is not installed.
fn service_status() -> Option<ServiceStatus> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).ok()?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)
        .ok()?;
    service.query_status().ok()
}

fn light_taskbar() -> bool {
    let personalize = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";
    let Ok(key) = CURRENT_USER.open(personalize) else {
        return false;
    };
    key.get_u32("SystemUsesLightTheme")
        .is_ok_and(|light| light == 1)
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
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::START
        | ServiceAccess::STOP
        | ServiceAccess::PAUSE_CONTINUE;
    Ok(manager.open_service(SERVICE_NAME, access)?)
}

/// Starting again re-reads the config.
fn restart() -> Result<(), BoxError> {
    let service = open_service()?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        service.stop()?;
    }
    for _ in 0..60 {
        if service.query_status()?.current_state == ServiceState::Stopped {
            return Ok(service.start::<&str>(&[])?);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err("The service did not stop.".into())
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
