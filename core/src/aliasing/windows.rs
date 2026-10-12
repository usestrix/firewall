use std::io::{Error, ErrorKind};
use std::path::Path;
use std::sync::Once;
use tracing::debug;
use windows::core::{BOOL, PCWSTR};
use windows::Win32::System::Console::{SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_C_EVENT};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Threading::GetCurrentProcess;

/// Called before spawning, so the manager behaves as it would run from the shell directly.
/// Once per process: a caller may run several managers.
pub fn prepare() {
    static PREPARED: Once = Once::new();
    PREPARED.call_once(|| {
        // The console sends Ctrl+C to the manager too. Exiting first would hand the prompt back
        // while a .cmd shim still asks "Terminate batch job (Y/N)?", so wait for its exit instead.
        // A handler, unlike ignoring the signal outright, is not inherited by the manager.
        let _ = unsafe { SetConsoleCtrlHandler(Some(ignore_interrupt), true) };
        if let Err(error) = kill_children_on_exit() {
            debug!(%error, "the manager may outlive the firewall");
        }
    });
}

unsafe extern "system" fn ignore_interrupt(event: u32) -> BOOL {
    (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT).into()
}

/// Joins a job that kills what is left in it once the firewall exits, even if killed itself.
/// The manager inherits the job when spawned, as do its own children.
fn kill_children_on_exit() -> windows::core::Result<()> {
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // Never closed: the handle closing as the firewall exits is what kills the rest.
    let job = unsafe { CreateJobObjectW(None, PCWSTR::null())? };
    unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            size_of_val(&limits) as u32,
        )?
    };
    unsafe { AssignProcessToJobObject(job, GetCurrentProcess()) }
}

/// Rust refuses to pass a line break to a batch file, where it would cut the command short.
pub fn explain(error: Error, program: &Path) -> Error {
    let batch = program
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("cmd") || ext.eq_ignore_ascii_case("bat"));
    if !batch || error.kind() != ErrorKind::InvalidInput {
        return error;
    }
    let name = program.file_name().unwrap_or(program.as_os_str()).to_string_lossy();
    Error::new(
        ErrorKind::InvalidInput,
        format!("{name} is a batch file, which cannot be passed an argument with a line break"),
    )
}
