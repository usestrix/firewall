pub mod forward;
pub mod managers;
#[cfg(windows)]
mod windows;

pub use forward::spawn;
pub use managers::*;

use crate::policies::registries::BUILT_IN;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::warn;

pub struct Invocation {
    pub program: String,
    pub args: Vec<String>,
}

impl Invocation {
    pub fn new(program: String, args: Vec<String>) -> Self {
        Invocation { program, args }
    }

    /// What the program is run with: the typed arguments plus any its manager needs.
    pub fn arguments(&self, proxy: &str) -> Vec<String> {
        let mut args = self.args.clone();
        let Some(manager) = MANAGERS.iter().find(|manager| manager.command == self.program) else {
            return args;
        };
        let ours = managers::arguments(proxy, manager, &args);
        // Anything after `--` belongs to another program, so ours go before it.
        let at = args.iter().position(|arg| arg == "--").unwrap_or(args.len());
        args.splice(at..at, ours);
        args
    }
}

pub fn run(port: u16, invocation: &Invocation, dir: Option<&Path>) -> std::io::Result<i32> {
    let proxy = crate::local_url(port, "");
    let program = resolve(&invocation.program)?;
    let mut command = Command::new(&program);
    command.args(invocation.arguments(&proxy));
    if let Some(dir) = dir {
        command.current_dir(dir);
    }
    for (key, value) in managers::variables(&proxy) {
        command.env(key, value);
    }
    #[cfg(windows)]
    windows::prepare();
    let status = command.status();
    #[cfg(windows)]
    let status = status.map_err(|error| windows::explain(error, &program));
    let code = status?.code().unwrap_or(1);
    let manager = MANAGERS.iter().find(|manager| manager.command == invocation.program);
    if let Some(lockfile) = manager.and_then(|manager| manager.lockfile) {
        warn_if_plaintext(lockfile, dir);
    }
    Ok(code)
}

// Command::new only finds .exe on Windows; npm, pnpm and gem are .cmd shims found via PATHEXT.
fn resolve(program: &str) -> std::io::Result<PathBuf> {
    which::which(program).map_err(|e| Error::new(ErrorKind::NotFound, e))
}

fn warn_if_plaintext(lockfile: &str, dir: Option<&Path>) {
    let path = dir.unwrap_or(Path::new(".")).join(lockfile);
    let Ok(text) = std::fs::read_to_string(path) else { return };
    if BUILT_IN.iter().any(|registry| text.contains(&format!("http://{}/", registry.host()))) {
        warn!("{lockfile} has http:// registry URLs; change them to https:// before committing");
    }
}
