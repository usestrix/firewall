pub mod forward;
pub mod managers;

pub use forward::spawn;
pub use managers::*;

use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Invocation {
    pub manager: &'static Manager,
    pub args: Vec<String>,
}

impl Invocation {
    pub fn new(manager: &'static Manager, args: Vec<String>) -> Self {
        Invocation { manager, args }
    }

    /// A manager's name followed by its arguments, kept verbatim, `--` included.
    pub fn parse(mut args: impl Iterator<Item = String>) -> Option<Self> {
        let command = args.next()?;
        let manager = MANAGERS.iter().find(|manager| manager.command == command)?;
        Some(Invocation::new(manager, args.collect()))
    }

    /// What the manager is run with: the typed arguments plus ours.
    pub fn arguments(&self, proxy: &str) -> Vec<String> {
        let mut args = self.args.clone();
        let ours = managers::arguments(proxy, self.manager, &args);
        // Anything after `--` belongs to another program, so ours go before it.
        let at = args.iter().position(|arg| arg == "--").unwrap_or(args.len());
        args.splice(at..at, ours);
        args
    }
}

pub fn run(port: u16, invocation: &Invocation, dir: Option<&Path>) -> std::io::Result<i32> {
    let proxy = crate::local_url(port, "");
    let mut command = Command::new(resolve(invocation.manager.command)?);
    command.args(invocation.arguments(&proxy));
    if let Some(dir) = dir {
        command.current_dir(dir);
    }
    for (key, value) in managers::variables(&proxy, invocation.manager) {
        command.env(key, value);
    }
    Ok(command.status()?.code().unwrap_or(1))
}

// Command::new only finds .exe on Windows; npm, pnpm and gem are .cmd shims found via PATHEXT.
fn resolve(program: &str) -> std::io::Result<PathBuf> {
    which::which(program).map_err(|e| Error::new(ErrorKind::NotFound, e))
}
