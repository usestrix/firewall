pub mod forward;
pub mod managers;

pub use forward::{spawn, LOG_PATH};
pub use managers::*;

use std::path::Path;
use std::process::Command;

pub struct Invocation {
    pub manager: &'static Manager,
    pub args: Vec<String>,
}

impl Invocation {
    pub fn new(manager: &'static Manager, args: Vec<String>) -> Self {
        Invocation { manager, args }
    }
}

pub fn run(port: u16, invocation: &Invocation, dir: Option<&Path>) -> std::io::Result<i32> {
    let proxy = crate::local_url(port, "");
    let mut args = invocation.args.clone();
    let ours = managers::arguments(&proxy, invocation.manager, &args);
    // Anything after `--` belongs to another program, so ours go before it.
    let at = args.iter().position(|arg| arg == "--").unwrap_or(args.len());
    args.splice(at..at, ours);

    let mut command = Command::new(invocation.manager.command);
    command.args(args);
    if let Some(dir) = dir {
        command.current_dir(dir);
    }
    for (key, value) in managers::variables(&proxy, invocation.manager) {
        command.env(key, value);
    }
    Ok(command.status()?.code().unwrap_or(1))
}
