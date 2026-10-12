mod bun;
mod cargo;
mod gem;
mod go;
mod npm;
mod pdm;
mod pip;
mod pipenv;
mod pnpm;
mod uv;

pub use bun::BUN;
pub use cargo::CARGO;
pub use gem::GEM;
pub use go::GO;
pub use npm::NPM;
pub use pdm::PDM;
pub use pip::{PIP, PIP3};
pub use pipenv::PIPENV;
pub use pnpm::PNPM;
pub use uv::UV;

pub const PYPI_SIMPLE: &str = "http://pypi.org/simple";

pub const PROXY: &str = "{proxy}";

/// Command-line flags the manager needs; `when` limits them to those subcommands, empty means always.
pub struct Args {
    pub when: &'static [&'static str],
    pub flags: &'static [&'static str],
}

/// An https:// registry arrives as a CONNECT tunnel naming only the host, so each
/// manager also overrides its registry URL to http://.
pub struct Manager {
    pub command: &'static str,
    pub env: &'static [(&'static str, &'static str)],
    pub args: &'static [Args],
}

pub static MANAGERS: &[&Manager] =
    &[&NPM, &PIP, &PIP3, &CARGO, &GO, &GEM, &UV, &PDM, &PIPENV, &PNPM, &BUN];

/// Every manager's variables, so whichever the command starts is pointed at the firewall.
pub fn variables(proxy: &str) -> Vec<(String, String)> {
    let env = MANAGERS.iter().flat_map(|manager| manager.env);
    env.map(|(key, value)| (key.to_string(), expand(value, proxy))).collect()
}

pub fn arguments(proxy: &str, manager: &Manager, typed: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for args in manager.args {
        let wanted =
            args.when.is_empty() || typed.iter().any(|arg| args.when.contains(&arg.as_str()));
        if wanted {
            out.extend(args.flags.iter().map(|flag| expand(flag, proxy)));
        }
    }
    out
}

fn expand(value: &str, proxy: &str) -> String {
    value.replace(PROXY, proxy)
}
