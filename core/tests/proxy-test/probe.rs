use firewall::aliasing::{self, Invocation, Manager, CARGO, GEM, GO, NPM, PIP, PIP3, UV};
use std::path::PathBuf;

struct Probe {
    manager: &'static Manager,
    args: &'static [&'static str],
    /// Clears any state a previous run left behind; returns the directory to run in.
    setup: Option<fn() -> Option<PathBuf>>,
}

const PIP_ARGS: &[&str] = &["download", "--no-deps", "--no-cache-dir", "-d", ".", "six"];

static PROBES: &[Probe] = &[
    Probe { manager: &NPM, args: &["view", "left-pad", "version"], setup: None },
    Probe { manager: &PIP, args: PIP_ARGS, setup: Some(|| scratch("fw-probe-pip")) },
    Probe { manager: &PIP3, args: PIP_ARGS, setup: Some(|| scratch("fw-probe-pip")) },
    // Cargo refuses search and info once crates-io is replaced, so this resolves a manifest.
    Probe { manager: &CARGO, args: &["fetch"], setup: Some(cargo) },
    Probe { manager: &GO, args: &["mod", "download", "github.com/pkg/errors"], setup: Some(go) },
    Probe {
        manager: &GEM,
        args: &["fetch", "rake", "-v", "13.0.6"],
        setup: Some(|| scratch("fw-probe-gem")),
    },
    Probe {
        manager: &UV,
        args: &["pip", "install", "--no-cache", "--target", ".", "--python", "python3", "six"],
        setup: Some(|| scratch("fw-probe-uv")),
    },
];

pub fn all(port: u16) -> Vec<(&'static str, Outcome)> {
    PROBES.iter().map(|probe| (probe.manager.command, run(probe, port))).collect()
}

fn run(probe: &Probe, port: u16) -> Outcome {
    let args = probe.args.iter().map(|arg| arg.to_string()).collect();
    let dir = probe.setup.and_then(|prepare| prepare());
    match aliasing::run(port, &Invocation::new(probe.manager.command.into(), args), dir.as_deref()) {
        Ok(0) => Outcome::Ok,
        Ok(_) => Outcome::Failed,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Outcome::Absent,
        Err(_) => Outcome::Failed,
    }
}

const GO_MOD: &str = "module fw-probe\n\ngo 1.21\n\nrequire github.com/pkg/errors v0.9.1\n";

fn go() -> Option<PathBuf> {
    let dir = scratch("fw-probe-go")?;
    std::fs::write(dir.join("go.mod"), GO_MOD).ok()?;
    Some(dir)
}

const MANIFEST: &str = "[package]\nname = \"fw-probe\"\nversion = \"0.0.0\"\n\
edition = \"2021\"\n\n[dependencies]\nleft-pad = \"1\"\n";

/// A scratch home, so a probe never reads a warm cache.
fn cargo() -> Option<PathBuf> {
    let home = std::env::temp_dir().join("fw-probe-cargo-home");
    let _ = std::fs::remove_dir_all(&home);
    std::env::set_var("CARGO_HOME", &home);
    let dir = scratch("fw-probe-cargo")?;
    std::fs::create_dir_all(dir.join("src")).ok()?;
    std::fs::write(dir.join("src/main.rs"), "fn main() {}\n").ok()?;
    std::fs::write(dir.join("Cargo.toml"), MANIFEST).ok()?;
    Some(dir)
}

/// Leftovers would be served from disk and the probe would pass without reaching the proxy.
fn scratch(name: &str) -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

#[derive(PartialEq)]
pub enum Outcome {
    Ok,
    Failed,
    Absent,
}

impl Outcome {
    pub fn label(&self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Failed => "FAILED",
            Outcome::Absent => "not installed",
        }
    }
}
