use clap::{Arg, Command};
use firewall::aliasing::{self, Invocation, MANAGERS};
use firewall::{config, proxy, telemetry, FirewallConfig};
use std::io::ErrorKind;
use std::path::Path;
use std::process::exit;
use tracing::{error, info};

fn main() {
    let matches = options().get_matches();
    if matches.subcommand_matches("serve").is_some() {
        firewall::init_logging("info");
        serve()
    }
    if matches.subcommand_matches("uninstall").is_some() {
        firewall::init_logging("info");
        uninstall()
    }
    let mut command = matches.get_many::<String>("COMMAND").unwrap().cloned();
    let program = command.next().unwrap();
    firewall::init_logging("warn");
    run(Invocation::new(program, command.collect()))
}

fn options() -> Command {
    let program = program_name();
    let managers: Vec<_> = MANAGERS.iter().map(|manager| manager.command).collect();
    let footer = format!(
        "Run a command through {program} to screen what it installs:\n  \
         {program} npm install left-pad\n\n\
         Alias it to screen every install without changing how you type:\n  \
         {}\n\n\
         Supported package managers: {}",
        alias(&program),
        managers.join(", ")
    );
    Command::new("firewall")
        .bin_name(&program)
        .about("Screens package downloads before they reach your machine")
        .after_help(footer)
        .arg_required_else_help(true)
        .args_conflicts_with_subcommands(true)
        .subcommand(
            Command::new("serve")
                .about("Serve a local registry for package managers configured to use it"),
        )
        // Run as root by the macOS app's uninstall.
        .subcommand(Command::new("uninstall").hide(true))
        .arg(
            Arg::new("COMMAND")
                .help("A command to run with its package downloads screened")
                .num_args(1..)
                .trailing_var_arg(true)
                .allow_hyphen_values(true),
        )
}

fn serve() -> ! {
    let config = load();
    let port = config.port;
    print_setup(&config);
    match proxy::serve(config) {
        Ok(()) => exit(0),
        Err(e) if e.kind() == ErrorKind::AddrInUse => {
            let location = config::path().map_or("the config".into(), |p| p.display().to_string());
            fail(
                "port",
                &format!("port {port} is in use, set another in {location}"),
            )
        }
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
            fail("port", &format!("not allowed to listen on port {port}"))
        }
        Err(e) => fail("serve", &format!("could not serve on port {port}: {e}")),
    }
}

fn uninstall() -> ! {
    match firewall::os::uninstall() {
        Ok(()) => exit(0),
        Err(e) => fail("uninstall", &format!("could not uninstall: {e}")),
    }
}

fn run(invocation: Invocation) -> ! {
    let command = &invocation.program;
    let port = match aliasing::spawn(0, load()) {
        Ok(port) => port,
        Err(e) => fail("spawn", &format!("could not start the firewall: {e}")),
    };
    info!(url = %firewall::local_url(port, ""), "firewall listening");

    let result = aliasing::run(port, &invocation, None);
    telemetry::flush();
    match result {
        Ok(code) => exit(code),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            error!("{command} is not installed");
            exit(127)
        }
        Err(e) => fail("run", &format!("could not run {command}: {e}")),
    }
}

fn print_setup(config: &FirewallConfig) {
    let base = config.local_url("");
    println!("Firewall listening on {base}\n");
    println!("Point your package managers at it:");
    println!("  npm    {}", variable("npm_config_registry", &format!("{base}/npm/")));
    println!("  pip    {}", variable("PIP_INDEX_URL", &format!("{base}/pypi/simple/")));
    println!("  cargo  [source.crates-io] replace-with = \"firewall\"");
    println!("         [source.firewall] registry = \"sparse+{base}/cargo/index/\"\n");
}

fn alias(program: &str) -> String {
    if cfg!(windows) {
        // Set-Alias cannot carry arguments, so a function stands in.
        format!(
            "PowerShell:  function npm {{ {program} npm @args }}\n  \
             cmd:         doskey npm={program} npm $*"
        )
    } else {
        format!("alias npm='{program} npm'")
    }
}

fn variable(key: &str, value: &str) -> String {
    if cfg!(windows) {
        format!("$env:{key} = \"{value}\"")
    } else {
        format!("{key}={value}")
    }
}

fn load() -> FirewallConfig {
    match FirewallConfig::load() {
        Ok(config) => config,
        Err(e) => fail("config", &format!("could not read the config: {e}")),
    }
}

fn fail(kind: &'static str, message: &str) -> ! {
    error!("{message}");
    telemetry::error(kind);
    telemetry::flush();
    exit(1)
}

fn program_name() -> String {
    let arg = std::env::args_os().next().unwrap_or_default();
    // Without `.exe` on Windows, which is how it is typed.
    let path = Path::new(&arg);
    match if cfg!(windows) { path.file_stem() } else { path.file_name() } {
        Some(name) => name.to_string_lossy().into_owned(),
        None => "firewall".into(),
    }
}
