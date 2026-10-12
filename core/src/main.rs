use bpaf::{any, choice, pure, OptionParser, Parser};
use firewall::aliasing::{self, Invocation, Manager, MANAGERS};
use firewall::{config, proxy, telemetry, FirewallConfig};
use std::io::ErrorKind;
use std::path::Path;
use std::process::exit;
use tracing::{error, info};

enum SubCommand {
    Serve,
    Run(Invocation),
}

fn main() {
    // bpaf swallows a `--` the manager needs to see, so a manager's arguments skip it.
    let args: Option<Vec<String>> =
        std::env::args_os().skip(1).map(|arg| arg.into_string().ok()).collect();
    if let Some(invocation) = args.and_then(|args| Invocation::parse(args.into_iter())) {
        firewall::init_logging("warn");
        run(invocation)
    }
    match options().run() {
        SubCommand::Serve => {
            firewall::init_logging("info");
            serve()
        }
        SubCommand::Run(invocation) => {
            firewall::init_logging("warn");
            run(invocation)
        }
    }
}

fn options() -> OptionParser<SubCommand> {
    let program = program_name();
    let footer = format!(
        "Run a package manager through {program} to screen what it installs:\n   \
         {program} npm install left-pad\n \n \
         Alias it to screen every install without changing how you type:\n   \
         alias npm='{program} npm'"
    );
    let serve = pure(())
        .map(|()| SubCommand::Serve)
        .to_options()
        .descr("Serve a local registry for package managers configured to use it")
        .command("serve");

    let mut commands: Vec<_> = MANAGERS
        .iter()
        .map(|manager| package(manager, &program).boxed())
        .collect();
    commands.push(serve.boxed());
    choice(commands)
        .to_options()
        .descr("Screens package downloads before they reach your machine")
        .footer(Box::leak(footer.into_boxed_str()) as &str)
        .fallback_to_usage()
}

fn package(manager: &'static Manager, program: &str) -> impl Parser<SubCommand> {
    let name = manager.command;
    let descr = format!("Run {name} with downloads screened: {program} {name} ARGS...");
    any::<String, String, _>("ARGS", Some)
        .many()
        .map(move |args| SubCommand::Run(Invocation::new(manager, args)))
        .to_options()
        .descr(Box::leak(descr.into_boxed_str()) as &str)
        .command(name)
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

fn run(invocation: Invocation) -> ! {
    let command = invocation.manager.command;
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
    println!("  npm    npm_config_registry={base}/npm/");
    println!("  pip    PIP_INDEX_URL={base}/pypi/simple/");
    println!("  cargo  [source.crates-io] replace-with = \"firewall\"");
    println!("         [source.firewall] registry = \"sparse+{base}/cargo/index/\"\n");
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
    match Path::new(&arg).file_name() {
        Some(name) => name.to_string_lossy().into_owned(),
        None => "firewall".into(),
    }
}
