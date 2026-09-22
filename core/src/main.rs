use bpaf::{any, choice, pure, OptionParser, Parser};
use firewall::aliasing::{self, Invocation, Manager, MANAGERS};
use firewall::{config, proxy, FirewallConfig};
use std::io::ErrorKind;
use tracing::{error, info};

enum SubCommand {
    Serve,
    Run(Invocation),
}

fn options() -> OptionParser<SubCommand> {
    let serve = pure(())
        .map(|()| SubCommand::Serve)
        .to_options()
        .descr("Serve the registry proxy package managers point at")
        .command("serve");

    let managers = MANAGERS.iter().map(|manager| package(manager).boxed());
    choice(std::iter::once(serve.boxed()).chain(managers))
        .to_options()
        .descr("Screens package downloads before they reach your machine")
        .fallback_to_usage()
}

fn package(manager: &'static Manager) -> impl Parser<SubCommand> {
    let name = manager.command;
    rest()
        .map(move |args| SubCommand::Run(Invocation::new(manager, args)))
        .to_options()
        .descr(leak(format!("Run {name} through the proxy: firewall {name} ARGS...")))
        .command(name)
}

fn rest() -> impl Parser<Vec<String>> {
    any::<String, String, _>("ARGS", Some).many()
}

fn leak(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

fn main() {
    firewall::init_logging();
    match options().run() {
        SubCommand::Serve => serve(),
        SubCommand::Run(invocation) => run(invocation),
    }
}

fn load() -> FirewallConfig {
    match FirewallConfig::load() {
        Ok(config) => config,
        Err(e) => fail(&format!("could not read the config: {e}")),
    }
}

fn serve() -> ! {
    let config = load();
    let port = config.port;
    banner(&config);
    match proxy::serve(config) {
        Ok(()) => std::process::exit(0),
        Err(e) if e.kind() == ErrorKind::AddrInUse => {
            let where_ = config::path().map_or("the config".into(), |p| p.display().to_string());
            fail(&format!("port {port} is in use, set another in {where_}"))
        }
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
            fail(&format!("not allowed to listen on port {port}"))
        }
        Err(e) => fail(&format!("could not serve on port {port}: {e}")),
    }
}

fn run(invocation: Invocation) -> ! {
    let port = match aliasing::spawn(0, load()) {
        Ok(port) => port,
        Err(e) => fail(&format!("could not start the proxy: {e}")),
    };
    info!(proxy = %firewall::local_url(port, ""), "forward proxy listening");

    match aliasing::run(port, &invocation, None) {
        Ok(code) => std::process::exit(code),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            error!("{} is not installed", invocation.manager.command);
            std::process::exit(127)
        }
        Err(e) => fail(&format!("could not run {}: {e}", invocation.manager.command)),
    }
}

fn fail(message: &str) -> ! {
    error!("{message}");
    std::process::exit(1)
}

fn banner(config: &FirewallConfig) {
    let base = config.local_url("");
    println!("firewall registry proxy on {base}");
    println!(
        "policy: {} when a package cannot be checked\n",
        if config.fail_open { "allow" } else { "block" }
    );
    println!("point your package managers at it:");
    println!("  npm    npm_config_registry={base}/npm/");
    println!("  pip    PIP_INDEX_URL={base}/pypi/simple/");
    println!("  cargo  [source.crates-io] replace-with=\"fw\"");
    println!("         [source.fw] registry=\"sparse+{base}/cargo/index/\"\n");
}
