use bpaf::{any, construct, long, short, OptionParser, Parser};
use firewall::aliasing::{self, Invocation, Manager};
use firewall::{proxy, Config, DEFAULT_PORT};
use std::io::ErrorKind;

enum SubCommand {
    Serve(Config),
    Run(Invocation),
}

fn options() -> OptionParser<SubCommand> {
    let serve = construct!(SubCommand::Serve(config()))
        .to_options()
        .descr("Serve the registry proxy package managers point at")
        .command("serve");

    let npm = package(&aliasing::NPM);
    let pip = package(&aliasing::PIP);
    let pip3 = package(&aliasing::PIP3);
    let cargo = package(&aliasing::CARGO);
    let go = package(&aliasing::GO);
    let gem = package(&aliasing::GEM);
    let uv = package(&aliasing::UV);
    let pdm = package(&aliasing::PDM);
    let pipenv = package(&aliasing::PIPENV);
    let pnpm = package(&aliasing::PNPM);
    let bun = package(&aliasing::BUN);

    construct!([serve, npm, pip, pip3, cargo, go, gem, uv, pdm, pipenv, pnpm, bun])
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

fn config() -> impl Parser<Config> {
    let port = short('p')
        .long("port")
        .help(leak(format!("Port to listen on (default {DEFAULT_PORT})")))
        .argument::<u16>("PORT")
        .fallback(DEFAULT_PORT);
    let fail_open = long("fail-closed")
        .help("Block when the OSV lookup fails, instead of allowing")
        .switch()
        .map(|closed| !closed);
    construct!(Config { port, fail_open })
}

fn main() {
    match options().run() {
        SubCommand::Serve(config) => serve(config),
        SubCommand::Run(invocation) => run(invocation),
    }
}

fn serve(config: Config) -> ! {
    let port = config.port;
    banner(&config);
    match proxy::serve(config) {
        Ok(()) => std::process::exit(0),
        Err(e) if e.kind() == ErrorKind::AddrInUse => {
            fail(&format!("port {port} is in use, pick another with --port"))
        }
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
            fail(&format!("not allowed to listen on port {port}"))
        }
        Err(e) => fail(&format!("could not serve on port {port}: {e}")),
    }
}

fn run(invocation: Invocation) -> ! {
    let port = match aliasing::spawn(0) {
        Ok(port) => port,
        Err(e) => fail(&format!("could not start the proxy: {e}")),
    };
    println!("firewall proxy on {}", firewall::local_url(port, ""));
    println!("logging every intercepted URL to {}\n", aliasing::LOG_PATH);

    match aliasing::run(port, &invocation, None) {
        Ok(code) => std::process::exit(code),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            eprintln!("firewall: {} is not installed", invocation.manager.command);
            std::process::exit(127)
        }
        Err(e) => fail(&format!("could not run {}: {e}", invocation.manager.command)),
    }
}

fn fail(message: &str) -> ! {
    eprintln!("firewall: {message}");
    std::process::exit(1)
}

fn banner(config: &Config) {
    let base = config.local_url("");
    println!("firewall registry proxy on {base}");
    println!(
        "policy: {} on OSV lookup failure\n",
        if config.fail_open { "allow" } else { "block" }
    );
    println!("point your package managers at it:");
    println!("  npm    npm_config_registry={base}/npm/");
    println!("  pip    PIP_INDEX_URL={base}/pypi/simple/");
    println!("  cargo  [source.crates-io] replace-with=\"fw\"");
    println!("         [source.fw] registry=\"sparse+{base}/cargo/index/\"\n");
}
