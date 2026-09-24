mod probe;

use firewall::aliasing;
use firewall::FirewallConfig;
use probe::Outcome;

fn main() -> std::io::Result<()> {
    firewall::init_logging("info");
    let port = aliasing::spawn(0, FirewallConfig::load()?)?;
    println!("firewall proxy on {}\n", firewall::local_url(port, ""));

    let results = probe::all(port);
    println!();
    let mut failed = 0;
    for (name, outcome) in &results {
        println!("{:<6} {}", name, outcome.label());
        failed += usize::from(*outcome == Outcome::Failed);
    }
    std::process::exit(i32::from(failed > 0))
}
