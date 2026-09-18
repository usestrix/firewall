mod probe;

use firewall::aliasing;
use probe::Outcome;

fn main() -> std::io::Result<()> {
    let port = aliasing::spawn(0)?;
    println!("firewall proxy on {}", firewall::local_url(port, ""));
    println!("logging every intercepted URL to {}\n", aliasing::LOG_PATH);

    let results = probe::all(port);
    println!();
    let mut failed = 0;
    for (name, outcome) in &results {
        println!("{:<6} {}", name, outcome.label());
        failed += usize::from(*outcome == Outcome::Failed);
    }
    std::process::exit(i32::from(failed > 0))
}
