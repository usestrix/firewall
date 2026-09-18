fn main() {
    firewall::init_logging();
    let requested = std::env::args().nth(1).and_then(|p| p.parse().ok()).unwrap_or(0);
    let port = firewall::aliasing::spawn(requested).expect("could not bind");
    println!("forward proxy on http://localhost:{port}");
    loop {
        std::thread::park();
    }
}
