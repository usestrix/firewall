use firewall::Firewall;

fn at(path: &str) -> (Option<String>, Option<String>, bool) {
    let firewall = Firewall::default();
    let (registry, rest) = firewall.match_path(path).expect("no registry matched");
    let resolved = firewall.resolve(registry, rest);
    let (name, version) = match resolved.pkg {
        Some(p) => (Some(p.name), p.version),
        None => (None, None),
    };
    (name, version, resolved.rewrite.is_some())
}

#[tokio::test]
async fn every_pattern_compiles() {
    Firewall::default();
}

#[tokio::test]
async fn hosts_come_from_upstreams() {
    let firewall = Firewall::default();
    assert!(firewall.hosts().contains(&"files.pythonhosted.org"));
    assert!(firewall.is_index_url("https://pypi.org/simple/six/"));
    assert!(!firewall.is_index_url("https://files.pythonhosted.org/six.whl.metadata"));
}

#[tokio::test]
async fn cargo_paths() {
    assert_eq!(at("/cargo/index/ru/st/rustdecimal"), (Some("rustdecimal".into()), None, false));
    assert_eq!(at("/cargo/index/3/s/syn"), (Some("syn".into()), None, false));
    assert_eq!(at("/cargo/index/config.json"), (None, None, true));
    assert_eq!(
        at("/cargo-dl/left-pad/1.0.1/download"),
        (Some("left-pad".into()), Some("1.0.1".into()), false)
    );
}

#[tokio::test]
async fn npm_paths() {
    assert_eq!(at("/npm/left-pad"), (Some("left-pad".into()), None, true));
    assert_eq!(at("/npm/caf%C3%A9"), (Some("café".into()), None, true));
    assert_eq!(at("/npm/@scope%2fpkg"), (Some("@scope/pkg".into()), None, true));
    assert_eq!(
        at("/npm/left-pad/-/left-pad-1.0.1.tgz"),
        (Some("left-pad".into()), Some("1.0.1".into()), false)
    );
    assert_eq!(
        at("/npm/@scope/pkg/-/pkg-2.0.0-beta.1.tgz"),
        (Some("@scope/pkg".into()), Some("2.0.0-beta.1".into()), false)
    );
}

#[tokio::test]
async fn pypi_paths() {
    assert_eq!(at("/pypi/simple/urllib3/"), (Some("urllib3".into()), None, true));
    assert_eq!(at("/pypi-files/packages/ab/cd/ef/urllib3-2.0.7.tar.gz"), (None, None, false));
}
