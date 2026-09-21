use firewall::FirewallState;

fn at(path: &str) -> (Option<String>, Option<String>, bool) {
    let state = FirewallState::default();
    let (registry, rest) = state.match_path(path).expect("no registry matched");
    let resolved = state.resolve(registry, rest);
    let (name, version) = match resolved.pkg {
        Some(p) => (Some(p.name), p.version),
        None => (None, None),
    };
    (name, version, resolved.rewrite.is_some())
}

#[test]
fn every_pattern_compiles() {
    FirewallState::default();
}

#[test]
fn hosts_come_from_upstreams() {
    let state = FirewallState::default();
    assert!(state.hosts().contains(&"files.pythonhosted.org"));
    assert!(state.is_index_url("https://pypi.org/simple/six/"));
    assert!(!state.is_index_url("https://files.pythonhosted.org/six.whl.metadata"));
}

#[test]
fn cargo_paths() {
    assert_eq!(at("/cargo/index/ru/st/rustdecimal"), (Some("rustdecimal".into()), None, false));
    assert_eq!(at("/cargo/index/3/s/syn"), (Some("syn".into()), None, false));
    assert_eq!(at("/cargo/index/config.json"), (None, None, true));
    assert_eq!(
        at("/cargo-dl/left-pad/1.0.1/download"),
        (Some("left-pad".into()), Some("1.0.1".into()), false)
    );
}

#[test]
fn npm_paths() {
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

#[test]
fn pypi_paths() {
    assert_eq!(at("/pypi/simple/urllib3/"), (Some("urllib3".into()), None, true));
    assert_eq!(at("/pypi-files/packages/ab/cd/ef/urllib3-2.0.7.tar.gz"), (None, None, false));
}
