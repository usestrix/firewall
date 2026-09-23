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
    // A prerelease tag that starts with a digit is the one the old pattern lost.
    assert_eq!(
        at("/npm/@accordproject/markdown-cli/-/markdown-cli-0.16.20-20251124101628.tgz"),
        (Some("@accordproject/markdown-cli".into()), Some("0.16.20-20251124101628".into()), false)
    );
    // Names may begin with a hyphen; 20 on the list do.
    assert_eq!(
        at("/npm/-john-wick-4/-/-john-wick-4-1.0.0.tgz"),
        (Some("-john-wick-4".into()), Some("1.0.0".into()), false)
    );
}

#[tokio::test]
async fn pypi_paths() {
    assert_eq!(at("/pypi/simple/urllib3/"), (Some("urllib3".into()), None, true));
    // A wheel escapes the name into the filename, so it comes back PEP 503 normalised.
    assert_eq!(
        at("/pypi-files/packages/ab/cd/ef/zope_interface-5.4.0-cp39-cp39-macosx.whl"),
        (Some("zope-interface".into()), Some("5.4.0".into()), false)
    );
    assert_eq!(
        at("/pypi-files/packages/ab/cd/ef/urllib3-2.0.7-py3-none-any.whl.metadata"),
        (Some("urllib3".into()), Some("2.0.7".into()), false)
    );
    assert_eq!(
        at("/pypi-files/packages/ab/cd/ef/django-allauth-0.54.0.tar.gz"),
        (Some("django-allauth".into()), Some("0.54.0".into()), false)
    );
    assert_eq!(at("/pypi/simple/Zope.Interface/"), (Some("zope-interface".into()), None, true));
}

#[tokio::test]
async fn gem_paths() {
    assert_eq!(
        at("/gem/gems/activerecord-jdbc-adapter-1.3.0.gem"),
        (Some("activerecord-jdbc-adapter".into()), Some("1.3.0".into()), false)
    );
    // A platform suffix is not part of the version.
    assert_eq!(
        at("/gem/gems/nokogiri-1.13.0-x86_64-linux.gem"),
        (Some("nokogiri".into()), Some("1.13.0".into()), false)
    );
    assert_eq!(at("/gem/info/rails"), (Some("rails".into()), None, false));
}

#[tokio::test]
async fn go_paths() {
    // Capitals travel as !<lowercase>, and the v is not part of the version.
    assert_eq!(
        at("/go/github.com/!buffer!zone!corp/config-loader/@v/v1.8.0-rc1.zip"),
        (Some("github.com/BufferZoneCorp/config-loader".into()), Some("1.8.0-rc1".into()), false)
    );
    assert_eq!(
        at("/go/github.com/gorilla/mux/@v/list"),
        (Some("github.com/gorilla/mux".into()), None, false)
    );
}
