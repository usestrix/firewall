use firewall::config::path;
use firewall::policies::filters::consult;
use firewall::policies::{screen, Package};
use firewall::{Firewall, FirewallConfig};

#[test]
fn a_file_only_has_to_set_what_it_changes() {
    let config: FirewallConfig = serde_json::from_str(r#"{"fail_open": false}"#).expect("parses");
    assert!(!config.fail_open);
    assert_eq!(config.port, firewall::DEFAULT_PORT);
}

#[test]
fn a_misspelled_setting_is_an_error() {
    assert!(serde_json::from_str::<FirewallConfig>(r#"{"fail-open": false}"#).is_err());
}

#[test]
fn the_config_lives_under_the_config_directory() {
    let path = path().expect("a home directory");
    assert!(path.ends_with("config.json"), "{}", path.display());
}

#[tokio::test]
async fn an_allowed_version_skips_the_filters() {
    // An unreachable denylist would otherwise leave the package unchecked.
    let config = r#"{"allow": {"go": [{"name": "golang.org/x/net", "version": "v0.20.0"}]}, "denylist": {"base": "http://127.0.0.1:1"}}"#;
    let firewall = Firewall::new(serde_json::from_str(config).expect("parses"));
    let (registry, _) = firewall.match_on("/go/golang.org/x/net/@v/list", |r| r.prefix).expect("go");
    let pkg = |version: &str| Package { name: "golang.org/x/net".into(), version: Some(version.into()) };
    assert!(consult(&firewall, registry, &pkg("0.20.0")).await.is_none());
    assert!(consult(&firewall, registry, &pkg("0.21.0")).await.is_some());
}

#[tokio::test]
async fn failing_closed_blocks_what_could_not_be_checked() {
    let config = r#"{"fail_open": false, "denylist": {"base": "http://127.0.0.1:1"}}"#;
    let firewall = Firewall::new(serde_json::from_str(config).expect("parses"));
    let url = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
    let blocked = screen(url, &firewall).await.unwrap_or_default();
    assert!(blocked.contains("could not be checked"), "{blocked:?}");
}
