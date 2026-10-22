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

#[test]
fn a_later_file_wins_and_allow_lists_add_up() {
    let dir = std::env::temp_dir().join(format!("firewall-layers-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let user = dir.join("user.json");
    let system = dir.join("system.json");
    std::fs::write(&user, r#"{"min_age_hours": 1, "fail_open": false, "allow": {"npm": [{"name": "a"}]}}"#).expect("write");
    std::fs::write(&system, r#"{"min_age_hours": 24, "allow": {"npm": [{"name": "b"}]}}"#).expect("write");
    let missing = dir.join("missing.json");
    let config = FirewallConfig::load_from(&[user, system, missing]).expect("loads");
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(config.min_age_hours, 24);
    assert!(!config.fail_open);
    let names: Vec<&str> = config.allow["npm"].iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["a", "b"]);
}

#[tokio::test]
async fn an_allowed_version_is_still_checked_for_malware() {
    // The unreachable denylist shows that it still runs.
    let config = r#"{"allow": {"go": [{"name": "golang.org/x/net", "version": "v0.20.0"}]}, "denylist": {"base": "http://127.0.0.1:1"}}"#;
    let firewall = Firewall::new(serde_json::from_str(config).expect("parses"));
    let (registry, _) = firewall.match_on("/go/golang.org/x/net/@v/list", |r| r.prefix).expect("go");
    let pkg = Package { name: "golang.org/x/net".into(), version: Some("0.20.0".into()) };
    let verdict = consult(&firewall, registry, &pkg).await;
    assert_eq!(verdict.map(|(filter, _)| filter), Some("denylist"));
}

#[tokio::test]
async fn failing_closed_blocks_what_could_not_be_checked() {
    let config = r#"{"fail_open": false, "denylist": {"base": "http://127.0.0.1:1"}}"#;
    let firewall = Firewall::new(serde_json::from_str(config).expect("parses"));
    let url = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
    let blocked = screen(url, &firewall).await.unwrap_or_default();
    assert!(blocked.contains("could not be checked"), "{blocked:?}");
}

#[test]
fn allowing_keeps_the_rest_of_the_file() {
    let path = std::env::temp_dir().join(format!("firewall-allow-{}.json", std::process::id()));
    std::fs::write(&path, r#"{"fail_open": false}"#).expect("write");
    for _ in 0..2 {
        firewall::config::allow(&path, "npm", "left-pad", Some("1.3.0")).expect("allow");
    }
    let text = std::fs::read_to_string(&path).expect("read");
    std::fs::remove_file(&path).ok();
    let config: FirewallConfig = serde_json::from_str(&text).expect("parses");
    assert!(!config.fail_open);
    assert_eq!(config.allow["npm"].len(), 1);
    assert_eq!(config.allow["npm"][0].version.as_deref(), Some("1.3.0"));
}
