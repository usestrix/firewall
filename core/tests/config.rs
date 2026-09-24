use firewall::config::path;
use firewall::FirewallConfig;

#[test]
fn a_file_only_has_to_set_what_it_changes() {
    let config: FirewallConfig = serde_json::from_str(r#"{"fail_open": false}"#).expect("parses");
    assert!(!config.fail_open);
    assert_eq!(config.port, firewall::DEFAULT_PORT);
    assert_eq!(config.denylist.token, FirewallConfig::default().denylist.token);
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
