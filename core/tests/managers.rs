use firewall::aliasing::managers::*;
use firewall::aliasing::Invocation;
use firewall::{Firewall, FirewallConfig};

#[test]
fn arguments_after_a_double_dash_reach_the_program() {
    let typed = ["run", "--", "--release"].map(String::from).to_vec();
    let args = Invocation::new("cargo".into(), typed).arguments("http://127.0.0.1:9000", &FirewallConfig::default());
    assert_eq!(args.first().map(String::as_str), Some("run"));
    assert_eq!(args[args.len() - 2..], ["--", "--release"]);
}

#[test]
fn recipes_expand_into_the_environment() {
    let var = |name: &str, value: &str| (name.to_string(), value.to_string());
    let config = FirewallConfig::default();
    let npm = variables("http://127.0.0.1:9000", &config);
    assert!(npm.contains(&var("npm_config_proxy", "http://127.0.0.1:9000")));
    assert!(npm.contains(&var("npm_config_registry", "http://registry.npmjs.org/")));
    let gem = arguments("http://127.0.0.1:9000", &config, &GEM, &["install".to_string()]);
    assert_eq!(gem, ["--clear-sources", "--source", "http://rubygems.org/"]);
    assert!(arguments("http://127.0.0.1:9000", &config, &GEM, &["sources".to_string()]).is_empty());
}

#[test]
fn a_mirror_replaces_the_registry_it_copies() {
    let var = |name: &str, value: &str| (name.to_string(), value.to_string());
    let config = r#"{"registries": {"npm": ["https://npm.example.com/"], "pypi": ["https://art.example.com/pypi/"]}}"#;
    let env = variables("http://127.0.0.1:9000", &serde_json::from_str(config).expect("parses"));
    assert!(env.contains(&var("npm_config_registry", "http://npm.example.com/")));
    assert!(env.contains(&var("PIP_INDEX_URL", "http://art.example.com/pypi/simple")));
    assert!(env.contains(&var("PIP_TRUSTED_HOST", "art.example.com files.pythonhosted.org")));
}

#[test]
fn no_two_managers_set_a_variable_differently() {
    let mut seen = std::collections::HashMap::new();
    for manager in MANAGERS {
        for (key, value) in manager.env {
            let first = *seen.entry(key).or_insert(value);
            assert_eq!(first, value, "{} sets {key} differently", manager.command);
        }
    }
}

#[tokio::test]
async fn every_overridden_registry_is_known() {
    let config = FirewallConfig::default();
    let hosts = Firewall::default().hosts();
    let values = variables("", &config).into_iter().map(|(_, value)| value);
    let flags = MANAGERS.iter().flat_map(|manager| {
        let typed: Vec<String> = manager.args.iter().flat_map(|args| args.when).map(|arg| arg.to_string()).collect();
        arguments("", &config, manager, &typed)
    });
    for value in values.chain(flags) {
        for (_, after) in value.match_indices("http://").map(|(i, _)| value.split_at(i + 7)) {
            let host = after.split(['/', '"']).next().unwrap_or(after);
            assert!(hosts.contains(&host), "{value} points at {host}");
        }
    }
}
