use firewall::aliasing::managers::*;
use firewall::Firewall;

#[test]
fn recipes_expand_into_the_environment() {
    let var = |name: &str, value: &str| (name.to_string(), value.to_string());
    let npm = variables("http://127.0.0.1:9000", &NPM);
    assert!(npm.contains(&var("npm_config_proxy", "http://127.0.0.1:9000")));
    assert!(npm.contains(&var("npm_config_registry", "http://registry.npmjs.org/")));
    let gem = arguments("http://127.0.0.1:9000", &GEM, &["install".to_string()]);
    assert_eq!(gem, ["--clear-sources", "--source", "http://rubygems.org/"]);
    assert!(arguments("http://127.0.0.1:9000", &GEM, &["sources".to_string()]).is_empty());
}

/// A manager pointed at a host with no registry would be aliased but never screened.
#[tokio::test]
async fn every_overridden_registry_is_known() {
    let hosts = Firewall::default().hosts();
    for manager in MANAGERS {
        let values = manager.env.iter().map(|(_, value)| *value);
        let flags = manager.args.iter().flat_map(|args| args.flags.iter().copied());
        for value in values.chain(flags) {
            for (_, after) in value.match_indices("http://").map(|(i, _)| value.split_at(i + 7)) {
                let host = after.split(['/', '"']).next().unwrap_or(after);
                assert!(hosts.contains(&host), "{} points at {host}", manager.command);
            }
        }
    }
}
