use firewall::aliasing::managers::*;
use firewall::aliasing::Invocation;
use firewall::Firewall;

#[test]
fn arguments_after_a_double_dash_reach_the_program() {
    let typed = ["cargo", "run", "--", "--release"].map(String::from);
    let invocation = Invocation::parse(typed.into_iter()).expect("cargo is a manager");
    let args = invocation.arguments("http://127.0.0.1:9000");
    assert_eq!(args.first().map(String::as_str), Some("run"));
    assert_eq!(args[args.len() - 2..], ["--", "--release"]);
    assert!(Invocation::parse(["serve".to_string()].into_iter()).is_none());
}

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
