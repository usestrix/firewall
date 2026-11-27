use firewall::config::{path, AllowedPackage};
use firewall::policies::filters::org::Org;
use firewall::policies::filters::{consult, Filter, Verdict};
use firewall::policies::registries::BUILT_IN;
use firewall::policies::{screen, Package};
use firewall::{Firewall, FirewallConfig};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread::JoinHandle;

#[test]
fn a_file_only_has_to_set_what_it_changes() {
    let config: FirewallConfig = serde_json::from_str(r#"{"fail_open": false}"#).expect("parses");
    assert!(!config.fail_open);
    assert_eq!(config.port.get(), firewall::DEFAULT_PORT);
}

#[test]
fn a_misspelled_setting_is_an_error() {
    assert!(serde_json::from_str::<FirewallConfig>(r#"{"fail-open": false}"#).is_err());
}

#[test]
fn nonsense_values_are_errors() {
    let file = std::env::temp_dir().join(format!("firewall-nonsense-{}.json", std::process::id()));
    for bad in [
        r#"{"allow": {"nmp": [{"name": "left-pad"}]}}"#,
        r#"{"denylist": {"poll_secs": 0}}"#,
        r#"{"denylist": {"base": "raw.githubusercontent.com/usestrix"}}"#,
        r#"{"denylist": {"revision": "https://"}}"#,
        r#"{"port": 0}"#,
        r#"{"min_age_hours": 18446744073709551615}"#,
        r#"{"registries": {"npm": ["http://npm.example.com/"]}}"#,
        r#"{"registries": {"npm": ["https://npm.example.com"]}}"#,
        r#"{"registries": {"npm": ["https://npm.example.com:8443/"]}}"#,
        r#"{"registries": {"npm": ["https://user@npm.example.com/"]}}"#,
        r#"{"registries": {"npm": ["https://npm.example.com/?a=/"]}}"#,
    ] {
        std::fs::write(&file, bad).expect("write");
        assert!(FirewallConfig::load_from(std::slice::from_ref(&file)).is_err(), "{bad}");
    }
    std::fs::remove_file(&file).ok();
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
    std::fs::write(
        &user,
        r#"{"min_age_hours": 1, "fail_open": false, "allow": {"npm": [{"name": "a"}]}}"#,
    )
    .expect("write");
    std::fs::write(&system, r#"{"min_age_hours": 24, "allow": {"npm": [{"name": "b"}]}}"#)
        .expect("write");
    let missing = dir.join("missing.json");
    let config = FirewallConfig::load_from(&[user, system, missing]).expect("loads");
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(config.min_age_hours, 24);
    assert!(!config.fail_open);
    let names: Vec<&str> = config.allow["npm"].iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["a", "b"]);
}

#[tokio::test]
async fn a_mirror_is_screened_like_the_registry_it_copies() {
    let config = r#"{"registries": {"npm": ["https://npm.example.com/"]}}"#;
    let firewall = Firewall::new(serde_json::from_str(config).expect("parses"));
    assert!(firewall.hosts().contains(&"npm.example.com"));
    let url = "https://npm.example.com/left-pad/-/left-pad-1.3.0.tgz";
    let (registry, rest) = firewall.match_on(url, |r| r.upstream).expect("the mirror");
    assert_eq!(
        firewall.resolve(registry, rest).pkg.map(|p| p.label()),
        Some("left-pad@1.3.0".into())
    );
    let unknown = std::env::temp_dir().join(format!("firewall-mirror-{}.json", std::process::id()));
    std::fs::write(&unknown, r#"{"registries": {"nmp": ["https://npm.example.com/"]}}"#)
        .expect("write");
    let loaded = FirewallConfig::load_from(std::slice::from_ref(&unknown));
    std::fs::remove_file(&unknown).ok();
    assert!(loaded.is_err());
}

#[tokio::test]
async fn a_pypi_mirror_screens_the_files_it_serves() {
    let config = r#"{"registries": {"pypi": ["https://art.example.com/pypi/"]}}"#;
    let firewall = Firewall::new(serde_json::from_str(config).expect("parses"));
    let url = "https://art.example.com/pypi/packages/ab/cd/six-1.16.0-py2.py3-none-any.whl";
    let (registry, rest) = firewall.match_on(url, |r| r.upstream).expect("the mirror");
    assert_eq!(firewall.resolve(registry, rest).pkg.map(|p| p.label()), Some("six@1.16.0".into()));
}

#[tokio::test]
async fn an_allowed_version_is_still_checked_for_malware() {
    // The unreachable denylist shows that it still runs.
    let config = r#"{"allow": {"go": [{"name": "golang.org/x/net", "version": "v0.20.0"}]}, "denylist": {"base": "http://127.0.0.1:1"}}"#;
    let firewall = Firewall::new(serde_json::from_str(config).expect("parses"));
    let (registry, _) =
        firewall.match_on("/go/golang.org/x/net/@v/list", |r| r.prefix).expect("go");
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

#[tokio::test]
async fn lifting_the_age_check_still_checks_for_malware() {
    let config = r#"{"denylist": {"base": "http://127.0.0.1:1"}}"#;
    let firewall = Firewall::new(serde_json::from_str(config).expect("parses"));
    let (registry, _) =
        firewall.match_on("/go/golang.org/x/net/@v/list", |r| r.prefix).expect("go");
    let pkg = Package { name: "golang.org/x/net".into(), version: Some("0.20.0".into()) };
    firewall.lift_age_check("go", AllowedPackage { name: pkg.name.clone(), version: None }, None);
    let (filter, _) = consult(&firewall, registry, &pkg).await.expect("the denylist still runs");
    assert_eq!(filter, "denylist");
}

#[test]
fn allowing_keeps_the_rest_of_the_file() {
    let path = std::env::temp_dir().join(format!("firewall-allow-{}.json", std::process::id()));
    std::fs::write(&path, r#"{"fail_open": false}"#).expect("write");
    for _ in 0..2 {
        firewall::config::allow(&path, "npm", "left-pad", "1.3.0").expect("allow");
    }
    let text = std::fs::read_to_string(&path).expect("read");
    std::fs::remove_file(&path).ok();
    let config: FirewallConfig = serde_json::from_str(&text).expect("parses");
    assert!(!config.fail_open);
    assert_eq!(config.allow["npm"].len(), 1);
    assert_eq!(config.allow["npm"][0].version.as_deref(), Some("1.3.0"));
}

#[tokio::test]
async fn the_organizations_settings_win_and_its_allow_list_adds_up() {
    let (api_url, server) = serve_once(
        r#"{"min_age_hours": 72, "fail_open": null, "allow": {"npm": [{"name": "left-pad"}]}}"#,
    );
    let local = r#"{"fail_open": false, "allow": {"npm": [{"name": "is-odd"}]}}"#;
    let mut config: FirewallConfig = serde_json::from_str(local).unwrap();
    config.api_key = Some("strix_test".into());
    config.api_url = api_url;

    let firewall = Firewall::new(config);
    let request = server.join().unwrap();
    assert!(request.starts_with("GET /api/v1/firewall/settings "));
    assert!(request.to_lowercase().contains("authorization: bearer strix_test"));
    assert_eq!(firewall.config.min_age_hours, 72);
    assert!(!firewall.config.fail_open);
    let allowed: Vec<&str> = firewall.config.allow["npm"].iter().map(|a| a.name.as_str()).collect();
    assert_eq!(allowed, ["is-odd", "left-pad"]);
}

#[tokio::test]
async fn an_organization_block_matches_names_as_the_registry_does() {
    let (api_url, server) = serve_once(
        r#"{"blocks": [{"id": "b1", "ecosystem": "pypi", "name": "Six", "version": null, "reason": "compromised"}]}"#,
    );
    let org = Org::new(api_url, "strix_test".into());
    let registry = |eco| BUILT_IN.iter().find(|r| r.eco == eco).expect(eco);
    let six = Package { name: "six".into(), version: Some("1.16.0".into()) };

    match org.check(registry("pypi"), &six).await {
        Verdict::Deny(reason) => assert_eq!(reason, "is blocked by your organization: compromised"),
        _ => panic!("not blocked"),
    }
    assert!(matches!(org.check(registry("npm"), &six).await, Verdict::Allow));
    assert!(server.join().unwrap().starts_with("GET /api/v1/firewall/blocks "));
}

/// Answers one request with `body` and hands back what was asked.
fn serve_once(body: &'static str) -> (String, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/api/v1", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0; 4096];
        let read = stream.read(&mut request).unwrap();
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(format!("{head}{body}").as_bytes()).unwrap();
        String::from_utf8_lossy(&request[..read]).into_owned()
    });
    (url, server)
}
