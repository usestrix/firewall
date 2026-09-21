use firewall::policies::filters::osv::mal_ids;
use firewall::policies::screen;
use firewall::FirewallState;
use rama::rt::blocking::Runtime;
use serde_json::json;

#[test]
#[ignore = "queries api.osv.dev"]
fn osv_separates_a_flagged_crate_from_a_clean_one() {
    let runtime = Runtime::try_new().expect("runtime");
    let state = FirewallState::default();
    let flagged =
        runtime.block_on(screen("https://static.crates.io/crates/rustdecimal/1.0.0", &state));
    assert!(flagged.unwrap_or_default().contains("MAL-2022-1"));
    assert_eq!(
        runtime.block_on(screen("https://static.crates.io/crates/serde/1.0.200", &state)),
        None
    );
}

#[test]
fn each_mal_id_is_reported_once_from_ids_and_aliases() {
    let body = json!({"vulns": [
        {"id": "MAL-2022-1", "aliases": ["GHSA-x"]},
        {"id": "RUSTSEC-2022-0005"},
        {"id": "MAL-2022-1"},
        {"id": "GHSA-y", "aliases": ["MAL-2023-9"]},
    ]});
    assert_eq!(mal_ids(&body), vec!["MAL-2022-1", "MAL-2023-9"]);
    assert!(mal_ids(&json!({"vulns": [{"id": "RUSTSEC-2022-0005"}]})).is_empty());
    assert!(mal_ids(&json!({})).is_empty());
}
