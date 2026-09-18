use firewall::routing::screen;
use rama::rt::blocking::Runtime;

#[test]
#[ignore = "queries api.osv.dev"]
fn osv_separates_a_flagged_crate_from_a_clean_one() {
    let runtime = Runtime::try_new().expect("runtime");
    let flagged = runtime.block_on(screen("https://static.crates.io/crates/rustdecimal/1.0.0"));
    assert!(flagged.unwrap_or_default().contains("MAL-2022-1"));
    assert_eq!(runtime.block_on(screen("https://static.crates.io/crates/serde/1.0.200")), None);
}
