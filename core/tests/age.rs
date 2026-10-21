use firewall::policies::screen;
use firewall::{Firewall, FirewallConfig};
use rama::rt::blocking::Runtime;

const OLD_DOWNLOADS: &[&str] = &[
    "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
    "https://files.pythonhosted.org/packages/aa/bb/requests-2.31.0-py3-none-any.whl",
    "https://static.crates.io/crates/serde/1.0.200",
    "https://rubygems.org/gems/rake-13.0.6.gem",
    "https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v1.3.2.zip",
];

#[test]
#[ignore = "queries every registry"]
fn every_registry_reports_when_a_version_was_published() {
    let runtime = Runtime::try_new().expect("runtime");
    runtime.block_on(async {
        let firewall =
            |hours| Firewall::new(FirewallConfig { min_age_hours: hours, ..Default::default() });
        let (lenient, strict) = (firewall(24), firewall(24 * 365 * 100));
        for url in OLD_DOWNLOADS {
            assert_eq!(screen(url, &lenient).await, None, "{url}");
            let blocked = screen(url, &strict).await.unwrap_or_default();
            assert!(blocked.contains("hour minimum"), "{url}: {blocked:?}");
        }
    });
}
