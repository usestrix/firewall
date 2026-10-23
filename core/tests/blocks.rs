use firewall::blocks::{answer, block};
use firewall::policies::Package;
use firewall::Firewall;
use std::path::Path;
use std::time::Duration;

#[tokio::test]
async fn allowing_once_releases_the_held_download() {
    let firewall = Firewall::default();
    let config = Path::new("/nonexistent/config.json");
    let pkg = Package { name: "left-pad".into(), version: Some("1.3.0".into()) };
    assert!(!block("npm", &pkg, "age", "is new").await, "held while nothing was asking");
    answer(&firewall, config, "blocks");

    let held = tokio::spawn(async move { block("npm", &pkg, "age", "is new").await });
    let id = loop {
        let blocks: serde_json::Value = serde_json::from_str(&answer(&firewall, config, "blocks")).unwrap();
        if let Some(id) = blocks[0]["id"].as_u64() {
            break id;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert_eq!(answer(&firewall, config, &format!("allow-once {id}")), "ok");
    assert!(held.await.unwrap(), "the waiting download goes through");
    assert!(firewall.age_check_lifted("npm", |p| p.name == "left-pad"), "and the rest of the install");
    assert!(!block("npm", &Package { name: "evil".into(), version: None }, "denylist", "is malware").await);
}
