use firewall::policies::filters::denylist::parse;

#[test]
fn a_line_is_a_name_and_its_ids() {
    let list =
        parse("@0xengine/xmlrpc:MAL-2024-11182\nanalysis-chart:MAL-2026-10890,MAL-2026-6299\n");
    assert_eq!(list.get("@0xengine/xmlrpc").unwrap(), "MAL-2024-11182");
    assert_eq!(list.get("analysis-chart").unwrap(), "MAL-2026-10890,MAL-2026-6299");
}

#[test]
fn a_maven_name_keeps_its_own_colon() {
    let list = parse("io.github.leetcrunch:scribejava-core:MAL-2025-2552\n");
    assert_eq!(list.get("io.github.leetcrunch:scribejava-core").unwrap(), "MAL-2025-2552");
}

#[test]
fn lines_without_ids_are_skipped() {
    assert!(parse("\nrustdecimal\n").is_empty());
}
