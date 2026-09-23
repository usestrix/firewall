use firewall::policies::filters::denylist::{mal_ids, parse, AffectedVersions};

/// As published: one row per affected version, tab separated.
const LIST: &str = "\
@0xengine/xmlrpc\t*\tMAL-2024-11182
analysis-chart\t2.0.8\tMAL-2026-10890
analysis-chart\t2.0.9\tMAL-2026-10890
arrayref\t0.3.10\tMAL-2026-14336
@dydxprotocol/solo\t>=0.41.1\tMAL-2022-220
io.github.leetcrunch:scribejava-core\t*\tMAL-2025-2552
";

#[test]
fn a_row_is_a_name_a_version_and_an_id() {
    let list = parse(LIST).unwrap();
    assert_eq!(list["@0xengine/xmlrpc"][0].affected, AffectedVersions::All);
    assert_eq!(list["@0xengine/xmlrpc"][0].id, "MAL-2024-11182");
    assert_eq!(list["io.github.leetcrunch:scribejava-core"][0].id, "MAL-2025-2552");
}

#[test]
fn a_package_collects_every_row_filed_against_it() {
    assert_eq!(parse(LIST).unwrap()["analysis-chart"].len(), 2);
}

#[test]
fn a_star_covers_every_version_and_a_single_one_covers_only_itself() {
    let list = parse(LIST).unwrap();
    assert_eq!(mal_ids(&list["@0xengine/xmlrpc"], Some("0.0.1")), ["MAL-2024-11182"]);
    assert_eq!(mal_ids(&list["arrayref"], Some("0.3.10")), ["MAL-2026-14336"]);
    assert!(mal_ids(&list["arrayref"], Some("0.3.9")).is_empty());
}

#[test]
fn an_open_range_covers_its_floor_and_up() {
    let solo = &parse(LIST).unwrap()["@dydxprotocol/solo"];
    assert!(mal_ids(solo, Some("0.41.0")).is_empty());
    assert_eq!(mal_ids(solo, Some("0.41.1")), ["MAL-2022-220"]);
    // pypi, nuget and rubygems versions are not semver, and an unreadable one stays flagged.
    assert_eq!(mal_ids(solo, Some("2.0.7.post1")), ["MAL-2022-220"]);
}

#[test]
fn a_request_naming_no_version_answers_for_every_row() {
    let list = parse(LIST).unwrap();
    assert_eq!(mal_ids(&list["arrayref"], None), ["MAL-2026-14336"]);
    assert_eq!(mal_ids(&list["analysis-chart"], None), ["MAL-2026-10890", "MAL-2026-10890"]);
}

#[test]
fn a_list_nothing_parses_out_of_is_an_error() {
    assert!(parse("<html>404: Not Found</html>").is_err());
}
