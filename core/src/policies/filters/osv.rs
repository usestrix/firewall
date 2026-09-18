use super::{Answer, Filter, Verdict};
use crate::policies::registries::Registry;
use crate::policies::Package;
use rama::http::client::EasyHttpWebClient;
use rama::http::service::client::HttpClientExt;
use rama::http::{BodyExtractExt, StatusCode};

const URL: &str = "https://api.osv.dev/v1/query";

pub struct Osv;

impl Filter for Osv {
    fn name(&self) -> &'static str {
        "osv"
    }

    fn allow<'a>(&'a self, registry: &'static Registry, pkg: &'a Package) -> Answer<'a> {
        Box::pin(async move {
            let client = EasyHttpWebClient::default();
            let query = query(registry.osv_name, pkg);
            let response = match client.post(URL).body(query).send().await {
                Ok(response) => response,
                Err(e) => return Verdict::Unknown(e.to_string()),
            };
            if response.status() != StatusCode::OK {
                return Verdict::Unknown(format!("OSV replied {}", response.status()));
            }
            let text = match response.try_into_string().await {
                Ok(text) => text,
                Err(e) => return Verdict::Unknown(e.to_string()),
            };

            let hits = scan_mal_ids(&text);
            if hits.is_empty() {
                Verdict::Allow
            } else {
                Verdict::Deny(format!("is flagged malicious by OSV ({})", hits.join(", ")))
            }
        })
    }
}

fn query(eco: &str, pkg: &Package) -> String {
    match &pkg.version {
        Some(v) => format!(
            r#"{{"package":{{"name":"{}","ecosystem":"{}"}},"version":"{}"}}"#,
            escape(&pkg.name),
            eco,
            escape(v)
        ),
        None => {
            format!(r#"{{"package":{{"name":"{}","ecosystem":"{}"}}}}"#, escape(&pkg.name), eco)
        }
    }
}

/// MAL- appears only as an advisory id, so a substring scan avoids parsing the JSON.
fn scan_mal_ids(text: &str) -> Vec<String> {
    let mut hits = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("\"MAL-") {
        rest = &rest[i + 1..];
        if let Some(end) = rest.find('"') {
            let id = rest[..end].to_string();
            if !hits.contains(&id) {
                hits.push(id);
            }
        }
    }
    hits
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(name: &str, version: Option<&str>) -> Package {
        Package { name: name.to_string(), version: version.map(str::to_string) }
    }

    #[test]
    fn each_mal_id_is_reported_once() {
        let vulns = r#"{"vulns":[{"id":"MAL-2022-1","aliases":["GHSA-x"]},
            {"id":"RUSTSEC-2022-0005"},{"id":"MAL-2022-1"},{"id":"MAL-2023-9"}]}"#;
        assert_eq!(scan_mal_ids(vulns), vec!["MAL-2022-1", "MAL-2023-9"]);
        assert!(scan_mal_ids(r#"{"vulns":[{"id":"RUSTSEC-2022-0005"}]}"#).is_empty());
    }

    #[test]
    fn a_quote_in_a_name_cannot_break_out_of_the_query() {
        assert_eq!(
            query("npm", &pkg(r#"evil","ecosystem":"x"#, Some("1.0"))),
            r#"{"package":{"name":"evil\",\"ecosystem\":\"x","ecosystem":"npm"},"version":"1.0"}"#
        );
        assert_eq!(
            query("crates.io", &pkg("serde", None)),
            r#"{"package":{"name":"serde","ecosystem":"crates.io"}}"#
        );
    }
}
