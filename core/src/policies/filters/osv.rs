use super::{Filter, Verdict, VerdictFuture};
use crate::policies::registries::Registry;
use crate::policies::Package;
use rama::http::client::EasyHttpWebClient;
use rama::http::service::client::HttpClientExt;
use rama::http::{BodyExtractExt, StatusCode};
use serde_json::{json, Value};

const URL: &str = "https://api.osv.dev/v1/query";

pub struct Osv;

impl Filter for Osv {
    fn name(&self) -> &'static str {
        "osv"
    }

    fn check<'a>(&'a self, registry: &'static Registry, pkg: &'a Package) -> VerdictFuture<'a> {
        Box::pin(async move {
            // An index request names no version; only downloads are screened.
            let Some(version) = pkg.version.as_deref() else { return Verdict::Allow };
            let client = EasyHttpWebClient::default();
            let query = query(registry.osv_name, &pkg.name, version);
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
            let body: Value = match serde_json::from_str(&text) {
                Ok(body) => body,
                Err(e) => return Verdict::Unknown(format!("OSV sent unreadable JSON: {e}")),
            };

            let hits = mal_ids(&body);
            if hits.is_empty() {
                Verdict::Allow
            } else {
                let links: Vec<String> =
                    hits.iter().map(|id| format!("{id} https://osv.dev/vulnerability/{id}")).collect();
                Verdict::Deny(format!("is flagged malicious by OSV: {}", links.join(", ")))
            }
        })
    }
}

fn query(eco: &str, name: &str, version: &str) -> String {
    json!({ "package": { "name": name, "ecosystem": eco }, "version": version }).to_string()
}

/// A MAL- id marks a malware advisory; every other OSV id is an ordinary vulnerability.
pub fn mal_ids(body: &Value) -> Vec<String> {
    let mut ids = Vec::new();
    let Some(vulns) = body["vulns"].as_array() else {
        return ids;
    };
    for vuln in vulns {
        keep_mal(&vuln["id"], &mut ids);
        if let Some(aliases) = vuln["aliases"].as_array() {
            for alias in aliases {
                keep_mal(alias, &mut ids);
            }
        }
    }
    ids
}

fn keep_mal(value: &Value, ids: &mut Vec<String>) {
    let Some(id) = value.as_str() else { return };
    if id.starts_with("MAL-") && !ids.iter().any(|seen| seen == id) {
        ids.push(id.to_string());
    }
}
