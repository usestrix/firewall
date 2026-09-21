use super::{Answer, Filter, Verdict};
use crate::config;
use crate::policies::registries::Registry;
use crate::policies::Package;
use crate::state::FirewallState;
use rama::http::client::EasyHttpWebClient;
use rama::http::header::AUTHORIZATION;
use rama::http::service::client::HttpClientExt;
use rama::http::{BodyExtractExt, StatusCode};
use std::collections::HashMap;
use tracing::{info, warn};

/// Each flagged package name against the MAL- ids it was flagged under, or why the
/// list could not be read.
pub type List = Result<HashMap<String, String>, String>;

pub struct Denylist;

impl Filter for Denylist {
    fn name(&self) -> &'static str {
        "denylist"
    }

    fn allow<'a>(
        &'a self,
        state: &'a FirewallState,
        registry: &'static Registry,
        pkg: &'a Package,
    ) -> Answer<'a> {
        Box::pin(async move {
            let eco = registry.osv_name;
            match state.denylist(eco).get_or_init(|| load(&state.config.denylist, eco)).await {
                Err(e) => Verdict::Unknown(e.clone()),
                Ok(list) => match list.get(&pkg.name) {
                    Some(ids) => Verdict::Deny(format!("is on the malicious package list ({ids})")),
                    None => Verdict::Allow,
                },
            }
        })
    }
}

async fn load(source: &config::Denylist, eco: &'static str) -> List {
    let list = fetch(source, &eco.to_lowercase()).await;
    match &list {
        Ok(packages) => info!(%eco, packages = packages.len(), "denylist loaded"),
        Err(error) => warn!(%eco, %error, "denylist unavailable"),
    }
    list
}

async fn fetch(source: &config::Denylist, eco: &str) -> List {
    let url = format!("{}/{eco}", source.base);
    let client = EasyHttpWebClient::default();
    let mut request = client.get(&url);
    if let Ok(token) = std::env::var(&source.token) {
        request = request.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = request.send().await.map_err(|e| e.to_string())?;
    if response.status() != StatusCode::OK {
        return Err(format!("{url} replied {}", response.status()));
    }
    let text = response.try_into_string().await.map_err(|e| e.to_string())?;
    Ok(parse(&text))
}

/// Every line is "<name>:<MAL- id>[,...]". Maven names contain colons, so the ids
/// are what follows the last one.
pub fn parse(text: &str) -> HashMap<String, String> {
    let mut list = HashMap::new();
    for line in text.lines() {
        if let Some((name, ids)) = line.rsplit_once(':') {
            list.insert(name.to_string(), ids.to_string());
        }
    }
    list
}
