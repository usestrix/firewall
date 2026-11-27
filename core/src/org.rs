use crate::config::{AllowedPackage, FirewallConfig};
use crate::policies::filters::AGENT;
use rama::http::client::EasyHttpWebClient;
use rama::http::header::{AUTHORIZATION, USER_AGENT};
use rama::http::service::client::HttpClientExt;
use rama::http::{BodyExtractExt, StatusCode};
use rama::rt::blocking::Runtime;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{info, warn};

const TIMEOUT: Duration = Duration::from_secs(5);

/// What an admin set for the whole organization in the Strix app. `None` keeps the config file's value.
#[derive(Deserialize)]
struct OrgSettings {
    min_age_hours: Option<u64>,
    fail_open: Option<bool>,
    #[serde(default)]
    allow: HashMap<String, Vec<AllowedPackage>>,
}

/// The organization's settings win over the config file's, and its allow list adds to the file's.
/// Fetched once, so a change applies on restart.
pub fn with_settings(mut config: FirewallConfig) -> FirewallConfig {
    let Some(key) = &config.api_key else { return config };
    // Its own thread, as callers may already be inside a runtime.
    let fetched = std::thread::scope(|scope| {
        let fetch = || {
            let runtime = Runtime::try_new().map_err(|e| e.to_string())?;
            runtime.block_on(get::<OrgSettings>(&config.api_url, key, "firewall/settings"))
        };
        scope.spawn(fetch).join().unwrap_or_else(|_| Err("the fetch panicked".into()))
    });
    let settings = match fetched {
        Ok(settings) => settings,
        Err(error) => {
            warn!(%error, "organization settings unavailable, using the config file's");
            return config;
        }
    };
    if let Some(hours) = settings.min_age_hours {
        config.min_age_hours = hours;
    }
    if let Some(fail_open) = settings.fail_open {
        config.fail_open = fail_open;
    }
    for (eco, entries) in settings.allow {
        config.allow.entry(eco).or_default().extend(entries);
    }
    info!("organization settings applied");
    config
}

pub(crate) async fn get<T: DeserializeOwned>(
    api_url: &str,
    key: &str,
    path: &str,
) -> Result<T, String> {
    let url = format!("{}/{path}", api_url.trim_end_matches('/'));
    let client = EasyHttpWebClient::default();
    let request =
        client.get(&url).header(USER_AGENT, AGENT).header(AUTHORIZATION, format!("Bearer {key}"));
    let response = tokio::time::timeout(TIMEOUT, request.send())
        .await
        .map_err(|_| format!("{url} timed out"))?
        .map_err(|e| e.to_string())?;
    if response.status() != StatusCode::OK {
        return Err(format!("{url} replied {}", response.status()));
    }
    let text = response.try_into_string().await.map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| format!("{url} sent unreadable JSON: {e}"))
}
