use crate::config::{AllowedPackage, FirewallConfig};
use crate::policies::filters::AGENT;
use crate::policies::Package;
use rama::http::client::EasyHttpWebClient;
use rama::http::header::{AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use rama::http::service::client::HttpClientExt;
use rama::http::{BodyExtractExt, StatusCode};
use rama::rt::blocking::Runtime;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing::{info, warn};

const TIMEOUT: Duration = Duration::from_secs(5);

/// The API URL and key that blocks are reported to.
static REPORT_TO: OnceLock<(String, String)> = OnceLock::new();

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

/// Blocks are reported only with an `api_key`.
pub fn report_to(config: &FirewallConfig) {
    if let Some(key) = &config.api_key {
        REPORT_TO.set((config.api_url.clone(), key.clone())).ok();
    }
}

/// Tells the Strix app, so the organization's admins see what was blocked.
pub fn blocked(eco: &str, pkg: &Package, filter: &str, reason: &str) {
    let Some((api_url, key)) = REPORT_TO.get() else { return };
    let occurred_at = OffsetDateTime::now_utc().format(&Rfc3339).ok();
    let event = json!({
        "ecosystem": eco,
        "name": pkg.name,
        "version": pkg.version,
        "filter": filter,
        "reason": reason,
        "occurred_at": occurred_at,
    });
    let body = json!({ "events": [event] }).to_string();
    tokio::spawn(async move {
        if let Err(error) = post(api_url, key, "firewall/events", body).await {
            warn!(%error, "could not report a block to the Strix app");
        }
    });
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

async fn post(api_url: &str, key: &str, path: &str, body: String) -> Result<(), String> {
    let url = format!("{}/{path}", api_url.trim_end_matches('/'));
    let client = EasyHttpWebClient::default();
    let request = client
        .post(&url)
        .header(USER_AGENT, AGENT)
        .header(AUTHORIZATION, format!("Bearer {key}"))
        .header(CONTENT_TYPE, "application/json")
        .body(body);
    let response = tokio::time::timeout(TIMEOUT, request.send())
        .await
        .map_err(|_| format!("{url} timed out"))?
        .map_err(|e| e.to_string())?;
    if !response.status().is_success() {
        return Err(format!("{url} replied {}", response.status()));
    }
    Ok(())
}
