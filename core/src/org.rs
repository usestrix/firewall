use crate::config::FirewallConfig;
use crate::policies::filters::AGENT;
use rama::http::client::EasyHttpWebClient;
use rama::http::header::{AUTHORIZATION, USER_AGENT};
use rama::http::service::client::HttpClientExt;
use rama::http::{BodyExtractExt, StatusCode};
use rama::rt::blocking::Runtime;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use std::time::Duration;
use tracing::{info, warn};

const TIMEOUT: Duration = Duration::from_secs(5);

/// The organization's settings layer over the config file's; a `null` keeps the file's value.
/// Fetched once, so a change applies on restart.
pub fn with_settings(config: FirewallConfig) -> FirewallConfig {
    let Some(key) = &config.api_key else { return config };
    // Its own thread, as callers may already be inside a runtime.
    let fetched = std::thread::scope(|scope| {
        let fetch = || {
            let runtime = Runtime::try_new().map_err(|e| e.to_string())?;
            runtime.block_on(get::<Map<String, Value>>(&config.api_url, key, "firewall/settings"))
        };
        scope.spawn(fetch).join().unwrap_or_else(|_| Err("the fetch panicked".into()))
    });
    let merged = fetched.and_then(|mut settings| {
        settings.retain(|_, value| !value.is_null());
        config.with_layer(settings)
    });
    match merged {
        Ok(merged) => {
            info!("organization settings applied");
            merged
        }
        Err(error) => {
            warn!(%error, "organization settings unavailable, using the config file's");
            config
        }
    }
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
