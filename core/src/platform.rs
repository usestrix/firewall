use crate::config::PlatformConfig;
use crate::policies::Package;
use crate::FirewallConfig;
use rama::http::client::EasyHttpWebClient;
use rama::http::header::{AUTHORIZATION, CONTENT_TYPE};
use rama::http::service::client::HttpClientExt;
use serde_json::{json, Value};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing::{debug, warn};

const TIMEOUT: Duration = Duration::from_secs(10);
/// The most events the platform takes in one request.
const BATCH: usize = 500;

/// On when a readable config names a Strix API key.
static PLATFORM: LazyLock<Option<Platform>> = LazyLock::new(|| {
    let config = FirewallConfig::load().ok()?.platform?;
    Some(Platform { config, events: Mutex::default() })
});

struct Platform {
    config: PlatformConfig,
    events: Mutex<Vec<Value>>,
}

pub fn on() -> bool {
    PLATFORM.is_some()
}

pub fn record(eco: &str, pkg: &Package, reason: Option<&str>) {
    let Some(platform) = &*PLATFORM else { return };
    let event = json!({
        "ecosystem": eco,
        "name": pkg.name,
        "version": pkg.version,
        "blocked": reason.is_some(),
        "reason": reason,
        "occurred_at": OffsetDateTime::now_utc().format(&Rfc3339).ok(),
    });
    platform.events.lock().expect("platform lock").push(event);
}

/// Events in a batch the platform did not take are dropped, not retried.
pub async fn send() {
    let Some(platform) = &*PLATFORM else { return };
    let events = std::mem::take(&mut *platform.events.lock().expect("platform lock"));
    let url = format!("{}/api/v1/firewall/events", platform.config.url);
    let client = EasyHttpWebClient::default();
    for batch in events.chunks(BATCH) {
        let body = json!({
            "device": whoami::hostname().ok(),
            "user": whoami::username().ok(),
            "os": std::env::consts::OS,
            "firewall_version": env!("CARGO_PKG_VERSION"),
            "events": batch,
        });
        let request = client
            .post(&url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {}", platform.config.api_key));
        match tokio::time::timeout(TIMEOUT, request.body(body.to_string()).send()).await {
            Ok(Ok(response)) if response.status().is_success() => {
                debug!(events = batch.len(), "installs reported")
            }
            Ok(Ok(response)) => warn!(status = %response.status(), %url, "platform refused installs"),
            Ok(Err(error)) => warn!(%error, %url, "could not report installs"),
            Err(_) => warn!(%url, "reporting installs timed out"),
        }
    }
}
