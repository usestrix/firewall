use crate::{Firewall, FirewallConfig};
use rama::http::client::EasyHttpWebClient;
use rama::http::header::CONTENT_TYPE;
use rama::http::service::client::HttpClientExt;
use rama::rt::blocking::Runtime;
use serde_json::{json, Value};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing::debug;

const BATCH: &str = "https://us.i.posthog.com/batch/";
const KEY: Option<&str> = option_env!("FIREWALL_POSTHOG_KEY");
const HEARTBEAT: Duration = Duration::from_secs(5 * 60);
const TIMEOUT: Duration = Duration::from_secs(5);

/// Off only in a build without a PostHog key or when a readable config turns it off.
static TELEMETRY: LazyLock<Option<Telemetry>> = LazyLock::new(|| {
    let key = KEY?;
    if FirewallConfig::load().is_ok_and(|config| !config.telemetry) {
        return None;
    }
    let session = format!("{:016x}", rand::random::<u64>());
    Some(Telemetry {
        key,
        session,
        events: Mutex::default(),
    })
});

struct Telemetry {
    key: &'static str,
    session: String,
    events: Mutex<Vec<Value>>,
}

/// One event per package download, named only when blocked
pub fn screened(firewall: &Firewall, url: &str, blocked: bool) {
    if TELEMETRY.is_none() {
        return;
    }
    let Some((registry, rest)) = firewall.match_on(url, |r| r.upstream) else {
        return;
    };
    let Some(pkg) = firewall.resolve(registry, rest).pkg else {
        return;
    };
    let mut properties = json!({ "eco": registry.eco, "blocked": blocked });
    if blocked {
        properties["package"] = pkg.label().into();
    }
    record("package_screened", properties);
}

pub fn error(kind: &'static str) {
    record("error", json!({ "kind": kind }));
}

pub fn heartbeat() {
    if TELEMETRY.is_none() {
        return;
    }
    tokio::spawn(async {
        loop {
            tokio::time::sleep(HEARTBEAT).await;
            send().await;
        }
    });
}

pub fn flush() {
    if TELEMETRY.is_none() {
        return;
    }
    match Runtime::try_new() {
        Ok(runtime) => runtime.block_on(send()),
        Err(error) => debug!(%error, "telemetry runtime failed"),
    }
}

fn record(event: &str, mut properties: Value) {
    let Some(telemetry) = &*TELEMETRY else { return };
    properties["distinct_id"] = telemetry.session.clone().into();
    properties["os"] = std::env::consts::OS.into();
    properties["arch"] = std::env::consts::ARCH.into();
    properties["$process_person_profile"] = false.into();
    let timestamp = OffsetDateTime::now_utc().format(&Rfc3339).ok();
    let event = json!({ "event": event, "properties": properties, "timestamp": timestamp });
    telemetry.events.lock().expect("telemetry lock").push(event);
}

pub async fn send() {
    let Some(telemetry) = &*TELEMETRY else { return };
    let batch = std::mem::take(&mut *telemetry.events.lock().expect("telemetry lock"));
    if batch.is_empty() {
        return;
    }
    let body = json!({ "api_key": telemetry.key, "batch": batch });
    let client = EasyHttpWebClient::default();
    let request = client.post(BATCH).header(CONTENT_TYPE, "application/json");
    match tokio::time::timeout(TIMEOUT, request.body(body.to_string()).send()).await {
        Ok(Ok(response)) => debug!(status = %response.status(), "telemetry sent"),
        Ok(Err(error)) => debug!(%error, "telemetry failed"),
        Err(_) => debug!("telemetry timed out"),
    }
}
