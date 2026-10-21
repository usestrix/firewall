use super::{Filter, Verdict, VerdictFuture, AGENT};
use crate::policies::registries::{Published, Registry};
use crate::policies::Package;
use rama::http::client::EasyHttpWebClient;
use rama::http::header::USER_AGENT;
use rama::http::service::client::HttpClientExt;
use rama::http::{BodyExtractExt, StatusCode};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

pub struct Age {
    min: Duration,
}

impl Age {
    pub fn new(hours: u64) -> Self {
        Age { min: Duration::hours(hours as i64) }
    }
}

impl Filter for Age {
    fn name(&self) -> &'static str {
        "age"
    }

    fn check<'a>(&'a self, registry: &'static Registry, pkg: &'a Package) -> VerdictFuture<'a> {
        Box::pin(async move {
            let Some(version) = pkg.version.as_deref() else { return Verdict::Allow };
            let Some(published) = &registry.published else { return Verdict::Allow };
            let published_at = match published_at(published, &pkg.name, version).await {
                Ok(at) => at,
                Err(e) => return Verdict::Unknown(e),
            };

            let age = OffsetDateTime::now_utc() - published_at;
            if age >= self.min {
                return Verdict::Allow;
            }
            let (hours, min) = (age.whole_hours(), self.min.whole_hours());
            Verdict::Deny(format!("was published {hours} hours ago, under the {min}-hour minimum"))
        })
    }
}

async fn published_at(
    published: &Published,
    name: &str,
    version: &str,
) -> Result<OffsetDateTime, String> {
    let name = match published.escape {
        Some(escape) => escape(name),
        None => name.to_string(),
    };
    let url = published.url.replace("{name}", &name).replace("{version}", version);
    let pointer = published.pointer.replace("{version}", version);

    let client = EasyHttpWebClient::default();
    let response = client.get(&url).header(USER_AGENT, AGENT).send().await;
    let response = response.map_err(|e| e.to_string())?;
    if response.status() != StatusCode::OK {
        return Err(format!("{url} replied {}", response.status()));
    }
    let text = response.try_into_string().await.map_err(|e| e.to_string())?;
    let body: Value =
        serde_json::from_str(&text).map_err(|e| format!("{url} sent unreadable JSON: {e}"))?;

    let Some(stamp) = body.pointer(&pointer).and_then(Value::as_str) else {
        return Err(format!("{url} gave no publish time"));
    };
    OffsetDateTime::parse(stamp, &Rfc3339).map_err(|e| format!("{url} sent a bad time: {e}"))
}
