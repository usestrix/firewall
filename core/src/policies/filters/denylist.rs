use super::{Filter, Verdict, VerdictFuture};
use crate::config::DenylistSource;
use crate::policies::registries::Registry;
use crate::policies::Package;
use rama::http::client::EasyHttpWebClient;
use rama::http::header::{AUTHORIZATION, ETAG, IF_NONE_MATCH, USER_AGENT};
use rama::http::service::client::HttpClientExt;
use rama::http::{BodyExtractExt, StatusCode};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::OnceCell;
use tokio::task::JoinHandle;
use tracing::{info, warn};

/// The GitHub API turns away requests without a user agent.
const AGENT: &str = "strix-firewall";

/// Flagged package names and the MAL- ids behind them, or why the list is missing.
pub type FetchedDenylist = Result<HashMap<String, String>, String>;

/// One list per ecosystem, downloaded when a package from it is first screened.
type Lists = HashMap<&'static str, OnceCell<RwLock<Arc<FetchedDenylist>>>>;

pub struct Denylist {
    source: DenylistSource,
    token: Option<String>,
    lists: Arc<Lists>,
    watch: JoinHandle<()>,
}

impl Denylist {
    pub fn new(
        source: DenylistSource,
        token: Option<String>,
        ecosystems: impl Iterator<Item = &'static str>,
    ) -> Self {
        let lists: Arc<Lists> = Arc::new(ecosystems.map(|eco| (eco, OnceCell::new())).collect());
        let watch = tokio::spawn(watch(source.clone(), token.clone(), Arc::clone(&lists)));
        Denylist { source, token, lists, watch }
    }
}

impl Drop for Denylist {
    fn drop(&mut self) {
        self.watch.abort();
    }
}

impl Filter for Denylist {
    fn name(&self) -> &'static str {
        "denylist"
    }

    fn check<'a>(&'a self, registry: &'static Registry, pkg: &'a Package) -> VerdictFuture<'a> {
        Box::pin(async move {
            let eco = registry.osv_name;
            let load = || async {
                RwLock::new(Arc::new(load(&self.source, self.token.as_deref(), eco).await))
            };
            let list = self.lists[eco].get_or_init(load).await;
            let list = Arc::clone(&list.read().expect("denylist lock"));
            match &*list {
                Err(e) => Verdict::Unknown(e.clone()),
                Ok(list) => match list.get(&pkg.name) {
                    Some(ids) => Verdict::Deny(format!("is on the malicious package list ({ids})")),
                    None => Verdict::Allow,
                },
            }
        })
    }
}

/// Re-fetches the lists in use whenever the source gets a new commit. A failed
/// fetch leaves the last good list in place.
async fn watch(source: DenylistSource, token: Option<String>, lists: Arc<Lists>) {
    let period = Duration::from_secs(source.poll_secs);
    let mut seen = revision(&source, token.as_deref(), None).await;
    loop {
        tokio::time::sleep(period).await;
        let Some(current) = revision(&source, token.as_deref(), seen.as_deref()).await else {
            continue;
        };
        info!(revision = %current, "denylist source changed");
        seen = Some(current);
        for (eco, cell) in lists.iter() {
            let Some(list) = cell.get() else { continue };
            if let Ok(packages) = load(&source, token.as_deref(), eco).await {
                *list.write().expect("denylist lock") = Arc::new(Ok(packages));
            }
        }
    }
}

/// The new commit, or `None` when nothing moved or the check failed. GitHub answers
/// an unchanged `If-None-Match` with a 304, which costs no rate limit.
async fn revision(
    source: &DenylistSource,
    token: Option<&str>,
    seen: Option<&str>,
) -> Option<String> {
    let client = EasyHttpWebClient::default();
    let mut request = client.get(&source.revision).header(USER_AGENT, AGENT);
    if let Some(token) = token {
        request = request.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(seen) = seen {
        request = request.header(IF_NONE_MATCH, seen);
    }
    let response = match request.send().await {
        Ok(response) => response,
        Err(error) => {
            warn!(%error, "denylist revision check failed");
            return None;
        }
    };
    if response.status() != StatusCode::OK {
        return None;
    }
    response.headers().get(ETAG)?.to_str().ok().map(str::to_owned)
}

async fn load(source: &DenylistSource, token: Option<&str>, eco: &'static str) -> FetchedDenylist {
    let list = fetch(source, token, &eco.to_lowercase()).await;
    match &list {
        Ok(packages) => info!(%eco, packages = packages.len(), "denylist loaded"),
        Err(error) => warn!(%eco, %error, "denylist unavailable"),
    }
    list
}

async fn fetch(source: &DenylistSource, token: Option<&str>, eco: &str) -> FetchedDenylist {
    let url = format!("{}/{eco}", source.base);
    let client = EasyHttpWebClient::default();
    let mut request = client.get(&url).header(USER_AGENT, AGENT);
    if let Some(token) = token {
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
