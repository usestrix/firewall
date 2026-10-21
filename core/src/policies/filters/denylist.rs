use super::{Filter, Verdict, VerdictFuture, AGENT};
use crate::config::DenylistSource;
use crate::policies::registries::Registry;
use crate::policies::Package;
use rama::http::client::EasyHttpWebClient;
use rama::http::header::{AUTHORIZATION, ETAG, IF_NONE_MATCH, USER_AGENT};
use rama::http::service::client::HttpClientExt;
use rama::http::{BodyExtractExt, StatusCode};
use semver::Version;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::OnceCell;
use tokio::task::JoinHandle;
use tracing::{info, warn};

#[derive(Debug, PartialEq)]
pub enum AffectedVersions {
    All,
    AtLeast(Version),
    Only(String),
}

#[derive(Debug, PartialEq)]
pub struct Advisory {
    pub id: String,
    pub affected: AffectedVersions,
    pub link: Option<String>,
}

pub type Advisories = HashMap<String, Vec<Advisory>>;

pub type FetchedDenylist = Result<Advisories, String>;

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
                    None => Verdict::Allow,
                    Some(advisories) => {
                        let hits = covering(advisories, pkg.version.as_deref());
                        match hits.is_empty() {
                            true => Verdict::Allow,
                            false => Verdict::Deny(format!(
                                "contains malicious code: {}",
                                describe(&hits)
                            )),
                        }
                    }
                },
            }
        })
    }
}

impl AffectedVersions {
    /// `*` is every version, `>=X` a range opened at X, anything else one version.
    fn parse(version: &str) -> AffectedVersions {
        match version.strip_prefix(">=") {
            Some(floor) => match Version::parse(floor) {
                Ok(floor) => Self::AtLeast(floor),
                Err(e) => {
                    warn!(floor, "denylist floor is not semver, widening to every version: {e}");
                    Self::All
                }
            },
            None if version == "*" => Self::All,
            None => Self::Only(version.to_string()),
        }
    }

    fn covers(&self, version: &str) -> bool {
        match self {
            Self::All => true,
            Self::AtLeast(floor) => match Version::parse(version) {
                Ok(v) => &v >= floor,
                Err(e) => {
                    warn!(version, %floor, "requested version is not semver, covering it: {e}");
                    true
                }
            },
            Self::Only(exact) => exact == version,
        }
    }
}

/// With no version, only advisories covering every version apply.
pub fn covering<'a>(advisories: &'a [Advisory], version: Option<&str>) -> Vec<&'a Advisory> {
    advisories
        .iter()
        .filter(|advisory| match version {
            Some(v) => advisory.affected.covers(v),
            None => matches!(advisory.affected, AffectedVersions::All),
        })
        .collect()
}

pub fn describe(advisories: &[&Advisory]) -> String {
    let mut parts = Vec::new();
    for advisory in advisories {
        match &advisory.link {
            Some(link) => parts.push(format!("{} {link}", advisory.id)),
            None => parts.push(advisory.id.clone()),
        }
    }
    parts.join(", ")
}

/// A failed fetch leaves the last good list in place; a list that never loaded is retried every tick.
async fn watch(source: DenylistSource, token: Option<String>, lists: Arc<Lists>) {
    let period = Duration::from_secs(source.poll_secs);
    let mut seen = revision(&source, token.as_deref(), None).await;
    loop {
        tokio::time::sleep(period).await;
        let changed = revision(&source, token.as_deref(), seen.as_deref()).await;
        if let Some(current) = &changed {
            info!(revision = %current, "denylist source changed");
            seen = changed.clone();
        }
        for (eco, cell) in lists.iter() {
            let Some(list) = cell.get() else { continue };
            let failed = list.read().expect("denylist lock").is_err();
            if changed.is_none() && !failed {
                continue;
            }
            if let Ok(packages) = load(&source, token.as_deref(), eco).await {
                *list.write().expect("denylist lock") = Arc::new(Ok(packages));
            }
        }
    }
}

/// GitHub's 304 for an unchanged `If-None-Match` costs no rate limit.
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
    parse(&text)
}

/// Rows are "<name>\t<version>\t<MAL- id>[\t<link>]"; tab is the one separator no package name holds.
pub fn parse(text: &str) -> FetchedDenylist {
    let mut list = Advisories::new();
    let mut skipped = 0;
    for line in text.lines() {
        let mut row = line.split('\t');
        let (Some(name), Some(version), Some(id)) = (row.next(), row.next(), row.next()) else {
            skipped += 1;
            warn!(line = head(line), "denylist row is not <name>, <version>, <id> tab-separated");
            continue;
        };
        let link = row.next().filter(|link| !link.is_empty()).map(str::to_string);
        let affected = AffectedVersions::parse(version);
        let advisory = Advisory { id: id.to_string(), affected, link };
        list.entry(name.to_string()).or_default().push(advisory);
    }
    // An empty parse means a bad fetch; keep the last good list instead.
    match list.is_empty() {
        true => Err(format!("none of {skipped} rows parsed")),
        false => Ok(list),
    }
}

fn head(line: &str) -> &str {
    line.char_indices().nth(80).map_or(line, |(i, _)| &line[..i])
}
