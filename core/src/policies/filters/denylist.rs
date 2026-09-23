use super::{Filter, Verdict, VerdictFuture};
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

/// The GitHub API turns away requests without a user agent.
const AGENT: &str = "strix-firewall";

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
                        let hits = mal_ids(advisories, pkg.version.as_deref());
                        match hits.is_empty() {
                            true => Verdict::Allow,
                            false => Verdict::Deny(format!(
                                "is on the malicious package list ({})",
                                hits.join(",")
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
                // A floor that will not parse leaves nothing to place a version below.
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
                // A version that will not parse cannot be placed below the floor either.
                Err(e) => {
                    warn!(version, %floor, "requested version is not semver, covering it: {e}");
                    true
                }
            },
            Self::Only(exact) => exact == version,
        }
    }
}

/// An index request names no version, so it answers only for advisories covering every
/// version; a narrower one would flag the package's clean versions too.
pub fn mal_ids<'a>(advisories: &'a [Advisory], version: Option<&str>) -> Vec<&'a str> {
    advisories
        .iter()
        .filter(|advisory| match version {
            Some(v) => advisory.affected.covers(v),
            None => matches!(advisory.affected, AffectedVersions::All),
        })
        .map(|advisory| advisory.id.as_str())
        .collect()
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
    parse(&text)
}

/// Rows are "<name>\t<version>\t<MAL- id>"; tab is the one separator no package name holds.
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
        let advisory = Advisory { id: id.to_string(), affected: AffectedVersions::parse(version) };
        list.entry(name.to_string()).or_default().push(advisory);
    }
    // Nothing parsing out is a fetch gone wrong, not an ecosystem with no malicious
    // packages, and the last good list screens better than an empty one.
    match list.is_empty() {
        true => Err(format!("none of {skipped} rows parsed")),
        false => Ok(list),
    }
}

fn head(line: &str) -> &str {
    line.char_indices().nth(80).map_or(line, |(i, _)| &line[..i])
}
