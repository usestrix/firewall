use super::{matches, Filter, Verdict, VerdictFuture};
use crate::policies::registries::Registry;
use crate::policies::Package;
use serde::Deserialize;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::OnceCell;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

const POLL: Duration = Duration::from_secs(60);

#[derive(Deserialize)]
struct Blocks {
    blocks: Vec<Block>,
}

/// A package an admin blocked for the whole organization in the Strix app.
#[derive(Deserialize)]
struct Block {
    ecosystem: String,
    name: String,
    /// Every version when absent.
    version: Option<String>,
    reason: Option<String>,
}

type Fetched = Arc<Result<Vec<Block>, String>>;

struct Source {
    api_url: String,
    key: String,
}

/// Fetched when a package is first screened, then polled.
pub struct Org {
    source: Arc<Source>,
    blocks: Arc<OnceCell<RwLock<Fetched>>>,
    watch: JoinHandle<()>,
}

impl Org {
    pub fn new(api_url: String, key: String) -> Self {
        let source = Arc::new(Source { api_url, key });
        let blocks = Arc::new(OnceCell::new());
        let watch = tokio::spawn(watch(Arc::clone(&source), Arc::clone(&blocks)));
        Org { source, blocks, watch }
    }
}

impl Drop for Org {
    fn drop(&mut self) {
        self.watch.abort();
    }
}

impl Filter for Org {
    fn name(&self) -> &'static str {
        "org"
    }

    fn check<'a>(&'a self, registry: &'static Registry, pkg: &'a Package) -> VerdictFuture<'a> {
        Box::pin(async move {
            let load = || async { RwLock::new(load(&self.source).await) };
            let blocks = self.blocks.get_or_init(load).await;
            let blocks = Arc::clone(&blocks.read().expect("org blocks lock"));
            let blocks = match &*blocks {
                Ok(blocks) => blocks,
                Err(e) => return Verdict::Unknown(e.clone()),
            };
            let hit = blocks.iter().find(|block| {
                block.ecosystem == registry.eco
                    && matches(registry, pkg, &block.name, block.version.as_deref())
            });
            match hit {
                None => Verdict::Allow,
                Some(Block { reason: Some(reason), .. }) => {
                    Verdict::Deny(format!("is blocked by your organization: {reason}"))
                }
                Some(_) => Verdict::Deny("is blocked by your organization".into()),
            }
        })
    }
}

/// A failed fetch leaves the last good list in place.
async fn watch(source: Arc<Source>, blocks: Arc<OnceCell<RwLock<Fetched>>>) {
    loop {
        tokio::time::sleep(POLL).await;
        let Some(current) = blocks.get() else { continue };
        let fetched = load(&source).await;
        let failed_before = current.read().expect("org blocks lock").is_err();
        if fetched.is_ok() || failed_before {
            *current.write().expect("org blocks lock") = fetched;
        }
    }
}

async fn load(source: &Source) -> Fetched {
    let fetched = crate::org::get::<Blocks>(&source.api_url, &source.key, "firewall/blocks").await;
    match &fetched {
        Ok(fetched) => debug!(blocks = fetched.blocks.len(), "organization blocks loaded"),
        Err(error) => warn!(%error, "organization blocks unavailable"),
    }
    Arc::new(fetched.map(|fetched| fetched.blocks))
}
