use super::{listed, Filter, Verdict, VerdictFuture, AGENT};
use crate::config::{PackageList, PlatformConfig};
use crate::policies::registries::Registry;
use crate::policies::Package;
use rama::http::client::EasyHttpWebClient;
use rama::http::header::{AUTHORIZATION, USER_AGENT};
use rama::http::service::client::HttpClientExt;
use rama::http::{BodyExtractExt, StatusCode};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::OnceCell;
use tokio::task::JoinHandle;
use tracing::{info, warn};

const POLL: Duration = Duration::from_secs(60);

type Blocks = Arc<OnceCell<RwLock<Arc<Result<PackageList, String>>>>>;

/// Packages a Strix admin blocked, downloaded when the first package is screened.
pub struct OrganizationBlocks {
    platform: PlatformConfig,
    blocks: Blocks,
    watch: JoinHandle<()>,
}

impl OrganizationBlocks {
    pub fn new(platform: PlatformConfig) -> Self {
        let blocks = Arc::new(OnceCell::new());
        let watch = tokio::spawn(watch(platform.clone(), Arc::clone(&blocks)));
        OrganizationBlocks { platform, blocks, watch }
    }
}

impl Drop for OrganizationBlocks {
    fn drop(&mut self) {
        self.watch.abort();
    }
}

impl Filter for OrganizationBlocks {
    fn name(&self) -> &'static str {
        "organization"
    }

    fn check<'a>(&'a self, registry: &'static Registry, pkg: &'a Package) -> VerdictFuture<'a> {
        Box::pin(async move {
            let load = || async { RwLock::new(Arc::new(load(&self.platform).await)) };
            let blocks = self.blocks.get_or_init(load).await;
            let blocks = Arc::clone(&blocks.read().expect("blocks lock"));
            match &*blocks {
                Err(e) => Verdict::Unknown(e.clone()),
                Ok(blocks) if listed(blocks, registry, pkg) => {
                    Verdict::Deny("is blocked by your organization".into())
                }
                Ok(_) => Verdict::Allow,
            }
        })
    }
}

/// A failed fetch leaves the last good list in place.
async fn watch(platform: PlatformConfig, blocks: Blocks) {
    loop {
        tokio::time::sleep(POLL).await;
        let Some(current) = blocks.get() else { continue };
        if let Ok(fresh) = load(&platform).await {
            *current.write().expect("blocks lock") = Arc::new(Ok(fresh));
        }
    }
}

async fn load(platform: &PlatformConfig) -> Result<PackageList, String> {
    let blocks = fetch(platform).await;
    match &blocks {
        Ok(_) => info!("organization blocks loaded"),
        Err(error) => warn!(%error, "organization blocks unavailable"),
    }
    blocks
}

async fn fetch(platform: &PlatformConfig) -> Result<PackageList, String> {
    let url = format!("{}/api/v1/firewall/blocklist", platform.url);
    let client = EasyHttpWebClient::default();
    let request = client
        .get(&url)
        .header(USER_AGENT, AGENT)
        .header(AUTHORIZATION, format!("Bearer {}", platform.api_key));
    let response = request.send().await.map_err(|e| e.to_string())?;
    if response.status() != StatusCode::OK {
        return Err(format!("{url} replied {}", response.status()));
    }
    let text = response.try_into_string().await.map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}
