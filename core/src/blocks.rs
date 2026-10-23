use crate::config::{self, AllowedPackage};
use crate::policies::Package;
use crate::Firewall;
use rama::error::BoxError;
use serde::Serialize;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// So blocks can't pile up while no app collects them.
const KEPT: usize = 50;
/// Under pip's, pipenv's and pdm's 15 s read timeout, the shortest of the supported managers.
const HOLD: Duration = Duration::from_secs(10);
/// Only hold while an app is asking for blocks, so someone can answer.
const WATCHED: Duration = Duration::from_secs(2);
/// For a minute, so the rest of that install can fetch it too.
const ONCE: Duration = Duration::from_secs(60);

#[derive(Clone, Serialize)]
pub struct BlockedPackage {
    pub id: u64,
    pub eco: &'static str,
    pub name: String,
    pub version: Option<String>,
    pub filter: &'static str,
    pub reason: String,
    /// Flagged as malware, not just held back for being new.
    pub malicious: bool,
    /// Malware is never allowed, and a new package only by version. Saves each app the rule.
    pub trustable: bool,
}

struct Blocks {
    last_id: u64,
    unsent: Vec<BlockedPackage>,
    /// Age holds, the only blocks that can be allowed, each with what wakes its waiting downloads.
    held: Vec<(BlockedPackage, watch::Sender<bool>)>,
    polled: Option<Instant>,
}

static BLOCKS: Mutex<Blocks> =
    Mutex::new(Blocks { last_id: 0, unsent: Vec::new(), held: Vec::new(), polled: None });

/// Records a block and holds a new package's download for up to `HOLD`. Returns whether it was allowed.
pub async fn block(eco: &'static str, pkg: &Package, filter: &'static str, reason: &str) -> bool {
    let Some(mut answer) = record(eco, pkg, filter, reason) else {
        return false;
    };
    let allowed = tokio::time::timeout(HOLD, answer.wait_for(|allowed| *allowed)).await;
    matches!(allowed, Ok(Ok(_)))
}

/// The app's requests: `blocks`, `allow <id>` or `allow-once <id>`.
/// An allow replies `late` if the download had stopped waiting.
pub fn answer(firewall: &Firewall, config: &Path, request: &str) -> String {
    if request == "blocks" {
        return serde_json::to_string(&take()).expect("blocks serialize");
    }
    let result = match request.split_once(' ').map(|(verb, id)| (verb, id.parse())) {
        Some(("allow", Ok(id))) => trust(firewall, config, id),
        Some(("allow-once", Ok(id))) => allow_once(firewall, id),
        _ => Err(format!("unknown message {request}").into()),
    };
    match result {
        Ok(true) => "ok".to_owned(),
        Ok(false) => "late".to_owned(),
        Err(error) => format!("error: {error}"),
    }
}

/// Hands each block over once.
fn take() -> Vec<BlockedPackage> {
    let mut blocks = lock();
    blocks.polled = Some(Instant::now());
    std::mem::take(&mut blocks.unsent)
}

fn record(
    eco: &'static str,
    pkg: &Package,
    filter: &'static str,
    reason: &str,
) -> Option<watch::Receiver<bool>> {
    let mut blocks = lock();
    let watched = blocks.polled.is_some_and(|polled| polled.elapsed() < WATCHED);
    let holds = filter == "age" && watched;
    // A repeat fetch of a held package waits on the same answer.
    let waiting = blocks.held.iter().find(|(held, wake)| {
        wake.receiver_count() > 0 && held.eco == eco && held.name == pkg.name && held.version == pkg.version
    });
    if let (true, Some((_, wake))) = (holds, waiting) {
        return Some(wake.subscribe());
    }
    blocks.last_id += 1;
    let block = BlockedPackage {
        id: blocks.last_id,
        eco,
        name: pkg.name.clone(),
        version: pkg.version.clone(),
        filter,
        reason: reason.to_owned(),
        malicious: filter != "age",
        trustable: filter == "age" && pkg.version.is_some(),
    };
    push(&mut blocks.unsent, block.clone());
    if block.malicious {
        return None;
    }
    let (wake, allowed) = watch::channel(false);
    push(&mut blocks.held, (block, wake));
    holds.then_some(allowed)
}

/// Also saved to the config, so it survives a restart.
fn trust(firewall: &Firewall, config: &Path, id: u64) -> Result<bool, BoxError> {
    let block = held(id)?;
    let version = block.version.ok_or("only a version can be trusted")?;
    config::allow(config, block.eco, &block.name, &version)?;
    let package = AllowedPackage { name: block.name, version: Some(version) };
    firewall.lift_age_check(block.eco, package, None);
    Ok(release(id))
}

fn allow_once(firewall: &Firewall, id: u64) -> Result<bool, BoxError> {
    let block = held(id)?;
    let package = AllowedPackage { name: block.name, version: block.version };
    firewall.lift_age_check(block.eco, package, Some(Instant::now() + ONCE));
    Ok(release(id))
}

fn held(id: u64) -> Result<BlockedPackage, BoxError> {
    let blocks = lock();
    let held = blocks.held.iter().find(|(held, _)| held.id == id);
    Ok(held.ok_or(format!("no new package was held back as {id}"))?.0.clone())
}

/// Returns whether a download was still waiting.
fn release(id: u64) -> bool {
    let blocks = lock();
    let Some((_, wake)) = blocks.held.iter().find(|(held, _)| held.id == id) else {
        return false;
    };
    wake.send_replace(true);
    wake.receiver_count() > 0
}

fn push<T>(list: &mut Vec<T>, item: T) {
    if list.len() == KEPT {
        list.remove(0);
    }
    list.push(item);
}

fn lock() -> std::sync::MutexGuard<'static, Blocks> {
    BLOCKS.lock().unwrap_or_else(|e| e.into_inner())
}
