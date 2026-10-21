use crate::policies::Package;
use serde::Serialize;
use std::sync::Mutex;

/// Bounded, so blocks pile up harmlessly while nothing collects them.
const KEPT: usize = 50;

static RECENT: Mutex<Vec<BlockedPackage>> = Mutex::new(Vec::new());

#[derive(Serialize)]
pub struct BlockedPackage {
    pub eco: &'static str,
    pub name: String,
    pub version: Option<String>,
    pub filter: &'static str,
    pub reason: String,
}

pub fn record(eco: &'static str, pkg: &Package, filter: &'static str, reason: &str) {
    let mut recent = RECENT.lock().unwrap_or_else(|e| e.into_inner());
    if recent.len() == KEPT {
        recent.remove(0);
    }
    recent.push(BlockedPackage {
        eco,
        name: pkg.name.clone(),
        version: pkg.version.clone(),
        filter,
        reason: reason.to_owned(),
    });
}

/// Hands each block over once.
pub fn take() -> Vec<BlockedPackage> {
    std::mem::take(&mut *RECENT.lock().unwrap_or_else(|e| e.into_inner()))
}
