use std::path::{Path, PathBuf};

use crate::feeds::{FeedSpec, SyncManifest};

/// Serialize `manifest` to `<cache_dir>/manifest.json`.
pub fn save_manifest(_manifest: &SyncManifest, _cache_dir: &Path) -> anyhow::Result<()> {
    todo!("Phase 4 GREEN: implement manifest save")
}

/// Load manifest from `<cache_dir>/manifest.json`.
/// Returns an empty `SyncManifest` if the file does not exist.
pub fn load_manifest(_cache_dir: &Path) -> anyhow::Result<SyncManifest> {
    todo!("Phase 4 GREEN: implement manifest load")
}

/// Return refs to feeds whose `last_synced` is older than `threshold_secs` ago
/// (or whose `last_synced` is `None`).
#[must_use]
pub fn stale_feeds(manifest: &SyncManifest, threshold_secs: u64) -> Vec<&FeedSpec> {
    let _ = threshold_secs;
    let _ = manifest;
    todo!("Phase 4 GREEN: implement stale feed detection")
}

/// Create `<cache_dir>/<feed.name>/` if it does not exist, return the path.
pub fn prepare_feed_cache(spec: &FeedSpec, cache_dir: &Path) -> anyhow::Result<PathBuf> {
    let _ = spec;
    let _ = cache_dir;
    todo!("Phase 4 GREEN: implement cache dir creation")
}

/// Stub: will be implemented in Phase 5 with real HTTP.
pub fn download_feed(_spec: &FeedSpec, _cache_dir: &Path) -> anyhow::Result<()> {
    Ok(())
}
