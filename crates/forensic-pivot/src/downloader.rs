use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::feeds::{FeedSpec, SyncManifest};

const MANIFEST_FILE: &str = "manifest.json";

/// Serialize `manifest` to `<cache_dir>/manifest.json`.
///
/// # Errors
/// Returns an error if the file cannot be written or serialization fails.
pub fn save_manifest(manifest: &SyncManifest, cache_dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(cache_dir)?;
    let path = cache_dir.join(MANIFEST_FILE);
    let json = serde_json::to_string_pretty(manifest)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Load manifest from `<cache_dir>/manifest.json`.
/// Returns an empty `SyncManifest` if the file does not exist.
///
/// # Errors
/// Returns an error only for genuine I/O or parse failures (not missing file).
pub fn load_manifest(cache_dir: &Path) -> anyhow::Result<SyncManifest> {
    let path = cache_dir.join(MANIFEST_FILE);
    if !path.exists() {
        return Ok(SyncManifest {
            feeds: Vec::new(),
            updated_at: 0,
        });
    }
    let json = std::fs::read_to_string(path)?;
    let manifest: SyncManifest = serde_json::from_str(&json)?;
    Ok(manifest)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Return refs to feeds whose `last_synced` is older than `threshold_secs`
/// ago (or whose `last_synced` is `None`).
#[must_use]
pub fn stale_feeds(manifest: &SyncManifest, threshold_secs: u64) -> Vec<&FeedSpec> {
    let now = now_secs();
    manifest
        .feeds
        .iter()
        .filter(|f| match f.last_synced {
            None => true,
            Some(last) => now.saturating_sub(last) > threshold_secs,
        })
        .collect()
}

/// Create `<cache_dir>/<feed.name>/` if it does not exist; return the path.
///
/// # Errors
/// Returns an error if the directory cannot be created.
pub fn prepare_feed_cache(spec: &FeedSpec, cache_dir: &Path) -> anyhow::Result<PathBuf> {
    let feed_dir = cache_dir.join(&spec.name);
    std::fs::create_dir_all(&feed_dir)?;
    Ok(feed_dir)
}

/// Download a feed and extract it into `<cache_dir>/<feed.name>/`.
///
/// Extraction rules:
/// - URL ends with `.zip` → unzip all entries
/// - URL ends with `.tar.gz` or `.tgz` → extract tar+gz
/// - Otherwise → write raw bytes to `<feed_dir>/raw`
///
/// # Errors
/// Returns an error on network failure, I/O error, or archive parse error.
// URL already lowercased above; ends_with is the correct case-insensitive test
#[allow(clippy::case_sensitive_file_extension_comparisons)]
pub fn download_feed(spec: &FeedSpec, cache_dir: &Path) -> anyhow::Result<()> {
    let feed_dir = prepare_feed_cache(spec, cache_dir)?;

    let response = reqwest::blocking::get(&spec.url)
        .map_err(|e| anyhow::anyhow!("HTTP GET '{}' failed: {e}", spec.url))?;

    if !response.status().is_success() {
        anyhow::bail!(
            "HTTP GET '{}' returned status {}",
            spec.url,
            response.status()
        );
    }

    let bytes = response
        .bytes()
        .map_err(|e| anyhow::anyhow!("reading response body from '{}' failed: {e}", spec.url))?;

    let url_lower = spec.url.to_ascii_lowercase();
    if url_lower.ends_with(".zip") {
        extract_zip(&bytes, &feed_dir)?;
    } else if url_lower.ends_with(".tar.gz") || url_lower.ends_with(".tgz") {
        extract_tar_gz(&bytes, &feed_dir)?;
    } else {
        std::fs::write(feed_dir.join("raw"), &bytes)?;
    }

    Ok(())
}

fn extract_zip(bytes: &[u8], dest: &Path) -> anyhow::Result<()> {
    let cursor = std::io::Cursor::new(bytes);
    let mut archive =
        zip_core::ZipArchive::new(cursor).map_err(|e| anyhow::anyhow!("zip parse error: {e}"))?;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let entry_path = match entry.enclosed_name() {
            Some(p) => dest.join(p),
            None => continue,
        };
        if entry.is_dir() {
            std::fs::create_dir_all(&entry_path)?;
        } else {
            if let Some(parent) = entry_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut out = std::fs::File::create(&entry_path)?;
            std::io::copy(&mut entry, &mut out)?;
        }
    }
    Ok(())
}

fn extract_tar_gz(bytes: &[u8], dest: &Path) -> anyhow::Result<()> {
    let cursor = std::io::Cursor::new(bytes);
    let gz = flate2::read::GzDecoder::new(cursor);
    let mut archive = tar::Archive::new(gz);
    archive
        .unpack(dest)
        .map_err(|e| anyhow::anyhow!("tar.gz unpack error: {e}"))?;
    Ok(())
}
