use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};

use crate::model::{FeedKind, FeedSpec};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncOptions {
    pub suricata_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncResult {
    pub feed_name: String,
    pub source_url: String,
    pub archive_path: PathBuf,
    pub extracted_to: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("sync manifest serialization error: {0}")]
    ManifestSerialize(serde_json::Error),

    #[error("sync manifest parse error: {0}")]
    ManifestDeserialize(serde_json::Error),
}

#[must_use]
pub fn render_feed_url(feed: &FeedSpec, options: &SyncOptions) -> String {
    match feed.kind {
        FeedKind::SuricataUpdate => {
            let version = options
                .suricata_version
                .as_deref()
                .unwrap_or("8.0")
                .to_string();
            feed.url.replace("%(__version__)s", &version)
        }
        FeedKind::GitArchive => feed.url.clone(),
    }
}

/// Download and extract a single feed into `root`.
///
/// # Errors
///
/// Returns [`SyncError::Http`] on network failure, [`SyncError::Io`] on file-system
/// failure, or [`SyncError::Zip`] if archive extraction fails.
pub fn sync_feed(
    feed: &FeedSpec,
    root: &Path,
    options: &SyncOptions,
) -> Result<SyncResult, SyncError> {
    let source_url = render_feed_url(feed, options);
    let response = reqwest::blocking::get(&source_url)?.error_for_status()?;
    let bytes = response.bytes()?;

    let feed_root = root.join(sanitize_feed_name(&feed.name));
    let downloads_dir = feed_root.join("downloads");
    let extracted_to = feed_root.join("current");
    fs::create_dir_all(&downloads_dir)?;

    let archive_name = archive_file_name(feed, &source_url);
    let archive_path = downloads_dir.join(archive_name);
    fs::write(&archive_path, &bytes)?;
    materialize_download(feed, &bytes, &extracted_to)?;

    Ok(SyncResult {
        feed_name: feed.name.clone(),
        source_url,
        archive_path,
        extracted_to,
    })
}

/// Download and extract every feed in `feeds` into `root`.
///
/// # Errors
///
/// Returns the first [`SyncError`] encountered.
pub fn sync_registry(
    feeds: &[FeedSpec],
    root: &Path,
    options: &SyncOptions,
) -> Result<Vec<SyncResult>, SyncError> {
    feeds
        .iter()
        .map(|feed| sync_feed(feed, root, options))
        .collect()
}

/// Persist a slice of [`SyncResult`] records to `<root>/sync-manifest.json`.
///
/// # Errors
///
/// Returns [`SyncError::Io`] on write failure or [`SyncError::ManifestSerialize`]
/// if JSON serialization fails.
pub fn persist_sync_manifest(root: &Path, records: &[SyncResult]) -> Result<(), SyncError> {
    fs::create_dir_all(root)?;
    let manifest_path = root.join("sync-manifest.json");
    let json = serde_json::to_vec_pretty(records).map_err(SyncError::ManifestSerialize)?;
    fs::write(manifest_path, json)?;
    Ok(())
}

/// Load a previously persisted sync manifest from `<root>/sync-manifest.json`.
///
/// # Errors
///
/// Returns [`SyncError::Io`] if the file cannot be read, or
/// [`SyncError::ManifestDeserialize`] if the JSON is malformed.
pub fn load_sync_manifest(root: &Path) -> Result<Vec<SyncResult>, SyncError> {
    let manifest_path = root.join("sync-manifest.json");
    let raw = fs::read(manifest_path)?;
    serde_json::from_slice(&raw).map_err(SyncError::ManifestDeserialize)
}

/// Extract a downloaded archive into `destination`.
///
/// # Errors
///
/// Returns [`SyncError::Io`] on file-system failure or [`SyncError::Zip`] on
/// ZIP extraction failure.
pub fn materialize_download(
    feed: &FeedSpec,
    bytes: &[u8],
    destination: &Path,
) -> Result<(), SyncError> {
    if destination.exists() {
        fs::remove_dir_all(destination)?;
    }
    fs::create_dir_all(destination)?;

    match feed.kind {
        FeedKind::GitArchive => unpack_zip(bytes, destination),
        FeedKind::SuricataUpdate => unpack_tar_gz(bytes, destination),
    }
}

fn unpack_zip(bytes: &[u8], destination: &Path) -> Result<(), SyncError> {
    let reader = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(reader)?;
    archive.extract(destination)?;
    Ok(())
}

fn unpack_tar_gz(bytes: &[u8], destination: &Path) -> Result<(), SyncError> {
    let cursor = Cursor::new(bytes);
    let mut archive = tar::Archive::new(GzDecoder::new(cursor));
    archive.unpack(destination)?;
    Ok(())
}

fn archive_file_name(feed: &FeedSpec, source_url: &str) -> String {
    match feed.kind {
        FeedKind::GitArchive => {
            file_name_from_url(source_url).unwrap_or_else(|| "archive.zip".into())
        }
        FeedKind::SuricataUpdate => {
            file_name_from_url(source_url).unwrap_or_else(|| "emerging.rules.tar.gz".into())
        }
    }
}

fn file_name_from_url(url: &str) -> Option<String> {
    let mut parts = url.rsplit('/');
    let candidate = parts.next()?;
    if candidate.is_empty() {
        None
    } else {
        Some(candidate.to_string())
    }
}

fn sanitize_feed_name(name: &str) -> String {
    name.replace('/', "_")
}

#[allow(dead_code)]
fn read_to_vec(path: &Path) -> Result<Vec<u8>, SyncError> {
    let mut file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}
