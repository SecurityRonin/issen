// Feed fetching and local caching.
//
// Manages downloading threat intel feeds to a local cache directory,
// loading cached data, and tracking feed freshness via metadata files.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::config::FeedConfig;

/// Errors from feed operations.
#[derive(Debug, Error)]
pub enum FeedError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Feed not found in cache: {0}")]
    NotCached(String),

    #[error("Feed metadata parse error: {0}")]
    MetadataParse(String),
}

/// Metadata about a cached feed file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedMetadata {
    /// Feed ID.
    pub feed_id: String,
    /// When the feed was last fetched (ISO 8601).
    pub last_fetched: String,
    /// HTTP ETag for conditional requests.
    pub etag: Option<String>,
    /// Number of indicators loaded from this feed.
    pub indicator_count: usize,
    /// File size in bytes.
    pub file_size: u64,
}

/// Local feed cache manager.
///
/// Manages a directory of cached feed data files and their metadata.
/// Feeds are stored as `{cache_dir}/{feed_id}/data` with metadata
/// in `{cache_dir}/{feed_id}/metadata.json`.
#[derive(Debug)]
pub struct FeedCache {
    cache_dir: PathBuf,
}

impl FeedCache {
    /// Create a new cache manager for the given directory.
    pub fn new(cache_dir: impl Into<PathBuf>) -> Self {
        Self {
            cache_dir: cache_dir.into(),
        }
    }

    /// Get the base cache directory.
    #[must_use]
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Ensure the cache directory structure exists for a feed.
    pub fn ensure_feed_dir(&self, feed_id: &str) -> Result<PathBuf, FeedError> {
        let feed_dir = self.cache_dir.join(feed_id);
        fs::create_dir_all(&feed_dir)?;
        Ok(feed_dir)
    }

    /// Get the path where a feed's data file would be stored.
    #[must_use]
    pub fn data_path(&self, feed_id: &str) -> PathBuf {
        self.cache_dir.join(feed_id).join("data")
    }

    /// Get the path where a feed's metadata file would be stored.
    #[must_use]
    pub fn metadata_path(&self, feed_id: &str) -> PathBuf {
        self.cache_dir.join(feed_id).join("metadata.json")
    }

    /// Check if a feed has cached data.
    #[must_use]
    pub fn is_cached(&self, feed_id: &str) -> bool {
        self.data_path(feed_id).exists()
    }

    /// Store feed data in the cache.
    pub fn store_data(
        &self,
        feed_id: &str,
        data: &[u8],
        indicator_count: usize,
    ) -> Result<(), FeedError> {
        let feed_dir = self.ensure_feed_dir(feed_id)?;
        let data_path = feed_dir.join("data");
        fs::write(&data_path, data)?;

        // Write metadata.
        let metadata = FeedMetadata {
            feed_id: feed_id.to_string(),
            last_fetched: chrono::Utc::now().to_rfc3339(),
            etag: None,
            indicator_count,
            file_size: data.len() as u64,
        };
        let metadata_json = serde_json::to_string_pretty(&metadata)
            .map_err(|e| FeedError::MetadataParse(e.to_string()))?;
        fs::write(feed_dir.join("metadata.json"), metadata_json)?;

        Ok(())
    }

    /// Load cached feed data as bytes.
    pub fn load_data(&self, feed_id: &str) -> Result<Vec<u8>, FeedError> {
        let data_path = self.data_path(feed_id);
        if !data_path.exists() {
            return Err(FeedError::NotCached(feed_id.to_string()));
        }
        Ok(fs::read(&data_path)?)
    }

    /// Load cached feed data as a string.
    pub fn load_data_string(&self, feed_id: &str) -> Result<String, FeedError> {
        let data_path = self.data_path(feed_id);
        if !data_path.exists() {
            return Err(FeedError::NotCached(feed_id.to_string()));
        }
        Ok(fs::read_to_string(&data_path)?)
    }

    /// Load metadata for a cached feed.
    pub fn load_metadata(&self, feed_id: &str) -> Result<FeedMetadata, FeedError> {
        let meta_path = self.metadata_path(feed_id);
        if !meta_path.exists() {
            return Err(FeedError::NotCached(feed_id.to_string()));
        }
        let content = fs::read_to_string(&meta_path)?;
        serde_json::from_str(&content).map_err(|e| FeedError::MetadataParse(e.to_string()))
    }

    /// List all feed IDs that have cached data.
    pub fn list_cached_feeds(&self) -> Result<Vec<String>, FeedError> {
        if !self.cache_dir.exists() {
            return Ok(Vec::new());
        }

        let mut feeds = Vec::new();
        for entry in fs::read_dir(&self.cache_dir)? {
            let entry = entry?;
            if entry.path().is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    if self.data_path(name).exists() {
                        feeds.push(name.to_string());
                    }
                }
            }
        }
        feeds.sort();
        Ok(feeds)
    }

    /// Remove cached data for a feed.
    pub fn remove_feed(&self, feed_id: &str) -> Result<(), FeedError> {
        let feed_dir = self.cache_dir.join(feed_id);
        if feed_dir.exists() {
            fs::remove_dir_all(&feed_dir)?;
        }
        Ok(())
    }

    /// Store feed data from a local file path (copy into cache).
    pub fn store_from_file(
        &self,
        feed_id: &str,
        source_path: &Path,
        indicator_count: usize,
    ) -> Result<(), FeedError> {
        let data = fs::read(source_path)?;
        self.store_data(feed_id, &data, indicator_count)
    }
}

/// Load a feed from cache or from a local file path.
///
/// This is the primary interface for the pipeline: given a FeedConfig,
/// return the raw feed data as bytes. Checks cache first, falls back
/// to local path if configured.
pub fn load_feed_data(cache: &FeedCache, config: &FeedConfig) -> Result<Vec<u8>, FeedError> {
    // Try cache first.
    if cache.is_cached(&config.id) {
        return cache.load_data(&config.id);
    }

    Err(FeedError::NotCached(config.id.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feed_cache_new() {
        let cache = FeedCache::new("/tmp/test-feeds");
        assert_eq!(cache.cache_dir(), Path::new("/tmp/test-feeds"));
    }

    #[test]
    fn test_data_path() {
        let cache = FeedCache::new("/tmp/feeds");
        assert_eq!(
            cache.data_path("my-feed"),
            PathBuf::from("/tmp/feeds/my-feed/data")
        );
    }

    #[test]
    fn test_metadata_path() {
        let cache = FeedCache::new("/tmp/feeds");
        assert_eq!(
            cache.metadata_path("my-feed"),
            PathBuf::from("/tmp/feeds/my-feed/metadata.json")
        );
    }

    #[test]
    fn test_store_and_load_data() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());

        let data = b"10.0.0.1\n10.0.0.2\nevil.com\n";
        cache.store_data("test-feed", data, 3).expect("store");

        assert!(cache.is_cached("test-feed"));

        let loaded = cache.load_data("test-feed").expect("load");
        assert_eq!(loaded, data);
    }

    #[test]
    fn test_store_and_load_string() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());

        cache
            .store_data("string-feed", b"hello world", 1)
            .expect("store");
        let s = cache.load_data_string("string-feed").expect("load");
        assert_eq!(s, "hello world");
    }

    #[test]
    fn test_load_metadata() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());

        cache.store_data("meta-feed", b"data", 42).expect("store");

        let meta = cache.load_metadata("meta-feed").expect("load meta");
        assert_eq!(meta.feed_id, "meta-feed");
        assert_eq!(meta.indicator_count, 42);
        assert_eq!(meta.file_size, 4);
        assert!(!meta.last_fetched.is_empty());
    }

    #[test]
    fn test_not_cached() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());

        assert!(!cache.is_cached("nonexistent"));
        assert!(cache.load_data("nonexistent").is_err());
        assert!(cache.load_metadata("nonexistent").is_err());
    }

    #[test]
    fn test_list_cached_feeds() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());

        // Initially empty.
        let feeds = cache.list_cached_feeds().expect("list");
        assert!(feeds.is_empty());

        // Add some feeds.
        cache.store_data("feed-b", b"data", 1).expect("store");
        cache.store_data("feed-a", b"data", 2).expect("store");
        cache.store_data("feed-c", b"data", 3).expect("store");

        let feeds = cache.list_cached_feeds().expect("list");
        assert_eq!(feeds, vec!["feed-a", "feed-b", "feed-c"]); // sorted
    }

    #[test]
    fn test_remove_feed() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());

        cache.store_data("to-remove", b"data", 1).expect("store");
        assert!(cache.is_cached("to-remove"));

        cache.remove_feed("to-remove").expect("remove");
        assert!(!cache.is_cached("to-remove"));
    }

    #[test]
    fn test_remove_nonexistent_feed() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());

        // Should not error when removing something that doesn't exist.
        cache.remove_feed("nonexistent").expect("remove ok");
    }

    #[test]
    fn test_store_from_file() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let source_path = dir.path().join("source.txt");
        std::fs::write(&source_path, b"some feed data").expect("write source");

        let cache_dir = dir.path().join("cache");
        let cache = FeedCache::new(&cache_dir);

        cache
            .store_from_file("file-feed", &source_path, 5)
            .expect("store from file");

        assert!(cache.is_cached("file-feed"));
        let data = cache.load_data_string("file-feed").expect("load");
        assert_eq!(data, "some feed data");
    }

    #[test]
    fn test_load_feed_data_from_cache() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());

        cache
            .store_data("cached-feed", b"cached data", 1)
            .expect("store");

        let config = FeedConfig {
            id: "cached-feed".into(),
            name: "Test".into(),
            description: "Test feed".into(),
            url: None,
            format: super::super::config::FeedFormat::PlainText,
            indicator_type: super::super::config::FeedIndicatorType::Ip,
            update_frequency: super::super::config::UpdateFrequency::Daily,
            enabled: true,
            requires_api_key: false,
            csv_column: None,
            license: None,
        };

        let data = load_feed_data(&cache, &config).expect("load");
        assert_eq!(data, b"cached data");
    }

    #[test]
    fn test_load_feed_data_not_cached() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());

        let config = FeedConfig {
            id: "missing-feed".into(),
            name: "Test".into(),
            description: "Test".into(),
            url: None,
            format: super::super::config::FeedFormat::PlainText,
            indicator_type: super::super::config::FeedIndicatorType::Ip,
            update_frequency: super::super::config::UpdateFrequency::Daily,
            enabled: true,
            requires_api_key: false,
            csv_column: None,
            license: None,
        };

        assert!(load_feed_data(&cache, &config).is_err());
    }

    #[test]
    fn test_overwrite_cached_feed() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());

        cache
            .store_data("overwrite-test", b"old data", 1)
            .expect("store old");
        cache
            .store_data("overwrite-test", b"new data", 2)
            .expect("store new");

        let data = cache.load_data_string("overwrite-test").expect("load");
        assert_eq!(data, "new data");

        let meta = cache.load_metadata("overwrite-test").expect("meta");
        assert_eq!(meta.indicator_count, 2);
    }
}
