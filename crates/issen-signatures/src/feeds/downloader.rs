// HTTP feed downloader.
//
// Downloads threat intelligence feeds via HTTP and stores them in the local
// feed cache. Supports conditional requests (If-None-Match / ETag) to avoid
// re-downloading unchanged feeds.

use thiserror::Error;
use tracing::info;

use super::config::{FeedConfig, FeedRegistry};
use super::fetcher::{FeedCache, FeedError};

/// Errors that can occur during feed download.
#[derive(Debug, Error)]
pub enum DownloadError {
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("Feed has no URL configured")]
    NoUrl,
    #[error("Cache error: {0}")]
    Cache(#[from] FeedError),
}

/// Result of attempting to download a single feed.
#[derive(Debug, Clone)]
pub struct DownloadResult {
    /// Feed identifier.
    pub feed_id: String,
    /// Outcome of the download attempt.
    pub status: DownloadStatus,
    /// Number of bytes downloaded (0 if skipped or not modified).
    pub bytes_downloaded: u64,
}

/// Outcome status for a feed download attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownloadStatus {
    /// Feed was successfully downloaded and cached.
    Downloaded,
    /// Server returned 304 Not Modified (cache is still fresh).
    NotModified,
    /// Feed was skipped (with reason).
    Skipped(String),
    /// Download failed (with error message).
    Failed(String),
}

/// Download a single feed and store it in the cache.
///
/// Logic:
/// 1. If `config.url` is None, return Skipped.
/// 2. If `!config.enabled`, return Skipped.
/// 3. If `config.requires_api_key`, return Skipped.
/// 4. Build a reqwest blocking client.
/// 5. If the cache has an etag for this feed, add `If-None-Match` header.
/// 6. Send GET request.
/// 7. If 304, return NotModified.
/// 8. If 200, store response bytes in cache and return Downloaded.
/// 9. On error, return Failed.
pub fn download_feed(config: &FeedConfig, cache: &FeedCache) -> DownloadResult {
    let feed_id = config.id.clone();

    // Check preconditions.
    if !config.enabled {
        return DownloadResult {
            feed_id,
            status: DownloadStatus::Skipped("feed disabled".into()),
            bytes_downloaded: 0,
        };
    }

    if config.requires_api_key {
        return DownloadResult {
            feed_id,
            status: DownloadStatus::Skipped("requires API key".into()),
            bytes_downloaded: 0,
        };
    }

    let Some(url) = config.url.as_deref() else {
        return DownloadResult {
            feed_id,
            status: DownloadStatus::Skipped("no URL configured".into()),
            bytes_downloaded: 0,
        };
    };

    // Build the HTTP client.
    let client = match reqwest::blocking::Client::builder()
        .user_agent("Issen/0.1")
        .timeout(std::time::Duration::from_secs(120))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return DownloadResult {
                feed_id,
                status: DownloadStatus::Failed(format!("failed to build HTTP client: {e}")),
                bytes_downloaded: 0,
            };
        }
    };

    // Check for cached etag for conditional request.
    let mut request = client.get(url);
    if let Ok(metadata) = cache.load_metadata(&feed_id) {
        if let Some(ref etag) = metadata.etag {
            request = request.header("If-None-Match", etag.as_str());
        }
    }

    // Execute the request.
    info!(feed_id = %feed_id, url = %url, "downloading feed");
    let response = match request.send() {
        Ok(r) => r,
        Err(e) => {
            return DownloadResult {
                feed_id,
                status: DownloadStatus::Failed(format!("HTTP request failed: {e}")),
                bytes_downloaded: 0,
            };
        }
    };

    let status_code = response.status();

    // 304 Not Modified — cache is still fresh.
    if status_code == reqwest::StatusCode::NOT_MODIFIED {
        info!(feed_id = %feed_id, "feed not modified (304)");
        return DownloadResult {
            feed_id,
            status: DownloadStatus::NotModified,
            bytes_downloaded: 0,
        };
    }

    // Non-success status codes.
    if !status_code.is_success() {
        return DownloadResult {
            feed_id,
            status: DownloadStatus::Failed(format!("HTTP {}", status_code)),
            bytes_downloaded: 0,
        };
    }

    // Extract etag from response before consuming the body.
    let etag = response
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Read the response body.
    let bytes = match response.bytes() {
        Ok(b) => b,
        Err(e) => {
            return DownloadResult {
                feed_id,
                status: DownloadStatus::Failed(format!("failed to read response body: {e}")),
                bytes_downloaded: 0,
            };
        }
    };

    let byte_count = bytes.len() as u64;

    // Store in cache.
    if let Err(e) = cache.store_data(&feed_id, &bytes, 0) {
        return DownloadResult {
            feed_id,
            status: DownloadStatus::Failed(format!("cache store failed: {e}")),
            bytes_downloaded: byte_count,
        };
    }

    // If the server returned an ETag, update the metadata to include it.
    if let Some(etag_value) = etag {
        if let Ok(mut metadata) = cache.load_metadata(&feed_id) {
            metadata.etag = Some(etag_value);
            // Re-write metadata with etag.
            let meta_path = cache.metadata_path(&feed_id);
            if let Ok(json) = serde_json::to_string_pretty(&metadata) {
                let _ = std::fs::write(meta_path, json);
            }
        }
    }

    info!(feed_id = %feed_id, bytes = byte_count, "feed downloaded successfully");

    DownloadResult {
        feed_id,
        status: DownloadStatus::Downloaded,
        bytes_downloaded: byte_count,
    }
}

/// Download all enabled feeds with URLs from a registry.
///
/// Iterates through enabled feeds and calls `download_feed` for each.
/// Returns a result for every enabled feed.
pub fn download_all_feeds(registry: &FeedRegistry, cache: &FeedCache) -> Vec<DownloadResult> {
    let enabled = registry.enabled_feeds();
    enabled
        .iter()
        .map(|config| download_feed(config, cache))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feeds::config::{FeedFormat, FeedIndicatorType, FeedRegistry, UpdateFrequency};

    /// Helper to create a FeedConfig for testing.
    fn test_feed_config(
        id: &str,
        url: Option<&str>,
        enabled: bool,
        requires_api_key: bool,
    ) -> FeedConfig {
        FeedConfig {
            id: id.into(),
            name: format!("Test Feed {id}"),
            description: "A test feed".into(),
            url: url.map(String::from),
            format: FeedFormat::PlainText,
            indicator_type: FeedIndicatorType::Ip,
            update_frequency: UpdateFrequency::Daily,
            enabled,
            requires_api_key,
            csv_column: None,
            license: None,
        }
    }

    #[test]
    fn test_download_no_url() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());
        let config = test_feed_config("no-url", None, true, false);

        let result = download_feed(&config, &cache);
        assert_eq!(result.feed_id, "no-url");
        assert_eq!(
            result.status,
            DownloadStatus::Skipped("no URL configured".into())
        );
        assert_eq!(result.bytes_downloaded, 0);
    }

    #[test]
    fn test_download_disabled() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());
        let config = test_feed_config(
            "disabled",
            Some("https://example.com/feed.txt"),
            false,
            false,
        );

        let result = download_feed(&config, &cache);
        assert_eq!(result.feed_id, "disabled");
        assert_eq!(
            result.status,
            DownloadStatus::Skipped("feed disabled".into())
        );
        assert_eq!(result.bytes_downloaded, 0);
    }

    #[test]
    fn test_download_requires_api_key() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());
        let config = test_feed_config("api-feed", Some("https://example.com/feed.txt"), true, true);

        let result = download_feed(&config, &cache);
        assert_eq!(result.feed_id, "api-feed");
        assert_eq!(
            result.status,
            DownloadStatus::Skipped("requires API key".into())
        );
        assert_eq!(result.bytes_downloaded, 0);
    }

    #[test]
    fn test_download_status_equality() {
        assert_eq!(DownloadStatus::Downloaded, DownloadStatus::Downloaded);
        assert_eq!(DownloadStatus::NotModified, DownloadStatus::NotModified);
        assert_eq!(
            DownloadStatus::Skipped("reason".into()),
            DownloadStatus::Skipped("reason".into())
        );
        assert_eq!(
            DownloadStatus::Failed("err".into()),
            DownloadStatus::Failed("err".into())
        );
        assert_ne!(DownloadStatus::Downloaded, DownloadStatus::NotModified);
        assert_ne!(
            DownloadStatus::Skipped("a".into()),
            DownloadStatus::Skipped("b".into())
        );
    }

    #[test]
    fn test_download_result_construction() {
        let result = DownloadResult {
            feed_id: "test-feed".into(),
            status: DownloadStatus::Downloaded,
            bytes_downloaded: 1024,
        };
        assert_eq!(result.feed_id, "test-feed");
        assert_eq!(result.status, DownloadStatus::Downloaded);
        assert_eq!(result.bytes_downloaded, 1024);
    }

    #[test]
    fn test_download_all_empty_registry() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());
        let registry = FeedRegistry::new(dir.path().join("cache"));

        let results = download_all_feeds(&registry, &cache);
        assert!(results.is_empty());
    }

    #[test]
    fn test_download_all_skips_no_url_feeds() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());
        let mut registry = FeedRegistry::new(dir.path().join("cache"));

        // Add feeds without URLs (enabled).
        registry.add_feed(test_feed_config("feed-a", None, true, false));
        registry.add_feed(test_feed_config("feed-b", None, true, false));

        let results = download_all_feeds(&registry, &cache);
        assert_eq!(results.len(), 2);
        for r in &results {
            assert_eq!(
                r.status,
                DownloadStatus::Skipped("no URL configured".into())
            );
        }
    }

    #[test]
    fn test_download_invalid_url_fails() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());
        let config = test_feed_config(
            "bad-url",
            Some("http://127.0.0.1:1/nonexistent"),
            true,
            false,
        );

        let result = download_feed(&config, &cache);
        assert_eq!(result.feed_id, "bad-url");
        match &result.status {
            DownloadStatus::Failed(msg) => {
                assert!(
                    msg.contains("HTTP request failed"),
                    "Expected connection error, got: {msg}"
                );
            }
            other => panic!("Expected Failed status, got: {other:?}"),
        }
        assert_eq!(result.bytes_downloaded, 0);
    }

    #[test]
    fn test_download_all_mixed_feeds() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());
        let mut registry = FeedRegistry::new(dir.path().join("cache"));

        // One enabled with URL (will fail on connection), one disabled, one no URL.
        registry.add_feed(test_feed_config("feed-no-url", None, true, false));
        registry.add_feed(test_feed_config(
            "feed-disabled",
            Some("https://example.com/feed.txt"),
            false,
            false,
        ));
        registry.add_feed(test_feed_config(
            "feed-api-key",
            Some("https://example.com"),
            true,
            true,
        ));

        // Only enabled feeds are returned by enabled_feeds(), so disabled won't appear.
        let results = download_all_feeds(&registry, &cache);
        // enabled_feeds filters out disabled, so we get 2 (no-url and api-key).
        assert_eq!(results.len(), 2);

        // Check feed-no-url is skipped.
        let no_url = results.iter().find(|r| r.feed_id == "feed-no-url").unwrap();
        assert_eq!(
            no_url.status,
            DownloadStatus::Skipped("no URL configured".into())
        );

        // Check feed-api-key is skipped.
        let api = results
            .iter()
            .find(|r| r.feed_id == "feed-api-key")
            .unwrap();
        assert_eq!(
            api.status,
            DownloadStatus::Skipped("requires API key".into())
        );
    }

    /// Download the CISA KEV feed (small, public, free).
    /// This test makes a real HTTP request and is marked #[ignore] for CI.
    #[test]
    #[ignore]
    fn test_download_real_feed() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());
        let config = FeedConfig {
            id: "cisa-kev".into(),
            name: "CISA KEV".into(),
            description: "Known Exploited Vulnerabilities".into(),
            url: Some(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
                    .into(),
            ),
            format: FeedFormat::Json,
            indicator_type: FeedIndicatorType::Mixed,
            update_frequency: UpdateFrequency::Daily,
            enabled: true,
            requires_api_key: false,
            csv_column: None,
            license: Some("Public Domain".into()),
        };

        let result = download_feed(&config, &cache);
        assert_eq!(result.feed_id, "cisa-kev");
        assert_eq!(result.status, DownloadStatus::Downloaded);
        assert!(
            result.bytes_downloaded > 1000,
            "CISA KEV should be at least 1KB, got {} bytes",
            result.bytes_downloaded
        );

        // Verify data is in cache.
        assert!(cache.is_cached("cisa-kev"));
        let data = cache.load_data("cisa-kev").expect("load cached data");
        assert_eq!(data.len() as u64, result.bytes_downloaded);

        // Verify it looks like JSON.
        let text = String::from_utf8_lossy(&data);
        assert!(
            text.contains("vulnerabilities"),
            "Should contain vulnerability data"
        );
    }
}
