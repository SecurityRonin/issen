// Feed-to-engine loader.
//
// Loads all cached threat intel feeds from a registry, parses them
// using the appropriate format parser, and assembles a unified ScanEngine
// ready for matching.

use thiserror::Error;
use tracing::{debug, info, warn};

use crate::engines::ioc_hash::HashIocStore;
use crate::engines::ioc_network::NetworkIocStore;
use crate::feeds::config::{FeedFormat, FeedIndicatorType, FeedRegistry};
use crate::feeds::fetcher::{FeedCache, FeedError};
use crate::feeds::parsers::{self, FeedParseError};
use crate::matching::engine::ScanEngine;

/// Errors from the feed loader.
#[derive(Debug, Error)]
pub enum LoaderError {
    #[error("Feed error: {0}")]
    Feed(#[from] FeedError),
    #[error("Parse error: {0}")]
    Parse(#[from] FeedParseError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Summary of a feed loading operation.
#[derive(Debug, Clone, Default)]
pub struct LoadSummary {
    /// Number of feeds that were successfully loaded and parsed.
    pub feeds_loaded: usize,
    /// Number of feeds that were skipped (not cached, unsupported format, etc.).
    pub feeds_skipped: usize,
    /// Total number of hash indicators loaded across all feeds.
    pub hash_indicators: usize,
    /// Total number of network indicators loaded across all feeds.
    pub network_indicators: usize,
    /// Total number of KEV vulnerabilities loaded.
    pub kev_vulnerabilities: usize,
}

/// Load all cached feeds from a registry into a ScanEngine.
///
/// Iterates over all enabled feeds in the registry. For each feed that
/// has cached data, loads and parses it into the appropriate IOC store(s).
/// Returns a fully-assembled `ScanEngine` and a `LoadSummary` with counts.
///
/// Feeds that are not cached or have unsupported formats are skipped
/// (counted in `feeds_skipped`).
pub fn load_cached_feeds(
    registry: &FeedRegistry,
    cache: &FeedCache,
) -> Result<(ScanEngine, LoadSummary), LoaderError> {
    let mut engine = ScanEngine::new();
    let mut summary = LoadSummary::default();

    let enabled = registry.enabled_feeds();
    info!(
        enabled_feeds = enabled.len(),
        "loading cached feeds into scan engine"
    );

    for feed in &enabled {
        // Skip feeds that are not in the cache.
        if !cache.is_cached(&feed.id) {
            debug!(feed_id = %feed.id, "feed not cached, skipping");
            summary.feeds_skipped += 1;
            continue;
        }

        // Load the raw data from cache.
        let data = cache.load_data_string(&feed.id)?;

        // Parse based on format + indicator type combination.
        match (feed.format, feed.indicator_type) {
            (FeedFormat::PlainText, FeedIndicatorType::Hash) => {
                let mut store = HashIocStore::new(&feed.id);
                let count = parsers::parse_plaintext_hashes(&data, &mut store)?;
                debug!(feed_id = %feed.id, indicators = count, "loaded hash feed");
                summary.hash_indicators += count;
                engine.add_hash_store(store);
                summary.feeds_loaded += 1;
            }
            (FeedFormat::PlainText, FeedIndicatorType::Ip)
            | (FeedFormat::PlainText, FeedIndicatorType::Domain) => {
                let mut store = NetworkIocStore::new(&feed.id);
                let count = parsers::parse_plaintext_network(&data, &mut store)?;
                debug!(feed_id = %feed.id, indicators = count, "loaded network feed");
                summary.network_indicators += count;
                engine.add_network_store(store);
                summary.feeds_loaded += 1;
            }
            (FeedFormat::Csv, FeedIndicatorType::Mixed) => {
                let mut hash_store = HashIocStore::new(&feed.id);
                let mut network_store = NetworkIocStore::new(&feed.id);
                let count =
                    parsers::parse_threatfox_csv(&data, &mut hash_store, &mut network_store)?;
                debug!(feed_id = %feed.id, indicators = count, "loaded CSV feed");
                // Count hash and network indicators separately.
                summary.hash_indicators += hash_store.bad_count();
                summary.network_indicators += network_store.ip_count()
                    + network_store.cidr_count()
                    + network_store.domain_count();
                engine.add_hash_store(hash_store);
                engine.add_network_store(network_store);
                summary.feeds_loaded += 1;
            }
            (FeedFormat::Json, FeedIndicatorType::Mixed) => {
                // CISA KEV or similar JSON feeds with mixed indicator types.
                let vulns = parsers::parse_cisa_kev(&data)?;
                debug!(feed_id = %feed.id, vulnerabilities = vulns.len(), "loaded KEV feed");
                summary.kev_vulnerabilities += vulns.len();
                summary.feeds_loaded += 1;
                // KEV vulnerabilities are counted but don't populate an IOC store
                // (they require different handling — patch auditing, not IOC matching).
            }
            _ => {
                // Unsupported format/type combinations (STIX, YARA rules, Sigma rules, etc.)
                // need specialized engines — skip for now.
                warn!(
                    feed_id = %feed.id,
                    format = ?feed.format,
                    indicator_type = ?feed.indicator_type,
                    "unsupported feed format/type, skipping"
                );
                summary.feeds_skipped += 1;
            }
        }
    }

    info!(
        feeds_loaded = summary.feeds_loaded,
        feeds_skipped = summary.feeds_skipped,
        hash_indicators = summary.hash_indicators,
        network_indicators = summary.network_indicators,
        kev_vulnerabilities = summary.kev_vulnerabilities,
        "feed loading complete"
    );

    Ok((engine, summary))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feeds::config::*;

    /// Helper: create a FeedConfig with the given parameters.
    fn make_feed(
        id: &str,
        format: FeedFormat,
        indicator_type: FeedIndicatorType,
        enabled: bool,
    ) -> FeedConfig {
        FeedConfig {
            id: id.into(),
            name: id.into(),
            description: format!("Test feed: {id}"),
            url: None,
            format,
            indicator_type,
            update_frequency: UpdateFrequency::Daily,
            enabled,
            requires_api_key: false,
            csv_column: None,
            license: None,
        }
    }

    // ── 1. Empty registry ────────────────────────────────────────────

    #[test]
    fn test_empty_registry() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let registry = FeedRegistry::new(dir.path());
        let cache = FeedCache::new(dir.path());

        let (engine, summary) = load_cached_feeds(&registry, &cache).expect("load");

        assert_eq!(summary.feeds_loaded, 0);
        assert_eq!(summary.feeds_skipped, 0);
        assert_eq!(summary.hash_indicators, 0);
        assert_eq!(summary.network_indicators, 0);
        assert_eq!(summary.kev_vulnerabilities, 0);

        let stats = engine.stats();
        assert_eq!(stats.hash_stores, 0);
        assert_eq!(stats.network_stores, 0);
    }

    // ── 2. Uncached feeds skipped ────────────────────────────────────

    #[test]
    fn test_uncached_feeds_skipped() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut registry = FeedRegistry::new(dir.path());
        registry.add_feed(make_feed(
            "hash-feed",
            FeedFormat::PlainText,
            FeedIndicatorType::Hash,
            true,
        ));
        registry.add_feed(make_feed(
            "ip-feed",
            FeedFormat::PlainText,
            FeedIndicatorType::Ip,
            true,
        ));

        let cache = FeedCache::new(dir.path());
        // Don't cache anything.

        let (_engine, summary) = load_cached_feeds(&registry, &cache).expect("load");

        assert_eq!(summary.feeds_loaded, 0);
        assert_eq!(summary.feeds_skipped, 2);
    }

    // ── 3. Load plaintext hash feed ──────────────────────────────────

    #[test]
    fn test_load_plaintext_hash_feed() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());

        let hash_data = "# comment\n\
                          e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
                          d41d8cd98f00b204e9800998ecf8427e\n";
        cache
            .store_data("hash-feed", hash_data.as_bytes(), 0)
            .expect("store");

        let mut registry = FeedRegistry::new(dir.path());
        registry.add_feed(make_feed(
            "hash-feed",
            FeedFormat::PlainText,
            FeedIndicatorType::Hash,
            true,
        ));

        let (engine, summary) = load_cached_feeds(&registry, &cache).expect("load");

        assert_eq!(summary.feeds_loaded, 1);
        assert_eq!(summary.hash_indicators, 2);

        let stats = engine.stats();
        assert_eq!(stats.hash_stores, 1);
        assert_eq!(stats.total_bad_hashes, 2);
    }

    // ── 4. Load plaintext network feed ───────────────────────────────

    #[test]
    fn test_load_plaintext_network_feed() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());

        let ip_data = "# Feodo Tracker\n10.0.0.1\n10.0.0.2\n192.168.0.0/16\n";
        cache
            .store_data("ip-feed", ip_data.as_bytes(), 0)
            .expect("store");

        let mut registry = FeedRegistry::new(dir.path());
        registry.add_feed(make_feed(
            "ip-feed",
            FeedFormat::PlainText,
            FeedIndicatorType::Ip,
            true,
        ));

        let (engine, summary) = load_cached_feeds(&registry, &cache).expect("load");

        assert_eq!(summary.feeds_loaded, 1);
        assert_eq!(summary.network_indicators, 3);

        let stats = engine.stats();
        assert_eq!(stats.network_stores, 1);
    }

    // ── 5. Load ThreatFox CSV feed ───────────────────────────────────

    #[test]
    fn test_load_threatfox_csv() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());

        let csv_data = "# ThreatFox CSV\n\
            \"2024-01-01\",\"sha256_hash\",\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"botnet\",\"Emotet\",\"75\"\n\
            \"2024-01-01\",\"ip:port\",\"10.0.0.1:4444\",\"c2\",\"CobaltStrike\",\"90\"\n\
            \"2024-01-01\",\"domain\",\"evil.example.com\",\"c2\",\"Qakbot\",\"80\"\n";
        cache
            .store_data("csv-feed", csv_data.as_bytes(), 0)
            .expect("store");

        let mut registry = FeedRegistry::new(dir.path());
        registry.add_feed(make_feed(
            "csv-feed",
            FeedFormat::Csv,
            FeedIndicatorType::Mixed,
            true,
        ));

        let (engine, summary) = load_cached_feeds(&registry, &cache).expect("load");

        assert_eq!(summary.feeds_loaded, 1);
        assert_eq!(summary.hash_indicators, 1);
        assert_eq!(summary.network_indicators, 2);

        let stats = engine.stats();
        assert_eq!(stats.hash_stores, 1);
        assert_eq!(stats.network_stores, 1);
    }

    // ── 6. Load CISA KEV JSON feed ───────────────────────────────────

    #[test]
    fn test_load_cisa_kev() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());

        let kev_data = r#"{
            "title": "CISA KEV",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-1234",
                    "vendorProject": "Microsoft",
                    "product": "Windows",
                    "vulnerabilityName": "Windows RCE",
                    "shortDescription": "An RCE vulnerability",
                    "knownRansomwareCampaignUse": "Known"
                },
                {
                    "cveID": "CVE-2024-5678",
                    "vendorProject": "Apache",
                    "product": "Log4j",
                    "vulnerabilityName": "Log4Shell",
                    "shortDescription": "JNDI injection",
                    "knownRansomwareCampaignUse": "Known"
                }
            ]
        }"#;
        cache
            .store_data("kev-feed", kev_data.as_bytes(), 0)
            .expect("store");

        let mut registry = FeedRegistry::new(dir.path());
        registry.add_feed(make_feed(
            "kev-feed",
            FeedFormat::Json,
            FeedIndicatorType::Mixed,
            true,
        ));

        let (_engine, summary) = load_cached_feeds(&registry, &cache).expect("load");

        assert_eq!(summary.feeds_loaded, 1);
        assert_eq!(summary.kev_vulnerabilities, 2);
    }

    // ── 7. Mixed cached and uncached ─────────────────────────────────

    #[test]
    fn test_mixed_cached_and_uncached() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());

        // Cache only one of two feeds.
        let hash_data = "d41d8cd98f00b204e9800998ecf8427e\n";
        cache
            .store_data("cached-hash", hash_data.as_bytes(), 0)
            .expect("store");

        let mut registry = FeedRegistry::new(dir.path());
        registry.add_feed(make_feed(
            "cached-hash",
            FeedFormat::PlainText,
            FeedIndicatorType::Hash,
            true,
        ));
        registry.add_feed(make_feed(
            "uncached-ip",
            FeedFormat::PlainText,
            FeedIndicatorType::Ip,
            true,
        ));

        let (_engine, summary) = load_cached_feeds(&registry, &cache).expect("load");

        assert_eq!(summary.feeds_loaded, 1);
        assert_eq!(summary.feeds_skipped, 1);
        assert_eq!(summary.hash_indicators, 1);
        assert_eq!(summary.network_indicators, 0);
    }

    // ── 8. Summary counts correct ────────────────────────────────────

    #[test]
    fn test_summary_counts_correct() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());

        // Hash feed with 2 indicators.
        let hash_data = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
                          d41d8cd98f00b204e9800998ecf8427e\n";
        cache
            .store_data("hash-feed", hash_data.as_bytes(), 0)
            .expect("store");

        // IP feed with 3 indicators.
        let ip_data = "10.0.0.1\n10.0.0.2\n10.0.0.3\n";
        cache
            .store_data("ip-feed", ip_data.as_bytes(), 0)
            .expect("store");

        // KEV feed with 1 vulnerability.
        let kev_data = r#"{"vulnerabilities": [
            {
                "cveID": "CVE-2024-9999",
                "vendorProject": "Vendor",
                "product": "Product",
                "vulnerabilityName": "Vuln",
                "shortDescription": "Desc",
                "knownRansomwareCampaignUse": "Unknown"
            }
        ]}"#;
        cache
            .store_data("kev-feed", kev_data.as_bytes(), 0)
            .expect("store");

        // YARA feed — should be skipped (unsupported).
        cache
            .store_data("yara-feed", b"rule test { condition: true }", 0)
            .expect("store");

        // Uncached feed — should be skipped.
        // (no store_data call)

        let mut registry = FeedRegistry::new(dir.path());
        registry.add_feed(make_feed(
            "hash-feed",
            FeedFormat::PlainText,
            FeedIndicatorType::Hash,
            true,
        ));
        registry.add_feed(make_feed(
            "ip-feed",
            FeedFormat::PlainText,
            FeedIndicatorType::Ip,
            true,
        ));
        registry.add_feed(make_feed(
            "kev-feed",
            FeedFormat::Json,
            FeedIndicatorType::Mixed,
            true,
        ));
        registry.add_feed(make_feed(
            "yara-feed",
            FeedFormat::Yara,
            FeedIndicatorType::YaraRules,
            true,
        ));
        registry.add_feed(make_feed(
            "uncached-feed",
            FeedFormat::PlainText,
            FeedIndicatorType::Domain,
            true,
        ));

        let (engine, summary) = load_cached_feeds(&registry, &cache).expect("load");

        assert_eq!(summary.feeds_loaded, 3);
        assert_eq!(summary.feeds_skipped, 2); // yara + uncached
        assert_eq!(summary.hash_indicators, 2);
        assert_eq!(summary.network_indicators, 3);
        assert_eq!(summary.kev_vulnerabilities, 1);

        let stats = engine.stats();
        assert_eq!(stats.hash_stores, 1);
        assert_eq!(stats.network_stores, 1);
        assert_eq!(stats.total_bad_hashes, 2);
    }

    // ── 9. Disabled feeds skipped ────────────────────────────────────

    #[test]
    fn test_disabled_feeds_skipped() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());

        // Cache data for both feeds.
        let hash_data = "d41d8cd98f00b204e9800998ecf8427e\n";
        cache
            .store_data("enabled-feed", hash_data.as_bytes(), 0)
            .expect("store");
        cache
            .store_data("disabled-feed", hash_data.as_bytes(), 0)
            .expect("store");

        let mut registry = FeedRegistry::new(dir.path());
        registry.add_feed(make_feed(
            "enabled-feed",
            FeedFormat::PlainText,
            FeedIndicatorType::Hash,
            true,
        ));
        registry.add_feed(make_feed(
            "disabled-feed",
            FeedFormat::PlainText,
            FeedIndicatorType::Hash,
            false, // disabled!
        ));

        let (_engine, summary) = load_cached_feeds(&registry, &cache).expect("load");

        // Only the enabled feed should be loaded.
        assert_eq!(summary.feeds_loaded, 1);
        assert_eq!(summary.hash_indicators, 1);
    }

    // ── 10. Domain feeds use network parser ──────────────────────────

    #[test]
    fn test_load_plaintext_domain_feed() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());

        let domain_data = "# Malicious domains\nevil.com\nbad-site.org\n";
        cache
            .store_data("domain-feed", domain_data.as_bytes(), 0)
            .expect("store");

        let mut registry = FeedRegistry::new(dir.path());
        registry.add_feed(make_feed(
            "domain-feed",
            FeedFormat::PlainText,
            FeedIndicatorType::Domain,
            true,
        ));

        let (engine, summary) = load_cached_feeds(&registry, &cache).expect("load");

        assert_eq!(summary.feeds_loaded, 1);
        assert_eq!(summary.network_indicators, 2);

        let stats = engine.stats();
        assert_eq!(stats.network_stores, 1);
    }

    // ── 11. Unsupported formats are skipped ──────────────────────────

    #[test]
    fn test_unsupported_formats_skipped() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());

        // Cache data for unsupported format feeds.
        cache.store_data("stix-feed", b"{}", 0).expect("store");
        cache
            .store_data("sigma-feed", b"title: test", 0)
            .expect("store");

        let mut registry = FeedRegistry::new(dir.path());
        registry.add_feed(make_feed(
            "stix-feed",
            FeedFormat::Stix,
            FeedIndicatorType::Mixed,
            true,
        ));
        registry.add_feed(make_feed(
            "sigma-feed",
            FeedFormat::Sigma,
            FeedIndicatorType::SigmaRules,
            true,
        ));

        let (_engine, summary) = load_cached_feeds(&registry, &cache).expect("load");

        assert_eq!(summary.feeds_loaded, 0);
        assert_eq!(summary.feeds_skipped, 2);
    }

    // ── 12. Engine has correct stores after loading ──────────────────

    #[test]
    fn test_engine_stores_populated() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cache = FeedCache::new(dir.path());

        // Two hash feeds and one network feed.
        let hash_data_1 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n";
        let hash_data_2 = "d41d8cd98f00b204e9800998ecf8427e\n";
        let ip_data = "10.0.0.1\n";

        cache
            .store_data("hash-1", hash_data_1.as_bytes(), 0)
            .expect("store");
        cache
            .store_data("hash-2", hash_data_2.as_bytes(), 0)
            .expect("store");
        cache
            .store_data("ip-1", ip_data.as_bytes(), 0)
            .expect("store");

        let mut registry = FeedRegistry::new(dir.path());
        registry.add_feed(make_feed(
            "hash-1",
            FeedFormat::PlainText,
            FeedIndicatorType::Hash,
            true,
        ));
        registry.add_feed(make_feed(
            "hash-2",
            FeedFormat::PlainText,
            FeedIndicatorType::Hash,
            true,
        ));
        registry.add_feed(make_feed(
            "ip-1",
            FeedFormat::PlainText,
            FeedIndicatorType::Ip,
            true,
        ));

        let (engine, summary) = load_cached_feeds(&registry, &cache).expect("load");

        assert_eq!(summary.feeds_loaded, 3);

        let stats = engine.stats();
        assert_eq!(stats.hash_stores, 2);
        assert_eq!(stats.network_stores, 1);
        assert_eq!(stats.total_bad_hashes, 2);
    }
}
