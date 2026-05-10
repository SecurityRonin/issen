use std::path::Path;
use forensic_pivot::{FeedKind, FeedSpec, SyncManifest, cache_path_for_feed, is_stale};

// ──────────────────────────────────────────────────────────────────────────────
// Phase 2 tests
// ──────────────────────────────────────────────────────────────────────────────

/// 1. FeedSpec fields are accessible after construction.
#[test]
fn feed_spec_fields_are_accessible() {
    let spec = FeedSpec {
        name: "sigma-main".to_string(),
        url: "https://github.com/SigmaHQ/sigma".to_string(),
        kind: FeedKind::Sigma,
        last_synced: Some(1_700_000_000),
    };

    assert_eq!(spec.name, "sigma-main");
    assert_eq!(spec.url, "https://github.com/SigmaHQ/sigma");
    assert_eq!(spec.kind, FeedKind::Sigma);
    assert_eq!(spec.last_synced, Some(1_700_000_000));
}

/// 2. SyncManifest serializes to JSON and deserializes back correctly.
#[test]
fn sync_manifest_serializes_and_deserializes() {
    let manifest = SyncManifest {
        feeds: vec![FeedSpec {
            name: "yara-rules".to_string(),
            url: "https://github.com/Yara-Rules/rules".to_string(),
            kind: FeedKind::Yara,
            last_synced: None,
        }],
        updated_at: 1_700_001_000,
    };

    let json = serde_json::to_string(&manifest).expect("serialize");
    let back: SyncManifest = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(back.feeds.len(), 1);
    assert_eq!(back.feeds[0].name, "yara-rules");
    assert_eq!(back.updated_at, 1_700_001_000);
}

/// 3. cache_path_for_feed returns <cache_dir>/<name>/ deterministically.
#[test]
fn cache_path_derived_from_feed_name() {
    let cache_dir = Path::new("/var/cache/issen");
    let path = cache_path_for_feed("sigma", cache_dir);
    assert_eq!(path, cache_dir.join("sigma"));
}

/// 4. is_stale returns true when last_synced is older than threshold_secs.
#[test]
fn stale_feed_detected_when_last_synced_older_than_threshold() {
    // Use a fixed "now" by passing a very old last_synced timestamp.
    // We'll use std::time::SystemTime to get current time, then subtract.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs();

    let old_spec = FeedSpec {
        name: "sigma".to_string(),
        url: "https://example.com".to_string(),
        kind: FeedKind::Sigma,
        last_synced: Some(now_secs - 7200), // 2 hours ago
    };
    // threshold = 1 hour → stale
    assert!(is_stale(&old_spec, 3600), "feed synced 2h ago should be stale with 1h threshold");

    let fresh_spec = FeedSpec {
        name: "yara".to_string(),
        url: "https://example.com".to_string(),
        kind: FeedKind::Yara,
        last_synced: Some(now_secs - 1800), // 30 min ago
    };
    // threshold = 1 hour → not stale
    assert!(!is_stale(&fresh_spec, 3600), "feed synced 30 min ago should NOT be stale with 1h threshold");

    let never_synced = FeedSpec {
        name: "zeek".to_string(),
        url: "https://example.com".to_string(),
        kind: FeedKind::Zeek,
        last_synced: None,
    };
    // Never synced → always stale
    assert!(is_stale(&never_synced, 3600), "feed never synced should be stale");
}
