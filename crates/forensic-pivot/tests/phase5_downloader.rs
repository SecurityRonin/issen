use forensic_pivot::{
    FeedKind, FeedSpec, SyncManifest,
    downloader::{download_feed, load_manifest, prepare_feed_cache, save_manifest},
    loader::default_feeds,
};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// 1. default_feeds returns at least 3 entries
// ---------------------------------------------------------------------------
#[test]
fn default_feeds_returns_nonempty() {
    let feeds = default_feeds();
    assert!(
        feeds.len() >= 3,
        "expected at least 3 default feeds, got {}",
        feeds.len()
    );
}

// ---------------------------------------------------------------------------
// 2. default_feeds includes a Sigma feed
// ---------------------------------------------------------------------------
#[test]
fn default_feeds_includes_sigma() {
    let feeds = default_feeds();
    let has_sigma = feeds.iter().any(|f| f.kind == FeedKind::Sigma);
    assert!(has_sigma, "default_feeds must include at least one Sigma feed");
}

// ---------------------------------------------------------------------------
// 3. default_feeds includes a Yara feed
// ---------------------------------------------------------------------------
#[test]
fn default_feeds_includes_yara() {
    let feeds = default_feeds();
    let has_yara = feeds.iter().any(|f| f.kind == FeedKind::Yara);
    assert!(has_yara, "default_feeds must include at least one Yara feed");
}

// ---------------------------------------------------------------------------
// 4. default_feeds includes a Suricata feed
// ---------------------------------------------------------------------------
#[test]
fn default_feeds_includes_suricata() {
    let feeds = default_feeds();
    let has_suricata = feeds.iter().any(|f| f.kind == FeedKind::Suricata);
    assert!(
        has_suricata,
        "default_feeds must include at least one Suricata feed"
    );
}

// ---------------------------------------------------------------------------
// 5. default_feeds all have non-empty names and URLs
// ---------------------------------------------------------------------------
#[test]
fn default_feeds_have_non_empty_names_and_urls() {
    let feeds = default_feeds();
    for feed in &feeds {
        assert!(!feed.name.is_empty(), "feed name must not be empty");
        assert!(!feed.url.is_empty(), "feed URL must not be empty");
    }
}

// ---------------------------------------------------------------------------
// 6. default_feeds all start with no last_synced (None)
// ---------------------------------------------------------------------------
#[test]
fn default_feeds_have_no_last_synced() {
    let feeds = default_feeds();
    for feed in &feeds {
        assert!(
            feed.last_synced.is_none(),
            "default feed '{}' should have last_synced = None",
            feed.name
        );
    }
}

// ---------------------------------------------------------------------------
// 7. download_feed with a bogus URL returns Err (confirms it actually tries)
// ---------------------------------------------------------------------------
#[test]
fn download_feed_bogus_url_returns_error() {
    let dir = TempDir::new().expect("tempdir");
    let spec = FeedSpec {
        name: "bogus-feed".to_string(),
        url: "https://0.0.0.0:1/nonexistent/path/that/will/never/resolve".to_string(),
        kind: FeedKind::Sigma,
        last_synced: None,
    };

    let result = download_feed(&spec, dir.path());
    assert!(
        result.is_err(),
        "download_feed must return Err for an unreachable URL (was still a stub)"
    );
}
