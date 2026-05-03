use forensic_pivot::{
    save_manifest, load_manifest, stale_feeds, prepare_feed_cache,
    FeedSpec, FeedKind, SyncManifest,
};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn make_feed(name: &str, last_synced: Option<u64>) -> FeedSpec {
    FeedSpec {
        name: name.to_string(),
        url: format!("https://example.com/{name}"),
        kind: FeedKind::Sigma,
        last_synced,
    }
}

// ---------------------------------------------------------------------------
// 1. Manifest saved to disk and loaded back matches
// ---------------------------------------------------------------------------
#[test]
fn sync_manifest_saved_and_loaded_from_disk() {
    let dir = TempDir::new().expect("tempdir");
    let manifest = SyncManifest {
        feeds: vec![make_feed("sigma-rules", Some(1_000_000))],
        updated_at: 1_000_000,
    };

    save_manifest(&manifest, dir.path()).expect("save");
    let loaded = load_manifest(dir.path()).expect("load");

    assert_eq!(loaded.feeds.len(), 1);
    assert_eq!(loaded.feeds[0].name, "sigma-rules");
    assert_eq!(loaded.feeds[0].last_synced, Some(1_000_000));
    assert_eq!(loaded.updated_at, 1_000_000);
}

// ---------------------------------------------------------------------------
// 2. Stale feeds from manifest correctly identified
// ---------------------------------------------------------------------------
#[test]
fn stale_feeds_identified_from_manifest() {
    let now = now_secs();
    let manifest = SyncManifest {
        feeds: vec![
            make_feed("old-feed", Some(0)),        // epoch — always stale
            make_feed("fresh-feed", Some(now)),    // just synced — not stale
        ],
        updated_at: now,
    };

    let threshold = 3600; // 1 hour
    let stale = stale_feeds(&manifest, threshold);

    assert_eq!(stale.len(), 1, "only the old feed should be stale");
    assert_eq!(stale[0].name, "old-feed");
}

// ---------------------------------------------------------------------------
// 3. Cache dir created for each feed
// ---------------------------------------------------------------------------
#[test]
fn download_plan_creates_cache_dirs() {
    let dir = TempDir::new().expect("tempdir");
    let spec = make_feed("yara-rules", None);

    let feed_dir = prepare_feed_cache(&spec, dir.path()).expect("prepare_feed_cache");

    assert!(feed_dir.exists(), "feed cache dir should be created");
    assert!(feed_dir.is_dir(), "feed cache path should be a directory");
    assert_eq!(feed_dir, dir.path().join("yara-rules"));
}

// ---------------------------------------------------------------------------
// 4. Manifest updated_at advances after save
// ---------------------------------------------------------------------------
#[test]
fn manifest_updated_at_advances_on_save() {
    let dir = TempDir::new().expect("tempdir");

    // Write a manifest with an old timestamp
    let old_manifest = SyncManifest {
        feeds: vec![],
        updated_at: 1,
    };
    save_manifest(&old_manifest, dir.path()).expect("first save");

    // Load it back — the loader must preserve what was saved
    let loaded = load_manifest(dir.path()).expect("load");
    assert_eq!(loaded.updated_at, 1, "loaded updated_at should match saved value");

    // Now save with a newer timestamp and verify it advances
    let now = now_secs();
    let new_manifest = SyncManifest {
        feeds: vec![],
        updated_at: now,
    };
    save_manifest(&new_manifest, dir.path()).expect("second save");

    let loaded2 = load_manifest(dir.path()).expect("reload");
    assert!(
        loaded2.updated_at >= now,
        "updated_at should not regress after second save"
    );
}

// ---------------------------------------------------------------------------
// 5. load_manifest returns empty manifest when file missing
// ---------------------------------------------------------------------------
#[test]
fn load_manifest_returns_empty_when_missing() {
    let dir = TempDir::new().expect("tempdir");
    let manifest = load_manifest(dir.path()).expect("should not error when manifest missing");
    assert!(manifest.feeds.is_empty());
    assert_eq!(manifest.updated_at, 0);
}
