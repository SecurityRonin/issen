//! Multi-profile browser discovery through the directory-ingest front door.
//!
//! `issen <dir>` routes a plain directory to the disk leg, which runs
//! `run_auto_parse_jobs` — a recursive filesystem walk that classifies every
//! file with the registry-derived classifier (`issen_core::classify`). The
//! browser-history classifier matches a Chromium `History` file whenever a
//! vendor token (`chrome`, `edge`, …) appears anywhere in its path, so the walk
//! already discovers *every* profile under a real home tree — `Profile 2` and
//! `Default` alike — not only `Default`. (The `Default`-only limitation is
//! specific to the NTFS disk-image `disk_sources`, which hard-code the `Default`
//! subdir; it does not apply to a walkable directory.)
//!
//! These tests pin that behaviour end-to-end: a non-Default profile is
//! discovered and parsed, and a per-file `History` is not double-counted.

// Integration tests are their own crate, so the workspace `cfg_attr(test, ..)`
// opt-out in the library root does not reach here.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::path::Path;

use issen_cli::commands;
use issen_timeline::store::TimelineStore;
use rusqlite::{params, Connection};

/// Write a minimal Chrome `History` SQLite DB with a single visited URL at
/// `path` (its parent dirs must already exist). One `urls` row → one event.
fn write_chrome_history(path: &Path, url: &str) {
    let conn = Connection::open(path).expect("open history db");
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, \
         title TEXT DEFAULT '', visit_count INTEGER DEFAULT 0 NOT NULL, \
         last_visit_time INTEGER NOT NULL);",
    )
    .expect("create urls table");
    conn.execute(
        "INSERT INTO urls (url, title, visit_count, last_visit_time) \
         VALUES (?1, ?2, ?3, ?4)",
        // A WebKit/Chrome timestamp (µs since 1601) well inside the valid range.
        params![url, "Example", 3_i64, 13_350_000_000_000_000_i64],
    )
    .expect("insert url");
}

/// Count timeline rows whose description carries `needle` (the visited URL).
fn events_matching(store: &TimelineStore, needle: &str) -> i64 {
    store
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM timeline WHERE description LIKE '%' || ? || '%'",
            [needle],
            |row| row.get(0),
        )
        .expect("count query")
}

/// A Chrome `History` under a NON-`Default` profile (`Profile 2`) is discovered
/// and parsed by the directory-ingest front door — proving multi-profile
/// discovery, not just the `Default` profile.
#[test]
fn directory_ingest_discovers_non_default_chrome_profile() {
    let home = tempfile::tempdir().expect("home tempdir");
    let profile2 = home
        .path()
        .join("Users/alice/AppData/Local/Google/Chrome/User Data/Profile 2");
    std::fs::create_dir_all(&profile2).expect("mkdir Profile 2");
    let url = "https://non-default-profile.example/";
    write_chrome_history(&profile2.join("History"), url);

    let db = home.path().join("case.duckdb");
    let evidence = [home.path().to_path_buf()];
    commands::ingest::run(
        &evidence, &db, None, None, false, None, None, None, None, false, false, false,
    )
    .expect("directory ingest");

    let store = TimelineStore::open(&db).expect("open case db");
    assert_eq!(
        events_matching(&store, url),
        1,
        "the non-Default `Profile 2` History must be discovered and parsed",
    );
}

/// Discovery does not double-count: a single `Default` History file yields
/// exactly one event, not two — the recursive walk parses each on-disk file
/// once. (Dedup guard: any future profile-discovery enrichment must not
/// re-emit a file the walk already parsed.)
#[test]
fn directory_ingest_does_not_double_count_default_profile() {
    let home = tempfile::tempdir().expect("home tempdir");
    let default = home
        .path()
        .join("Users/bob/AppData/Local/Google/Chrome/User Data/Default");
    std::fs::create_dir_all(&default).expect("mkdir Default");
    let url = "https://default-profile.example/";
    write_chrome_history(&default.join("History"), url);

    let db = home.path().join("case.duckdb");
    let evidence = [home.path().to_path_buf()];
    commands::ingest::run(
        &evidence, &db, None, None, false, None, None, None, None, false, false, false,
    )
    .expect("directory ingest");

    let store = TimelineStore::open(&db).expect("open case db");
    assert_eq!(
        events_matching(&store, url),
        1,
        "one Default History file must produce exactly one event (no duplicate)",
    );
}

/// A Chromium `History` embedded by an Electron app (Slack) — its path carries
/// NO browser vendor token, so the path-based classifier misses it entirely.
/// Content-based detection (SQLite `urls` table) discovers and parses it anyway
/// (ADR 0017 Phase 3), so its visited URL lands in the timeline.
#[test]
fn directory_ingest_discovers_off_path_electron_history_by_content() {
    let home = tempfile::tempdir().expect("home tempdir");
    // Slack embeds Chromium; no "chrome"/"edge"/… token anywhere in this path.
    let slack = home
        .path()
        .join("Users/carol/AppData/Roaming/Slack/Partitions/default");
    std::fs::create_dir_all(&slack).expect("mkdir Slack partition");
    let url = "https://electron-embedded.example/";
    write_chrome_history(&slack.join("History"), url);

    let db = home.path().join("case.duckdb");
    let evidence = [home.path().to_path_buf()];
    commands::ingest::run(
        &evidence, &db, None, None, false, None, None, None, None, false, false, false,
    )
    .expect("directory ingest");

    let store = TimelineStore::open(&db).expect("open case db");
    assert_eq!(
        events_matching(&store, url),
        1,
        "an off-path Electron-embedded Chromium History must be found by content",
    );
}

/// A Chromium `History` deliberately renamed to hide it (`evidence.dat`, no
/// vendor token, non-canonical filename) — anti-forensic relocation. The path
/// classifier cannot see it; content detection recovers its `urls` visits into
/// the timeline.
#[test]
fn directory_ingest_discovers_renamed_history_by_content() {
    let home = tempfile::tempdir().expect("home tempdir");
    let stash = home.path().join("stash");
    std::fs::create_dir_all(&stash).expect("mkdir stash");
    let url = "https://renamed-evidence.example/";
    write_chrome_history(&stash.join("evidence.dat"), url);

    let db = home.path().join("case.duckdb");
    let evidence = [home.path().to_path_buf()];
    commands::ingest::run(
        &evidence, &db, None, None, false, None, None, None, None, false, false, false,
    )
    .expect("directory ingest");

    let store = TimelineStore::open(&db).expect("open case db");
    assert_eq!(
        events_matching(&store, url),
        1,
        "a renamed Chromium History (evidence.dat) must be found by its schema",
    );
}
