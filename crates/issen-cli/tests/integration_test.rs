#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Full end-to-end integration test:
//! Synthetic USN records → pipeline discovery → parser → DuckDB → query → SQLite export.
//!
//! This tests the entire data flow programmatically, without going through the CLI binary.

// Link rt-cli parsers so their inventory::submit! registrations are included.
extern crate issen_cli;

use issen_core::artifacts::ArtifactType;
use issen_core::timeline::event::EventType;
use issen_fswalker::orchestrator::{discover_artifacts, run_pipeline};
use issen_fswalker::progress::ProgressReporter;
use issen_timeline::query::TimelineQuery;
use issen_timeline::store::TimelineStore;
use tempfile::TempDir;

/// Build a synthetic USN V2 record with a given filename, reason, and references.
fn build_usn_v2_record(
    filename: &str,
    reason: u32,
    file_ref: u64,
    parent_ref: u64,
    usn: i64,
) -> Vec<u8> {
    let name_utf16: Vec<u8> = filename
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let file_name_offset: u16 = 60;
    let file_name_length = name_utf16.len() as u16;
    let record_length = file_name_offset as usize + name_utf16.len();
    let padded_length = (record_length + 7) & !7;

    let mut buf = vec![0u8; padded_length];
    buf[0..4].copy_from_slice(&(padded_length as u32).to_le_bytes());
    buf[4..6].copy_from_slice(&2u16.to_le_bytes());
    buf[6..8].copy_from_slice(&0u16.to_le_bytes());
    buf[8..16].copy_from_slice(&file_ref.to_le_bytes());
    buf[16..24].copy_from_slice(&parent_ref.to_le_bytes());
    buf[24..32].copy_from_slice(&usn.to_le_bytes());
    // 2023-11-14T22:13:20Z as FILETIME
    let filetime: i64 = 133_444_736_000_000_000;
    buf[32..40].copy_from_slice(&filetime.to_le_bytes());
    buf[40..44].copy_from_slice(&reason.to_le_bytes());
    buf[44..48].copy_from_slice(&0u32.to_le_bytes());
    buf[48..52].copy_from_slice(&0u32.to_le_bytes());
    buf[52..56].copy_from_slice(&0x20u32.to_le_bytes());
    buf[56..58].copy_from_slice(&file_name_length.to_le_bytes());
    buf[58..60].copy_from_slice(&file_name_offset.to_le_bytes());
    buf[60..60 + name_utf16.len()].copy_from_slice(&name_utf16);
    buf
}

#[test]
fn test_full_pipeline_usnjrnl_to_duckdb() {
    // Setup: create evidence directory with a $J file containing 3 USN records.
    let evidence_dir = TempDir::new().expect("tmpdir");

    let mut journal_data = Vec::new();
    journal_data.extend(build_usn_v2_record(
        "malware.exe",
        0x100, // FILE_CREATE
        1001,
        500,
        100,
    ));
    journal_data.extend(build_usn_v2_record(
        "malware.exe",
        0x200, // DATA_EXTEND
        1001,
        500,
        200,
    ));
    journal_data.extend(build_usn_v2_record(
        "evidence.docx",
        0x8000_0000, // CLOSE
        2002,
        600,
        300,
    ));

    std::fs::write(evidence_dir.path().join("$J"), &journal_data).expect("write $J");

    // Step 1: Discover artifacts.
    let artifacts = discover_artifacts(evidence_dir.path()).expect("discover");
    assert_eq!(artifacts.len(), 1);
    assert_eq!(artifacts[0].artifact_type, ArtifactType::UsnJournal);

    // Step 2: Run pipeline.
    let progress = ProgressReporter::new();
    let (events, result) = run_pipeline(evidence_dir.path(), &progress).expect("pipeline");

    assert_eq!(result.artifacts_found, 1);
    assert_eq!(result.artifacts_parsed, 1);
    assert_eq!(result.total_events, 3);
    assert_eq!(events.len(), 3);
    assert!(result.errors.is_empty());

    // Verify event content.
    let create_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == EventType::FileCreate)
        .collect();
    assert_eq!(create_events.len(), 1);
    assert!(
        create_events[0].description.contains("malware.exe"),
        "Description should contain filename"
    );

    // Step 3: Store in DuckDB.
    let store = TimelineStore::in_memory().expect("duckdb");
    let inserted = store.inseissen_batch(&events).expect("insert");
    assert_eq!(inserted, 3);

    // Step 4: Query back.
    let all_rows = store.query(&TimelineQuery::new()).expect("query all");
    assert_eq!(all_rows.len(), 3);

    // Query by event type.
    let create_rows = store
        .query(&TimelineQuery::new().event_type("FileCreate"))
        .expect("query by type");
    assert_eq!(create_rows.len(), 1);
    assert!(create_rows[0].description.contains("malware.exe"));

    // Query by source.
    let usn_rows = store
        .query(&TimelineQuery::new().source("UsnJournal"))
        .expect("query by source");
    assert_eq!(usn_rows.len(), 3);

    // Verify ordering (ascending by default).
    let ordered = store
        .query(&TimelineQuery::new().limit(3))
        .expect("ordered");
    // All have the same timestamp, so order is stable insertion order.
    assert_eq!(ordered.len(), 3);

    // Step 5: Deduplication — re-insert same events.
    let inserted_again = store.inseissen_batch(&events).expect("re-insert");
    assert_eq!(inserted_again, 0, "Dedup should prevent re-insertion");
    assert_eq!(store.event_count().expect("count"), 3);

    // Step 6: Export to SQLite.
    let export_dir = TempDir::new().expect("export tmpdir");
    let sqlite_path = export_dir.path().join("case.sqlite");
    let exported = store.export_sqlite(&sqlite_path).expect("export");
    assert_eq!(exported, 3);
    assert!(sqlite_path.exists());
}

#[test]
fn test_pipeline_with_mixed_artifacts() {
    // Create evidence directory with a $J file and a non-artifact file.
    let evidence_dir = TempDir::new().expect("tmpdir");
    let record = build_usn_v2_record("test.txt", 0x100, 42, 100, 0);
    std::fs::write(evidence_dir.path().join("$J"), &record).expect("write $J");
    std::fs::write(evidence_dir.path().join("readme.txt"), b"not an artifact").expect("write");
    std::fs::write(evidence_dir.path().join("notes.md"), b"also not").expect("write");

    let artifacts = discover_artifacts(evidence_dir.path()).expect("discover");
    assert_eq!(artifacts.len(), 1, "Only $J should be discovered");

    let progress = ProgressReporter::new();
    let (events, result) = run_pipeline(evidence_dir.path(), &progress).expect("pipeline");
    assert_eq!(result.artifacts_found, 1);
    assert_eq!(result.artifacts_parsed, 1);
    assert_eq!(events.len(), 1);
}

#[test]
fn test_pipeline_stats_after_ingest() {
    let evidence_dir = TempDir::new().expect("tmpdir");
    let mut data = Vec::new();
    data.extend(build_usn_v2_record("a.txt", 0x100, 1, 10, 0));
    data.extend(build_usn_v2_record("b.txt", 0x200, 2, 10, 100));
    std::fs::write(evidence_dir.path().join("$J"), &data).expect("write");

    let progress = ProgressReporter::new();
    let (events, _) = run_pipeline(evidence_dir.path(), &progress).expect("pipeline");

    let store = TimelineStore::in_memory().expect("duckdb");
    store.inseissen_batch(&events).expect("insert");

    let stats = store.stats().expect("stats");
    assert_eq!(stats.total_events, 2);
    assert!(!stats.event_type_counts.is_empty());

    // All events should be from UsnJournal.
    let usn_count: u64 = stats
        .source_counts
        .iter()
        .filter(|(s, _)| s == "UsnJournal")
        .map(|(_, c)| *c)
        .sum();
    assert_eq!(usn_count, 2);
}
