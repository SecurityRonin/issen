//! DRY invariant: `run_auto` (flat) must be exactly the sorted flattening of
//! `run_auto_units` (per-unit) for the same evidence — they are ONE orchestration
//! run two ways, not two copy-paste stacks that can drift (the sort divergence was
//! one symptom). This locks the refactor that makes `run_auto` a thin wrapper over
//! `run_auto_units`. It lives in `issen-cli`'s test suite because it needs the
//! force-linked parser registry (an issen-fswalker unit test would see an empty
//! registry and compare two empty results).
#![allow(clippy::unwrap_used, clippy::expect_used)]

// Force-link the issen_cli library so its parser anchors populate the inventory
// registry in THIS in-process test (run_auto/run_auto_units read all_parsers()).
extern crate issen_cli as _;

use issen_fswalker::orchestrator::{run_auto, run_auto_units};
use issen_fswalker::progress::ProgressReporter;
use tempfile::tempdir;

/// Minimal USNv2 record — a `$J` the real USN-journal parser will decode.
fn build_usn(filename: &str, reason: u32, file_ref: u64, parent_ref: u64, usn: i64) -> Vec<u8> {
    let name: Vec<u8> = filename.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let off: u16 = 60;
    let padded = (off as usize + name.len() + 7) & !7;
    let mut b = vec![0u8; padded];
    b[0..4].copy_from_slice(&(padded as u32).to_le_bytes());
    b[4..6].copy_from_slice(&2u16.to_le_bytes());
    b[8..16].copy_from_slice(&file_ref.to_le_bytes());
    b[16..24].copy_from_slice(&parent_ref.to_le_bytes());
    b[24..32].copy_from_slice(&usn.to_le_bytes());
    b[32..40].copy_from_slice(&133_444_736_000_000_000i64.to_le_bytes());
    b[40..44].copy_from_slice(&reason.to_le_bytes());
    b[52..56].copy_from_slice(&0x20u32.to_le_bytes());
    b[56..58].copy_from_slice(&(name.len() as u16).to_le_bytes());
    b[58..60].copy_from_slice(&off.to_le_bytes());
    b[60..60 + name.len()].copy_from_slice(&name);
    b
}

#[test]
fn run_auto_is_sorted_flatten_of_run_auto_units() {
    let dir = tempdir().unwrap();
    let mut j = Vec::new();
    j.extend(build_usn("malware.exe", 0x100, 1001, 500, 100));
    j.extend(build_usn("malware.exe", 0x200, 1001, 500, 200));
    j.extend(build_usn("evidence.docx", 0x8000_0000, 2002, 600, 300));
    std::fs::write(dir.path().join("$J"), &j).unwrap();

    let progress = ProgressReporter::new();
    let (flat, r_flat) = run_auto(dir.path(), &progress).unwrap();
    let (units, r_units, _) = run_auto_units(
        dir.path(),
        &progress,
        &|_, _, _| false,
        &issen_core::plugin::ParseOptions::default(),
    )
    .unwrap();

    // Flatten + sort by the SAME key run_auto uses (timestamp_ns, record_hash).
    let mut from_units: Vec<_> = units.into_iter().flat_map(|u| u.events).collect();
    from_units.sort_by(|a, b| {
        a.timestamp_ns
            .cmp(&b.timestamp_ns)
            .then_with(|| a.record_hash.cmp(&b.record_hash))
    });

    // Exactly the 3 USN records must parse (guards against a vacuous pass if the
    // parser were unlinked or only partially decoded the journal).
    assert_eq!(flat.len(), 3, "the 3 USN records must all parse");
    assert_eq!(
        flat.len(),
        from_units.len(),
        "flat and per-unit must carry the same number of events"
    );
    let flat_hashes: Vec<&str> = flat.iter().map(|e| e.record_hash.as_str()).collect();
    let unit_hashes: Vec<&str> = from_units.iter().map(|e| e.record_hash.as_str()).collect();
    assert_eq!(
        flat_hashes, unit_hashes,
        "run_auto must equal the sorted flattening of run_auto_units — one orchestration, not two"
    );
    assert_eq!(
        r_flat.artifacts_found, r_units.artifacts_found,
        "artifacts_found"
    );
    assert_eq!(
        r_flat.artifacts_parsed, r_units.artifacts_parsed,
        "artifacts_parsed"
    );
    assert_eq!(r_flat.total_events, r_units.total_events, "total_events");
    assert_eq!(r_flat.total_bytes, r_units.total_bytes, "total_bytes");
}
