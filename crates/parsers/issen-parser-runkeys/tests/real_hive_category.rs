//! Real-data category test (CADET): drive `runkeys` over the Case-001 DC01
//! `SOFTWARE` hive and assert every emitted Run-key event carries the
//! `Persistence` activity category.
//!
//! Fixture (gitignored): extract `DC01-ProtectedFiles.zip` → `tests/data/case001-hives/`
//! (see `docs/corpus-catalog.md`). The test skips cleanly when the hive is absent
//! (e.g. CI without the corpus), so it only asserts where real data exists.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::redundant_closure_for_method_calls)]

use std::path::PathBuf;

fn hive(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/data/case001-hives")
        .join(name)
}

#[test]
fn runkeys_real_software_hive_tagged_persistence() {
    let path = hive("SOFTWARE");
    if !path.exists() {
        eprintln!(
            "SKIP: {} absent — extract DC01-ProtectedFiles.zip (see docs/corpus-catalog.md)",
            path.display()
        );
        return;
    }
    let events = issen_parser_runkeys::parse_runkeys(&path, "case001-DC01-SOFTWARE")
        .expect("parse_runkeys must decode a real SOFTWARE hive");
    assert!(
        !events.is_empty(),
        "Case-001 SOFTWARE hive has HKLM Run/RunOnce entries"
    );
    assert!(
        events
            .iter()
            .all(|e| e.activity_category.map(|c| c.code()) == Some("persistence")),
        "every Run-key event must be tagged ActivityCategory::Persistence"
    );
    // Run-key events must carry the key's LastWriteTime (the autostart key's
    // create/modify time), not timestamp 0 — the forensic "when was this set".
    assert!(
        events.iter().any(|e| e.timestamp_ns > 0),
        "events must carry a real LastWriteTime, not 0"
    );
}
