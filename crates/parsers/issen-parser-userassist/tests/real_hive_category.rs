//! Real-data category test (CADET): drive `userassist` over the Case-001 DC01
//! `NTUSER.DAT` hive and assert every emitted UserAssist event carries the
//! `Execution` activity category.
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
fn userassist_real_ntuser_hive_tagged_execution() {
    let path = hive("NTUSER.DAT");
    if !path.exists() {
        eprintln!(
            "SKIP: {} absent — extract DC01-ProtectedFiles.zip (see docs/corpus-catalog.md)",
            path.display()
        );
        return;
    }
    let events = issen_parser_userassist::parse_userassist(&path, "case001-DC01-NTUSER")
        .expect("parse_userassist must decode a real NTUSER.DAT hive");
    assert!(
        !events.is_empty(),
        "Case-001 NTUSER.DAT hive has UserAssist Count entries"
    );
    assert!(
        events
            .iter()
            .all(|e| e.activity_category.map(|c| c.code()) == Some("execution")),
        "every UserAssist event must be tagged ActivityCategory::Execution"
    );
}
