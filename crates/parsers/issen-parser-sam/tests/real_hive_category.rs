//! Real-data category test (CADET): drive `sam` over the Case-001 DC01 `SAM`
//! hive and assert every emitted account event carries the `AccountActivity`
//! activity category.
//!
//! Fixture (gitignored): extract `DC01-ProtectedFiles.zip` → `tests/data/dfirmadness-szechuan-sauce/extracted/szechuan-sauce-hives/`
//! (see `docs/corpus-catalog.md`). The test skips cleanly when the hive is absent
//! (e.g. CI without the corpus), so it only asserts where real data exists.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

fn hive(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/data/dfirmadness-szechuan-sauce/extracted/szechuan-sauce-hives")
        .join(name)
}

#[test]
fn sam_real_sam_hive_tagged_account_activity() {
    let path = hive("SAM");
    if !path.exists() {
        eprintln!(
            "SKIP: {} absent — extract DC01-ProtectedFiles.zip (see docs/corpus-catalog.md)",
            path.display()
        );
        return;
    }
    let events = issen_parser_sam::parse_sam(&path, "szechuan-sauce-DC01-SAM")
        .expect("parse_sam must decode a real SAM hive");
    assert!(
        !events.is_empty(),
        "Case-001 SAM hive has local-account entries"
    );
    assert!(
        events
            .iter()
            .all(|e| e.activity_category.map(|c| c.code()) == Some("account-activity")),
        "every SAM event must be tagged ActivityCategory::AccountActivity"
    );
}
