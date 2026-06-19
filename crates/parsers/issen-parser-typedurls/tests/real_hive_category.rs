//! Real-data category test (CADET): drive `typedurls` over the Case-001 DC01
//! `NTUSER.DAT` hive and assert every emitted TypedURLs event carries the
//! `BrowserActivity` activity category.
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
fn typedurls_real_ntuser_hive_tagged_browser_activity() {
    let path = hive("NTUSER.DAT");
    if !path.exists() {
        eprintln!(
            "SKIP: {} absent — extract DC01-ProtectedFiles.zip (see docs/corpus-catalog.md)",
            path.display()
        );
        return;
    }
    let events = issen_parser_typedurls::parse_typedurls(&path, "szechuan-sauce-DC01-NTUSER")
        .expect("parse_typedurls must decode a real NTUSER.DAT hive");
    assert!(
        !events.is_empty(),
        "Case-001 NTUSER.DAT hive has IE/Edge TypedURLs entries"
    );
    assert!(
        events
            .iter()
            .all(|e| e.activity_category.map(|c| c.code()) == Some("browser-activity")),
        "every TypedURLs event must be tagged ActivityCategory::BrowserActivity"
    );
}
