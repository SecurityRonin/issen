//! Real-data category test (CADET): drive `shimcache` over the Case-001 DC01
//! `SYSTEM` hive and assert every emitted ShimCache event carries the
//! `Execution` activity category.
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
fn shimcache_real_system_hive_tagged_execution() {
    let path = hive("SYSTEM");
    if !path.exists() {
        eprintln!(
            "SKIP: {} absent — extract DC01-ProtectedFiles.zip (see docs/corpus-catalog.md)",
            path.display()
        );
        return;
    }
    let events = issen_parser_shimcache::parse_shimcache(&path, "szechuan-sauce-DC01-SYSTEM")
        .expect("parse_shimcache must decode a real SYSTEM hive");
    assert!(
        !events.is_empty(),
        "Case-001 SYSTEM hive has AppCompatCache (ShimCache) entries"
    );
    assert!(
        events
            .iter()
            .all(|e| e.activity_category.map(|c| c.code()) == Some("execution")),
        "every ShimCache event must be tagged ActivityCategory::Execution"
    );
}
