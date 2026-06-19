//! Real-data category test (CADET): drive `registry` over the Case-001 DC01
//! `SOFTWARE` hive and assert every emitted registry-key event carries the
//! `SystemState` activity category.
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
fn registry_real_software_hive_tagged_system_state() {
    let path = hive("SOFTWARE");
    if !path.exists() {
        eprintln!(
            "SKIP: {} absent — extract DC01-ProtectedFiles.zip (see docs/corpus-catalog.md)",
            path.display()
        );
        return;
    }
    let events = issen_parser_registry::parser::parse_hive(&path, "szechuan-sauce-DC01-SOFTWARE")
        .expect("parse_hive must decode a real SOFTWARE hive");
    assert!(
        !events.is_empty(),
        "Case-001 SOFTWARE hive has registry keys"
    );
    assert!(
        events
            .iter()
            .all(|e| e.activity_category.map(|c| c.code()) == Some("system-state")),
        "every registry-key event must be tagged ActivityCategory::SystemState"
    );
}
