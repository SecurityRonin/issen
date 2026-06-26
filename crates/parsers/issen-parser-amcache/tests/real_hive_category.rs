//! Real-data CADET test: drive `amcache` over a Case-001 `Amcache.hve` and
//! assert every program-execution event carries the `Execution` category. Works
//! for either host's hive — the Desktop (Win10) uses the modern
//! `Root\InventoryApplicationFile` schema, the DC (Server 2012 R2) the legacy
//! `Root\File\{VolumeGUID}` schema — both decode via winreg-artifacts 0.2.2.
//!
//! Fixture (gitignored): `tests/data/dfirmadness-szechuan-sauce/extracted/szechuan-sauce-hives/Amcache.hve` (carve via the
//! `extract_amcache` issen-disk example, see `docs/corpus-catalog.md` §A3b).
//! Skips if absent.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::redundant_closure_for_method_calls
)]

use std::path::PathBuf;

fn hive(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/data/dfirmadness-szechuan-sauce/extracted/szechuan-sauce-hives")
        .join(name)
}

#[test]
fn amcache_real_hive_tagged_execution() {
    let path = hive("Amcache.hve");
    if !path.exists() {
        eprintln!(
            "SKIP: {} absent — carve via extract_amcache (see docs/corpus-catalog.md §A3b)",
            path.display()
        );
        return;
    }
    let events = issen_parser_amcache::parse_amcache(&path, "szechuan-sauce-Desktop-Amcache")
        .expect("parse_amcache must decode a real Amcache.hve");
    assert!(
        !events.is_empty(),
        "Case-001 Amcache.hve has Root\\InventoryApplicationFile entries"
    );
    assert!(
        events
            .iter()
            .all(|e| e.activity_category.map(|c| c.code()) == Some("execution")),
        "every Amcache program-execution event must be tagged ActivityCategory::Execution"
    );
}
