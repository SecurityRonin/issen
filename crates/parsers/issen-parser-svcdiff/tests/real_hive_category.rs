//! Real-data CADET test: drive `svcdiff` over the Case-001 DC01 `SYSTEM` hive
//! and assert every service event carries the `Persistence` category. Also serves
//! as the end-to-end proof of the winreg-artifacts 0.1.2 `svc_diff` fix
//! (offline `ControlSet001` resolution) — a non-empty result requires it.
//!
//! Fixture (gitignored): `tests/data/dfirmadness-szechuan-sauce/extracted/szechuan-sauce-hives/SYSTEM` (extract from
//! `DC01-ProtectedFiles.zip`, see `docs/corpus-catalog.md` §A3b). Skips if absent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

fn hive(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/data/dfirmadness-szechuan-sauce/extracted/szechuan-sauce-hives")
        .join(name)
}

#[test]
fn svcdiff_real_system_hive_tagged_persistence() {
    let path = hive("SYSTEM");
    if !path.exists() {
        eprintln!(
            "SKIP: {} absent — extract DC01-ProtectedFiles.zip (see docs/corpus-catalog.md §A3b)",
            path.display()
        );
        return;
    }
    let events = issen_parser_svcdiff::parse_svcdiff(&path, "szechuan-sauce-DC01-SYSTEM")
        .expect("parse_svcdiff must decode a real SYSTEM hive");
    assert!(
        !events.is_empty(),
        "Case-001 SYSTEM has services under ControlSet001\\Services (needs winreg-artifacts 0.1.2)"
    );
    assert!(
        events
            .iter()
            .all(|e| e.activity_category.map(|c| c.code()) == Some("persistence")),
        "every service event must be tagged ActivityCategory::Persistence"
    );
    // Service events must carry the service key's LastWriteTime (install/modify
    // time), not timestamp 0 — the forensic "when was this service created".
    assert!(
        events.iter().any(|e| e.timestamp_ns > 0),
        "service events must carry a real LastWriteTime, not 0"
    );
}
