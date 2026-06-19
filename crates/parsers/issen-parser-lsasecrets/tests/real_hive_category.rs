//! Real-data CADET test: drive `lsasecrets` over the Case-001 DC `SECURITY` hive
//! and assert every LSA-secret event carries the `AccountActivity` category.
//! The non-empty result also proves real `Policy\Secrets` enumeration end-to-end
//! ($MACHINE.ACC / DPAPI_SYSTEM / NL$KM are present in Case-001).
//!
//! Fixture (gitignored): `tests/data/dfirmadness-szechuan-sauce/extracted/szechuan-sauce-hives/SECURITY` (extract from
//! `DC01-ProtectedFiles.zip`, see `docs/corpus-catalog.md` §A3b). Skips if absent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

fn hive(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/data/dfirmadness-szechuan-sauce/extracted/szechuan-sauce-hives")
        .join(name)
}

#[test]
fn lsasecrets_real_security_hive_tagged_account_activity() {
    let path = hive("SECURITY");
    if !path.exists() {
        eprintln!(
            "SKIP: {} absent — extract DC01-ProtectedFiles.zip (see docs/corpus-catalog.md §A3b)",
            path.display()
        );
        return;
    }
    let events = issen_parser_lsasecrets::parse_lsasecrets(&path, "szechuan-sauce-DC-SECURITY")
        .expect("parse_lsasecrets must decode a real SECURITY hive");
    assert!(
        !events.is_empty(),
        "Case-001 SECURITY has Policy\\Secrets entries ($MACHINE.ACC / DPAPI_SYSTEM / NL$KM)"
    );
    assert!(
        events
            .iter()
            .all(|e| e.activity_category.map(|c| c.code()) == Some("account-activity")),
        "every LSA-secret event must be tagged ActivityCategory::AccountActivity"
    );
    // LSA-secret events must carry the secret key's LastWriteTime, not 0.
    assert!(
        events.iter().any(|e| e.timestamp_ns > 0),
        "events must carry a real LastWriteTime, not 0"
    );
}
