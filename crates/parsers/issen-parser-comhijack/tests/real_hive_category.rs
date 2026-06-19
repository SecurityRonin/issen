//! Real-data CADET test: drive `comhijack` over a real Win10 `UsrClass.dat`
//! (ricksanchez's, carved from the Case-001 Desktop E01) and assert every COM
//! registration event carries `Persistence`. Also the end-to-end proof of the
//! winreg-artifacts 0.1.2 `com_hijacking` fix (reads UsrClass root `CLSID`) — a
//! non-empty result requires it (NTUSER.DAT-only code returned zero here).
//!
//! Fixture (gitignored): `tests/data/dfirmadness-szechuan-sauce/extracted/szechuan-sauce-hives/UsrClass.dat` (carve from
//! `DESKTOP-E01.zip`, see `docs/corpus-catalog.md` §A3b). Skips if absent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

fn hive(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/data/dfirmadness-szechuan-sauce/extracted/szechuan-sauce-hives")
        .join(name)
}

#[test]
fn comhijack_real_usrclass_tagged_persistence() {
    let path = hive("UsrClass.dat");
    if !path.exists() {
        eprintln!(
            "SKIP: {} absent — carve from DESKTOP-E01.zip (see docs/corpus-catalog.md §A3b)",
            path.display()
        );
        return;
    }
    let events = issen_parser_comhijack::parse_com_hijacking(&path, "szechuan-sauce-ricksanchez-UsrClass")
        .expect("parse_com_hijacking must decode a real UsrClass.dat");
    assert!(
        !events.is_empty(),
        "Win10 UsrClass.dat has CLSID InprocServer32 registrations (needs winreg-artifacts 0.1.2)"
    );
    assert!(
        events
            .iter()
            .all(|e| e.activity_category.map(|c| c.code()) == Some("persistence")),
        "every COM-registration event must be tagged ActivityCategory::Persistence"
    );
    // COM-hijack events must carry the CLSID key's LastWriteTime, not 0.
    assert!(
        events.iter().any(|e| e.timestamp_ns > 0),
        "events must carry a real LastWriteTime, not 0"
    );
}
