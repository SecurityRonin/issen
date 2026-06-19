//! Real-data CADET test: regcatalog is the catalog-driven scanner — it surfaces
//! hundreds of distinct artifact kinds from one hive, so each event must carry
//! its OWN category (per the forensicnomicon `ArtifactDescriptor::activity_category`
//! classifier), not one uniform tag. Drives the Case-001 hives and asserts the
//! representative families land in their correct, DISTINCT categories.
//!
//! Fixtures (gitignored): `tests/data/dfirmadness-szechuan-sauce/extracted/szechuan-sauce-hives/{SOFTWARE,SYSTEM,NTUSER.DAT,SAM,SECURITY}`
//! (extract from `DC01-ProtectedFiles.zip`, see `docs/corpus-catalog.md` §A3b).
//! Skips when absent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

fn case001_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/data/dfirmadness-szechuan-sauce/extracted/szechuan-sauce-hives")
}

/// Map every emitted event's `catalog_id` → its CADET category code.
fn category_by_catalog_id() -> HashMap<String, String> {
    let mut out: HashMap<String, String> = HashMap::new();
    for h in ["SOFTWARE", "SYSTEM", "NTUSER.DAT", "SAM", "SECURITY"] {
        let p = case001_dir().join(h);
        if !p.exists() {
            continue;
        }
        let events = issen_parser_regcatalog::parse_regcatalog(&p, "szechuan-sauce").expect("parse");
        for e in events {
            if let Some(cid) = e.metadata.get("catalog_id").and_then(|v| v.as_str()) {
                let cat = e
                    .activity_category
                    .map(|c| c.code().to_string())
                    .unwrap_or_else(|| "<none>".to_string());
                out.entry(cid.to_string()).or_insert(cat);
            }
        }
    }
    out
}

#[test]
fn regcatalog_tags_each_hit_with_its_own_category() {
    if !case001_dir().join("SOFTWARE").exists() {
        eprintln!("SKIP: szechuan-sauce-hives absent (see docs/corpus-catalog.md §A3b)");
        return;
    }
    let cats = category_by_catalog_id();
    assert!(!cats.is_empty(), "regcatalog must surface catalog hits");

    // Representative artifact families must land in their DISTINCT categories —
    // proving per-hit classification, not one uniform tag.
    let expect = [
        ("run_key_hklm", "persistence"),
        ("winlogon_shell", "persistence"),
        ("userassist_exe", "execution"),
        ("shimcache", "execution"),
        ("browsers_ie_typed_urls", "browser-activity"),
        ("profile_list_users", "account-activity"),
        ("fa_system_mounteddevices", "device-install"),
    ];
    for (cid, want) in expect {
        if let Some(got) = cats.get(cid) {
            assert_eq!(got, want, "catalog_id {cid} → category {got}, want {want}");
        }
    }
    // At least the autostart + execution split must be observable.
    assert_eq!(
        cats.get("run_key_hklm").map(String::as_str),
        Some("persistence")
    );
    assert_eq!(
        cats.get("userassist_exe").map(String::as_str),
        Some("execution")
    );
}

#[test]
fn regcatalog_events_carry_real_last_write_time() {
    if !case001_dir().join("SOFTWARE").exists() {
        eprintln!("SKIP: szechuan-sauce-hives absent (see docs/corpus-catalog.md §A3b)");
        return;
    }
    // Catalog hits resolve against a real key whose LastWriteTime is the event's
    // forensic timestamp — at least one hit across the Case-001 hives must carry
    // it, not timestamp 0.
    let mut any_ts = false;
    for h in ["SOFTWARE", "SYSTEM", "NTUSER.DAT", "SAM", "SECURITY"] {
        let p = case001_dir().join(h);
        if !p.exists() {
            continue;
        }
        let events = issen_parser_regcatalog::parse_regcatalog(&p, "szechuan-sauce").expect("parse");
        if events.iter().any(|e| e.timestamp_ns > 0) {
            any_ts = true;
            break;
        }
    }
    assert!(any_ts, "events must carry a real LastWriteTime, not 0");
}
