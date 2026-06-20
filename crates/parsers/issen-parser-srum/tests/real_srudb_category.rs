//! Real-data CADET category test: drive `SrumParser::parse_path` over the real
//! `chainsaw_SRUDB.dat` (sibling `srum-forensic` repo) and assert each emitted
//! event carries the category matching its kind — SRUM is a *mixed* source:
//! network-usage records are `NetworkActivity`, app-usage records are `Execution`.
//! Skips cleanly when the sibling fixture is absent (CI without the corpus).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::redundant_closure_for_method_calls)]

use std::path::{Path, PathBuf};

use issen_parser_srum::SrumParser;

/// Path to the real chainsaw SRUDB.dat in the sibling srum-forensic repo.
fn chainsaw_srudb() -> Option<PathBuf> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../srum-forensic/tests/data/srudb/chainsaw_SRUDB.dat");
    if p.exists() {
        Some(p)
    } else {
        eprintln!("SKIP — real SRUDB fixture not present: {}", p.display());
        None
    }
}

#[test]
fn chainsaw_srudb_events_tagged_by_kind() {
    let Some(path) = chainsaw_srudb() else { return };
    let events = SrumParser
        .parse_path(&path)
        .expect("parse_path must succeed on a valid SRUDB.dat");
    let mut saw_network = false;
    for e in &events {
        let cat = e.activity_category.map(|c| c.code());
        if e.description.starts_with("SRUM NetworkUsage") {
            assert_eq!(
                cat,
                Some("network-activity"),
                "network usage → NetworkActivity"
            );
            saw_network = true;
        } else if e.description.starts_with("SRUM AppUsage") {
            assert_eq!(cat, Some("execution"), "app usage → Execution");
        }
    }
    assert!(
        saw_network,
        "chainsaw SRUDB must surface network-usage events"
    );
}
