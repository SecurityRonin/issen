//! Real-data regression: SRUM's NetworkConnectivity table records when the host
//! was connected to a network and for how long — placement/timeline evidence the
//! wrapper dropped (only NetworkUsage + AppUsage were wired). `chainsaw_SRUDB.dat`
//! has 6 connectivity rows. Skips cleanly when the corpus is absent.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::redundant_closure_for_method_calls
)]

use std::path::{Path, PathBuf};

use issen_parser_srum::SrumParser;

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
fn surfaces_network_connectivity_intervals() {
    let Some(path) = chainsaw_srudb() else { return };
    let events = SrumParser
        .parse_path(&path)
        .expect("parse_path must succeed on a valid SRUDB.dat");
    let conn = events
        .iter()
        .find(|e| e.description.starts_with("SRUM NetworkConnectivity"))
        .expect("a NetworkConnectivity event");
    assert_eq!(
        conn.activity_category.map(|c| c.code()),
        Some("network-activity"),
        "network connectivity → NetworkActivity"
    );
    assert!(
        conn.metadata.iter().any(|(k, _)| k == "connected_time"),
        "must surface the connection duration"
    );
}
