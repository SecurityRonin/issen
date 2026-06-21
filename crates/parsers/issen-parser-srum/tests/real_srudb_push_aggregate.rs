//! Real-data regression: SRUM's PushNotifications table is high-volume, low-signal
//! (`chainsaw_SRUDB.dat` has 562 rows). Per the design, it must be AGGREGATED
//! per-app — one summary event with an occurrence count + first/last-seen — not
//! emitted per-row (which would flood the timeline). Skips when the corpus is absent.
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
fn push_notifications_are_aggregated_per_app_not_per_row() {
    let Some(path) = chainsaw_srudb() else { return };
    let events = SrumParser
        .parse_path(&path)
        .expect("parse_path must succeed on a valid SRUDB.dat");
    let push: Vec<_> = events
        .iter()
        .filter(|e| e.description.starts_with("SRUM PushNotifications"))
        .collect();
    assert!(!push.is_empty(), "push notifications must surface");
    // Aggregation: the table's 562 rows must collapse to one event per app, so the
    // total occurrence count (rows) strictly exceeds the number of events.
    let total_rows: u64 = push
        .iter()
        .filter_map(|e| {
            e.metadata
                .iter()
                .find(|(k, _)| k.as_str() == "occurrences")
                .and_then(|(_, v)| v.as_u64())
        })
        .sum();
    assert!(
        total_rows > push.len() as u64,
        "PushNotifications must be aggregated per-app: {total_rows} rows collapsed \
         into {} events (not per-row)",
        push.len()
    );
    assert_eq!(
        push[0].activity_category.map(|c| c.code()),
        Some("network-activity"),
        "push notifications → NetworkActivity"
    );
    // At least one app aggregated multiple rows — proves real aggregation.
    assert!(
        push.iter().any(|e| e
            .metadata
            .iter()
            .any(|(k, v)| k == "occurrences" && v.as_u64().is_some_and(|n| n > 1))),
        "an aggregated push event must carry occurrences>1"
    );
}
