//! File-level SQLite deleted-row carving for Issen (ADR 0018 tier 1).
//!
//! STUB (RED): `events_from_bytes` returns an empty vector so the recovery test
//! fails. The GREEN commit wires `sqlite_forensic::carve_all_deleted_records`.

use issen_core::timeline::event::TimelineEvent;

/// Carve deleted rows from a located SQLite database's own free space and build a
/// [`TimelineEvent`] per recovered row. Anything not a valid SQLite file yields an
/// empty vector.
#[must_use]
pub fn events_from_bytes(_bytes: &[u8], _source_id: &str) -> Vec<TimelineEvent> {
    Vec::new()
}
