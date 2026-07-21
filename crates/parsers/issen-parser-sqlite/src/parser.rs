//! File-level SQLite deleted-row carving for Issen (ADR 0018 tier 1).
//!
//! Decoding is delegated to our published fleet crates: `sqlite-core` is the
//! panic-free SQLite file-format reader (freelist + free-space navigation) and
//! `sqlite-forensic`'s [`carve_all_deleted_records`](sqlite_forensic::carve_all_deleted_records)
//! recovers deleted rows from a located file's OWN free space — its freelist
//! pages, dropped-table pages, in-page free blocks, and freeblock-reconstructed
//! cells. Cost is bounded by the file already in hand (ADR 0018 tier 1), so this
//! runs in the default triage path. Whole-disk unallocated carving (the
//! `--deleted` tier) is out of scope.
//!
//! Recovery is **schema-agnostic**: `carve_all_deleted_records` infers each
//! record's column count from the cell itself, so a carved row is a coarse
//! `Vec<Value>` in column order with no per-row wall-clock timestamp to trust.
//! Events therefore carry `timestamp_ns = 0` (no reliable temporal anchor) and
//! are clearly marked deleted/carved, with the recovered table (when attributable),
//! rowid, field values, and page/offset/confidence provenance in the metadata.

use sqlite_core::Value;
use sqlite_forensic::{Attribution, CarvedRecord};

use issen_core::artifacts::ArtifactType;
use issen_core::timeline::event::{EventType, TimelineEvent};

/// Upper bound on the in-memory carve. SQLite databases in triage (browser
/// history, chat, mobile artifacts) are well under this; a larger file is skipped
/// rather than risk a large allocation on an untrusted length.
const MAX_CARVE_BYTES: usize = 1024 * 1024 * 1024; // 1 GiB

/// Carve deleted rows from a located SQLite database's own free space and build a
/// [`TimelineEvent`] per recovered row. Anything not a valid SQLite file, or a
/// file above [`MAX_CARVE_BYTES`], yields an empty vector.
///
/// Each event is tagged `source = ArtifactType::SqliteCarved` and marked
/// deleted/carved, so it is additive to and clearly distinct from any live-row
/// events another parser (e.g. `issen-browser`) emits for the same database.
#[must_use]
pub fn events_from_bytes(bytes: &[u8], source_id: &str) -> Vec<TimelineEvent> {
    if bytes.len() > MAX_CARVE_BYTES {
        return Vec::new();
    }
    // `Database::open` validates magic + page size; a non-SQLite or malformed
    // header is a typed Err, never a panic.
    let Ok(db) = sqlite_core::Database::open(bytes.to_vec()) else {
        return Vec::new();
    };

    let records = sqlite_forensic::carve_all_deleted_records(&db);
    if records.is_empty() {
        return Vec::new();
    }
    // Attribute each record back to a live table where the linkage survives
    // (CERTAIN), or by shape (INFERRED), else UNATTRIBUTED. Parallel to `records`.
    let attributions = sqlite_forensic::attribute_records(&db, &records);

    records
        .iter()
        .zip(attributions.iter())
        .map(|(rec, attr)| event_for_record(rec, attr, source_id))
        .collect()
}

/// Human table label + tier + ambiguity flag for a carved record's attribution.
fn attribution_label(attr: &Attribution) -> (String, &'static str, bool) {
    match attr {
        Attribution::Known(table) => (table.clone(), "certain", false),
        Attribution::Inferred { guess, ambiguous } => (guess.clone(), "inferred", *ambiguous),
        Attribution::Unattributed => ("<unattributed>".to_string(), "unattributed", false),
    }
}

/// Build one carved-deleted [`TimelineEvent`] from a recovered record.
fn event_for_record(rec: &CarvedRecord, attr: &Attribution, source_id: &str) -> TimelineEvent {
    let (table, tier, ambiguous) = attribution_label(attr);
    let preview = rec
        .values
        .iter()
        .map(value_display)
        .collect::<Vec<_>>()
        .join(" | ");
    let values_json: Vec<serde_json::Value> = rec.values.iter().map(value_to_json).collect();

    let description = format!(
        "Deleted SQLite row carved from {table} (rowid {}, {:?}, confidence {:.2}): {preview}",
        rec.rowid, rec.source, rec.confidence,
    );

    TimelineEvent::new(
        0, // schema-agnostic carve: no reliable per-row timestamp
        String::new(),
        EventType::Other("SqliteCarvedRow".to_string()),
        ArtifactType::SqliteCarved,
        table.clone(),
        description,
        source_id.to_string(),
    )
    .with_tag("deleted")
    .with_tag("carved")
    .with_metadata("deleted", serde_json::json!(true))
    .with_metadata("allocated", serde_json::json!(rec.allocated))
    .with_metadata("table", serde_json::json!(table))
    .with_metadata("attribution", serde_json::json!(tier))
    .with_metadata("attribution_ambiguous", serde_json::json!(ambiguous))
    .with_metadata("rowid", serde_json::json!(rec.rowid))
    .with_metadata("page", serde_json::json!(rec.page))
    .with_metadata("offset", serde_json::json!(rec.offset))
    .with_metadata("confidence", serde_json::json!(rec.confidence))
    .with_metadata(
        "recovery_source",
        serde_json::json!(format!("{:?}", rec.source)),
    )
    .with_metadata("values", serde_json::json!(values_json))
}

/// Faithful JSON rendering of a recovered cell for the machine-readable metadata.
/// A BLOB is summarized by byte count (content is not inlined into the timeline).
fn value_to_json(v: &Value) -> serde_json::Value {
    match v {
        Value::Null => serde_json::Value::Null,
        Value::Integer(n) => serde_json::json!(n),
        Value::Real(f) => serde_json::json!(f),
        Value::Text(s) => serde_json::json!(s),
        Value::Blob(b) => serde_json::json!(format!("<blob:{} bytes>", b.len())),
    }
}

/// Compact human rendering of a recovered cell for the event description preview.
fn value_display(v: &Value) -> String {
    match v {
        Value::Null => "NULL".to_string(),
        Value::Integer(n) => n.to_string(),
        Value::Real(f) => f.to_string(),
        Value::Text(s) => s.clone(),
        Value::Blob(b) => format!("<blob:{} bytes>", b.len()),
    }
}
