//! Core registry hive parsing logic using `notatin`.

use std::path::Path;

use issen_core::artifacts::ArtifactType;
use issen_core::timeline::event::{EventType, TimelineEvent};

/// Parse a Windows registry hive file and emit [`TimelineEvent`]s.
///
/// For each key with a `LastWrite` timestamp, one event is emitted with:
/// - `event_type = RegistryModify`
/// - `source = Registry`
/// - `timestamp` from the key's LastWrite time (nanoseconds since Unix epoch)
/// - `path` = full key path
/// - `description` = "Registry key modified: <key_name>"
/// - `attributes` = JSON `{"hive": "<filename>", "key": "<path>", "value_count": N}`
///
/// # Errors
/// Returns `Err` only on unrecoverable I/O failures.  Parse errors from
/// `notatin` on a zero-byte or malformed hive are caught and returned as
/// `Ok(vec![])`.
pub fn parse_hive(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    use notatin::parser_builder::ParserBuilder;

    // Zero-byte or very small files are not valid hives — return empty.
    let meta = std::fs::metadata(path);
    if meta.map(|m| m.len()).unwrap_or(0) == 0 {
        return Ok(vec![]);
    }

    let hive_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    // Build from the path so co-located transaction logs (LOG1/LOG2) are replayed;
    // on any error (corrupt header, wrong magic) return empty rather than propagate.
    let owned_path = path.to_path_buf();
    let parser = match ParserBuilder::from_path(owned_path).build() {
        Ok(p) => p,
        Err(_) => return Ok(vec![]),
    };
    Ok(events_from_parser(&parser, hive_name, source_id))
}

/// Parse a registry hive from an in-memory reader — the bytes a [`DataSource`]
/// yields during ingest. Unlike [`parse_hive`], this parses the **primary hive
/// only** (transaction-log replay needs the sidecar files on disk). Returns an
/// empty vec on any parse error (not a valid hive).
///
/// [`DataSource`]: issen_core::plugin::traits::DataSource
pub fn parse_hive_reader<R>(reader: R, hive_name: &str, source_id: &str) -> Vec<TimelineEvent>
where
    R: notatin::file_info::ReadSeek + 'static,
{
    use notatin::parser_builder::ParserBuilder;

    match ParserBuilder::from_file(reader).build() {
        Ok(parser) => events_from_parser(&parser, hive_name, source_id),
        Err(_) => vec![],
    }
}

/// Emit one `RegistryModify` event per key, keyed on its LastWrite time.
fn events_from_parser(
    parser: &notatin::parser::Parser,
    hive_name: &str,
    source_id: &str,
) -> Vec<TimelineEvent> {
    use notatin::parser::ParserIterator;

    let mut events = Vec::new();
    for key in ParserIterator::new(parser) {
        let ts: chrono::DateTime<chrono::Utc> = key.last_key_written_date_and_time();

        // Convert to nanoseconds since Unix epoch.
        let timestamp_ns = ts.timestamp_nanos_opt().unwrap_or(0);
        let timestamp_display = ts.to_rfc3339();

        let key_path = key.path.clone();
        let key_name = key.key_name.clone();
        let value_count = key.value_iter().count();

        let description = format!("Registry key modified: {key_name}");

        let event = TimelineEvent::new(
            timestamp_ns,
            timestamp_display,
            EventType::RegistryModify,
            ArtifactType::Registry,
            key_path.clone(),
            description,
            source_id.to_string(),
        )
        .with_metadata("hive", serde_json::json!(hive_name))
        .with_metadata("key", serde_json::json!(key_path))
        .with_metadata("value_count", serde_json::json!(value_count));

        events.push(event);
    }

    events
}
