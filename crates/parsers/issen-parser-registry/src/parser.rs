//! Core registry hive parsing logic using our `winreg-core` / `winreg-artifacts`
//! fleet crates — the registry equivalent of `ntfs-core` (prefer over the
//! third-party `notatin`).

use std::io::Cursor;
use std::path::Path;

use issen_core::artifacts::ArtifactType;
use issen_core::timeline::event::{EventType, TimelineEvent};
use winreg_artifacts::registry_keys::walk_keys;
use winreg_core::hive::Hive;

/// Parse a Windows registry hive file and emit [`TimelineEvent`]s.
///
/// For each key, one event is emitted:
/// - `event_type = RegistryModify`, `source = Registry`
/// - `timestamp` from the key's LastWrite time
/// - `path` = full key path; `description` = "Registry key modified: <key_name>"
/// - metadata `{hive, key, value_count}`
///
/// # Errors
/// Returns `Err` only on unrecoverable I/O failure. A malformed or zero-byte
/// hive yields `Ok(vec![])`.
pub fn parse_hive(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    let meta = std::fs::metadata(path);
    if meta.map_or(0, |m| m.len()) == 0 {
        return Ok(vec![]);
    }
    let hive_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    let data = std::fs::read(path)?;
    Ok(parse_hive_bytes(data, hive_name, source_id))
}

/// Parse a registry hive from an in-memory byte buffer — the bytes a
/// [`DataSource`] yields during ingest. Returns an empty vec on any parse error
/// (not a valid hive: bad signature, checksum, or truncation).
///
/// [`DataSource`]: issen_core::plugin::traits::DataSource
#[must_use]
pub fn parse_hive_bytes(data: Vec<u8>, hive_name: &str, source_id: &str) -> Vec<TimelineEvent> {
    match Hive::from_bytes(data) {
        Ok(hive) => events_from_hive(&hive, hive_name, source_id),
        Err(_) => vec![],
    }
}

/// Emit one `RegistryModify` event per key, keyed on its LastWrite time.
fn events_from_hive(
    hive: &Hive<Cursor<Vec<u8>>>,
    hive_name: &str,
    source_id: &str,
) -> Vec<TimelineEvent> {
    let mut events = Vec::new();
    for key in walk_keys(hive) {
        let (timestamp_ns, timestamp_display) = match &key.last_written {
            Some(s) => (iso_to_ns(s), s.clone()),
            None => (0, String::new()),
        };

        let description = format!("Registry key modified: {}", key.name);

        let event = TimelineEvent::new(
            timestamp_ns,
            timestamp_display,
            EventType::RegistryModify,
            ArtifactType::Registry,
            key.path.clone(),
            description,
            source_id.to_string(),
        )
        .with_activity_category(issen_core::ActivityCategory::SystemState)
        .with_metadata("hive", serde_json::json!(hive_name))
        .with_metadata("key", serde_json::json!(key.path))
        .with_metadata("value_count", serde_json::json!(key.value_count));

        events.push(event);
    }
    events
}

/// Convert a `walk_keys` ISO-8601 string (`%Y-%m-%dT%H:%M:%S`, UTC) to
/// nanoseconds since the Unix epoch; `0` if unparseable.
fn iso_to_ns(s: &str) -> i64 {
    chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S")
        .ok()
        .and_then(|ndt| ndt.and_utc().timestamp_nanos_opt())
        .unwrap_or(0)
}
