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

/// Read a REG_SZ named value as a string (None if key/value absent or wrong type).
fn str_value(hive: &Hive<Cursor<Vec<u8>>>, key_path: &str, name: &str) -> Option<String> {
    let v = hive
        .open_key(key_path)
        .ok()
        .flatten()?
        .value(name)
        .ok()
        .flatten()?;
    v.as_string()
        .ok()
        .map(|s| s.trim_end_matches('\0').to_string())
}

/// Resolve the live `ControlSet00N` from `Select\Current` (there is no
/// `CurrentControlSet` link in an offline SYSTEM hive).
fn current_control_set(hive: &Hive<Cursor<Vec<u8>>>) -> String {
    let n = hive
        .open_key("Select")
        .ok()
        .flatten()
        .and_then(|k| k.value("Current").ok().flatten())
        .and_then(|v| v.as_u32().ok())
        .unwrap_or(1);
    format!("ControlSet{n:03}")
}

/// Extract high-value **named values** (not just key-write timestamps) that
/// answer host-identity questions: OS version (SOFTWARE), timezone + computer
/// name (SYSTEM). Emitted as `system-info` events tagged for discovery.
fn extract_named_values(
    hive: &Hive<Cursor<Vec<u8>>>,
    hive_name: &str,
    source_id: &str,
) -> Vec<TimelineEvent> {
    let mut out = Vec::new();
    let mk = |desc: String, key: &str| {
        TimelineEvent::new(
            0,
            String::new(),
            EventType::Other("system-info".into()),
            ArtifactType::Registry,
            key.to_string(),
            desc,
            source_id.to_string(),
        )
        .with_activity_category(issen_core::ActivityCategory::SystemState)
        .with_tag("system-info")
        .with_metadata("hive", serde_json::json!(hive_name))
    };
    match hive_name.to_lowercase().as_str() {
        "software" => {
            let k = r"Microsoft\Windows NT\CurrentVersion";
            let product = str_value(hive, k, "ProductName");
            let build = str_value(hive, k, "CurrentBuild")
                .or_else(|| str_value(hive, k, "CurrentBuildNumber"));
            if product.is_some() || build.is_some() {
                out.push(
                    mk(
                        format!(
                            "OS version: {} (build {})",
                            product.as_deref().unwrap_or("?"),
                            build.as_deref().unwrap_or("?")
                        ),
                        k,
                    )
                    .with_metadata("product_name", serde_json::json!(product))
                    .with_metadata("current_build", serde_json::json!(build)),
                );
            }
        }
        "system" => {
            let cs = current_control_set(hive);
            let tz_key = format!(r"{cs}\Control\TimeZoneInformation");
            if let Some(tz) = str_value(hive, &tz_key, "TimeZoneKeyName")
                .filter(|s| !s.is_empty())
                .or_else(|| str_value(hive, &tz_key, "StandardName"))
            {
                out.push(
                    mk(format!("Timezone: {tz}"), &tz_key)
                        .with_metadata("timezone", serde_json::json!(tz)),
                );
            }
            let cn_key = format!(r"{cs}\Control\ComputerName\ComputerName");
            if let Some(cn) = str_value(hive, &cn_key, "ComputerName") {
                out.push(
                    mk(format!("Computer name: {cn}"), &cn_key)
                        .with_metadata("computer_name", serde_json::json!(cn)),
                );
            }
        }
        _ => {}
    }
    out
}

/// Convert a `walk_keys` ISO-8601 string (`%Y-%m-%dT%H:%M:%S`, UTC) to
/// nanoseconds since the Unix epoch; `0` if unparseable.
fn iso_to_ns(s: &str) -> i64 {
    chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S")
        .ok()
        .and_then(|ndt| ndt.and_utc().timestamp_nanos_opt())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn hive(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../../tests/data/dfirmadness-szechuan-sauce/extracted/szechuan-sauce-hives/{name}"
        ))
    }

    /// Real DC SOFTWARE hive: the named-value extraction must surface the OS
    /// version (F1: Windows Server 2012 R2, build 9600) — a parsed VALUE, not a
    /// key-write timestamp. Skips cleanly when the corpus is absent.
    #[test]
    fn real_software_hive_yields_os_version() {
        let p = hive("SOFTWARE");
        if !p.exists() {
            eprintln!("SKIP: SOFTWARE hive absent (see docs/corpus-catalog.md)");
            return;
        }
        let events = parse_hive(&p, "dc01-SOFTWARE").unwrap();
        let os = events
            .iter()
            .find(|e| e.description.starts_with("OS version:"))
            .expect("OS version system-info event");
        assert!(os.description.contains("9600"), "build 9600: {}", os.description);
        assert!(
            os.description.contains("2012 R2"),
            "Server 2012 R2: {}",
            os.description
        );
        assert!(matches!(&os.event_type, EventType::Other(s) if s == "system-info"));
    }

    /// Real DC SYSTEM hive: timezone (F3: Pacific — the clock-skew root cause)
    /// resolved through Select\Current -> ControlSet00N.
    #[test]
    fn real_system_hive_yields_pacific_timezone() {
        let p = hive("SYSTEM");
        if !p.exists() {
            eprintln!("SKIP: SYSTEM hive absent");
            return;
        }
        let events = parse_hive(&p, "dc01-SYSTEM").unwrap();
        let tz = events
            .iter()
            .find(|e| e.description.starts_with("Timezone:"))
            .expect("Timezone system-info event");
        assert!(
            tz.description.contains("Pacific"),
            "Pacific timezone: {}",
            tz.description
        );
    }
}
