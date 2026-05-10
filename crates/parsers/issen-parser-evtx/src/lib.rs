#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::format_push_string,
    clippy::manual_let_else,
    clippy::map_unwrap_or,
    clippy::needless_borrow,
    clippy::redundant_closure_for_method_calls,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::uninlined_format_args,
    clippy::elidable_lifetime_names,
    clippy::match_same_arms,
    clippy::return_self_not_must_use,
    clippy::single_match_else,
    clippy::unnested_or_patterns,
    clippy::field_reassign_with_default,
    clippy::inefficient_to_string,
    clippy::manual_strip,
    clippy::redundant_else,
    clippy::trim_split_whitespace,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::unused_self,
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::missing_fields_in_debug,
    clippy::result_unit_err,
    clippy::unreadable_literal,
    clippy::manual_contains,
    clippy::unnecessary_literal_bound
)]
//! Windows Event Log (EVTX) parser for `Issen`.
//!
//! Wraps the `evtx` crate to parse `.evtx` files and emit [`TimelineEvent`]s
//! via the [`ForensicParser`] trait.

use evtx::EvtxParser as EvtxCrateParser;
use issen_core::artifacts::ArtifactType;
use issen_core::error::RtError;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseStats, ParserCapabilities,
};
use issen_core::timeline::event::{EventType, TimelineEvent};
use serde_json::Value;
use tracing::warn;

/// Windows Event Log parser.
pub struct EvtxFileParser;

/// Map a Windows Security/System Event ID to the corresponding [`EventType`].
#[must_use]
pub fn event_id_to_event_type(event_id: u64) -> EventType {
    match event_id {
        4624 => EventType::LogonSuccess,
        4625 => EventType::LogonFailure,
        4634 | 4647 => EventType::Logoff,
        4688 => EventType::ProcessExec,
        4689 => EventType::ProcessExit,
        7045 => EventType::ServiceInstall,
        7036 => EventType::ServiceStart, // Could be start or stop; default to start
        4698 => EventType::ScheduledTaskCreate,
        4702 | 106 => EventType::ScheduledTaskRun,
        4720 | 4722 | 4725 | 4726 | 4738 => EventType::UserAccountChange,
        4719 => EventType::PolicyChange,
        6005 | 6009 => EventType::SystemBoot,
        6006 | 6008 => EventType::SystemShutdown,
        5156 | 5157 => EventType::NetworkConnect,
        other => EventType::Other(format!("EventID:{other}")),
    }
}

/// Extract the numeric Event ID from the JSON representation of an EVTX record.
///
/// The Event ID lives at `Event.System.EventID` and may be either a plain
/// number or an object like `{"#text": "4624", ...}`.
#[must_use]
pub fn extract_event_id(data: &Value) -> Option<u64> {
    let event_id_val = data
        .get("Event")
        .and_then(|e| e.get("System"))
        .and_then(|s| s.get("EventID"))?;

    // Case 1: plain number
    if let Some(n) = event_id_val.as_u64() {
        return Some(n);
    }

    // Case 2: object with "#text" key (e.g. {"#text": "4624", "@Name": "..."})
    if let Some(text) = event_id_val.get("#text") {
        if let Some(n) = text.as_u64() {
            return Some(n);
        }
        if let Some(s) = text.as_str() {
            return s.parse::<u64>().ok();
        }
    }

    // Case 3: string at the top level
    if let Some(s) = event_id_val.as_str() {
        return s.parse::<u64>().ok();
    }

    None
}

/// Convert a timestamp's seconds + subsecond nanoseconds to total nanoseconds
/// since the Unix epoch.
///
/// Uses `i128` internally to avoid overflow, then truncates to `i64` (which
/// covers dates well beyond the year 2262).
#[must_use]
fn timestamp_to_ns(seconds: i64, subsec_nanos: i32) -> i64 {
    let ns_128 = i128::from(seconds) * 1_000_000_000 + i128::from(subsec_nanos);
    // Clamp to i64 range — safe for any realistic forensic timestamp.
    #[allow(clippy::cast_possible_truncation)]
    let result = ns_128.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;
    result
}

/// Extract a string value from a nested JSON path, returning an empty string
/// if the path doesn't exist or isn't a string.
fn json_str<'a>(data: &'a Value, keys: &[&str]) -> &'a str {
    let mut current = data;
    for key in keys {
        match current.get(*key) {
            Some(v) => current = v,
            None => return "",
        }
    }
    current.as_str().unwrap_or("")
}

/// Convert a single parsed EVTX record into a [`TimelineEvent`].
///
/// `timestamp_ns` and `timestamp_display` are pre-computed from the record's
/// timestamp so that this function stays independent of any specific timestamp
/// library.
#[must_use]
pub fn record_to_event(
    record_id: u64,
    timestamp_ns: i64,
    timestamp_display: &str,
    data: &Value,
    source_id: &str,
) -> TimelineEvent {
    let event_id = extract_event_id(data).unwrap_or(0);
    let event_type = event_id_to_event_type(event_id);

    let channel = json_str(data, &["Event", "System", "Channel"]);
    let provider = json_str(
        data,
        &["Event", "System", "Provider", "#attributes", "Name"],
    );
    let computer = json_str(data, &["Event", "System", "Computer"]);

    let description =
        format!("EventID:{event_id} Provider:{provider} Channel:{channel} (Record {record_id})");

    let artifact_path = if channel.is_empty() {
        "EventLog".to_string()
    } else {
        channel.to_string()
    };

    let mut event = TimelineEvent::new(
        timestamp_ns,
        timestamp_display.to_string(),
        event_type,
        ArtifactType::EventLog,
        artifact_path,
        description,
        source_id.to_string(),
    )
    .with_metadata("event_id", serde_json::json!(event_id))
    .with_metadata("record_id", serde_json::json!(record_id));

    if !provider.is_empty() {
        event = event.with_metadata("provider", serde_json::json!(provider));
    }
    if !channel.is_empty() {
        event = event.with_metadata("channel", serde_json::json!(channel));
    }
    if !computer.is_empty() {
        event = event.with_hostname(computer);
    }

    event
}

impl ForensicParser for EvtxFileParser {
    #[allow(clippy::unnecessary_literal_bound)]
    fn name(&self) -> &str {
        "EVTX Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::EventLog]
    }

    #[allow(clippy::cast_possible_truncation)] // u64 -> usize: EVTX files fit in memory
    fn parse(
        &self,
        input: &dyn DataSource,
        emitter: &dyn EventEmitter,
    ) -> Result<ParseStats, RtError> {
        /// Minimum size for a valid EVTX file (header is 4 KiB).
        const EVTX_MIN_HEADER_SIZE: usize = 4096;

        let start = std::time::Instant::now();
        let mut stats = ParseStats::new();

        let total_len = input.len();
        if total_len == 0 {
            stats.duration = start.elapsed();
            return Ok(stats);
        }

        // Read all bytes from the DataSource into memory.
        let mut buffer = vec![0u8; total_len as usize];
        let mut offset = 0u64;
        while offset < total_len {
            let bytes_read = input.read_at(offset, &mut buffer[offset as usize..])?;
            if bytes_read == 0 {
                break;
            }
            offset += bytes_read as u64;
        }
        stats.bytes_processed = offset;

        // EVTX files have an 8-byte signature "ElfFile\0".
        // If the buffer is too small to even contain the header, return gracefully.
        if buffer.len() < EVTX_MIN_HEADER_SIZE {
            warn!(
                len = buffer.len(),
                "Input too small to be a valid EVTX file, skipping"
            );
            stats.duration = start.elapsed();
            return Ok(stats);
        }

        // Parse via the evtx crate.
        let mut parser = match EvtxCrateParser::from_buffer(buffer) {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "Failed to initialise EVTX parser");
                stats.duration = start.elapsed();
                return Ok(stats);
            }
        };

        let source_id = "evtx-evidence";
        let mut batch: Vec<TimelineEvent> = Vec::with_capacity(1000);

        for result in parser.records_json_value() {
            match result {
                Ok(record) => {
                    let ts = &record.timestamp;
                    let ts_ns = timestamp_to_ns(ts.as_second(), ts.subsec_nanosecond());
                    let ts_display = ts.to_string();

                    let event = record_to_event(
                        record.event_record_id,
                        ts_ns,
                        &ts_display,
                        &record.data,
                        source_id,
                    );
                    batch.push(event);

                    if batch.len() >= 1000 {
                        stats.events_emitted += batch.len() as u64;
                        emitter.emit_batch(std::mem::take(&mut batch))?;
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to parse EVTX record, skipping");
                    stats.errors_recovered += 1;
                }
            }
        }

        // Flush remaining batch.
        if !batch.is_empty() {
            stats.events_emitted += batch.len() as u64;
            emitter.emit_batch(batch)?;
        }

        stats.duration = start.elapsed();
        Ok(stats)
    }

    fn capabilities(&self) -> ParserCapabilities {
        ParserCapabilities {
            max_memory_bytes: Some(256 * 1024 * 1024), // 256 MiB — EVTX files loaded fully
            streaming: false,
            deterministic: true,
        }
    }
}

// Compile-time registration with the parser inventory.
inventory::submit! {
    ParserRegistration { create: || Box::new(EvtxFileParser) }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // -- Test helpers -------------------------------------------------------

    struct CollectingEmitter {
        events: Mutex<Vec<TimelineEvent>>,
    }

    impl CollectingEmitter {
        fn new() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
            }
        }
        fn into_events(self) -> Vec<TimelineEvent> {
            self.events.into_inner().unwrap_or_default()
        }
    }

    impl EventEmitter for CollectingEmitter {
        fn emit(&self, event: TimelineEvent) -> Result<(), RtError> {
            self.events
                .lock()
                .expect("CollectingEmitter lock poisoned")
                .push(event);
            Ok(())
        }
        fn emit_batch(&self, events: Vec<TimelineEvent>) -> Result<(), RtError> {
            self.events
                .lock()
                .expect("CollectingEmitter lock poisoned")
                .extend(events);
            Ok(())
        }
    }

    struct SliceSource(Vec<u8>);

    #[allow(clippy::cast_possible_truncation)]
    impl DataSource for SliceSource {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
            let off = offset as usize;
            if off >= self.0.len() {
                return Ok(0);
            }
            let n = buf.len().min(self.0.len() - off);
            buf[..n].copy_from_slice(&self.0[off..off + n]);
            Ok(n)
        }
    }

    // -- Trait contract tests -----------------------------------------------

    #[test]
    fn test_parser_trait_contract() {
        let parser = EvtxFileParser;
        assert_eq!(parser.name(), "EVTX Parser");
        assert_eq!(parser.supported_artifacts(), &[ArtifactType::EventLog]);
        let caps = parser.capabilities();
        assert!(
            !caps.streaming,
            "EVTX parser loads entire file, not streaming"
        );
        assert!(caps.deterministic);
        assert!(caps.max_memory_bytes.is_some());
    }

    // -- Accuracy: comprehensive event ID coverage -------------------------

    /// Verify every security-relevant event ID maps to the exact expected variant.
    /// This is an accuracy regression guard — if a mapping changes, this fails loudly.
    #[test]
    fn test_event_id_accuracy_table() {
        let cases: &[(u64, EventType)] = &[
            (4624, EventType::LogonSuccess),
            (4625, EventType::LogonFailure),
            (4634, EventType::Logoff),
            (4647, EventType::Logoff),
            (4688, EventType::ProcessExec),
            (4689, EventType::ProcessExit),
            (7045, EventType::ServiceInstall),
            (7036, EventType::ServiceStart),
            (4698, EventType::ScheduledTaskCreate),
            (4702, EventType::ScheduledTaskRun),
            (106, EventType::ScheduledTaskRun),
            (4720, EventType::UserAccountChange),
            (4722, EventType::UserAccountChange),
            (4725, EventType::UserAccountChange),
            (4726, EventType::UserAccountChange),
            (4738, EventType::UserAccountChange),
            (4719, EventType::PolicyChange),
            (6005, EventType::SystemBoot),
            (6009, EventType::SystemBoot),
            (6006, EventType::SystemShutdown),
            (6008, EventType::SystemShutdown),
            (5156, EventType::NetworkConnect),
            (5157, EventType::NetworkConnect),
            (9999, EventType::Other("EventID:9999".to_string())),
            (0, EventType::Other("EventID:0".to_string())),
        ];
        for (id, expected) in cases {
            let got = event_id_to_event_type(*id);
            assert_eq!(
                got, *expected,
                "event_id_to_event_type({id}) expected {expected:?} but got {got:?}"
            );
        }
    }

    // -- Accuracy: extract_event_id edge cases -----------------------------

    #[test]
    fn test_extract_event_id_4624_accuracy() {
        // Canonical Security event structure
        let data = serde_json::json!({
            "Event": { "System": { "EventID": 4624 } }
        });
        assert_eq!(extract_event_id(&data), Some(4624));
    }

    #[test]
    fn test_extract_event_id_4625_string_form() {
        // Some EVTX serialisers emit the EventID as a string
        let data = serde_json::json!({
            "Event": { "System": { "EventID": "4625" } }
        });
        assert_eq!(extract_event_id(&data), Some(4625));
    }

    #[test]
    fn test_extract_event_id_object_with_numeric_u64_text() {
        // Numeric value inside an "#text" wrapper (as emitted by some evtx decoders)
        let data = serde_json::json!({
            "Event": { "System": { "EventID": { "#text": 4688_u64 } } }
        });
        assert_eq!(extract_event_id(&data), Some(4688));
    }

    #[test]
    fn test_extract_event_id_malformed_returns_none() {
        // Boolean value is invalid — must not panic, must return None
        let data = serde_json::json!({
            "Event": { "System": { "EventID": true } }
        });
        assert_eq!(extract_event_id(&data), None);
    }

    #[test]
    fn test_extract_event_id_null_returns_none() {
        let data = serde_json::json!({
            "Event": { "System": { "EventID": null } }
        });
        assert_eq!(extract_event_id(&data), None);
    }

    #[test]
    fn test_extract_event_id_nested_text_string() {
        // Canonical object form with string "#text"
        let data = serde_json::json!({
            "Event": { "System": { "EventID": { "#text": "7045" } } }
        });
        assert_eq!(extract_event_id(&data), Some(7045));
    }

    // -- Accuracy: record_to_event field extraction ------------------------

    #[test]
    fn test_record_to_event_process_create_accuracy() {
        let ts_ns = 1_700_000_000_000_000_000_i64;
        let data = serde_json::json!({
            "Event": {
                "System": {
                    "EventID": 4688,
                    "Channel": "Security",
                    "Computer": "DC01.corp.local",
                    "Provider": { "#attributes": { "Name": "Microsoft-Windows-Security-Auditing" } }
                },
                "EventData": { "NewProcessName": "C:\\Windows\\System32\\cmd.exe" }
            }
        });

        let event = record_to_event(55, ts_ns, "2023-11-14T22:13:20Z", &data, "evtx-src");

        assert_eq!(event.event_type, EventType::ProcessExec);
        assert_eq!(event.source, ArtifactType::EventLog);
        assert_eq!(event.metadata["event_id"], serde_json::json!(4688));
        assert_eq!(event.metadata["record_id"], serde_json::json!(55));
        assert_eq!(event.hostname.as_deref(), Some("DC01.corp.local"));
        assert!(event.description.contains("EventID:4688"));
        assert!(event.description.contains("Record 55"));
    }

    #[test]
    fn test_record_to_event_service_install_accuracy() {
        let data = serde_json::json!({
            "Event": {
                "System": {
                    "EventID": 7045,
                    "Channel": "System",
                    "Computer": "SERVER02",
                    "Provider": { "#attributes": { "Name": "Service Control Manager" } }
                },
                "EventData": { "ServiceName": "malicious_svc" }
            }
        });

        let event = record_to_event(200, 0, "2023-01-01T00:00:00Z", &data, "evtx-src");

        assert_eq!(event.event_type, EventType::ServiceInstall);
        assert_eq!(event.metadata["event_id"], serde_json::json!(7045));
        assert_eq!(event.metadata["channel"], serde_json::json!("System"));
        assert_eq!(
            event.metadata["provider"],
            serde_json::json!("Service Control Manager")
        );
    }

    #[test]
    fn test_record_to_event_no_channel_uses_eventlog_path() {
        // When Channel is absent, artifact_path should default to "EventLog"
        let data = serde_json::json!({
            "Event": { "System": { "EventID": 4624 } }
        });
        let event = record_to_event(1, 0, "2023-01-01T00:00:00Z", &data, "src");
        assert_eq!(event.artifact_path, "EventLog");
    }

    #[test]
    fn test_record_to_event_channel_used_as_path() {
        let data = serde_json::json!({
            "Event": {
                "System": {
                    "EventID": 4625,
                    "Channel": "Microsoft-Windows-Security-Auditing/Operational"
                }
            }
        });
        let event = record_to_event(2, 0, "2023-01-01T00:00:00Z", &data, "src");
        assert_eq!(
            event.artifact_path,
            "Microsoft-Windows-Security-Auditing/Operational"
        );
    }

    // -- Event ID mapping tests ---------------------------------------------

    #[test]
    fn test_event_id_mapping_logon() {
        assert_eq!(event_id_to_event_type(4624), EventType::LogonSuccess);
        assert_eq!(event_id_to_event_type(4625), EventType::LogonFailure);
    }

    #[test]
    fn test_event_id_mapping_logoff() {
        assert_eq!(event_id_to_event_type(4634), EventType::Logoff);
        assert_eq!(event_id_to_event_type(4647), EventType::Logoff);
    }

    #[test]
    fn test_event_id_mapping_process() {
        assert_eq!(event_id_to_event_type(4688), EventType::ProcessExec);
        assert_eq!(event_id_to_event_type(4689), EventType::ProcessExit);
    }

    #[test]
    fn test_event_id_mapping_service() {
        assert_eq!(event_id_to_event_type(7045), EventType::ServiceInstall);
        assert_eq!(event_id_to_event_type(7036), EventType::ServiceStart);
    }

    #[test]
    fn test_event_id_mapping_scheduled_task() {
        assert_eq!(event_id_to_event_type(4698), EventType::ScheduledTaskCreate);
        assert_eq!(event_id_to_event_type(4702), EventType::ScheduledTaskRun);
        assert_eq!(event_id_to_event_type(106), EventType::ScheduledTaskRun);
    }

    #[test]
    fn test_event_id_mapping_account_and_policy() {
        assert_eq!(event_id_to_event_type(4720), EventType::UserAccountChange);
        assert_eq!(event_id_to_event_type(4722), EventType::UserAccountChange);
        assert_eq!(event_id_to_event_type(4725), EventType::UserAccountChange);
        assert_eq!(event_id_to_event_type(4726), EventType::UserAccountChange);
        assert_eq!(event_id_to_event_type(4738), EventType::UserAccountChange);
        assert_eq!(event_id_to_event_type(4719), EventType::PolicyChange);
    }

    #[test]
    fn test_event_id_mapping_system() {
        assert_eq!(event_id_to_event_type(6005), EventType::SystemBoot);
        assert_eq!(event_id_to_event_type(6009), EventType::SystemBoot);
        assert_eq!(event_id_to_event_type(6006), EventType::SystemShutdown);
        assert_eq!(event_id_to_event_type(6008), EventType::SystemShutdown);
    }

    #[test]
    fn test_event_id_mapping_network() {
        assert_eq!(event_id_to_event_type(5156), EventType::NetworkConnect);
        assert_eq!(event_id_to_event_type(5157), EventType::NetworkConnect);
    }

    #[test]
    fn test_event_id_mapping_unknown() {
        assert_eq!(
            event_id_to_event_type(9999),
            EventType::Other("EventID:9999".to_string())
        );
    }

    // -- extract_event_id tests ---------------------------------------------

    #[test]
    fn test_extract_event_id_number() {
        let data = serde_json::json!({
            "Event": {
                "System": {
                    "EventID": 4624
                }
            }
        });
        assert_eq!(extract_event_id(&data), Some(4624));
    }

    #[test]
    fn test_extract_event_id_object_with_text() {
        let data = serde_json::json!({
            "Event": {
                "System": {
                    "EventID": {
                        "#text": "4624",
                        "@Name": "Something"
                    }
                }
            }
        });
        assert_eq!(extract_event_id(&data), Some(4624));
    }

    #[test]
    fn test_extract_event_id_object_with_numeric_text() {
        let data = serde_json::json!({
            "Event": {
                "System": {
                    "EventID": {
                        "#text": 4625
                    }
                }
            }
        });
        assert_eq!(extract_event_id(&data), Some(4625));
    }

    #[test]
    fn test_extract_event_id_string() {
        let data = serde_json::json!({
            "Event": {
                "System": {
                    "EventID": "7045"
                }
            }
        });
        assert_eq!(extract_event_id(&data), Some(7045));
    }

    #[test]
    fn test_extract_event_id_missing() {
        let data = serde_json::json!({ "Event": { "System": {} } });
        assert_eq!(extract_event_id(&data), None);
    }

    #[test]
    fn test_extract_event_id_no_event() {
        let data = serde_json::json!({});
        assert_eq!(extract_event_id(&data), None);
    }

    // -- timestamp_to_ns tests ----------------------------------------------

    #[test]
    fn test_timestamp_to_ns_basic() {
        // 2023-11-14T22:13:20Z = 1_700_000_000 seconds
        let ns = timestamp_to_ns(1_700_000_000, 0);
        let expected = 1_700_000_000_i64 * 1_000_000_000;
        assert_eq!(ns, expected);
    }

    #[test]
    fn test_timestamp_to_ns_with_subsec() {
        let ns = timestamp_to_ns(100, 500_000_000);
        assert_eq!(ns, 100_500_000_000);
    }

    #[test]
    fn test_timestamp_to_ns_zero() {
        assert_eq!(timestamp_to_ns(0, 0), 0);
    }

    // -- record_to_event tests ----------------------------------------------

    #[test]
    fn test_record_to_event_logon() {
        let ts_ns = 1_686_821_400_000_000_000_i64; // 2023-06-15T10:30:00Z
        let ts_display = "2023-06-15T10:30:00Z";
        let data = serde_json::json!({
            "Event": {
                "System": {
                    "EventID": 4624,
                    "Channel": "Security",
                    "Computer": "WORKSTATION01",
                    "Provider": {
                        "#attributes": {
                            "Name": "Microsoft-Windows-Security-Auditing"
                        }
                    }
                },
                "EventData": {
                    "TargetUserName": "jdoe"
                }
            }
        });

        let event = record_to_event(42, ts_ns, ts_display, &data, "evidence-001");

        assert_eq!(event.event_type, EventType::LogonSuccess);
        assert_eq!(event.source, ArtifactType::EventLog);
        assert_eq!(event.evidence_source_id, "evidence-001");
        assert!(event.description.contains("EventID:4624"));
        assert!(event.description.contains("Security"));
        assert!(event.description.contains("Record 42"));
        assert_eq!(event.hostname.as_deref(), Some("WORKSTATION01"));
        assert_eq!(event.metadata["event_id"], serde_json::json!(4624));
        assert_eq!(event.metadata["record_id"], serde_json::json!(42));
        assert_eq!(event.metadata["channel"], serde_json::json!("Security"));
        assert_eq!(
            event.metadata["provider"],
            serde_json::json!("Microsoft-Windows-Security-Auditing")
        );
    }

    #[test]
    fn test_record_to_event_unknown_id() {
        let data = serde_json::json!({
            "Event": {
                "System": {
                    "EventID": 1234,
                    "Channel": "Application",
                    "Computer": "SERVER01",
                    "Provider": {
                        "#attributes": {
                            "Name": "SomeApp"
                        }
                    }
                }
            }
        });

        let event = record_to_event(100, 0, "2023-06-15T10:30:00Z", &data, "src-1");

        assert_eq!(
            event.event_type,
            EventType::Other("EventID:1234".to_string())
        );
        assert!(event.description.contains("EventID:1234"));
    }

    #[test]
    fn test_record_to_event_minimal_data() {
        let data = serde_json::json!({
            "Event": {
                "System": {}
            }
        });

        let event = record_to_event(1, 0, "2023-01-01T00:00:00Z", &data, "test");

        // event_id defaults to 0 when missing
        assert_eq!(event.metadata["event_id"], serde_json::json!(0));
        assert_eq!(event.event_type, EventType::Other("EventID:0".to_string()));
        assert!(event.hostname.is_none());
    }

    // -- parse() with invalid inputs ----------------------------------------

    #[test]
    fn test_parse_empty_input() {
        let source = SliceSource(vec![]);
        let emitter = CollectingEmitter::new();
        let parser = EvtxFileParser;

        let stats = parser.parse(&source, &emitter).expect("parse empty input");
        assert_eq!(stats.events_emitted, 0);
        assert_eq!(stats.bytes_processed, 0);

        let events = emitter.into_events();
        assert!(events.is_empty());
    }

    #[test]
    fn test_parse_too_small() {
        // A buffer smaller than the EVTX header should be handled gracefully.
        let source = SliceSource(vec![0x45, 0x6C, 0x66, 0x46]); // "ElfF" partial
        let emitter = CollectingEmitter::new();
        let parser = EvtxFileParser;

        let stats = parser.parse(&source, &emitter).expect("parse tiny input");
        assert_eq!(stats.events_emitted, 0);

        let events = emitter.into_events();
        assert!(events.is_empty());
    }

    #[test]
    fn test_parse_garbage_data() {
        // 8 KiB of random-ish data that is not a valid EVTX file.
        let garbage: Vec<u8> = (0..8192_u16).map(|i| (i % 251) as u8).collect();
        let source = SliceSource(garbage);
        let emitter = CollectingEmitter::new();
        let parser = EvtxFileParser;

        let stats = parser
            .parse(&source, &emitter)
            .expect("parse garbage gracefully");
        assert_eq!(stats.events_emitted, 0);

        let events = emitter.into_events();
        assert!(events.is_empty());
    }
}
