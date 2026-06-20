//! Prefetch (`.pf`) parsing for Issen.
//!
//! Decoding is delegated to our published `prefetch-forensic` fleet crate, which
//! handles the `MAM`/Xpress-Huffman wrapper and the SCCA v30/31 structure
//! (executable, run count, up to eight last-run times, volume serial, loaded
//! files) and grades masquerade / suspicious-location execution. We emit one
//! `ProcessExec` [`TimelineEvent`] per recorded run time (each a distinct
//! execution), or a single existence event when no run time is present.

use std::path::Path;

use forensicnomicon::report::Observation;
use issen_core::artifacts::ArtifactType;
use issen_core::timeline::event::{EventType, TimelineEvent};

/// 100-ns ticks between the Windows `FILETIME` epoch (1601-01-01) and the Unix
/// epoch (1970-01-01).
const FILETIME_EPOCH_DIFF: i64 = 116_444_736_000_000_000;

/// Convert a Windows `FILETIME` to (unix-nanoseconds, RFC 3339 display).
fn filetime_to_unix(ft: i64) -> (i64, String) {
    let ns = ft.saturating_sub(FILETIME_EPOCH_DIFF).saturating_mul(100);
    let display = chrono::DateTime::from_timestamp_nanos(ns).to_rfc3339();
    (ns, display)
}

/// Parse a Windows Prefetch file and return [`TimelineEvent`]s.
///
/// Returns `Ok(vec![])` for nonexistent / empty files and for anything that is
/// not a recognized prefetch container (bad signature, decompression failure).
///
/// # Errors
/// Returns `Err` only on unrecoverable I/O failures other than not-found.
pub fn parse_prefetch(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    let bytes = match std::fs::read(path) {
        Ok(b) if !b.is_empty() => b,
        Ok(_) => return Ok(vec![]),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.into()),
    };
    Ok(events_from_bytes(&bytes, source_id))
}

/// Build prefetch [`TimelineEvent`]s from raw `.pf` bytes — the shared core used
/// by both [`parse_prefetch`] (path-based) and the `ForensicParser::parse`
/// ingest path (`DataSource` bytes). Anything not a recognized prefetch container
/// yields an empty vec.
#[must_use]
pub fn events_from_bytes(bytes: &[u8], source_id: &str) -> Vec<TimelineEvent> {
    let Ok((rec, anomalies)) = prefetch_forensic::audit_bytes(bytes) else {
        return Vec::new();
    };

    // Carry the masquerade / suspicious-path signal on the timeline as the
    // finding codes (the analyzer narrative; hash matching stays elsewhere).
    let anomaly_codes: Vec<String> = anomalies.iter().map(|a| a.code().to_string()).collect();
    let volume_serial = rec.volume_serial.map(|s| format!("{s:08X}"));
    let image_path = rec
        .image_path
        .clone()
        .unwrap_or_else(|| rec.executable.clone());

    let make_event = |timestamp_ns: i64, timestamp_display: String| {
        TimelineEvent::new(
            timestamp_ns,
            timestamp_display,
            EventType::ProcessExec,
            ArtifactType::Prefetch,
            image_path.clone(),
            format!(
                "Prefetch: {} executed (run count {})",
                rec.executable, rec.run_count
            ),
            source_id.to_string(),
        )
        .with_activity_category(issen_core::ActivityCategory::Execution)
        .with_metadata("executable", serde_json::json!(rec.executable))
        .with_metadata("run_count", serde_json::json!(rec.run_count))
        .with_metadata("image_path", serde_json::json!(rec.image_path))
        .with_metadata("volume_serial", serde_json::json!(volume_serial))
        .with_metadata("loaded_files", serde_json::json!(rec.loaded_file_count))
        .with_metadata("anomalies", serde_json::json!(anomaly_codes))
    };

    let events = if rec.last_run_filetimes.is_empty() {
        // No recorded run time — emit a single existence event.
        vec![make_event(0, String::new())]
    } else {
        rec.last_run_filetimes
            .iter()
            .map(|&ft| {
                let (ns, display) = filetime_to_unix(ft);
                make_event(ns, display)
            })
            .collect()
    };

    events
}
