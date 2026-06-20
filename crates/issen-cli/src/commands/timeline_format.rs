use std::io::Write;

use anyhow::Result;
use issen_timeline::query::TimelineRow;

/// Write timeline events in CSV format.
///
/// Header: timestamp,event_type,source,path,description,evidence_source
pub fn write_csv(events: &[TimelineRow], out: &mut impl Write) -> Result<()> {
    let mut wtr = csv::Writer::from_writer(out);
    wtr.write_record([
        "timestamp",
        "event_type",
        "source",
        "path",
        "description",
        "evidence_source",
    ])?;
    for row in events {
        wtr.write_record([
            &row.timestamp_display,
            &row.event_type,
            &row.source,
            &row.artifact_path,
            &row.description,
            &row.evidence_source,
        ])?;
    }
    wtr.flush()?;
    Ok(())
}

/// Write timeline events in mactime-compatible bodyfile format.
///
/// Format: 0|<path>|0|----------|0|0|0|<atime>|<mtime>|<ctime>|<crtime>
/// Timestamp fields use Unix epoch seconds (0 when not applicable).
#[allow(clippy::similar_names)] // atime/mtime/ctime/crtime are canonical MACB field names
pub fn write_bodyfile(events: &[TimelineRow], out: &mut impl Write) -> Result<()> {
    for row in events {
        let epoch = ns_to_epoch(row.timestamp_ns);

        let (atime, mtime, ctime, crtime) = match row.event_type.as_str() {
            "FileCreate" | "FileCreated" => (0, 0, 0, epoch),
            "FileModify" | "FileModified" => (0, epoch, 0, 0),
            "FileAccess" | "FileAccessed" => (epoch, 0, 0, 0),
            _ => (0, epoch, 0, 0),
        };

        writeln!(
            out,
            "0|{}|0|----------|0|0|0|{}|{}|{}|{}",
            row.artifact_path, atime, mtime, ctime, crtime
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a nanosecond timestamp to Unix epoch seconds.
fn ns_to_epoch(ns: i64) -> i64 {
    ns / 1_000_000_000
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_row(event_type: &str, timestamp_ns: i64, path: &str) -> TimelineRow {
        TimelineRow {
            id: 1,
            timestamp_ns,
            timestamp_display: "2024-01-15T10:23:45Z".to_string(),
            event_type: event_type.to_string(),
            source: "MFT".to_string(),
            artifact_path: path.to_string(),
            description: "Test event".to_string(),
            metadata: None,
            user_account: None,
            hostname: None,
            record_hash: "abc123".to_string(),
            evidence_source: "evidence.zip".to_string(),
        }
    }

    // ---- CSV tests ----

    #[test]
    fn csv_has_correct_headers() {
        let events = vec![make_row(
            "FileCreate",
            1_705_314_225_000_000_000,
            r"C:\foo\bar.exe",
        )];
        let mut out = Vec::new();
        write_csv(&events, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        let first_line = text.lines().next().unwrap();
        assert_eq!(
            first_line,
            "timestamp,event_type,source,path,description,evidence_source"
        );
    }

    #[test]
    fn csv_event_serialises_correctly() {
        let events = vec![make_row(
            "FileCreate",
            1_705_314_225_000_000_000,
            r"C:\foo\bar.exe",
        )];
        let mut out = Vec::new();
        write_csv(&events, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        let mut lines = text.lines();
        let _header = lines.next().unwrap(); // skip header
        let data_line = lines.next().expect("expected at least one data row");
        // Should contain the timestamp display value
        assert!(
            data_line.contains("2024-01-15T10:23:45Z"),
            "missing timestamp: {data_line}"
        );
        // Should contain event_type
        assert!(
            data_line.contains("FileCreate"),
            "missing event_type: {data_line}"
        );
        // Should contain source
        assert!(data_line.contains("MFT"), "missing source: {data_line}");
        // Should contain evidence_source
        assert!(
            data_line.contains("evidence.zip"),
            "missing evidence_source: {data_line}"
        );
    }

    // ---- Bodyfile tests ----

    #[test]
    fn bodyfile_filecreate_sets_crtime() {
        // 2024-01-15T10:23:45Z in ns → epoch 1_705_314_225
        let ts_ns = 1_705_314_225_000_000_000i64;
        let expected_epoch = 1_705_314_225i64;
        let events = vec![make_row(
            "FileCreate",
            ts_ns,
            r"C:\Users\victim\malware.exe",
        )];
        let mut out = Vec::new();
        write_bodyfile(&events, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        let line = text.lines().next().expect("expected output line");
        // bodyfile: 0|path|0|----------|0|0|0|atime|mtime|ctime|crtime
        let fields: Vec<&str> = line.split('|').collect();
        assert_eq!(fields.len(), 11, "wrong field count: {line}");
        // atime (index 7) should be 0 for FileCreate
        assert_eq!(fields[7], "0", "atime should be 0 for FileCreate: {line}");
        // mtime (index 8) should be 0 for FileCreate
        assert_eq!(fields[8], "0", "mtime should be 0 for FileCreate: {line}");
        // ctime (index 9) should be 0 for FileCreate
        assert_eq!(fields[9], "0", "ctime should be 0 for FileCreate: {line}");
        // crtime (index 10) should be the epoch timestamp
        assert_eq!(
            fields[10],
            expected_epoch.to_string(),
            "crtime should be epoch ts for FileCreate: {line}"
        );
    }

    #[test]
    fn bodyfile_filemodify_sets_mtime() {
        let ts_ns = 1_705_314_225_000_000_000i64;
        let expected_epoch = 1_705_314_225i64;
        let events = vec![make_row(
            "FileModify",
            ts_ns,
            r"C:\Windows\System32\evil.dll",
        )];
        let mut out = Vec::new();
        write_bodyfile(&events, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        let line = text.lines().next().expect("expected output line");
        let fields: Vec<&str> = line.split('|').collect();
        assert_eq!(fields.len(), 11, "wrong field count: {line}");
        // mtime (index 8) should be the epoch timestamp for FileModify
        assert_eq!(
            fields[8],
            expected_epoch.to_string(),
            "mtime should be epoch ts for FileModify: {line}"
        );
        // atime (index 7) should be 0
        assert_eq!(fields[7], "0", "atime should be 0 for FileModify: {line}");
        // crtime (index 10) should be 0
        assert_eq!(fields[10], "0", "crtime should be 0 for FileModify: {line}");
    }

    #[test]
    fn bodyfile_pipe_separated() {
        let events = vec![make_row(
            "FileAccess",
            1_705_314_225_000_000_000,
            r"C:\temp\data.csv",
        )];
        let mut out = Vec::new();
        write_bodyfile(&events, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        let line = text.lines().next().expect("expected output line");
        // Must contain pipe characters (mactime bodyfile format)
        assert!(
            line.contains('|'),
            "output should be pipe-separated: {line}"
        );
        // Must have exactly 10 pipes (11 fields)
        let pipe_count = line.chars().filter(|&c| c == '|').count();
        assert_eq!(
            pipe_count, 10,
            "should have 10 pipe separators (11 fields): {line}"
        );
    }
}
