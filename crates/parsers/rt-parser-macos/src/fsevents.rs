//! Parser for macOS FSEvents text log exports.

use std::path::Path;

use rt_core::timeline::event::TimelineEvent;

/// Parse an FSEvents text export and return timeline events.
///
/// # Errors
/// Returns `anyhow::Error` only on I/O failures. Missing or empty files
/// return `Ok(vec![])`. Malformed lines are silently skipped.
pub fn parse_fsevents_log(_path: &Path, _source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    todo!("parse_fsevents_log not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;

    // ── Test 7: empty file → Ok(vec![]) ──────────────────────────────────────

    #[test]
    fn empty_file_returns_empty_vec() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let events =
            parse_fsevents_log(tmp.path(), "test-source").expect("must not Err on empty file");
        assert!(events.is_empty(), "expected empty vec for zero-byte file");
    }

    // ── Test 8: "Created" flag → EventType::FileCreate ───────────────────────

    #[test]
    fn created_flag_yields_file_create() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            "2026-04-15 10:25:00  /Users/alice/Documents/report.pdf  Created Modified"
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events = parse_fsevents_log(tmp.path(), "test-source").expect("must not Err");
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type,
            rt_core::timeline::event::EventType::FileCreate,
            "Created flag should map to FileCreate"
        );
    }

    // ── Test 9: "Executable" flag → EventType::ProcessExec ──────────────────

    #[test]
    fn executable_flag_yields_process_start() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            "2026-04-15 10:25:01  /private/tmp/malware.sh  Created Executable"
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events = parse_fsevents_log(tmp.path(), "test-source").expect("must not Err");
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type,
            rt_core::timeline::event::EventType::ProcessExec,
            "Executable flag should map to ProcessStart"
        );
    }

    // ── Test 10: malformed line → no panic ───────────────────────────────────

    #[test]
    fn malformed_line_skipped_without_panic() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(tmp, "not-a-valid-fsevents-line").expect("write");
        writeln!(tmp, "").expect("write");
        tmp.flush().expect("flush");

        let result = parse_fsevents_log(tmp.path(), "test-source");
        assert!(result.is_ok(), "malformed lines must not cause Err");
    }
}
