//! Parser for macOS Unified Log text exports (`log show --style syslog`).

use std::path::Path;

use rt_core::timeline::event::TimelineEvent;

/// Parse a Unified Log text export and return timeline events.
///
/// # Errors
/// Returns `anyhow::Error` only on I/O failures reading the file.
/// Malformed lines are silently skipped. Missing files return `Ok(vec![])`.
pub fn parse_unified_log(_path: &Path, _source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    todo!("parse_unified_log not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;

    // ── Test 1: empty file → Ok(vec![]) ──────────────────────────────────────

    #[test]
    fn empty_file_returns_empty_vec() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let events = parse_unified_log(tmp.path(), "test-source")
            .expect("must not return Err on empty file");
        assert!(events.is_empty(), "expected empty vec for zero-byte file");
    }

    // ── Test 2: one well-formed line → 1 event with correct process metadata ─

    #[test]
    fn one_wellformed_line_emits_one_event_with_process_metadata() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            "2026-04-15 10:23:01.123456-0700  localhost kernel[0]: (AppleIntelCPU) Kernel connected"
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events =
            parse_unified_log(tmp.path(), "test-source").expect("must not Err on well-formed line");
        assert_eq!(events.len(), 1, "expected exactly 1 event");
        let ev = &events[0];
        assert_eq!(
            ev.metadata.get("process").and_then(|v| v.as_str()),
            Some("kernel"),
            "process metadata should be 'kernel'"
        );
    }

    // ── Test 3: launchd "Service exited" → EventType::ProcessExec ───────────

    #[test]
    fn launchd_service_exited_yields_process_start() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            "2026-04-15 10:23:02.456789-0700  localhost com.apple.xpc.launchd[1] (com.apple.logind): Service exited with abnormal code: 1"
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events = parse_unified_log(tmp.path(), "test-source").expect("must not Err");
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type,
            rt_core::timeline::event::EventType::ProcessExec,
            "launchd Service exited should map to ProcessStart"
        );
    }

    // ── Test 4: sshd "Accepted publickey" → ProcessStart + process="sshd" ────

    #[test]
    fn sshd_accepted_publickey_yields_process_start_with_sshd_process() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            "2026-04-15 10:23:03.111111-0700  localhost sshd[1234]: Accepted publickey for alice from 192.168.1.1"
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events = parse_unified_log(tmp.path(), "test-source").expect("must not Err");
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(
            ev.event_type,
            rt_core::timeline::event::EventType::ProcessExec,
            "sshd Accepted publickey should map to ProcessStart"
        );
        assert_eq!(
            ev.metadata.get("process").and_then(|v| v.as_str()),
            Some("sshd"),
            "process metadata should be 'sshd'"
        );
    }

    // ── Test 5: garbled line → Ok (no panic, no Err) ─────────────────────────

    #[test]
    fn garbled_line_returns_ok_no_panic() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(tmp, "THIS IS NOT A VALID LOG LINE AT ALL !!!@#$%").expect("write");
        writeln!(tmp, "").expect("write");
        writeln!(tmp, "   ").expect("write");
        tmp.flush().expect("flush");

        let result = parse_unified_log(tmp.path(), "test-source");
        assert!(result.is_ok(), "garbled lines must not cause Err");
        // Garbled lines are skipped
        let events = result.expect("ok");
        assert!(
            events.is_empty(),
            "garbled lines should be silently skipped"
        );
    }

    // ── Test 6: known timestamp → timestamp_ns is non-zero ───────────────────

    #[test]
    fn known_timestamp_yields_nonzero_timestamp_ns() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        // 2026-04-15 10:23:01 UTC (offset +0000) → well-known Unix ts
        writeln!(
            tmp,
            "2026-04-15 10:23:01.000000+0000  localhost kernel[0]: Some message here"
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events = parse_unified_log(tmp.path(), "test-source").expect("must not Err");
        assert_eq!(events.len(), 1);
        assert_ne!(
            events[0].timestamp_ns, 0,
            "timestamp_ns must be non-zero for a valid timestamp"
        );
        // 2026-04-15 10:23:01 UTC = 1744712581 seconds since epoch
        let expected_ns: i64 = 1_744_712_581_000_000_000;
        assert_eq!(
            events[0].timestamp_ns, expected_ns,
            "timestamp_ns mismatch for 2026-04-15 10:23:01 UTC"
        );
    }
}
