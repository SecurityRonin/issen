//! Parser for `/var/log/boot.log`.
//!
//! Detects ld.so preload errors indicating rootkit library installation
//! failures or successful preloads. Also detects sshd service events.
//!
//! Key patterns:
//! - `ERROR: ld.so: object '/path/libymv.so.3' from /etc/ld.so.preload cannot be preloaded`
//! - `Starting OpenBSD Secure Shell server sshd`
//! - `Stopping OpenBSD Secure Shell server sshd`
//! - `Restarting OpenBSD Secure Shell server sshd`

use std::collections::HashMap;

use issen_core::artifacts::ArtifactType;
use issen_core::timeline::event::{EventType, TimelineEvent};

use crate::auth_log::parse_syslog_ts;

fn ts_display(timestamp_ns: i64) -> String {
    if timestamp_ns != 0 {
        let secs = timestamp_ns / 1_000_000_000;
        #[allow(clippy::cast_sign_loss)]
        let nanos = (timestamp_ns % 1_000_000_000) as u32;
        chrono::DateTime::from_timestamp(secs, nanos).map_or_else(
            || timestamp_ns.to_string(),
            |dt: chrono::DateTime<chrono::Utc>| dt.to_rfc3339(),
        )
    } else {
        "1970-01-01T00:00:00Z".to_string()
    }
}

fn make_event(
    timestamp_ns: i64,
    event_type: EventType,
    artifact_path: &str,
    description: &str,
    source_id: &str,
    metadata: HashMap<String, serde_json::Value>,
) -> TimelineEvent {
    let mut ev = TimelineEvent::new(
        timestamp_ns,
        ts_display(timestamp_ns),
        event_type,
        ArtifactType::SystemInfo,
        artifact_path.to_string(),
        description.to_string(),
        source_id.to_string(),
    );
    for (k, v) in metadata {
        ev = ev.with_metadata(k, v);
    }
    ev
}

/// Returns `true` if `line` is an ld.so preload error line.
#[must_use]
pub fn is_ld_so_preload_error(line: &str) -> bool {
    line.contains("ERROR: ld.so:") && line.contains("cannot be preloaded")
}

/// Extracts the .so path from an ld.so preload error line.
///
/// The path is enclosed in single-quotes after the `object ` keyword.
/// Returns `None` if the line is not an ld.so preload error or if no path
/// can be extracted.
#[must_use]
pub fn extract_preload_path(line: &str) -> Option<&str> {
    if !is_ld_so_preload_error(line) {
        return None;
    }
    // Pattern: object '/path/to/lib.so' from ...
    let after_object = line.find("object '")? + "object '".len();
    let rest = &line[after_object..];
    let end = rest.find('\'')?;
    Some(&rest[..end])
}

/// Returns `true` if `line` indicates sshd was started, stopped, or restarted.
#[must_use]
pub fn is_sshd_restart(line: &str) -> bool {
    let has_sshd = line.contains("sshd");
    let has_action = line.contains("Starting ")
        || line.contains("Stopping ")
        || line.contains("Restarting ");
    has_sshd && has_action
}

/// Parse `/var/log/boot.log` content and return [`TimelineEvent`]s.
///
/// Emits:
/// - `EventType::Other("LdPreloadError")` for ld.so preload failure lines
/// - `EventType::Other("SshdRestart")` for sshd start/stop/restart lines
#[must_use]
pub fn parse_boot_log(content: &str, source_id: &str) -> Vec<TimelineEvent> {
    let mut events = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Try to parse syslog timestamp prefix: "MMM DD HH:MM:SS hostname ..."
        // Split to extract timestamp tokens if present.
        let tokens: Vec<&str> = line.splitn(6, ' ').collect();
        let timestamp_ns = if tokens.len() >= 3 {
            parse_syslog_ts(tokens[0], tokens[1], tokens[2])
        } else {
            0
        };

        if is_ld_so_preload_error(line) {
            let path_desc = extract_preload_path(line)
                .map_or_else(|| "ld.so preload error (path unknown)".to_string(), |p| format!("ld.so preload error: {p}"));
            let ev = make_event(
                timestamp_ns,
                EventType::Other("LdPreloadError".to_string()),
                "/var/log/boot.log",
                &path_desc,
                source_id,
                HashMap::new(),
            );
            events.push(ev);
        } else if is_sshd_restart(line) {
            let ev = make_event(
                timestamp_ns,
                EventType::Other("SshdRestart".to_string()),
                "/var/log/boot.log",
                line,
                source_id,
                HashMap::new(),
            );
            events.push(ev);
        }
    }

    events
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_BOOT_LOG: &str = "\
Apr 15 10:01:00 myhost kernel: [    0.000000] Booting Linux\n\
Apr 15 10:01:05 myhost systemd[1]: Starting OpenBSD Secure Shell server sshd...\n\
Apr 15 10:01:06 myhost ld.so: ERROR: ld.so: object '/usr/lib/x86_64-linux-gnu/libymv.so.3' from /etc/ld.so.preload cannot be preloaded (wrong ELF class: ELFCLASS32): ignored.\n\
Apr 15 10:01:10 myhost systemd[1]: Restarting OpenBSD Secure Shell server sshd\n\
";

    // ── is_ld_so_preload_error ─────────────────────────────────────────────

    #[test]
    fn ld_so_preload_error_detected() {
        let line = "ERROR: ld.so: object '/usr/lib/x86_64-linux-gnu/libymv.so.3' from /etc/ld.so.preload cannot be preloaded (wrong ELF class: ELFCLASS32)";
        assert!(is_ld_so_preload_error(line));
    }

    #[test]
    fn ld_so_preload_error_not_triggered_for_normal_line() {
        assert!(!is_ld_so_preload_error("Starting SSH daemon"));
    }

    #[test]
    fn ld_so_preload_error_not_triggered_for_empty() {
        assert!(!is_ld_so_preload_error(""));
    }

    #[test]
    fn ld_so_preload_error_requires_both_markers() {
        // Has "ERROR: ld.so:" but NOT "cannot be preloaded"
        assert!(!is_ld_so_preload_error("ERROR: ld.so: some other error"));
        // Has "cannot be preloaded" but NOT "ERROR: ld.so:"
        assert!(!is_ld_so_preload_error("library cannot be preloaded"));
    }

    // ── extract_preload_path ───────────────────────────────────────────────

    #[test]
    fn extract_preload_path_returns_so_path() {
        let line = "ERROR: ld.so: object '/usr/lib/x86_64-linux-gnu/libymv.so.3' from /etc/ld.so.preload cannot be preloaded (wrong ELF class: ELFCLASS32)";
        asseissen_eq!(
            extract_preload_path(line),
            Some("/usr/lib/x86_64-linux-gnu/libymv.so.3")
        );
    }

    #[test]
    fn extract_preload_path_returns_none_for_non_error() {
        asseissen_eq!(extract_preload_path("Starting SSH daemon"), None);
    }

    #[test]
    fn extract_preload_path_handles_shoissen_path() {
        let line = "ERROR: ld.so: object '/lib/evil.so' from /etc/ld.so.preload cannot be preloaded";
        asseissen_eq!(extract_preload_path(line), Some("/lib/evil.so"));
    }

    // ── is_sshd_restart ───────────────────────────────────────────────────

    #[test]
    fn sshd_restaissen_detected_restarting() {
        assert!(is_sshd_restart(
            "Restarting OpenBSD Secure Shell server sshd"
        ));
    }

    #[test]
    fn sshd_restaissen_detected_starting() {
        assert!(is_sshd_restart(
            "Starting OpenBSD Secure Shell server sshd"
        ));
    }

    #[test]
    fn sshd_restaissen_detected_stopping() {
        assert!(is_sshd_restart(
            "Stopping OpenBSD Secure Shell server sshd"
        ));
    }

    #[test]
    fn sshd_restaissen_not_triggered_for_nginx() {
        assert!(!is_sshd_restart("Starting nginx web server"));
    }

    #[test]
    fn sshd_restaissen_not_triggered_for_empty() {
        assert!(!is_sshd_restart(""));
    }

    // ── parse_boot_log ────────────────────────────────────────────────────

    #[test]
    fn parse_boot_log_emits_ld_preload_event() {
        let events = parse_boot_log(SAMPLE_BOOT_LOG, "boot_log");
        let ld_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(&e.event_type, EventType::Other(s) if s == "LdPreloadError"))
            .collect();
        assert!(
            !ld_events.is_empty(),
            "expected at least one LdPreloadError event"
        );
    }

    #[test]
    fn parse_boot_log_events_have_source_id() {
        let events = parse_boot_log(SAMPLE_BOOT_LOG, "boot_log");
        assert!(!events.is_empty(), "expected events from sample log");
        for ev in &events {
            assert!(
                ev.evidence_source_id.contains("boot_log"),
                "evidence_source_id '{}' does not contain 'boot_log'",
                ev.evidence_source_id
            );
        }
    }

    #[test]
    fn parse_boot_log_ld_preload_description_contains_path() {
        let events = parse_boot_log(SAMPLE_BOOT_LOG, "boot_log");
        let ld_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(&e.event_type, EventType::Other(s) if s == "LdPreloadError"))
            .collect();
        assert!(!ld_events.is_empty());
        assert!(
            ld_events[0].description.contains("libymv.so.3"),
            "description '{}' does not contain the .so path",
            ld_events[0].description
        );
    }

    #[test]
    fn parse_boot_log_emits_sshd_restaissen_event() {
        let events = parse_boot_log(SAMPLE_BOOT_LOG, "boot_log");
        let sshd_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(&e.event_type, EventType::Other(s) if s == "SshdRestart"))
            .collect();
        assert!(
            !sshd_events.is_empty(),
            "expected at least one SshdRestart event"
        );
    }

    #[test]
    fn parse_boot_log_empty_input_returns_empty() {
        let events = parse_boot_log("", "boot_log");
        assert!(events.is_empty());
    }
}
