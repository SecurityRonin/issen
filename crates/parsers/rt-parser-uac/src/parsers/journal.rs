use serde::Serialize;

/// A parsed entry from systemd journal text export.
#[derive(Debug, Clone, Serialize)]
pub struct JournalEntry {
    pub timestamp: String,
    pub hostname: String,
    pub unit: String,
    pub pid: Option<u32>,
    pub message: String,
    pub priority: u8,
    pub is_suspicious: bool,
}

/// Parse journalctl text output into structured entries.
///
/// Handles two formats:
/// 1. Syslog-style: `TIMESTAMP HOSTNAME UNIT[PID]: MESSAGE`
/// 2. KEY=VALUE format (journalctl -o verbose/export)
#[must_use]
pub fn parse_journal_text(_content: &str) -> Vec<JournalEntry> {
    todo!("implement parse_journal_text")
}

/// Classify a journal entry as suspicious or not.
#[must_use]
pub fn classify_journal_entry(_entry: &JournalEntry) -> bool {
    todo!("implement classify_journal_entry")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_syslog_format_line() {
        let content = "Apr 03 02:15:44 myhost sshd[1234]: Accepted publickey for root from 10.0.0.1 port 22\n";
        let entries = parse_journal_text(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].timestamp, "Apr 03 02:15:44");
        assert_eq!(entries[0].hostname, "myhost");
        assert!(entries[0].unit.contains("sshd"));
        assert_eq!(entries[0].pid, Some(1234));
        assert!(entries[0].message.contains("Accepted publickey for root"));
    }

    #[test]
    fn parse_key_value_format_entries() {
        let content = "\
__REALTIME_TIMESTAMP=1712100000000000\n\
_HOSTNAME=myhost\n\
_SYSTEMD_UNIT=sshd.service\n\
_PID=1234\n\
MESSAGE=Accepted publickey for root\n\
PRIORITY=6\n\
\n\
__REALTIME_TIMESTAMP=1712100060000000\n\
_HOSTNAME=myhost\n\
_SYSTEMD_UNIT=sudo.service\n\
MESSAGE=new user: name=hacker\n\
PRIORITY=5\n\
\n";
        let entries = parse_journal_text(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].unit, "sshd.service");
        assert_eq!(entries[0].pid, Some(1234));
        assert_eq!(entries[0].priority, 6);
        assert_eq!(entries[1].message, "new user: name=hacker");
    }

    #[test]
    fn parse_empty_returns_empty() {
        let entries = parse_journal_text("");
        assert!(entries.is_empty());
    }

    #[test]
    fn classify_error_priority_suspicious() {
        let entry = JournalEntry {
            timestamp: "Apr 03 02:15:44".to_string(),
            hostname: "myhost".to_string(),
            unit: "kernel".to_string(),
            pid: None,
            message: "Some error occurred".to_string(),
            priority: 3,
            is_suspicious: false,
        };
        assert!(classify_journal_entry(&entry));

        let info_entry = JournalEntry {
            timestamp: "Apr 03 02:15:44".to_string(),
            hostname: "myhost".to_string(),
            unit: "sshd.service".to_string(),
            pid: Some(1234),
            message: "Server listening on 0.0.0.0 port 22".to_string(),
            priority: 6,
            is_suspicious: false,
        };
        assert!(!classify_journal_entry(&info_entry));
    }

    #[test]
    fn classify_oom_kill_suspicious() {
        let entry = JournalEntry {
            timestamp: "Apr 03 05:00:00".to_string(),
            hostname: "myhost".to_string(),
            unit: "kernel".to_string(),
            pid: None,
            message: "Out of memory: Kill process 1234 (evil)".to_string(),
            priority: 4,
            is_suspicious: false,
        };
        assert!(classify_journal_entry(&entry));
    }

    #[test]
    fn classify_root_login_suspicious() {
        let entry = JournalEntry {
            timestamp: "Apr 03 02:15:44".to_string(),
            hostname: "myhost".to_string(),
            unit: "sshd.service".to_string(),
            pid: Some(1234),
            message: "Accepted password for root from 1.2.3.4 port 22".to_string(),
            priority: 6,
            is_suspicious: false,
        };
        assert!(classify_journal_entry(&entry));
    }
}
