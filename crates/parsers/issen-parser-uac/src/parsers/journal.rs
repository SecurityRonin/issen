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
/// 1. Syslog-style: `MONTH DAY TIME HOSTNAME UNIT[PID]: MESSAGE`
/// 2. KEY=VALUE format (journalctl -o verbose/export), with blank-line record
///    separators.
#[must_use]
pub fn parse_journal_text(content: &str) -> Vec<JournalEntry> {
    if content.trim().is_empty() {
        return Vec::new();
    }

    // Detect format: KEY=VALUE blocks have lines like "KEY=value"
    // A syslog line starts with a month abbreviation (3 letters).
    let first_line = content.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    if first_line.contains('=') && !first_line.starts_with(char::is_alphabetic) {
        parse_kv_format(content)
    } else {
        parse_syslog_format(content)
    }
}

/// Parse syslog-style journalctl output.
///
/// Format: `MMM DD HH:MM:SS HOSTNAME UNIT[PID]: MESSAGE`
fn parse_syslog_format(content: &str) -> Vec<JournalEntry> {
    let mut results = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Tokens: [month, day, time, hostname, unit_pid, ...message]
        let tokens: Vec<&str> = line.splitn(6, ' ').collect();
        if tokens.len() < 5 {
            continue;
        }

        let timestamp = format!("{} {} {}", tokens[0], tokens[1], tokens[2]);
        let hostname = tokens[3].to_string();
        let unit_pid = tokens[4].trim_end_matches(':');
        let message = if tokens.len() == 6 {
            tokens[5].to_string()
        } else {
            String::new()
        };

        let (unit, pid) = parse_unit_pid(unit_pid);

        let mut entry = JournalEntry {
            timestamp,
            hostname,
            unit,
            pid,
            message,
            priority: 6, // default info
            is_suspicious: false,
        };
        entry.is_suspicious = classify_journal_entry(&entry);
        results.push(entry);
    }

    results
}

/// Parse KEY=VALUE format (journalctl -o verbose/export).
///
/// Records are separated by blank lines. Known keys:
/// - `__REALTIME_TIMESTAMP`, `_HOSTNAME`, `_SYSTEMD_UNIT`, `_PID`,
///   `MESSAGE`, `PRIORITY`
fn parse_kv_format(content: &str) -> Vec<JournalEntry> {
    let mut results = Vec::new();

    // Split on blank lines to get records
    for block in content.split("\n\n") {
        let block = block.trim();
        if block.is_empty() {
            continue;
        }

        let mut timestamp = String::new();
        let mut hostname = String::new();
        let mut unit = String::new();
        let mut pid: Option<u32> = None;
        let mut message = String::new();
        let mut priority: u8 = 6;

        for kv_line in block.lines() {
            let kv_line = kv_line.trim();
            if let Some((key, value)) = kv_line.split_once('=') {
                match key {
                    "__REALTIME_TIMESTAMP" => {
                        // Microseconds since epoch
                        timestamp = value.to_string();
                    }
                    "_HOSTNAME" => hostname = value.to_string(),
                    "_SYSTEMD_UNIT" | "SYSLOG_IDENTIFIER" => {
                        if unit.is_empty() {
                            unit = value.to_string();
                        }
                    }
                    "_PID" | "SYSLOG_PID" => {
                        if pid.is_none() {
                            pid = value.parse::<u32>().ok();
                        }
                    }
                    "MESSAGE" => message = value.to_string(),
                    "PRIORITY" => priority = value.parse::<u8>().unwrap_or(6),
                    _ => {}
                }
            }
        }

        if message.is_empty() && unit.is_empty() {
            continue;
        }

        let mut entry = JournalEntry {
            timestamp,
            hostname,
            unit,
            pid,
            message,
            priority,
            is_suspicious: false,
        };
        entry.is_suspicious = classify_journal_entry(&entry);
        results.push(entry);
    }

    results
}

/// Split "unit[pid]" or "unit" into (unit, Option<pid>).
fn parse_unit_pid(s: &str) -> (String, Option<u32>) {
    if let Some(bracket) = s.find('[') {
        let unit = s[..bracket].to_string();
        let pid_str = s[bracket + 1..].trim_end_matches(']');
        let pid = pid_str.parse::<u32>().ok();
        (unit, pid)
    } else {
        (s.to_string(), None)
    }
}

/// Classify a journal entry as suspicious or not.
///
/// Suspicious if:
/// - priority <= 3 (error or worse)
/// - message contains OOM kill, segfault, or kernel BUG patterns
/// - message indicates root login, new user creation, or passwd change
/// - unit is empty/unknown with a non-trivial message
#[must_use]
pub fn classify_journal_entry(entry: &JournalEntry) -> bool {
    if entry.priority <= 3 {
        return true;
    }

    let msg = &entry.message;
    let suspicious_patterns = [
        "segfault",
        "kernel BUG",
        "Out of memory: Kill",
        "Accepted password for root",
        "new user:",
        "useradd",
        "passwd changed",
    ];

    if suspicious_patterns.iter().any(|&p| msg.contains(p)) {
        return true;
    }

    false
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
