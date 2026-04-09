use serde::Serialize;

/// A parsed entry from /var/log/auth.log or /var/log/secure.
#[derive(Debug, Clone, Serialize)]
pub struct AuthLogEntry {
    pub timestamp: String,
    pub hostname: String,
    pub service: String,
    pub event_type: String,
    pub user: String,
    pub source_ip: Option<String>,
    pub source_port: Option<u16>,
    pub is_suspicious: bool,
}

/// Parse auth.log / secure log content into structured entries.
#[must_use]
pub fn parse_auth_log(_content: &str) -> Vec<AuthLogEntry> {
    todo!("implement parse_auth_log")
}

/// Classify an auth log entry as suspicious or not.
#[must_use]
pub fn classify_auth_event(_entry: &AuthLogEntry) -> bool {
    todo!("implement classify_auth_event")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ssh_accepted_login() {
        let line = "Apr  3 02:15:44 myhost sshd[1234]: Accepted password for alice from 10.0.0.5 port 54321 ssh2\n";
        let entries = parse_auth_log(line);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event_type, "accepted");
        assert_eq!(entries[0].user, "alice");
        assert_eq!(entries[0].source_ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(entries[0].source_port, Some(54321));
        assert_eq!(entries[0].service, "sshd");
    }

    #[test]
    fn parse_ssh_failed_login() {
        let line = "Apr  3 02:16:00 myhost sshd[1234]: Failed password for bob from 203.0.113.1 port 22222 ssh2\n";
        let entries = parse_auth_log(line);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event_type, "failed");
        assert_eq!(entries[0].user, "bob");
        assert_eq!(entries[0].source_ip.as_deref(), Some("203.0.113.1"));
    }

    #[test]
    fn parse_sudo_command() {
        let line = "Apr  3 03:00:00 myhost sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id\n";
        let entries = parse_auth_log(line);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event_type, "sudo");
        assert_eq!(entries[0].user, "alice");
        assert_eq!(entries[0].service, "sudo");
    }

    #[test]
    fn parse_invalid_user() {
        let line = "Apr  3 02:20:00 myhost sshd[9999]: Invalid user hacker from 1.2.3.4\n";
        let entries = parse_auth_log(line);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event_type, "invalid_user");
        assert_eq!(entries[0].user, "hacker");
        assert_eq!(entries[0].source_ip.as_deref(), Some("1.2.3.4"));
    }

    #[test]
    fn classify_failed_login_suspicious() {
        let entry = AuthLogEntry {
            timestamp: "Apr  3 02:16:00".to_string(),
            hostname: "myhost".to_string(),
            service: "sshd".to_string(),
            event_type: "failed".to_string(),
            user: "bob".to_string(),
            source_ip: Some("203.0.113.1".to_string()),
            source_port: Some(22222),
            is_suspicious: false,
        };
        assert!(classify_auth_event(&entry));
    }

    #[test]
    fn classify_sudo_shell_escape_suspicious() {
        let entry = AuthLogEntry {
            timestamp: "Apr  3 03:00:00".to_string(),
            hostname: "myhost".to_string(),
            service: "sudo".to_string(),
            event_type: "sudo".to_string(),
            user: "alice".to_string(),
            source_ip: None,
            source_port: None,
            is_suspicious: false,
        };
        // We need the command embedded in the user field for sudo classification.
        // The classify function checks the event_type + command context.
        // For sudo shell escapes, the command is stored in the message.
        // We'll use a dedicated sudo entry with shell command in the user field.
        let shell_entry = AuthLogEntry {
            timestamp: "Apr  3 03:00:00".to_string(),
            hostname: "myhost".to_string(),
            service: "sudo".to_string(),
            event_type: "sudo:/bin/bash".to_string(),
            user: "alice".to_string(),
            source_ip: None,
            source_port: None,
            is_suspicious: false,
        };
        assert!(classify_auth_event(&shell_entry));
        // Normal sudo is not suspicious
        let normal_entry = entry;
        assert!(!classify_auth_event(&normal_entry));
    }

    #[test]
    fn parse_empty_content_returns_empty() {
        let entries = parse_auth_log("");
        assert!(entries.is_empty());
    }
}
