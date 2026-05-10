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
///
/// Recognises sshd accepted/failed/invalid-user/disconnect lines and
/// sudo command lines.
#[must_use]
pub fn parse_auth_log(content: &str) -> Vec<AuthLogEntry> {
    let mut results = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Syslog format: "MMM DD HH:MM:SS hostname service[pid]: message"
        // Split on whitespace to handle double-space padding for single-digit days
        // (e.g. "Apr  3" → ["Apr", "3", ...]).
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 5 {
            continue;
        }

        // tokens[0]=month tokens[1]=day tokens[2]=time tokens[3]=hostname tokens[4]=service_pid
        let timestamp = format!("{} {} {}", tokens[0], tokens[1], tokens[2]);
        let hostname = tokens[3].to_string();
        let service_pid = tokens[4]; // e.g. "sshd[1234]:" or "sudo:"
                                     // Remainder of line after the first 5 whitespace tokens
        let message = tokens[5..].join(" ");

        // Strip trailing colon from service_pid and split off the PID.
        let service_pid = service_pid.trim_end_matches(':');
        let service = if let Some(idx) = service_pid.find('[') {
            service_pid[..idx].to_string()
        } else {
            service_pid.to_string()
        };

        if let Some(entry) = parse_line(&timestamp, &hostname, &service, &message) {
            results.push(entry);
        }
    }

    results
}

fn parse_line(
    timestamp: &str,
    hostname: &str,
    service: &str,
    message: &str,
) -> Option<AuthLogEntry> {
    // sshd: Accepted password for USER from IP port PORT
    if service == "sshd" {
        if let Some(rest) = message.strip_prefix("Accepted password for ") {
            let (user, ip, port) = parse_from_ip_port(rest);
            let entry = make_entry(timestamp, hostname, service, "accepted", &user, ip, port);
            return Some(entry);
        }
        if let Some(rest) = message.strip_prefix("Accepted publickey for ") {
            let (user, ip, port) = parse_from_ip_port(rest);
            let entry = make_entry(timestamp, hostname, service, "accepted", &user, ip, port);
            return Some(entry);
        }
        if let Some(rest) = message.strip_prefix("Failed password for ") {
            // may be "Failed password for invalid user X from ..."
            let rest = rest.strip_prefix("invalid user ").unwrap_or(rest);
            let (user, ip, port) = parse_from_ip_port(rest);
            let entry = make_entry(timestamp, hostname, service, "failed", &user, ip, port);
            return Some(entry);
        }
        if let Some(rest) = message.strip_prefix("Invalid user ") {
            // "Invalid user USER from IP"
            let parts: Vec<&str> = rest.splitn(3, ' ').collect();
            let user = parts.first().copied().unwrap_or("").to_string();
            let ip = if parts.len() >= 3 && parts[1] == "from" {
                Some(parts[2].to_string())
            } else {
                None
            };
            let entry = make_entry(
                timestamp,
                hostname,
                service,
                "invalid_user",
                &user,
                ip,
                None,
            );
            return Some(entry);
        }
        if let Some(rest) = message.strip_prefix("Disconnected from ") {
            // "Disconnected from USER IP port PORT"
            let parts: Vec<&str> = rest.split_whitespace().collect();
            // May be "Disconnected from authenticating user USER IP port PORT"
            let (user, ip, port) = if parts.first().copied() == Some("authenticating") {
                // skip "authenticating user"
                let rest2 = parts[2..].join(" ");
                parse_from_ip_port_str(&rest2)
            } else {
                parse_from_ip_port_str(&parts.join(" "))
            };
            let entry = make_entry(timestamp, hostname, service, "disconnect", &user, ip, port);
            return Some(entry);
        }
    }

    // sudo: USER : TTY=... ; USER=root ; COMMAND=CMD
    if service == "sudo" {
        // Format: "USER : TTY=... ; PWD=... ; USER=root ; COMMAND=CMD"
        let user = message.split_whitespace().next().unwrap_or("").to_string();
        // Extract COMMAND value if present
        let command = message
            .split(';')
            .find_map(|seg| {
                let seg = seg.trim();
                seg.strip_prefix("COMMAND=")
            })
            .unwrap_or("")
            .to_string();
        // Encode command into event_type so classify_auth_event can inspect it
        let event_type = if command.is_empty() {
            "sudo".to_string()
        } else {
            format!("sudo:{command}")
        };
        let entry = make_entry(timestamp, hostname, service, &event_type, &user, None, None);
        return Some(entry);
    }

    None
}

/// Parse "USER from IP port PORT ..." returning (user, Option<ip>, Option<port>).
fn parse_from_ip_port(s: &str) -> (String, Option<String>, Option<u16>) {
    parse_from_ip_port_str(s)
}

fn parse_from_ip_port_str(s: &str) -> (String, Option<String>, Option<u16>) {
    // Pattern: USER from IP port PORT [rest]
    let parts: Vec<&str> = s.split_whitespace().collect();
    // Find "from" keyword
    if let Some(from_idx) = parts.iter().position(|&p| p == "from") {
        let user = parts[..from_idx].join(" ");
        let ip = parts.get(from_idx + 1).map(|s| s.to_string());
        let port = if parts.get(from_idx + 2).copied() == Some("port") {
            parts.get(from_idx + 3).and_then(|p| p.parse::<u16>().ok())
        } else {
            None
        };
        (user, ip, port)
    } else {
        // No "from" — whole string is the user
        (s.trim().to_string(), None, None)
    }
}

fn make_entry(
    timestamp: &str,
    hostname: &str,
    service: &str,
    event_type: &str,
    user: &str,
    source_ip: Option<String>,
    source_port: Option<u16>,
) -> AuthLogEntry {
    let mut entry = AuthLogEntry {
        timestamp: timestamp.to_string(),
        hostname: hostname.to_string(),
        service: service.to_string(),
        event_type: event_type.to_string(),
        user: user.to_string(),
        source_ip,
        source_port,
        is_suspicious: false,
    };
    entry.is_suspicious = classify_auth_event(&entry);
    entry
}

/// Classify an auth log entry as suspicious or not.
///
/// Suspicious conditions:
/// - Failed authentication (brute force)
/// - Invalid user (scanning)
/// - Sudo shell escape commands
/// - Root login from RFC 1918 (lateral movement indicator)
#[must_use]
pub fn classify_auth_event(entry: &AuthLogEntry) -> bool {
    match entry.event_type.as_str() {
        "failed" | "invalid_user" => return true,
        _ => {}
    }

    // sudo shell escape: event_type is "sudo:COMMAND"
    if let Some(cmd) = entry.event_type.strip_prefix("sudo:") {
        let shell_bins = ["/bin/bash", "/bin/sh", "/usr/bin/python", "/usr/bin/perl"];
        if shell_bins.iter().any(|&b| cmd.starts_with(b)) {
            return true;
        }
    }

    // Root login from RFC 1918 source
    if entry.user == "root" {
        if let Some(ref ip) = entry.source_ip {
            if is_rfc1918(ip) {
                return true;
            }
        }
    }

    false
}

fn is_rfc1918(ip: &str) -> bool {
    if ip.starts_with("10.") {
        return true;
    }
    if ip.starts_with("192.168.") {
        return true;
    }
    // 172.16.0.0/12 — 172.16.x through 172.31.x
    if let Some(rest) = ip.strip_prefix("172.") {
        if let Some(second_octet_str) = rest.split('.').next() {
            if let Ok(second) = second_octet_str.parse::<u8>() {
                if (16..=31).contains(&second) {
                    return true;
                }
            }
        }
    }
    false
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
        assert_eq!(entries[0].user, "alice");
        assert_eq!(entries[0].service, "sudo");
        assert!(entries[0].event_type.starts_with("sudo"));
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
