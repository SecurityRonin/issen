use serde::Serialize;

/// A parsed login record from `last` command output.
#[derive(Debug, Clone, Serialize)]
pub struct LoginRecord {
    pub user: String,
    pub terminal: String,
    pub source: String,
    pub login_time: Option<String>,
    pub logout_time: Option<String>,
    pub duration: Option<String>,
}

/// System information parsed from UAC system artifacts.
#[derive(Debug, Clone, Serialize)]
pub struct SystemInfo {
    pub hostname: Option<String>,
    pub uname: Option<String>,
    pub uptime: Option<String>,
}

/// Parse `last` command output.
///
/// Format: `user  tty  source  login_day login_time - logout_time  (duration)`
#[must_use]
pub fn parse_last_output(content: &str) -> Vec<LoginRecord> {
    let mut results = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("wtmp begins")
            || trimmed.starts_with("btmp begins")
        {
            continue;
        }

        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }

        let user = fields[0].to_string();
        let terminal = fields[1].to_string();

        let (source, time_start_idx) = if fields.len() > 4
            && (fields[2].contains('.') || fields[2].contains(':') || fields[2] == "0.0.0.0")
        {
            (fields[2].to_string(), 3)
        } else {
            (String::new(), 2)
        };

        let login_time = if time_start_idx + 2 <= fields.len() {
            Some(fields[time_start_idx..time_start_idx + 2].join(" "))
        } else {
            None
        };

        let logout_time = fields
            .iter()
            .position(|&f| f == "-")
            .and_then(|i| fields.get(i + 1).map(|s| (*s).to_string()));

        let duration = fields
            .iter()
            .find(|f| f.starts_with('('))
            .map(|f| f.trim_start_matches('(').trim_end_matches(')').to_string());

        results.push(LoginRecord {
            user,
            terminal,
            source,
            login_time,
            logout_time,
            duration,
        });
    }

    results
}

/// Parse system info from UAC system directory files.
#[must_use]
pub fn parse_system_info(dir: &std::path::Path) -> SystemInfo {
    let hostname = std::fs::read_to_string(dir.join("hostname.txt"))
        .ok()
        .map(|s| s.trim().to_string());
    let uname = std::fs::read_to_string(dir.join("uname-a.txt"))
        .ok()
        .map(|s| s.trim().to_string());
    let uptime = std::fs::read_to_string(dir.join("uptime.txt"))
        .ok()
        .map(|s| s.trim().to_string());

    SystemInfo {
        hostname,
        uname,
        uptime,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_last_output() {
        let content = "root     pts/0        10.0.0.5         Mon Mar 24 19:38   still logged in\n\
                        admin    tty1                          Mon Mar 24 10:00 - 12:30  (02:30)\n\
                        \n\
                        wtmp begins Mon Mar 24 00:00:00 2026\n";
        let records = parse_last_output(content);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].user, "root");
        assert_eq!(records[0].terminal, "pts/0");
        assert_eq!(records[0].source, "10.0.0.5");
        assert_eq!(records[1].user, "admin");
    }

    #[test]
    fn test_parse_last_empty() {
        assert!(parse_last_output("").is_empty());
        assert!(parse_last_output("wtmp begins Mon Mar 24 00:00:00 2026\n").is_empty());
    }

    #[test]
    fn test_parse_system_info() {
        let dir = tempfile::tempdir().expect("tmpdir");
        std::fs::write(dir.path().join("hostname.txt"), "testhost\n").expect("write");
        std::fs::write(dir.path().join("uname-a.txt"), "Linux testhost 5.15.0\n").expect("write");

        let info = parse_system_info(dir.path());
        assert_eq!(info.hostname.as_deref(), Some("testhost"));
        assert!(info.uname.as_ref().expect("uname").contains("Linux"));
        assert!(info.uptime.is_none());
    }
}
