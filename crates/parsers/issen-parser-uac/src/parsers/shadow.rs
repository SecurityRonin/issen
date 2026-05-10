use serde::Serialize;

/// A parsed entry from /etc/passwd.
#[derive(Debug, Clone, Serialize)]
pub struct PasswdEntry {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home_dir: String,
    pub shell: String,
    pub has_password: bool,
    pub is_suspicious: bool,
}

/// A parsed entry from /etc/shadow.
#[derive(Debug, Clone, Serialize)]
pub struct ShadowEntry {
    pub username: String,
    pub hash_algorithm: String,
    pub last_changed_days: Option<i64>,
    pub is_suspicious: bool,
}

/// Parse /etc/passwd content into structured entries.
///
/// Format: `username:x:uid:gid:gecos:home:shell`
/// Lines starting with `#` are ignored.
#[must_use]
pub fn parse_passwd(content: &str) -> Vec<PasswdEntry> {
    let mut results = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 7 {
            continue;
        }

        let username = fields[0].to_string();
        let uid = fields[2].parse::<u32>().unwrap_or(u32::MAX);
        let gid = fields[3].parse::<u32>().unwrap_or(u32::MAX);
        let home_dir = fields[5].to_string();
        let shell = fields[6].to_string();
        // password field: 'x' means shadow, '*' or '!' means locked/no-login
        let has_password = fields[1] != "*" && fields[1] != "!" && !fields[1].is_empty();

        let mut entry = PasswdEntry {
            username,
            uid,
            gid,
            home_dir,
            shell,
            has_password,
            is_suspicious: false,
        };
        entry.is_suspicious = classify_passwd_entry(&entry);
        results.push(entry);
    }

    results
}

/// Classify a passwd entry as suspicious or not.
///
/// Suspicious if:
/// - uid == 0 and username != "root" (hidden root account)
/// - shell is `/bin/bash` or `/bin/sh`, uid < 100, and username not in the
///   standard privileged-service allow-list
#[must_use]
pub fn classify_passwd_entry(entry: &PasswdEntry) -> bool {
    // Hidden root account
    if entry.uid == 0 && entry.username != "root" {
        return true;
    }

    // Service account with interactive shell
    let interactive_shells = ["/bin/bash", "/bin/sh"];
    let safe_service_accounts = ["root", "sync", "shutdown", "halt"];
    if interactive_shells.iter().any(|&s| entry.shell == s)
        && entry.uid < 100
        && !safe_service_accounts.contains(&entry.username.as_str())
    {
        return true;
    }

    false
}

/// Parse /etc/shadow content into structured entries.
///
/// Format: `username:hash:last_changed:min:max:warn:inactive:expire:`
/// The hash algorithm is determined from the `$id$` prefix.
#[must_use]
pub fn parse_shadow(content: &str) -> Vec<ShadowEntry> {
    let mut results = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 3 {
            continue;
        }

        let username = fields[0].to_string();
        let hash_field = fields[1];

        let hash_algorithm = detect_hash_algorithm(hash_field);

        let last_changed_days = fields[2].parse::<i64>().ok();

        let mut entry = ShadowEntry {
            username,
            hash_algorithm,
            last_changed_days,
            is_suspicious: false,
        };
        entry.is_suspicious = classify_shadow_entry(&entry);
        results.push(entry);
    }

    results
}

fn detect_hash_algorithm(hash_field: &str) -> String {
    // Locked or no-login markers
    if hash_field == "!" || hash_field == "*" || hash_field.is_empty() {
        return hash_field.to_string();
    }
    // Extract $id$ prefix: e.g. "$6$rounds=..." → "$6$"
    if hash_field.starts_with('$') {
        let without_dollar = &hash_field[1..];
        if let Some(end) = without_dollar.find('$') {
            return format!("${}$", &without_dollar[..end]);
        }
    }
    // Unknown format
    hash_field.to_string()
}

/// Classify a shadow entry as suspicious or not.
///
/// Suspicious if:
/// - `hash_algorithm` is `$1$` (MD5 — weak)
/// - `hash_algorithm` is an unrecognised `$X$` prefix
#[must_use]
pub fn classify_shadow_entry(entry: &ShadowEntry) -> bool {
    let known_strong = ["$5$", "$6$", "$7$", "$y$", "$2b$", "!", "*", ""];
    let alg = entry.hash_algorithm.as_str();

    // MD5 is explicitly weak
    if alg == "$1$" {
        return true;
    }

    // Unknown $X$ prefix
    if alg.starts_with('$') && !known_strong.contains(&alg) {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_passwd_line() {
        let content =
            "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:/home/alice:/bin/bash\n";
        let entries = parse_passwd(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].username, "root");
        assert_eq!(entries[0].uid, 0);
        assert_eq!(entries[0].shell, "/bin/bash");
        assert_eq!(entries[1].username, "alice");
        assert_eq!(entries[1].uid, 1000);
    }

    #[test]
    fn parse_passwd_skips_comments() {
        let content = "# /etc/passwd\nroot:x:0:0:root:/root:/bin/bash\n";
        let entries = parse_passwd(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].username, "root");
    }

    #[test]
    fn classify_uid_zero_non_root_suspicious() {
        let entry = PasswdEntry {
            username: "backdoor".to_string(),
            uid: 0,
            gid: 0,
            home_dir: "/root".to_string(),
            shell: "/bin/bash".to_string(),
            has_password: true,
            is_suspicious: false,
        };
        assert!(classify_passwd_entry(&entry));
    }

    #[test]
    fn classify_service_account_with_shell_suspicious() {
        let entry = PasswdEntry {
            username: "daemon".to_string(),
            uid: 2,
            gid: 2,
            home_dir: "/usr/sbin".to_string(),
            shell: "/bin/bash".to_string(),
            has_password: false,
            is_suspicious: false,
        };
        assert!(classify_passwd_entry(&entry));
    }

    #[test]
    fn parse_shadow_line_sha512() {
        let content = "root:$6$rounds=5000$saltsalt$hashhash:18000:0:99999:7:::\nalice:!:18001:0:99999:7:::\n";
        let entries = parse_shadow(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].username, "root");
        assert_eq!(entries[0].hash_algorithm, "$6$");
        assert_eq!(entries[0].last_changed_days, Some(18000));
        assert_eq!(entries[1].hash_algorithm, "!");
    }

    #[test]
    fn classify_shadow_md5_suspicious() {
        let entry = ShadowEntry {
            username: "olduser".to_string(),
            hash_algorithm: "$1$".to_string(),
            last_changed_days: Some(15000),
            is_suspicious: false,
        };
        assert!(classify_shadow_entry(&entry));

        let strong_entry = ShadowEntry {
            username: "root".to_string(),
            hash_algorithm: "$6$".to_string(),
            last_changed_days: Some(18000),
            is_suspicious: false,
        };
        assert!(!classify_shadow_entry(&strong_entry));
    }
}
