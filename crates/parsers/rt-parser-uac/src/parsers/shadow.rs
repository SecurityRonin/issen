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
#[must_use]
pub fn parse_passwd(_content: &str) -> Vec<PasswdEntry> {
    todo!("implement parse_passwd")
}

/// Classify a passwd entry as suspicious or not.
#[must_use]
pub fn classify_passwd_entry(_entry: &PasswdEntry) -> bool {
    todo!("implement classify_passwd_entry")
}

/// Parse /etc/shadow content into structured entries.
#[must_use]
pub fn parse_shadow(_content: &str) -> Vec<ShadowEntry> {
    todo!("implement parse_shadow")
}

/// Classify a shadow entry as suspicious or not.
#[must_use]
pub fn classify_shadow_entry(_entry: &ShadowEntry) -> bool {
    todo!("implement classify_shadow_entry")
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
