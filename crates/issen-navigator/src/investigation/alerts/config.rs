//! Configuration file alert detection heuristics.

use issen_parser_uac::parsers::configs::ConfigFile;
use issen_parser_uac::parsers::process::CrontabEntry;

use super::types::{Alert, AlertSeverity};

/// Check for suspicious configuration: ld.so.preload and crontab commands.
pub(super) fn check_config_alerts(
    configs: &[ConfigFile],
    crontabs: &[CrontabEntry],
    alerts: &mut Vec<Alert>,
) {
    let suspicious_commands = ["wget", "curl", "base64", "nc"];

    // ld.so.preload with content
    for cfg in configs {
        if cfg.path.ends_with("ld.so.preload") && !cfg.content.trim().is_empty() {
            alerts.push(Alert {
                severity: AlertSeverity::Critical,
                category: "config".into(),
                message: "ld.so.preload is non-empty (potential shared-library hijack)".into(),
                detail: cfg.content.lines().next().unwrap_or("").to_string(),
            });
        }
    }

    // Suspicious crontab commands
    for entry in crontabs {
        let cmd_lower = entry.command.to_lowercase();
        for keyword in &suspicious_commands {
            if cmd_lower.contains(keyword) {
                alerts.push(Alert {
                    severity: AlertSeverity::Warning,
                    category: "config".into(),
                    message: format!("Suspicious crontab command ({keyword})"),
                    detail: format!(
                        "schedule={} user={} cmd={}",
                        entry.schedule, entry.user, entry.command
                    ),
                });
                break;
            }
        }
    }
}

/// System configuration security auditor from collected config files.
///
/// Audits passwd, hosts, SSH config, sudoers, SSH keys, and macOS
/// persistence mechanisms.
pub(super) fn check_config_baseline(configs: &[ConfigFile], alerts: &mut Vec<Alert>) {
    const NON_INTERACTIVE_SHELLS: &[&str] = &[
        "/usr/sbin/nologin",
        "/bin/false",
        "/sbin/nologin",
        "/bin/sync",
        "/usr/bin/false",
    ];

    for config in configs {
        let path = &config.path;
        let content = &config.content;

        // --- passwd audit ---
        if path.ends_with("passwd") && !path.ends_with("passwd-") {
            let mut interactive_accounts = Vec::new();

            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() < 7 {
                    continue;
                }
                let name = fields[0];
                let uid_str = fields[2];
                let shell = fields[6];

                // UID 0 accounts that aren't root
                if let Ok(uid) = uid_str.parse::<u32>() {
                    if uid == 0 && name != "root" {
                        alerts.push(Alert {
                            severity: AlertSeverity::Critical,
                            category: "config".into(),
                            message: format!("Unexpected UID 0 account: {name}"),
                            detail: format!("line: {line}"),
                        });
                    }
                }

                // Interactive accounts
                let is_interactive = !NON_INTERACTIVE_SHELLS.iter().any(|s| shell == *s);
                if is_interactive {
                    interactive_accounts.push(name.to_string());
                }
            }

            if !interactive_accounts.is_empty() {
                alerts.push(Alert {
                    severity: AlertSeverity::Info,
                    category: "config".into(),
                    message: format!("Interactive accounts: {}", interactive_accounts.join(", ")),
                    detail: format!(
                        "{} interactive accounts in {path}",
                        interactive_accounts.len()
                    ),
                });
            }
        }

        // --- hosts file ---
        if path.ends_with("/hosts") || path == "hosts" {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let lower = line.to_lowercase();
                let is_standard = lower.contains("localhost")
                    || lower.contains("127.0.0.1")
                    || lower.contains("::1")
                    || lower.contains("broadcasthost")
                    || lower.contains("ip6-");
                if !is_standard {
                    alerts.push(Alert {
                        severity: AlertSeverity::Warning,
                        category: "config".into(),
                        message: format!("Hosts file entry: {line}"),
                        detail: format!("source: {path}"),
                    });
                }
            }
        }

        // --- SSH config ---
        if path.contains("sshd_config") && !path.contains("sshd_config.d") {
            for line in content.lines() {
                let line = line.trim();
                if line.starts_with('#') || line.is_empty() {
                    continue;
                }
                let lower = line.to_lowercase();
                if lower.starts_with("permitrootlogin") && lower.contains("yes") {
                    alerts.push(Alert {
                        severity: AlertSeverity::Warning,
                        category: "config".into(),
                        message: "SSH PermitRootLogin is enabled".into(),
                        detail: format!("{line} (in {path})"),
                    });
                }
                if lower.starts_with("passwordauthentication") && lower.contains("yes") {
                    alerts.push(Alert {
                        severity: AlertSeverity::Info,
                        category: "config".into(),
                        message: "SSH PasswordAuthentication is enabled".into(),
                        detail: format!("{line} (in {path})"),
                    });
                }
            }
        }

        // --- sudoers ---
        if path.contains("sudoers") && !path.contains("sudoers.d") {
            for line in content.lines() {
                let line = line.trim();
                if line.starts_with('#') || line.is_empty() {
                    continue;
                }
                if line.contains("NOPASSWD") {
                    alerts.push(Alert {
                        severity: AlertSeverity::Warning,
                        category: "config".into(),
                        message: format!("Sudoers NOPASSWD rule: {line}"),
                        detail: format!("source: {path}"),
                    });
                }
            }
        }

        // --- SSH known_hosts ---
        if path.contains("known_hosts") {
            let entries: Vec<&str> = content
                .lines()
                .filter(|l| {
                    let trimmed = l.trim();
                    !trimmed.is_empty() && !trimmed.starts_with('#')
                })
                .collect();
            let count = entries.len();
            if count > 0 {
                let first_three: Vec<&str> = entries.iter().take(3).copied().collect();
                let detail = format!("first entries: {}", first_three.join(" | "));

                if path.contains("root") || path.starts_with("root/") {
                    alerts.push(Alert {
                        severity: AlertSeverity::Warning,
                        category: "config".into(),
                        message: format!(
                            "Root SSH known_hosts ({count} hosts) \u{2014} lateral movement indicator"
                        ),
                        detail,
                    });
                } else {
                    alerts.push(Alert {
                        severity: AlertSeverity::Info,
                        category: "config".into(),
                        message: format!("SSH known_hosts ({count} hosts) in {path}"),
                        detail,
                    });
                }
            }
        }

        // --- SSH authorized_keys ---
        if path.contains("authorized_keys") {
            let count = content
                .lines()
                .filter(|l| {
                    let trimmed = l.trim();
                    !trimmed.is_empty() && !trimmed.starts_with('#')
                })
                .count();
            if count > 0 {
                let is_root = path.contains("root") || path.starts_with("root/");
                alerts.push(Alert {
                    severity: if is_root {
                        AlertSeverity::Warning
                    } else {
                        AlertSeverity::Info
                    },
                    category: "config".into(),
                    message: format!("SSH authorized_keys ({count} keys) in {path}"),
                    detail: format!("source: {path}"),
                });
            }
        }

        // --- SSH private keys ---
        if (path.contains("id_rsa") || path.contains("id_ed25519") || path.contains("id_ecdsa"))
            && !path.ends_with(".pub")
        {
            if content.starts_with("-----BEGIN") {
                alerts.push(Alert {
                    severity: AlertSeverity::Warning,
                    category: "config".into(),
                    message: format!("SSH private key found: {path}"),
                    detail: format!("source: {path}"),
                });
            }
        }

        // --- macOS LaunchDaemons / LaunchAgents ---
        if path.contains("LaunchDaemons") || path.contains("LaunchAgents") {
            alerts.push(Alert {
                severity: AlertSeverity::Info,
                category: "config".into(),
                message: format!("macOS persistence mechanism: {path}"),
                detail: format!("source: {path}"),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::engine::detect_alerts;
    use super::super::types::AlertInput;
    use super::super::types::AlertSeverity;
    use super::*;

    fn cfg(path: &str, content: &str) -> ConfigFile {
        ConfigFile {
            path: path.into(),
            content: content.into(),
        }
    }

    fn empty_input() -> AlertInput<'static> {
        AlertInput {
            bodyfile: &[],
            network: &[],
            processes: &[],
            crontabs: &[],
            chkrootkit: &[],
            rootkit_findings: &[],
            configs: &[],
            hashes: &[],
            packages: &[],
            logins: &[],
            windows_events: &[],
            mft_entries: &[],
            connection_log: &[],
        }
    }

    #[test]
    fn config_passwd_uid0_non_root_critical() {
        let configs = vec![cfg(
            "/etc/passwd",
            "root:x:0:0:root:/root:/bin/bash\n\
             toor:x:0:0:backdoor:/root:/bin/bash\n",
        )];
        let input = AlertInput {
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Critical
                && a.category == "config"
                && a.message.contains("Unexpected UID 0")
                && a.message.contains("toor")),
            "expected critical for non-root UID 0, got: {alerts:?}"
        );
    }

    #[test]
    fn config_passwd_interactive_accounts_info() {
        let configs = vec![cfg(
            "/etc/passwd",
            "root:x:0:0:root:/root:/bin/bash\n\
             daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
             analyst:x:1000:1000:Analyst:/home/analyst:/bin/bash\n",
        )];
        let input = AlertInput {
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Info
                && a.category == "config"
                && a.message.contains("Interactive accounts")),
            "expected interactive accounts enumeration, got: {alerts:?}"
        );
    }

    #[test]
    fn config_passwd_backup_file_not_audited() {
        // passwd- (backup) should not be audited
        let configs = vec![cfg("/etc/passwd-", "toor:x:0:0:backdoor:/root:/bin/bash\n")];
        let input = AlertInput {
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts
                .iter()
                .any(|a| a.category == "config" && a.message.contains("UID 0")),
            "passwd- backup should not trigger, got: {alerts:?}"
        );
    }

    #[test]
    fn config_hosts_suspicious_entry_warning() {
        let configs = vec![cfg(
            "/etc/hosts",
            "127.0.0.1 localhost\n\
             ::1 localhost\n\
             10.0.0.5 evil.corp\n",
        )];
        let input = AlertInput {
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Warning
                && a.category == "config"
                && a.message.contains("Hosts file entry")
                && a.message.contains("evil.corp")),
            "expected hosts warning for non-standard entry, got: {alerts:?}"
        );
    }

    #[test]
    fn config_hosts_standard_entries_not_flagged() {
        let configs = vec![cfg(
            "/etc/hosts",
            "127.0.0.1 localhost\n\
             ::1 localhost\n\
             255.255.255.255 broadcasthost\n\
             fe00::0 ip6-localnet\n",
        )];
        let input = AlertInput {
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts
                .iter()
                .any(|a| a.category == "config" && a.message.contains("Hosts file entry")),
            "standard hosts entries should not trigger, got: {alerts:?}"
        );
    }

    #[test]
    fn config_sshd_permit_root_login_warning() {
        let configs = vec![cfg(
            "/etc/ssh/sshd_config",
            "# Authentication\n\
             PermitRootLogin yes\n\
             PubkeyAuthentication yes\n",
        )];
        let input = AlertInput {
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.severity == AlertSeverity::Warning
                    && a.message.contains("PermitRootLogin")),
            "expected PermitRootLogin warning, got: {alerts:?}"
        );
    }

    #[test]
    fn config_sshd_password_auth_info() {
        let configs = vec![cfg("/etc/ssh/sshd_config", "PasswordAuthentication yes\n")];
        let input = AlertInput {
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Info
                && a.message.contains("PasswordAuthentication")),
            "expected PasswordAuthentication info, got: {alerts:?}"
        );
    }

    #[test]
    fn config_sshd_commented_lines_not_flagged() {
        let configs = vec![cfg(
            "/etc/ssh/sshd_config",
            "#PermitRootLogin yes\n\
             #PasswordAuthentication yes\n",
        )];
        let input = AlertInput {
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts.iter().any(|a| a.message.contains("PermitRootLogin")
                || a.message.contains("PasswordAuthentication")),
            "commented sshd lines should not trigger, got: {alerts:?}"
        );
    }

    #[test]
    fn config_sudoers_nopasswd_warning() {
        let configs = vec![cfg(
            "/etc/sudoers",
            "# Defaults\n\
             analyst ALL=(ALL) NOPASSWD: ALL\n",
        )];
        let input = AlertInput {
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.severity == AlertSeverity::Warning && a.message.contains("NOPASSWD")),
            "expected sudoers NOPASSWD warning, got: {alerts:?}"
        );
    }

    #[test]
    fn config_known_hosts_root_lateral_movement() {
        let configs = vec![cfg(
            "root/.ssh/known_hosts",
            "10.0.0.5 ssh-rsa AAAA...\n\
             10.0.0.6 ssh-ed25519 AAAA...\n",
        )];
        let input = AlertInput {
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Warning
                && a.message.contains("Root SSH known_hosts")
                && a.message.contains("lateral movement")),
            "expected root known_hosts lateral movement warning, got: {alerts:?}"
        );
    }

    #[test]
    fn config_known_hosts_non_root_info() {
        let configs = vec![cfg(
            "analyst/.ssh/known_hosts",
            "github.com ssh-rsa AAAA...\n",
        )];
        let input = AlertInput {
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Info
                && a.message.contains("SSH known_hosts")
                && a.message.contains("analyst")),
            "expected info for non-root known_hosts, got: {alerts:?}"
        );
    }

    #[test]
    fn config_authorized_keys_root_warning() {
        let configs = vec![cfg(
            "root/.ssh/authorized_keys",
            "ssh-rsa AAAA... attacker@evil\n",
        )];
        let input = AlertInput {
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Warning
                && a.message.contains("authorized_keys")
                && a.message.contains("1 keys")),
            "expected root authorized_keys warning, got: {alerts:?}"
        );
    }

    #[test]
    fn config_authorized_keys_non_root_info() {
        let configs = vec![cfg(
            "analyst/.ssh/authorized_keys",
            "ssh-ed25519 AAAA... analyst@workstation\n",
        )];
        let input = AlertInput {
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Info
                && a.message.contains("authorized_keys")
                && a.message.contains("1 keys")),
            "expected info for non-root authorized_keys, got: {alerts:?}"
        );
    }

    #[test]
    fn config_ssh_private_key_warning() {
        let configs = vec![cfg(
            "root/.ssh/id_rsa",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n",
        )];
        let input = AlertInput {
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.severity == AlertSeverity::Warning
                    && a.message.contains("SSH private key")),
            "expected SSH private key warning, got: {alerts:?}"
        );
    }

    #[test]
    fn config_ssh_pub_key_not_flagged() {
        // .pub files should not trigger private key alert
        let configs = vec![cfg("root/.ssh/id_rsa.pub", "ssh-rsa AAAA... root@host\n")];
        let input = AlertInput {
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts.iter().any(|a| a.message.contains("SSH private key")),
            ".pub should not trigger private key alert, got: {alerts:?}"
        );
    }

    #[test]
    fn config_macos_launchdaemon_info() {
        let configs = vec![cfg(
            "/Library/LaunchDaemons/com.evil.plist",
            "<plist>...</plist>",
        )];
        let input = AlertInput {
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.severity == AlertSeverity::Info
                    && a.message.contains("macOS persistence")),
            "expected macOS LaunchDaemons info, got: {alerts:?}"
        );
    }

    #[test]
    fn config_macos_launchagent_info() {
        let configs = vec![cfg(
            "/Library/LaunchAgents/com.user.agent.plist",
            "<plist>...</plist>",
        )];
        let input = AlertInput {
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.severity == AlertSeverity::Info
                    && a.message.contains("macOS persistence")),
            "expected macOS LaunchAgents info, got: {alerts:?}"
        );
    }
}
