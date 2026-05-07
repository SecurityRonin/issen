//! Authentication and session forensics alert detection heuristics.
//!
//! Covers both Linux/macOS login analysis (from parsed `last` output) and
//! Windows authentication forensics (from Security EVTX events).

use issen_parser_uac::parsers::system::LoginRecord;

use super::types::{Alert, AlertSeverity, WindowsEvent};

/// Detect suspicious login patterns from parsed `last` output.
///
/// Detects:
/// - Root login from a remote host (Critical)
/// - Login source that appears only once across all records (Warning)
pub(super) fn check_login_anomalies(logins: &[LoginRecord], alerts: &mut Vec<Alert>) {
    // Count occurrences of each non-empty login source
    let mut source_counts: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::new();
    for login in logins {
        let src = login.source.as_str();
        if !src.is_empty() {
            *source_counts.entry(src).or_insert(0) += 1;
        }
    }

    for login in logins {
        let src = login.source.as_str();

        // Root login from remote host (non-empty, non-local source)
        if login.user == "root" && !src.is_empty() && src != "localhost" && !src.starts_with(':') {
            alerts.push(Alert {
                severity: AlertSeverity::Critical,
                category: "auth".into(),
                message: format!("Remote root login from {src}"),
                detail: format!(
                    "user={} terminal={} source={} time={}",
                    login.user,
                    login.terminal,
                    src,
                    login.login_time.as_deref().unwrap_or("unknown")
                ),
            });
        }

        // Unique login source — appears exactly once
        if !src.is_empty() && source_counts.get(src) == Some(&1) && logins.len() > 1 {
            alerts.push(Alert {
                severity: AlertSeverity::Warning,
                category: "auth".into(),
                message: format!("Unique login source: {src} (seen only once)"),
                detail: format!(
                    "user={} terminal={} source={} time={}",
                    login.user,
                    login.terminal,
                    src,
                    login.login_time.as_deref().unwrap_or("unknown")
                ),
            });
        }
    }
}

/// Session pattern analyzer from `last` output.
///
/// Detects crash/reboot entries, rapid reboots, local root console sessions,
/// and very short sessions.
pub(super) fn check_session_forensics(logins: &[LoginRecord], alerts: &mut Vec<Alert>) {
    let mut reboot_count: usize = 0;

    for record in logins {
        let user_lower = record.user.to_lowercase();

        // Crash/reboot entries
        if user_lower == "reboot" && record.terminal.to_lowercase().contains("system boot") {
            reboot_count += 1;
            alerts.push(Alert {
                severity: AlertSeverity::Warning,
                category: "auth".into(),
                message: "System reboot detected".into(),
                detail: format!(
                    "login_time={}",
                    record.login_time.as_deref().unwrap_or("unknown")
                ),
            });
        } else if user_lower == "shutdown" {
            alerts.push(Alert {
                severity: AlertSeverity::Warning,
                category: "auth".into(),
                message: "System shutdown entry detected".into(),
                detail: format!(
                    "login_time={}",
                    record.login_time.as_deref().unwrap_or("unknown")
                ),
            });
        }

        // Count reboots (also count plain reboot entries without "system boot")
        if user_lower == "reboot" && !record.terminal.to_lowercase().contains("system boot") {
            reboot_count += 1;
        }

        // Local root sessions (console, not SSH pseudo-terminal)
        if user_lower == "root"
            && record.terminal.starts_with("tty")
            && !record.terminal.starts_with("pts")
        {
            alerts.push(Alert {
                severity: AlertSeverity::Warning,
                category: "auth".into(),
                message: "Local root console session detected".into(),
                detail: format!(
                    "terminal={} login_time={}",
                    record.terminal,
                    record.login_time.as_deref().unwrap_or("unknown")
                ),
            });
        }

        // Very short sessions (< 1 minute)
        if let Some(ref duration) = record.duration {
            if user_lower != "reboot" && user_lower != "shutdown" {
                let cleaned = duration.trim_matches(|c| c == '(' || c == ')');
                let is_short = if let Some((minutes_str, seconds_str)) = cleaned.split_once(':') {
                    let minutes = minutes_str.parse::<u64>().unwrap_or(u64::MAX);
                    let seconds = seconds_str.parse::<u64>().unwrap_or(u64::MAX);
                    minutes == 0 && seconds < 60
                } else {
                    false
                };

                if is_short {
                    alerts.push(Alert {
                        severity: AlertSeverity::Info,
                        category: "auth".into(),
                        message: format!("Very short session for user '{}'", record.user),
                        detail: format!("duration={} terminal={}", duration, record.terminal),
                    });
                }
            }
        }
    }

    // Rapid reboot detection
    if reboot_count >= 3 {
        alerts.push(Alert {
            severity: AlertSeverity::Warning,
            category: "auth".into(),
            message: format!("Rapid reboot activity detected ({reboot_count} reboots)"),
            detail: "Multiple reboots may indicate instability, crash loops, or anti-forensics"
                .into(),
        });
    }
}

/// Windows authentication forensics from Security event log.
///
/// Detects brute-force logon attempts (4625), account manipulation (4720/4726),
/// and provides logon success/failure ratio analysis.
pub(super) fn check_windows_auth_forensics(events: &[WindowsEvent], alerts: &mut Vec<Alert>) {
    if events.is_empty() {
        return;
    }

    let mut failed_logons: Vec<&WindowsEvent> = Vec::new();
    let mut successful_logons: usize = 0;

    for event in events {
        match event.event_id {
            4625 => failed_logons.push(event),
            4624 => successful_logons += 1,
            // Account created
            4720 => {
                alerts.push(Alert {
                    severity: AlertSeverity::Warning,
                    category: "windows-auth".into(),
                    message: format!(
                        "User account created (EventID:4720) on {}",
                        if event.computer.is_empty() {
                            "unknown"
                        } else {
                            &event.computer
                        }
                    ),
                    detail: event.description.clone(),
                });
            }
            // Account deleted
            4726 => {
                alerts.push(Alert {
                    severity: AlertSeverity::Info,
                    category: "windows-auth".into(),
                    message: format!(
                        "User account deleted (EventID:4726) on {}",
                        if event.computer.is_empty() {
                            "unknown"
                        } else {
                            &event.computer
                        }
                    ),
                    detail: event.description.clone(),
                });
            }
            // Account modified (group membership, enabled/disabled, etc.)
            4722 | 4725 | 4738 => {
                alerts.push(Alert {
                    severity: AlertSeverity::Info,
                    category: "windows-auth".into(),
                    message: format!(
                        "Account modification (EventID:{}) on {}",
                        event.event_id,
                        if event.computer.is_empty() {
                            "unknown"
                        } else {
                            &event.computer
                        }
                    ),
                    detail: event.description.clone(),
                });
            }
            _ => {}
        }
    }

    let fail_count = failed_logons.len();

    // Brute-force thresholds based on SIGMA rule `0e4c1e08`
    // (Windows Security - Multiple Logon Failures)
    if fail_count >= 50 {
        alerts.push(Alert {
            severity: AlertSeverity::Critical,
            category: "windows-auth".into(),
            message: format!("Sustained brute-force: {fail_count} failed logons detected"),
            detail: format!(
                "source: SIGMA 0e4c1e08 | successes={successful_logons} failures={fail_count}"
            ),
        });
    } else if fail_count >= 10 {
        alerts.push(Alert {
            severity: AlertSeverity::Warning,
            category: "windows-auth".into(),
            message: format!("Brute-force attempt: {fail_count} failed logons detected"),
            detail: format!(
                "source: SIGMA 0e4c1e08 | successes={successful_logons} failures={fail_count}"
            ),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::super::engine::detect_alerts;
    use super::super::types::AlertInput;
    use super::super::types::AlertSeverity;
    use super::*;

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

    fn login(user: &str, terminal: &str, duration: Option<&str>) -> LoginRecord {
        LoginRecord {
            user: user.into(),
            terminal: terminal.into(),
            source: String::new(),
            login_time: Some("Mon Mar 24 12:00".into()),
            logout_time: None,
            duration: duration.map(String::from),
        }
    }

    fn winevt(event_id: u64, desc: &str) -> WindowsEvent {
        WindowsEvent {
            event_id,
            channel: "Security".into(),
            provider: "Microsoft-Windows-Security-Auditing".into(),
            computer: "WORKSTATION01".into(),
            timestamp: 1_700_000_000,
            description: desc.into(),
        }
    }

    // --- Linux/macOS login anomaly tests ---

    #[test]
    fn root_login_from_remote_host_critical() {
        let logins = vec![LoginRecord {
            user: "root".into(),
            terminal: "pts/0".into(),
            source: "10.0.0.50".into(),
            login_time: Some("Mon Mar 24 10:00 2026".into()),
            logout_time: None,
            duration: None,
        }];
        let input = AlertInput {
            logins: &logins,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Critical
                && a.category == "auth"
                && a.message.contains("root")),
            "expected critical root remote login alert, got: {alerts:?}"
        );
    }

    #[test]
    fn root_login_local_console_not_flagged() {
        let logins = vec![LoginRecord {
            user: "root".into(),
            terminal: "tty1".into(),
            source: String::new(),
            login_time: Some("Mon Mar 24 10:00 2026".into()),
            logout_time: None,
            duration: None,
        }];
        let input = AlertInput {
            logins: &logins,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts
                .iter()
                .any(|a| a.category == "auth" && a.severity == AlertSeverity::Critical),
            "should not flag local console root login as critical, got: {alerts:?}"
        );
    }

    #[test]
    fn unique_login_source_flagged() {
        let logins = vec![
            LoginRecord {
                user: "admin".into(),
                terminal: "pts/0".into(),
                source: "192.168.1.100".into(),
                login_time: None,
                logout_time: None,
                duration: None,
            },
            LoginRecord {
                user: "admin".into(),
                terminal: "pts/1".into(),
                source: "192.168.1.100".into(),
                login_time: None,
                logout_time: None,
                duration: None,
            },
            LoginRecord {
                user: "admin".into(),
                terminal: "pts/2".into(),
                source: "10.99.99.99".into(),
                login_time: None,
                logout_time: None,
                duration: None,
            },
        ];
        let input = AlertInput {
            logins: &logins,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.category == "auth"
                && a.message.contains("Unique login source")
                && a.detail.contains("10.99.99.99")),
            "expected unique source alert for 10.99.99.99, got: {alerts:?}"
        );
    }

    #[test]
    fn all_same_login_source_no_unique_alert() {
        let logins = vec![
            LoginRecord {
                user: "admin".into(),
                terminal: "pts/0".into(),
                source: "192.168.1.100".into(),
                login_time: None,
                logout_time: None,
                duration: None,
            },
            LoginRecord {
                user: "admin".into(),
                terminal: "pts/1".into(),
                source: "192.168.1.100".into(),
                login_time: None,
                logout_time: None,
                duration: None,
            },
        ];
        let input = AlertInput {
            logins: &logins,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts
                .iter()
                .any(|a| a.message.contains("Unique login source")),
            "should not flag when all sources are the same, got: {alerts:?}"
        );
    }

    #[test]
    fn session_reboot_detected() {
        let logins = vec![login("reboot", "system boot", None)];
        let input = AlertInput {
            logins: &logins,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.category == "auth" && a.message.contains("System reboot detected")),
            "expected reboot alert, got: {alerts:?}"
        );
    }

    #[test]
    fn session_shutdown_detected() {
        let logins = vec![login("shutdown", "~", None)];
        let input = AlertInput {
            logins: &logins,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.category == "auth" && a.message.contains("shutdown entry")),
            "expected shutdown alert, got: {alerts:?}"
        );
    }

    #[test]
    fn session_rapid_reboots_warning() {
        // 3+ reboots triggers rapid reboot warning
        let logins = vec![
            login("reboot", "system boot", None),
            login("reboot", "system boot", None),
            login("reboot", "system boot", None),
        ];
        let input = AlertInput {
            logins: &logins,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.category == "auth" && a.message.contains("Rapid reboot")),
            "expected rapid reboot alert for 3+ reboots, got: {alerts:?}"
        );
    }

    #[test]
    fn session_two_reboots_no_rapid_alert() {
        // Only 2 reboots — below threshold
        let logins = vec![
            login("reboot", "system boot", None),
            login("reboot", "system boot", None),
        ];
        let input = AlertInput {
            logins: &logins,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts
                .iter()
                .any(|a| a.category == "auth" && a.message.contains("Rapid reboot")),
            "2 reboots should not trigger rapid alert, got: {alerts:?}"
        );
    }

    #[test]
    fn session_local_root_console_warning() {
        let logins = vec![login("root", "tty1", None)];
        let input = AlertInput {
            logins: &logins,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.category == "auth" && a.message.contains("Local root console session")),
            "expected local root console alert, got: {alerts:?}"
        );
    }

    #[test]
    fn session_root_on_pts_not_local_console() {
        // root on pts/0 is SSH pseudo-terminal, not local console
        let logins = vec![login("root", "pts/0", None)];
        let input = AlertInput {
            logins: &logins,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts
                .iter()
                .any(|a| a.message.contains("Local root console session")),
            "root on pts should not trigger local console alert, got: {alerts:?}"
        );
    }

    #[test]
    fn session_shoissen_duration_info() {
        // Duration < 1 min
        let logins = vec![login("analyst", "pts/0", Some("(00:05)"))];
        let input = AlertInput {
            logins: &logins,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Info
                && a.message.contains("Very short session")
                && a.message.contains("analyst")),
            "expected short session alert, got: {alerts:?}"
        );
    }

    #[test]
    fn session_normal_duration_not_flagged() {
        // Duration > 1 min — should not flag
        let logins = vec![login("analyst", "pts/0", Some("(05:30)"))];
        let input = AlertInput {
            logins: &logins,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts
                .iter()
                .any(|a| a.message.contains("Very short session")),
            "normal duration should not trigger short session, got: {alerts:?}"
        );
    }

    #[test]
    fn session_reboot_user_no_shoissen_session_alert() {
        // "reboot" user with duration should NOT get short session alert
        let logins = vec![login("reboot", "system boot", Some("(00:01)"))];
        let input = AlertInput {
            logins: &logins,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts
                .iter()
                .any(|a| a.message.contains("Very short session")),
            "reboot entry should not trigger short session, got: {alerts:?}"
        );
    }

    // --- Windows authentication forensics tests ---

    #[test]
    fn win_auth_brute_force_10_failures_warning() {
        let events: Vec<WindowsEvent> = (0..10)
            .map(|i| winevt(4625, &format!("Logon failure #{i} user=admin")))
            .collect();
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Warning
                && a.category == "windows-auth"
                && a.message.contains("Brute-force")),
            "expected brute-force warning at 10 failures, got: {alerts:?}"
        );
    }

    #[test]
    fn win_auth_sustained_brute_force_50_critical() {
        let events: Vec<WindowsEvent> = (0..50)
            .map(|i| winevt(4625, &format!("Logon failure #{i}")))
            .collect();
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Critical
                && a.category == "windows-auth"
                && a.message.contains("Sustained brute-force")),
            "expected critical at 50 failures, got: {alerts:?}"
        );
    }

    #[test]
    fn win_auth_9_failures_no_brute_force_alert() {
        let events: Vec<WindowsEvent> = (0..9)
            .map(|i| winevt(4625, &format!("Failure #{i}")))
            .collect();
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts
                .iter()
                .any(|a| a.category == "windows-auth" && a.message.contains("rute-force")),
            "9 failures should not trigger brute-force, got: {alerts:?}"
        );
    }

    #[test]
    fn win_auth_account_created_warning() {
        let events = vec![winevt(4720, "TargetUserName=backdoor")];
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Warning
                && a.category == "windows-auth"
                && a.message.contains("account created")
                && a.message.contains("4720")),
            "expected account creation warning, got: {alerts:?}"
        );
    }

    #[test]
    fn win_auth_account_deleted_info() {
        let events = vec![winevt(4726, "TargetUserName=tempuser")];
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Info
                && a.category == "windows-auth"
                && a.message.contains("account deleted")
                && a.message.contains("4726")),
            "expected account deletion info, got: {alerts:?}"
        );
    }

    #[test]
    fn win_auth_account_modified_info() {
        let events = vec![winevt(4738, "TargetUserName=admin")];
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Info
                && a.category == "windows-auth"
                && a.message.contains("Account modification")
                && a.message.contains("4738")),
            "expected account modification info, got: {alerts:?}"
        );
    }

    #[test]
    fn win_auth_success_failure_ratio_in_detail() {
        // Mix of successes and failures
        let mut events = Vec::new();
        for i in 0..15 {
            events.push(winevt(4625, &format!("Failure #{i}")));
        }
        for i in 0..5 {
            events.push(winevt(4624, &format!("Success #{i}")));
        }
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        let brute = alerts.iter().find(|a| a.message.contains("rute-force"));
        assert!(
            brute.is_some(),
            "expected brute-force alert, got: {alerts:?}"
        );
        let detail = &brute.unwrap().detail;
        assert!(
            detail.contains("successes=5") && detail.contains("failures=15"),
            "detail should include ratio: {detail}"
        );
    }

    #[test]
    fn win_auth_empty_computer_shows_unknown() {
        let events = vec![WindowsEvent {
            event_id: 4720,
            channel: "Security".into(),
            provider: String::new(),
            computer: String::new(),
            timestamp: 0,
            description: "account created".into(),
        }];
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.category == "windows-auth" && a.message.contains("unknown")),
            "empty computer should show 'unknown', got: {alerts:?}"
        );
    }

    #[test]
    fn win_auth_only_successes_no_alert() {
        let events: Vec<WindowsEvent> = (0..100)
            .map(|i| winevt(4624, &format!("Success #{i}")))
            .collect();
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts
                .iter()
                .any(|a| a.category == "windows-auth" && a.message.contains("rute-force")),
            "only successes should not trigger brute-force, got: {alerts:?}"
        );
    }
}
