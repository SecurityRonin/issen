//! System integrity and environment consistency detection heuristics.
//!
//! Covers Linux/macOS environment checks (hypervisor module conflicts,
//! DYLD injection) and Windows system integrity forensics (log clearing,
//! unexpected shutdowns, audit policy changes from EVTX events).

use issen_parser_uac::parsers::configs::ConfigFile;
use issen_parser_uac::parsers::rootkit::RootkitFinding;

use super::types::{Alert, AlertSeverity, WindowsEvent};

/// Environment and virtualization consistency checks.
///
/// Detects conflicting hypervisor modules (e.g. VirtualBox + VMware loaded
/// simultaneously), macOS DYLD injection, and environment anomalies.
pub(super) fn check_environment_consistency(
    rootkit_findings: &[RootkitFinding],
    configs: &[ConfigFile],
    alerts: &mut Vec<Alert>,
) {
    const VBOX_MODULES: &[&str] = &["vboxguest", "vboxsf", "vboxvideo", "vboxdrv"];
    const VMWARE_MODULES: &[&str] = &[
        "vmw_balloon",
        "vmw_vsock_vmci",
        "vmwgfx",
        "vmw_vmci",
        "vmxnet3",
        "vmw_pvscsi",
    ];
    const KVM_MODULES: &[&str] = &["kvm", "kvm_intel", "kvm_amd"];
    const HYPERV_MODULES: &[&str] = &["hv_vmbus", "hv_storvsc", "hv_netvsc"];

    // Collect module names from rootkit_findings with check == "kernel_module"
    let mut rootkit_modules: Vec<String> = Vec::new();
    for finding in rootkit_findings {
        if finding.check == "kernel_module" {
            // Extract module names from evidence field
            for word in finding.evidence.split_whitespace() {
                let cleaned = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '_');
                if !cleaned.is_empty() {
                    rootkit_modules.push(cleaned.to_lowercase());
                }
            }
        }
    }

    // Parse lsmod from configs for comprehensive module list
    let mut loaded_modules: std::collections::HashSet<String> = std::collections::HashSet::new();

    for config in configs {
        if config.path.contains("lsmod") {
            for (i, line) in config.content.lines().enumerate() {
                // Skip header line
                if i == 0 {
                    continue;
                }
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Some(module_name) = trimmed.split_whitespace().next() {
                    loaded_modules.insert(module_name.to_lowercase());
                }
            }
        }
    }

    // Also add rootkit-detected modules
    for m in &rootkit_modules {
        loaded_modules.insert(m.clone());
    }

    // Check for hypervisor conflicts
    let has_vbox = loaded_modules
        .iter()
        .any(|m| VBOX_MODULES.contains(&m.as_str()));
    let has_vmware = loaded_modules
        .iter()
        .any(|m| VMWARE_MODULES.contains(&m.as_str()));
    let has_kvm = loaded_modules
        .iter()
        .any(|m| KVM_MODULES.contains(&m.as_str()));
    let has_hyperv = loaded_modules
        .iter()
        .any(|m| HYPERV_MODULES.contains(&m.as_str()));

    let mut conflicts: Vec<(&str, &str)> = Vec::new();
    if has_vbox && has_vmware {
        conflicts.push(("VirtualBox", "VMware"));
    }
    if has_vbox && has_kvm {
        conflicts.push(("VirtualBox", "KVM"));
    }
    if has_vbox && has_hyperv {
        conflicts.push(("VirtualBox", "Hyper-V"));
    }
    if has_vmware && has_kvm {
        conflicts.push(("VMware", "KVM"));
    }
    if has_vmware && has_hyperv {
        conflicts.push(("VMware", "Hyper-V"));
    }
    if has_kvm && has_hyperv {
        conflicts.push(("KVM", "Hyper-V"));
    }

    if !conflicts.is_empty() {
        let pairs: Vec<String> = conflicts
            .iter()
            .map(|(a, b)| format!("{a} + {b}"))
            .collect();
        let detected_modules: Vec<&String> = loaded_modules
            .iter()
            .filter(|m| {
                VBOX_MODULES.contains(&m.as_str())
                    || VMWARE_MODULES.contains(&m.as_str())
                    || KVM_MODULES.contains(&m.as_str())
                    || HYPERV_MODULES.contains(&m.as_str())
            })
            .collect();

        alerts.push(Alert {
            severity: AlertSeverity::Warning,
            category: "environment".into(),
            message: "Conflicting hypervisor modules detected".into(),
            detail: format!(
                "conflicts: {} | modules: {}",
                pairs.join(", "),
                detected_modules
                    .iter()
                    .map(|m| m.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        });
    }

    // macOS DYLD_INSERT_LIBRARIES injection
    for config in configs {
        if config.path.contains("env") || config.path.contains("environment") {
            for line in config.content.lines() {
                if line.contains("DYLD_INSERT_LIBRARIES") {
                    alerts.push(Alert {
                        severity: AlertSeverity::Critical,
                        category: "environment".into(),
                        message: "DYLD_INSERT_LIBRARIES detected (macOS library injection)".into(),
                        detail: format!("source: {} | line: {}", config.path, line.trim()),
                    });
                }
            }
        }
    }
}

/// Windows system integrity checks from System and Security event logs.
///
/// Detects security log clearing (1102 — Critical, anti-forensics indicator),
/// unexpected/dirty shutdowns (6008), rapid boot cycles, and audit policy
/// changes (4719).
pub(super) fn check_windows_system_integrity(events: &[WindowsEvent], alerts: &mut Vec<Alert>) {
    let mut boot_count: usize = 0;
    let mut shutdown_count: usize = 0;

    for event in events {
        match event.event_id {
            // Security log cleared — SIGMA `104/1102 detection` (anti-forensics)
            1102 => {
                alerts.push(Alert {
                    severity: AlertSeverity::Critical,
                    category: "windows-integrity".into(),
                    message: format!(
                        "Security event log cleared (EventID:1102) on {}",
                        if event.computer.is_empty() {
                            "unknown"
                        } else {
                            &event.computer
                        }
                    ),
                    detail: format!(
                        "Anti-forensics indicator — SIGMA detection | {}",
                        event.description
                    ),
                });
            }
            // System log cleared (System channel)
            104 => {
                alerts.push(Alert {
                    severity: AlertSeverity::Warning,
                    category: "windows-integrity".into(),
                    message: format!(
                        "Event log cleared (EventID:104) on {}",
                        if event.computer.is_empty() {
                            "unknown"
                        } else {
                            &event.computer
                        }
                    ),
                    detail: event.description.clone(),
                });
            }
            // Unexpected shutdown / dirty shutdown (no clean shutdown before restart)
            6008 => {
                alerts.push(Alert {
                    severity: AlertSeverity::Warning,
                    category: "windows-integrity".into(),
                    message: format!(
                        "Unexpected shutdown (EventID:6008) on {}",
                        if event.computer.is_empty() {
                            "unknown"
                        } else {
                            &event.computer
                        }
                    ),
                    detail: event.description.clone(),
                });
            }
            // Audit policy changed — potential evidence tampering
            4719 => {
                alerts.push(Alert {
                    severity: AlertSeverity::Warning,
                    category: "windows-integrity".into(),
                    message: format!(
                        "Audit policy changed (EventID:4719) on {}",
                        if event.computer.is_empty() {
                            "unknown"
                        } else {
                            &event.computer
                        }
                    ),
                    detail: event.description.clone(),
                });
            }
            // Boot events
            6005 | 6009 => {
                boot_count += 1;
            }
            // Clean shutdown events
            6006 => {
                shutdown_count += 1;
            }
            _ => {}
        }
    }

    // Rapid boot cycles (same logic as Linux session forensics, but from EVTX)
    if boot_count >= 3 {
        alerts.push(Alert {
            severity: AlertSeverity::Warning,
            category: "windows-integrity".into(),
            message: format!(
                "Rapid boot activity: {boot_count} boot events, {shutdown_count} clean shutdowns"
            ),
            detail: "Multiple reboots may indicate instability, crash loops, or anti-forensics"
                .into(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::super::engine::detect_alerts;
    use super::super::types::AlertInput;
    use super::super::types::AlertSeverity;
    use super::*;

    use issen_parser_uac::parsers::configs::ConfigFile;

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

    fn sysevt(event_id: u64, desc: &str) -> WindowsEvent {
        WindowsEvent {
            event_id,
            channel: "System".into(),
            provider: "EventLog".into(),
            computer: "SERVER01".into(),
            timestamp: 1_700_000_000,
            description: desc.into(),
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

    // --- Linux/macOS environment consistency tests ---

    #[test]
    fn env_vbox_vmware_conflict_warning() {
        let configs = vec![cfg(
            "system/lsmod.txt",
            "Module                  Size  Used by\n\
             vboxguest             123456  2\n\
             vmw_balloon            65536  0\n\
             ext4                  987654  1\n",
        )];
        let input = AlertInput {
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Warning
                && a.category == "environment"
                && a.message.contains("Conflicting hypervisor")),
            "expected VBox+VMware conflict warning, got: {alerts:?}"
        );
    }

    #[test]
    fn env_kvm_hyperv_conflict_warning() {
        let configs = vec![cfg(
            "lsmod",
            "Module                  Size  Used by\n\
             kvm_intel             234567  0\n\
             hv_vmbus               98765  3\n",
        )];
        let input = AlertInput {
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(
                |a| a.category == "environment" && a.message.contains("Conflicting hypervisor")
            ),
            "expected KVM+Hyper-V conflict warning, got: {alerts:?}"
        );
    }

    #[test]
    fn env_single_hypervisor_not_flagged() {
        let configs = vec![cfg(
            "system/lsmod.txt",
            "Module                  Size  Used by\n\
             vboxguest             123456  2\n\
             vboxsf                 45678  1\n\
             ext4                  987654  1\n",
        )];
        let input = AlertInput {
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts
                .iter()
                .any(|a| a.category == "environment" && a.message.contains("Conflicting")),
            "single hypervisor should not trigger conflict, got: {alerts:?}"
        );
    }

    #[test]
    fn env_rootkit_modules_contribute_to_detection() {
        use issen_parser_uac::parsers::rootkit::RootkitSeverity;
        // Rootkit finding provides vboxguest, lsmod provides vmw_balloon
        let findings = vec![RootkitFinding {
            severity: RootkitSeverity::Info,
            check: "kernel_module".into(),
            description: "VBox module".into(),
            evidence: "vboxguest loaded".into(),
        }];
        let configs = vec![cfg(
            "system/lsmod.txt",
            "Module                  Size  Used by\n\
             vmw_balloon            65536  0\n",
        )];
        let input = AlertInput {
            rootkit_findings: &findings,
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(
                |a| a.category == "environment" && a.message.contains("Conflicting hypervisor")
            ),
            "rootkit findings should contribute to hypervisor detection, got: {alerts:?}"
        );
    }

    #[test]
    fn env_dyld_inseissen_libraries_critical() {
        let configs = vec![cfg(
            "system/env_vars.txt",
            "PATH=/usr/bin:/usr/local/bin\n\
             DYLD_INSERT_LIBRARIES=/tmp/evil.dylib\n\
             HOME=/Users/analyst\n",
        )];
        let input = AlertInput {
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Critical
                && a.category == "environment"
                && a.message.contains("DYLD_INSERT_LIBRARIES")),
            "expected DYLD injection critical alert, got: {alerts:?}"
        );
    }

    #[test]
    fn env_clean_environment_not_flagged() {
        let configs = vec![cfg(
            "system/environment",
            "PATH=/usr/bin:/usr/local/bin\n\
             HOME=/Users/analyst\n\
             SHELL=/bin/zsh\n",
        )];
        let input = AlertInput {
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts.iter().any(|a| a.category == "environment"),
            "clean environment should not trigger, got: {alerts:?}"
        );
    }

    #[test]
    fn env_lsmod_header_skipped() {
        // Ensure the header line "Module Size Used by" is not parsed as a module
        let configs = vec![cfg(
            "system/lsmod.txt",
            "Module                  Size  Used by\n\
             ext4                  987654  1\n",
        )];
        let input = AlertInput {
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts
                .iter()
                .any(|a| a.category == "environment" && a.message.contains("Conflicting")),
            "header-only lsmod should not trigger, got: {alerts:?}"
        );
    }

    // --- Windows system integrity tests ---

    #[test]
    fn win_integrity_security_log_cleared_critical() {
        let events = vec![winevt(1102, "The audit log was cleared")];
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Critical
                && a.category == "windows-integrity"
                && a.message.contains("Security event log cleared")
                && a.message.contains("1102")),
            "expected critical for log clearing, got: {alerts:?}"
        );
    }

    #[test]
    fn win_integrity_system_log_cleared_warning() {
        let events = vec![sysevt(104, "The System log was cleared")];
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Warning
                && a.category == "windows-integrity"
                && a.message.contains("Event log cleared")
                && a.message.contains("104")),
            "expected warning for system log clearing, got: {alerts:?}"
        );
    }

    #[test]
    fn win_integrity_unexpected_shutdown_warning() {
        let events = vec![sysevt(6008, "The previous system shutdown was unexpected")];
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Warning
                && a.category == "windows-integrity"
                && a.message.contains("Unexpected shutdown")
                && a.message.contains("6008")),
            "expected unexpected shutdown warning, got: {alerts:?}"
        );
    }

    #[test]
    fn win_integrity_audit_policy_changed_warning() {
        let events = vec![winevt(4719, "System audit policy was changed")];
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Warning
                && a.category == "windows-integrity"
                && a.message.contains("Audit policy changed")
                && a.message.contains("4719")),
            "expected audit policy change warning, got: {alerts:?}"
        );
    }

    #[test]
    fn win_integrity_rapid_boot_cycles_warning() {
        // 3+ boot events trigger rapid boot warning
        let events = vec![
            sysevt(6005, "Event Log service started"),
            sysevt(6006, "Event Log service stopped"),
            sysevt(6005, "Event Log service started"),
            sysevt(6006, "Event Log service stopped"),
            sysevt(6009, "Microsoft Windows boot"),
        ];
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Warning
                && a.category == "windows-integrity"
                && a.message.contains("Rapid boot")),
            "expected rapid boot warning for 3+ boots, got: {alerts:?}"
        );
    }

    #[test]
    fn win_integrity_two_boots_no_rapid_alert() {
        let events = vec![
            sysevt(6005, "Boot 1"),
            sysevt(6006, "Shutdown 1"),
            sysevt(6005, "Boot 2"),
        ];
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts
                .iter()
                .any(|a| a.category == "windows-integrity" && a.message.contains("Rapid boot")),
            "2 boots should not trigger rapid alert, got: {alerts:?}"
        );
    }

    #[test]
    fn win_integrity_empty_events_no_alerts() {
        let input = AlertInput {
            windows_events: &[],
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts.iter().any(|a| a.category.starts_with("windows-")),
            "empty windows events should produce no windows alerts, got: {alerts:?}"
        );
    }

    #[test]
    fn win_integrity_mixed_scenario() {
        // Realistic attack scenario: log clearing + account creation + service install
        let events = vec![
            winevt(1102, "Security log cleared"),
            winevt(4720, "TargetUserName=backdoor"),
            winevt(
                7045,
                "ServiceName=EvilSvc ImagePath=C:\\Users\\Public\\svc.exe",
            ),
            winevt(4625, "Logon failure"),
            winevt(4624, "Logon success"),
        ];
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);

        // Should have: log clearing (critical), account created (warning),
        // service install from suspicious path (critical)
        let windows_alerts: Vec<&Alert> = alerts
            .iter()
            .filter(|a| a.category.starts_with("windows-"))
            .collect();

        assert!(
            windows_alerts
                .iter()
                .any(|a| a.severity == AlertSeverity::Critical
                    && a.message.contains("log cleared")),
            "expected log clearing critical"
        );
        assert!(
            windows_alerts
                .iter()
                .any(|a| a.message.contains("account created")),
            "expected account creation"
        );
        assert!(
            windows_alerts
                .iter()
                .any(|a| a.message.contains("service installed")),
            "expected service install"
        );
        assert!(
            windows_alerts.len() >= 3,
            "expected at least 3 windows alerts, got {}",
            windows_alerts.len()
        );
    }

    #[test]
    fn win_integrity_boot_count_includes_6009() {
        // 6009 is also a boot event (OS version info at startup)
        let events = vec![
            sysevt(6009, "Microsoft Windows 10 boot"),
            sysevt(6009, "Microsoft Windows 10 boot"),
            sysevt(6009, "Microsoft Windows 10 boot"),
        ];
        let input = AlertInput {
            windows_events: &events,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.message.contains("Rapid boot")),
            "6009 events should count as boots, got: {alerts:?}"
        );
    }
}
