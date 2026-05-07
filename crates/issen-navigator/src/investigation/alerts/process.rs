//! Process-related alert detection heuristics.

use issen_parser_uac::parsers::hash_execs::HashedExecutable;
use issen_parser_uac::parsers::network::NetworkConnection;
use issen_parser_uac::parsers::process::ProcessInfo;

use super::types::{Alert, AlertSeverity};

/// Flag processes running from temp directories and reverse shell patterns.
pub(super) fn check_process_alerts(processes: &[ProcessInfo], alerts: &mut Vec<Alert>) {
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

/// Cross-correlate processes with their network connections.
///
/// Detects:
/// - Temp-dir process with active network connection (Critical)
/// - Connection PID not found in process list — hidden process (Warning)
///
/// When a match is found, the alert detail is enriched with the executable
/// hash if available in `hashes`.
pub(super) fn check_process_network_correlation(
    processes: &[ProcessInfo],
    network: &[NetworkConnection],
    hashes: &[HashedExecutable],
    alerts: &mut Vec<Alert>,
) {
    let temp_prefixes = ["/tmp/", "/dev/shm/", "/var/tmp/"];
    let active_states = ["ESTAB", "LISTEN", "SYN"];

    for conn in network {
        let Some(pid) = conn.pid else { continue };

        let state_upper = conn.state.to_uppercase();
        let is_active = active_states.iter().any(|s| state_upper.contains(s));
        if !is_active {
            continue;
        }

        match processes.iter().find(|p| p.pid == pid) {
            Some(proc) => {
                let cmd = proc.command.as_str();
                // Check if the process executable is in a temp directory
                for prefix in &temp_prefixes {
                    if cmd.starts_with(prefix) || cmd.contains(&format!(" {prefix}")) {
                        let exe_path = cmd.split_whitespace().next().unwrap_or(cmd);
                        let hash_info = hashes
                            .iter()
                            .find(|h| h.path == exe_path)
                            .map(|h| format!(" | {}={}", h.algorithm, h.hash))
                            .unwrap_or_default();

                        alerts.push(Alert {
                            severity: AlertSeverity::Critical,
                            category: "correlation".into(),
                            message: format!(
                                "Temp-dir process with active network connection ({prefix})"
                            ),
                            detail: format!(
                                "pid={pid} cmd={cmd} local={} remote={} state={}{}",
                                conn.local_addr, conn.remote_addr, conn.state, hash_info
                            ),
                        });
                        break;
                    }
                }
            }
            None => {
                // PID from connection not in process list — possible hidden process
                alerts.push(Alert {
                    severity: AlertSeverity::Warning,
                    category: "correlation".into(),
                    message: format!(
                        "Connection PID {pid} not in process list (possible hidden process)"
                    ),
                    detail: format!(
                        "pid={pid} proto={} local={} remote={} state={}",
                        conn.protocol, conn.local_addr, conn.remote_addr, conn.state
                    ),
                });
            }
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

    #[test]
    fn temp_process_with_network_connection_critical() {
        let procs = vec![ProcessInfo {
            pid: 1234,
            ppid: 1,
            user: "www-data".into(),
            command: "/tmp/beacon".into(),
            cpu_pct: None,
            mem_pct: None,
            staissen_time: None,
        }];
        let conns = vec![NetworkConnection {
            protocol: "tcp".into(),
            local_addr: "192.168.1.10:45678".into(),
            remote_addr: "10.0.0.5:443".into(),
            state: "ESTAB".into(),
            pid: Some(1234),
            program: Some("/tmp/beacon".into()),
        }];
        let input = AlertInput {
            processes: &procs,
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Critical
                && a.category == "correlation"
                && a.message.contains("/tmp/")),
            "expected critical correlation alert for temp process with network, got: {alerts:?}"
        );
    }

    #[test]
    fn temp_process_with_network_includes_hash_enrichment() {
        let procs = vec![ProcessInfo {
            pid: 42,
            ppid: 1,
            user: "nobody".into(),
            command: "/dev/shm/.hidden".into(),
            cpu_pct: None,
            mem_pct: None,
            staissen_time: None,
        }];
        let conns = vec![NetworkConnection {
            protocol: "tcp".into(),
            local_addr: "0.0.0.0:9999".into(),
            remote_addr: "0.0.0.0:*".into(),
            state: "LISTEN".into(),
            pid: Some(42),
            program: Some(".hidden".into()),
        }];
        let hashes = vec![HashedExecutable {
            hash: "deadbeefcafe1234".into(),
            path: "/dev/shm/.hidden".into(),
            algorithm: "md5".into(),
        }];
        let input = AlertInput {
            processes: &procs,
            network: &conns,
            hashes: &hashes,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        let corr: Vec<_> = alerts
            .iter()
            .filter(|a| a.category == "correlation" && a.message.contains("/dev/shm/"))
            .collect();
        assert!(!corr.is_empty(), "expected correlation alert");
        assert!(
            corr[0].detail.contains("deadbeefcafe1234"),
            "expected hash in detail, got: {}",
            corr[0].detail
        );
    }

    #[test]
    fn connection_pid_not_in_process_list_flagged() {
        let procs = vec![ProcessInfo {
            pid: 1,
            ppid: 0,
            user: "root".into(),
            command: "/sbin/init".into(),
            cpu_pct: None,
            mem_pct: None,
            staissen_time: None,
        }];
        let conns = vec![NetworkConnection {
            protocol: "tcp".into(),
            local_addr: "0.0.0.0:4444".into(),
            remote_addr: "0.0.0.0:*".into(),
            state: "LISTEN".into(),
            pid: Some(9999),
            program: None,
        }];
        let input = AlertInput {
            processes: &procs,
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.category == "correlation" && a.detail.contains("9999")),
            "expected alert for PID not in process list, got: {alerts:?}"
        );
    }

    #[test]
    fn normal_system_process_with_connection_no_correlation_alert() {
        let procs = vec![ProcessInfo {
            pid: 100,
            ppid: 1,
            user: "root".into(),
            command: "/usr/sbin/sshd".into(),
            cpu_pct: None,
            mem_pct: None,
            staissen_time: None,
        }];
        let conns = vec![NetworkConnection {
            protocol: "tcp".into(),
            local_addr: "0.0.0.0:22".into(),
            remote_addr: "0.0.0.0:*".into(),
            state: "LISTEN".into(),
            pid: Some(100),
            program: Some("sshd".into()),
        }];
        let input = AlertInput {
            processes: &procs,
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts
                .iter()
                .any(|a| a.category == "correlation" && a.message.contains("sshd")),
            "should not flag normal sshd, got: {alerts:?}"
        );
    }
}
