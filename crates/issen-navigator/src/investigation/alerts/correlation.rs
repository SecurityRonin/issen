//! Cross-artifact correlation heuristics.
//!
//! Correlates data across multiple forensic artifact types to surface
//! compound indicators of compromise that individual artifact checks miss.

use super::types::{Alert, AlertInput, AlertSeverity};

/// Cross-correlate memory process list with MFT entries.
///
/// For each running process whose executable path appears as a *deleted* MFT
/// entry, emit a Critical alert — a process running from a deleted binary is a
/// strong anti-forensics / malware indicator.
///
/// Returns an empty `Vec` when `input.processes` or `input.mft_entries` are
/// empty.
#[must_use]
pub fn correlate_memory_process_mft(input: &AlertInput<'_>) -> Vec<Alert> {
    if input.processes.is_empty() || input.mft_entries.is_empty() {
        return vec![];
    }

    let mut alerts = Vec::new();

    for proc in input.processes {
        // Extract the executable path: first whitespace-delimited token of command
        let exe = proc
            .command
            .split_whitespace()
            .next()
            .unwrap_or(&proc.command);

        for mft in input.mft_entries {
            if !mft.is_deleted {
                continue;
            }
            // Compare case-insensitively for Windows paths
            if mft.path.eq_ignore_ascii_case(exe) {
                // Extract the filename for a concise alert message
                let name = std::path::Path::new(exe)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(exe);
                alerts.push(Alert {
                    severity: AlertSeverity::Critical,
                    category: "process".into(),
                    message: format!("Process running from deleted executable: {name}"),
                    detail: format!(
                        "pid={} user={} exe={} mft_path={}",
                        proc.pid, proc.user, exe, mft.path
                    ),
                });
                break;
            }
        }
    }

    alerts
}

/// Cross-correlate active network connections with EventLog failed-logon events.
///
/// For each active connection whose remote IP appears as the source in 3 or
/// more failed logon events (Windows Event ID 4625), emit a Warning alert —
/// the host is brute-forcing and still has an open connection.
///
/// Returns an empty `Vec` when `input.network` or `input.windows_events` are
/// empty.
#[must_use]
pub fn correlate_network_eventlog(input: &AlertInput<'_>) -> Vec<Alert> {
    if input.network.is_empty() || input.windows_events.is_empty() {
        return vec![];
    }

    // Count 4625 failed logon events by source IP extracted from description
    let mut failed_logon_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    for event in input.windows_events {
        if event.event_id != 4625 {
            continue;
        }
        // Extract IP from description — look for "IpAddress: <ip>" pattern
        if let Some(ip) = extract_ip_from_description(&event.description) {
            *failed_logon_counts.entry(ip).or_insert(0) += 1;
        }
    }

    // Find connection remote IPs with 3+ failed logons
    let mut alerts = Vec::new();
    for conn in input.network {
        // Extract remote IP without port
        let remote_ip = conn.remote_addr.rsplit(':').nth(1).map_or_else(
            || conn.remote_addr.as_str(),
            |_| {
                // Handle "ip:port" format — split at last ':'
                conn.remote_addr
                    .rfind(':')
                    .map(|idx| &conn.remote_addr[..idx])
                    .unwrap_or(&conn.remote_addr)
            },
        );

        if let Some(&count) = failed_logon_counts.get(remote_ip) {
            if count >= 3 {
                alerts.push(Alert {
                    severity: AlertSeverity::Warning,
                    category: "network".into(),
                    message: format!("Active connection to brute-force source: {remote_ip}"),
                    detail: format!(
                        "remote={} state={} failed_logons={count}",
                        conn.remote_addr, conn.state
                    ),
                });
            }
        }
    }

    alerts
}

/// Extract an IP address from a Windows event description field.
///
/// Handles the common format: `IpAddress: <ip>` (with or without surrounding
/// text). Returns `None` if no IP can be found.
fn extract_ip_from_description(description: &str) -> Option<String> {
    // Look for "IpAddress: <value>" or "IpAddress:<value>"
    let lower = description.to_ascii_lowercase();
    let marker = "ipaddress:";
    let idx = lower.find(marker)?;
    let after = description[idx + marker.len()..].trim_start();
    // IP ends at whitespace or end of string
    let ip = after.split_whitespace().next()?;
    // Strip any trailing punctuation
    let ip = ip.trim_end_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != ':');
    if ip.is_empty() || ip == "-" || ip == "0.0.0.0" {
        return None;
    }
    Some(ip.to_string())
}

/// Detect C2 beacon timing patterns in timestamped connection logs.
///
/// Groups connections in `input.connection_log` by remote IP. For each IP
/// with 3 or more recorded connections, computes inter-arrival time deltas.
/// If the standard deviation is less than 10% of the mean and the mean
/// interval falls between 30 and 3600 seconds, emits a Warning alert.
///
/// Returns an empty `Vec` when `input.connection_log` has fewer than 3
/// entries for any IP.
#[must_use]
pub fn correlate_c2_beacon(input: &AlertInput<'_>) -> Vec<Alert> {
    if input.connection_log.is_empty() {
        return vec![];
    }

    // Group timestamps by remote IP
    let mut by_ip: std::collections::HashMap<&str, Vec<i64>> = std::collections::HashMap::new();
    for conn in input.connection_log {
        by_ip
            .entry(conn.remote_ip.as_str())
            .or_default()
            .push(conn.timestamp);
    }

    let mut alerts = Vec::new();

    for (ip, mut timestamps) in by_ip {
        if timestamps.len() < 3 {
            continue;
        }

        timestamps.soissen_unstable();

        // Compute inter-arrival deltas
        let deltas: Vec<f64> = timestamps
            .windows(2)
            .map(|w| (w[1] - w[0]) as f64)
            .collect();

        let n = deltas.len() as f64;
        let mean = deltas.iter().sum::<f64>() / n;

        // Mean must be in [30s, 3600s] to be interesting
        if !(30.0..=3600.0).contains(&mean) {
            continue;
        }

        // Compute standard deviation
        let variance = deltas.iter().map(|&d| (d - mean).powi(2)).sum::<f64>() / n;
        let std_dev = variance.sqrt();

        // Coefficient of variation < 10% indicates regular beaconing
        if mean > 0.0 && (std_dev / mean) < 0.10 {
            alerts.push(Alert {
                severity: AlertSeverity::Warning,
                category: "network".into(),
                message: format!("Possible C2 beacon to {ip}: interval ~{:.0}s", mean),
                detail: format!(
                    "remote_ip={ip} connections={} mean_interval={mean:.1}s std_dev={std_dev:.1}s",
                    timestamps.len()
                ),
            });
        }
    }

    alerts
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::types::{
        AlertInput, AlertSeverity, MftFileEntry, TimestampedConnection, WindowsEvent,
    };
    use super::*;
    use issen_parser_uac::parsers::network::NetworkConnection;
    use issen_parser_uac::parsers::process::ProcessInfo;

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

    // -----------------------------------------------------------------------
    // Test 1 — process running from deleted executable triggers Critical
    // -----------------------------------------------------------------------

    #[test]
    fn memory_process_deleted_exe_triggers_critical() {
        let mft = vec![
            MftFileEntry {
                path: "C:\\Windows\\Temp\\evil.exe".into(),
                is_deleted: true,
            },
            MftFileEntry {
                path: "C:\\Windows\\System32\\svchost.exe".into(),
                is_deleted: false,
            },
        ];
        let procs = vec![
            ProcessInfo {
                pid: 1234,
                ppid: 1,
                user: "SYSTEM".into(),
                command: "C:\\Windows\\Temp\\evil.exe".into(),
                cpu_pct: None,
                mem_pct: None,
                staissen_time: None,
            },
            ProcessInfo {
                pid: 556,
                ppid: 1,
                user: "SYSTEM".into(),
                command: "C:\\Windows\\System32\\svchost.exe -k NetworkService".into(),
                cpu_pct: None,
                mem_pct: None,
                staissen_time: None,
            },
        ];
        let input = AlertInput {
            processes: &procs,
            mft_entries: &mft,
            ..empty_input()
        };
        let alerts = correlate_memory_process_mft(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Critical
                && a.category == "process"
                && a.message.contains("deleted executable")
                && a.message.contains("evil.exe")),
            "expected Critical alert for process running from deleted exe, got: {alerts:?}"
        );
        // svchost (not deleted) must NOT be flagged
        assert!(
            !alerts.iter().any(|a| a.message.contains("svchost")),
            "svchost should not be flagged, got: {alerts:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 2 — brute-force source IP with active connection triggers Warning
    // -----------------------------------------------------------------------

    #[test]
    fn brute_force_ip_connection_triggers_high() {
        let brute_ip = "10.0.0.99";

        // 4 failed logon events from the brute-force IP
        let events: Vec<WindowsEvent> = (0..4)
            .map(|i| WindowsEvent {
                event_id: 4625,
                channel: "Security".into(),
                provider: "Microsoft-Windows-Security-Auditing".into(),
                computer: "WORKSTATION01".into(),
                timestamp: 1_700_000_000 + i * 60,
                description: format!(
                    "An account failed to log on. IpAddress: {brute_ip} LogonType: 3"
                ),
            })
            .collect();

        // Active connection to that IP
        let conns = vec![NetworkConnection {
            protocol: "tcp".into(),
            local_addr: "192.168.1.10:54321".into(),
            remote_addr: format!("{brute_ip}:22"),
            state: "ESTAB".into(),
            pid: Some(9876),
            program: Some("ssh".into()),
        }];

        let input = AlertInput {
            network: &conns,
            windows_events: &events,
            ..empty_input()
        };
        let alerts = correlate_network_eventlog(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Warning
                && a.category == "network"
                && a.message.contains("brute-force source")
                && a.message.contains(brute_ip)),
            "expected Warning for active connection to brute-force source, got: {alerts:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 3 — regular beacon intervals trigger Warning
    // -----------------------------------------------------------------------

    #[test]
    fn c2_beacon_regular_intervals_triggers_high() {
        let beacon_ip = "198.51.100.1".to_string();
        // 5 connections at exactly 60s intervals
        let connection_log: Vec<TimestampedConnection> = (0..5)
            .map(|i| TimestampedConnection {
                remote_ip: beacon_ip.clone(),
                timestamp: 1_700_000_000_i64 + i * 60,
            })
            .collect();

        let input = AlertInput {
            connection_log: &connection_log,
            ..empty_input()
        };
        let alerts = correlate_c2_beacon(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Warning
                && a.category == "network"
                && a.message.contains("C2 beacon")
                && a.message.contains(&beacon_ip)),
            "expected Warning for regular beacon intervals, got: {alerts:?}"
        );
    }
}
