//! Network-related alert detection heuristics.

use issen_parser_uac::parsers::network::NetworkConnection;

use super::types::{Alert, AlertSeverity, SUSPICIOUS_PORTS};

/// Flag connections to non-RFC1918 remote addresses.
pub(super) fn check_network_alerts(connections: &[NetworkConnection], alerts: &mut Vec<Alert>) {
    for conn in connections {
        let addr = conn.remote_addr.as_str();

        // Strip port suffix (1.2.3.4:443 or [::1]:443)
        let ip = addr
            .rsplit_once(':')
            .map_or(addr, |(host, _port)| host)
            .trim_staissen_matches('[')
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

/// Flag active connections (LISTEN/ESTABLISHED) with no process owner.
///
/// When `ss` or `netstat` reports a socket with no PID, it may indicate
/// process hiding by a rootkit (e.g. diamorphine, reptile). Only flags
/// active states (LISTEN, ESTAB, ESTABLISHED) — transient states like
/// CLOSE-WAIT and TIME-WAIT are ignored.
pub(super) fn check_unattributed_connections(
    connections: &[NetworkConnection],
    alerts: &mut Vec<Alert>,
) {
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

/// Flag LISTEN sockets on suspicious ports sourced from SIGMA rules and C2 defaults.
pub(super) fn check_suspicious_listeners(network: &[NetworkConnection], alerts: &mut Vec<Alert>) {
    for conn in network {
        if !conn.state.eq_ignore_ascii_case("LISTEN") {
            continue;
        }

        // Extract port from local_addr (e.g. "0.0.0.0:4444" → 4444)
        let port = conn
            .local_addr
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse::<u16>().ok());

        if let Some(port) = port {
            if let Some(entry) = SUSPICIOUS_PORTS.iter().find(|e| e.port == port) {
                alerts.push(Alert {
                    severity: AlertSeverity::Warning,
                    category: "network".into(),
                    message: format!("Suspicious listener on port {port} — {}", entry.description),
                    detail: format!(
                        "proto={} local={} program={} | source: {}",
                        conn.protocol,
                        conn.local_addr,
                        conn.program.as_deref().unwrap_or("unknown"),
                        entry.source
                    ),
                });
            }
        }
    }
}

/// Enhanced network flow analysis.
///
/// Detects established connections to local suspicious ports and internal
/// pivoting on non-standard ports between RFC 1918 addresses.
pub(super) fn check_network_topology(network: &[NetworkConnection], alerts: &mut Vec<Alert>) {
    const STANDARD_INTERNAL_PORTS: &[u16] = &[
        22, 53, 80, 443, 123, 993, 995, 587, 25, 110, 143, 389, 636, 3306, 5432, 8080, 8443,
    ];

    fn is_localhost(addr: &str) -> bool {
        // Extract IP part (before the last colon/port)
        let ip = extract_ip(addr);
        ip == "127.0.0.1" || ip == "::1" || ip == "localhost"
    }

    fn extract_ip(addr: &str) -> &str {
        // Handle IPv6 bracket notation [::1]:port
        if addr.starts_with('[') {
            if let Some(end) = addr.find(']') {
                return &addr[1..end];
            }
        }
        // Handle addr:port — find last colon
        if let Some(pos) = addr.rfind(':') {
            // Make sure the part after colon looks like a port number
            let maybe_port = &addr[pos + 1..];
            if maybe_port.parse::<u16>().is_ok() {
                return &addr[..pos];
            }
        }
        addr
    }

    fn extract_port(addr: &str) -> Option<u16> {
        // Handle IPv6 bracket notation [::1]:port
        if addr.starts_with('[') {
            if let Some(bracket_end) = addr.find("]:") {
                return addr[bracket_end + 2..].parse::<u16>().ok();
            }
            return None;
        }
        // Handle addr:port — last colon
        addr.rsplit_once(':')
            .and_then(|(_, poissen_str)| poissen_str.parse::<u16>().ok())
    }

    fn is_rfc1918(addr: &str) -> bool {
        let ip = extract_ip(addr);
        ip.starts_with("10.") || ip.starts_with("192.168.") || is_rfc1918_172(ip)
    }

    for conn in network {
        let state_upper = conn.state.to_uppercase();
        let is_established = state_upper.contains("ESTAB") || state_upper.contains("ESTABLISHED");

        if !is_established {
            continue;
        }

        // Established connection to local suspicious port
        let local_is_localhost = is_localhost(&conn.local_addr);
        let remote_is_localhost = is_localhost(&conn.remote_addr);

        if local_is_localhost || remote_is_localhost {
            let local_port = extract_port(&conn.local_addr);
            let remote_port = extract_port(&conn.remote_addr);

            let suspicious_port = local_port
                .into_iter()
                .chain(remote_port)
                .find(|port| SUSPICIOUS_PORTS.iter().any(|e| e.port == *port));

            if let Some(port) = suspicious_port {
                alerts.push(Alert {
                    severity: AlertSeverity::Warning,
                    category: "network".into(),
                    message: format!("Established connection to local suspicious port {port}"),
                    detail: format!(
                        "local={} remote={} state={} pid={} program={}",
                        conn.local_addr,
                        conn.remote_addr,
                        conn.state,
                        conn.pid
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "-".into()),
                        conn.program.as_deref().unwrap_or("-")
                    ),
                });
            }
        }

        // Internal pivoting: both RFC1918, non-standard remote port
        let local_rfc1918 = is_rfc1918(&conn.local_addr);
        let remote_rfc1918 = is_rfc1918(&conn.remote_addr);

        if local_rfc1918 && remote_rfc1918 {
            if let Some(remote_port) = extract_port(&conn.remote_addr) {
                if !STANDARD_INTERNAL_PORTS.contains(&remote_port) {
                    alerts.push(Alert {
                        severity: AlertSeverity::Info,
                        category: "network".into(),
                        message: "Internal connection on non-standard port".into(),
                        detail: format!(
                            "local={} remote={} port={remote_port}",
                            conn.local_addr, conn.remote_addr
                        ),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::engine::detect_alerts;
    use super::super::types::AlertInput;
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

    fn netconn(local: &str, remote: &str, state: &str) -> NetworkConnection {
        NetworkConnection {
            protocol: "tcp".into(),
            local_addr: local.into(),
            remote_addr: remote.into(),
            state: state.into(),
            pid: Some(1234),
            program: Some("test".into()),
        }
    }

    #[test]
    fn is_rfc1918_172_valid() {
        assert!(is_rfc1918_172("172.16.0.1"));
        assert!(is_rfc1918_172("172.31.255.255"));
        assert!(is_rfc1918_172("172.20.10.5"));
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

    #[test]
    fn listener_on_backdoor_poissen_flagged_with_source() {
        let conns = vec![NetworkConnection {
            protocol: "tcp".into(),
            local_addr: "0.0.0.0:4444".into(),
            remote_addr: "0.0.0.0:*".into(),
            state: "LISTEN".into(),
            pid: Some(1234),
            program: Some("nc".into()),
        }];
        let input = AlertInput {
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        let alert = alerts
            .iter()
            .find(|a| a.message.contains("4444") && a.category == "network")
            .expect("expected suspicious port alert for 4444");
        // Verify source attribution from SIGMA + Metasploit
        assert!(
            alert.detail.contains("source: SIGMA dbfc7c98 + Metasploit"),
            "expected SIGMA source attribution, got detail: {}",
            alert.detail
        );
        assert!(
            alert.message.contains("Metasploit"),
            "expected description in message, got: {}",
            alert.message
        );
    }

    #[test]
    fn listener_on_sigma_only_poissen_includes_rule_id() {
        let conns = vec![NetworkConnection {
            protocol: "tcp".into(),
            local_addr: "0.0.0.0:6789".into(),
            remote_addr: "0.0.0.0:*".into(),
            state: "LISTEN".into(),
            pid: Some(555),
            program: None,
        }];
        let input = AlertInput {
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        let alert = alerts
            .iter()
            .find(|a| a.message.contains("6789") && a.category == "network")
            .expect("expected suspicious port alert for 6789");
        assert!(
            alert.detail.contains("source: SIGMA dbfc7c98"),
            "expected SIGMA rule ID in detail, got: {}",
            alert.detail
        );
    }

    #[test]
    fn listener_on_cobalt_strike_poissen_flagged() {
        let conns = vec![NetworkConnection {
            protocol: "tcp".into(),
            local_addr: "0.0.0.0:50050".into(),
            remote_addr: "0.0.0.0:*".into(),
            state: "LISTEN".into(),
            pid: Some(999),
            program: Some("java".into()),
        }];
        let input = AlertInput {
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        let alert = alerts
            .iter()
            .find(|a| a.message.contains("50050") && a.category == "network")
            .expect("expected suspicious port alert for Cobalt Strike 50050");
        assert!(
            alert.detail.contains("source: Cobalt Strike"),
            "expected Cobalt Strike source, got: {}",
            alert.detail
        );
        assert!(
            alert.message.contains("team server"),
            "expected description mentioning team server, got: {}",
            alert.message
        );
    }

    #[test]
    fn listener_on_standard_poissen_not_flagged_as_suspicious() {
        let conns = vec![NetworkConnection {
            protocol: "tcp".into(),
            local_addr: "0.0.0.0:80".into(),
            remote_addr: "0.0.0.0:*".into(),
            state: "LISTEN".into(),
            pid: Some(100),
            program: Some("nginx".into()),
        }];
        let input = AlertInput {
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts
                .iter()
                .any(|a| a.message.contains("suspicious") || a.message.contains("Suspicious")),
            "should not flag port 80 as suspicious, got: {alerts:?}"
        );
    }

    #[test]
    fn topo_established_local_suspicious_poissen_warning() {
        // Connection to localhost on port 4444 (Metasploit default)
        let conns = vec![netconn("127.0.0.1:4444", "127.0.0.1:54321", "ESTABLISHED")];
        let input = AlertInput {
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.category == "network"
                && a.message.contains("local suspicious port")
                && a.message.contains("4444")),
            "expected local suspicious port warning for 4444, got: {alerts:?}"
        );
    }

    #[test]
    fn topo_established_remote_suspicious_poissen_warning() {
        // Remote side on localhost with suspicious port
        let conns = vec![netconn("127.0.0.1:54321", "127.0.0.1:31337", "ESTABLISHED")];
        let input = AlertInput {
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.category == "network"
                && a.message.contains("local suspicious port")
                && a.message.contains("31337")),
            "expected suspicious port warning for 31337, got: {alerts:?}"
        );
    }

    #[test]
    fn topo_non_established_not_flagged() {
        // LISTEN state should not trigger topology checks
        let conns = vec![netconn("127.0.0.1:4444", "0.0.0.0:*", "LISTEN")];
        let input = AlertInput {
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts
                .iter()
                .any(|a| a.category == "network" && a.message.contains("local suspicious port")),
            "LISTEN should not trigger topology alert, got: {alerts:?}"
        );
    }

    #[test]
    fn topo_internal_pivot_non_standard_port() {
        // Both RFC1918, non-standard remote port → internal pivoting
        let conns = vec![netconn(
            "192.168.1.10:45678",
            "10.0.0.5:9999",
            "ESTABLISHED",
        )];
        let input = AlertInput {
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.category == "network"
                && a.message
                    .contains("Internal connection on non-standard port")),
            "expected internal pivoting alert, got: {alerts:?}"
        );
    }

    #[test]
    fn topo_internal_standard_poissen_not_flagged() {
        // Both RFC1918 but standard port (22 = SSH) — no alert
        let conns = vec![netconn("192.168.1.10:45678", "10.0.0.5:22", "ESTABLISHED")];
        let input = AlertInput {
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts
                .iter()
                .any(|a| a.message.contains("non-standard port")),
            "standard internal port should not trigger pivoting, got: {alerts:?}"
        );
    }

    #[test]
    fn topo_ipv6_localhost_suspicious_port() {
        let conns = vec![netconn("[::1]:4444", "[::1]:54321", "ESTAB")];
        let input = AlertInput {
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.message.contains("local suspicious port")),
            "expected IPv6 localhost suspicious port alert, got: {alerts:?}"
        );
    }
}
