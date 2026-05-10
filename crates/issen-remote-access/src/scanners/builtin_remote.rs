use std::collections::HashMap;

use crate::model::{
    DetectionSource, Finding, HitArtifactType, RawArtifactHit, RemoteAccessCategory,
};
use crate::providers::{ArtifactProvider, EventLogQuery};
use crate::scanners::{CategoryScanner, ScanError};

/// Scanner for built-in remote access tools: RDP and SSH.
///
/// Checks RDP configuration risk (enabled, NLA disabled, non-standard port,
/// logon events) and SSH service/config presence.
pub struct BuiltinRemoteScanner;

impl BuiltinRemoteScanner {
    /// Create a new `BuiltinRemoteScanner`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Check RDP configuration and logon activity.
    ///
    /// Examines:
    /// - `fDenyTSConnections=0` -> RDP enabled
    /// - `SecurityLayer=0` -> NLA disabled (high risk)
    /// - `PortNumber != 3389` -> non-standard port
    /// - Event 4624 with `LogonType=10` -> RDP logon events
    fn scan_rdp(&self, provider: &dyn ArtifactProvider) -> Vec<RawArtifactHit> {
        let mut hits = Vec::new();

        // Check fDenyTSConnections (RDP enabled when 0)
        let ts_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server";
        if let Ok(values) = provider.registry_values(ts_path) {
            for entry in &values {
                if entry.name == "fDenyTSConnections" && entry.value == "0" {
                    hits.push(RawArtifactHit {
                        artifact_type: HitArtifactType::RegistryValue,
                        source_path: ts_path.to_owned(),
                        value: "fDenyTSConnections=0 (RDP enabled)".into(),
                        timestamp: entry.timestamp,
                        context: HashMap::from([
                            ("name".into(), entry.name.clone()),
                            ("value".into(), entry.value.clone()),
                        ]),
                    });
                }
            }
        }

        // Check SecurityLayer (NLA disabled when 0)
        let rdp_tcp_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
        if let Ok(values) = provider.registry_values(rdp_tcp_path) {
            for entry in &values {
                if entry.name == "SecurityLayer" && entry.value == "0" {
                    hits.push(RawArtifactHit {
                        artifact_type: HitArtifactType::RegistryValue,
                        source_path: rdp_tcp_path.to_owned(),
                        value: "SecurityLayer=0 (NLA disabled — high risk)".into(),
                        timestamp: entry.timestamp,
                        context: HashMap::from([
                            ("name".into(), entry.name.clone()),
                            ("value".into(), entry.value.clone()),
                            ("risk".into(), "high".into()),
                        ]),
                    });
                }

                // Check for non-standard port
                if entry.name == "PortNumber" && entry.value != "3389" {
                    hits.push(RawArtifactHit {
                        artifact_type: HitArtifactType::RegistryValue,
                        source_path: rdp_tcp_path.to_owned(),
                        value: format!("PortNumber={} (non-standard RDP port)", entry.value),
                        timestamp: entry.timestamp,
                        context: HashMap::from([
                            ("name".into(), entry.name.clone()),
                            ("value".into(), entry.value.clone()),
                        ]),
                    });
                }
            }
        }

        // Check for RDP logon events (Event 4624 with LogonType=10)
        let query = EventLogQuery {
            event_id: Some(4624),
            provider_name: None,
            log_file: Some("Security".into()),
            keyword: None,
        };
        if let Ok(events) = provider.event_log_search(&query) {
            for event in &events {
                let logon_type = event
                    .data
                    .get("LogonType")
                    .map(String::as_str)
                    .unwrap_or("unknown");
                if logon_type == "10" {
                    let source_ip = event
                        .data
                        .get("IpAddress")
                        .map(String::as_str)
                        .unwrap_or("unknown");
                    let target_user = event
                        .data
                        .get("TargetUserName")
                        .map(String::as_str)
                        .unwrap_or("unknown");
                    hits.push(RawArtifactHit {
                        artifact_type: HitArtifactType::EventLog,
                        source_path: "Security".into(),
                        value: format!(
                            "Event 4624 LogonType=10 (RDP) from {source_ip} as {target_user}"
                        ),
                        timestamp: event.timestamp,
                        context: HashMap::from([
                            ("event_id".into(), "4624".into()),
                            ("logon_type".into(), "10".into()),
                            ("source_ip".into(), source_ip.to_owned()),
                            ("target_user".into(), target_user.to_owned()),
                        ]),
                    });
                }
            }
        }

        hits
    }

    /// Check for SSH server presence.
    ///
    /// Examines:
    /// - Services list for sshd / OpenSSH
    /// - File presence of sshd_config
    fn scan_ssh(&self, provider: &dyn ArtifactProvider) -> Vec<RawArtifactHit> {
        let mut hits = Vec::new();

        // Check for sshd service
        if let Ok(services) = provider.services() {
            for svc in &services {
                let name_lower = svc.name.to_lowercase();
                let display_lower = svc.display_name.to_lowercase();
                if name_lower.contains("sshd")
                    || name_lower.contains("openssh")
                    || display_lower.contains("sshd")
                    || display_lower.contains("openssh")
                {
                    hits.push(RawArtifactHit {
                        artifact_type: HitArtifactType::Service,
                        source_path: format!("services/{}", svc.name),
                        value: format!("SSH service: {} ({})", svc.display_name, svc.name),
                        timestamp: None,
                        context: HashMap::from([
                            ("service_name".into(), svc.name.clone()),
                            ("display_name".into(), svc.display_name.clone()),
                            ("image_path".into(), svc.image_path.clone()),
                            ("start_type".into(), svc.start_type.to_string()),
                        ]),
                    });
                }
            }
        }

        // Check for sshd_config file
        if let Ok(files) = provider.file_exists("*sshd_config*") {
            for file in &files {
                hits.push(RawArtifactHit {
                    artifact_type: HitArtifactType::FilePresence,
                    source_path: file.path.clone(),
                    value: "sshd_config found".into(),
                    timestamp: file.modified,
                    context: HashMap::new(),
                });
            }
        }

        hits
    }
}

impl Default for BuiltinRemoteScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CategoryScanner for BuiltinRemoteScanner {
    fn category(&self) -> RemoteAccessCategory {
        RemoteAccessCategory::BuiltInRemoteAccess
    }

    fn scan(&self, provider: &dyn ArtifactProvider) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();

        // Scan RDP
        let rdp_hits = self.scan_rdp(provider);
        if !rdp_hits.is_empty() {
            let first_seen = rdp_hits.iter().filter_map(|h| h.timestamp).min();
            let last_seen = rdp_hits.iter().filter_map(|h| h.timestamp).max();
            findings.push(Finding {
                id: uuid::Uuid::new_v4().to_string(),
                tool_name: "RDP".into(),
                category: RemoteAccessCategory::BuiltInRemoteAccess,
                artifacts: rdp_hits,
                first_seen,
                last_seen,
                detection_source: DetectionSource::CategoryScanner("builtin_remote".into()),
            });
        }

        // Scan SSH
        let ssh_hits = self.scan_ssh(provider);
        if !ssh_hits.is_empty() {
            let first_seen = ssh_hits.iter().filter_map(|h| h.timestamp).min();
            let last_seen = ssh_hits.iter().filter_map(|h| h.timestamp).max();
            findings.push(Finding {
                id: uuid::Uuid::new_v4().to_string(),
                tool_name: "SSH".into(),
                category: RemoteAccessCategory::BuiltInRemoteAccess,
                artifacts: ssh_hits,
                first_seen,
                last_seen,
                detection_source: DetectionSource::CategoryScanner("builtin_remote".into()),
            });
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{
        EventLogEntry, MockArtifactProvider, ProviderCapability, RegistryEntry, ServiceEntry,
    };

    #[test]
    fn test_rdp_enabled_detected() {
        let mut mock = MockArtifactProvider {
            caps: vec![
                ProviderCapability::RegistryKeys,
                ProviderCapability::EventLogs,
            ],
            ..MockArtifactProvider::default()
        };
        mock.add_registry_value(
            r"SYSTEM\CurrentControlSet\Control\Terminal Server",
            RegistryEntry {
                path: r"SYSTEM\CurrentControlSet\Control\Terminal Server".into(),
                name: "fDenyTSConnections".into(),
                value: "0".into(),
                data_type: "REG_DWORD".into(),
                timestamp: None,
            },
        );

        let scanner = BuiltinRemoteScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool_name, "RDP");
        assert_eq!(
            findings[0].category,
            RemoteAccessCategory::BuiltInRemoteAccess
        );
        assert_eq!(
            findings[0].detection_source,
            DetectionSource::CategoryScanner("builtin_remote".into())
        );
        assert!(!findings[0].artifacts.is_empty());
    }

    #[test]
    fn test_rdp_nla_disabled() {
        let mut mock = MockArtifactProvider {
            caps: vec![
                ProviderCapability::RegistryKeys,
                ProviderCapability::EventLogs,
            ],
            ..MockArtifactProvider::default()
        };
        // RDP enabled
        mock.add_registry_value(
            r"SYSTEM\CurrentControlSet\Control\Terminal Server",
            RegistryEntry {
                path: r"SYSTEM\CurrentControlSet\Control\Terminal Server".into(),
                name: "fDenyTSConnections".into(),
                value: "0".into(),
                data_type: "REG_DWORD".into(),
                timestamp: None,
            },
        );
        // NLA disabled
        mock.add_registry_value(
            r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            RegistryEntry {
                path: r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
                    .into(),
                name: "SecurityLayer".into(),
                value: "0".into(),
                data_type: "REG_DWORD".into(),
                timestamp: None,
            },
        );

        let scanner = BuiltinRemoteScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool_name, "RDP");
        // Should have at least 2 artifacts (RDP enabled + NLA disabled).
        assert!(
            findings[0].artifacts.len() >= 2,
            "expected >= 2 artifacts, got {}",
            findings[0].artifacts.len()
        );
    }

    #[test]
    fn test_rdp_logon_events() {
        let mut mock = MockArtifactProvider {
            caps: vec![
                ProviderCapability::RegistryKeys,
                ProviderCapability::EventLogs,
            ],
            ..MockArtifactProvider::default()
        };
        mock.add_event_log(EventLogEntry {
            event_id: 4624,
            provider_name: "Microsoft-Windows-Security-Auditing".into(),
            log_file: "Security".into(),
            timestamp: Some(1_700_000_000_000_000_000),
            data: HashMap::from([
                ("LogonType".into(), "10".into()),
                ("IpAddress".into(), "192.168.1.100".into()),
                ("TargetUserName".into(), "admin".into()),
            ]),
        });

        let scanner = BuiltinRemoteScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool_name, "RDP");

        // Verify the finding contains the source IP
        let artifact = &findings[0].artifacts[0];
        assert!(
            artifact.value.contains("192.168.1.100"),
            "expected IP in finding value, got: {}",
            artifact.value
        );
        assert_eq!(
            artifact.context.get("source_ip"),
            Some(&"192.168.1.100".to_string())
        );
    }

    #[test]
    fn test_ssh_service_detected() {
        let mut mock = MockArtifactProvider {
            caps: vec![
                ProviderCapability::Services,
                ProviderCapability::FilePresence,
            ],
            ..MockArtifactProvider::default()
        };
        mock.add_service(ServiceEntry {
            name: "sshd".into(),
            display_name: "OpenSSH SSH Server".into(),
            image_path: r"C:\Windows\System32\OpenSSH\sshd.exe".into(),
            start_type: 2,
            service_type: 16,
            account: Some("LocalSystem".into()),
        });

        let scanner = BuiltinRemoteScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool_name, "SSH");
        assert_eq!(
            findings[0].category,
            RemoteAccessCategory::BuiltInRemoteAccess
        );
        assert_eq!(
            findings[0].detection_source,
            DetectionSource::CategoryScanner("builtin_remote".into())
        );
        assert!(!findings[0].artifacts.is_empty());
        assert_eq!(
            findings[0].artifacts[0].artifact_type,
            HitArtifactType::Service
        );
    }

    #[test]
    fn test_no_remote_access_found() {
        let mock = MockArtifactProvider {
            caps: vec![
                ProviderCapability::RegistryKeys,
                ProviderCapability::EventLogs,
                ProviderCapability::Services,
                ProviderCapability::FilePresence,
            ],
            ..MockArtifactProvider::default()
        };

        let scanner = BuiltinRemoteScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert!(
            findings.is_empty(),
            "expected no findings on empty mock, got {}",
            findings.len()
        );
    }
}
