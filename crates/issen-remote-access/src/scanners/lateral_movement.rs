use std::collections::HashMap;

use crate::model::{
    DetectionSource, Finding, HitArtifactType, RawArtifactHit, RemoteAccessCategory,
};
use crate::providers::{ArtifactProvider, EventLogQuery};
use crate::scanners::{CategoryScanner, ScanError};

/// Scanner for lateral movement tools: PsExec, WMI, and Kerberoasting.
///
/// Detects:
/// - **PsExec**: Event 7045 where `ServiceName` contains "PSEXESVC"
/// - **WMI**: Event 5857 from provider "Microsoft-Windows-WMI-Activity"
/// - **Kerberoasting**: Event 4769 where `TicketEncryptionType` == "0x17"
///   (RC4) and `TargetUserName` does NOT end with "$"
pub struct LateralMovementScanner;

impl LateralMovementScanner {
    /// Create a new `LateralMovementScanner`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Scan for PsExec usage via service installation events.
    ///
    /// Event 7045 (new service installed) where `ServiceName` contains
    /// "PSEXESVC" is a strong indicator of PsExec lateral movement.
    fn scan_psexec(&self, provider: &dyn ArtifactProvider) -> Vec<RawArtifactHit> {
        let mut hits = Vec::new();

        let query = EventLogQuery {
            event_id: Some(7045),
            provider_name: Some("Service Control Manager".into()),
            log_file: Some("System".into()),
            keyword: None,
        };

        if let Ok(events) = provider.event_log_search(&query) {
            for event in &events {
                let service_name = event
                    .data
                    .get("ServiceName")
                    .map(String::as_str)
                    .unwrap_or("");
                if service_name.to_uppercase().contains("PSEXESVC") {
                    let image_path = event.data.get("ImagePath").cloned().unwrap_or_default();
                    hits.push(RawArtifactHit {
                        artifact_type: HitArtifactType::EventLog,
                        source_path: "System".into(),
                        value: format!("PsExec service installed: {service_name} ({image_path})"),
                        timestamp: event.timestamp,
                        context: HashMap::from([
                            ("event_id".into(), "7045".into()),
                            ("service_name".into(), service_name.to_owned()),
                            ("image_path".into(), image_path),
                        ]),
                    });
                }
            }
        }

        hits
    }

    /// Scan for WMI-based lateral movement.
    ///
    /// Event 5857 from "Microsoft-Windows-WMI-Activity" indicates WMI
    /// provider operations, which are commonly abused for lateral movement.
    fn scan_wmi(&self, provider: &dyn ArtifactProvider) -> Vec<RawArtifactHit> {
        let mut hits = Vec::new();

        let query = EventLogQuery {
            event_id: Some(5857),
            provider_name: Some("Microsoft-Windows-WMI-Activity".into()),
            log_file: None,
            keyword: None,
        };

        if let Ok(events) = provider.event_log_search(&query) {
            for event in &events {
                let provider_name = event.data.get("ProviderName").cloned().unwrap_or_default();
                hits.push(RawArtifactHit {
                    artifact_type: HitArtifactType::EventLog,
                    source_path: event.log_file.clone(),
                    value: format!("WMI provider loaded: {provider_name}"),
                    timestamp: event.timestamp,
                    context: HashMap::from([
                        ("event_id".into(), "5857".into()),
                        ("provider_name".into(), provider_name),
                    ]),
                });
            }
        }

        hits
    }

    /// Scan for Kerberoasting indicators.
    ///
    /// Event 4769 (Kerberos Service Ticket Request) where
    /// `TicketEncryptionType` == "0x17" (RC4) AND `TargetUserName` does NOT
    /// end with "$" (i.e., not a machine account) is a strong Kerberoasting
    /// indicator.
    fn scan_kerberoasting(&self, provider: &dyn ArtifactProvider) -> Vec<RawArtifactHit> {
        let mut hits = Vec::new();

        let query = EventLogQuery {
            event_id: Some(4769),
            provider_name: Some("Microsoft-Windows-Security-Auditing".into()),
            log_file: Some("Security".into()),
            keyword: None,
        };

        if let Ok(events) = provider.event_log_search(&query) {
            for event in &events {
                let enc_type = event
                    .data
                    .get("TicketEncryptionType")
                    .map(String::as_str)
                    .unwrap_or("");
                let target_user = event
                    .data
                    .get("TargetUserName")
                    .map(String::as_str)
                    .unwrap_or("");

                // RC4 encryption + non-machine account = Kerberoasting indicator
                if enc_type == "0x17" && !target_user.ends_with('$') {
                    let service_name = event.data.get("ServiceName").cloned().unwrap_or_default();
                    hits.push(RawArtifactHit {
                        artifact_type: HitArtifactType::EventLog,
                        source_path: "Security".into(),
                        value: format!(
                            "Kerberoasting: RC4 ticket for {target_user} (SPN: {service_name})"
                        ),
                        timestamp: event.timestamp,
                        context: HashMap::from([
                            ("event_id".into(), "4769".into()),
                            ("target_user".into(), target_user.to_owned()),
                            ("encryption_type".into(), enc_type.to_owned()),
                            ("service_name".into(), service_name),
                        ]),
                    });
                }
            }
        }

        hits
    }
}

impl Default for LateralMovementScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CategoryScanner for LateralMovementScanner {
    fn category(&self) -> RemoteAccessCategory {
        RemoteAccessCategory::LateralMovement
    }

    fn scan(&self, provider: &dyn ArtifactProvider) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();

        // Scan PsExec
        let psexec_hits = self.scan_psexec(provider);
        if !psexec_hits.is_empty() {
            let first_seen = psexec_hits.iter().filter_map(|h| h.timestamp).min();
            let last_seen = psexec_hits.iter().filter_map(|h| h.timestamp).max();
            findings.push(Finding {
                id: uuid::Uuid::new_v4().to_string(),
                tool_name: "PsExec".into(),
                category: RemoteAccessCategory::LateralMovement,
                artifacts: psexec_hits,
                first_seen,
                last_seen,
                detection_source: DetectionSource::CategoryScanner("lateral_movement".into()),
            });
        }

        // Scan WMI
        let wmi_hits = self.scan_wmi(provider);
        if !wmi_hits.is_empty() {
            let first_seen = wmi_hits.iter().filter_map(|h| h.timestamp).min();
            let last_seen = wmi_hits.iter().filter_map(|h| h.timestamp).max();
            findings.push(Finding {
                id: uuid::Uuid::new_v4().to_string(),
                tool_name: "WMI".into(),
                category: RemoteAccessCategory::LateralMovement,
                artifacts: wmi_hits,
                first_seen,
                last_seen,
                detection_source: DetectionSource::CategoryScanner("lateral_movement".into()),
            });
        }

        // Scan Kerberoasting
        let kerb_hits = self.scan_kerberoasting(provider);
        if !kerb_hits.is_empty() {
            let first_seen = kerb_hits.iter().filter_map(|h| h.timestamp).min();
            let last_seen = kerb_hits.iter().filter_map(|h| h.timestamp).max();
            findings.push(Finding {
                id: uuid::Uuid::new_v4().to_string(),
                tool_name: "Kerberoasting".into(),
                category: RemoteAccessCategory::LateralMovement,
                artifacts: kerb_hits,
                first_seen,
                last_seen,
                detection_source: DetectionSource::CategoryScanner("lateral_movement".into()),
            });
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{EventLogEntry, MockArtifactProvider, ProviderCapability};

    #[test]
    fn test_psexec_service_detected() {
        let mut mock = MockArtifactProvider {
            caps: vec![ProviderCapability::EventLogs],
            ..MockArtifactProvider::default()
        };
        mock.add_event_log(EventLogEntry {
            event_id: 7045,
            provider_name: "Service Control Manager".into(),
            log_file: "System".into(),
            timestamp: Some(1_700_000_000_000_000_000),
            data: HashMap::from([
                ("ServiceName".into(), "PSEXESVC".into()),
                ("ImagePath".into(), r"C:\Windows\PSEXESVC.exe".into()),
            ]),
        });

        let scanner = LateralMovementScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool_name, "PsExec");
        assert_eq!(findings[0].category, RemoteAccessCategory::LateralMovement);
        assert_eq!(
            findings[0].detection_source,
            DetectionSource::CategoryScanner("lateral_movement".into())
        );
        assert!(!findings[0].artifacts.is_empty());
        assert_eq!(
            findings[0].artifacts[0].artifact_type,
            HitArtifactType::EventLog
        );
        assert!(findings[0].artifacts[0].value.contains("PSEXESVC"));
    }

    #[test]
    fn test_no_lateral_movement_found() {
        let mock = MockArtifactProvider {
            caps: vec![ProviderCapability::EventLogs],
            ..MockArtifactProvider::default()
        };

        let scanner = LateralMovementScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert!(
            findings.is_empty(),
            "expected no findings on empty mock, got {}",
            findings.len()
        );
    }

    #[test]
    fn test_wmi_activity_detected() {
        let mut mock = MockArtifactProvider {
            caps: vec![ProviderCapability::EventLogs],
            ..MockArtifactProvider::default()
        };
        mock.add_event_log(EventLogEntry {
            event_id: 5857,
            provider_name: "Microsoft-Windows-WMI-Activity".into(),
            log_file: "Microsoft-Windows-WMI-Activity/Operational".into(),
            timestamp: Some(1_700_000_000_000_000_000),
            data: HashMap::from([("ProviderName".into(), "WmiPerfClass".into())]),
        });

        let scanner = LateralMovementScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool_name, "WMI");
        assert!(findings[0].artifacts[0].value.contains("WmiPerfClass"));
    }

    #[test]
    fn test_kerberoasting_detected() {
        let mut mock = MockArtifactProvider {
            caps: vec![ProviderCapability::EventLogs],
            ..MockArtifactProvider::default()
        };
        mock.add_event_log(EventLogEntry {
            event_id: 4769,
            provider_name: "Microsoft-Windows-Security-Auditing".into(),
            log_file: "Security".into(),
            timestamp: Some(1_700_000_000_000_000_000),
            data: HashMap::from([
                ("TicketEncryptionType".into(), "0x17".into()),
                ("TargetUserName".into(), "svc_sql".into()),
                ("ServiceName".into(), "MSSQLSvc/db01.corp.local:1433".into()),
            ]),
        });

        let scanner = LateralMovementScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool_name, "Kerberoasting");
        assert!(findings[0].artifacts[0].value.contains("svc_sql"));
    }

    #[test]
    fn test_kerberoasting_ignores_machine_accounts() {
        let mut mock = MockArtifactProvider {
            caps: vec![ProviderCapability::EventLogs],
            ..MockArtifactProvider::default()
        };
        // Machine account (ends with $) should be ignored
        mock.add_event_log(EventLogEntry {
            event_id: 4769,
            provider_name: "Microsoft-Windows-Security-Auditing".into(),
            log_file: "Security".into(),
            timestamp: Some(1_700_000_000_000_000_000),
            data: HashMap::from([
                ("TicketEncryptionType".into(), "0x17".into()),
                ("TargetUserName".into(), "WORKSTATION01$".into()),
                ("ServiceName".into(), "krbtgt/CORP.LOCAL".into()),
            ]),
        });

        let scanner = LateralMovementScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert!(
            findings.is_empty(),
            "machine accounts should not trigger Kerberoasting detection"
        );
    }
}
