use std::collections::HashMap;

use crate::model::{
    DetectionSource, Finding, HitArtifactType, RawArtifactHit, RemoteAccessCategory,
};
use crate::providers::{ArtifactProvider, EventLogQuery};
use crate::scanners::{CategoryScanner, ScanError};

/// Scanner for C2 (Command and Control) framework indicators.
///
/// Detects:
/// - **Suspicious service installs**: Event 7045 with base64/encoded
///   characters in `ImagePath` (e.g., "powershell -enc" or unusual
///   base64 strings)
/// - **Named pipe patterns**: Event log entries indicating suspicious
///   named pipe creation/usage
pub struct C2Scanner;

/// Patterns in service image paths that suggest C2 activity.
const SUSPICIOUS_IMAGE_PATTERNS: &[&str] = &[
    "powershell -enc",
    "powershell.exe -enc",
    "powershell -e ",
    "powershell.exe -e ",
    "powershell -nop",
    "powershell.exe -nop",
    "-encodedcommand",
    "frombase64string",
    "downloadstring",
    "invoke-expression",
    "iex(",
    "iex (",
    "hidden -",
    "-windowstyle hidden",
    "bypass -",
    "-executionpolicy bypass",
    "cmd /c echo",
    "rundll32",
    "%comspec%",
];

/// Named pipe patterns associated with common C2 frameworks.
const C2_PIPE_PATTERNS: &[&str] = &[
    "msagent_",
    "msse-",
    "postex_",
    "status_",
    "mypipe-f",
    "mypipe-h",
    "ntsvcs_",
    "scerpc_",
    "win\\msrpc_",
    "dce\\srvpipe_",
    "spoolss_",
    "winsock",
];

impl C2Scanner {
    /// Create a new `C2Scanner`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Scan for suspicious service installations that may indicate C2
    /// implants.
    ///
    /// Event 7045 (new service installed) where the `ImagePath` contains
    /// encoded commands, base64 strings, or other obfuscation patterns
    /// commonly used by C2 frameworks for persistence.
    fn scan_suspicious_services(&self, provider: &dyn ArtifactProvider) -> Vec<RawArtifactHit> {
        let mut hits = Vec::new();

        let query = EventLogQuery {
            event_id: Some(7045),
            provider_name: Some("Service Control Manager".into()),
            log_file: Some("System".into()),
            keyword: None,
        };

        if let Ok(events) = provider.event_log_search(&query) {
            for event in &events {
                let image_path = event
                    .data
                    .get("ImagePath")
                    .map(String::as_str)
                    .unwrap_or("");
                let image_lower = image_path.to_lowercase();

                let matched_pattern = SUSPICIOUS_IMAGE_PATTERNS
                    .iter()
                    .find(|p| image_lower.contains(*p));

                if let Some(pattern) = matched_pattern {
                    let service_name = event.data.get("ServiceName").cloned().unwrap_or_default();
                    hits.push(RawArtifactHit {
                        artifact_type: HitArtifactType::EventLog,
                        source_path: "System".into(),
                        value: format!("Suspicious service: {service_name} (matched: {pattern})"),
                        timestamp: event.timestamp,
                        context: HashMap::from([
                            ("event_id".into(), "7045".into()),
                            ("service_name".into(), service_name),
                            ("image_path".into(), image_path.to_owned()),
                            ("matched_pattern".into(), (*pattern).to_owned()),
                        ]),
                    });
                }
            }
        }

        hits
    }

    /// Scan for C2-associated named pipe patterns.
    ///
    /// Checks event logs for pipe creation events (Event 17 from
    /// Sysmon) that match known C2 framework pipe naming conventions.
    fn scan_named_pipes(&self, provider: &dyn ArtifactProvider) -> Vec<RawArtifactHit> {
        let mut hits = Vec::new();

        // Sysmon Event 17: Pipe Created
        let query = EventLogQuery {
            event_id: Some(17),
            provider_name: Some("Microsoft-Windows-Sysmon".into()),
            log_file: None,
            keyword: None,
        };

        if let Ok(events) = provider.event_log_search(&query) {
            for event in &events {
                let pipe_name = event.data.get("PipeName").map(String::as_str).unwrap_or("");
                let pipe_lower = pipe_name.to_lowercase();

                let matched = C2_PIPE_PATTERNS.iter().find(|p| pipe_lower.contains(*p));

                if let Some(pattern) = matched {
                    hits.push(RawArtifactHit {
                        artifact_type: HitArtifactType::EventLog,
                        source_path: event.log_file.clone(),
                        value: format!("Suspicious named pipe: {pipe_name} (matched: {pattern})"),
                        timestamp: event.timestamp,
                        context: HashMap::from([
                            ("event_id".into(), "17".into()),
                            ("pipe_name".into(), pipe_name.to_owned()),
                            ("matched_pattern".into(), (*pattern).to_owned()),
                        ]),
                    });
                }
            }
        }

        hits
    }
}

impl Default for C2Scanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CategoryScanner for C2Scanner {
    fn category(&self) -> RemoteAccessCategory {
        RemoteAccessCategory::C2Framework
    }

    fn scan(&self, provider: &dyn ArtifactProvider) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();

        // Scan suspicious service installs
        let svc_hits = self.scan_suspicious_services(provider);
        if !svc_hits.is_empty() {
            let first_seen = svc_hits.iter().filter_map(|h| h.timestamp).min();
            let last_seen = svc_hits.iter().filter_map(|h| h.timestamp).max();
            findings.push(Finding {
                id: uuid::Uuid::new_v4().to_string(),
                tool_name: "Suspicious Service".into(),
                category: RemoteAccessCategory::C2Framework,
                artifacts: svc_hits,
                first_seen,
                last_seen,
                detection_source: DetectionSource::CategoryScanner("c2".into()),
            });
        }

        // Scan named pipes
        let pipe_hits = self.scan_named_pipes(provider);
        if !pipe_hits.is_empty() {
            let first_seen = pipe_hits.iter().filter_map(|h| h.timestamp).min();
            let last_seen = pipe_hits.iter().filter_map(|h| h.timestamp).max();
            findings.push(Finding {
                id: uuid::Uuid::new_v4().to_string(),
                tool_name: "C2 Named Pipe".into(),
                category: RemoteAccessCategory::C2Framework,
                artifacts: pipe_hits,
                first_seen,
                last_seen,
                detection_source: DetectionSource::CategoryScanner("c2".into()),
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
    fn test_suspicious_service_powershell_enc() {
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
                ("ServiceName".into(), "MaliciousSvc".into()),
                (
                    "ImagePath".into(),
                    r"powershell -enc SQBFAFgAIAAoA...".into(),
                ),
            ]),
        });

        let scanner = C2Scanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool_name, "Suspicious Service");
        assert_eq!(findings[0].category, RemoteAccessCategory::C2Framework);
        assert_eq!(
            findings[0].detection_source,
            DetectionSource::CategoryScanner("c2".into())
        );
        assert!(!findings[0].artifacts.is_empty());
        assert!(findings[0].artifacts[0].value.contains("powershell -enc"));
    }

    #[test]
    fn test_no_c2_found() {
        let mock = MockArtifactProvider {
            caps: vec![ProviderCapability::EventLogs],
            ..MockArtifactProvider::default()
        };

        let scanner = C2Scanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert!(
            findings.is_empty(),
            "expected no findings on empty mock, got {}",
            findings.len()
        );
    }

    #[test]
    fn test_legitimate_service_not_flagged() {
        let mut mock = MockArtifactProvider {
            caps: vec![ProviderCapability::EventLogs],
            ..MockArtifactProvider::default()
        };
        // Normal service install should not trigger
        mock.add_event_log(EventLogEntry {
            event_id: 7045,
            provider_name: "Service Control Manager".into(),
            log_file: "System".into(),
            timestamp: Some(1_700_000_000_000_000_000),
            data: HashMap::from([
                ("ServiceName".into(), "WindowsUpdate".into()),
                (
                    "ImagePath".into(),
                    r"C:\Windows\System32\svchost.exe -k netsvcs".into(),
                ),
            ]),
        });

        let scanner = C2Scanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert!(
            findings.is_empty(),
            "legitimate service should not be flagged"
        );
    }

    #[test]
    fn test_c2_named_pipe_detected() {
        let mut mock = MockArtifactProvider {
            caps: vec![ProviderCapability::EventLogs],
            ..MockArtifactProvider::default()
        };
        mock.add_event_log(EventLogEntry {
            event_id: 17,
            provider_name: "Microsoft-Windows-Sysmon".into(),
            log_file: "Microsoft-Windows-Sysmon/Operational".into(),
            timestamp: Some(1_700_000_000_000_000_000),
            data: HashMap::from([("PipeName".into(), r"\postex_1234".into())]),
        });

        let scanner = C2Scanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool_name, "C2 Named Pipe");
        assert!(findings[0].artifacts[0].value.contains("postex_"));
    }
}
