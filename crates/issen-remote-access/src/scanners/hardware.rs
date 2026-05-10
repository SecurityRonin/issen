use std::collections::HashMap;

use crate::model::{
    DetectionSource, Finding, HitArtifactType, RawArtifactHit, RemoteAccessCategory,
};
use crate::providers::ArtifactProvider;
use crate::scanners::{CategoryScanner, ScanError};

/// Scanner for hardware-based remote management tools.
///
/// Detects services and files for:
/// - **iLO** (HP Integrated Lights-Out)
/// - **iDRAC** (Dell Integrated Dell Remote Access Controller)
/// - **IPMI** (Intelligent Platform Management Interface)
/// - **AMT** (Intel Active Management Technology)
pub struct HardwareScanner;

/// Hardware remote management tool patterns: `(keyword, display_name)`.
const HARDWARE_TOOLS: &[(&str, &str)] = &[
    ("ilo", "HP iLO"),
    ("idrac", "Dell iDRAC"),
    ("ipmi", "IPMI"),
    ("amt", "Intel AMT"),
    ("intel_amt", "Intel AMT"),
    ("lms", "Intel Local Management Service"),
];

impl HardwareScanner {
    /// Create a new `HardwareScanner`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Scan for hardware remote management services.
    ///
    /// Checks the system's service list for names matching known
    /// hardware remote management tools (iLO, iDRAC, IPMI, AMT).
    fn scan_hardware_services(
        &self,
        provider: &dyn ArtifactProvider,
    ) -> Vec<(String, Vec<RawArtifactHit>)> {
        let mut tool_hits: HashMap<String, Vec<RawArtifactHit>> = HashMap::new();

        if let Ok(services) = provider.services() {
            for svc in &services {
                let name_lower = svc.name.to_lowercase();
                let display_lower = svc.display_name.to_lowercase();

                for &(keyword, display_name) in HARDWARE_TOOLS {
                    if name_lower.contains(keyword) || display_lower.contains(keyword) {
                        tool_hits
                            .entry(display_name.into())
                            .or_default()
                            .push(RawArtifactHit {
                                artifact_type: HitArtifactType::Service,
                                source_path: format!("services/{}", svc.name),
                                value: format!(
                                    "{display_name} service: {} ({})",
                                    svc.display_name, svc.name
                                ),
                                timestamp: None,
                                context: HashMap::from([
                                    ("service_name".into(), svc.name.clone()),
                                    ("display_name".into(), svc.display_name.clone()),
                                    ("image_path".into(), svc.image_path.clone()),
                                    ("start_type".into(), svc.start_type.to_string()),
                                ]),
                            });
                        break; // Don't double-match the same service
                    }
                }
            }
        }

        tool_hits.into_iter().collect()
    }

    /// Scan for hardware remote management files.
    ///
    /// Checks for common file paths associated with iLO, iDRAC, and AMT
    /// management software.
    fn scan_hardware_files(
        &self,
        provider: &dyn ArtifactProvider,
    ) -> Vec<(String, Vec<RawArtifactHit>)> {
        let mut tool_hits: HashMap<String, Vec<RawArtifactHit>> = HashMap::new();

        let file_patterns: &[(&str, &str)] = &[
            ("*HP*iLO*", "HP iLO"),
            ("*iDRAC*", "Dell iDRAC"),
            ("*Intel*AMT*", "Intel AMT"),
            ("*Intel*Management*Engine*", "Intel AMT"),
            ("*IPMI*", "IPMI"),
        ];

        for &(pattern, tool_name) in file_patterns {
            if let Ok(files) = provider.file_exists(pattern) {
                for file in &files {
                    tool_hits
                        .entry(tool_name.into())
                        .or_default()
                        .push(RawArtifactHit {
                            artifact_type: HitArtifactType::FilePresence,
                            source_path: file.path.clone(),
                            value: format!("{tool_name} file: {}", file.path),
                            timestamp: file.modified.or(file.created),
                            context: HashMap::from([
                                ("file_path".into(), file.path.clone()),
                                ("tool".into(), tool_name.into()),
                            ]),
                        });
                }
            }
        }

        tool_hits.into_iter().collect()
    }
}

impl Default for HardwareScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CategoryScanner for HardwareScanner {
    fn category(&self) -> RemoteAccessCategory {
        RemoteAccessCategory::HardwareRemote
    }

    fn scan(&self, provider: &dyn ArtifactProvider) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();

        // Collect hits from services
        let svc_tool_hits = self.scan_hardware_services(provider);
        // Collect hits from files
        let file_tool_hits = self.scan_hardware_files(provider);

        // Merge hits by tool name
        let mut merged: HashMap<String, Vec<RawArtifactHit>> = HashMap::new();
        for (tool, hits) in svc_tool_hits {
            merged.entry(tool).or_default().extend(hits);
        }
        for (tool, hits) in file_tool_hits {
            merged.entry(tool).or_default().extend(hits);
        }

        // Create one finding per tool
        let mut tool_names: Vec<String> = merged.keys().cloned().collect();
        tool_names.sort(); // deterministic ordering
        for tool_name in tool_names {
            if let Some(hits) = merged.remove(&tool_name) {
                if !hits.is_empty() {
                    let first_seen = hits.iter().filter_map(|h| h.timestamp).min();
                    let last_seen = hits.iter().filter_map(|h| h.timestamp).max();
                    findings.push(Finding {
                        id: uuid::Uuid::new_v4().to_string(),
                        tool_name,
                        category: RemoteAccessCategory::HardwareRemote,
                        artifacts: hits,
                        first_seen,
                        last_seen,
                        detection_source: DetectionSource::CategoryScanner("hardware".into()),
                    });
                }
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{MockArtifactProvider, ProviderCapability, ServiceEntry};

    #[test]
    fn test_ilo_service_detected() {
        let mut mock = MockArtifactProvider {
            caps: vec![
                ProviderCapability::Services,
                ProviderCapability::FilePresence,
            ],
            ..MockArtifactProvider::default()
        };
        mock.add_service(ServiceEntry {
            name: "hpiLO".into(),
            display_name: "HP iLO Management Service".into(),
            image_path: r"C:\Program Files\HP\iLO\hpilod.exe".into(),
            start_type: 2,
            service_type: 16,
            account: Some("LocalSystem".into()),
        });

        let scanner = HardwareScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool_name, "HP iLO");
        assert_eq!(findings[0].category, RemoteAccessCategory::HardwareRemote);
        assert_eq!(
            findings[0].detection_source,
            DetectionSource::CategoryScanner("hardware".into())
        );
        assert!(!findings[0].artifacts.is_empty());
        assert_eq!(
            findings[0].artifacts[0].artifact_type,
            HitArtifactType::Service
        );
    }

    #[test]
    fn test_no_hardware_remote_found() {
        let mock = MockArtifactProvider {
            caps: vec![
                ProviderCapability::Services,
                ProviderCapability::FilePresence,
            ],
            ..MockArtifactProvider::default()
        };

        let scanner = HardwareScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert!(
            findings.is_empty(),
            "expected no findings on empty mock, got {}",
            findings.len()
        );
    }

    #[test]
    fn test_amt_service_detected() {
        let mut mock = MockArtifactProvider {
            caps: vec![
                ProviderCapability::Services,
                ProviderCapability::FilePresence,
            ],
            ..MockArtifactProvider::default()
        };
        mock.add_service(ServiceEntry {
            name: "LMS".into(),
            display_name: "Intel(R) Management and Security Application Local Management Service"
                .into(),
            image_path: r"C:\Program Files\Intel\iCLS Client\LMS.exe".into(),
            start_type: 2,
            service_type: 16,
            account: Some("LocalSystem".into()),
        });

        let scanner = HardwareScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool_name, "Intel Local Management Service");
        assert!(!findings[0].artifacts.is_empty());
    }

    #[test]
    fn test_idrac_service_detected() {
        let mut mock = MockArtifactProvider {
            caps: vec![
                ProviderCapability::Services,
                ProviderCapability::FilePresence,
            ],
            ..MockArtifactProvider::default()
        };
        mock.add_service(ServiceEntry {
            name: "iDRAC Service Module".into(),
            display_name: "Dell iDRAC Service Module".into(),
            image_path: r"C:\Program Files\Dell\iDRAC\iDRACsvc.exe".into(),
            start_type: 2,
            service_type: 16,
            account: Some("LocalSystem".into()),
        });

        let scanner = HardwareScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool_name, "Dell iDRAC");
    }
}
