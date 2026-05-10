use std::collections::HashMap;

use crate::model::{
    DetectionSource, Finding, HitArtifactType, RawArtifactHit, RemoteAccessCategory,
};
use crate::providers::ArtifactProvider;
use crate::scanners::{CategoryScanner, ScanError};

/// Scanner for Windows Firewall configuration assessment.
///
/// Checks if the firewall is disabled for any profile:
/// - **DomainProfile**: `EnableFirewall` = 0
/// - **StandardProfile**: `EnableFirewall` = 0
/// - **PublicProfile**: `EnableFirewall` = 0
pub struct FirewallScanner;

/// Registry paths for each Windows Firewall profile.
const FIREWALL_PROFILES: &[(&str, &str)] = &[
    (
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
        "DomainProfile",
    ),
    (
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
        "StandardProfile",
    ),
    (
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
        "PublicProfile",
    ),
];

impl FirewallScanner {
    /// Create a new `FirewallScanner`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Check firewall status for all three Windows Firewall profiles.
    ///
    /// Examines the `EnableFirewall` registry value under each profile
    /// key. A value of "0" means the firewall is disabled for that
    /// profile, which is a significant security finding.
    fn scan_firewall_profiles(&self, provider: &dyn ArtifactProvider) -> Vec<RawArtifactHit> {
        let mut hits = Vec::new();

        for &(reg_path, profile_name) in FIREWALL_PROFILES {
            if let Ok(values) = provider.registry_values(reg_path) {
                for entry in &values {
                    if entry.name == "EnableFirewall" && entry.value == "0" {
                        hits.push(RawArtifactHit {
                            artifact_type: HitArtifactType::RegistryValue,
                            source_path: reg_path.into(),
                            value: format!("Firewall DISABLED for {profile_name}"),
                            timestamp: entry.timestamp,
                            context: HashMap::from([
                                ("profile".into(), profile_name.into()),
                                ("registry_path".into(), reg_path.into()),
                                ("name".into(), entry.name.clone()),
                                ("value".into(), entry.value.clone()),
                                ("risk".into(), "high".into()),
                            ]),
                        });
                    }
                }
            }
        }

        hits
    }
}

impl Default for FirewallScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CategoryScanner for FirewallScanner {
    fn category(&self) -> RemoteAccessCategory {
        RemoteAccessCategory::FirewallConfig
    }

    fn scan(&self, provider: &dyn ArtifactProvider) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();

        let fw_hits = self.scan_firewall_profiles(provider);
        if !fw_hits.is_empty() {
            let first_seen = fw_hits.iter().filter_map(|h| h.timestamp).min();
            let last_seen = fw_hits.iter().filter_map(|h| h.timestamp).max();
            findings.push(Finding {
                id: uuid::Uuid::new_v4().to_string(),
                tool_name: "Windows Firewall".into(),
                category: RemoteAccessCategory::FirewallConfig,
                artifacts: fw_hits,
                first_seen,
                last_seen,
                detection_source: DetectionSource::CategoryScanner("firewall".into()),
            });
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{MockArtifactProvider, ProviderCapability, RegistryEntry};

    #[test]
    fn test_firewall_disabled_detected() {
        let mut mock = MockArtifactProvider {
            caps: vec![ProviderCapability::RegistryKeys],
            ..MockArtifactProvider::default()
        };
        mock.add_registry_value(
            r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
            RegistryEntry {
                path: r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile".into(),
                name: "EnableFirewall".into(),
                value: "0".into(),
                data_type: "REG_DWORD".into(),
                timestamp: None,
            },
        );

        let scanner = FirewallScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool_name, "Windows Firewall");
        assert_eq!(findings[0].category, RemoteAccessCategory::FirewallConfig);
        assert_eq!(
            findings[0].detection_source,
            DetectionSource::CategoryScanner("firewall".into())
        );
        assert!(!findings[0].artifacts.is_empty());
        assert_eq!(
            findings[0].artifacts[0].artifact_type,
            HitArtifactType::RegistryValue
        );
        assert!(findings[0].artifacts[0].value.contains("DISABLED"));
        assert_eq!(
            findings[0].artifacts[0].context.get("profile"),
            Some(&"DomainProfile".to_string())
        );
        assert_eq!(
            findings[0].artifacts[0].context.get("risk"),
            Some(&"high".to_string())
        );
    }

    #[test]
    fn test_no_firewall_issues() {
        let mock = MockArtifactProvider {
            caps: vec![ProviderCapability::RegistryKeys],
            ..MockArtifactProvider::default()
        };

        let scanner = FirewallScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert!(
            findings.is_empty(),
            "expected no findings on empty mock, got {}",
            findings.len()
        );
    }

    #[test]
    fn test_firewall_enabled_not_flagged() {
        let mut mock = MockArtifactProvider {
            caps: vec![ProviderCapability::RegistryKeys],
            ..MockArtifactProvider::default()
        };
        // Firewall enabled (value = "1") should NOT trigger a finding
        mock.add_registry_value(
            r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
            RegistryEntry {
                path: r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile".into(),
                name: "EnableFirewall".into(),
                value: "1".into(),
                data_type: "REG_DWORD".into(),
                timestamp: None,
            },
        );

        let scanner = FirewallScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert!(
            findings.is_empty(),
            "firewall enabled should not be flagged"
        );
    }

    #[test]
    fn test_multiple_profiles_disabled() {
        let mut mock = MockArtifactProvider {
            caps: vec![ProviderCapability::RegistryKeys],
            ..MockArtifactProvider::default()
        };
        // Domain profile disabled
        mock.add_registry_value(
            r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
            RegistryEntry {
                path: r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile".into(),
                name: "EnableFirewall".into(),
                value: "0".into(),
                data_type: "REG_DWORD".into(),
                timestamp: None,
            },
        );
        // Public profile disabled
        mock.add_registry_value(
            r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
            RegistryEntry {
                path: r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile".into(),
                name: "EnableFirewall".into(),
                value: "0".into(),
                data_type: "REG_DWORD".into(),
                timestamp: None,
            },
        );

        let scanner = FirewallScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert_eq!(findings.len(), 1);
        // Should have 2 artifacts (one per disabled profile)
        assert_eq!(
            findings[0].artifacts.len(),
            2,
            "expected 2 artifacts for 2 disabled profiles, got {}",
            findings[0].artifacts.len()
        );
    }
}
