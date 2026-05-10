use std::collections::HashMap;

use crate::model::{
    DetectionSource, Finding, HitArtifactType, RawArtifactHit, RemoteAccessCategory,
};
use crate::providers::ArtifactProvider;
use crate::scanners::{CategoryScanner, ScanError};

/// Scanner for tunneling tools: ngrok, cloudflared, and netsh portproxy.
///
/// Detects:
/// - **ngrok**: Prefetch match for "NGROK", service named "ngrok"
/// - **cloudflared**: Prefetch match for "CLOUDFLARED", service named
///   "cloudflared"
/// - **netsh portproxy**: Registry key
///   `SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4`
pub struct TunnelingScanner;

impl TunnelingScanner {
    /// Create a new `TunnelingScanner`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Scan for ngrok tunneling usage.
    ///
    /// Checks prefetch entries for "NGROK" and services list for ngrok.
    fn scan_ngrok(&self, provider: &dyn ArtifactProvider) -> Vec<RawArtifactHit> {
        let mut hits = Vec::new();

        // Check prefetch for ngrok
        if let Ok(entries) = provider.prefetch_entries() {
            for entry in &entries {
                if entry.executable_name.to_uppercase().contains("NGROK") {
                    hits.push(RawArtifactHit {
                        artifact_type: HitArtifactType::Prefetch,
                        source_path: entry.path.clone(),
                        value: format!(
                            "ngrok prefetch: {} (run count: {})",
                            entry.executable_name, entry.run_count
                        ),
                        timestamp: entry.last_run,
                        context: HashMap::from([
                            ("executable_name".into(), entry.executable_name.clone()),
                            ("run_count".into(), entry.run_count.to_string()),
                        ]),
                    });
                }
            }
        }

        // Check services for ngrok
        if let Ok(services) = provider.services() {
            for svc in &services {
                let name_lower = svc.name.to_lowercase();
                let display_lower = svc.display_name.to_lowercase();
                if name_lower.contains("ngrok") || display_lower.contains("ngrok") {
                    hits.push(RawArtifactHit {
                        artifact_type: HitArtifactType::Service,
                        source_path: format!("services/{}", svc.name),
                        value: format!("ngrok service: {} ({})", svc.display_name, svc.name),
                        timestamp: None,
                        context: HashMap::from([
                            ("service_name".into(), svc.name.clone()),
                            ("display_name".into(), svc.display_name.clone()),
                            ("image_path".into(), svc.image_path.clone()),
                        ]),
                    });
                }
            }
        }

        hits
    }

    /// Scan for cloudflared tunnel usage.
    ///
    /// Checks prefetch entries for "CLOUDFLARED" and services list for
    /// cloudflared.
    fn scan_cloudflared(&self, provider: &dyn ArtifactProvider) -> Vec<RawArtifactHit> {
        let mut hits = Vec::new();

        // Check prefetch for cloudflared
        if let Ok(entries) = provider.prefetch_entries() {
            for entry in &entries {
                if entry.executable_name.to_uppercase().contains("CLOUDFLARED") {
                    hits.push(RawArtifactHit {
                        artifact_type: HitArtifactType::Prefetch,
                        source_path: entry.path.clone(),
                        value: format!(
                            "cloudflared prefetch: {} (run count: {})",
                            entry.executable_name, entry.run_count
                        ),
                        timestamp: entry.last_run,
                        context: HashMap::from([
                            ("executable_name".into(), entry.executable_name.clone()),
                            ("run_count".into(), entry.run_count.to_string()),
                        ]),
                    });
                }
            }
        }

        // Check services for cloudflared
        if let Ok(services) = provider.services() {
            for svc in &services {
                let name_lower = svc.name.to_lowercase();
                let display_lower = svc.display_name.to_lowercase();
                if name_lower.contains("cloudflared") || display_lower.contains("cloudflared") {
                    hits.push(RawArtifactHit {
                        artifact_type: HitArtifactType::Service,
                        source_path: format!("services/{}", svc.name),
                        value: format!("cloudflared service: {} ({})", svc.display_name, svc.name),
                        timestamp: None,
                        context: HashMap::from([
                            ("service_name".into(), svc.name.clone()),
                            ("display_name".into(), svc.display_name.clone()),
                            ("image_path".into(), svc.image_path.clone()),
                        ]),
                    });
                }
            }
        }

        hits
    }

    /// Scan for netsh portproxy configuration.
    ///
    /// The registry key
    /// `SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4` stores port
    /// forwarding rules created by `netsh interface portproxy add v4tov4`.
    fn scan_portproxy(&self, provider: &dyn ArtifactProvider) -> Vec<RawArtifactHit> {
        let mut hits = Vec::new();

        let portproxy_path = r"SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4";
        if let Ok(true) = provider.registry_key_exists(portproxy_path) {
            hits.push(RawArtifactHit {
                artifact_type: HitArtifactType::RegistryKey,
                source_path: portproxy_path.into(),
                value: "netsh portproxy v4tov4 configuration present".into(),
                timestamp: None,
                context: HashMap::from([("registry_path".into(), portproxy_path.into())]),
            });

            // Also check for specific forwarding rules
            if let Ok(values) = provider.registry_values(portproxy_path) {
                for entry in &values {
                    hits.push(RawArtifactHit {
                        artifact_type: HitArtifactType::RegistryValue,
                        source_path: portproxy_path.into(),
                        value: format!("portproxy rule: {} -> {}", entry.name, entry.value),
                        timestamp: entry.timestamp,
                        context: HashMap::from([
                            ("listen_address".into(), entry.name.clone()),
                            ("connect_address".into(), entry.value.clone()),
                        ]),
                    });
                }
            }
        }

        hits
    }
}

impl Default for TunnelingScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CategoryScanner for TunnelingScanner {
    fn category(&self) -> RemoteAccessCategory {
        RemoteAccessCategory::Tunneling
    }

    fn scan(&self, provider: &dyn ArtifactProvider) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();

        // Scan ngrok
        let ngrok_hits = self.scan_ngrok(provider);
        if !ngrok_hits.is_empty() {
            let first_seen = ngrok_hits.iter().filter_map(|h| h.timestamp).min();
            let last_seen = ngrok_hits.iter().filter_map(|h| h.timestamp).max();
            findings.push(Finding {
                id: uuid::Uuid::new_v4().to_string(),
                tool_name: "ngrok".into(),
                category: RemoteAccessCategory::Tunneling,
                artifacts: ngrok_hits,
                first_seen,
                last_seen,
                detection_source: DetectionSource::CategoryScanner("tunneling".into()),
            });
        }

        // Scan cloudflared
        let cf_hits = self.scan_cloudflared(provider);
        if !cf_hits.is_empty() {
            let first_seen = cf_hits.iter().filter_map(|h| h.timestamp).min();
            let last_seen = cf_hits.iter().filter_map(|h| h.timestamp).max();
            findings.push(Finding {
                id: uuid::Uuid::new_v4().to_string(),
                tool_name: "cloudflared".into(),
                category: RemoteAccessCategory::Tunneling,
                artifacts: cf_hits,
                first_seen,
                last_seen,
                detection_source: DetectionSource::CategoryScanner("tunneling".into()),
            });
        }

        // Scan portproxy
        let pp_hits = self.scan_portproxy(provider);
        if !pp_hits.is_empty() {
            let first_seen = pp_hits.iter().filter_map(|h| h.timestamp).min();
            let last_seen = pp_hits.iter().filter_map(|h| h.timestamp).max();
            findings.push(Finding {
                id: uuid::Uuid::new_v4().to_string(),
                tool_name: "netsh portproxy".into(),
                category: RemoteAccessCategory::Tunneling,
                artifacts: pp_hits,
                first_seen,
                last_seen,
                detection_source: DetectionSource::CategoryScanner("tunneling".into()),
            });
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{
        MockArtifactProvider, PrefetchEntry, ProviderCapability, RegistryEntry,
    };

    #[test]
    fn test_ngrok_prefetch_detected() {
        let mut mock = MockArtifactProvider {
            caps: vec![
                ProviderCapability::PrefetchEntries,
                ProviderCapability::Services,
            ],
            ..MockArtifactProvider::default()
        };
        mock.add_prefetch(PrefetchEntry {
            executable_name: "NGROK.EXE".into(),
            run_count: 5,
            last_run: Some(1_700_000_000_000_000_000),
            path: r"C:\Windows\Prefetch\NGROK.EXE-12345678.pf".into(),
        });

        let scanner = TunnelingScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool_name, "ngrok");
        assert_eq!(findings[0].category, RemoteAccessCategory::Tunneling);
        assert_eq!(
            findings[0].detection_source,
            DetectionSource::CategoryScanner("tunneling".into())
        );
        assert!(!findings[0].artifacts.is_empty());
        assert_eq!(
            findings[0].artifacts[0].artifact_type,
            HitArtifactType::Prefetch
        );
    }

    #[test]
    fn test_portproxy_registry_detected() {
        let mut mock = MockArtifactProvider {
            caps: vec![ProviderCapability::RegistryKeys],
            ..MockArtifactProvider::default()
        };
        mock.add_registry_key(r"SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4", true);
        mock.add_registry_value(
            r"SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4",
            RegistryEntry {
                path: r"SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4".into(),
                name: "0.0.0.0/8080".into(),
                value: "10.0.0.5/80".into(),
                data_type: "REG_SZ".into(),
                timestamp: None,
            },
        );

        let scanner = TunnelingScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool_name, "netsh portproxy");
        assert_eq!(findings[0].category, RemoteAccessCategory::Tunneling);
        // Should have at least 2 artifacts: key existence + value
        assert!(
            findings[0].artifacts.len() >= 2,
            "expected >= 2 artifacts, got {}",
            findings[0].artifacts.len()
        );
    }

    #[test]
    fn test_no_tunneling_found() {
        let mock = MockArtifactProvider {
            caps: vec![
                ProviderCapability::PrefetchEntries,
                ProviderCapability::Services,
                ProviderCapability::RegistryKeys,
            ],
            ..MockArtifactProvider::default()
        };

        let scanner = TunnelingScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert!(
            findings.is_empty(),
            "expected no findings on empty mock, got {}",
            findings.len()
        );
    }

    #[test]
    fn test_cloudflared_service_detected() {
        let mut mock = MockArtifactProvider {
            caps: vec![
                ProviderCapability::PrefetchEntries,
                ProviderCapability::Services,
            ],
            ..MockArtifactProvider::default()
        };
        mock.add_service(crate::providers::ServiceEntry {
            name: "cloudflared".into(),
            display_name: "Cloudflare Argo Tunnel".into(),
            image_path: r"C:\Program Files\cloudflared\cloudflared.exe".into(),
            start_type: 2,
            service_type: 16,
            account: Some("LocalSystem".into()),
        });

        let scanner = TunnelingScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool_name, "cloudflared");
        assert!(!findings[0].artifacts.is_empty());
        assert_eq!(
            findings[0].artifacts[0].artifact_type,
            HitArtifactType::Service
        );
    }
}
