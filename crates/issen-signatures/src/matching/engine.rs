// Unified scan orchestrator.
//
// Coordinates all signature engines (YARA, Sigma, Hash IOC, Network IOC, STIX)
// behind a single API. Accepts files or byte buffers and returns a unified
// `ScanReport` with findings from all configured engines.

use std::collections::HashMap;
use std::path::Path;

use thiserror::Error;
use tracing::{debug, warn};

use crate::engines::ioc_hash::HashIocStore;
use crate::engines::ioc_network::NetworkIocStore;
use crate::engines::sigma::SigmaEngine;
use crate::engines::yara::YaraEngine;

use super::results::{MatchSource, ScanFinding, ScanReport, Severity};

/// Errors from the scan orchestrator.
#[derive(Debug, Error)]
pub enum ScanError {
    #[error("YARA error: {0}")]
    Yara(#[from] crate::engines::yara::YaraError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Unified scan engine that coordinates all signature engines.
///
/// Use the builder methods (`with_yara`, `with_sigma`, etc.) to configure
/// which engines are active. Then call `scan_file` or `scan_bytes` to
/// run all active engines and collect results.
pub struct ScanEngine {
    yara: Option<YaraEngine>,
    sigma: Option<SigmaEngine>,
    hash_stores: Vec<HashIocStore>,
    network_stores: Vec<NetworkIocStore>,
}

impl std::fmt::Debug for ScanEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanEngine")
            .field("yara", &self.yara.is_some())
            .field("sigma", &self.sigma.is_some())
            .field("hash_stores", &self.hash_stores.len())
            .field("network_stores", &self.network_stores.len())
            .finish()
    }
}

impl ScanEngine {
    /// Create a new empty scan engine with no engines configured.
    pub fn new() -> Self {
        Self {
            yara: None,
            sigma: None,
            hash_stores: Vec::new(),
            network_stores: Vec::new(),
        }
    }

    /// Configure the YARA engine.
    pub fn with_yara(mut self, engine: YaraEngine) -> Self {
        self.yara = Some(engine);
        self
    }

    /// Configure the Sigma engine.
    pub fn with_sigma(mut self, engine: SigmaEngine) -> Self {
        self.sigma = Some(engine);
        self
    }

    /// Add a hash IOC store.
    pub fn add_hash_store(&mut self, store: HashIocStore) {
        self.hash_stores.push(store);
    }

    /// Add a hash IOC store (builder pattern).
    pub fn with_hash_store(mut self, store: HashIocStore) -> Self {
        self.hash_stores.push(store);
        self
    }

    /// Add a network IOC store.
    pub fn add_network_store(&mut self, store: NetworkIocStore) {
        self.network_stores.push(store);
    }

    /// Add a network IOC store (builder pattern).
    pub fn with_network_store(mut self, store: NetworkIocStore) -> Self {
        self.network_stores.push(store);
        self
    }

    /// Scan a file on disk with all configured engines.
    ///
    /// This will:
    /// 1. Run YARA rules against the file (if configured)
    /// 2. Compute file hashes and check against hash IOC stores
    /// 3. Return a unified ScanReport
    pub fn scan_file(&self, path: &Path) -> Result<ScanReport, ScanError> {
        let target = path.display().to_string();
        let mut report = ScanReport::new(&target);

        debug!(target = %target, "starting file scan");

        // Read file contents for hash computation and YARA scanning.
        let data = std::fs::read(path)?;

        // 1. YARA scan.
        if let Some(yara) = &self.yara {
            match yara.scan_bytes(&data) {
                Ok(matches) => {
                    for m in matches {
                        report.add_finding(ScanFinding {
                            source: MatchSource::Yara,
                            severity: Severity::High,
                            rule_name: m.rule_name.clone(),
                            description: format!(
                                "YARA rule '{}' matched (tags: {})",
                                m.rule_name,
                                if m.tags.is_empty() {
                                    "none".to_string()
                                } else {
                                    m.tags.join(", ")
                                }
                            ),
                            matched_indicator: if m.strings_matched.is_empty() {
                                None
                            } else {
                                Some(m.strings_matched.join(", "))
                            },
                            tags: m.tags,
                        });
                    }
                }
                Err(e) => {
                    warn!(error = %e, "YARA scan failed");
                }
            }
        }

        // 2. Hash IOC check.
        self.check_hashes(&data, &mut report);

        debug!(
            target = %target,
            findings = report.finding_count(),
            "file scan complete"
        );

        Ok(report)
    }

    /// Scan in-memory bytes with all configured engines.
    ///
    /// Similar to `scan_file` but operates on a byte buffer. The `target`
    /// parameter is used for labeling the report.
    pub fn scan_bytes(&self, target: &str, data: &[u8]) -> Result<ScanReport, ScanError> {
        let mut report = ScanReport::new(target);

        // 1. YARA scan.
        if let Some(yara) = &self.yara {
            match yara.scan_bytes(data) {
                Ok(matches) => {
                    for m in matches {
                        report.add_finding(ScanFinding {
                            source: MatchSource::Yara,
                            severity: Severity::High,
                            rule_name: m.rule_name.clone(),
                            description: format!("YARA rule '{}' matched", m.rule_name),
                            matched_indicator: if m.strings_matched.is_empty() {
                                None
                            } else {
                                Some(m.strings_matched.join(", "))
                            },
                            tags: m.tags,
                        });
                    }
                }
                Err(e) => {
                    warn!(error = %e, "YARA scan failed");
                }
            }
        }

        // 2. Hash IOC check.
        self.check_hashes(data, &mut report);

        Ok(report)
    }

    /// Evaluate a log event against Sigma rules.
    ///
    /// This is separate from file scanning because Sigma operates on
    /// structured event data, not raw file bytes.
    pub fn evaluate_event(&self, event: &HashMap<String, serde_json::Value>) -> Vec<ScanFinding> {
        let mut findings = Vec::new();

        if let Some(sigma) = &self.sigma {
            for m in sigma.evaluate(event) {
                findings.push(ScanFinding {
                    source: MatchSource::Sigma,
                    severity: Severity::from_str_lossy(&m.level),
                    rule_name: m.rule_title.clone(),
                    description: m
                        .description
                        .unwrap_or_else(|| format!("Sigma rule '{}' matched", m.rule_title)),
                    matched_indicator: m.rule_id.clone(),
                    tags: m.tags,
                });
            }
        }

        findings
    }

    /// Check an IP address against all network IOC stores.
    ///
    /// `lookup_ip` on `NetworkIocStore` already checks both exact IP matches
    /// and CIDR containment, returning the match type in `indicator_type`.
    pub fn check_ip(&self, ip: &str) -> Vec<ScanFinding> {
        use crate::engines::ioc_network::IndicatorType;

        let mut findings = Vec::new();
        for store in &self.network_stores {
            if let Some(entry) = store.lookup_ip(ip) {
                let severity = match entry.indicator_type {
                    IndicatorType::Ip => Severity::High,
                    IndicatorType::Cidr => Severity::Medium,
                    _ => Severity::High,
                };
                let match_kind = match entry.indicator_type {
                    IndicatorType::Cidr => "cidr_match",
                    _ => "ip_match",
                };
                findings.push(ScanFinding {
                    source: MatchSource::NetworkIoc,
                    severity,
                    rule_name: format!("{}:{}", store.name(), match_kind),
                    description: format!(
                        "IP '{}' matched '{}' in feed '{}'",
                        ip,
                        entry.matched_against,
                        store.name()
                    ),
                    matched_indicator: Some(ip.to_string()),
                    tags: Vec::new(),
                });
            }
        }
        findings
    }

    /// Check a domain against all network IOC stores.
    pub fn check_domain(&self, domain: &str) -> Vec<ScanFinding> {
        let mut findings = Vec::new();
        for store in &self.network_stores {
            if let Some(entry) = store.lookup_domain(domain) {
                findings.push(ScanFinding {
                    source: MatchSource::NetworkIoc,
                    severity: Severity::High,
                    rule_name: format!("{}:domain_match", store.name()),
                    description: format!(
                        "Domain '{}' matched '{}' in feed '{}'",
                        domain,
                        entry.matched_against,
                        store.name()
                    ),
                    matched_indicator: Some(domain.to_string()),
                    tags: Vec::new(),
                });
            }
        }
        findings
    }

    /// Returns summary statistics about configured engines.
    pub fn stats(&self) -> ScanEngineStats {
        ScanEngineStats {
            yara_rules: self.yara.as_ref().map(|y| y.rule_count()).unwrap_or(0),
            sigma_rules: self.sigma.as_ref().map(|s| s.rule_count()).unwrap_or(0),
            hash_stores: self.hash_stores.len(),
            network_stores: self.network_stores.len(),
            total_bad_hashes: self.hash_stores.iter().map(|s| s.bad_count()).sum(),
            total_good_hashes: self.hash_stores.iter().map(|s| s.good_count()).sum(),
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────

    /// Compute SHA-256 and MD5 of data and check against all hash IOC stores.
    fn check_hashes(&self, data: &[u8], report: &mut ScanReport) {
        if self.hash_stores.is_empty() {
            return;
        }

        let sha256 = crate::engines::ioc_hash::sha256_hex(data);
        let md5 = crate::engines::ioc_hash::md5_hex(data);

        for store in &self.hash_stores {
            // Check SHA-256.
            if let Some(entry) = store.lookup_bad(&sha256) {
                // Filter out known-good hashes (NSRL).
                if !store.is_known_good(&sha256) {
                    report.add_finding(ScanFinding {
                        source: MatchSource::HashIoc,
                        severity: Severity::Critical,
                        rule_name: format!("{}:sha256_match", store.name()),
                        description: format!(
                            "SHA-256 hash matches known bad indicator in '{}'",
                            store.name()
                        ),
                        matched_indicator: Some(entry.hash.clone()),
                        tags: Vec::new(),
                    });
                }
            }

            // Check MD5.
            if let Some(entry) = store.lookup_bad(&md5) {
                if !store.is_known_good(&md5) {
                    report.add_finding(ScanFinding {
                        source: MatchSource::HashIoc,
                        severity: Severity::Critical,
                        rule_name: format!("{}:md5_match", store.name()),
                        description: format!(
                            "MD5 hash matches known bad indicator in '{}'",
                            store.name()
                        ),
                        matched_indicator: Some(entry.hash.clone()),
                        tags: Vec::new(),
                    });
                }
            }
        }
    }
}

impl Default for ScanEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary statistics about the scan engine configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanEngineStats {
    pub yara_rules: usize,
    pub sigma_rules: usize,
    pub hash_stores: usize,
    pub network_stores: usize,
    pub total_bad_hashes: usize,
    pub total_good_hashes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    // ── Empty engine ──────────────────────────────────────────────

    #[test]
    fn test_new_engine_is_empty() {
        let engine = ScanEngine::new();
        let stats = engine.stats();
        assert_eq!(stats.yara_rules, 0);
        assert_eq!(stats.sigma_rules, 0);
        assert_eq!(stats.hash_stores, 0);
        assert_eq!(stats.network_stores, 0);
    }

    #[test]
    fn test_scan_bytes_no_engines() {
        let engine = ScanEngine::new();
        let report = engine.scan_bytes("test", b"hello world").unwrap();
        assert_eq!(report.finding_count(), 0);
        assert!(!report.has_findings());
    }

    // ── YARA integration ──────────────────────────────────────────

    #[test]
    fn test_scan_bytes_yara_match() {
        let yara = YaraEngine::from_source(
            r#"rule test_malware { strings: $a = "malicious" condition: $a }"#,
        )
        .unwrap();

        let engine = ScanEngine::new().with_yara(yara);
        let report = engine
            .scan_bytes("test.bin", b"this is malicious content")
            .unwrap();

        assert_eq!(report.finding_count(), 1);
        let f = &report.findings[0];
        assert_eq!(f.source, MatchSource::Yara);
        assert_eq!(f.rule_name, "test_malware");
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn test_scan_bytes_yara_no_match() {
        let yara = YaraEngine::from_source(
            r#"rule test_malware { strings: $a = "malicious" condition: $a }"#,
        )
        .unwrap();

        let engine = ScanEngine::new().with_yara(yara);
        let report = engine
            .scan_bytes("test.bin", b"totally benign content")
            .unwrap();
        assert_eq!(report.finding_count(), 0);
    }

    #[test]
    fn test_scan_file_yara() {
        let yara =
            YaraEngine::from_source(r#"rule file_test { strings: $s = "payload" condition: $s }"#)
                .unwrap();

        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"deliver the payload now").unwrap();
        tmp.flush().unwrap();

        let engine = ScanEngine::new().with_yara(yara);
        let report = engine.scan_file(tmp.path()).unwrap();

        assert_eq!(report.finding_count(), 1);
        assert_eq!(report.findings[0].rule_name, "file_test");
    }

    // ── Hash IOC integration ──────────────────────────────────────

    #[test]
    fn test_scan_bytes_hash_match() {
        let data = b"known malware content";
        let sha256 = crate::engines::ioc_hash::sha256_hex(data);

        let mut store = HashIocStore::new("test-feed");
        store.inseissen_bad(&sha256).unwrap();

        let engine = ScanEngine::new().with_hash_store(store);
        let report = engine.scan_bytes("sample.bin", data).unwrap();

        assert!(report.has_findings());
        let hash_findings = report.findings_by_source(MatchSource::HashIoc);
        assert!(!hash_findings.is_empty());
        assert_eq!(hash_findings[0].severity, Severity::Critical);
        assert!(hash_findings[0].rule_name.contains("sha256_match"));
    }

    #[test]
    fn test_scan_bytes_hash_no_match() {
        let mut store = HashIocStore::new("test-feed");
        store
            .inseissen_bad("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .unwrap();

        let engine = ScanEngine::new().with_hash_store(store);
        let report = engine
            .scan_bytes("sample.bin", b"different content")
            .unwrap();

        let hash_findings = report.findings_by_source(MatchSource::HashIoc);
        assert!(hash_findings.is_empty());
    }

    #[test]
    fn test_scan_bytes_hash_filtered_by_known_good() {
        let data = b"known good system file";
        let sha256 = crate::engines::ioc_hash::sha256_hex(data);

        let mut store = HashIocStore::new("test-feed");
        store.inseissen_bad(&sha256).unwrap();
        store.inseissen_good(&sha256).unwrap(); // Also in known good list (NSRL).

        let engine = ScanEngine::new().with_hash_store(store);
        let report = engine.scan_bytes("system.dll", data).unwrap();

        // Should be filtered out because it's in the known good list.
        let hash_findings = report.findings_by_source(MatchSource::HashIoc);
        assert!(hash_findings.is_empty());
    }

    // ── Sigma integration ─────────────────────────────────────────

    #[test]
    fn test_evaluate_event_sigma_match() {
        let mut sigma = SigmaEngine::new();
        sigma
            .load_rule(
                r#"
title: Suspicious Login
id: sigma-test-001
level: high
detection:
    selection:
        EventType: login_failed
    condition: selection
"#,
            )
            .unwrap();

        let engine = ScanEngine::new().with_sigma(sigma);
        let event: HashMap<String, serde_json::Value> =
            [("EventType".to_string(), serde_json::json!("login_failed"))]
                .into_iter()
                .collect();

        let findings = engine.evaluate_event(&event);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source, MatchSource::Sigma);
        assert_eq!(findings[0].rule_name, "Suspicious Login");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_evaluate_event_sigma_no_match() {
        let mut sigma = SigmaEngine::new();
        sigma
            .load_rule(
                r#"
title: Suspicious Login
id: sigma-test-001
level: high
detection:
    selection:
        EventType: login_failed
    condition: selection
"#,
            )
            .unwrap();

        let engine = ScanEngine::new().with_sigma(sigma);
        let event: HashMap<String, serde_json::Value> =
            [("EventType".to_string(), serde_json::json!("login_success"))]
                .into_iter()
                .collect();

        let findings = engine.evaluate_event(&event);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_evaluate_event_no_sigma() {
        let engine = ScanEngine::new();
        let event: HashMap<String, serde_json::Value> = HashMap::new();
        let findings = engine.evaluate_event(&event);
        assert!(findings.is_empty());
    }

    // ── Network IOC integration ───────────────────────────────────

    #[test]
    fn test_check_ip_match() {
        let mut store = NetworkIocStore::new("c2-tracker");
        store.inseissen_ip("10.0.0.1").unwrap();

        let engine = ScanEngine::new().with_network_store(store);
        let findings = engine.check_ip("10.0.0.1");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source, MatchSource::NetworkIoc);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].matched_indicator.as_deref() == Some("10.0.0.1"));
    }

    #[test]
    fn test_check_ip_cidr_match() {
        let mut store = NetworkIocStore::new("bogon-list");
        store.inseissen_cidr("192.168.0.0/16").unwrap();

        let engine = ScanEngine::new().with_network_store(store);
        let findings = engine.check_ip("192.168.1.100");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium); // CIDR = Medium
    }

    #[test]
    fn test_check_ip_no_match() {
        let mut store = NetworkIocStore::new("c2-tracker");
        store.inseissen_ip("10.0.0.1").unwrap();

        let engine = ScanEngine::new().with_network_store(store);
        let findings = engine.check_ip("10.0.0.2");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_check_domain_match() {
        let mut store = NetworkIocStore::new("urlhaus");
        store.inseissen_domain("evil.com");

        let engine = ScanEngine::new().with_network_store(store);
        let findings = engine.check_domain("evil.com");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source, MatchSource::NetworkIoc);
        assert!(findings[0].matched_indicator.as_deref() == Some("evil.com"));
    }

    #[test]
    fn test_check_domain_subdomain_match() {
        let mut store = NetworkIocStore::new("urlhaus");
        store.inseissen_domain("evil.com");

        let engine = ScanEngine::new().with_network_store(store);
        let findings = engine.check_domain("malware.evil.com");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_check_domain_no_match() {
        let mut store = NetworkIocStore::new("urlhaus");
        store.inseissen_domain("evil.com");

        let engine = ScanEngine::new().with_network_store(store);
        let findings = engine.check_domain("good.com");
        assert!(findings.is_empty());
    }

    // ── Multi-engine combined scan ────────────────────────────────

    #[test]
    fn test_combined_yara_and_hash_scan() {
        // Data that triggers both YARA and hash IOC.
        let data = b"this file contains malicious payload";
        let sha256 = crate::engines::ioc_hash::sha256_hex(data);

        let yara = YaraEngine::from_source(
            r#"rule detect_payload { strings: $s = "malicious" condition: $s }"#,
        )
        .unwrap();

        let mut hash_store = HashIocStore::new("bazaar");
        hash_store.inseissen_bad(&sha256).unwrap();

        let engine = ScanEngine::new()
            .with_yara(yara)
            .with_hash_store(hash_store);

        let report = engine.scan_bytes("suspect.bin", data).unwrap();

        // Should have findings from BOTH engines.
        assert!(report.finding_count() >= 2);
        assert!(!report.findings_by_source(MatchSource::Yara).is_empty());
        assert!(!report.findings_by_source(MatchSource::HashIoc).is_empty());
        assert_eq!(report.max_severity(), Some(Severity::Critical));
    }

    #[test]
    fn test_multiple_hash_stores() {
        let data = b"multi-store test data";
        let sha256 = crate::engines::ioc_hash::sha256_hex(data);

        let mut store_a = HashIocStore::new("feed-a");
        store_a.inseissen_bad(&sha256).unwrap();

        let mut store_b = HashIocStore::new("feed-b");
        store_b.inseissen_bad(&sha256).unwrap();

        let engine = ScanEngine::new()
            .with_hash_store(store_a)
            .with_hash_store(store_b);

        let report = engine.scan_bytes("test.bin", data).unwrap();

        // Should get findings from both stores.
        let hash_findings = report.findings_by_source(MatchSource::HashIoc);
        assert!(hash_findings.len() >= 2);
    }

    #[test]
    fn test_multiple_network_stores() {
        let mut store_a = NetworkIocStore::new("feed-a");
        store_a.inseissen_ip("10.0.0.1").unwrap();

        let mut store_b = NetworkIocStore::new("feed-b");
        store_b.inseissen_ip("10.0.0.1").unwrap();

        let engine = ScanEngine::new()
            .with_network_store(store_a)
            .with_network_store(store_b);

        let findings = engine.check_ip("10.0.0.1");
        assert_eq!(findings.len(), 2);
    }

    // ── Stats ─────────────────────────────────────────────────────

    #[test]
    fn test_stats_with_engines() {
        let yara = YaraEngine::from_source(
            r#"rule r1 { strings: $s = "x" condition: $s }
               rule r2 { strings: $s = "y" condition: $s }"#,
        )
        .unwrap();

        let mut sigma = SigmaEngine::new();
        sigma
            .load_rule(
                r#"
title: Test
level: low
detection:
    selection:
        A: B
    condition: selection
"#,
            )
            .unwrap();

        let mut hash_store = HashIocStore::new("test");
        hash_store
            .inseissen_bad("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .unwrap();

        let engine = ScanEngine::new()
            .with_yara(yara)
            .with_sigma(sigma)
            .with_hash_store(hash_store);

        let stats = engine.stats();
        assert_eq!(stats.yara_rules, 2);
        assert_eq!(stats.sigma_rules, 1);
        assert_eq!(stats.hash_stores, 1);
        assert_eq!(stats.total_bad_hashes, 1);
    }

    // ── Builder pattern ───────────────────────────────────────────

    #[test]
    fn test_builder_pattern() {
        let engine = ScanEngine::new()
            .with_hash_store(HashIocStore::new("a"))
            .with_hash_store(HashIocStore::new("b"))
            .with_network_store(NetworkIocStore::new("c"));

        let stats = engine.stats();
        assert_eq!(stats.hash_stores, 2);
        assert_eq!(stats.network_stores, 1);
    }

    #[test]
    fn test_add_methods() {
        let mut engine = ScanEngine::new();
        engine.add_hash_store(HashIocStore::new("a"));
        engine.add_network_store(NetworkIocStore::new("b"));

        let stats = engine.stats();
        assert_eq!(stats.hash_stores, 1);
        assert_eq!(stats.network_stores, 1);
    }

    #[test]
    fn test_debug_format() {
        let engine = ScanEngine::new();
        let debug_str = format!("{:?}", engine);
        assert!(debug_str.contains("ScanEngine"));
    }
}
