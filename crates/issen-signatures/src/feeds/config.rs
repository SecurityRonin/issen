// Feed configuration and registry.
//
// Defines known threat intelligence feeds, their URLs, formats,
// and update schedules. Provides a registry for managing feed sources.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Format of a threat intel feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedFormat {
    /// One indicator per line (IP, domain, or hash).
    PlainText,
    /// CSV with configurable column index.
    Csv,
    /// JSON array or STIX bundle.
    Json,
    /// STIX 2.1 JSON bundle.
    Stix,
    /// YARA rule files.
    Yara,
    /// Sigma rule YAML files.
    Sigma,
}

/// Type of indicators provided by a feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedIndicatorType {
    /// File hashes (MD5, SHA1, SHA256).
    Hash,
    /// IP addresses and CIDR ranges.
    Ip,
    /// Domain names.
    Domain,
    /// URLs.
    Url,
    /// Mixed indicator types.
    Mixed,
    /// YARA rules (not indicators, but detection rules).
    YaraRules,
    /// Sigma detection rules.
    SigmaRules,
}

/// Update frequency for a feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateFrequency {
    /// Updated every few minutes.
    Realtime,
    /// Updated hourly.
    Hourly,
    /// Updated daily.
    Daily,
    /// Updated weekly.
    Weekly,
    /// Updated monthly or less.
    Monthly,
    /// Manual update only.
    Manual,
}

/// Configuration for a single threat intelligence feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedConfig {
    /// Unique identifier for this feed.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Description of the feed.
    pub description: String,
    /// URL to fetch the feed from (None for local-only feeds).
    pub url: Option<String>,
    /// Format of the feed data.
    pub format: FeedFormat,
    /// Type of indicators in the feed.
    pub indicator_type: FeedIndicatorType,
    /// Update frequency.
    pub update_frequency: UpdateFrequency,
    /// Whether this feed is enabled by default.
    pub enabled: bool,
    /// Whether an API key is required.
    pub requires_api_key: bool,
    /// For CSV feeds: which column contains the indicator (0-indexed).
    pub csv_column: Option<usize>,
    /// License/attribution information.
    pub license: Option<String>,
}

/// Registry of all known/configured feeds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedRegistry {
    pub feeds: Vec<FeedConfig>,
    /// Base directory for cached feed data.
    pub cache_dir: PathBuf,
}

impl FeedRegistry {
    /// Create a new registry with the given cache directory.
    #[must_use]
    pub fn new(cache_dir: impl Into<PathBuf>) -> Self {
        Self {
            feeds: Vec::new(),
            cache_dir: cache_dir.into(),
        }
    }

    /// Create a registry pre-loaded with all known free feeds.
    #[must_use]
    pub fn with_defaults(cache_dir: impl Into<PathBuf>) -> Self {
        let mut registry = Self::new(cache_dir);
        registry.feeds = default_feeds();
        registry
    }

    /// Add a custom feed configuration.
    pub fn add_feed(&mut self, config: FeedConfig) {
        self.feeds.push(config);
    }

    /// Get all enabled feeds.
    #[must_use]
    pub fn enabled_feeds(&self) -> Vec<&FeedConfig> {
        self.feeds.iter().filter(|f| f.enabled).collect()
    }

    /// Get feeds by indicator type.
    #[must_use]
    pub fn feeds_by_type(&self, indicator_type: FeedIndicatorType) -> Vec<&FeedConfig> {
        self.feeds
            .iter()
            .filter(|f| f.indicator_type == indicator_type)
            .collect()
    }

    /// Find a feed by ID.
    #[must_use]
    pub fn find_feed(&self, id: &str) -> Option<&FeedConfig> {
        self.feeds.iter().find(|f| f.id == id)
    }

    /// Get the local cache path for a feed.
    #[must_use]
    pub fn cache_path(&self, feed_id: &str) -> PathBuf {
        self.cache_dir.join(feed_id)
    }

    /// Number of feeds in the registry.
    #[must_use]
    pub fn len(&self) -> usize {
        self.feeds.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.feeds.is_empty()
    }

    /// Load a registry from a YAML config file.
    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("Failed to read config: {e}"))?;
        serde_yaml::from_str(&content).map_err(|e| format!("Failed to parse config: {e}"))
    }

    /// Save the registry to a YAML config file.
    pub fn save_to_file(&self, path: &Path) -> Result<(), String> {
        let content =
            serde_yaml::to_string(self).map_err(|e| format!("Failed to serialize config: {e}"))?;
        std::fs::write(path, content).map_err(|e| format!("Failed to write config: {e}"))
    }
}

/// Default feed configurations for well-known free threat intel sources.
#[must_use]
fn default_feeds() -> Vec<FeedConfig> {
    vec![
        // === Hash-based feeds ===
        FeedConfig {
            id: "abusech-malwarebazaar-recent".into(),
            name: "MalwareBazaar Recent Hashes".into(),
            description: "Recent malware sample hashes from abuse.ch MalwareBazaar".into(),
            url: Some("https://bazaar.abuse.ch/export/txt/sha256/recent/".into()),
            format: FeedFormat::PlainText,
            indicator_type: FeedIndicatorType::Hash,
            update_frequency: UpdateFrequency::Hourly,
            enabled: true,
            requires_api_key: false,
            csv_column: None,
            license: Some("CC0 1.0".into()),
        },
        // === IP-based feeds ===
        FeedConfig {
            id: "abusech-feodo-ipblocklist".into(),
            name: "Feodo Tracker IP Blocklist".into(),
            description: "Botnet C2 IP addresses tracked by abuse.ch".into(),
            url: Some("https://feodotracker.abuse.ch/downloads/ipblocklist.txt".into()),
            format: FeedFormat::PlainText,
            indicator_type: FeedIndicatorType::Ip,
            update_frequency: UpdateFrequency::Realtime,
            enabled: true,
            requires_api_key: false,
            csv_column: None,
            license: Some("CC0 1.0".into()),
        },
        FeedConfig {
            id: "spamhaus-drop".into(),
            name: "Spamhaus DROP List".into(),
            description: "Hijacked IP ranges that should be dropped".into(),
            url: Some("https://www.spamhaus.org/drop/drop.txt".into()),
            format: FeedFormat::PlainText,
            indicator_type: FeedIndicatorType::Ip,
            update_frequency: UpdateFrequency::Daily,
            enabled: true,
            requires_api_key: false,
            csv_column: None,
            license: Some("Spamhaus non-commercial".into()),
        },
        FeedConfig {
            id: "ipsum-level3".into(),
            name: "IPsum Level 3+".into(),
            description: "Aggregated malicious IPs (appears in 3+ blacklists)".into(),
            url: Some("https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt".into()),
            format: FeedFormat::PlainText,
            indicator_type: FeedIndicatorType::Ip,
            update_frequency: UpdateFrequency::Daily,
            enabled: true,
            requires_api_key: false,
            csv_column: None,
            license: Some("MIT".into()),
        },
        FeedConfig {
            id: "tor-exit-nodes".into(),
            name: "Tor Exit Nodes".into(),
            description: "Current Tor exit node IP addresses".into(),
            url: Some("https://check.torproject.org/torbulkexitlist".into()),
            format: FeedFormat::PlainText,
            indicator_type: FeedIndicatorType::Ip,
            update_frequency: UpdateFrequency::Hourly,
            enabled: true,
            requires_api_key: false,
            csv_column: None,
            license: Some("Public".into()),
        },
        FeedConfig {
            id: "c2-tracker".into(),
            name: "C2 Tracker".into(),
            description: "Active C2 server IPs (Cobalt Strike, Sliver, etc.)".into(),
            url: Some("https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/all.txt".into()),
            format: FeedFormat::PlainText,
            indicator_type: FeedIndicatorType::Ip,
            update_frequency: UpdateFrequency::Weekly,
            enabled: true,
            requires_api_key: false,
            csv_column: None,
            license: Some("MIT".into()),
        },
        // === Domain-based feeds ===
        FeedConfig {
            id: "abusech-urlhaus-domains".into(),
            name: "URLhaus Malware Distribution Domains".into(),
            description: "Domains used for malware distribution from abuse.ch".into(),
            url: Some("https://urlhaus.abuse.ch/downloads/text_online/".into()),
            format: FeedFormat::PlainText,
            indicator_type: FeedIndicatorType::Url,
            update_frequency: UpdateFrequency::Realtime,
            enabled: true,
            requires_api_key: false,
            csv_column: None,
            license: Some("CC0 1.0".into()),
        },
        FeedConfig {
            id: "abusech-threatfox-iocs".into(),
            name: "ThreatFox IOCs (CSV)".into(),
            description: "Mixed IOCs from abuse.ch ThreatFox".into(),
            url: Some("https://threatfox.abuse.ch/export/csv/recent/".into()),
            format: FeedFormat::Csv,
            indicator_type: FeedIndicatorType::Mixed,
            update_frequency: UpdateFrequency::Hourly,
            enabled: true,
            requires_api_key: false,
            csv_column: Some(2),
            license: Some("CC0 1.0".into()),
        },
        // === STIX feeds ===
        FeedConfig {
            id: "mitre-attack-enterprise".into(),
            name: "MITRE ATT&CK Enterprise".into(),
            description: "MITRE ATT&CK Enterprise techniques, groups, and software".into(),
            url: Some("https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json".into()),
            format: FeedFormat::Stix,
            indicator_type: FeedIndicatorType::Mixed,
            update_frequency: UpdateFrequency::Monthly,
            enabled: false, // large file, enable manually
            requires_api_key: false,
            csv_column: None,
            license: Some("Apache 2.0".into()),
        },
        // === Government feeds ===
        FeedConfig {
            id: "cisa-kev".into(),
            name: "CISA Known Exploited Vulnerabilities".into(),
            description: "CVEs with known active exploitation".into(),
            url: Some("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json".into()),
            format: FeedFormat::Json,
            indicator_type: FeedIndicatorType::Mixed,
            update_frequency: UpdateFrequency::Daily,
            enabled: true,
            requires_api_key: false,
            csv_column: None,
            license: Some("Public Domain".into()),
        },
        // === YARA rule feeds ===
        FeedConfig {
            id: "yara-forge-core".into(),
            name: "YARA Forge Core Rules".into(),
            description: "Quality-checked YARA rules from 70+ repositories".into(),
            url: Some("https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip".into()),
            format: FeedFormat::Yara,
            indicator_type: FeedIndicatorType::YaraRules,
            update_frequency: UpdateFrequency::Monthly,
            enabled: false,
            requires_api_key: false,
            csv_column: None,
            license: Some("Various".into()),
        },
        // === Sigma rule feeds ===
        FeedConfig {
            id: "sigmahq-core".into(),
            name: "SigmaHQ Core Rules".into(),
            description: "Core Sigma detection rules (~3,100 rules)".into(),
            url: Some("https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_core.zip".into()),
            format: FeedFormat::Sigma,
            indicator_type: FeedIndicatorType::SigmaRules,
            update_frequency: UpdateFrequency::Monthly,
            enabled: false,
            requires_api_key: false,
            csv_column: None,
            license: Some("LGPL-2.1".into()),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_feeds_not_empty() {
        let feeds = default_feeds();
        assert!(!feeds.is_empty());
        assert!(feeds.len() >= 10, "Should have at least 10 default feeds");
    }

    #[test]
    fn test_registry_with_defaults() {
        let registry = FeedRegistry::with_defaults("/tmp/feeds");
        assert!(!registry.is_empty());
        assert!(registry.len() >= 10);
    }

    #[test]
    fn test_registry_enabled_feeds() {
        let registry = FeedRegistry::with_defaults("/tmp/feeds");
        let enabled = registry.enabled_feeds();
        // At least some feeds should be enabled by default.
        assert!(!enabled.is_empty());
        // All returned feeds should be enabled.
        for feed in &enabled {
            assert!(feed.enabled);
        }
    }

    #[test]
    fn test_registry_feeds_by_type() {
        let registry = FeedRegistry::with_defaults("/tmp/feeds");
        let ip_feeds = registry.feeds_by_type(FeedIndicatorType::Ip);
        assert!(!ip_feeds.is_empty());
        for feed in &ip_feeds {
            assert_eq!(feed.indicator_type, FeedIndicatorType::Ip);
        }
    }

    #[test]
    fn test_registry_find_feed() {
        let registry = FeedRegistry::with_defaults("/tmp/feeds");
        let feed = registry.find_feed("abusech-feodo-ipblocklist");
        assert!(feed.is_some());
        assert_eq!(feed.expect("feed").name, "Feodo Tracker IP Blocklist");
    }

    #[test]
    fn test_registry_find_feed_miss() {
        let registry = FeedRegistry::with_defaults("/tmp/feeds");
        assert!(registry.find_feed("nonexistent-feed").is_none());
    }

    #[test]
    fn test_registry_cache_path() {
        let registry = FeedRegistry::with_defaults("/tmp/feeds");
        let path = registry.cache_path("abusech-feodo-ipblocklist");
        assert_eq!(path, PathBuf::from("/tmp/feeds/abusech-feodo-ipblocklist"));
    }

    #[test]
    fn test_registry_add_custom_feed() {
        let mut registry = FeedRegistry::new("/tmp/feeds");
        assert!(registry.is_empty());

        registry.add_feed(FeedConfig {
            id: "custom-feed".into(),
            name: "My Custom Feed".into(),
            description: "A custom threat feed".into(),
            url: Some("https://example.com/feed.txt".into()),
            format: FeedFormat::PlainText,
            indicator_type: FeedIndicatorType::Ip,
            update_frequency: UpdateFrequency::Daily,
            enabled: true,
            requires_api_key: false,
            csv_column: None,
            license: None,
        });

        assert_eq!(registry.len(), 1);
        assert!(registry.find_feed("custom-feed").is_some());
    }

    #[test]
    fn test_registry_serde_roundtrip() {
        let registry = FeedRegistry::with_defaults("/tmp/feeds");
        let yaml = serde_yaml::to_string(&registry).expect("serialize");
        let parsed: FeedRegistry = serde_yaml::from_str(&yaml).expect("deserialize");
        assert_eq!(parsed.len(), registry.len());
        assert_eq!(parsed.cache_dir, registry.cache_dir);
    }

    #[test]
    fn test_registry_save_and_load() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let config_path = dir.path().join("feeds.yml");

        let registry = FeedRegistry::with_defaults(dir.path().join("cache"));
        registry.save_to_file(&config_path).expect("save");

        let loaded = FeedRegistry::load_from_file(&config_path).expect("load");
        assert_eq!(loaded.len(), registry.len());
    }

    #[test]
    fn test_all_default_feeds_have_required_fields() {
        let feeds = default_feeds();
        for feed in &feeds {
            assert!(!feed.id.is_empty(), "Feed ID must not be empty");
            assert!(!feed.name.is_empty(), "Feed name must not be empty");
            assert!(
                !feed.description.is_empty(),
                "Feed description must not be empty"
            );
        }
    }

    #[test]
    fn test_no_api_key_feeds() {
        let feeds = default_feeds();
        let no_key: Vec<_> = feeds.iter().filter(|f| !f.requires_api_key).collect();
        // All our default feeds should be free (no API key).
        assert_eq!(no_key.len(), feeds.len());
    }
}
