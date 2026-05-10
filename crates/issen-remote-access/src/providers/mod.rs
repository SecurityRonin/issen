//! Pluggable artifact provider abstraction.
//!
//! The [`ArtifactProvider`] trait defines a uniform interface for querying
//! forensic artifacts (registry keys, event logs, prefetch entries, etc.).
//! Detection rules program against this trait rather than concrete data
//! sources, which enables:
//!
//! - **Graceful degradation** when a parser is unavailable.
//! - **Easy unit testing** via [`MockArtifactProvider`].
//! - **Composition** via [`CompositeArtifactProvider`] that delegates to
//!   the first sub-provider advertising the required capability.

pub mod filesystem;

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Capability enum
// ---------------------------------------------------------------------------

/// Capabilities a provider can advertise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderCapability {
    RegistryKeys,
    FilePresence,
    EventLogs,
    PrefetchEntries,
    AmcacheEntries,
    Services,
    ScheduledTasks,
    LnkFiles,
    Jumplists,
    ShimCache,
    BamDam,
    UserAssist,
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by provider methods.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// The provider does not support this capability.
    #[error("capability not available")]
    NotAvailable,
    /// An internal error occurred.
    #[error("internal error: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// Entry types
// ---------------------------------------------------------------------------

/// A single registry value entry.
#[derive(Debug, Clone)]
pub struct RegistryEntry {
    pub path: String,
    pub name: String,
    pub value: String,
    pub data_type: String,
    pub timestamp: Option<i64>,
}

/// A file entry with optional metadata.
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub path: String,
    pub size: Option<u64>,
    pub created: Option<i64>,
    pub modified: Option<i64>,
}

/// Query parameters for event log searches.
#[derive(Debug, Clone)]
pub struct EventLogQuery {
    pub event_id: Option<u32>,
    pub provider_name: Option<String>,
    pub log_file: Option<String>,
    pub keyword: Option<String>,
}

/// A single event log entry.
#[derive(Debug, Clone)]
pub struct EventLogEntry {
    pub event_id: u32,
    pub provider_name: String,
    pub log_file: String,
    pub timestamp: Option<i64>,
    pub data: HashMap<String, String>,
}

/// A prefetch file entry.
#[derive(Debug, Clone)]
pub struct PrefetchEntry {
    pub executable_name: String,
    pub run_count: u32,
    pub last_run: Option<i64>,
    pub path: String,
}

/// An Amcache entry.
#[derive(Debug, Clone)]
pub struct AmcacheEntry {
    pub program_name: String,
    pub file_path: Option<String>,
    pub sha1: Option<String>,
    pub install_date: Option<i64>,
    pub link_date: Option<i64>,
}

/// A Windows service entry.
#[derive(Debug, Clone)]
pub struct ServiceEntry {
    pub name: String,
    pub display_name: String,
    pub image_path: String,
    pub start_type: u32,
    pub service_type: u32,
    pub account: Option<String>,
}

/// A scheduled task entry.
#[derive(Debug, Clone)]
pub struct ScheduledTaskEntry {
    pub name: String,
    pub command: String,
    pub arguments: Option<String>,
    pub trigger_description: Option<String>,
    pub principal: Option<String>,
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// ArtifactProvider trait
// ---------------------------------------------------------------------------

/// Uniform interface for querying forensic artifacts.
///
/// Every method has a default implementation that returns
/// [`ProviderError::NotAvailable`], so concrete providers only need to
/// override the methods they actually support.
#[allow(unused_variables)]
pub trait ArtifactProvider: Send + Sync {
    /// Returns the set of capabilities this provider supports.
    fn capabilities(&self) -> Vec<ProviderCapability>;

    // -- Registry --------------------------------------------------------

    /// Check whether a registry key exists.
    ///
    /// # Errors
    /// Returns [`ProviderError::NotAvailable`] if unsupported, or
    /// [`ProviderError::Internal`] on failure.
    fn registry_key_exists(&self, path: &str) -> Result<bool, ProviderError> {
        Err(ProviderError::NotAvailable)
    }

    /// Return all values under a registry key.
    ///
    /// # Errors
    /// Returns [`ProviderError::NotAvailable`] if unsupported, or
    /// [`ProviderError::Internal`] on failure.
    fn registry_values(&self, path: &str) -> Result<Vec<RegistryEntry>, ProviderError> {
        Err(ProviderError::NotAvailable)
    }

    /// Return subkey names under a registry key.
    ///
    /// # Errors
    /// Returns [`ProviderError::NotAvailable`] if unsupported, or
    /// [`ProviderError::Internal`] on failure.
    fn registry_subkeys(&self, path: &str) -> Result<Vec<String>, ProviderError> {
        Err(ProviderError::NotAvailable)
    }

    // -- File system -----------------------------------------------------

    /// Return files matching a glob-style path pattern.
    ///
    /// # Errors
    /// Returns [`ProviderError::NotAvailable`] if unsupported, or
    /// [`ProviderError::Internal`] on failure.
    fn file_exists(&self, pattern: &str) -> Result<Vec<FileEntry>, ProviderError> {
        Err(ProviderError::NotAvailable)
    }

    // -- Event logs ------------------------------------------------------

    /// Search event logs matching the given query.
    ///
    /// # Errors
    /// Returns [`ProviderError::NotAvailable`] if unsupported, or
    /// [`ProviderError::Internal`] on failure.
    fn event_log_search(&self, query: &EventLogQuery) -> Result<Vec<EventLogEntry>, ProviderError> {
        Err(ProviderError::NotAvailable)
    }

    // -- Prefetch --------------------------------------------------------

    /// Return all prefetch entries.
    ///
    /// # Errors
    /// Returns [`ProviderError::NotAvailable`] if unsupported, or
    /// [`ProviderError::Internal`] on failure.
    fn prefetch_entries(&self) -> Result<Vec<PrefetchEntry>, ProviderError> {
        Err(ProviderError::NotAvailable)
    }

    // -- Amcache ---------------------------------------------------------

    /// Return all Amcache entries.
    ///
    /// # Errors
    /// Returns [`ProviderError::NotAvailable`] if unsupported, or
    /// [`ProviderError::Internal`] on failure.
    fn amcache_entries(&self) -> Result<Vec<AmcacheEntry>, ProviderError> {
        Err(ProviderError::NotAvailable)
    }

    // -- ShimCache -------------------------------------------------------

    /// Return `ShimCache` entries as executable paths.
    ///
    /// # Errors
    /// Returns [`ProviderError::NotAvailable`] if unsupported, or
    /// [`ProviderError::Internal`] on failure.
    fn shimcache_entries(&self) -> Result<Vec<String>, ProviderError> {
        Err(ProviderError::NotAvailable)
    }

    // -- BAM/DAM ---------------------------------------------------------

    /// Return BAM/DAM entries as `(executable_path, timestamp)` pairs.
    ///
    /// # Errors
    /// Returns [`ProviderError::NotAvailable`] if unsupported, or
    /// [`ProviderError::Internal`] on failure.
    fn bam_entries(&self) -> Result<Vec<(String, i64)>, ProviderError> {
        Err(ProviderError::NotAvailable)
    }

    // -- UserAssist ------------------------------------------------------

    /// Return `UserAssist` entries as `(program, run_count, last_run)` tuples.
    ///
    /// # Errors
    /// Returns [`ProviderError::NotAvailable`] if unsupported, or
    /// [`ProviderError::Internal`] on failure.
    fn userassist_entries(&self) -> Result<Vec<(String, u32, Option<i64>)>, ProviderError> {
        Err(ProviderError::NotAvailable)
    }

    // -- Services --------------------------------------------------------

    /// Return all Windows service entries.
    ///
    /// # Errors
    /// Returns [`ProviderError::NotAvailable`] if unsupported, or
    /// [`ProviderError::Internal`] on failure.
    fn services(&self) -> Result<Vec<ServiceEntry>, ProviderError> {
        Err(ProviderError::NotAvailable)
    }

    // -- Scheduled tasks -------------------------------------------------

    /// Return all scheduled task entries.
    ///
    /// # Errors
    /// Returns [`ProviderError::NotAvailable`] if unsupported, or
    /// [`ProviderError::Internal`] on failure.
    fn scheduled_tasks(&self) -> Result<Vec<ScheduledTaskEntry>, ProviderError> {
        Err(ProviderError::NotAvailable)
    }
}

// ---------------------------------------------------------------------------
// CompositeArtifactProvider
// ---------------------------------------------------------------------------

/// Delegates each query to the first sub-provider that advertises the
/// required [`ProviderCapability`].
pub struct CompositeArtifactProvider {
    providers: Vec<Box<dyn ArtifactProvider>>,
}

impl CompositeArtifactProvider {
    /// Create an empty composite provider.
    #[must_use]
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    /// Add a sub-provider.
    pub fn add_provider(&mut self, provider: Box<dyn ArtifactProvider>) {
        self.providers.push(provider);
    }

    /// Find the first sub-provider advertising `cap`.
    fn provider_for(&self, cap: ProviderCapability) -> Option<&dyn ArtifactProvider> {
        self.providers
            .iter()
            .find(|p| p.capabilities().contains(&cap))
            .map(AsRef::as_ref)
    }
}

impl Default for CompositeArtifactProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactProvider for CompositeArtifactProvider {
    fn capabilities(&self) -> Vec<ProviderCapability> {
        let mut caps = Vec::new();
        for p in &self.providers {
            for cap in p.capabilities() {
                if !caps.contains(&cap) {
                    caps.push(cap);
                }
            }
        }
        caps
    }

    fn registry_key_exists(&self, path: &str) -> Result<bool, ProviderError> {
        self.provider_for(ProviderCapability::RegistryKeys)
            .map_or(Err(ProviderError::NotAvailable), |p| {
                p.registry_key_exists(path)
            })
    }

    fn registry_values(&self, path: &str) -> Result<Vec<RegistryEntry>, ProviderError> {
        self.provider_for(ProviderCapability::RegistryKeys)
            .map_or(Err(ProviderError::NotAvailable), |p| {
                p.registry_values(path)
            })
    }

    fn registry_subkeys(&self, path: &str) -> Result<Vec<String>, ProviderError> {
        self.provider_for(ProviderCapability::RegistryKeys)
            .map_or(Err(ProviderError::NotAvailable), |p| {
                p.registry_subkeys(path)
            })
    }

    fn file_exists(&self, pattern: &str) -> Result<Vec<FileEntry>, ProviderError> {
        self.provider_for(ProviderCapability::FilePresence)
            .map_or(Err(ProviderError::NotAvailable), |p| p.file_exists(pattern))
    }

    fn event_log_search(&self, query: &EventLogQuery) -> Result<Vec<EventLogEntry>, ProviderError> {
        self.provider_for(ProviderCapability::EventLogs)
            .map_or(Err(ProviderError::NotAvailable), |p| {
                p.event_log_search(query)
            })
    }

    fn prefetch_entries(&self) -> Result<Vec<PrefetchEntry>, ProviderError> {
        self.provider_for(ProviderCapability::PrefetchEntries)
            .map_or(
                Err(ProviderError::NotAvailable),
                ArtifactProvider::prefetch_entries,
            )
    }

    fn amcache_entries(&self) -> Result<Vec<AmcacheEntry>, ProviderError> {
        self.provider_for(ProviderCapability::AmcacheEntries)
            .map_or(
                Err(ProviderError::NotAvailable),
                ArtifactProvider::amcache_entries,
            )
    }

    fn shimcache_entries(&self) -> Result<Vec<String>, ProviderError> {
        self.provider_for(ProviderCapability::ShimCache).map_or(
            Err(ProviderError::NotAvailable),
            ArtifactProvider::shimcache_entries,
        )
    }

    fn bam_entries(&self) -> Result<Vec<(String, i64)>, ProviderError> {
        self.provider_for(ProviderCapability::BamDam).map_or(
            Err(ProviderError::NotAvailable),
            ArtifactProvider::bam_entries,
        )
    }

    fn userassist_entries(&self) -> Result<Vec<(String, u32, Option<i64>)>, ProviderError> {
        self.provider_for(ProviderCapability::UserAssist).map_or(
            Err(ProviderError::NotAvailable),
            ArtifactProvider::userassist_entries,
        )
    }

    fn services(&self) -> Result<Vec<ServiceEntry>, ProviderError> {
        self.provider_for(ProviderCapability::Services)
            .map_or(Err(ProviderError::NotAvailable), ArtifactProvider::services)
    }

    fn scheduled_tasks(&self) -> Result<Vec<ScheduledTaskEntry>, ProviderError> {
        self.provider_for(ProviderCapability::ScheduledTasks)
            .map_or(
                Err(ProviderError::NotAvailable),
                ArtifactProvider::scheduled_tasks,
            )
    }
}

// ---------------------------------------------------------------------------
// MockArtifactProvider (test-only)
// ---------------------------------------------------------------------------

/// A configurable mock provider for unit tests.
///
/// Gated behind `cfg(test)` or the `test-utils` feature so it never
/// appears in release builds.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Debug, Default)]
pub struct MockArtifactProvider {
    pub caps: Vec<ProviderCapability>,
    pub registry_keys: HashMap<String, bool>,
    pub registry_values: HashMap<String, Vec<RegistryEntry>>,
    pub registry_subkeys: HashMap<String, Vec<String>>,
    pub files: HashMap<String, Vec<FileEntry>>,
    pub event_logs: Vec<EventLogEntry>,
    pub prefetch: Vec<PrefetchEntry>,
    pub amcache: Vec<AmcacheEntry>,
    pub services: Vec<ServiceEntry>,
    pub scheduled_tasks: Vec<ScheduledTaskEntry>,
}

#[cfg(any(test, feature = "test-utils"))]
impl MockArtifactProvider {
    /// Add a registry key existence entry.
    pub fn add_registry_key(&mut self, path: &str, exists: bool) -> &mut Self {
        self.registry_keys.insert(path.to_owned(), exists);
        self
    }

    /// Add registry values for a key path.
    pub fn add_registry_value(&mut self, path: &str, entry: RegistryEntry) -> &mut Self {
        self.registry_values
            .entry(path.to_owned())
            .or_default()
            .push(entry);
        self
    }

    /// Add subkey names for a key path.
    pub fn add_registry_subkeys(&mut self, path: &str, subkeys: Vec<String>) -> &mut Self {
        self.registry_subkeys.insert(path.to_owned(), subkeys);
        self
    }

    /// Add file entries for a pattern.
    pub fn add_file(&mut self, pattern: &str, entry: FileEntry) -> &mut Self {
        self.files
            .entry(pattern.to_owned())
            .or_default()
            .push(entry);
        self
    }

    /// Add an event log entry.
    pub fn add_event_log(&mut self, entry: EventLogEntry) -> &mut Self {
        self.event_logs.push(entry);
        self
    }

    /// Add a prefetch entry.
    pub fn add_prefetch(&mut self, entry: PrefetchEntry) -> &mut Self {
        self.prefetch.push(entry);
        self
    }

    /// Add an Amcache entry.
    pub fn add_amcache(&mut self, entry: AmcacheEntry) -> &mut Self {
        self.amcache.push(entry);
        self
    }

    /// Add a service entry.
    pub fn add_service(&mut self, entry: ServiceEntry) -> &mut Self {
        self.services.push(entry);
        self
    }

    /// Add a scheduled task entry.
    pub fn add_scheduled_task(&mut self, entry: ScheduledTaskEntry) -> &mut Self {
        self.scheduled_tasks.push(entry);
        self
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl ArtifactProvider for MockArtifactProvider {
    fn capabilities(&self) -> Vec<ProviderCapability> {
        self.caps.clone()
    }

    fn registry_key_exists(&self, path: &str) -> Result<bool, ProviderError> {
        Ok(self.registry_keys.get(path).copied().unwrap_or(false))
    }

    fn registry_values(&self, path: &str) -> Result<Vec<RegistryEntry>, ProviderError> {
        Ok(self.registry_values.get(path).cloned().unwrap_or_default())
    }

    fn registry_subkeys(&self, path: &str) -> Result<Vec<String>, ProviderError> {
        Ok(self.registry_subkeys.get(path).cloned().unwrap_or_default())
    }

    fn file_exists(&self, pattern: &str) -> Result<Vec<FileEntry>, ProviderError> {
        Ok(self.files.get(pattern).cloned().unwrap_or_default())
    }

    fn event_log_search(&self, query: &EventLogQuery) -> Result<Vec<EventLogEntry>, ProviderError> {
        let results = self
            .event_logs
            .iter()
            .filter(|e| {
                if let Some(id) = query.event_id {
                    if e.event_id != id {
                        return false;
                    }
                }
                if let Some(ref pn) = query.provider_name {
                    if e.provider_name != *pn {
                        return false;
                    }
                }
                if let Some(ref lf) = query.log_file {
                    if e.log_file != *lf {
                        return false;
                    }
                }
                if let Some(ref kw) = query.keyword {
                    let has_keyword = e.data.values().any(|v| v.contains(kw.as_str()));
                    if !has_keyword {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();
        Ok(results)
    }

    fn prefetch_entries(&self) -> Result<Vec<PrefetchEntry>, ProviderError> {
        Ok(self.prefetch.clone())
    }

    fn amcache_entries(&self) -> Result<Vec<AmcacheEntry>, ProviderError> {
        Ok(self.amcache.clone())
    }

    fn shimcache_entries(&self) -> Result<Vec<String>, ProviderError> {
        Ok(Vec::new())
    }

    fn bam_entries(&self) -> Result<Vec<(String, i64)>, ProviderError> {
        Ok(Vec::new())
    }

    fn userassist_entries(&self) -> Result<Vec<(String, u32, Option<i64>)>, ProviderError> {
        Ok(Vec::new())
    }

    fn services(&self) -> Result<Vec<ServiceEntry>, ProviderError> {
        Ok(self.services.clone())
    }

    fn scheduled_tasks(&self) -> Result<Vec<ScheduledTaskEntry>, ProviderError> {
        Ok(self.scheduled_tasks.clone())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_composite_has_no_capabilities() {
        let composite = CompositeArtifactProvider::new();
        assert!(composite.capabilities().is_empty());
    }

    #[test]
    fn test_composite_returns_not_available_without_providers() {
        let composite = CompositeArtifactProvider::new();
        assert!(composite.registry_key_exists("HKLM\\SOFTWARE").is_err());
        assert!(composite.file_exists("*.exe").is_err());
        assert!(composite.prefetch_entries().is_err());
        assert!(composite.amcache_entries().is_err());
        assert!(composite.services().is_err());
        assert!(composite.scheduled_tasks().is_err());
        assert!(composite.shimcache_entries().is_err());
        assert!(composite.bam_entries().is_err());
        assert!(composite.userassist_entries().is_err());
    }

    #[test]
    fn test_mock_provider_registry() {
        let mut mock = MockArtifactProvider {
            caps: vec![ProviderCapability::RegistryKeys],
            ..MockArtifactProvider::default()
        };
        mock.add_registry_key(r"HKLM\SOFTWARE\TeamViewer", true);
        mock.add_registry_value(
            r"HKLM\SOFTWARE\TeamViewer",
            RegistryEntry {
                path: r"HKLM\SOFTWARE\TeamViewer".into(),
                name: "Version".into(),
                value: "15.0".into(),
                data_type: "REG_SZ".into(),
                timestamp: None,
            },
        );
        mock.add_registry_subkeys(
            r"HKLM\SOFTWARE\TeamViewer",
            vec!["Settings".into(), "Logging".into()],
        );

        assert!(mock
            .registry_key_exists(r"HKLM\SOFTWARE\TeamViewer")
            .expect("should succeed"));
        assert!(!mock
            .registry_key_exists(r"HKLM\SOFTWARE\NonExistent")
            .expect("should succeed"));

        let values = mock
            .registry_values(r"HKLM\SOFTWARE\TeamViewer")
            .expect("should succeed");
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].name, "Version");

        let subkeys = mock
            .registry_subkeys(r"HKLM\SOFTWARE\TeamViewer")
            .expect("should succeed");
        assert_eq!(subkeys, vec!["Settings", "Logging"]);
    }

    #[test]
    fn test_mock_provider_files() {
        let mut mock = MockArtifactProvider {
            caps: vec![ProviderCapability::FilePresence],
            ..MockArtifactProvider::default()
        };
        mock.add_file(
            "C:\\Program Files\\AnyDesk\\*",
            FileEntry {
                path: "C:\\Program Files\\AnyDesk\\AnyDesk.exe".into(),
                size: Some(4_096_000),
                created: Some(1_700_000_000),
                modified: Some(1_700_100_000),
            },
        );

        let files = mock
            .file_exists("C:\\Program Files\\AnyDesk\\*")
            .expect("should succeed");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "C:\\Program Files\\AnyDesk\\AnyDesk.exe");
        assert_eq!(files[0].size, Some(4_096_000));

        let empty = mock.file_exists("C:\\NoMatch\\*").expect("should succeed");
        assert!(empty.is_empty());
    }

    #[test]
    fn test_mock_provider_event_log_filter() {
        let mut mock = MockArtifactProvider {
            caps: vec![ProviderCapability::EventLogs],
            ..MockArtifactProvider::default()
        };
        mock.add_event_log(EventLogEntry {
            event_id: 7045,
            provider_name: "Service Control Manager".into(),
            log_file: "System".into(),
            timestamp: Some(1_700_000_000),
            data: {
                let mut m = HashMap::new();
                m.insert("ServiceName".into(), "TeamViewer".into());
                m
            },
        });
        mock.add_event_log(EventLogEntry {
            event_id: 4624,
            provider_name: "Microsoft-Windows-Security-Auditing".into(),
            log_file: "Security".into(),
            timestamp: Some(1_700_000_100),
            data: HashMap::new(),
        });

        // Filter by event_id
        let query = EventLogQuery {
            event_id: Some(7045),
            provider_name: None,
            log_file: None,
            keyword: None,
        };
        let results = mock.event_log_search(&query).expect("should succeed");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event_id, 7045);

        // Filter by keyword
        let query_kw = EventLogQuery {
            event_id: None,
            provider_name: None,
            log_file: None,
            keyword: Some("TeamViewer".into()),
        };
        let results_kw = mock.event_log_search(&query_kw).expect("should succeed");
        assert_eq!(results_kw.len(), 1);

        // No match
        let query_miss = EventLogQuery {
            event_id: Some(9999),
            provider_name: None,
            log_file: None,
            keyword: None,
        };
        let results_miss = mock.event_log_search(&query_miss).expect("should succeed");
        assert!(results_miss.is_empty());
    }

    #[test]
    fn test_composite_delegates_to_correct_provider() {
        let mut registry_mock = MockArtifactProvider {
            caps: vec![ProviderCapability::RegistryKeys],
            ..MockArtifactProvider::default()
        };
        registry_mock.add_registry_key(r"HKLM\SOFTWARE\Test", true);

        let mut file_mock = MockArtifactProvider {
            caps: vec![ProviderCapability::FilePresence],
            ..MockArtifactProvider::default()
        };
        file_mock.add_file(
            "C:\\test\\*",
            FileEntry {
                path: "C:\\test\\app.exe".into(),
                size: None,
                created: None,
                modified: None,
            },
        );

        let mut composite = CompositeArtifactProvider::new();
        composite.add_provider(Box::new(registry_mock));
        composite.add_provider(Box::new(file_mock));

        // Should have both capabilities
        let caps = composite.capabilities();
        assert!(caps.contains(&ProviderCapability::RegistryKeys));
        assert!(caps.contains(&ProviderCapability::FilePresence));

        // Registry queries go to registry_mock
        assert!(composite
            .registry_key_exists(r"HKLM\SOFTWARE\Test")
            .expect("should succeed"));

        // File queries go to file_mock
        let files = composite
            .file_exists("C:\\test\\*")
            .expect("should succeed");
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn test_composite_graceful_degradation() {
        // Provider only supports registry; file queries should fail gracefully.
        let registry_only = MockArtifactProvider {
            caps: vec![ProviderCapability::RegistryKeys],
            ..MockArtifactProvider::default()
        };

        let mut composite = CompositeArtifactProvider::new();
        composite.add_provider(Box::new(registry_only));

        // Registry works
        assert!(composite.registry_key_exists(r"HKLM\SOFTWARE\X").is_ok());

        // File queries are not available
        let err = composite.file_exists("*.exe");
        assert!(err.is_err());

        // Event log queries are not available
        let err = composite.event_log_search(&EventLogQuery {
            event_id: None,
            provider_name: None,
            log_file: None,
            keyword: None,
        });
        assert!(err.is_err());
    }
}
