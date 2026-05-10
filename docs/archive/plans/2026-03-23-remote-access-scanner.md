# Remote Access Artifact Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect every form of remote access capability in forensic evidence by scanning parsed artifacts against LOLRMM definitions, custom YAML rules, and behavioral category scanners.

**Architecture:** New `rt-remote-access` crate with hybrid detection engine — rule engine for presence-based detection (LOLRMM YAML, 260+ RMM tools) plus category scanners for behavioral/correlation detection (RDP config, lateral movement, tunneling). Pluggable `ArtifactProvider` trait abstracts over available artifact sources. Findings stored in DuckDB `findings` table with timeline cross-reference events.

**Tech Stack:** Rust, notatin (registry), frnsc-prefetch, frnsc-amcache, lnk_parser, jumplist_parser, quick-xml, serde_yaml, LOLRMM data (Apache-2.0), DuckDB

**Spec:** `docs/superpowers/specs/2026-03-23-remote-access-scanner-design.md`

---

## File Structure

### New crate: `crates/rt-remote-access/`

| File | Responsibility |
|------|---------------|
| `Cargo.toml` | Crate dependencies and workspace integration |
| `src/lib.rs` | Public API: `scan()`, `ScanConfig`, re-exports |
| `src/model.rs` | `Finding`, `RawArtifactHit`, `RemoteAccessCategory`, `ArtifactType`, `DetectionSource` |
| `src/providers/mod.rs` | `ArtifactProvider` trait, `CompositeArtifactProvider`, `ProviderCapability`, `ProviderError` |
| `src/providers/registry.rs` | Registry hive provider (notatin) |
| `src/providers/prefetch.rs` | Prefetch provider (frnsc-prefetch) |
| `src/providers/evtx.rs` | Event log provider (evtx crate) |
| `src/providers/filesystem.rs` | File/directory existence checks |
| `src/providers/amcache.rs` | Amcache provider (frnsc-amcache) |
| `src/providers/lnk.rs` | LNK shortcut provider (lnk_parser) |
| `src/providers/jumplist.rs` | Jumplist provider (jumplist_parser) |
| `src/providers/scheduled_tasks.rs` | XML task parser (quick-xml) |
| `src/rules/mod.rs` | `RuleEngine`: load YAML + evaluate rules |
| `src/rules/lolrmm.rs` | LOLRMM YAML deserialization structs |
| `src/rules/detection_rule.rs` | `DetectionRule`, `DetectionCondition` uniform representation |
| `src/rules/evaluator.rs` | Rule evaluation against `ArtifactProvider` |
| `src/scanners/mod.rs` | `CategoryScanner` trait, scanner registry |
| `src/scanners/builtin_remote.rs` | RDP, SSH, WinRM, VNC config analysis |
| `src/scanners/tunneling.rs` | ngrok, cloudflared, LOLBins, reverse shells |
| `src/scanners/lateral_movement.rs` | PsExec, WMI, DCOM, Kerberoasting |
| `src/scanners/c2.rs` | C2 framework indicators |
| `src/scanners/webshell.rs` | Web root filesystem scanning |
| `src/scanners/firewall.rs` | Inbound rules, port forwarding |
| `src/scanners/hardware.rs` | iLO/iDRAC/IPMI/AMT indicators |
| `src/aggregator.rs` | Group raw hits into `Finding` per tool |
| `src/store.rs` | DuckDB `findings` table + timeline cross-ref events |
| `data/lolrmm/` | Vendored LOLRMM YAML files |
| `data/custom/` | Custom VPN/ZTNA/hardware YAML definitions |

### Modified files

| File | Change |
|------|--------|
| `Cargo.toml` (root) | Add `rt-remote-access` to workspace members + workspace deps |
| `crates/rt-core/src/artifacts/types.rs` | Add `Assessment` variant to `ArtifactType` enum |
| `crates/rt-cli/Cargo.toml` | Add `rt-remote-access` dependency |
| `crates/rt-cli/src/main.rs` | Add `RemoteAccess` subcommand to `Commands` enum |
| `crates/rt-cli/src/commands/mod.rs` | Add `pub mod remote_access;` |
| `crates/rt-cli/src/commands/remote_access.rs` | New command handler |
| `crates/rt-cli/tests/cli_tests.rs` | New CLI e2e tests |

---

## Task 1: Crate Skeleton + Data Model

**Files:**
- Create: `crates/rt-remote-access/Cargo.toml`
- Create: `crates/rt-remote-access/src/lib.rs`
- Create: `crates/rt-remote-access/src/model.rs`
- Modify: `Cargo.toml` (root workspace)

- [ ] **Step 1: Write the failing test for data model types**

Create `crates/rt-remote-access/src/model.rs` with tests first:

```rust
// crates/rt-remote-access/src/model.rs
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// What kind of artifact source produced this hit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HitArtifactType {
    RegistryKey,
    RegistryValue,
    FilePresence,
    FileContent,
    EventLog,
    Service,
    Prefetch,
    Amcache,
    ShimCache,
    ScheduledTask,
    NetworkIndicator,
    FirewallRule,
    LnkFile,
    JumplistEntry,
}

/// A single artifact observation — one registry key, one file, one event log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawArtifactHit {
    /// What kind of artifact.
    pub artifact_type: HitArtifactType,
    /// Where we found it (hive path, file path, log channel).
    pub source_path: String,
    /// What we found (key path, filename, event data).
    pub value: String,
    /// Nanosecond timestamp if available.
    pub timestamp: Option<i64>,
    /// Additional key-value context.
    pub context: HashMap<String, String>,
}

/// Detection categories for remote access findings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RemoteAccessCategory {
    CommercialRmm,
    BuiltInRemoteAccess,
    VpnZtna,
    Tunneling,
    LateralMovement,
    C2Framework,
    WebShell,
    FirewallConfig,
    HardwareRemote,
}

impl std::fmt::Display for RemoteAccessCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CommercialRmm => write!(f, "Commercial RMM"),
            Self::BuiltInRemoteAccess => write!(f, "Built-in Remote Access"),
            Self::VpnZtna => write!(f, "VPN/ZTNA"),
            Self::Tunneling => write!(f, "Tunneling"),
            Self::LateralMovement => write!(f, "Lateral Movement"),
            Self::C2Framework => write!(f, "C2 Framework"),
            Self::WebShell => write!(f, "Web Shell"),
            Self::FirewallConfig => write!(f, "Firewall Config"),
            Self::HardwareRemote => write!(f, "Hardware Remote"),
        }
    }
}

/// How was this finding detected?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionSource {
    /// Matched a LOLRMM or custom YAML rule definition.
    LolrmmRule(String),
    /// Matched a Sigma detection rule.
    SigmaRule(String),
    /// Matched a YARA detection rule.
    YaraRule(String),
    /// Detected by a behavioral category scanner.
    CategoryScanner(String),
}

/// An aggregated finding — one per detected tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier (UUID v4).
    pub id: String,
    /// Tool name (e.g., "TeamViewer", "PsExec").
    pub tool_name: String,
    /// Detection category.
    pub category: RemoteAccessCategory,
    /// All raw evidence for this tool.
    pub artifacts: Vec<RawArtifactHit>,
    /// Earliest timestamp across artifacts.
    pub first_seen: Option<i64>,
    /// Latest timestamp across artifacts.
    pub last_seen: Option<i64>,
    /// What found this.
    pub detection_source: DetectionSource,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_category_display() {
        assert_eq!(
            format!("{}", RemoteAccessCategory::CommercialRmm),
            "Commercial RMM"
        );
        assert_eq!(
            format!("{}", RemoteAccessCategory::LateralMovement),
            "Lateral Movement"
        );
        assert_eq!(
            format!("{}", RemoteAccessCategory::VpnZtna),
            "VPN/ZTNA"
        );
    }

    #[test]
    fn test_finding_construction() {
        let finding = Finding {
            id: "test-uuid".into(),
            tool_name: "TeamViewer".into(),
            category: RemoteAccessCategory::CommercialRmm,
            artifacts: vec![RawArtifactHit {
                artifact_type: HitArtifactType::RegistryKey,
                source_path: r"HKLM\SOFTWARE\TeamViewer".into(),
                value: "TeamViewer key exists".into(),
                timestamp: None,
                context: HashMap::new(),
            }],
            first_seen: None,
            last_seen: None,
            detection_source: DetectionSource::LolrmmRule("teamviewer.yaml".into()),
        };
        assert_eq!(finding.tool_name, "TeamViewer");
        assert_eq!(finding.category, RemoteAccessCategory::CommercialRmm);
        assert_eq!(finding.artifacts.len(), 1);
    }

    #[test]
    fn test_finding_serde_roundtrip() {
        let finding = Finding {
            id: "uuid-001".into(),
            tool_name: "AnyDesk".into(),
            category: RemoteAccessCategory::CommercialRmm,
            artifacts: vec![
                RawArtifactHit {
                    artifact_type: HitArtifactType::FilePresence,
                    source_path: r"C:\Program Files\AnyDesk\AnyDesk.exe".into(),
                    value: "AnyDesk executable found".into(),
                    timestamp: Some(1_700_000_000_000_000_000),
                    context: HashMap::from([("size".into(), "12345".into())]),
                },
            ],
            first_seen: Some(1_700_000_000_000_000_000),
            last_seen: Some(1_700_000_000_000_000_000),
            detection_source: DetectionSource::LolrmmRule("anydesk.yaml".into()),
        };

        let json = serde_json::to_string(&finding).expect("serialize");
        let deserialized: Finding = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.tool_name, "AnyDesk");
        assert_eq!(deserialized.artifacts.len(), 1);
        assert_eq!(deserialized.first_seen, Some(1_700_000_000_000_000_000));
    }

    #[test]
    fn test_raw_artifact_hit_with_context() {
        let hit = RawArtifactHit {
            artifact_type: HitArtifactType::EventLog,
            source_path: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational".into(),
            value: "EventID 21: Session logon".into(),
            timestamp: Some(1_700_000_000_000_000_000),
            context: HashMap::from([
                ("event_id".into(), "21".into()),
                ("user".into(), "DOMAIN\\admin".into()),
                ("source_ip".into(), "10.0.0.5".into()),
            ]),
        };
        assert_eq!(hit.context.get("event_id"), Some(&"21".to_string()));
        assert_eq!(hit.context.get("source_ip"), Some(&"10.0.0.5".to_string()));
    }

    #[test]
    fn test_detection_source_variants() {
        let sources = vec![
            DetectionSource::LolrmmRule("teamviewer.yaml".into()),
            DetectionSource::SigmaRule("sigma-rule-123".into()),
            DetectionSource::YaraRule("webshell_detect".into()),
            DetectionSource::CategoryScanner("builtin_remote".into()),
        ];
        // All variants should serialize.
        for source in &sources {
            let json = serde_json::to_string(source).expect("serialize");
            assert!(!json.is_empty());
        }
    }

    #[test]
    fn test_hit_artifact_type_equality() {
        assert_eq!(HitArtifactType::RegistryKey, HitArtifactType::RegistryKey);
        assert_ne!(HitArtifactType::RegistryKey, HitArtifactType::FilePresence);
    }
}
```

- [ ] **Step 2: Create the Cargo.toml for the new crate**

```toml
# crates/rt-remote-access/Cargo.toml
[package]
name = "rt-remote-access"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
description = "Remote access infrastructure detection for Issen"
repository.workspace = true

[dependencies]
rt-core = { workspace = true }
rt-timeline = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
serde_yaml = { workspace = true }
thiserror = { workspace = true }
tracing = { workspace = true }
uuid = { version = "1", features = ["v4"] }
glob = "0.3"
quick-xml = "0.37"

# Forensic artifact parsers
notatin = "1.0"

[dev-dependencies]
tempfile = { workspace = true }

[lints]
workspace = true
```

**Note:** Start with minimal dependencies. Add `frnsc-prefetch`, `frnsc-amcache`, `lnk_parser`, `jumplist_parser`, `evtx` in later tasks when their providers are implemented.

- [ ] **Step 3: Create lib.rs**

```rust
// crates/rt-remote-access/src/lib.rs
pub mod model;
```

- [ ] **Step 4: Add crate to workspace**

Modify root `Cargo.toml`:

In `[workspace]` members list, add `"crates/rt-remote-access"` after `"crates/rt-signatures"`.

In `[workspace.dependencies]`, add:
```toml
rt-remote-access = { path = "crates/rt-remote-access" }
```

Also add new workspace dependencies:
```toml
uuid = { version = "1", features = ["v4"] }
glob = "0.3"
quick-xml = "0.37"
notatin = "1.0"
```

- [ ] **Step 5: Add Assessment variant to ArtifactType**

In `crates/rt-core/src/artifacts/types.rs`, add `Assessment` variant to the `ArtifactType` enum (after `Srum`):

```rust
    /// Assessment or derived finding (not a raw artifact).
    Assessment,
```

Add the display match arm:
```rust
            Self::Assessment => write!(f, "Assessment"),
```

- [ ] **Step 6: Run tests to verify everything compiles and passes**

Run: `cargo test -p rt-remote-access`
Expected: All 6 tests pass.

Run: `cargo test -p rt-core`
Expected: All existing tests still pass.

- [ ] **Step 7: Commit**

```bash
git add crates/rt-remote-access/ Cargo.toml crates/rt-core/src/artifacts/types.rs
git commit -m "feat(rt-remote-access): add crate skeleton with data model

New rt-remote-access crate with Finding, RawArtifactHit,
RemoteAccessCategory, DetectionSource types. Add Assessment
variant to ArtifactType for timeline cross-references."
```

---

## Task 2: ArtifactProvider Trait + Mock + Composite

**Files:**
- Create: `crates/rt-remote-access/src/providers/mod.rs`
- Modify: `crates/rt-remote-access/src/lib.rs`

- [ ] **Step 1: Write the ArtifactProvider trait and supporting types**

```rust
// crates/rt-remote-access/src/providers/mod.rs
use std::collections::HashMap;

use thiserror::Error;

/// What an artifact provider can answer queries about.
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

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("capability not available")]
    NotAvailable,
    #[error("provider error: {0}")]
    Internal(String),
}

/// A registry key/value entry returned by the provider.
#[derive(Debug, Clone)]
pub struct RegistryEntry {
    pub path: String,
    pub name: String,
    pub value: String,
    pub data_type: String,
    pub timestamp: Option<i64>,
}

/// A file entry returned by the provider.
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub path: String,
    pub size: Option<u64>,
    pub created: Option<i64>,
    pub modified: Option<i64>,
}

/// A query for searching event logs.
#[derive(Debug, Clone)]
pub struct EventLogQuery {
    pub event_id: Option<u32>,
    pub provider_name: Option<String>,
    pub log_file: Option<String>,
    pub keyword: Option<String>,
}

/// An event log entry returned by the provider.
#[derive(Debug, Clone)]
pub struct EventLogEntry {
    pub event_id: u32,
    pub provider_name: String,
    pub log_file: String,
    pub timestamp: Option<i64>,
    pub data: HashMap<String, String>,
}

/// A prefetch execution record.
#[derive(Debug, Clone)]
pub struct PrefetchEntry {
    pub executable_name: String,
    pub run_count: u32,
    pub last_run: Option<i64>,
    pub path: String,
}

/// An amcache program record.
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

/// Trait implemented by each artifact source.
///
/// All methods have default implementations returning `NotAvailable`.
/// Providers override only the methods they can serve.
#[allow(unused_variables)]
pub trait ArtifactProvider: Send + Sync {
    fn capabilities(&self) -> Vec<ProviderCapability>;

    fn registry_key_exists(&self, path: &str) -> Result<bool, ProviderError> {
        Err(ProviderError::NotAvailable)
    }
    fn registry_values(&self, path: &str) -> Result<Vec<RegistryEntry>, ProviderError> {
        Err(ProviderError::NotAvailable)
    }
    fn registry_subkeys(&self, path: &str) -> Result<Vec<String>, ProviderError> {
        Err(ProviderError::NotAvailable)
    }
    fn file_exists(&self, pattern: &str) -> Result<Vec<FileEntry>, ProviderError> {
        Err(ProviderError::NotAvailable)
    }
    fn event_log_search(
        &self,
        query: &EventLogQuery,
    ) -> Result<Vec<EventLogEntry>, ProviderError> {
        Err(ProviderError::NotAvailable)
    }
    fn prefetch_entries(&self) -> Result<Vec<PrefetchEntry>, ProviderError> {
        Err(ProviderError::NotAvailable)
    }
    fn amcache_entries(&self) -> Result<Vec<AmcacheEntry>, ProviderError> {
        Err(ProviderError::NotAvailable)
    }
    fn shimcache_entries(&self) -> Result<Vec<String>, ProviderError> {
        Err(ProviderError::NotAvailable)
    }
    fn bam_entries(&self) -> Result<Vec<(String, i64)>, ProviderError> {
        Err(ProviderError::NotAvailable)
    }
    fn userassist_entries(&self) -> Result<Vec<(String, u32, Option<i64>)>, ProviderError> {
        Err(ProviderError::NotAvailable)
    }
    fn services(&self) -> Result<Vec<ServiceEntry>, ProviderError> {
        Err(ProviderError::NotAvailable)
    }
    fn scheduled_tasks(&self) -> Result<Vec<ScheduledTaskEntry>, ProviderError> {
        Err(ProviderError::NotAvailable)
    }
}

/// Composite provider that delegates to specialized sub-providers.
pub struct CompositeArtifactProvider {
    providers: Vec<Box<dyn ArtifactProvider>>,
}

impl CompositeArtifactProvider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    pub fn add_provider(&mut self, provider: Box<dyn ArtifactProvider>) {
        self.providers.push(provider);
    }

    /// Find the first provider that supports a given capability.
    fn provider_for(
        &self,
        capability: ProviderCapability,
    ) -> Option<&dyn ArtifactProvider> {
        self.providers
            .iter()
            .find(|p| p.capabilities().contains(&capability))
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
        let mut caps: Vec<ProviderCapability> = self
            .providers
            .iter()
            .flat_map(|p| p.capabilities())
            .collect();
        caps.sort_by_key(|c| format!("{c:?}"));
        caps.dedup();
        caps
    }

    fn registry_key_exists(&self, path: &str) -> Result<bool, ProviderError> {
        self.provider_for(ProviderCapability::RegistryKeys)
            .ok_or(ProviderError::NotAvailable)?
            .registry_key_exists(path)
    }

    fn registry_values(&self, path: &str) -> Result<Vec<RegistryEntry>, ProviderError> {
        self.provider_for(ProviderCapability::RegistryKeys)
            .ok_or(ProviderError::NotAvailable)?
            .registry_values(path)
    }

    fn registry_subkeys(&self, path: &str) -> Result<Vec<String>, ProviderError> {
        self.provider_for(ProviderCapability::RegistryKeys)
            .ok_or(ProviderError::NotAvailable)?
            .registry_subkeys(path)
    }

    fn file_exists(&self, pattern: &str) -> Result<Vec<FileEntry>, ProviderError> {
        self.provider_for(ProviderCapability::FilePresence)
            .ok_or(ProviderError::NotAvailable)?
            .file_exists(pattern)
    }

    fn event_log_search(
        &self,
        query: &EventLogQuery,
    ) -> Result<Vec<EventLogEntry>, ProviderError> {
        self.provider_for(ProviderCapability::EventLogs)
            .ok_or(ProviderError::NotAvailable)?
            .event_log_search(query)
    }

    fn prefetch_entries(&self) -> Result<Vec<PrefetchEntry>, ProviderError> {
        self.provider_for(ProviderCapability::PrefetchEntries)
            .ok_or(ProviderError::NotAvailable)?
            .prefetch_entries()
    }

    fn amcache_entries(&self) -> Result<Vec<AmcacheEntry>, ProviderError> {
        self.provider_for(ProviderCapability::AmcacheEntries)
            .ok_or(ProviderError::NotAvailable)?
            .amcache_entries()
    }

    fn services(&self) -> Result<Vec<ServiceEntry>, ProviderError> {
        self.provider_for(ProviderCapability::Services)
            .ok_or(ProviderError::NotAvailable)?
            .services()
    }

    fn scheduled_tasks(&self) -> Result<Vec<ScheduledTaskEntry>, ProviderError> {
        self.provider_for(ProviderCapability::ScheduledTasks)
            .ok_or(ProviderError::NotAvailable)?
            .scheduled_tasks()
    }
}

/// Mock provider for testing. Pre-load it with canned data.
#[cfg(any(test, feature = "test-utils"))]
pub struct MockArtifactProvider {
    caps: Vec<ProviderCapability>,
    registry_keys: HashMap<String, bool>,
    registry_values: HashMap<String, Vec<RegistryEntry>>,
    registry_subkeys: HashMap<String, Vec<String>>,
    files: HashMap<String, Vec<FileEntry>>,
    event_logs: Vec<EventLogEntry>,
    prefetch: Vec<PrefetchEntry>,
    amcache: Vec<AmcacheEntry>,
    services: Vec<ServiceEntry>,
    scheduled_tasks: Vec<ScheduledTaskEntry>,
}

#[cfg(any(test, feature = "test-utils"))]
impl MockArtifactProvider {
    #[must_use]
    pub fn new(caps: Vec<ProviderCapability>) -> Self {
        Self {
            caps,
            registry_keys: HashMap::new(),
            registry_values: HashMap::new(),
            registry_subkeys: HashMap::new(),
            files: HashMap::new(),
            event_logs: Vec::new(),
            prefetch: Vec::new(),
            amcache: Vec::new(),
            services: Vec::new(),
            scheduled_tasks: Vec::new(),
        }
    }

    pub fn add_registry_key(&mut self, path: &str) {
        self.registry_keys.insert(path.to_string(), true);
    }

    pub fn add_registry_value(&mut self, path: &str, entry: RegistryEntry) {
        self.registry_values
            .entry(path.to_string())
            .or_default()
            .push(entry);
    }

    pub fn add_registry_subkeys(&mut self, path: &str, subkeys: Vec<String>) {
        self.registry_subkeys.insert(path.to_string(), subkeys);
    }

    pub fn add_file(&mut self, pattern: &str, entry: FileEntry) {
        self.files
            .entry(pattern.to_string())
            .or_default()
            .push(entry);
    }

    pub fn add_event_log(&mut self, entry: EventLogEntry) {
        self.event_logs.push(entry);
    }

    pub fn add_prefetch(&mut self, entry: PrefetchEntry) {
        self.prefetch.push(entry);
    }

    pub fn add_amcache(&mut self, entry: AmcacheEntry) {
        self.amcache.push(entry);
    }

    pub fn add_service(&mut self, entry: ServiceEntry) {
        self.services.push(entry);
    }

    pub fn add_scheduled_task(&mut self, entry: ScheduledTaskEntry) {
        self.scheduled_tasks.push(entry);
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl ArtifactProvider for MockArtifactProvider {
    fn capabilities(&self) -> Vec<ProviderCapability> {
        self.caps.clone()
    }

    fn registry_key_exists(&self, path: &str) -> Result<bool, ProviderError> {
        Ok(self.registry_keys.contains_key(path))
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

    fn event_log_search(
        &self,
        query: &EventLogQuery,
    ) -> Result<Vec<EventLogEntry>, ProviderError> {
        let filtered: Vec<EventLogEntry> = self
            .event_logs
            .iter()
            .filter(|e| {
                query.event_id.map_or(true, |id| e.event_id == id)
                    && query
                        .provider_name
                        .as_ref()
                        .map_or(true, |p| e.provider_name.contains(p.as_str()))
                    && query
                        .log_file
                        .as_ref()
                        .map_or(true, |l| e.log_file.contains(l.as_str()))
            })
            .cloned()
            .collect();
        Ok(filtered)
    }

    fn prefetch_entries(&self) -> Result<Vec<PrefetchEntry>, ProviderError> {
        Ok(self.prefetch.clone())
    }

    fn amcache_entries(&self) -> Result<Vec<AmcacheEntry>, ProviderError> {
        Ok(self.amcache.clone())
    }

    fn services(&self) -> Result<Vec<ServiceEntry>, ProviderError> {
        Ok(self.services.clone())
    }

    fn scheduled_tasks(&self) -> Result<Vec<ScheduledTaskEntry>, ProviderError> {
        Ok(self.scheduled_tasks.clone())
    }
}

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
        assert!(composite.registry_key_exists("any").is_err());
        assert!(composite.file_exists("any").is_err());
        assert!(composite.prefetch_entries().is_err());
    }

    #[test]
    fn test_mock_provider_registry() {
        let mut mock = MockArtifactProvider::new(vec![ProviderCapability::RegistryKeys]);
        mock.add_registry_key(r"HKLM\SOFTWARE\TeamViewer");

        assert!(mock
            .registry_key_exists(r"HKLM\SOFTWARE\TeamViewer")
            .expect("query"));
        assert!(!mock
            .registry_key_exists(r"HKLM\SOFTWARE\NotInstalled")
            .expect("query"));
    }

    #[test]
    fn test_mock_provider_files() {
        let mut mock = MockArtifactProvider::new(vec![ProviderCapability::FilePresence]);
        mock.add_file(
            r"C:\Program Files\AnyDesk\*",
            FileEntry {
                path: r"C:\Program Files\AnyDesk\AnyDesk.exe".into(),
                size: Some(12345),
                created: None,
                modified: None,
            },
        );

        let files = mock.file_exists(r"C:\Program Files\AnyDesk\*").expect("query");
        assert_eq!(files.len(), 1);
        assert!(files[0].path.contains("AnyDesk.exe"));
    }

    #[test]
    fn test_mock_provider_event_log_filter() {
        let mut mock = MockArtifactProvider::new(vec![ProviderCapability::EventLogs]);
        mock.add_event_log(EventLogEntry {
            event_id: 7045,
            provider_name: "Service Control Manager".into(),
            log_file: "System".into(),
            timestamp: Some(1_700_000_000_000_000_000),
            data: HashMap::from([("ServiceName".into(), "PSEXESVC".into())]),
        });
        mock.add_event_log(EventLogEntry {
            event_id: 4624,
            provider_name: "Microsoft-Windows-Security-Auditing".into(),
            log_file: "Security".into(),
            timestamp: Some(1_700_000_000_000_000_001),
            data: HashMap::new(),
        });

        let results = mock
            .event_log_search(&EventLogQuery {
                event_id: Some(7045),
                provider_name: None,
                log_file: None,
                keyword: None,
            })
            .expect("query");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event_id, 7045);
    }

    #[test]
    fn test_composite_delegates_to_correct_provider() {
        let mut mock_reg =
            MockArtifactProvider::new(vec![ProviderCapability::RegistryKeys]);
        mock_reg.add_registry_key(r"HKLM\SOFTWARE\Test");

        let mock_files =
            MockArtifactProvider::new(vec![ProviderCapability::FilePresence]);

        let mut composite = CompositeArtifactProvider::new();
        composite.add_provider(Box::new(mock_reg));
        composite.add_provider(Box::new(mock_files));

        let caps = composite.capabilities();
        assert!(caps.contains(&ProviderCapability::RegistryKeys));
        assert!(caps.contains(&ProviderCapability::FilePresence));

        assert!(composite
            .registry_key_exists(r"HKLM\SOFTWARE\Test")
            .expect("query"));
        // File provider has no files, so empty vec.
        let files = composite.file_exists("anything").expect("query");
        assert!(files.is_empty());
    }

    #[test]
    fn test_composite_graceful_degradation() {
        let composite = CompositeArtifactProvider::new();
        // No providers — all queries return NotAvailable, not panic.
        assert!(matches!(
            composite.registry_key_exists("any"),
            Err(ProviderError::NotAvailable)
        ));
        assert!(matches!(
            composite.event_log_search(&EventLogQuery {
                event_id: None,
                provider_name: None,
                log_file: None,
                keyword: None,
            }),
            Err(ProviderError::NotAvailable)
        ));
    }
}
```

- [ ] **Step 2: Update lib.rs to expose providers module**

```rust
// crates/rt-remote-access/src/lib.rs
pub mod model;
pub mod providers;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p rt-remote-access`
Expected: All model tests + all provider tests pass.

- [ ] **Step 4: Commit**

```bash
git add crates/rt-remote-access/src/providers/
git commit -m "feat(rt-remote-access): add ArtifactProvider trait + mock + composite

Pluggable interface for artifact sources with graceful degradation.
CompositeArtifactProvider delegates to specialized sub-providers.
MockArtifactProvider for testing with canned data."
```

---

## Task 3: LOLRMM YAML Loader

**Files:**
- Create: `crates/rt-remote-access/src/rules/mod.rs`
- Create: `crates/rt-remote-access/src/rules/lolrmm.rs`
- Modify: `crates/rt-remote-access/src/lib.rs`

- [ ] **Step 1: Vendor LOLRMM test fixtures**

Download 3 representative LOLRMM YAML files for testing:

```bash
mkdir -p crates/rt-remote-access/tests/fixtures/lolrmm
curl -sL "https://raw.githubusercontent.com/magicsword-io/LOLRMM/main/yaml/anydesk.yaml" \
  -o crates/rt-remote-access/tests/fixtures/lolrmm/anydesk.yaml
curl -sL "https://raw.githubusercontent.com/magicsword-io/LOLRMM/main/yaml/teamviewer.yaml" \
  -o crates/rt-remote-access/tests/fixtures/lolrmm/teamviewer.yaml
curl -sL "https://raw.githubusercontent.com/magicsword-io/LOLRMM/main/yaml/splashtop.yaml" \
  -o crates/rt-remote-access/tests/fixtures/lolrmm/splashtop.yaml
```

If the exact URLs differ, check https://github.com/magicsword-io/LOLRMM/tree/main/yaml for correct filenames.

- [ ] **Step 2: Write LOLRMM deserialization structs and tests**

```rust
// crates/rt-remote-access/src/rules/lolrmm.rs
use std::path::Path;

use serde::Deserialize;

/// Direct representation of a LOLRMM YAML file.
/// Fields are optional where LOLRMM data may be incomplete.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LolrmmDefinition {
    pub name: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub details: Option<LolrmmDetails>,
    #[serde(default)]
    pub artifacts: Option<LolrmmArtifacts>,
    #[serde(default)]
    pub detections: Option<Vec<LolrmmDetection>>,
    #[serde(default)]
    pub references: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct LolrmmDetails {
    #[serde(default)]
    pub website: Option<String>,
    #[serde(default, rename = "PEMetadata")]
    pub pe_metadata: Option<Vec<PeMetadata>>,
    #[serde(default)]
    pub privileges: Option<String>,
    #[serde(default)]
    pub free: Option<bool>,
    #[serde(default)]
    pub verification: Option<bool>,
    #[serde(default, rename = "SupportedOS")]
    pub supported_os: Option<Vec<String>>,
    #[serde(default)]
    pub capabilities: Option<Vec<String>>,
    #[serde(default)]
    pub vulnerabilities: Option<Vec<String>>,
    #[serde(default)]
    pub installation_paths: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PeMetadata {
    #[serde(default)]
    pub filename: Option<String>,
    #[serde(default)]
    pub original_file_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub product: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct LolrmmArtifacts {
    #[serde(default)]
    pub disk: Option<Vec<DiskArtifact>>,
    #[serde(default)]
    pub event_log: Option<Vec<EventLogArtifact>>,
    #[serde(default)]
    pub registry: Option<Vec<RegistryArtifact>>,
    #[serde(default)]
    pub network: Option<Vec<NetworkArtifact>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DiskArtifact {
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default, rename = "OS")]
    pub os: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EventLogArtifact {
    #[serde(default, rename = "EventID")]
    pub event_id: Option<u32>,
    #[serde(default)]
    pub provider_name: Option<String>,
    #[serde(default)]
    pub log_file: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RegistryArtifact {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NetworkArtifact {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub domains: Option<Vec<String>>,
    #[serde(default)]
    pub ports: Option<Vec<u16>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LolrmmDetection {
    #[serde(default)]
    pub sigma: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

/// Load a single LOLRMM YAML file.
pub fn load_lolrmm_file(path: &Path) -> Result<LolrmmDefinition, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    serde_yaml::from_str(&content)
        .map_err(|e| format!("failed to parse {}: {e}", path.display()))
}

/// Load all LOLRMM YAML files from a directory.
pub fn load_lolrmm_directory(dir: &Path) -> Result<Vec<LolrmmDefinition>, String> {
    if !dir.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    let mut definitions = Vec::new();
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("failed to read directory {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("directory entry error: {e}"))?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("yaml")
            || path.extension().and_then(|e| e.to_str()) == Some("yml")
        {
            match load_lolrmm_file(&path) {
                Ok(def) => definitions.push(def),
                Err(e) => {
                    tracing::warn!("skipping {}: {e}", path.display());
                }
            }
        }
    }
    Ok(definitions)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("lolrmm")
    }

    #[test]
    fn test_load_anydesk_yaml() {
        let path = fixtures_dir().join("anydesk.yaml");
        if !path.exists() {
            eprintln!("Skipping: fixture not found at {}", path.display());
            return;
        }
        let def = load_lolrmm_file(&path).expect("parse anydesk.yaml");
        assert_eq!(def.name, "AnyDesk");
        assert!(def.artifacts.is_some());
        let artifacts = def.artifacts.as_ref().expect("artifacts");
        // AnyDesk should have disk and/or registry artifacts.
        assert!(
            artifacts.disk.is_some() || artifacts.registry.is_some(),
            "AnyDesk should have disk or registry artifacts"
        );
    }

    #[test]
    fn test_load_teamviewer_yaml() {
        let path = fixtures_dir().join("teamviewer.yaml");
        if !path.exists() {
            eprintln!("Skipping: fixture not found at {}", path.display());
            return;
        }
        let def = load_lolrmm_file(&path).expect("parse teamviewer.yaml");
        assert_eq!(def.name, "TeamViewer");
    }

    #[test]
    fn test_load_directory() {
        let dir = fixtures_dir();
        if !dir.exists() {
            eprintln!("Skipping: fixtures dir not found");
            return;
        }
        let defs = load_lolrmm_directory(&dir).expect("load directory");
        // Should find at least the fixtures we downloaded.
        assert!(!defs.is_empty(), "should load at least one YAML file");
    }

    #[test]
    fn test_load_nonexistent_file() {
        let result = load_lolrmm_file(Path::new("/nonexistent/file.yaml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_nonexistent_directory() {
        let result = load_lolrmm_directory(Path::new("/nonexistent/dir"));
        assert!(result.is_err());
    }
}
```

- [ ] **Step 3: Create rules/mod.rs**

```rust
// crates/rt-remote-access/src/rules/mod.rs
pub mod lolrmm;
```

- [ ] **Step 4: Update lib.rs**

```rust
// crates/rt-remote-access/src/lib.rs
pub mod model;
pub mod providers;
pub mod rules;
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p rt-remote-access`
Expected: All tests pass (model + providers + lolrmm loader).

- [ ] **Step 6: Commit**

```bash
git add crates/rt-remote-access/src/rules/ crates/rt-remote-access/tests/
git commit -m "feat(rt-remote-access): add LOLRMM YAML loader

Deserialize LOLRMM YAML files natively. Supports loading single files
and entire directories. Handles optional/missing fields gracefully."
```

---

## Task 4: Detection Rule Compiler + Evaluator

**Files:**
- Create: `crates/rt-remote-access/src/rules/detection_rule.rs`
- Create: `crates/rt-remote-access/src/rules/evaluator.rs`
- Modify: `crates/rt-remote-access/src/rules/mod.rs`

- [ ] **Step 1: Write DetectionRule and compiler from LOLRMM**

```rust
// crates/rt-remote-access/src/rules/detection_rule.rs
use crate::model::RemoteAccessCategory;
use crate::rules::lolrmm::LolrmmDefinition;

/// A condition that the evaluator checks against an ArtifactProvider.
#[derive(Debug, Clone)]
pub enum DetectionCondition {
    RegistryKeyExists(String),
    RegistryValueContains(String, String),
    FileExists(String),
    ServiceExists(String),
    EventLogMatch {
        event_id: u32,
        provider: String,
        log_file: String,
    },
    PrefetchMatch(String),
    AmcacheMatch(String),
    NetworkIndicator {
        domains: Vec<String>,
        ports: Vec<u16>,
    },
}

/// A compiled detection rule — uniform representation from LOLRMM or custom YAML.
#[derive(Debug, Clone)]
pub struct DetectionRule {
    pub id: String,
    pub tool_name: String,
    pub category: RemoteAccessCategory,
    pub conditions: Vec<DetectionCondition>,
    pub source_file: String,
}

/// Compile a LOLRMM definition into a DetectionRule.
pub fn compile_lolrmm(def: &LolrmmDefinition, source_file: &str) -> DetectionRule {
    let mut conditions = Vec::new();

    if let Some(ref artifacts) = def.artifacts {
        // Registry artifacts → RegistryKeyExists conditions.
        if let Some(ref registry) = artifacts.registry {
            for reg in registry {
                if let Some(ref path) = reg.path {
                    conditions.push(DetectionCondition::RegistryKeyExists(path.clone()));
                }
            }
        }

        // Disk artifacts → FileExists conditions.
        if let Some(ref disk) = artifacts.disk {
            for d in disk {
                if let Some(ref file) = d.file {
                    conditions.push(DetectionCondition::FileExists(file.clone()));
                }
            }
        }

        // Event log artifacts → EventLogMatch conditions.
        if let Some(ref event_logs) = artifacts.event_log {
            for el in event_logs {
                if let (Some(event_id), Some(ref provider), Some(ref log_file)) =
                    (el.event_id, &el.provider_name, &el.log_file)
                {
                    conditions.push(DetectionCondition::EventLogMatch {
                        event_id,
                        provider: provider.clone(),
                        log_file: log_file.clone(),
                    });
                }
            }
        }

        // Network artifacts → NetworkIndicator conditions.
        if let Some(ref network) = artifacts.network {
            for net in network {
                let domains = net.domains.clone().unwrap_or_default();
                let ports = net.ports.clone().unwrap_or_default();
                if !domains.is_empty() || !ports.is_empty() {
                    conditions.push(DetectionCondition::NetworkIndicator { domains, ports });
                }
            }
        }
    }

    // Installation paths → FileExists conditions.
    if let Some(ref details) = def.details {
        if let Some(ref paths) = details.installation_paths {
            for path in paths {
                conditions.push(DetectionCondition::FileExists(path.clone()));
            }
        }
    }

    // Determine category from LOLRMM category field.
    let category = match def.category.to_lowercase().as_str() {
        "rmm" => RemoteAccessCategory::CommercialRmm,
        _ => RemoteAccessCategory::CommercialRmm, // LOLRMM is all RMM tools
    };

    DetectionRule {
        id: format!("lolrmm:{}", def.name.to_lowercase().replace(' ', "-")),
        tool_name: def.name.clone(),
        category,
        conditions,
        source_file: source_file.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::lolrmm::load_lolrmm_file;

    #[test]
    fn test_compile_lolrmm_anydesk() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/lolrmm/anydesk.yaml");
        if !path.exists() {
            eprintln!("Skipping: fixture not found");
            return;
        }
        let def = load_lolrmm_file(&path).expect("parse");
        let rule = compile_lolrmm(&def, "anydesk.yaml");
        assert_eq!(rule.tool_name, "AnyDesk");
        assert_eq!(rule.category, RemoteAccessCategory::CommercialRmm);
        assert!(
            !rule.conditions.is_empty(),
            "AnyDesk should have at least one detection condition"
        );
        assert!(rule.id.starts_with("lolrmm:"));
    }

    #[test]
    fn test_compile_empty_artifacts() {
        let def = LolrmmDefinition {
            name: "EmptyTool".into(),
            category: "RMM".into(),
            description: String::new(),
            details: None,
            artifacts: None,
            detections: None,
            references: None,
        };
        let rule = compile_lolrmm(&def, "empty.yaml");
        assert_eq!(rule.tool_name, "EmptyTool");
        assert!(rule.conditions.is_empty());
    }
}
```

- [ ] **Step 2: Write the rule evaluator**

```rust
// crates/rt-remote-access/src/rules/evaluator.rs
use std::collections::HashMap;

use tracing::debug;

use crate::model::{DetectionSource, Finding, HitArtifactType, RawArtifactHit};
use crate::providers::{ArtifactProvider, EventLogQuery, ProviderCapability, ProviderError};
use crate::rules::detection_rule::{DetectionCondition, DetectionRule};

/// Evaluate a single detection rule against an artifact provider.
/// Returns a Finding if any condition matched, None otherwise.
pub fn evaluate_rule(
    rule: &DetectionRule,
    provider: &dyn ArtifactProvider,
) -> Option<Finding> {
    let caps = provider.capabilities();
    let mut hits: Vec<RawArtifactHit> = Vec::new();

    for condition in &rule.conditions {
        match condition {
            DetectionCondition::RegistryKeyExists(path) => {
                if !caps.contains(&ProviderCapability::RegistryKeys) {
                    continue;
                }
                if let Ok(true) = provider.registry_key_exists(path) {
                    hits.push(RawArtifactHit {
                        artifact_type: HitArtifactType::RegistryKey,
                        source_path: path.clone(),
                        value: format!("Registry key exists: {path}"),
                        timestamp: None,
                        context: HashMap::new(),
                    });
                }
            }
            DetectionCondition::RegistryValueContains(path, substring) => {
                if !caps.contains(&ProviderCapability::RegistryKeys) {
                    continue;
                }
                if let Ok(values) = provider.registry_values(path) {
                    for val in &values {
                        if val.value.contains(substring) {
                            hits.push(RawArtifactHit {
                                artifact_type: HitArtifactType::RegistryValue,
                                source_path: path.clone(),
                                value: format!("{}={}", val.name, val.value),
                                timestamp: val.timestamp,
                                context: HashMap::from([
                                    ("name".into(), val.name.clone()),
                                    ("data_type".into(), val.data_type.clone()),
                                ]),
                            });
                        }
                    }
                }
            }
            DetectionCondition::FileExists(pattern) => {
                if !caps.contains(&ProviderCapability::FilePresence) {
                    continue;
                }
                if let Ok(files) = provider.file_exists(pattern) {
                    for file in &files {
                        hits.push(RawArtifactHit {
                            artifact_type: HitArtifactType::FilePresence,
                            source_path: file.path.clone(),
                            value: format!("File found: {}", file.path),
                            timestamp: file.created.or(file.modified),
                            context: file
                                .size
                                .map(|s| HashMap::from([("size".into(), s.to_string())]))
                                .unwrap_or_default(),
                        });
                    }
                }
            }
            DetectionCondition::ServiceExists(name_pattern) => {
                if !caps.contains(&ProviderCapability::Services) {
                    continue;
                }
                if let Ok(services) = provider.services() {
                    for svc in &services {
                        let pattern_lower = name_pattern.to_lowercase();
                        if svc.name.to_lowercase().contains(&pattern_lower)
                            || svc.display_name.to_lowercase().contains(&pattern_lower)
                        {
                            hits.push(RawArtifactHit {
                                artifact_type: HitArtifactType::Service,
                                source_path: format!("Services\\{}", svc.name),
                                value: format!(
                                    "Service: {} ({})",
                                    svc.display_name, svc.image_path
                                ),
                                timestamp: None,
                                context: HashMap::from([
                                    ("image_path".into(), svc.image_path.clone()),
                                    ("start_type".into(), svc.start_type.to_string()),
                                ]),
                            });
                        }
                    }
                }
            }
            DetectionCondition::EventLogMatch {
                event_id,
                provider: provider_name,
                log_file,
            } => {
                if !caps.contains(&ProviderCapability::EventLogs) {
                    continue;
                }
                let query = EventLogQuery {
                    event_id: Some(*event_id),
                    provider_name: Some(provider_name.clone()),
                    log_file: Some(log_file.clone()),
                    keyword: None,
                };
                if let Ok(entries) = provider.event_log_search(&query) {
                    for entry in &entries {
                        hits.push(RawArtifactHit {
                            artifact_type: HitArtifactType::EventLog,
                            source_path: format!("{}/{}", entry.log_file, entry.provider_name),
                            value: format!("EventID {}: {:?}", entry.event_id, entry.data),
                            timestamp: entry.timestamp,
                            context: entry.data.clone(),
                        });
                    }
                }
            }
            DetectionCondition::PrefetchMatch(exe_pattern) => {
                if !caps.contains(&ProviderCapability::PrefetchEntries) {
                    continue;
                }
                if let Ok(entries) = provider.prefetch_entries() {
                    let pattern_lower = exe_pattern.to_lowercase();
                    for entry in &entries {
                        if entry.executable_name.to_lowercase().contains(&pattern_lower) {
                            hits.push(RawArtifactHit {
                                artifact_type: HitArtifactType::Prefetch,
                                source_path: entry.path.clone(),
                                value: format!(
                                    "Prefetch: {} (run count: {})",
                                    entry.executable_name, entry.run_count
                                ),
                                timestamp: entry.last_run,
                                context: HashMap::from([(
                                    "run_count".into(),
                                    entry.run_count.to_string(),
                                )]),
                            });
                        }
                    }
                }
            }
            DetectionCondition::AmcacheMatch(program_pattern) => {
                if !caps.contains(&ProviderCapability::AmcacheEntries) {
                    continue;
                }
                if let Ok(entries) = provider.amcache_entries() {
                    let pattern_lower = program_pattern.to_lowercase();
                    for entry in &entries {
                        if entry.program_name.to_lowercase().contains(&pattern_lower) {
                            hits.push(RawArtifactHit {
                                artifact_type: HitArtifactType::Amcache,
                                source_path: entry
                                    .file_path
                                    .clone()
                                    .unwrap_or_else(|| "unknown".into()),
                                value: format!("Amcache: {}", entry.program_name),
                                timestamp: entry.install_date.or(entry.link_date),
                                context: HashMap::new(),
                            });
                        }
                    }
                }
            }
            DetectionCondition::NetworkIndicator { domains, ports } => {
                // Network indicators are informational — no provider query needed.
                // They're stored as context for the finding.
                debug!(
                    tool = %rule.tool_name,
                    domains = ?domains,
                    ports = ?ports,
                    "network indicators recorded"
                );
            }
        }
    }

    if hits.is_empty() {
        return None;
    }

    let first_seen = hits.iter().filter_map(|h| h.timestamp).min();
    let last_seen = hits.iter().filter_map(|h| h.timestamp).max();

    Some(Finding {
        id: uuid::Uuid::new_v4().to_string(),
        tool_name: rule.tool_name.clone(),
        category: rule.category.clone(),
        artifacts: hits,
        first_seen,
        last_seen,
        detection_source: DetectionSource::LolrmmRule(rule.source_file.clone()),
    })
}

/// Evaluate all rules against a provider. Returns findings for rules that matched.
pub fn evaluate_all(
    rules: &[DetectionRule],
    provider: &dyn ArtifactProvider,
) -> Vec<Finding> {
    rules.iter().filter_map(|r| evaluate_rule(r, provider)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::RemoteAccessCategory;
    use crate::providers::{FileEntry, MockArtifactProvider, ProviderCapability};
    use crate::rules::detection_rule::DetectionCondition;

    fn teamviewer_rule() -> DetectionRule {
        DetectionRule {
            id: "lolrmm:teamviewer".into(),
            tool_name: "TeamViewer".into(),
            category: RemoteAccessCategory::CommercialRmm,
            conditions: vec![
                DetectionCondition::RegistryKeyExists(
                    r"HKLM\SOFTWARE\TeamViewer".into(),
                ),
                DetectionCondition::FileExists(
                    r"C:\Program Files\TeamViewer\*".into(),
                ),
                DetectionCondition::PrefetchMatch("TEAMVIEWER".into()),
            ],
            source_file: "teamviewer.yaml".into(),
        }
    }

    #[test]
    fn test_evaluate_no_match() {
        let rule = teamviewer_rule();
        let mock = MockArtifactProvider::new(vec![
            ProviderCapability::RegistryKeys,
            ProviderCapability::FilePresence,
            ProviderCapability::PrefetchEntries,
        ]);
        let result = evaluate_rule(&rule, &mock);
        assert!(result.is_none(), "No artifacts present, should not match");
    }

    #[test]
    fn test_evaluate_registry_match() {
        let rule = teamviewer_rule();
        let mut mock = MockArtifactProvider::new(vec![
            ProviderCapability::RegistryKeys,
            ProviderCapability::FilePresence,
            ProviderCapability::PrefetchEntries,
        ]);
        mock.add_registry_key(r"HKLM\SOFTWARE\TeamViewer");

        let result = evaluate_rule(&rule, &mock);
        assert!(result.is_some(), "Registry key match should produce finding");
        let finding = result.expect("finding");
        assert_eq!(finding.tool_name, "TeamViewer");
        assert_eq!(finding.category, RemoteAccessCategory::CommercialRmm);
        assert_eq!(finding.artifacts.len(), 1);
        assert_eq!(finding.artifacts[0].artifact_type, HitArtifactType::RegistryKey);
    }

    #[test]
    fn test_evaluate_multiple_hits() {
        let rule = teamviewer_rule();
        let mut mock = MockArtifactProvider::new(vec![
            ProviderCapability::RegistryKeys,
            ProviderCapability::FilePresence,
            ProviderCapability::PrefetchEntries,
        ]);
        mock.add_registry_key(r"HKLM\SOFTWARE\TeamViewer");
        mock.add_file(
            r"C:\Program Files\TeamViewer\*",
            FileEntry {
                path: r"C:\Program Files\TeamViewer\TeamViewer.exe".into(),
                size: Some(50_000_000),
                created: Some(1_700_000_000_000_000_000),
                modified: None,
            },
        );

        let finding = evaluate_rule(&rule, &mock).expect("should match");
        assert_eq!(finding.artifacts.len(), 2);
        assert_eq!(finding.first_seen, Some(1_700_000_000_000_000_000));
    }

    #[test]
    fn test_evaluate_skips_unavailable_capabilities() {
        let rule = teamviewer_rule();
        // Only provide registry — file and prefetch conditions should be skipped.
        let mut mock = MockArtifactProvider::new(vec![ProviderCapability::RegistryKeys]);
        mock.add_registry_key(r"HKLM\SOFTWARE\TeamViewer");

        let finding = evaluate_rule(&rule, &mock).expect("should match on registry alone");
        assert_eq!(finding.artifacts.len(), 1);
    }

    #[test]
    fn test_evaluate_all_multiple_rules() {
        let rules = vec![
            teamviewer_rule(),
            DetectionRule {
                id: "lolrmm:anydesk".into(),
                tool_name: "AnyDesk".into(),
                category: RemoteAccessCategory::CommercialRmm,
                conditions: vec![DetectionCondition::RegistryKeyExists(
                    r"HKLM\SOFTWARE\AnyDesk".into(),
                )],
                source_file: "anydesk.yaml".into(),
            },
        ];

        let mut mock = MockArtifactProvider::new(vec![ProviderCapability::RegistryKeys]);
        mock.add_registry_key(r"HKLM\SOFTWARE\TeamViewer");
        // AnyDesk not present — should not match.

        let findings = evaluate_all(&rules, &mock);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool_name, "TeamViewer");
    }
}
```

- [ ] **Step 3: Update rules/mod.rs**

```rust
// crates/rt-remote-access/src/rules/mod.rs
pub mod detection_rule;
pub mod evaluator;
pub mod lolrmm;
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p rt-remote-access`
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/rt-remote-access/src/rules/
git commit -m "feat(rt-remote-access): add detection rule compiler + evaluator

Compile LOLRMM definitions into uniform DetectionRules. Evaluator
checks conditions against ArtifactProvider, skipping capabilities
the provider doesn't support."
```

---

## Task 5: Findings Aggregator + DuckDB Store

**Files:**
- Create: `crates/rt-remote-access/src/aggregator.rs`
- Create: `crates/rt-remote-access/src/store.rs`
- Modify: `crates/rt-remote-access/src/lib.rs`

- [ ] **Step 1: Write aggregator**

```rust
// crates/rt-remote-access/src/aggregator.rs
use std::collections::HashMap;

use crate::model::Finding;

/// Merge findings that refer to the same tool into a single finding.
/// Combines artifacts and recomputes first_seen / last_seen.
pub fn merge_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut by_tool: HashMap<String, Finding> = HashMap::new();

    for finding in findings {
        let key = format!("{}:{:?}", finding.tool_name, finding.category);
        by_tool
            .entry(key)
            .and_modify(|existing| {
                existing.artifacts.extend(finding.artifacts.clone());
                existing.first_seen = match (existing.first_seen, finding.first_seen) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
                existing.last_seen = match (existing.last_seen, finding.last_seen) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (a, b) => a.or(b),
                };
            })
            .or_insert(finding);
    }

    by_tool.into_values().collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::model::{
        DetectionSource, Finding, HitArtifactType, RawArtifactHit, RemoteAccessCategory,
    };

    use super::*;

    fn make_finding(tool: &str, ts: Option<i64>, source: &str) -> Finding {
        Finding {
            id: uuid::Uuid::new_v4().to_string(),
            tool_name: tool.into(),
            category: RemoteAccessCategory::CommercialRmm,
            artifacts: vec![RawArtifactHit {
                artifact_type: HitArtifactType::RegistryKey,
                source_path: "test".into(),
                value: source.into(),
                timestamp: ts,
                context: HashMap::new(),
            }],
            first_seen: ts,
            last_seen: ts,
            detection_source: DetectionSource::LolrmmRule(source.into()),
        }
    }

    #[test]
    fn test_merge_same_tool() {
        let findings = vec![
            make_finding("TeamViewer", Some(1000), "rule-a"),
            make_finding("TeamViewer", Some(2000), "rule-b"),
        ];
        let merged = merge_findings(findings);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].tool_name, "TeamViewer");
        assert_eq!(merged[0].artifacts.len(), 2);
        assert_eq!(merged[0].first_seen, Some(1000));
        assert_eq!(merged[0].last_seen, Some(2000));
    }

    #[test]
    fn test_merge_different_tools() {
        let findings = vec![
            make_finding("TeamViewer", Some(1000), "rule-a"),
            make_finding("AnyDesk", Some(2000), "rule-b"),
        ];
        let merged = merge_findings(findings);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn test_merge_no_timestamps() {
        let findings = vec![
            make_finding("Tool", None, "rule-a"),
            make_finding("Tool", None, "rule-b"),
        ];
        let merged = merge_findings(findings);
        assert_eq!(merged.len(), 1);
        assert!(merged[0].first_seen.is_none());
        assert!(merged[0].last_seen.is_none());
    }

    #[test]
    fn test_merge_empty() {
        let merged = merge_findings(vec![]);
        assert!(merged.is_empty());
    }
}
```

- [ ] **Step 2: Write DuckDB store**

```rust
// crates/rt-remote-access/src/store.rs
use rt_core::artifacts::ArtifactType;
use rt_core::timeline::event::{EventType, TimelineEvent};
use rt_timeline::store::{TimelineStore, TimelineStoreError};

use crate::model::Finding;

/// Initialize the findings schema in the timeline DuckDB database.
pub fn initialize_findings_schema(store: &TimelineStore) -> Result<(), TimelineStoreError> {
    store.connection().execute_batch(
        "CREATE TABLE IF NOT EXISTS findings (
            id              VARCHAR PRIMARY KEY,
            tool_name       VARCHAR NOT NULL,
            category        VARCHAR NOT NULL,
            first_seen_ns   BIGINT,
            last_seen_ns    BIGINT,
            artifact_count  INTEGER NOT NULL,
            artifacts_json  VARCHAR NOT NULL,
            detection_source VARCHAR NOT NULL,
            evidence_source VARCHAR NOT NULL,
            assessed_at     TIMESTAMP DEFAULT current_timestamp
        );",
    )?;
    Ok(())
}

/// Insert a finding into the findings table.
pub fn insert_finding(
    store: &TimelineStore,
    finding: &Finding,
    evidence_source: &str,
) -> Result<(), TimelineStoreError> {
    let artifacts_json =
        serde_json::to_string(&finding.artifacts).unwrap_or_else(|_| "[]".to_string());
    let detection_source_json =
        serde_json::to_string(&finding.detection_source).unwrap_or_else(|_| "\"unknown\"".to_string());

    store.connection().execute(
        "INSERT OR REPLACE INTO findings (
            id, tool_name, category, first_seen_ns, last_seen_ns,
            artifact_count, artifacts_json, detection_source, evidence_source
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        duckdb::params![
            finding.id,
            finding.tool_name,
            format!("{}", finding.category),
            finding.first_seen,
            finding.last_seen,
            finding.artifacts.len() as i32,
            artifacts_json,
            detection_source_json,
            evidence_source,
        ],
    )?;
    Ok(())
}

/// Emit a timeline cross-reference event for a finding.
pub fn emit_cross_reference_event(
    store: &TimelineStore,
    finding: &Finding,
    evidence_source_id: &str,
) -> Result<(), TimelineStoreError> {
    // Only emit if the finding has a timestamp.
    let Some(timestamp_ns) = finding.first_seen else {
        return Ok(());
    };

    let description = format!(
        "{} detected ({}) \u{2014} {} artifacts found",
        finding.tool_name,
        finding.category,
        finding.artifacts.len()
    );

    let event = TimelineEvent::new(
        timestamp_ns,
        String::new(), // display timestamp computed at report time
        EventType::Other("RemoteAccessFinding".to_string()),
        ArtifactType::Assessment,
        format!("findings/{}", finding.id),
        description,
        evidence_source_id.to_string(),
    )
    .with_metadata("finding_id", serde_json::json!(finding.id))
    .with_metadata("tool_name", serde_json::json!(finding.tool_name))
    .with_metadata("category", serde_json::json!(format!("{}", finding.category)))
    .with_tag("remote-access")
    .with_tag(&finding.tool_name.to_lowercase().replace(' ', "-"));

    store.insert_event(&event)?;
    Ok(())
}

/// Get the total number of findings.
pub fn finding_count(store: &TimelineStore) -> Result<u64, TimelineStoreError> {
    let mut stmt = store.connection().prepare("SELECT COUNT(*) FROM findings")?;
    let count: u64 = stmt.query_row([], |row| row.get(0))?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::model::{
        DetectionSource, Finding, HitArtifactType, RawArtifactHit, RemoteAccessCategory,
    };

    use super::*;

    fn sample_finding() -> Finding {
        Finding {
            id: "test-finding-001".into(),
            tool_name: "TeamViewer".into(),
            category: RemoteAccessCategory::CommercialRmm,
            artifacts: vec![RawArtifactHit {
                artifact_type: HitArtifactType::RegistryKey,
                source_path: r"HKLM\SOFTWARE\TeamViewer".into(),
                value: "Registry key exists".into(),
                timestamp: Some(1_700_000_000_000_000_000),
                context: HashMap::new(),
            }],
            first_seen: Some(1_700_000_000_000_000_000),
            last_seen: Some(1_700_000_000_000_000_000),
            detection_source: DetectionSource::LolrmmRule("teamviewer.yaml".into()),
        }
    }

    #[test]
    fn test_initialize_schema() {
        let store = TimelineStore::in_memory().expect("store");
        initialize_findings_schema(&store).expect("schema");
        // Should be idempotent.
        initialize_findings_schema(&store).expect("schema again");
    }

    #[test]
    fn test_insert_and_count_findings() {
        let store = TimelineStore::in_memory().expect("store");
        initialize_findings_schema(&store).expect("schema");

        assert_eq!(finding_count(&store).expect("count"), 0);
        insert_finding(&store, &sample_finding(), "evidence-001").expect("insert");
        assert_eq!(finding_count(&store).expect("count"), 1);
    }

    #[test]
    fn test_insert_finding_upsert() {
        let store = TimelineStore::in_memory().expect("store");
        initialize_findings_schema(&store).expect("schema");

        let finding = sample_finding();
        insert_finding(&store, &finding, "evidence-001").expect("first");
        insert_finding(&store, &finding, "evidence-001").expect("second (upsert)");
        assert_eq!(finding_count(&store).expect("count"), 1);
    }

    #[test]
    fn test_cross_reference_event() {
        let store = TimelineStore::in_memory().expect("store");
        initialize_findings_schema(&store).expect("schema");

        let finding = sample_finding();
        emit_cross_reference_event(&store, &finding, "evidence-001").expect("emit");
        assert_eq!(store.event_count().expect("count"), 1);
    }

    #[test]
    fn test_cross_reference_skipped_without_timestamp() {
        let store = TimelineStore::in_memory().expect("store");
        initialize_findings_schema(&store).expect("schema");

        let mut finding = sample_finding();
        finding.first_seen = None;
        emit_cross_reference_event(&store, &finding, "evidence-001").expect("emit");
        assert_eq!(store.event_count().expect("count"), 0);
    }
}
```

- [ ] **Step 3: Update lib.rs**

```rust
// crates/rt-remote-access/src/lib.rs
pub mod aggregator;
pub mod model;
pub mod providers;
pub mod rules;
pub mod store;
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p rt-remote-access`
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/rt-remote-access/src/aggregator.rs crates/rt-remote-access/src/store.rs crates/rt-remote-access/src/lib.rs
git commit -m "feat(rt-remote-access): add aggregator + DuckDB findings store

Merge duplicate findings per tool. Store findings in DuckDB with
timeline cross-reference events for chronological context."
```

---

## Task 6: Category Scanner Trait + Built-in Remote Scanner

**Files:**
- Create: `crates/rt-remote-access/src/scanners/mod.rs`
- Create: `crates/rt-remote-access/src/scanners/builtin_remote.rs`
- Modify: `crates/rt-remote-access/src/lib.rs`

- [ ] **Step 1: Write the CategoryScanner trait**

```rust
// crates/rt-remote-access/src/scanners/mod.rs
pub mod builtin_remote;

use crate::model::{Finding, RemoteAccessCategory};
use crate::providers::ArtifactProvider;

/// Error type for scanner operations.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("scanner error: {0}")]
    Internal(String),
}

/// Trait for behavioral category scanners.
pub trait CategoryScanner: Send + Sync {
    fn category(&self) -> RemoteAccessCategory;
    fn scan(&self, provider: &dyn ArtifactProvider) -> Result<Vec<Finding>, ScanError>;
}
```

- [ ] **Step 2: Write the built-in remote access scanner (RDP, SSH, WinRM, VNC)**

```rust
// crates/rt-remote-access/src/scanners/builtin_remote.rs
use std::collections::HashMap;

use crate::model::{
    DetectionSource, Finding, HitArtifactType, RawArtifactHit, RemoteAccessCategory,
};
use crate::providers::{ArtifactProvider, EventLogQuery, ProviderCapability};
use crate::scanners::{CategoryScanner, ScanError};

pub struct BuiltinRemoteScanner;

impl BuiltinRemoteScanner {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    fn scan_rdp(&self, provider: &dyn ArtifactProvider) -> Vec<Finding> {
        let caps = provider.capabilities();
        let mut hits: Vec<RawArtifactHit> = Vec::new();

        // Check RDP enabled status.
        if caps.contains(&ProviderCapability::RegistryKeys) {
            if let Ok(values) = provider.registry_values(
                r"SYSTEM\CurrentControlSet\Control\Terminal Server",
            ) {
                for val in &values {
                    if val.name == "fDenyTSConnections" && val.value == "0" {
                        hits.push(RawArtifactHit {
                            artifact_type: HitArtifactType::RegistryValue,
                            source_path: r"SYSTEM\CurrentControlSet\Control\Terminal Server".into(),
                            value: "RDP enabled (fDenyTSConnections=0)".into(),
                            timestamp: val.timestamp,
                            context: HashMap::new(),
                        });
                    }
                }
            }

            // Check NLA status.
            if let Ok(values) = provider.registry_values(
                r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            ) {
                for val in &values {
                    if val.name == "SecurityLayer" && val.value == "0" {
                        hits.push(RawArtifactHit {
                            artifact_type: HitArtifactType::RegistryValue,
                            source_path: r"SYSTEM\...\WinStations\RDP-Tcp".into(),
                            value: "NLA disabled (SecurityLayer=0) — weaker authentication".into(),
                            timestamp: val.timestamp,
                            context: HashMap::from([("risk".into(), "high".into())]),
                        });
                    }
                    // Non-standard port.
                    if val.name == "PortNumber" && val.value != "3389" {
                        hits.push(RawArtifactHit {
                            artifact_type: HitArtifactType::RegistryValue,
                            source_path: r"SYSTEM\...\WinStations\RDP-Tcp".into(),
                            value: format!("Non-standard RDP port: {}", val.value),
                            timestamp: val.timestamp,
                            context: HashMap::from([("port".into(), val.value.clone())]),
                        });
                    }
                }
            }
        }

        // Check for RDP logon events.
        if caps.contains(&ProviderCapability::EventLogs) {
            if let Ok(entries) = provider.event_log_search(&EventLogQuery {
                event_id: Some(4624),
                provider_name: Some("Microsoft-Windows-Security-Auditing".into()),
                log_file: Some("Security".into()),
                keyword: None,
            }) {
                for entry in &entries {
                    if entry.data.get("LogonType").map(String::as_str) == Some("10") {
                        hits.push(RawArtifactHit {
                            artifact_type: HitArtifactType::EventLog,
                            source_path: "Security/4624".into(),
                            value: format!(
                                "RDP logon from {}",
                                entry
                                    .data
                                    .get("IpAddress")
                                    .map(String::as_str)
                                    .unwrap_or("unknown")
                            ),
                            timestamp: entry.timestamp,
                            context: entry.data.clone(),
                        });
                    }
                }
            }
        }

        if hits.is_empty() {
            return vec![];
        }

        let first_seen = hits.iter().filter_map(|h| h.timestamp).min();
        let last_seen = hits.iter().filter_map(|h| h.timestamp).max();

        vec![Finding {
            id: uuid::Uuid::new_v4().to_string(),
            tool_name: "RDP".into(),
            category: RemoteAccessCategory::BuiltInRemoteAccess,
            artifacts: hits,
            first_seen,
            last_seen,
            detection_source: DetectionSource::CategoryScanner("builtin_remote".into()),
        }]
    }

    fn scan_ssh(&self, provider: &dyn ArtifactProvider) -> Vec<Finding> {
        let caps = provider.capabilities();
        let mut hits: Vec<RawArtifactHit> = Vec::new();

        if caps.contains(&ProviderCapability::Services) {
            if let Ok(services) = provider.services() {
                for svc in &services {
                    if svc.name.to_lowercase().contains("sshd")
                        || svc.name.to_lowercase().contains("openssh")
                    {
                        hits.push(RawArtifactHit {
                            artifact_type: HitArtifactType::Service,
                            source_path: format!("Services\\{}", svc.name),
                            value: format!("SSH service: {} ({})", svc.display_name, svc.image_path),
                            timestamp: None,
                            context: HashMap::from([
                                ("start_type".into(), svc.start_type.to_string()),
                            ]),
                        });
                    }
                }
            }
        }

        if caps.contains(&ProviderCapability::FilePresence) {
            if let Ok(files) = provider.file_exists("*sshd_config*") {
                for file in &files {
                    hits.push(RawArtifactHit {
                        artifact_type: HitArtifactType::FilePresence,
                        source_path: file.path.clone(),
                        value: "SSH server configuration found".into(),
                        timestamp: file.modified,
                        context: HashMap::new(),
                    });
                }
            }
        }

        if hits.is_empty() {
            return vec![];
        }

        let first_seen = hits.iter().filter_map(|h| h.timestamp).min();
        let last_seen = hits.iter().filter_map(|h| h.timestamp).max();

        vec![Finding {
            id: uuid::Uuid::new_v4().to_string(),
            tool_name: "SSH".into(),
            category: RemoteAccessCategory::BuiltInRemoteAccess,
            artifacts: hits,
            first_seen,
            last_seen,
            detection_source: DetectionSource::CategoryScanner("builtin_remote".into()),
        }]
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
        findings.extend(self.scan_rdp(provider));
        findings.extend(self.scan_ssh(provider));
        // WinRM and VNC scanners follow the same pattern — add in subsequent commits.
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{EventLogEntry, MockArtifactProvider, ProviderCapability, RegistryEntry, ServiceEntry};

    #[test]
    fn test_rdp_enabled_detected() {
        let mut mock = MockArtifactProvider::new(vec![
            ProviderCapability::RegistryKeys,
            ProviderCapability::EventLogs,
        ]);
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
        let findings = scanner.scan(&mock).expect("scan");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool_name, "RDP");
        assert!(!findings[0].artifacts.is_empty());
    }

    #[test]
    fn test_rdp_nla_disabled() {
        let mut mock = MockArtifactProvider::new(vec![
            ProviderCapability::RegistryKeys,
            ProviderCapability::EventLogs,
        ]);
        mock.add_registry_value(
            r"SYSTEM\CurrentControlSet\Control\Terminal Server",
            RegistryEntry {
                path: "...".into(),
                name: "fDenyTSConnections".into(),
                value: "0".into(),
                data_type: "REG_DWORD".into(),
                timestamp: None,
            },
        );
        mock.add_registry_value(
            r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            RegistryEntry {
                path: "...".into(),
                name: "SecurityLayer".into(),
                value: "0".into(),
                data_type: "REG_DWORD".into(),
                timestamp: None,
            },
        );

        let scanner = BuiltinRemoteScanner::new();
        let findings = scanner.scan(&mock).expect("scan");
        assert_eq!(findings.len(), 1);
        // Should have at least 2 artifacts (RDP enabled + NLA disabled).
        assert!(findings[0].artifacts.len() >= 2);
    }

    #[test]
    fn test_rdp_logon_events() {
        let mut mock = MockArtifactProvider::new(vec![
            ProviderCapability::RegistryKeys,
            ProviderCapability::EventLogs,
        ]);
        mock.add_event_log(EventLogEntry {
            event_id: 4624,
            provider_name: "Microsoft-Windows-Security-Auditing".into(),
            log_file: "Security".into(),
            timestamp: Some(1_700_000_000_000_000_000),
            data: HashMap::from([
                ("LogonType".into(), "10".into()),
                ("IpAddress".into(), "192.168.1.100".into()),
            ]),
        });

        let scanner = BuiltinRemoteScanner::new();
        let findings = scanner.scan(&mock).expect("scan");
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .artifacts
            .iter()
            .any(|a| a.value.contains("192.168.1.100")));
    }

    #[test]
    fn test_ssh_service_detected() {
        let mut mock = MockArtifactProvider::new(vec![
            ProviderCapability::Services,
            ProviderCapability::FilePresence,
        ]);
        mock.add_service(ServiceEntry {
            name: "sshd".into(),
            display_name: "OpenSSH SSH Server".into(),
            image_path: r"C:\Windows\System32\OpenSSH\sshd.exe".into(),
            start_type: 2,
            service_type: 16,
            account: Some("LocalSystem".into()),
        });

        let scanner = BuiltinRemoteScanner::new();
        let findings = scanner.scan(&mock).expect("scan");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool_name, "SSH");
    }

    #[test]
    fn test_no_remote_access_found() {
        let mock = MockArtifactProvider::new(vec![
            ProviderCapability::RegistryKeys,
            ProviderCapability::EventLogs,
            ProviderCapability::Services,
            ProviderCapability::FilePresence,
        ]);
        let scanner = BuiltinRemoteScanner::new();
        let findings = scanner.scan(&mock).expect("scan");
        assert!(findings.is_empty());
    }
}
```

- [ ] **Step 3: Update lib.rs**

```rust
// crates/rt-remote-access/src/lib.rs
pub mod aggregator;
pub mod model;
pub mod providers;
pub mod rules;
pub mod scanners;
pub mod store;
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p rt-remote-access`
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/rt-remote-access/src/scanners/ crates/rt-remote-access/src/lib.rs
git commit -m "feat(rt-remote-access): add CategoryScanner trait + built-in remote scanner

RDP config assessment (enabled, NLA, port, logon events) and SSH
service/config detection. CategoryScanner trait for behavioral scanners."
```

---

## Task 7: Remaining Category Scanners (Stubs with Key Detection Logic)

**Files:**
- Create: `crates/rt-remote-access/src/scanners/tunneling.rs`
- Create: `crates/rt-remote-access/src/scanners/lateral_movement.rs`
- Create: `crates/rt-remote-access/src/scanners/c2.rs`
- Create: `crates/rt-remote-access/src/scanners/webshell.rs`
- Create: `crates/rt-remote-access/src/scanners/firewall.rs`
- Create: `crates/rt-remote-access/src/scanners/hardware.rs`
- Modify: `crates/rt-remote-access/src/scanners/mod.rs`

Each scanner follows the same pattern as `builtin_remote.rs`. For brevity the plan provides the lateral movement scanner in full (the most complex) and specifies the key detection logic for each other scanner. Implement each scanner with at least 2 test cases.

- [ ] **Step 1: Write lateral_movement.rs**

This scanner detects PsExec (Event 7045 with PSEXESVC), WMI activity (Event 5857), and Kerberoasting (Event 4769 with RC4 encryption). Follow the exact same structure as `builtin_remote.rs` — private methods per tool (`scan_psexec`, `scan_wmi`, `scan_kerberoasting`), each querying event logs via `provider.event_log_search()`.

Key detection conditions:
- **PsExec**: Event 7045 where `ServiceName` contains "PSEXESVC"
- **WMI**: Event 5857 from provider "Microsoft-Windows-WMI-Activity"
- **Kerberoasting**: Event 4769 where `TicketEncryptionType` == "0x17" (RC4) and `TargetUserName` does not end with "$"

Tests: mock provider with matching events → verify findings; mock with no matching events → empty.

- [ ] **Step 2: Write tunneling.rs**

Key detection conditions:
- **ngrok**: Prefetch match for "NGROK", service named "ngrok"
- **cloudflared**: Prefetch match for "CLOUDFLARED", service named "cloudflared"
- **netsh portproxy**: Registry key `SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4`

Tests: mock with ngrok prefetch hit, mock with portproxy registry key.

- [ ] **Step 3: Write c2.rs, webshell.rs, firewall.rs, hardware.rs**

Each follows the same pattern. Minimal initial logic:

- **c2.rs**: Event 7045 with encoded/base64 ImagePath, named pipe patterns via event logs
- **webshell.rs**: File existence checks in web root paths (`*inetpub*wwwroot*`, `*xampp*htdocs*`)
- **firewall.rs**: Registry key `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy` values for domain/standard/public profile enabled status
- **hardware.rs**: File/service checks for iLO/iDRAC/IPMI/AMT

- [ ] **Step 4: Update scanners/mod.rs to register all scanners**

```rust
// crates/rt-remote-access/src/scanners/mod.rs
pub mod builtin_remote;
pub mod c2;
pub mod firewall;
pub mod hardware;
pub mod lateral_movement;
pub mod tunneling;
pub mod webshell;

// ... (trait definition stays the same)

/// Return all available category scanners.
pub fn all_scanners() -> Vec<Box<dyn CategoryScanner>> {
    vec![
        Box::new(builtin_remote::BuiltinRemoteScanner::new()),
        Box::new(lateral_movement::LateralMovementScanner::new()),
        Box::new(tunneling::TunnelingScanner::new()),
        Box::new(c2::C2Scanner::new()),
        Box::new(webshell::WebShellScanner::new()),
        Box::new(firewall::FirewallScanner::new()),
        Box::new(hardware::HardwareScanner::new()),
    ]
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p rt-remote-access`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/rt-remote-access/src/scanners/
git commit -m "feat(rt-remote-access): add all category scanners

Lateral movement (PsExec/WMI/Kerberoasting), tunneling (ngrok/
cloudflared/portproxy), C2 indicators, web shell detection,
firewall config assessment, hardware remote access."
```

---

## Task 8: Public Scan API + Orchestration

**Files:**
- Modify: `crates/rt-remote-access/src/lib.rs`

- [ ] **Step 1: Write the top-level scan function and ScanConfig**

```rust
// crates/rt-remote-access/src/lib.rs
pub mod aggregator;
pub mod model;
pub mod providers;
pub mod rules;
pub mod scanners;
pub mod store;

use std::path::Path;

use model::{Finding, RemoteAccessCategory};
use providers::ArtifactProvider;
use rules::detection_rule::compile_lolrmm;
use rules::evaluator::evaluate_all;
use rules::lolrmm::load_lolrmm_directory;
use scanners::CategoryScanner;

/// Configuration for a remote access scan.
pub struct ScanConfig {
    /// Directory containing LOLRMM YAML files.
    pub lolrmm_dir: Option<std::path::PathBuf>,
    /// Directory containing custom YAML definitions.
    pub custom_rules_dir: Option<std::path::PathBuf>,
    /// Which categories to scan (None = all).
    pub categories: Option<Vec<RemoteAccessCategory>>,
}

/// Result of a remote access scan.
pub struct ScanResult {
    /// All findings (merged by tool).
    pub findings: Vec<Finding>,
    /// Which provider capabilities were available.
    pub available_capabilities: Vec<providers::ProviderCapability>,
    /// Which categories were scanned.
    pub categories_scanned: Vec<RemoteAccessCategory>,
}

/// Run a full remote access scan.
pub fn scan(
    provider: &dyn ArtifactProvider,
    config: &ScanConfig,
) -> ScanResult {
    let available_capabilities = provider.capabilities();
    let mut all_findings: Vec<Finding> = Vec::new();

    // Phase 1: Rule engine — load LOLRMM + custom YAML, compile, evaluate.
    if let Some(ref lolrmm_dir) = config.lolrmm_dir {
        if lolrmm_dir.is_dir() {
            if let Ok(defs) = load_lolrmm_directory(lolrmm_dir) {
                let rules: Vec<_> = defs
                    .iter()
                    .map(|d| compile_lolrmm(d, &d.name))
                    .collect();
                let findings = evaluate_all(&rules, provider);
                all_findings.extend(findings);
            }
        }
    }

    if let Some(ref custom_dir) = config.custom_rules_dir {
        if custom_dir.is_dir() {
            if let Ok(defs) = load_lolrmm_directory(custom_dir) {
                let rules: Vec<_> = defs
                    .iter()
                    .map(|d| compile_lolrmm(d, &d.name))
                    .collect();
                let findings = evaluate_all(&rules, provider);
                all_findings.extend(findings);
            }
        }
    }

    // Phase 2: Category scanners.
    let all_scanners = scanners::all_scanners();
    let mut categories_scanned = Vec::new();

    for scanner in &all_scanners {
        let category = scanner.category();
        if let Some(ref filter) = config.categories {
            if !filter.contains(&category) {
                continue;
            }
        }
        categories_scanned.push(category);

        match scanner.scan(provider) {
            Ok(findings) => all_findings.extend(findings),
            Err(e) => {
                tracing::warn!(
                    scanner = %std::any::type_name_of_val(&**scanner),
                    error = %e,
                    "category scanner failed"
                );
            }
        }
    }

    // Phase 3: Merge findings by tool.
    let merged = aggregator::merge_findings(all_findings);

    ScanResult {
        findings: merged,
        available_capabilities,
        categories_scanned,
    }
}
```

- [ ] **Step 2: Write integration test**

Add to `crates/rt-remote-access/src/lib.rs` (or a separate test file):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{MockArtifactProvider, ProviderCapability, RegistryEntry};

    #[test]
    fn test_scan_with_mock_provider() {
        let mut mock = MockArtifactProvider::new(vec![
            ProviderCapability::RegistryKeys,
            ProviderCapability::EventLogs,
            ProviderCapability::Services,
            ProviderCapability::FilePresence,
        ]);
        // Add TeamViewer-like registry key (won't match without LOLRMM rules loaded).
        mock.add_registry_value(
            r"SYSTEM\CurrentControlSet\Control\Terminal Server",
            RegistryEntry {
                path: "...".into(),
                name: "fDenyTSConnections".into(),
                value: "0".into(),
                data_type: "REG_DWORD".into(),
                timestamp: None,
            },
        );

        let config = ScanConfig {
            lolrmm_dir: None,
            custom_rules_dir: None,
            categories: None,
        };

        let result = scan(&mock, &config);
        // Should find RDP via built-in remote scanner.
        assert!(
            result.findings.iter().any(|f| f.tool_name == "RDP"),
            "Should detect RDP as enabled"
        );
    }

    #[test]
    fn test_scan_empty_provider() {
        let mock = MockArtifactProvider::new(vec![]);
        let config = ScanConfig {
            lolrmm_dir: None,
            custom_rules_dir: None,
            categories: None,
        };

        let result = scan(&mock, &config);
        assert!(result.findings.is_empty());
        assert!(result.available_capabilities.is_empty());
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p rt-remote-access`
Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git add crates/rt-remote-access/src/lib.rs
git commit -m "feat(rt-remote-access): add top-level scan() API

Orchestrates rule engine (LOLRMM + custom YAML) and category
scanners. Returns merged findings with capability coverage."
```

---

## Task 9: Filesystem Provider (First Real Provider)

**Files:**
- Create: `crates/rt-remote-access/src/providers/filesystem.rs`
- Modify: `crates/rt-remote-access/src/providers/mod.rs`

- [ ] **Step 1: Write filesystem provider with glob matching**

The filesystem provider checks if files/directories exist under an evidence root path. Uses the `glob` crate for pattern matching.

```rust
// crates/rt-remote-access/src/providers/filesystem.rs
use std::path::{Path, PathBuf};

use crate::providers::{ArtifactProvider, FileEntry, ProviderCapability, ProviderError};

/// Checks file existence against a mounted evidence filesystem.
pub struct FilesystemProvider {
    root: PathBuf,
}

impl FilesystemProvider {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }
}

impl ArtifactProvider for FilesystemProvider {
    fn capabilities(&self) -> Vec<ProviderCapability> {
        vec![ProviderCapability::FilePresence]
    }

    fn file_exists(&self, pattern: &str) -> Result<Vec<FileEntry>, ProviderError> {
        // Normalize the pattern: strip drive letter, convert backslashes.
        let normalized = pattern
            .trim_start_matches(|c: char| c.is_ascii_alphabetic())
            .trim_start_matches(':')
            .replace('\\', "/");

        let full_pattern = format!("{}{normalized}", self.root.display());

        let entries: Vec<FileEntry> = glob::glob(&full_pattern)
            .map_err(|e| ProviderError::Internal(format!("glob error: {e}")))?
            .filter_map(Result::ok)
            .filter(|p| p.is_file())
            .map(|path| {
                let metadata = path.metadata().ok();
                FileEntry {
                    path: path.to_string_lossy().to_string(),
                    size: metadata.as_ref().map(|m| m.len()),
                    created: None, // would need platform-specific code
                    modified: None,
                }
            })
            .collect();

        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filesystem_provider_finds_files() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let sub = dir.path().join("Program Files").join("TestApp");
        std::fs::create_dir_all(&sub).expect("mkdir");
        std::fs::write(sub.join("test.exe"), b"fake exe").expect("write");

        let provider = FilesystemProvider::new(dir.path());
        let results = provider
            .file_exists("Program Files/TestApp/*")
            .expect("query");
        assert_eq!(results.len(), 1);
        assert!(results[0].path.contains("test.exe"));
    }

    #[test]
    fn test_filesystem_provider_no_match() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let provider = FilesystemProvider::new(dir.path());
        let results = provider.file_exists("NonExistent/*").expect("query");
        assert!(results.is_empty());
    }

    #[test]
    fn test_filesystem_provider_normalizes_windows_paths() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let sub = dir.path().join("Program Files").join("AnyDesk");
        std::fs::create_dir_all(&sub).expect("mkdir");
        std::fs::write(sub.join("AnyDesk.exe"), b"fake").expect("write");

        let provider = FilesystemProvider::new(dir.path());
        // Windows-style path with backslashes and drive letter.
        let results = provider
            .file_exists(r"C:\Program Files\AnyDesk\*")
            .expect("query");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_capabilities() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let provider = FilesystemProvider::new(dir.path());
        assert_eq!(provider.capabilities(), vec![ProviderCapability::FilePresence]);
    }
}
```

- [ ] **Step 2: Export from providers/mod.rs**

Add `pub mod filesystem;` to `crates/rt-remote-access/src/providers/mod.rs`.

- [ ] **Step 3: Run tests**

Run: `cargo test -p rt-remote-access`
Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git add crates/rt-remote-access/src/providers/filesystem.rs crates/rt-remote-access/src/providers/mod.rs
git commit -m "feat(rt-remote-access): add filesystem artifact provider

Glob-based file existence checks against mounted evidence.
Normalizes Windows paths (drive letters, backslashes)."
```

---

## Task 10: CLI Subcommand + E2E Tests

**Files:**
- Create: `crates/rt-cli/src/commands/remote_access.rs`
- Modify: `crates/rt-cli/src/main.rs`
- Modify: `crates/rt-cli/src/commands/mod.rs`
- Modify: `crates/rt-cli/Cargo.toml`
- Modify: `crates/rt-cli/tests/cli_tests.rs`

- [ ] **Step 1: Add rt-remote-access dependency to rt-cli**

In `crates/rt-cli/Cargo.toml`, add:
```toml
rt-remote-access = { workspace = true }
```

- [ ] **Step 2: Add RemoteAccess subcommand to main.rs**

Add to `Commands` enum in `crates/rt-cli/src/main.rs`:

```rust
    /// Scan evidence for remote access infrastructure.
    RemoteAccess {
        /// Path to evidence directory or mounted image.
        #[arg(value_name = "EVIDENCE_PATH")]
        evidence_path: PathBuf,

        /// Path to LOLRMM YAML rules directory.
        #[arg(long)]
        rules_dir: Option<PathBuf>,

        /// Path to custom YAML definitions directory.
        #[arg(long)]
        custom_rules: Option<PathBuf>,

        /// Comma-separated categories to scan (default: all).
        #[arg(long)]
        categories: Option<String>,

        /// Output format: table, json.
        #[arg(long, default_value = "table")]
        format: String,

        /// DuckDB database to write findings into.
        #[arg(long)]
        db: Option<PathBuf>,
    },
```

Add the match arm in `main()`:

```rust
        Commands::RemoteAccess {
            evidence_path,
            rules_dir,
            custom_rules,
            categories,
            format,
            db,
        } => commands::remote_access::run(
            &evidence_path,
            rules_dir.as_deref(),
            custom_rules.as_deref(),
            categories.as_deref(),
            &format,
            db.as_deref(),
        ),
```

- [ ] **Step 3: Create commands/remote_access.rs**

```rust
// crates/rt-cli/src/commands/remote_access.rs
use std::path::Path;

use anyhow::{Context, Result};
use rt_remote_access::providers::filesystem::FilesystemProvider;
use rt_remote_access::providers::CompositeArtifactProvider;
use rt_remote_access::ScanConfig;

pub fn run(
    evidence_path: &Path,
    rules_dir: Option<&Path>,
    custom_rules: Option<&Path>,
    categories: Option<&str>,
    format: &str,
    db: Option<&Path>,
) -> Result<()> {
    if !evidence_path.exists() {
        anyhow::bail!("Evidence path does not exist: {}", evidence_path.display());
    }

    // Build composite provider from available evidence.
    let mut composite = CompositeArtifactProvider::new();
    composite.add_provider(Box::new(FilesystemProvider::new(evidence_path)));
    // Additional providers (registry, evtx, etc.) added in future tasks.

    let config = ScanConfig {
        lolrmm_dir: rules_dir.map(std::path::PathBuf::from),
        custom_rules_dir: custom_rules.map(std::path::PathBuf::from),
        categories: None, // TODO: parse categories string
    };

    let result = rt_remote_access::scan(&composite, &config);

    // Print results.
    if result.findings.is_empty() {
        println!("No remote access artifacts detected.");
    } else {
        println!("Found {} remote access tool(s):\n", result.findings.len());
        for finding in &result.findings {
            match format {
                "json" => {
                    let json =
                        serde_json::to_string_pretty(finding).unwrap_or_else(|_| "{}".into());
                    println!("{json}");
                }
                _ => {
                    println!(
                        "  {} [{}] — {} artifact(s)",
                        finding.tool_name,
                        finding.category,
                        finding.artifacts.len()
                    );
                    if let Some(first) = finding.first_seen {
                        println!("    First seen: {first}");
                    }
                    if let Some(last) = finding.last_seen {
                        println!("    Last seen:  {last}");
                    }
                }
            }
        }
    }

    // Write to DuckDB if requested.
    if let Some(db_path) = db {
        let store = rt_timeline::store::TimelineStore::open(db_path)
            .with_context(|| format!("Failed to open database: {}", db_path.display()))?;
        rt_remote_access::store::initialize_findings_schema(&store)
            .context("Failed to create findings schema")?;
        for finding in &result.findings {
            rt_remote_access::store::insert_finding(&store, finding, "cli-scan")
                .context("Failed to insert finding")?;
            rt_remote_access::store::emit_cross_reference_event(&store, finding, "cli-scan")
                .context("Failed to emit cross-reference")?;
        }
        println!(
            "\nFindings written to {}",
            db_path.display()
        );
    }

    Ok(())
}
```

- [ ] **Step 4: Register in commands/mod.rs**

Add `pub mod remote_access;` to `crates/rt-cli/src/commands/mod.rs`.

- [ ] **Step 5: Add CLI e2e tests**

Add to `crates/rt-cli/tests/cli_tests.rs`:

```rust
#[test]
fn test_remote_access_help() {
    rt_cmd()
        .args(["remote-access", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("remote access"));
}

#[test]
fn test_remote_access_missing_path() {
    rt_cmd()
        .args(["remote-access", "/nonexistent/path"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"));
}

#[test]
fn test_remote_access_empty_dir() {
    let dir = TempDir::new().expect("tmpdir");
    rt_cmd()
        .args(["remote-access", &dir.path().to_string_lossy()])
        .assert()
        .success()
        .stdout(predicate::str::contains("No remote access artifacts detected"));
}

#[test]
fn test_remote_access_json_format() {
    let dir = TempDir::new().expect("tmpdir");
    rt_cmd()
        .args([
            "remote-access",
            &dir.path().to_string_lossy(),
            "--format",
            "json",
        ])
        .assert()
        .success();
}
```

Also update `test_help_flag` to include `"remote-access"`.

- [ ] **Step 6: Run tests**

Run: `cargo test -p rt-cli`
Expected: All tests pass (existing + new).

Run: `cargo test --workspace`
Expected: All 419+ tests pass.

- [ ] **Step 7: Commit**

```bash
git add crates/rt-cli/ crates/rt-remote-access/ Cargo.toml
git commit -m "feat(rt-cli): add 'remote-access' subcommand

Scan evidence for remote access infrastructure. Outputs table or
JSON. Optionally writes findings to DuckDB timeline database."
```

---

## Task 11: Vendor LOLRMM Data + Integration Test

**Files:**
- Create: `crates/rt-remote-access/data/lolrmm/` (vendored YAML files)
- Create: `crates/rt-remote-access/data/custom/` (VPN/ZTNA definitions)

- [ ] **Step 1: Vendor full LOLRMM YAML catalog**

```bash
cd crates/rt-remote-access
mkdir -p data/lolrmm data/custom
# Download all LOLRMM YAML files.
git clone --depth 1 https://github.com/magicsword-io/LOLRMM.git /tmp/lolrmm-clone
cp /tmp/lolrmm-clone/yaml/*.yaml data/lolrmm/
rm -rf /tmp/lolrmm-clone
ls data/lolrmm/ | wc -l  # Should be ~294 files
```

- [ ] **Step 2: Write 3-5 custom VPN/ZTNA YAML definitions**

Create `data/custom/tailscale.yaml`, `data/custom/wireguard.yaml`, `data/custom/openvpn.yaml` using the LOLRMM schema format. Example:

```yaml
# crates/rt-remote-access/data/custom/tailscale.yaml
Name: Tailscale
Category: VPN
Description: |
    Tailscale is a mesh VPN built on WireGuard that provides direct
    device-to-device connectivity via ZTNA.
Details:
    Website: https://tailscale.com
    SupportedOS:
        - Windows
        - macOS
        - Linux
    InstallationPaths:
        - C:\Program Files\Tailscale\*
        - C:\Program Files (x86)\Tailscale\*
Artifacts:
    Disk:
        - File: '%ProgramFiles%\Tailscale\tailscaled.exe'
          Description: 'Tailscale daemon'
          OS: Windows
    Registry:
        - Path: HKLM\SYSTEM\CurrentControlSet\Services\Tailscale
          Description: 'Tailscale service registration'
    Network:
        - Description: 'Tailscale coordination server'
          Domains:
              - controlplane.tailscale.com
              - login.tailscale.com
          Ports:
              - 41641
```

- [ ] **Step 3: Write integration test loading full catalog**

```rust
#[test]
fn test_load_full_lolrmm_catalog() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("lolrmm");
    if !dir.exists() {
        eprintln!("Skipping: LOLRMM data not vendored yet");
        return;
    }
    let defs = load_lolrmm_directory(&dir).expect("load");
    assert!(defs.len() > 200, "Expected 200+ tools, got {}", defs.len());

    // Verify a few well-known tools are present.
    let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
    assert!(names.contains(&"AnyDesk"), "AnyDesk should be in catalog");
    assert!(names.contains(&"TeamViewer"), "TeamViewer should be in catalog");
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p rt-remote-access`
Expected: All tests pass including full catalog load.

- [ ] **Step 5: Commit**

```bash
git add crates/rt-remote-access/data/
git commit -m "data: vendor LOLRMM YAML catalog + custom VPN/ZTNA definitions

294 LOLRMM RMM tool definitions (Apache-2.0) plus custom YAML
for Tailscale, WireGuard, and OpenVPN detection."
```

---

## Task 12: Ralph Loop — Full Workspace Verification

- [ ] **Step 1: cargo fmt --all -- --check**

Run: `cargo fmt --all -- --check`
Expected: No formatting issues.

- [ ] **Step 2: cargo clippy --workspace --lib --bins**

Run: `cargo clippy --workspace --lib --bins`
Expected: No errors (warnings OK for doc_markdown pedantic lint).

- [ ] **Step 3: cargo test --workspace**

Run: `cargo test --workspace`
Expected: All tests pass (419 existing + ~50 new from rt-remote-access + CLI e2e).

- [ ] **Step 4: cargo deny check**

Run: `cargo deny check`
Expected: All pass. If new dependencies (notatin, uuid, glob, quick-xml) introduce license issues, add to deny.toml allow list.

- [ ] **Step 5: Fix any issues and re-verify**

Iterate until all 4 checks pass clean.

- [ ] **Step 6: Push**

```bash
git push origin main
```

---

## Follow-Up (Out of Scope for This Plan)

- **Report integration**: The spec calls for `rt-report` to gain a "Remote Access Assessment" section (summary table, expandable per-tool detail, coverage indicator). This is a separate task that depends on the findings table schema being stable. Implement after this plan is complete.
- **Additional providers**: Registry (notatin), prefetch (frnsc-prefetch), amcache (frnsc-amcache), evtx, LNK, jumplist providers. Each provider is an independent task that enriches scan results without changing the scanner architecture.
- **Pipeline integration**: Wire `rt-remote-access::scan()` into `rt-pipeline` post-ingest phase. Depends on providers being available.
- **ASM/OSINT scanner**: Subsystem 2 — separate spec and plan.
