# Remote Access Artifact Scanner — Design Spec

**Date:** 2026-03-23
**Status:** Approved
**Scope:** Subsystem 1 of 2 (Subsystem 2: ASM/OSINT Exposure Scanner — separate spec)

## Goal

Detect every form of remote access capability present on a forensic evidence image — commercial RMM tools, built-in remote access (RDP/SSH/WinRM/VNC), VPN/ZTNA clients, tunneling/reverse shells, lateral movement, C2 frameworks, web shells, firewall misconfigurations, and hardware remote access — by scanning parsed forensic artifacts and producing structured assessment findings.

## Architecture

Hybrid detection engine in a new `rt-remote-access` crate. A rule engine consumes LOLRMM YAML definitions (294 RMM tools, Apache-2.0) and custom YAML definitions for presence-based detection. Category-specific scanner modules handle behavioral/correlation-heavy detection. Both share a pluggable `ArtifactProvider` interface that abstracts over available artifact sources, gracefully degrading when parsers are missing.

Findings stored in a dedicated DuckDB `findings` table with lightweight cross-reference events emitted into the existing timeline, so analysts see remote access evidence in chronological context.

## Tech Stack

- **Rust** (workspace crate `rt-remote-access`)
- **notatin** (Apache-2.0) — Windows registry hive parsing
- **frnsc-prefetch** (MIT) — Prefetch file parsing
- **frnsc-amcache** (MIT) — Amcache parsing
- **lnk_parser** (MIT) — LNK shortcut parsing
- **jumplist_parser** (MIT) — Jumplist parsing
- **quick-xml** — Scheduled task XML parsing
- **serde + serde_yaml** — LOLRMM YAML loading
- **LOLRMM data** (Apache-2.0) — 294 RMM tool detection definitions
- **Artemis** (MIT) — Reference for ShimCache, BAM/DAM, UserAssist, SRUM parsers

---

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Detection model | Hybrid: Sigma/YARA + LOLRMM YAML + category scanners | Maximize community rule reuse (Sigma, YARA, LOLRMM) while allowing behavioral detection for complex categories |
| LOLRMM schema | Consume natively, no translation | Enables drop-in updates from upstream; 294 tools immediately available |
| Evidence grading | Raw artifacts with tags, scored at report time | Separates detection from interpretation; analysts can apply own weighting |
| Crate placement | New `rt-remote-access` crate | Thematic assessment is semantically different from raw signature matching; clean separation of concerns |
| Artifact access | Pluggable `ArtifactProvider` trait with graceful degradation | Scanner works with whatever parsers are available; missing sources produce coverage gaps, not errors |
| Storage | Findings table + timeline cross-references | Analysts get both views: chronological (timeline) and assessment (findings table) |
| Scope | All 9 categories in v1 | Categories 5-6 lean on existing Sigma/YARA; marginal cost is low |
| SRUM/ESE | Deferred (Tier 3) — FFI to libesedb or extract from Artemis | No stable pure-Rust ESE parser; design accommodates adding it later via provider interface |

## Detection Categories

| # | Category | Engine | Detection Approach |
|---|----------|--------|--------------------|
| 1 | Commercial RMM (260+ tools) | Rule engine | LOLRMM YAML → presence checks (registry, files, services, event logs, prefetch, amcache) |
| 2 | Built-in Remote Access | Category scanner | RDP/SSH/WinRM/VNC configuration assessment + event log correlation |
| 3 | VPN/ZTNA | Rule engine | Custom YAML definitions (same schema as LOLRMM) |
| 4 | Tunneling/Reverse Shells | Category scanner | Behavioral: prefetch + command-line args + scheduled tasks + LOLBin patterns |
| 5 | Lateral Movement | Category scanner | Event log correlation: PsExec (7045), WMI (5857), DCOM (10028), Kerberoasting (4769) |
| 6 | C2 Frameworks | Category scanner | Delegates to Sigma/YARA + named pipe patterns + encoded service paths |
| 7 | Web Shells | Category scanner | Filesystem scan of web roots + YARA content matching + MFT timestamp analysis |
| 8 | Firewall Config | Rule engine | Registry-based firewall profile and rule assessment |
| 9 | Hardware Remote | Rule engine | Custom YAML for iLO/iDRAC/IPMI/AMT indicators |

---

## Crate Structure

```
crates/rt-remote-access/
├── Cargo.toml
├── src/
│   ├── lib.rs                    # Public API: scan(), ScanConfig, re-exports
│   ├── model.rs                  # Finding, RawArtifactHit, RemoteAccessCategory, DetectionSource
│   ├── providers/
│   │   ├── mod.rs                # ArtifactProvider trait, CompositeArtifactProvider, ProviderCapability
│   │   ├── registry.rs           # Registry hive provider (notatin)
│   │   ├── prefetch.rs           # Prefetch provider (frnsc-prefetch)
│   │   ├── evtx.rs               # Event log provider (evtx crate)
│   │   ├── filesystem.rs         # File/directory existence checks (MFT or raw FS)
│   │   ├── amcache.rs            # Amcache provider (frnsc-amcache)
│   │   ├── lnk.rs                # LNK shortcut provider (lnk_parser)
│   │   ├── jumplist.rs           # Jumplist provider (jumplist_parser)
│   │   └── scheduled_tasks.rs    # XML task parser (quick-xml)
│   ├── rules/
│   │   ├── mod.rs                # RuleEngine: load + evaluate
│   │   ├── lolrmm.rs             # LOLRMM YAML deserialization (native schema)
│   │   ├── detection_rule.rs     # DetectionRule, DetectionCondition (uniform representation)
│   │   └── evaluator.rs          # Rule evaluation against ArtifactProvider
│   ├── scanners/
│   │   ├── mod.rs                # CategoryScanner trait, scanner registry
│   │   ├── builtin_remote.rs     # RDP, SSH, WinRM, VNC config analysis
│   │   ├── tunneling.rs          # ngrok, cloudflared, Chisel, LOLBins, reverse shells
│   │   ├── lateral_movement.rs   # PsExec, WMI, DCOM, Kerberoasting, RDP pivoting
│   │   ├── c2.rs                 # C2 framework indicators (delegates to Sigma/YARA)
│   │   ├── webshell.rs           # Web root filesystem scanning + YARA
│   │   ├── firewall.rs           # Inbound rules, port forwarding, IP forwarding
│   │   └── hardware.rs           # iLO/iDRAC/IPMI/AMT indicators
│   ├── aggregator.rs             # Group raw hits → Finding per tool
│   └── store.rs                  # DuckDB findings table + timeline cross-ref events
└── data/
    ├── lolrmm/                   # Vendored LOLRMM YAML files (294 tools)
    └── custom/                   # Custom YAML definitions (VPN/ZTNA, hardware, etc.)
```

### Dependencies

```toml
[dependencies]
rt-core = { path = "../rt-core" }
rt-timeline = { path = "../rt-timeline" }
rt-signatures = { path = "../rt-signatures" }
notatin = "1.0"
frnsc-prefetch = "0.13"
frnsc-amcache = "0.13"
lnk_parser = "0.4"
jumplist_parser = "0.1"
quick-xml = "0.37"
serde = { version = "1", features = ["derive"] }
serde_yaml = "0.9"
uuid = { version = "1", features = ["v4"] }
tracing = "0.1"
thiserror = "2"
glob = "0.3"
```

---

## Data Model

### RawArtifactHit

A single artifact observation — one registry key, one file, one event log entry.

```rust
pub struct RawArtifactHit {
    pub artifact_type: ArtifactType,
    pub source_path: String,
    pub value: String,
    pub timestamp: Option<i64>,
    pub context: HashMap<String, String>,
}

pub enum ArtifactType {
    RegistryKey, RegistryValue, FilePresence, FileContent,
    EventLog, Service, Prefetch, Amcache, ShimCache,
    ScheduledTask, NetworkIndicator, FirewallRule, LnkFile, JumplistEntry,
}
```

### Finding

An aggregated assessment — one per detected tool.

```rust
pub struct Finding {
    pub id: String,                          // UUID v4
    pub tool_name: String,                   // "TeamViewer", "PsExec", etc.
    pub category: RemoteAccessCategory,
    pub artifacts: Vec<RawArtifactHit>,
    pub first_seen: Option<i64>,
    pub last_seen: Option<i64>,
    pub detection_source: DetectionSource,
}

pub enum RemoteAccessCategory {
    CommercialRmm, BuiltInRemoteAccess, VpnZtna, Tunneling,
    LateralMovement, C2Framework, WebShell, FirewallConfig, HardwareRemote,
}

pub enum DetectionSource {
    LolrmmRule(String),
    SigmaRule(String),
    YaraRule(String),
    CategoryScanner(String),
}
```

### DuckDB Schema

```sql
CREATE TABLE IF NOT EXISTS findings (
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
);
```

### Timeline Cross-Reference Events

For each Finding with a timestamp, emit a TimelineEvent into the existing timeline table:

```
event_type:      "RemoteAccessFinding"
source:          "rt-remote-access"
description:     "{tool_name} detected ({category}) — {artifact_count} artifacts found"
metadata:        {"finding_id": "<uuid>", "tool_name": "...", "category": "..."}
tags:            "remote-access,{category-slug},{tool-name-slug}"
timestamp_ns:    first_seen from finding
```

---

## ArtifactProvider Interface

```rust
pub enum ProviderCapability {
    RegistryKeys, FilePresence, EventLogs, PrefetchEntries,
    AmcacheEntries, Services, ScheduledTasks, LnkFiles,
    Jumplists, ShimCache, BamDam, UserAssist,
}

pub trait ArtifactProvider: Send + Sync {
    fn capabilities(&self) -> Vec<ProviderCapability>;

    fn registry_key_exists(&self, path: &str) -> Result<bool, ProviderError>;
    fn registry_values(&self, path: &str) -> Result<Vec<RegistryEntry>, ProviderError>;
    fn registry_subkeys(&self, path: &str) -> Result<Vec<String>, ProviderError>;
    fn file_exists(&self, pattern: &str) -> Result<Vec<FileEntry>, ProviderError>;
    fn event_log_search(&self, query: &EventLogQuery) -> Result<Vec<EventLogEntry>, ProviderError>;
    fn prefetch_entries(&self) -> Result<Vec<PrefetchEntry>, ProviderError>;
    fn amcache_entries(&self) -> Result<Vec<AmcacheEntry>, ProviderError>;
    fn shimcache_entries(&self) -> Result<Vec<ShimCacheEntry>, ProviderError>;
    fn bam_entries(&self) -> Result<Vec<BamEntry>, ProviderError>;
    fn userassist_entries(&self) -> Result<Vec<UserAssistEntry>, ProviderError>;
    fn services(&self) -> Result<Vec<ServiceEntry>, ProviderError>;
    fn scheduled_tasks(&self) -> Result<Vec<ScheduledTaskEntry>, ProviderError>;
}
```

- All methods have default implementations returning `ProviderError::NotAvailable`
- `CompositeArtifactProvider` aggregates multiple sub-providers, delegates based on capabilities
- Scanner checks capabilities before querying; logs missing sources rather than failing

### Provider Implementations (Tier 1 — crate dependencies)

| Provider | Backing crate | Capability |
|----------|---------------|------------|
| RegistryProvider | notatin 1.0 (Apache-2.0) | RegistryKeys, Services, ShimCache, BamDam, UserAssist |
| PrefetchProvider | frnsc-prefetch 0.13 (MIT) | PrefetchEntries |
| AmcacheProvider | frnsc-amcache 0.13 (MIT) | AmcacheEntries |
| EvtxProvider | evtx crate (existing) | EventLogs |
| FilesystemProvider | MFT data or raw FS | FilePresence |
| LnkProvider | lnk_parser 0.4 (MIT) | LnkFiles |
| JumplistProvider | jumplist_parser 0.1 (MIT) | Jumplists |
| ScheduledTaskProvider | quick-xml | ScheduledTasks |

### Tier 2 — Built on registry provider (~400 LOC total)

| Artifact | Approach | Effort |
|----------|----------|--------|
| ShimCache | notatin + custom binary parser (version-aware) | ~150 LOC |
| BAM/DAM | notatin + FILETIME parsing | ~50-100 LOC |
| UserAssist | notatin + ROT13 decode + binary struct | ~100-150 LOC |
| Services | notatin + key enumeration | ~50 LOC |

### Tier 3 — Deferred

| Artifact | Approach | Notes |
|----------|----------|-------|
| SRUM (ESE DB) | FFI to libesedb or extract from Artemis | Provider interface accommodates future addition |

---

## Rule Engine

### LOLRMM Loader

Deserializes LOLRMM YAML files into Rust structs mirroring their native schema:

```rust
pub struct LolrmmDefinition {
    pub name: String,
    pub category: String,
    pub description: String,
    pub details: LolrmmDetails,
    pub artifacts: LolrmmArtifacts,
    pub detections: Vec<LolrmmDetection>,
}

pub struct LolrmmArtifacts {
    pub disk: Vec<DiskArtifact>,
    pub event_log: Vec<EventLogArtifact>,
    pub registry: Vec<RegistryArtifact>,
    pub network: Vec<NetworkArtifact>,
}
```

### Detection Rule (Uniform Representation)

LOLRMM definitions and custom YAML compile into uniform `DetectionRule` objects:

```rust
pub struct DetectionRule {
    pub id: String,
    pub tool_name: String,
    pub category: RemoteAccessCategory,
    pub conditions: Vec<DetectionCondition>,
    pub source_file: String,
}

pub enum DetectionCondition {
    RegistryKeyExists(String),
    RegistryValueContains(String, String),
    FileExists(String),
    ServiceExists(String),
    EventLogMatch { event_id: u32, provider: String, log_file: String },
    PrefetchMatch(String),
    AmcacheMatch(String),
    NetworkIndicator { domains: Vec<String>, ports: Vec<u16> },
}
```

### Evaluation Flow

1. Load all YAML files from `data/lolrmm/` + `data/custom/`
2. Compile each into DetectionRule
3. For each rule: check provider capabilities, evaluate conditions, collect hits
4. Run Sigma rules tagged `remote_access` via rt-signatures
5. Run YARA rules tagged `remote_access` via rt-signatures
6. Merge all hits into unified Finding list

### Updating LOLRMM Data

Vendored in `data/lolrmm/`. Update by pulling latest YAML files from LOLRMM GitHub. No code changes required — new YAML files are automatically loaded at scan time.

Custom VPN/ZTNA and hardware definitions maintained in `data/custom/` using the same LOLRMM schema.

---

## Category Scanners

Each implements `CategoryScanner` trait with `category()` and `scan()` methods.

### builtin_remote.rs — RDP, SSH, WinRM, VNC

Configuration risk assessment beyond presence detection:
- RDP: NLA status, non-standard port, shadow session config, restricted admin mode, Type 10 logon events
- SSH: OpenSSH server presence, sshd_config settings, authorized_keys
- WinRM: Enabled status, TrustedHosts, HTTP vs HTTPS listener, WSMan events
- VNC: Multiple flavor detection (UltraVNC, TightVNC, TigerVNC, RealVNC) with distinct artifact locations

### tunneling.rs — Reverse Tunnels, LOLBins

- ngrok/cloudflared/Chisel: execution evidence + persistence + command-line args
- LOLBins: netsh portproxy, ssh -R, plink.exe
- socat/ncat: prefetch + network artifacts

### lateral_movement.rs — Post-Compromise Movement

Event log correlation:
- PsExec: Event 7045 (PSEXESVC) + Event 4624 Type 3
- WMI: Event 5857 + Event 4648
- DCOM: Event 10028 from remote IP
- Kerberoasting: Event 4769 with RC4 (0x17) on non-machine accounts
- RDP pivoting: Type 10 logons from internal IPs

### c2.rs — C2 Framework Indicators

Delegates to Sigma/YARA + named pipe patterns + encoded service paths + beacon-like scheduled tasks.

### webshell.rs — Web Shell Detection

Filesystem scan of web roots + suspicious extensions + YARA content scanning + MFT timestamp analysis.

### firewall.rs — Firewall Configuration

Registry-based: profile enable/disable status, inbound allow rules, port forwarding, IP forwarding.

### hardware.rs — Hardware Remote Access

iLO/iDRAC/IPMI/AMT driver and software artifacts + BMC network config + Secure Boot status.

---

## CLI Integration

```
rt remote-access scan <evidence-path> [OPTIONS]

Options:
    --rules-dir <DIR>       Custom rules directory (default: bundled data/)
    --categories <LIST>     Comma-separated categories (default: all)
    --output-format <FMT>   json | table | timeline (default: table)
    --db <PATH>             DuckDB database for findings + timeline cross-refs
    --verbose               Per-artifact detail
```

### Pipeline Integration

`rt ingest` with `--scan-remote-access` flag runs scan after artifact parsing:

```
Ingest → Parse → Emit TimelineEvents → Remote access scan → Emit Findings + cross-refs
```

### Report Integration

`rt-report` HTML report gains a "Remote Access Assessment" section:
- Summary table: tool, category, artifact count, first/last seen
- Expandable per-tool artifact detail
- Coverage indicator: which artifact providers were available vs missing

---

## Testing Strategy

### Unit Tests

| Module | Approach |
|--------|----------|
| rules/lolrmm.rs | Real LOLRMM YAML fixtures (TeamViewer, AnyDesk, Splashtop) |
| rules/detection_rule.rs | Compile LOLRMM → DetectionRule, verify conditions |
| rules/evaluator.rs | MockArtifactProvider with canned data |
| model.rs | Construction, serialization, category display |
| aggregator.rs | Raw hits → grouped Findings, first/last seen |
| store.rs | In-memory DuckDB: insert + query findings |

### Provider Unit Tests

| Provider | Approach |
|----------|----------|
| registry.rs | Real small hive fixtures via notatin |
| prefetch.rs | Real .pf fixtures via frnsc-prefetch |
| evtx.rs | Existing test .evtx files |
| filesystem.rs | Tempdir with planted files |
| amcache.rs | Small Amcache.hve fixture |

### Category Scanner Tests

MockArtifactProvider simulating specific scenarios per scanner (e.g., RDP with NLA disabled, PsExec service install events).

### Integration Tests

- End-to-end: CompositeArtifactProvider from fixtures → full scan → verify DuckDB findings
- CLI e2e: `rt remote-access scan <test-dir>` → verify exit code, output, DB contents

### Test Fixtures

- Synthetic artifacts where possible (tempdir file trees, programmatic registry hives)
- 5 vendored LOLRMM YAML files for rule engine tests
- Real anonymized samples for format correctness

---

## Future Work (Out of Scope)

- **Subsystem 2: ASM/OSINT Exposure Scanner** — separate spec, separate implementation cycle
- **SRUM/ESE provider** — add when pure-Rust ESE parser stabilizes or FFI to libesedb
- **macOS/Linux remote access detection** — same architecture, different artifact providers and YAML definitions
- **Automated evidence grading** — scoring function on top of raw findings (separate concern)
- **LOLRMM contribution pipeline** — submit new tool definitions back to LOLRMM project
