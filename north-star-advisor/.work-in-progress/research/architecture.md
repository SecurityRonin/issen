# Issen Architecture Research: Plugin-Based Extensible Forensic Platform

> Research date: 2026-03-20
> Context: Solo founder, bootstrapped. Community adoption first, then paying customers.

---

## 1. Monorepo vs Multi-Repo for Mixed Open-Source/Proprietary

### Recommendation: Hybrid — Cargo Workspace Monorepo (Open-Source) + Separate Private Repo (Proprietary)

**Industry precedents:**

| Company | Model | Structure |
|---------|-------|-----------|
| **Grafana** | Single public monorepo (AGPL) + proprietary binary built separately. `LICENSING.md` draws per-directory boundaries between AGPL and Apache-2.0 packages. Enterprise features gated by license key at runtime. ([Source](https://github.com/grafana/grafana/blob/main/LICENSING.md)) |
| **HashiCorp** | Open-core with BSL 1.1 on products, MPL 2.0 on APIs/SDKs/libraries. Enterprise features in separate proprietary builds. ([Source](https://www.hashicorp.com/en/blog/hashicorp-adopts-business-source-license)) |
| **Elastic** | Returned to AGPL for core (Elasticsearch, Kibana). Proprietary plugins under separate Elastic License. ([Source](https://www.elastic.co/about/open-source)) |
| **GitLab** | CE (MIT) and EE (proprietary) as separate editions from same codebase. ([Source](https://en.wikipedia.org/wiki/Open-core_model)) |

**Issen recommended structure:**

```
github.com/h4x0r/issen          # Public monorepo (Apache 2.0 / MIT)
├── Cargo.toml                          # Virtual workspace manifest
├── LICENSING.md                        # Per-crate license declarations
├── crates/
│   ├── issen-core/                        # Core types, timeline schema, plugin traits (Apache 2.0)
│   ├── issen-pipeline/                    # Data pipeline abstractions (Apache 2.0)
│   ├── issen-plugin-sdk/                  # Plugin development SDK (Apache 2.0)
│   ├── issen-timeline/                    # Timeline storage & query engine (Apache 2.0)
│   ├── parsers/
│   │   ├── issen-parser-usnjrnl/          # USN Journal parser (Apache 2.0)
│   │   ├── issen-parser-mft/             # MFT parser (Apache 2.0)
│   │   ├── issen-parser-evtx/           # Windows Event Log (Apache 2.0)
│   │   └── ...                        # Community parsers
│   ├── issen-ewf/                        # E01/EWF reader (Apache 2.0)
│   ├── issen-shrinkpath/                 # Path utility (MIT)
│   └── issen-cli/                        # CLI frontend (Apache 2.0)
│
private-repo/issen-enterprise     # Private repo (Proprietary)
├── Cargo.toml                          # Workspace, depends on public crates via git deps
├── crates/
│   ├── issen-repoissen-engine/              # Attorney-ready report generation
│   ├── issen-correlation/                # Cross-artifact correlation engine
│   ├── issen-gui/                        # Desktop GUI (Tauri/Dioxus)
│   ├── issen-web/                        # Web UI + API server
│   ├── issen-enterprise/                 # RBAC, audit logs, team features
│   └── issen-license/                    # License validation
```

**Key design decisions:**

1. **Public workspace is self-contained** — it compiles and runs independently as a powerful CLI tool. This is critical for community adoption.
2. **Private repo references public crates via `git` dependencies** in Cargo.toml, or via a private Cargo registry (supported since Rust 1.34, [Source](https://www.infoq.com/news/2019/04/rust-1.34-additional-registries/)).
3. **Dependency flow is strictly one-directional**: proprietary crates depend on open-source crates, never the reverse. ([Source](https://openfang.one/))
4. **No git submodules** — they add friction for contributors. Use git dependencies or path overrides for local development.

---

## 2. Plugin Architecture Patterns in Rust

### Recommendation: Three-Tier Plugin System

Based on research into Rust plugin patterns ([NullDeref](https://nullderef.com/blog/plugin-dynload/), [AniLog](https://blog.anirudha.dev/rust-plugin-system/), [peerdh](https://peerdh.com/blogs/programming-insights/implementing-a-rust-based-plugin-architecture-for-dynamic-feature-loading)) and industry systems (Terraform, Autopsy, VS Code), Issen should implement three tiers:

#### Tier 1: Compile-Time Trait Plugins (First-Party Parsers)

```rust
/// Core trait all parsers implement — defined in issen-plugin-sdk
pub trait ForensicParser: Send + Sync {
    fn name(&self) -> &str;
    fn supported_artifacts(&self) -> &[ArtifactType];
    fn parse(&self, input: &dyn DataSource, emitter: &dyn EventEmitter) -> Result<ParseStats>;
    fn capabilities(&self) -> ParserCapabilities;
}

/// Registration via inventory crate or linkme for zero-cost static dispatch
inventory::submit! {
    ParserRegistration::new::<UsnJrnlParser>()
}
```

- **Use case**: All first-party and "blessed" community parsers shipped with the binary.
- **Advantage**: Zero runtime overhead, full type safety, dead code elimination.
- **Pattern precedent**: This mirrors `tl`'s existing parser architecture.
- **Crate**: Use `inventory` or `linkme` for automatic static registration without central enum.

#### Tier 2: WASM Sandboxed Plugins (Community/Third-Party)

```rust
// Host loads untrusted community plugin
let engine = wasmtime::Engine::new(&config)?;
let component = Component::from_file(&engine, "community-parser.wasm")?;
let parser = PluginInstance::instantiate(&mut store, &component, &linker)?;
let events = parser.call_parse(&mut store, artifact_data)?;
```

- **Use case**: Untrusted community-contributed parsers downloaded from a plugin registry.
- **Runtime**: `wasmtime` with WASI Preview 2 Component Model. ([Source](https://benw.is/posts/plugins-with-rust-and-wasi))
- **Safety**: Full sandboxing — plugins cannot access filesystem, network, or host memory beyond explicit grants.
- **Performance**: ~3x slower than native, acceptable for most parsers. ([Source](https://nullderef.com/blog/plugin-tech/))
- **Portability**: Single `.wasm` binary works on all platforms.
- **Component Model**: Define plugin interface via WIT (WebAssembly Interface Types) for language-agnostic plugin authoring.
- **Size consideration**: Embedding wasmtime adds ~14MB to binary. ([Source](https://nullderef.com/blog/plugin-tech/))

#### Tier 3: gRPC/IPC Process-Isolated Plugins (Enterprise/Heavy-Weight)

```rust
// Terraform-style: launch plugin as subprocess, communicate via gRPC
let plugin_process = Command::new("./issen-plugin-axiom-bridge")
    .stdout(Stdio::piped())
    .spawn()?;
// Read handshake from stdout, connect via gRPC on loopback
let channel = tonic::transport::Channel::from_shared(format!("http://127.0.0.1:{}", port))?
    .connect().await?;
```

- **Use case**: Language-agnostic integrations (Python ML models, Java Autopsy module bridges), enterprise connectors.
- **Pattern precedent**: HashiCorp's `go-plugin` system — plugins are separate OS processes communicating over gRPC on loopback. Crash isolation: plugin panic doesn't crash host. ([Source](https://zerofruit-web3.medium.com/hashicorp-plugin-system-design-and-implementation-5f939f09e3b3))
- **Protocol**: Define `.proto` files for `ForensicParser` service; version the protocol (like Terraform's `tfplugin5`/`tfplugin6`). ([Source](https://github.com/hashicorp/terraform/blob/main/docs/plugin-protocol/README.md))
- **When to use**: When plugins need full OS access, are written in other languages, or require process-level isolation for stability.

#### Plugin Discovery & Loading Priority

```
1. Built-in (Tier 1) — compiled into binary, always available
2. User plugin directory — ~/.config/issen/plugins/*.wasm (Tier 2)
3. System plugin directory — /usr/lib/issen/plugins/ (Tier 2 or Tier 3)
4. Case-specific plugins — specified in case config (any tier)
```

#### Comparison with Industry Systems

| System | Plugin Model | Isolation | Languages |
|--------|-------------|-----------|-----------|
| **Autopsy** | Java/Jython ingest modules ([Source](http://www.sleuthkit.org/autopsy/docs/api-docs/4.3/platform_page.html)) | JVM sandbox | Java, Python |
| **Terraform** | gRPC subprocess ([Source](https://developer.hashicorp.com/terraform/plugin/framework/provider-servers)) | Process | Go (primarily) |
| **VS Code** | Node.js extension host process | Process | JS/TS |
| **Neovim** | RPC (msgpack) to external processes | Process | Any |
| **Issen** | Trait (T1) + WASM (T2) + gRPC (T3) | Compile/Sandbox/Process | Rust (T1), Any→WASM (T2), Any (T3) |

---

## 3. Data Pipeline Architecture for Forensics

### Recommendation: Multi-Layer Accessor Abstraction (Velociraptor-Inspired)

The data pipeline should implement a layered abstraction stack, inspired by Velociraptor's accessor/remapping model ([Source](https://docs.velociraptor.app/docs/forensic/deaddisk/)):

```
Layer 4: Artifact Parser        (USN Journal, Event Log, Registry, etc.)
Layer 3: Filesystem Accessor    (NTFS, ext4, APFS, FAT32)
Layer 2: Volume/Partition       (GPT, MBR, LVM, APFS Container)
Layer 1: Image Format           (E01/EWF, raw/dd, VMDK, VHDX, AFF4)
Layer 0: Storage I/O            (local file, S3, network share, split files)
```

#### Core Traits

```rust
/// Layer 0: Raw byte access to evidence containers
pub trait StorageProvider: Send + Sync {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize>;
    fn size(&self) -> u64;
    fn is_seekable(&self) -> bool;
}

/// Layer 1: Disk image format decoding
pub trait ImageFormat: StorageProvider {
    fn format_name(&self) -> &str;
    fn sector_size(&self) -> u32;
    fn metadata(&self) -> &ImageMetadata; // hash, acquisition info
}

/// Layer 2: Partition/volume access
pub trait VolumeSystem {
    fn partitions(&self) -> Vec<PartitionInfo>;
    fn open_partition(&self, index: usize) -> Result<Box<dyn StorageProvider>>;
}

/// Layer 3: Filesystem operations
pub trait FilesystemAccessor: Send + Sync {
    fn read_file(&self, path: &Path) -> Result<Box<dyn Read>>;
    fn list_dir(&self, path: &Path) -> Result<Vec<DirEntry>>;
    fn metadata(&self, path: &Path) -> Result<FileMetadata>;
    fn walk(&self) -> Box<dyn Iterator<Item = WalkEntry>>;
}

/// Layer 4: Artifact parsing (= ForensicParser trait from plugin system)
```

#### The "Fused Filesystem" Concept

Velociraptor's key insight: **remap accessors to impersonate a live system**, so the same artifact parsers work on both live endpoints and dead disk images without modification. ([Source](https://docs.velociraptor.app/blog/2022/2022-03-22-deaddisk/))

Issen should implement this via a `VirtualFilesystem` that fuses multiple sources:

```rust
pub struct VirtualFilesystem {
    mounts: Vec<MountPoint>,  // e.g., C:\ -> EWF image partition 2, NTFS
}

impl VirtualFilesystem {
    /// Fuse multiple acquisition types into unified view
    /// - KAPE triage package (logical files)
    /// - Full disk image (E01)
    /// - Memory dump (for registry hives)
    /// - Cloud logs (Azure AD, M365)
    pub fn fuse(sources: Vec<DataSource>) -> Result<Self>;
}
```

#### Stream vs Batch Processing

For terabyte-scale evidence:

- **Stream processing by default**: Parsers receive a streaming `DataSource`, emit events to an `EventEmitter` — never buffer entire artifacts in memory.
- **Parallel pipeline**: Use `rayon` or `tokio` for concurrent parsing of independent artifacts from the same image.
- **Memory-mapped I/O**: For random-access artifacts (MFT, registry hives), use `memmap2` over the image format layer.
- **Progress reporting**: Each pipeline stage reports progress via channels for CLI/TUI/GUI display.

---

## 4. Unified Timeline Architecture

### Recommendation: DuckDB-Backed Columnar Timeline Store

Based on analysis of Plaso's SQLite-based architecture ([Source](https://deepwiki.com/log2timeline/plaso/3.3-storage-system)) and DuckDB's capabilities ([Source](https://endjin.com/blog/2025/04/duckdb-in-depth-how-it-works-what-makes-it-fast)), DuckDB is the superior choice for Issen's timeline backend.

#### Why DuckDB Over SQLite

| Criterion | SQLite (Plaso's choice) | DuckDB (Recommended) |
|-----------|------------------------|---------------------|
| **Storage model** | Row-oriented | Columnar — ideal for analytical scans over timestamp/type columns |
| **Time-range queries** | Requires manual indexing | Zone maps auto-skip irrelevant data |
| **Concurrent reads** | Limited | Designed for analytical concurrency |
| **Aggregation** | Slow on billions of rows | Vectorized execution, 10-100x faster |
| **Memory** | In-memory or disk | Larger-than-memory workloads natively ([Source](https://motherduck.com/duckdb-book-summary-chapter10/)) |
| **Rust integration** | `rusqlite` (mature) | `duckdb-rs` crate + Rust UDFs for zero-copy processing ([Source](https://medium.com/@hadiyolworld007/rust-udfs-in-duckdb-zero-copy-speed-21a6d860937a)) |
| **Scale proven** | Plaso: millions of events | DuckDB: billions of rows on single machine ([Source](https://duckdb.org/)) |

#### Timeline Event Schema

```sql
CREATE TABLE timeline_events (
    event_id        UBIGINT,          -- monotonic, per-case unique
    timestamp_utc   TIMESTAMP_NS,     -- nanosecond precision
    timestamp_desc  VARCHAR,          -- "Created", "Modified", "Accessed", "Birth"
    source_type     VARCHAR,          -- "USN", "EVTX", "MFT", "REGISTRY", etc.
    source_name     VARCHAR,          -- parser name
    evidence_id     UINTEGER,         -- which evidence container
    artifact_path   VARCHAR,          -- path within evidence
    message         VARCHAR,          -- human-readable description
    extra_json      JSON,             -- parser-specific structured data

    -- For efficient filtering
    hostname        VARCHAR,
    username        VARCHAR,
    pid             UINTEGER,
);

-- Partition by date for range queries on TB-scale cases
-- DuckDB handles this natively with zone maps
```

#### Indexing Strategy

1. **Primary**: Clustered by `timestamp_utc` (DuckDB's zone maps provide automatic range-skip)
2. **Secondary**: `source_type` for artifact-type filtering
3. **Full-text**: Integrated keyword search via DuckDB FTS extension or external tantivy index
4. **Tag index**: Separate `event_tags` table for analyst annotations and automated tagging

#### Incremental Processing

```rust
pub struct CaseTimeline {
    db: duckdb::Connection,
    processed_sources: HashSet<SourceFingerprint>,
}

impl CaseTimeline {
    /// Add new evidence without reprocessing existing data
    pub fn ingest_incremental(&mut self, source: &DataSource, parsers: &[&dyn ForensicParser]) -> Result<IngestStats> {
        let fingerprint = source.fingerprint(); // hash of source metadata
        if self.processed_sources.contains(&fingerprint) {
            return Ok(IngestStats::already_processed());
        }
        // Parse and append only new events
        let emitter = DuckDbEventEmitter::new(&self.db, source.evidence_id());
        for parser in parsers {
            parser.parse(source, &emitter)?;
        }
        self.processed_sources.insert(fingerprint);
        Ok(emitter.stats())
    }
}
```

#### Comparison with Existing Tools

| Tool | Storage | Scale | Incremental | Query Speed |
|------|---------|-------|-------------|-------------|
| **Plaso** | SQLite + Redis ([Source](https://deepwiki.com/log2timeline/plaso/3.3-storage-system)) | Millions | No (reprocess) | Slow (row-store) |
| **Autopsy** | SQLite + Solr ([Source](https://www.cyberforensicacademy.com/blog/autopsy-forensics-tool-complete-step-by-step-beginner-guide)) | Millions | Partial | Moderate |
| **AXIOM** | Proprietary ([Source](https://www.magnetforensics.com/products/magnet-axiom/)) | Millions | Yes | Fast |
| **Issen** | DuckDB | Billions | Yes | Very fast (columnar) |

---

## 5. Open-Core Architecture Boundary Design

### Recommendation: Crate-Level Boundary with Cargo Features + Runtime License Check

Drawing from Grafana's LICENSING.md approach ([Source](https://github.com/grafana/grafana/blob/main/LICENSING.md)) and the Open Core Ventures framework ([Source](https://handbook.opencoreventures.com/open-core-business-model/)):

#### The Boundary: Buyer-Based Open Core (BBOC)

| Tier | Audience | License | Examples |
|------|----------|---------|----------|
| **Open Source** | Individual practitioner / community | Apache 2.0 | All parsers, CLI, timeline engine, plugin SDK |
| **Professional** | Solo consultant / small team | Proprietary (free tier possible) | Report engine, correlation, desktop GUI |
| **Enterprise** | Organization / firm | Proprietary (paid) | Web UI, RBAC, audit logs, case management, multi-user |

#### Implementation Patterns

**1. Crate-level separation (primary boundary):**
Open-source crates never `use` or `depend on` proprietary crates. This is enforced by having them in separate repos/workspaces.

**2. Cargo features for optional integration points:**
```toml
# In issen-core/Cargo.toml (open source)
[features]
default = []
repoissen-hooks = []  # Enables hook points for report engine, no proprietary code included
correlation-hooks = []  # Enables hook points for correlation engine
```

The open-source core defines trait-based extension points (ports); the proprietary layer provides implementations (adapters). This is hexagonal architecture applied to licensing.

**3. Runtime license validation (for distributed proprietary binaries):**
```rust
// In proprietary issen-license crate
pub enum Edition { Community, Professional, Enterprise }

pub fn active_edition() -> Edition {
    // Check license file / key / environment
    // Degrade gracefully to Community if no valid license
}
```

**4. Preventing proprietary code leaks:**
- Separate git repos (not just separate directories in a monorepo)
- CI/CD checks: public repo CI must build and pass all tests without access to private repo
- `.gitignore` and pre-commit hooks in public repo to reject files from proprietary paths
- Code review policy: PRs to public repo reviewed for accidental proprietary imports

**5. API boundary design for community extensions:**
```rust
// Public issen-plugin-sdk defines stable interfaces
// Community plugins depend ONLY on issen-plugin-sdk and issen-core
// Internal APIs (issen-pipeline internals, etc.) are pub(crate) — not exposed

// Stable public API — versioned with semver
pub trait EventEmitter: Send + Sync {
    fn emit(&self, event: TimelineEvent) -> Result<()>;
    fn emit_batch(&self, events: Vec<TimelineEvent>) -> Result<()>;
}

// Internal implementation detail — NOT in plugin SDK
pub(crate) struct DuckDbEventEmitter { /* ... */ }
```

---

## 6. Scalability from CLI to GUI to Enterprise

### Recommendation: Hexagonal Architecture with Crux-Inspired Core Separation

Based on research into hexagonal architecture in Rust ([Source](https://www.howtocodeit.com/articles/master-hexagonal-architecture-rust)), the Crux framework ([Source](https://redbadger.github.io/crux/)), and GUI ecosystem ([Source](https://www.boringcactus.com/2025/04/13/2025-survey-of-rust-gui-libraries.html)):

#### Progression Path

```
Phase 1: CLI (clap + ratatui progress bars)
    └── issen-core, issen-pipeline, issen-timeline, parsers

Phase 2: TUI (ratatui interactive dashboard)
    └── Same core, adds issen-tui shell

Phase 3: Desktop GUI (Tauri 2 recommended)
    └── Same core, adds issen-gui shell
    └── Tauri: Rust backend + web frontend (React/Svelte)
    └── Minimal binary size (~10MB vs Electron's 100MB+)

Phase 4: Web UI + API Server (axum + Leptos/React)
    └── Same core, adds issen-web shell
    └── REST/GraphQL API for automation
    └── WebSocket for real-time progress

Phase 5: Enterprise (multi-user, team features)
    └── Same core, adds issen-enterprise
    └── Case management, RBAC, audit logs
    └── Client-server: analysis workers + web frontend
```

#### Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    Frontend Shells                        │
│  ┌─────┐  ┌─────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ CLI │  │ TUI │  │ Desktop  │  │    Web UI        │  │
│  │clap │  │rata-│  │  Tauri   │  │ axum + Leptos    │  │
│  │     │  │ tui │  │          │  │                  │  │
│  └──┬──┘  └──┬──┘  └────┬─────┘  └────────┬─────────┘  │
│     │        │          │                  │             │
│     └────────┴──────────┴──────────────────┘             │
│                         │                                │
│              ┌──────────▼──────────┐                     │
│              │   issen-core (Ports)   │  ◄── Stable API     │
│              │  - CaseManager      │      boundary       │
│              │  - AnalysisEngine   │                     │
│              │  - TimelineQuery    │                     │
│              │  - ReportGenerator  │                     │
│              └──────────┬──────────┘                     │
│                         │                                │
│     ┌───────────────────┼───────────────────┐            │
│     │                   │                   │            │
│  ┌──▼───────┐  ┌───────▼──────┐  ┌────────▼────────┐   │
│  │issen-pipeline│  │ issen-timeline  │  │ issen-repoissen-engine│   │
│  │(ingest)   │  │ (DuckDB)     │  │ (docx/html/pdf) │   │
│  └───────────┘  └──────────────┘  └─────────────────┘   │
│                                                          │
│  ┌─────────────────────────────────────────────────────┐ │
│  │              Plugin System (3-tier)                  │ │
│  │  [Compiled Parsers] [WASM Plugins] [gRPC Plugins]   │ │
│  └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

#### Framework Recommendations

| Frontend | Framework | Rationale |
|----------|-----------|-----------|
| CLI | `clap` + `indicatif` | Industry standard, excellent UX |
| TUI | `ratatui` | Most active Rust TUI framework, sub-ms rendering ([Source](https://ratatui.rs/)) |
| Desktop | `tauri` v2 | Rust backend + web frontend; small binary; mature ecosystem ([Source](https://dioxuslabs.com/)) |
| Web | `axum` (API) + React or Leptos (UI) | axum for backend performance; React for hiring/ecosystem, or Leptos for full-Rust stack |
| Mobile | Deferred — not in initial roadmap | If needed: Crux framework for shared core with Swift/Kotlin shells ([Source](https://redbadger.github.io/crux/)) |

#### Key Principle: The `issen-core` Crate is Side-Effect-Free

Following Crux's architecture: the core crate contains pure business logic with no I/O. All side effects (file access, network, database) are expressed as **commands** that shells execute. This makes the core trivially testable and portable across all frontend types.

```rust
// Core emits commands, shells execute them
pub enum Command {
    ReadEvidence { source_id: EvidenceId, offset: u64, len: usize },
    QueryTimeline { filter: TimelineFilter },
    GenerateReport { config: ReportConfig },
    EmitProgress { stage: String, percent: f32 },
}

pub enum Event {
    EvidenceData { source_id: EvidenceId, data: Bytes },
    TimelineResults { events: Vec<TimelineEvent> },
    ReportReady { path: PathBuf },
    Error { message: String },
}

pub fn update(state: &mut AppState, event: Event) -> Vec<Command> {
    // Pure function: given state + event, produce new state + commands
}
```

---

## Summary: Priority Implementation Order

For a solo founder maximizing velocity:

1. **Start with CLI + Tier 1 plugins** — compile-time trait-based parsers, `clap` CLI, DuckDB timeline store. This is your open-source community magnet.

2. **Add plugin SDK early** — define stable `ForensicParser` and `EventEmitter` traits in `issen-plugin-sdk` v0.1. Community contributors target this API.

3. **DuckDB timeline from day one** — don't start with SQLite and migrate later. DuckDB's Rust bindings are mature enough and the performance advantage compounds.

4. **Defer WASM plugins to v0.3+** — The WASM Component Model is still maturing. Start with compile-time plugins; add WASM when community demand requires it.

5. **Defer gRPC plugins to v0.5+** — Only needed for enterprise integrations and cross-language bridges.

6. **Build report engine as first proprietary module** — This is the core differentiator (attorney-ready output). Keep it in the private repo from day one.

7. **TUI before GUI** — Faster to build, serves the CLI-native forensics audience, validates the core API boundary.

---

## Sources

### Monorepo & Repository Structure
- [Terraform Monorepo vs Multi-Repo](https://www.hashicorp.com/en/blog/terraform-mono-repo-vs-multi-repo-the-great-debate)
- [Monorepo vs Multi-Repo: Pros and Cons](https://kinsta.com/blog/monorepo-vs-multi-repo/)
- [Building a Monorepo with Rust](https://earthly.dev/blog/rust-monorepo/)
- [Cargo Workspaces](https://doc.rust-lang.org/cargo/reference/workspaces.html)
- [Cargo Workspace Best Practices for Large Projects](https://reintech.io/blog/cargo-workspace-best-practices-large-rust-projects)

### Plugin Architecture
- [Plugins in Rust: Dynamic Loading (NullDeref)](https://nullderef.com/blog/plugin-dynload/)
- [Plugins in Rust: The Technologies (NullDeref)](https://nullderef.com/blog/plugin-tech/)
- [Building a Rust Plugin System (AniLog)](https://blog.anirudha.dev/rust-plugin-system/)
- [Implementing Rust Plugin Architecture (peerdh)](https://peerdh.com/blogs/programming-insights/implementing-a-rust-based-plugin-architecture-for-dynamic-feature-loading)
- [Plugins with Rust and WASI Preview 2](https://benw.is/posts/plugins-with-rust-and-wasi)
- [Rust WASM Plugin Examples](https://github.com/engindearing-projects/rust-wasm-plugins-examples)

### Terraform / HashiCorp Plugin Model
- [HashiCorp Plugin System Design (Medium)](https://zerofruit-web3.medium.com/hashicorp-plugin-system-design-and-implementation-5f939f09e3b3)
- [Terraform Plugin Protocol](https://github.com/hashicorp/terraform/blob/main/docs/plugin-protocol/README.md)
- [Terraform Provider Servers](https://developer.hashicorp.com/terraform/plugin/framework/provider-servers)
- [A Deep Dive into Terraform](https://thecodinggopher.substack.com/p/a-deep-dive-into-terraform)

### Forensic Data Pipeline
- [Velociraptor Dead Disk Forensics](https://docs.velociraptor.app/blog/2022/2022-03-22-deaddisk/)
- [Velociraptor Dead Disk Analysis](https://docs.velociraptor.app/docs/forensic/deaddisk/)
- [Velociraptor Forensic Analysis](https://docs.velociraptor.app/docs/forensic/)
- [Velociraptor VHDX Analysis at Scale](https://www.infoguard.ch/en/blog/dfir-velociraptor-scans-vhdx)

### Timeline Architecture
- [Plaso Storage System (DeepWiki)](https://deepwiki.com/log2timeline/plaso/3.3-storage-system)
- [Plaso Multi-Processing (DeepWiki)](https://deepwiki.com/log2timeline/plaso/6.1-multi-processing-and-performance)
- [Plaso Documentation](https://plaso.readthedocs.io/)
- [Log2Timeline Guide](https://www.cyberforensicacademy.com/blog/log2timeline-guide-creating-forensic-timelines)

### DuckDB
- [DuckDB In Depth (endjin)](https://endjin.com/blog/2025/04/duckdb-in-depth-how-it-works-what-makes-it-fast)
- [DuckDB Performance: Querying Large Datasets](https://motherduck.com/duckdb-book-summary-chapter10/)
- [Rust UDFs in DuckDB](https://medium.com/@hadiyolworld007/rust-udfs-in-duckdb-zero-copy-speed-21a6d860937a)
- [DuckDB Official](https://duckdb.org/)

### Open-Core Business Model
- [Open Core Business Model Handbook](https://handbook.opencoreventures.com/open-core-business-model/)
- [Open Core is Misunderstood](https://www.opencoreventures.com/blog/open-core-is-a-misunderstood-business-model)
- [Open Core vs Open Source (Opensource.com)](https://opensource.com/article/21/11/open-core-vs-open-source)
- [Open Core vs Open Perimeter](https://opensource.com/article/17/8/open-core-vs-open-perimeter)
- [Grafana LICENSING.md](https://github.com/grafana/grafana/blob/main/LICENSING.md)
- [How Grafana Differentiates Enterprise](https://grafana.com/blog/2019/09/04/how-we-differentiate-grafana-enterprise-from-open-source-grafana/)
- [HashiCorp BSL Announcement](https://www.hashicorp.com/en/blog/hashicorp-adopts-business-source-license)
- [Elastic Open Source](https://www.elastic.co/about/open-source)
- [Rust 1.34 Alternative Registries](https://www.infoq.com/news/2019/04/rust-1.34-additional-registries/)

### Forensic Tools
- [Autopsy Module Development](http://www.sleuthkit.org/autopsy/docs/api-docs/4.3/platform_page.html)
- [Autopsy Forensics 2025 Guide](https://www.cyberforensicacademy.com/blog/autopsy-forensics-tool-complete-step-by-step-beginner-guide)
- [Magnet AXIOM](https://www.magnetforensics.com/products/magnet-axiom/)

### Hexagonal Architecture & Multi-Frontend
- [Master Hexagonal Architecture in Rust](https://www.howtocodeit.com/articles/master-hexagonal-architecture-rust)
- [How to Apply Hexagonal Architecture to Rust](https://www.barrage.net/blog/technology/how-to-apply-hexagonal-architecture-to-rust)
- [Crux: Cross-Platform App Development in Rust](https://redbadger.github.io/crux/)
- [2025 Survey of Rust GUI Libraries](https://www.boringcactus.com/2025/04/13/2025-survey-of-rust-gui-libraries.html)
- [Dioxus Framework](https://dioxuslabs.com/)
- [Ratatui TUI Framework](https://ratatui.rs/)
- [Grafana Monorepo (DeepWiki)](https://deepwiki.com/grafana/grafana)
- [OpenFang Architecture](https://openfang.one/)
