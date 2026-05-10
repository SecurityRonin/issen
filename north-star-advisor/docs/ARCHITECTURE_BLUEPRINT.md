# Issen: Architecture Blueprint

> **Tier**: 2 -- Technical Blueprint
> **Created**: 2026-03-20
> **Status**: Active
> **Generation Step**: 6 of 13 -- Requires `brand.*`, `northstar.*`, `extract.*`, `journeys.*`
> **North Star Metric**: Time-to-Attorney-Ready Report (TARR) < 4 hours

---

## Document Structure

This architecture blueprint is modularized for maintainability. The core document contains:
- Executive Summary and System Topology
- Data Pipeline Architecture
- Technology Stack
- Phase 2+ Extensions
- Deployment Checklist
- Appendices

Detailed implementation specifications are in `north-star-advisor/docs/architecture/`:

| Document | Content |
|----------|---------|
| [PIPELINE_ORCHESTRATION.md](architecture/PIPELINE_ORCHESTRATION.md) | Multi-layer data pipeline, state schema, execution patterns |
| [RESILIENCE_PATTERNS.md](architecture/RESILIENCE_PATTERNS.md) | Graceful degradation, parser fallbacks, corrupt evidence handling |
| [IMPLEMENTATION_SCAFFOLD.md](architecture/IMPLEMENTATION_SCAFFOLD.md) | Crate structure, trait definitions, build configuration |
| [OBSERVABILITY.md](architecture/OBSERVABILITY.md) | Tracing infrastructure, TARR instrumentation, audit logging |
| [TESTING_STRATEGY.md](architecture/TESTING_STRATEGY.md) | Test categories, NIST reference datasets, golden file tests |
| [INTELLIGENCE_LAYER.md](architecture/INTELLIGENCE_LAYER.md) | ForensicLLM, RAG architecture, embedding design, YARA-X/Sigma |

---

## Executive Summary

Issen is a forensic triage platform built in Rust that transforms digital forensic artifacts into attorney-ready reports. The architecture follows a **hexagonal (ports and adapters) pattern** inspired by Crux, where a side-effect-free core (`issen-core`) contains all analysis logic and multiple frontends (CLI, TUI, Desktop GUI via Tauri, Web UI via axum) share identical processing through well-defined ports.

The system uses a **multi-layer data pipeline** that progressively transforms raw evidence (E01 images, KAPE collections, Velociraptor output) through storage I/O, image format parsing, volume/partition detection, filesystem traversal, and artifact-specific parsing into a **unified DuckDB columnar timeline** with nanosecond precision. An **SQLite export** path provides portable case sharing and chain-of-custody snapshots.

A **three-tier plugin system** enables extensibility: compile-time trait-based plugins for first-party parsers (v0.1+), WASM-sandboxed community plugins via Wasmtime (v0.3+), and gRPC/IPC subprocess plugins for enterprise integrations (v0.5+).

The **open-core business model** enforces crate-level separation: open-source crates (Apache 2.0/MIT) never depend on proprietary crates. The public monorepo contains parsers, core types, and the plugin SDK. The private repository contains the report engine, correlation engine, GUI, web UI, and enterprise features.

### Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| **Core Architecture** | Hexagonal (Crux-inspired) | Side-effect-free core enables multi-surface rendering (CLI/TUI/GUI/Web) from identical analysis logic. Maximizes solo-dev velocity -- write once, render everywhere. |
| **Primary Datastore** | DuckDB (columnar) | Analytical queries over 100M+ timeline events. Zone maps for time-range filtering. TIMESTAMP_NS for nanosecond forensic precision. In-process (no server). |
| **Exchange Format** | SQLite | Portable case handoff, legal hold archival, chain-of-custody snapshots. Universal tooling support. DuckDB --> SQLite export on case close. |
| **Language** | Rust | Memory safety without GC. Zero-cost abstractions for parser performance. Ownership model prevents evidence data leaks. Existing codebase (usnjrnl-forensic, tl, ewf, shrinkpath). |
| **Plugin System** | Three-tier (traits/WASM/gRPC) | Tier 1 for performance-critical first-party parsers. Tier 2 WASM for sandboxed community contributions. Tier 3 gRPC for enterprise tool integration. Progressive complexity. |
| **AI Strategy** | Local-first via Ollama | Forensic data cannot leave the examiner's machine. Grounded generation only -- every AI claim must cite evidence. AI-free mode mandatory. |
| **Open-Core Boundary** | Crate-level separation | Open-source crates never `use` proprietary crates. Feature flags for tier gating. Runtime license validation. Follows Grafana/GitLab precedent. |
| **Report Engine** | Dual HTML + DOCX/PDF | Interactive HTML for attorney exploration. Polished Word/PDF for court filing. The report is the product (Axiom 2). |

---

## 1. System Topology

### 1.1 Hexagonal Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              FRONTENDS (Adapters)                          │
│                                                                             │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐  ┌──────────────────────┐  │
│  │  issen-cli  │  │  issen-tui  │  │   issen-gui      │  │      issen-web          │  │
│  │  (clap)  │  │(ratatui) │  │  (Tauri v2)   │  │  (axum + Leptos)     │  │
│  │          │  │          │  │  webview       │  │  server-rendered     │  │
│  └────┬─────┘  └────┬─────┘  └──────┬────────┘  └──────────┬───────────┘  │
│       │              │               │                      │              │
│       └──────────────┴───────┬───────┴──────────────────────┘              │
│                              │                                              │
│                     ┌────────▼────────┐                                     │
│                     │   Port Layer    │                                     │
│                     │  (async traits) │                                     │
│                     └────────┬────────┘                                     │
│                              │                                              │
├──────────────────────────────┼──────────────────────────────────────────────┤
│                              │                                              │
│                     ┌────────▼────────┐                                     │
│                     │    issen-core      │   PURE / SIDE-EFFECT-FREE           │
│                     │                 │   - Timeline analysis               │
│                     │  No I/O         │   - Correlation logic               │
│                     │  No network     │   - Findings extraction             │
│                     │  No filesystem  │   - Report data assembly            │
│                     │                 │   - Filter / search / aggregate     │
│                     └────────┬────────┘                                     │
│                              │                                              │
├──────────────────────────────┼──────────────────────────────────────────────┤
│                              │                                              │
│                     ┌────────▼────────┐                                     │
│                     │  Adapter Layer  │                                     │
│                     │  (side effects) │                                     │
│                     └────────┬────────┘                                     │
│                              │                                              │
│  ┌────────────┐  ┌──────────┴──────────┐  ┌────────────┐  ┌────────────┐  │
│  │ issen-pipeline│  │    issen-timeline      │  │ issen-report  │  │ issen-intel   │  │
│  │ (ingest)   │  │  (DuckDB store)     │  │ (HTML/DOCX)│  │ (Ollama)   │  │
│  └────────────┘  └─────────────────────┘  └────────────┘  └────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Design principle**: `issen-core` contains zero side effects. All I/O, database access, network calls, and filesystem operations live in adapters. This means every frontend (CLI, TUI, Tauri GUI, axum Web) calls the same pure analysis functions. When Sarah Chen runs `rt timeline` in her terminal, she gets identical results to an attorney viewing the same case in a browser.

### 1.2 Component Specifications

| Component | Crate | License | Responsibility | Dependencies |
|-----------|-------|---------|----------------|--------------|
| **Core Types** | `issen-core` | Apache 2.0 | Timeline schema, event types, plugin traits, analysis logic | None (pure) |
| **Data Pipeline** | `issen-pipeline` | Apache 2.0 | Multi-layer evidence ingestion, parser orchestration | `issen-core` |
| **Plugin SDK** | `issen-plugin-sdk` | Apache 2.0 | Plugin development kit, trait re-exports, test harness | `issen-core` |
| **Timeline Store** | `issen-timeline` | Apache 2.0 | DuckDB storage, query engine, SQLite export | `issen-core`, `duckdb-rs` |
| **EWF Reader** | `issen-ewf` | MIT | E01/EWF forensic image parsing, multi-segment | None |
| **CLI Frontend** | `issen-cli` | Apache 2.0 | Command-line interface, batch processing | `issen-core`, `issen-pipeline`, `issen-timeline` |
| **TUI Frontend** | `issen-tui` | Proprietary | Interactive terminal UI, timeline exploration | `issen-core`, `issen-timeline`, `ratatui` |
| **Report Engine** | `issen-report` | Proprietary | HTML generation, PDF rendering, DOCX assembly | `issen-core`, `issen-timeline` |
| **Correlation Engine** | `issen-correlation` | Proprietary | Cross-artifact correlation, attack pattern detection | `issen-core`, `issen-timeline` |
| **Intelligence Layer** | `issen-intel` | Proprietary | ForensicLLM, RAG, YARA-X, Sigma, TI integration | `issen-core`, `issen-timeline` |
| **Desktop GUI** | `issen-gui` | Proprietary | Tauri v2 desktop application | `issen-core`, `issen-timeline`, `issen-report` |
| **Web UI** | `issen-web` | Proprietary | axum server + Leptos frontend | `issen-core`, `issen-timeline`, `issen-report` |
| **Enterprise** | `issen-enterprise` | Proprietary | SSO, teams, audit, license management | `issen-core` |

### 1.3 Component Roles

#### issen-core (Pure Analysis Engine)

- **Job**: Provide all forensic analysis logic as pure functions with no side effects. Define the canonical `TimelineEvent` schema, plugin traits, and analysis primitives.
- **Outputs**: `{ TimelineEvent, AnalysisResult, Finding, Narrative, FilterSpec, AggregationResult }`
- **Special considerations**: Must never import I/O crates. All data arrives via function parameters. This enables deterministic testing and multi-frontend sharing.
- **Tools required**: None (pure computation)

#### issen-pipeline (Evidence Ingestion Pipeline)

- **Job**: Orchestrate multi-layer evidence processing from raw storage through artifact parsing. Manage parser registration, parallel execution, and incremental processing.
- **Outputs**: `{ IngestResult, ParseProgress, TimelineEvent[], SourceFingerprint }`
- **Special considerations**: Must handle corrupted evidence gracefully. Streaming architecture -- never load entire evidence into memory. Parallel parsing via rayon.
- **Tools required**: Filesystem I/O, EWF reader, parser plugins

#### issen-timeline (DuckDB Timeline Store)

- **Job**: Store, index, and query the unified forensic timeline. Manage DuckDB lifecycle, schema migrations, and SQLite export.
- **Outputs**: `{ QueryResult, TimelineSlice, ExportResult, TimelineStats }`
- **Special considerations**: DuckDB TIMESTAMP_NS for nanosecond precision. Zone maps enable fast time-range queries without full scans. Incremental append via source fingerprinting (skip already-ingested sources).
- **Tools required**: DuckDB (in-process), SQLite (export)

#### issen-report (Attorney-Ready Report Engine)

- **Job**: Transform analysis findings into dual-format attorney-ready deliverables: interactive HTML for exploration and polished Word/PDF for court filing.
- **Outputs**: `{ HtmlReport, DocxReport, PdfReport, ReportManifest }`
- **Special considerations**: HTML reports are self-contained (no external dependencies, no CDN). DOCX generation via docx-rs with python-docx fallback for complex formatting. PDF via headless Chromium rendering of HTML. Reports include chain-of-custody metadata and hash verification.
- **Tools required**: Template engine (Askama), headless Chromium, docx-rs
- **Full prompt**: See [AGENT_PROMPTS.md](architecture/AGENT_PROMPTS.md#issen-report)

#### issen-intel (Intelligence Layer)

- **Job**: Provide AI-assisted analysis, detection rules, and threat intelligence integration. All AI features are optional -- the platform must function fully without them.
- **Outputs**: `{ NarrativeDraft, DetectionResult[], ThreatIntelEnrichment, SimilarCaseMatch[] }`
- **Special considerations**: Local-first via Ollama. Grounded generation only -- every AI-generated claim must cite specific timeline events. Dual RAG: case-specific (current evidence) and cross-case (historical knowledge base). YARA-X for file-based detection. Sigma rules for event-based detection.
- **Tools required**: Ollama (local LLM), YARA-X, Sigma engine, vector store
- **Full prompt**: See [AGENT_PROMPTS.md](architecture/AGENT_PROMPTS.md#issen-intel)

### 1.4 Cross-Component Data Flows

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Evidence    │     │  issen-pipeline │     │  issen-timeline │     │  issen-report   │
│  (E01/KAPE/ │────►│  (ingest +   │────►│  (DuckDB     │────►│  (HTML/DOCX  │
│  Veloci)     │     │   parse)     │     │   store)     │     │   output)    │
└─────────────┘     └──────┬───────┘     └──────┬───────┘     └──────────────┘
                           │                     │
                           │ TimelineEvent[]     │ Query API
                           │                     │
                    ┌──────▼───────┐     ┌──────▼───────┐
                    │  issen-core     │     │  issen-intel    │
                    │  (analysis)  │     │  (AI/detect) │
                    └──────────────┘     └──────────────┘
```

**Data flow for core TARR journey (Sarah Chen):**

1. **Ingest** (2 min): `rt ingest ./evidence/` --> `issen-pipeline` detects evidence format (E01, KAPE, raw), routes through appropriate Layer 1-3 handlers
2. **Parse** (8 min): `issen-pipeline` discovers artifacts via filesystem traversal, dispatches to registered Tier 1 parsers in parallel via rayon. Each parser emits `TimelineEvent[]`
3. **Store** (concurrent): `issen-timeline` appends events to DuckDB with source fingerprinting. Deduplicates on re-ingest
4. **Review** (90 min): Frontend queries `issen-timeline` via `issen-core` filter/aggregate functions. Sarah bookmarks findings, adds annotations
5. **Report** (30 min): `issen-report` pulls bookmarked findings + timeline context, generates interactive HTML + polished DOCX. `issen-intel` (optional) drafts narrative sections with citations
6. **Export**: `issen-timeline` exports case to SQLite for archival/sharing. Chain-of-custody hash written

### 1.5 Model Strategy & RAG Assessment

#### Model Approach

**Multi-model with local-first routing** -- 80% of AI tasks use small, fast models (7B-13B parameter); 20% of complex tasks route to larger models (70B) or cloud APIs (only with explicit user consent).

| Task | Model Tier | Example Model | Rationale |
|------|-----------|---------------|-----------|
| Timeline event classification | Small (7B) | Llama 3 8B / Phi-3 | High volume, low complexity. Classify event types, extract entities. |
| Report narrative drafting | Medium (13B-34B) | Llama 3 70B-Q4 / Mixtral | Requires coherent multi-paragraph output with forensic terminology. |
| Complex correlation analysis | Large (70B+) | Llama 3 70B / Cloud API | Rare. Cross-artifact pattern detection requiring broad reasoning. |
| IOC extraction | Small (7B) | Fine-tuned Phi-3 | Structured extraction. Domain-specific fine-tuning on forensic data. |
| Similar case matching | Embedding only | nomic-embed-text | Vector similarity, no generative model needed. |

**Cost Projection (Local-First):**

| Metric | Estimate |
|--------|----------|
| Avg cost per case (local) | $0 (hardware amortized) |
| Avg cost per case (cloud fallback) | ~$2-5 (large model tasks only) |
| Hardware requirement | 16GB+ VRAM for 13B models, 32GB+ for 70B quantized |
| Estimated cases per month (solo practitioner) | 15-30 |
| Projected monthly cloud cost (if used) | $30-150 |

**AI-Free Mode**: All AI features are behind a global toggle. When disabled, the platform operates as a pure pipeline-to-report tool. No model loading, no inference, no embedding. YARA-X and Sigma rules operate independently of AI (deterministic pattern matching). This is mandatory for air-gapped labs, resource-constrained machines, and examiners who do not trust AI-generated content.

#### RAG Assessment

**Yes** -- forensic analysis benefits from retrieval-augmented generation for both case-specific evidence and cross-case institutional knowledge.

- **Knowledge sources**:
  - **Case-specific RAG**: Current case timeline events, parsed artifacts, examiner annotations, bookmarked findings. Indexed per-case in an ephemeral vector store.
  - **Cross-case RAG**: Historical case patterns, known attack signatures, organizational TTP library, previous report narratives (anonymized). Persistent vector store.
  - **Reference RAG**: MITRE ATT&CK framework, forensic artifact documentation, Windows internals references. Static, updated quarterly.
- **Update cadence**: Case-specific is real-time (indexed on ingest). Cross-case updated on case close. Reference updated quarterly.
- **Pattern**: Modular RAG -- separate retrieval pipelines per knowledge source, merged at generation time with source attribution.

> For detailed retrieval architecture, embedding design, and evaluation framework,
> see [INTELLIGENCE_LAYER.md](architecture/INTELLIGENCE_LAYER.md)

---

## 2. Multi-Layer Data Pipeline

The data pipeline is Issen's core value chain. Evidence flows through five layers, each abstracting the layer below.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Layer 4: Artifact Parsers                        │
│  MFT | USN Journal | Event Logs | Prefetch | Registry | Amcache   │
│  LNK | Jumplists | BAM | SRUM | Browser History | ...             │
│  (Tier 1 compile-time plugins via ArtifactParser trait)            │
├─────────────────────────────────────────────────────────────────────┤
│                    Layer 3: Filesystem                              │
│  NTFS (MFT-based) | ext4 | APFS | FAT32 | exFAT                  │
│  (File enumeration, metadata extraction, deleted file recovery)    │
├─────────────────────────────────────────────────────────────────────┤
│                    Layer 2: Volume / Partition                      │
│  GPT | MBR | LVM | Apple Partition Map | Dynamic Disk              │
│  (Partition discovery, offset calculation, volume mounting)         │
├─────────────────────────────────────────────────────────────────────┤
│                    Layer 1: Image Format                            │
│  E01/EWF (issen-ewf) | Raw/dd | VMDK | VHD/VHDX | AFF4              │
│  (Block-level read abstraction, decompression, verification)       │
├─────────────────────────────────────────────────────────────────────┤
│                    Layer 0: Storage I/O                             │
│  Local filesystem | Network share | Cloud storage (S3/GCS)         │
│  (Buffered reads, memory-mapped I/O, streaming)                    │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.1 VirtualFilesystem (Multi-Source Fusion)

When a case involves multiple evidence sources (disk image + endpoint collection + cloud logs), the `VirtualFilesystem` provides a unified namespace:

```rust
// Conceptual API
let vfs = VirtualFilesystem::new()
    .mount("/disk", EwfSource::open("laptop.E01")?)     // Layer 1: E01 image
    .mount("/kape", DirectorySource::open("./kape/")?)   // Layer 0: KAPE collection
    .mount("/veloci", VelociraptorSource::open("flow.zip")?) // Layer 0: Velociraptor
    .mount("/cloud", CloudLogSource::open("o365-audit.json")?); // Layer 0: Cloud logs

// Layer 4 parsers operate on the unified namespace
for artifact in vfs.discover_artifacts()? {
    let events = parser_registry.parse(&vfs, &artifact)?;
    timeline.append(events)?;
}
```

**TARR impact**: Eliminates 2-4 hours of manual evidence merging (per journey mapping). Sarah Chen runs `rt ingest --source laptop.E01 --source ./kape/ --source o365-audit.json` and gets a single unified timeline.

### 2.2 Pipeline State Schema

```rust
/// Core timeline event -- the universal unit of forensic data
pub struct TimelineEvent {
    /// Nanosecond-precision timestamp (DuckDB TIMESTAMP_NS)
    pub timestamp: i64,
    /// ISO 8601 with original timezone preserved
    pub timestamp_display: String,
    /// Event classification (FileCreate, FileDelete, ProcessExec, RegistryMod, etc.)
    pub event_type: EventType,
    /// Source artifact type (MFT, USNJournal, EventLog, Prefetch, etc.)
    pub source: ArtifactSource,
    /// Full path within VirtualFilesystem
    pub artifact_path: String,
    /// Human-readable description
    pub description: String,
    /// Structured key-value metadata (artifact-specific fields)
    pub metadata: HashMap<String, Value>,
    /// User/SID associated with event (if determinable)
    pub user: Option<String>,
    /// Machine hostname
    pub hostname: Option<String>,
    /// Tags (bookmarked, suspicious, ai-flagged, sigma-hit, yara-hit)
    pub tags: Vec<String>,
    /// SHA-256 of source record for deduplication and integrity
    pub record_hash: String,
    /// Source evidence identifier for chain-of-custody
    pub evidence_source_id: String,
}
```

### 2.3 DuckDB Timeline Schema

```sql
CREATE TABLE timeline (
    id              UBIGINT PRIMARY KEY DEFAULT nextval('timeline_seq'),
    timestamp_ns    TIMESTAMP_NS NOT NULL,     -- Nanosecond precision
    timestamp_display VARCHAR NOT NULL,         -- Original timezone preserved
    event_type      VARCHAR NOT NULL,           -- Enum as string for extensibility
    source          VARCHAR NOT NULL,           -- Artifact source type
    artifact_path   VARCHAR NOT NULL,           -- VFS path
    description     VARCHAR NOT NULL,           -- Human-readable
    metadata        JSON,                       -- Artifact-specific key-value
    user_account    VARCHAR,                    -- User/SID
    hostname        VARCHAR,                    -- Machine name
    tags            VARCHAR[],                  -- Array of tags
    record_hash     VARCHAR NOT NULL,           -- SHA-256 dedup key
    evidence_source VARCHAR NOT NULL,           -- Chain-of-custody link
    ingested_at     TIMESTAMP_NS DEFAULT current_timestamp
);

-- Zone maps on timestamp_ns for fast time-range queries (DuckDB automatic)
-- Explicit index for common filter patterns
CREATE INDEX idx_timeline_type ON timeline(event_type);
CREATE INDEX idx_timeline_source ON timeline(source);
CREATE INDEX idx_timeline_user ON timeline(user_account);
CREATE INDEX idx_timeline_tags ON timeline USING GIN(tags);
```

**Incremental processing**: Each evidence source is fingerprinted (SHA-256 of header + size + modification time). On re-ingest, `issen-pipeline` checks fingerprints against `evidence_sources` metadata table and skips already-processed sources. This enables the "add more evidence to an existing case" workflow without reprocessing.

**SQLite export**: `issen-timeline` exports the DuckDB timeline to SQLite on demand (`rt case export --format sqlite`). The SQLite file includes the full timeline, examiner annotations, chain-of-custody log, and report metadata. This is the portable exchange format for case sharing, legal hold, and long-term archival.

---

## 3. Three-Tier Plugin System

### Tier 1: Compile-Time Trait Plugins (v0.1+)

First-party parsers implement the `ArtifactParser` trait and are registered at compile time via the `inventory` crate. Zero runtime overhead. Full type safety.

```rust
/// The core parser trait -- all artifact parsers implement this
pub trait ArtifactParser: Send + Sync {
    /// Unique parser identifier (e.g., "usnjrnl", "mft", "evtx")
    fn id(&self) -> &'static str;

    /// Human-readable name
    fn name(&self) -> &'static str;

    /// Artifact types this parser handles
    fn supported_artifacts(&self) -> &[ArtifactType];

    /// Check if this parser can handle the given file/path
    fn can_parse(&self, path: &Path, header: &[u8]) -> bool;

    /// Parse artifacts and emit timeline events
    fn parse(
        &self,
        input: &mut dyn Read + Seek,
        context: &ParseContext,
    ) -> Result<Vec<TimelineEvent>, ParseError>;

    /// Parser version for cache invalidation
    fn version(&self) -> &str;
}

// Registration via inventory crate
inventory::submit! {
    ParserRegistration::new::<UsnjrnlParser>()
}
inventory::submit! {
    ParserRegistration::new::<MftParser>()
}
// ... all first-party parsers auto-registered at link time
```

**First-party parsers (v0.1 scope)**:

| Parser | Artifact | Existing Crate | Status |
|--------|----------|----------------|--------|
| `issen-parser-usnjrnl` | NTFS USN Journal | usnjrnl-forensic v0.6 | Field-tested, needs trait adaptation |
| `issen-parser-mft` | NTFS Master File Table | (new) | Port from tl v0.1 |
| `issen-parser-evtx` | Windows Event Logs | (new, wraps evtx crate) | Port from tl v0.1 |
| `issen-parser-prefetch` | Windows Prefetch | (new) | Port from tl v0.1 |
| `issen-parser-registry` | Windows Registry | (new, wraps nt-hive2) | Port from tl v0.1 |
| `issen-parser-lnk` | Shortcut files | (new, wraps lnk crate) | Port from tl v0.1 |
| `issen-parser-amcache` | Application cache | (new) | Port from tl v0.1 |
| `issen-parser-bam` | Background Activity Monitor | (new) | Port from tl v0.1 |
| `issen-parser-browser` | Browser history (SQLite) | (new) | Port from tl v0.1 |
| `issen-parser-jumplists` | Windows Jump Lists | (new) | Port from tl v0.1 |
| `issen-parser-srum` | System Resource Usage | (new) | Port from tl v0.1 |

### Tier 2: WASM Sandboxed Plugins (v0.3+, deferred)

Community-contributed parsers run in Wasmtime with WIT (WebAssembly Interface Type) contracts. Memory-isolated, capability-based security (explicit filesystem/network grants).

```wit
// forensic-parser.wit -- WIT interface definition
package issen:parser@0.1.0;

interface parser {
    record timeline-event {
        timestamp-ns: s64,
        event-type: string,
        source: string,
        artifact-path: string,
        description: string,
        metadata: list<tuple<string, string>>,
    }

    record parse-context {
        case-id: string,
        evidence-source: string,
        timezone: option<string>,
    }

    id: func() -> string;
    name: func() -> string;
    can-parse: func(path: string, header: list<u8>) -> bool;
    parse: func(data: list<u8>, ctx: parse-context) -> result<list<timeline-event>, string>;
}
```

**Security model**: WASM plugins have no ambient authority. They receive evidence bytes as input and return structured events. No filesystem access, no network access, no syscalls. The host controls all I/O.

### Tier 3: gRPC/IPC Subprocess Plugins (v0.5+, deferred)

Enterprise integrations (VirusTotal, MISP, OpenCTI, commercial SIEM connectors) run as separate processes communicating via gRPC (tonic). Supports any language. Process-level isolation.

```protobuf
// issen/plugin/v1/plugin.proto
service EnterprisePlugin {
    rpc Enrich(EnrichRequest) returns (EnrichResponse);
    rpc Query(QueryRequest) returns (stream QueryResponse);
    rpc Healthcheck(Empty) returns (HealthResponse);
}

message EnrichRequest {
    repeated string iocs = 1;          // IOCs to enrich
    string case_id = 2;
    EnrichmentConfig config = 3;       // API keys, rate limits
}
```

---

## 4. Repository Structure & Open-Core Boundary

### 4.1 Public Monorepo (Apache 2.0 / MIT)

```
github.com/h4x0r/issen
├── Cargo.toml                      # Virtual workspace manifest
├── LICENSING.md                    # Per-crate license declarations
├── crates/
│   ├── issen-core/                    # Core types, timeline schema, plugin traits (Apache 2.0)
│   ├── issen-pipeline/                # Data pipeline abstractions (Apache 2.0)
│   ├── issen-plugin-sdk/              # Plugin development SDK (Apache 2.0)
│   ├── issen-timeline/                # Timeline storage & query engine (Apache 2.0)
│   ├── parsers/
│   │   ├── issen-parser-usnjrnl/      # USN Journal parser (Apache 2.0)
│   │   ├── issen-parser-mft/          # MFT parser (Apache 2.0)
│   │   ├── issen-parser-evtx/         # Windows Event Logs (Apache 2.0)
│   │   ├── issen-parser-prefetch/     # Prefetch files (Apache 2.0)
│   │   ├── issen-parser-registry/     # Windows Registry (Apache 2.0)
│   │   ├── issen-parser-lnk/          # Shortcut files (Apache 2.0)
│   │   ├── issen-parser-amcache/      # Application cache (Apache 2.0)
│   │   ├── issen-parser-bam/          # Background Activity Monitor (Apache 2.0)
│   │   ├── issen-parser-browser/      # Browser history (Apache 2.0)
│   │   ├── issen-parser-jumplists/    # Jump Lists (Apache 2.0)
│   │   └── issen-parser-srum/         # System Resource Usage (Apache 2.0)
│   ├── issen-ewf/                     # E01/EWF reader (MIT)
│   ├── issen-shrinkpath/              # Path utility (MIT)
│   └── issen-cli/                     # CLI frontend (Apache 2.0)
├── tests/                          # Integration tests, golden files
├── benches/                        # Criterion benchmarks
└── docs/                           # Public documentation
```

### 4.2 Private Repository (Proprietary)

```
private/issen-pro
├── Cargo.toml                      # Workspace, depends on public crates via git/path
├── crates/
│   ├── issen-report/                  # Report engine (HTML, DOCX, PDF)
│   ├── issen-correlation/             # Cross-artifact correlation engine
│   ├── issen-intel/                   # Intelligence layer (ForensicLLM, RAG, YARA-X)
│   ├── issen-tui/                     # Interactive TUI (ratatui)
│   ├── issen-gui/                     # Tauri v2 desktop GUI
│   ├── issen-web/                     # axum + Leptos web UI
│   ├── issen-enterprise/              # SSO, teams, audit, license management
│   └── issen-license/                 # License validation, feature gating
└── assets/                         # Report templates, UI assets
```

### 4.3 Dependency Direction Rule

```
INVARIANT: Open-source crates NEVER depend on proprietary crates.

  issen-core          (open)  -->  depends on: nothing (pure)
  issen-pipeline      (open)  -->  depends on: issen-core
  issen-timeline      (open)  -->  depends on: issen-core
  issen-parser-*      (open)  -->  depends on: issen-core (via issen-plugin-sdk)
  issen-cli           (open)  -->  depends on: issen-core, issen-pipeline, issen-timeline

  issen-report        (prop)  -->  depends on: issen-core, issen-timeline
  issen-correlation   (prop)  -->  depends on: issen-core, issen-timeline
  issen-intel         (prop)  -->  depends on: issen-core, issen-timeline
  issen-gui           (prop)  -->  depends on: issen-core, issen-timeline, issen-report
  issen-web           (prop)  -->  depends on: issen-core, issen-timeline, issen-report
  issen-enterprise    (prop)  -->  depends on: issen-core
```

**Feature flag gating**: The `issen-cli` crate uses Cargo feature flags to conditionally enable proprietary functionality when built from the private repo:

```toml
# issen-cli/Cargo.toml (public repo -- features are absent)
[features]
default = []
pro = ["issen-report", "issen-correlation", "issen-tui"]
enterprise = ["pro", "issen-enterprise", "issen-license"]

# When built from private repo, features are activated:
# cargo build --features enterprise
```

**Runtime license validation**: `issen-license` validates a signed license key at startup. Features degrade gracefully -- unlicensed users get open-source CLI with timeline query capabilities. Licensed users unlock TUI, report generation, correlation, and AI features.

---

## 5. Intelligence Layer

### 5.1 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Intelligence Layer (issen-intel)                   │
│                                                                     │
│  ┌───────────────┐  ┌───────────────┐  ┌────────────────────────┐  │
│  │  ForensicLLM  │  │  Detection    │  │  Threat Intelligence   │  │
│  │  (Ollama)     │  │  Engine       │  │  Integration           │  │
│  │               │  │               │  │                        │  │
│  │ - Narrative   │  │ - YARA-X      │  │ - MISP (API + offline) │  │
│  │   drafting    │  │   (files)     │  │ - OpenCTI (GraphQL)    │  │
│  │ - IOC extract │  │ - Sigma       │  │ - VirusTotal           │  │
│  │ - Correlation │  │   (events)    │  │ - AlienVault OTX       │  │
│  │   assist      │  │ - Custom      │  │ - Local cache          │  │
│  └───────┬───────┘  │   rules       │  └────────────────────────┘  │
│          │          └───────┬───────┘                                │
│          │                  │                                        │
│  ┌───────▼──────────────────▼───────┐                               │
│  │          RAG Pipeline            │                               │
│  │                                  │                               │
│  │  ┌──────────┐  ┌──────────────┐  │                               │
│  │  │Case-     │  │Cross-Case    │  │                               │
│  │  │Specific  │  │Knowledge     │  │                               │
│  │  │(ephemeral│  │(persistent   │  │                               │
│  │  │ per case)│  │ shared)      │  │                               │
│  │  └──────────┘  └──────────────┘  │                               │
│  └──────────────────────────────────┘                               │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.2 Grounded Generation Protocol

Every AI-generated statement must be grounded in evidence. The ForensicLLM prompt template enforces this:

```
You are a forensic analysis assistant. You MUST:
1. Only make claims supported by evidence in the provided timeline events
2. Cite specific event IDs for every factual statement
3. Clearly label inferences vs. observations
4. Use hedging language for uncertain conclusions ("consistent with", "suggests")
5. Never fabricate timestamps, file paths, or user accounts

If the evidence is insufficient to support a conclusion, say so explicitly.
```

**Hallucination guardrail**: Post-generation validation checks every cited event ID against the DuckDB timeline. Claims referencing non-existent events are flagged and removed before report inclusion.

### 5.3 Detection Engine

- **YARA-X**: Compiled Rust implementation. Scans extracted files and memory dumps against rule sets. Built-in rules for common malware families, stealer logs, webshells. Custom rule directories supported.
- **Sigma**: Event log matching against Sigma rules (ported from tl v0.1). Converts Sigma YAML to DuckDB SQL predicates for timeline-native matching. Supports custom rule directories.
- **Combined output**: Detection hits are written as tags on matching `TimelineEvent` records (`yara-hit`, `sigma-hit`) with rule metadata in the event's `metadata` JSON.

### 5.4 AI-Free Mode

When `--no-ai` flag is set or `RT_AI_ENABLED=false`:

- No Ollama process is started
- No embedding models are loaded
- No vector stores are created
- YARA-X and Sigma rules still execute (deterministic, no AI)
- Report generation uses template-only mode (structured data, no narrative drafting)
- All pipeline stages function normally

This is not a degraded mode -- it is a first-class operating mode for air-gapped environments, resource-constrained machines, and examiners who prefer manual analysis.

---

## 6. Report Engine Architecture

The report is the product (Axiom 2). The report engine is proprietary and produces dual-format output.

### 6.1 Rendering Pipeline

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Findings   │     │   Template   │     │    Output     │
│   + Context  │────►│   Engine     │────►│   Formats     │
│              │     │  (Askama)    │     │              │
│ - Bookmarks  │     │              │     │ - HTML (self- │
│ - Timeline   │     │ - Executive  │     │   contained)  │
│   slice      │     │   summary    │     │ - DOCX (docx- │
│ - Annotations│     │ - Timeline   │     │   rs + py)    │
│ - AI draft   │     │ - Findings   │     │ - PDF (Chrome │
│   (optional) │     │ - Appendices │     │   headless)   │
└──────────────┘     └──────────────┘     └──────────────┘
```

### 6.2 Format Details

| Format | Technology | Use Case | Requirements |
|--------|-----------|----------|-------------|
| **Interactive HTML** | Askama templates, vanilla JS, self-contained CSS | Attorney exploration: filterable timeline, expandable evidence, interactive charts | No external dependencies. Single .html file. Test across Chrome/Firefox/Edge/Safari. |
| **Word (DOCX)** | docx-rs (Rust-native) with python-docx fallback | Formal expert witness reports for court filing | Numbered headings via multilevel list (never literal section numbers in text). Firm template support. |
| **PDF** | Headless Chromium rendering of HTML template | Print-ready version of HTML report | Pagination, headers/footers, page numbers. Fallback for restricted environments. |

### 6.3 Chain-of-Custody in Reports

Every report includes:
- Evidence source hashes (SHA-256) at time of ingest
- Processing audit log (parser versions, timestamps, any errors)
- Examiner identity and case metadata
- Report generation timestamp and tool version
- Content hash of the final report file

---

## 7. Technology Stack

| Layer | Technology | Rationale |
|-------|------------|-----------|
| **Language** | Rust (2021 edition) | Memory safety, zero-cost abstractions, ownership prevents evidence data leaks. Existing codebase. |
| **LLM Runtime** | Ollama (local) | Local-first requirement for forensic data sovereignty. No cloud dependency. Supports llama.cpp models. |
| **LLM Integration** | ollama-rs | Rust-native Ollama client. Async, streaming, structured output. |
| **Orchestration** | Custom Rust pipeline (rayon + tokio) | rayon for CPU-bound parallel parsing, tokio for async I/O and network. No framework overhead. |
| **Serialization** | serde + serde_json | Rust ecosystem standard. Zero-copy deserialization where possible. |
| **CLI Framework** | clap v4 | Derive macros, completions, subcommands. Existing usage in tl. |
| **TUI Framework** | ratatui 0.29 + crossterm 0.28 | Mature Rust TUI. Timeline widget, keybinding system, dark mode native. |
| **Desktop GUI** | Tauri v2 | Rust backend + webview frontend. Small binary (~10MB vs 200MB+ Electron). IPC via commands. |
| **Web Framework** | axum 0.8 | Tower ecosystem, async, middleware, type-safe extractors. Lightweight. |
| **Web Frontend** | Leptos (SSR) | Rust-native, fine-grained reactivity, SSR for initial load. Shares types with backend. |
| **Primary Database** | DuckDB (via duckdb-rs) | Columnar analytics for 100M+ event timelines. In-process, TIMESTAMP_NS, zone maps, parallel query. |
| **Exchange Database** | SQLite (via rusqlite) | Portable case export. Universal tooling. Legal hold format. |
| **Template Engine** | Askama | Compile-time HTML templates. Type-safe. Zero runtime overhead. |
| **DOCX Generation** | docx-rs + python-docx (fallback) | Rust-native DOCX creation. python-docx via PyO3 for complex formatting edge cases. |
| **PDF Generation** | headless-chrome (Rust) | Chromium rendering of HTML reports to PDF. Pagination, headers/footers. |
| **Image Parsing** | issen-ewf (custom) | Pure Rust E01/EWF reader. Multi-segment, streaming, verified. |
| **Detection (Files)** | yara-x | YARA compiled to Rust. Fast file scanning. Memory-safe. |
| **Detection (Events)** | Custom Sigma engine | Sigma YAML to DuckDB SQL. Ported from tl v0.1. |
| **Vector Store** | lancedb (embedded) | Embedded vector DB. Rust-native. No server. Fits local-first model. |
| **Embedding Model** | nomic-embed-text (via Ollama) | Open-source, 8K context, good forensic text performance. Local. |
| **Hashing** | ring / sha2 | SHA-256 for evidence integrity, chain-of-custody, deduplication. |
| **Logging/Tracing** | tracing + tracing-subscriber | Structured logging. Spans for pipeline stage timing. TARR instrumentation. |
| **Error Handling** | thiserror + anyhow | thiserror for library errors, anyhow for application. Consistent error chains. |
| **Testing** | cargo test + criterion + proptest | Unit + integration + benchmark + property-based. Golden file tests for parsers. |
| **WASM Runtime** | wasmtime (v0.3+) | WIT support, capability-based security, memory isolation for community plugins. |
| **gRPC** | tonic (v0.5+) | Rust gRPC. Codegen from protobuf. Enterprise plugin communication. |

### Key Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `duckdb` | 1.x | Timeline storage engine |
| `rusqlite` | 0.32+ | SQLite export |
| `rayon` | 1.x | Parallel parsing |
| `tokio` | 1.x | Async runtime |
| `clap` | 4.x | CLI argument parsing |
| `ratatui` | 0.29 | TUI framework |
| `tauri` | 2.x | Desktop GUI shell |
| `axum` | 0.8 | Web server |
| `leptos` | 0.7 | Web frontend |
| `serde` | 1.x | Serialization |
| `askama` | 0.12+ | HTML templates |
| `ollama-rs` | latest | LLM client |
| `yara-x` | latest | YARA rule engine |
| `lancedb` | latest | Embedded vector store |
| `tracing` | 0.1 | Structured logging |
| `inventory` | latest | Compile-time plugin registration |

---

## 8. Phase 2+ Extensions

### 8.1 WASM Plugin Ecosystem (v0.3)

Target: Enable community-contributed parsers without requiring Rust compilation or trust in third-party native code.

```
Community Parser Development Workflow:
1. `cargo install issen-plugin-cli`
2. `issen-plugin new my-parser --template artifact`
3. Implement ArtifactParser trait in Rust (compiled to WASM)
4. `issen-plugin build` → my-parser.wasm
5. `issen-plugin test` → runs against golden files
6. `rt plugin install my-parser.wasm` → registered in user's plugin directory
```

Decision criteria for v0.3 launch: 5+ community requests for custom parser support, OR first paying customer requesting artifact type we do not natively support.

### 8.2 Enterprise Integrations (v0.5)

Target: gRPC plugin tier for SIEM, TI platform, and ticketing integrations.

```
Enterprise Integration Points:
- Threat Intel: MISP, OpenCTI, VirusTotal, AlienVault OTX
- Case Management: TheHive, ServiceNow, Jira
- SIEM Export: Splunk, Elastic, Sentinel (push findings)
- Evidence Platforms: Relativity, Nuix (export chain-of-custody packages)
```

Decision criteria: First enterprise customer with specific integration requirement and willingness to pay.

### 8.3 Multi-User Collaboration (v0.7)

Target: Team-based case management with concurrent analysis, shared annotations, and review workflows. Requires `issen-enterprise` crate with SSO, RBAC, and audit logging.

---

## 9. Testing Strategy

| Category | Scope | Tooling | Trigger |
|----------|-------|---------|---------|
| **Unit Tests** | Individual parser output, core analysis functions | `cargo test`, proptest | Every commit |
| **Golden File Tests** | Parser output against known-good reference files | Custom test harness + NIST reference images | Every commit |
| **Integration Tests** | Full pipeline (ingest --> timeline --> query) | cargo test (integration feature) | PR merge |
| **Benchmark Tests** | Parse throughput, query latency, memory usage | Criterion | Weekly + release |
| **Forensic Validation** | Output compared against AXIOM/X-Ways/Autopsy for same evidence | Manual + automated diff | Release |
| **Report Regression** | HTML/DOCX output visual diff | Playwright screenshots + diff | PR merge |
| **TARR E2E** | Full journey timing (ingest to report) | Custom harness | Release candidate |

**NIST reference datasets**: Test against NIST Computer Forensics Reference Data Sets (CFReDS) for parser correctness validation. Critical for Daubert admissibility -- Issen must produce results consistent with validated tools.

---

## 10. Deployment Checklist

### Pre-Launch (v0.1 -- Open-Source CLI)

- [ ] All first-party parsers pass golden file tests against NIST CFReDS
- [ ] `issen-core` has zero I/O imports (enforced by `#![deny(clippy::disallowed_methods)]`)
- [ ] DuckDB timeline handles 10M+ events without OOM on 16GB machine
- [ ] `rt ingest` processes 50GB E01 image in < 10 minutes
- [ ] Chain-of-custody hash verification passes on all output formats
- [ ] LICENSING.md accurately maps every crate to its license
- [ ] CI pipeline: `cargo test`, `cargo clippy`, `cargo fmt`, `cargo audit`
- [ ] README with quick-start: install, ingest, query, export
- [ ] Binary releases for Linux x86_64, macOS arm64, Windows x86_64

### Post-Launch (v0.1+)

- [ ] Monitor GitHub issues for parser accuracy reports
- [ ] Track download counts and `rt ingest` success/failure rates (opt-in telemetry)
- [ ] Benchmark against AXIOM/Autopsy on identical evidence sets
- [ ] Community contribution guide for new parsers
- [ ] Begin issen-report development (proprietary, v0.2 target)

---

## Appendix A: Forensic Domain Resources

| Resource | URL | Relevance |
|----------|-----|-----------|
| NIST CFReDS | https://cfreds.nist.gov/ | Reference datasets for parser validation |
| MITRE ATT&CK | https://attack.mitre.org/ | Technique taxonomy for correlation |
| ForensicArtifacts.com | https://forensicartifacts.com/ | Artifact definitions (GRR format) |
| YARA Rules | https://github.com/Yara-Rules/rules | Community detection rules |
| SigmaHQ | https://github.com/SigmaHQ/sigma | Community detection rules for event logs |
| Eric Zimmerman's tools | https://ericzimmerman.github.io/ | Reference implementations (C#) for validation |
| Autopsy | https://www.autopsy.com/ | Open-source forensic platform (competitive reference) |
| DuckDB Docs | https://duckdb.org/docs/ | Timeline store reference |

## Appendix B: Decision Log

| Date | Decision | Rationale | Alternatives Considered |
|------|----------|-----------|------------------------|
| 2026-03-20 | DuckDB as primary timeline store | Columnar analytics for 100M+ events. In-process. TIMESTAMP_NS. Zone maps for time-range queries. FTK's PostgreSQL and Autopsy's SQLite both hit scaling walls. | SQLite (too slow for analytics), PostgreSQL (server overhead), Apache Arrow/Parquet (no query engine) |
| 2026-03-20 | SQLite as exchange format | Universal tooling, portable, attorney/paralegal can open with DB Browser. Legal hold compliance. | Parquet (tooling barrier for legal teams), JSON (too large), proprietary format (vendor lock-in) |
| 2026-03-20 | Hexagonal architecture (Crux-inspired) | Side-effect-free core enables CLI/TUI/GUI/Web from same logic. Critical for solo dev velocity -- write analysis once. | MVC (couples UI to logic), microservices (over-engineering for solo dev), monolith (hard to add surfaces) |
| 2026-03-20 | Three-tier plugin system | Tier 1 (traits) for performance. Tier 2 (WASM) for safety. Tier 3 (gRPC) for enterprise. Research shows over-engineering plugins early is a pitfall -- start with Tier 1 only. | WASM-only (too much overhead for first-party), dylib/FFI (unsafe), single-tier (insufficient flexibility) |
| 2026-03-20 | Hybrid public/private repo | Grafana/GitLab precedent. Open parsers build trust. Private integration captures value. Crate-level boundary is clean in Rust. | Single private repo (no community), single public repo (cannot monetize), AGPL (deters enterprise adoption) |
| 2026-03-20 | Local-first AI via Ollama | Forensic data sovereignty. Evidence cannot leave examiner's machine. Cost predictability. Air-gapped lab support. | Cloud-only (data sovereignty violation), hybrid-default (complexity), no AI (leaves value on table) |
| 2026-03-20 | Dual report output (HTML + DOCX) | Attorneys need both: interactive exploration (HTML) and couissen-ready filing (DOCX/PDF). No competitor does both well. | HTML-only (court needs formal docs), PDF-only (no interactivity), proprietary format (vendor lock-in) |

---

*Cross-references: [BRAND_GUIDELINES.md](BRAND_GUIDELINES.md) | [NORTHSTAR.md](NORTHSTAR.md) | [NORTHSTAR_EXTRACT.md](NORTHSTAR_EXTRACT.md) | [USER_JOURNEYS.md](design/USER_JOURNEYS.md) | [COMPETITIVE_LANDSCAPE.md](COMPETITIVE_LANDSCAPE.md)*
