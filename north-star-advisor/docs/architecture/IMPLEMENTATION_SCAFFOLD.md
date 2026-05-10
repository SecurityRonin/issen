# Issen: Implementation Scaffold

> **Parent**: [ARCHITECTURE_BLUEPRINT.md](../ARCHITECTURE_BLUEPRINT.md)
> **Created**: 2026-03-20
> **Status**: Active

Directory structure, workspace configuration, build automation, CI/CD pipeline, and the git-clone-to-running-tests developer path for Issen.

---

## 1. Directory Structure

Issen uses a **hybrid dual-repo** model: a public Cargo workspace monorepo (Apache 2.0 / MIT) and a separate private repo for proprietary crates. Both repos are developed independently; the private repo consumes public crates as path or git dependencies.

### 1.1 Public Monorepo (`github.com/h4x0r/issen`)

```
issen/
├── Cargo.toml                          # Virtual workspace manifest
├── Cargo.lock                          # Pinned dependency graph
├── LICENSING.md                        # Per-crate license declarations
├── deny.toml                           # cargo-deny configuration
├── supply-chain/                       # cargo-vet audit data
│   ├── config.toml
│   ├── audits.toml
│   └── imports.lock
├── rust-toolchain.toml                 # Pinned toolchain (stable)
├── .cargo/
│   └── config.toml                     # Workspace-wide Cargo settings
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                      # Primary CI pipeline
│   │   ├── release.yml                 # Release builds + crate publishing
│   │   ├── audit.yml                   # Nightly cargo-audit + cargo-deny
│   │   └── bench.yml                   # Criterion benchmark regression
│   ├── dependabot.yml                  # Dependency update automation
│   └── CODEOWNERS                      # Review gate per crate
├── .pre-commit-config.yaml             # Pre-commit hooks
├── clippy.toml                         # Workspace-wide clippy configuration
├── crates/
│   ├── issen-core/                        # Core types & plugin traits (Apache 2.0)
│   │   ├── Cargo.toml
│   │   ├── LICENSE-APACHE
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── timeline/               # TimelineEvent, Timestamp, EventKind
│   │       │   ├── mod.rs
│   │       │   ├── event.rs            # TimelineEvent struct
│   │       │   ├── schema.rs           # Column types, DuckDB mapping
│   │       │   └── timestamp.rs        # Nanosecond-precision timestamp
│   │       ├── artifacts/              # ArtifactType enum, artifact metadata
│   │       │   ├── mod.rs
│   │       │   └── types.rs
│   │       ├── plugin/                 # ForensicParser trait, registration
│   │       │   ├── mod.rs
│   │       │   ├── traits.rs           # ForensicParser, EventEmitter
│   │       │   └── registry.rs         # inventory-based registration
│   │       ├── vfs/                    # VirtualFilesystem abstraction
│   │       │   ├── mod.rs
│   │       │   ├── node.rs
│   │       │   └── overlay.rs          # Multi-source VFS merge
│   │       ├── error.rs                # RtError enum (thiserror)
│   │       └── config.rs               # Runtime configuration types
│   │
│   ├── issen-pipeline/                    # Evidence ingestion pipeline (Apache 2.0)
│   │   ├── Cargo.toml
│   │   ├── LICENSE-APACHE
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── layers/                 # Layer 0-4 pipeline stages
│   │       │   ├── mod.rs
│   │       │   ├── layer0_storage.rs   # Raw evidence access (E01, raw, VMDK)
│   │       │   ├── layer1_volume.rs    # Volume system parsing (GPT, MBR)
│   │       │   ├── layer2_fs.rs        # Filesystem access (NTFS, ext4, APFS)
│   │       │   ├── layer3_artifact.rs  # Artifact extraction
│   │       │   └── layer4_parse.rs     # Parser dispatch (rayon parallel)
│   │       ├── orchestrator.rs         # Pipeline coordination
│   │       ├── fingerprint.rs          # SourceFingerprint for incremental
│   │       └── progress.rs             # Progress reporting channel
│   │
│   ├── issen-plugin-sdk/                  # Plugin development kit (Apache 2.0)
│   │   ├── Cargo.toml
│   │   ├── LICENSE-APACHE
│   │   └── src/
│   │       ├── lib.rs                  # Re-exports from issen-core
│   │       ├── test_harness.rs         # Test utilities for parser authors
│   │       └── macros.rs               # #[forensic_parser] proc macro
│   │
│   ├── issen-timeline/                    # DuckDB timeline store (Apache 2.0)
│   │   ├── Cargo.toml
│   │   ├── LICENSE-APACHE
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── store.rs                # DuckDB connection, schema DDL
│   │       ├── ingest.rs               # Batch insert via appender
│   │       ├── query.rs                # Timeline query builder
│   │       ├── export.rs               # SQLite portable export
│   │       └── stats.rs                # Timeline statistics
│   │
│   ├── issen-ewf/                         # E01/EWF forensic image reader (MIT)
│   │   ├── Cargo.toml
│   │   ├── LICENSE-MIT
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── header.rs               # EWF header parsing
│   │       ├── segment.rs              # Multi-segment file handling
│   │       └── reader.rs               # Streaming read interface
│   │
│   ├── issen-shrinkpath/                  # Path utility (MIT)
│   │   ├── Cargo.toml
│   │   ├── LICENSE-MIT
│   │   └── src/lib.rs
│   │
│   ├── parsers/                        # First-party parsers (all Apache 2.0)
│   │   ├── issen-parser-usnjrnl/          # USN Journal
│   │   │   ├── Cargo.toml
│   │   │   └── src/lib.rs
│   │   ├── issen-parser-mft/              # Master File Table
│   │   ├── issen-parser-evtx/             # Windows Event Logs
│   │   ├── issen-parser-prefetch/         # Prefetch files
│   │   ├── issen-parser-registry/         # Windows Registry hives
│   │   ├── issen-parser-shellbags/        # Shellbags
│   │   ├── issen-parser-lnk/             # LNK shortcut files
│   │   ├── issen-parser-amcache/          # Application cache
│   │   ├── issen-parser-bam/              # Background Activity Monitor
│   │   ├── issen-parser-browser/          # Browser history
│   │   ├── issen-parser-jumplists/        # Jump Lists
│   │   └── issen-parser-srum/             # System Resource Usage Monitor
│   │
│   └── issen-cli/                         # CLI frontend (Apache 2.0)
│       ├── Cargo.toml
│       ├── LICENSE-APACHE
│       └── src/
│           ├── main.rs
│           ├── commands/               # Subcommand modules
│           │   ├── mod.rs
│           │   ├── ingest.rs           # Evidence ingestion
│           │   ├── timeline.rs         # Timeline query/export
│           │   ├── parse.rs            # Single-artifact parse
│           │   └── info.rs             # Evidence metadata
│           └── output.rs               # Table/JSON/CSV formatters
│
├── tests/                              # Integration tests
│   ├── pipeline_integration.rs         # End-to-end pipeline tests
│   ├── timeline_integration.rs         # DuckDB roundtrip tests
│   ├── parser_conformance.rs           # All parsers against golden data
│   └── fixtures/                       # Test data (committed, small)
│       ├── usnjrnl/
│       ├── mft/
│       ├── evtx/
│       └── ewf/
│
├── benches/                            # Criterion benchmarks
│   ├── pipeline_bench.rs
│   ├── parser_bench.rs
│   └── timeline_bench.rs
│
├── xtask/                              # Build automation (cargo xtask)
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── codegen.rs                  # Generated code (schema DDL, etc.)
│       ├── dist.rs                     # Release packaging
│       ├── bench_report.rs             # Benchmark comparison
│       └── test_data.rs                # Download/validate test fixtures
│
├── docs/                               # Public documentation
│   ├── CONTRIBUTING.md
│   ├── plugin-guide.md
│   └── architecture.md
│
└── north-star-advisor/                 # Strategic documentation (gitignored in releases)
    └── docs/
```

### 1.2 Private Repository (`github.com/h4x0r/issen-pro`)

```
issen-pro/
├── Cargo.toml                          # Workspace manifest (path deps to ../issen/crates/)
├── Cargo.lock
├── .cargo/
│   └── config.toml                     # paths override for local development
├── crates/
│   ├── issen-report/                      # Report engine (Proprietary)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── html.rs                 # Interactive HTML report generation
│   │       ├── docx.rs                 # Word document assembly
│   │       ├── pdf.rs                  # PDF rendering
│   │       └── templates/              # Askama report templates
│   │
│   ├── issen-correlation/                 # Cross-artifact correlation (Proprietary)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── engine.rs               # Correlation rule engine
│   │       ├── patterns.rs             # Attack pattern definitions
│   │       └── graph.rs                # Event relationship graph
│   │
│   ├── issen-intel/                       # Intelligence layer (Proprietary)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── llm/                    # ForensicLLM, Ollama client
│   │       ├── rag/                    # RAG pipeline, lancedb store
│   │       ├── yara.rs                 # YARA-X rule integration
│   │       ├── sigma.rs                # Sigma rule engine
│   │       └── enrichment.rs           # Threat intelligence enrichment
│   │
│   ├── issen-tui/                         # Terminal UI (Proprietary)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── app.rs                  # ratatui application state
│   │       ├── views/                  # Timeline, detail, filter views
│   │       └── keybindings.rs
│   │
│   ├── issen-gui/                         # Desktop GUI (Proprietary)
│   │   ├── Cargo.toml
│   │   ├── tauri.conf.json
│   │   └── src/
│   │       ├── main.rs                 # Tauri entry point
│   │       └── commands/               # Tauri IPC commands
│   │
│   ├── issen-web/                         # Web UI (Proprietary)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs                 # axum server
│   │       ├── routes/                 # API endpoints
│   │       └── frontend/               # Leptos components
│   │
│   └── issen-license/                     # License validation (Proprietary)
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           └── editions.rs             # Community / Professional / Enterprise
│
└── tests/
    ├── report_integration.rs
    ├── correlation_integration.rs
    └── intel_integration.rs
```

---

## 2. Workspace Configuration

### 2.1 Root `Cargo.toml` (Public Monorepo)

```toml
[workspace]
resolver = "2"
members = [
    "crates/issen-core",
    "crates/issen-pipeline",
    "crates/issen-plugin-sdk",
    "crates/issen-timeline",
    "crates/issen-ewf",
    "crates/issen-shrinkpath",
    "crates/parsers/issen-parser-usnjrnl",
    "crates/parsers/issen-parser-mft",
    "crates/parsers/issen-parser-evtx",
    "crates/parsers/issen-parser-prefetch",
    "crates/parsers/issen-parser-registry",
    "crates/parsers/issen-parser-shellbags",
    "crates/parsers/issen-parser-lnk",
    "crates/parsers/issen-parser-amcache",
    "crates/parsers/issen-parser-bam",
    "crates/parsers/issen-parser-browser",
    "crates/parsers/issen-parser-jumplists",
    "crates/parsers/issen-parser-srum",
    "crates/issen-cli",
    "xtask",
]

[workspace.package]
edition = "2021"
rust-version = "1.80"
license = "Apache-2.0"
repository = "https://github.com/h4x0r/issen"
homepage = "https://issen.dev"
authors = ["Issen Contributors"]

[workspace.dependencies]
# Internal crates (path dependencies)
issen-core       = { path = "crates/issen-core" }
issen-pipeline   = { path = "crates/issen-pipeline" }
issen-plugin-sdk = { path = "crates/issen-plugin-sdk" }
issen-timeline   = { path = "crates/issen-timeline" }
issen-ewf        = { path = "crates/issen-ewf" }
issen-shrinkpath = { path = "crates/issen-shrinkpath" }

# External dependencies (pinned to compatible ranges)
duckdb       = { version = "1", features = ["bundled"] }
rusqlite     = { version = "0.32", features = ["bundled"] }
rayon        = "1"
tokio        = { version = "1", features = ["full"] }
clap         = { version = "4", features = ["derive"] }
serde        = { version = "1", features = ["derive"] }
serde_json   = "1"
thiserror    = "2"
anyhow       = "1"
tracing      = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
inventory    = "0.3"
chrono       = { version = "0.4", features = ["serde"] }
bytes        = "1"
memmap2      = "0.9"
tempfile     = "3"
criterion    = { version = "0.5", features = ["html_reports"] }
insta        = { version = "1", features = ["yaml"] }
assert_cmd   = "2"
predicates   = "3"

[workspace.lints.rust]
unsafe_code = "deny"
missing_docs = "warn"

[workspace.lints.clippy]
all = { level = "warn", priority = -1 }
pedantic = { level = "warn", priority = -1 }
nursery = { level = "warn", priority = -1 }
unwrap_used = "deny"
expect_used = "warn"
panic = "deny"
```

### 2.2 Feature Flag Configuration

Feature flags control optional capabilities without pulling in proprietary code.

```toml
# crates/issen-core/Cargo.toml
[features]
default = []
repoissen-hooks = []       # Enables trait extension points for report engine
correlation-hooks = []  # Enables trait extension points for correlation engine
intel-hooks = []        # Enables trait extension points for intelligence layer
simd = ["dep:packed_simd"]  # SIMD-accelerated parsing (opt-in)

# crates/issen-pipeline/Cargo.toml
[features]
default = ["all-parsers"]
all-parsers = [
    "parser-usnjrnl", "parser-mft", "parser-evtx", "parser-prefetch",
    "parser-registry", "parser-shellbags", "parser-lnk", "parser-amcache",
    "parser-bam", "parser-browser", "parser-jumplists", "parser-srum",
]
parser-usnjrnl = ["dep:issen-parser-usnjrnl"]
parser-mft = ["dep:issen-parser-mft"]
parser-evtx = ["dep:issen-parser-evtx"]
parser-prefetch = ["dep:issen-parser-prefetch"]
parser-registry = ["dep:issen-parser-registry"]
parser-shellbags = ["dep:issen-parser-shellbags"]
parser-lnk = ["dep:issen-parser-lnk"]
parser-amcache = ["dep:issen-parser-amcache"]
parser-bam = ["dep:issen-parser-bam"]
parser-browser = ["dep:issen-parser-browser"]
parser-jumplists = ["dep:issen-parser-jumplists"]
parser-srum = ["dep:issen-parser-srum"]

# crates/issen-cli/Cargo.toml
[features]
default = ["color"]
color = ["dep:owo-colors"]
json-output = []        # JSON output format (always available, flag for clarity)
```

### 2.3 Example Crate `Cargo.toml` (`issen-core`)

```toml
[package]
name = "issen-core"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license = "Apache-2.0"
description = "Core types, timeline schema, and plugin traits for Issen"
repository.workspace = true

[dependencies]
serde = { workspace = true }
chrono = { workspace = true }
thiserror = { workspace = true }
inventory = { workspace = true }
bytes = { workspace = true }
packed_simd = { version = "0.3", optional = true }

[dev-dependencies]
insta = { workspace = true }
```

---

## 3. Plugin Trait (BaseAgent Equivalent)

Issen does not use LLM-style "agents" in the traditional sense. Instead, the core extensibility primitive is the **`ForensicParser` trait**, which plays the same role as a BaseAgent class: every parser implements it, and the pipeline orchestrates them uniformly.

### 3.1 Interface Definition

```rust
// crates/issen-core/src/plugin/traits.rs

use crate::artifacts::ArtifactType;
use crate::error::RtError;
use crate::timeline::event::TimelineEvent;

/// Capabilities advertised by a parser.
#[derive(Debug, Clone)]
pub struct ParserCapabilities {
    /// Maximum expected memory usage in bytes.
    pub max_memory_bytes: Option<u64>,
    /// Whether the parser supports streaming (required for large artifacts).
    pub streaming: bool,
    /// Whether the parser is deterministic (same input => same output).
    pub deterministic: bool,
}

/// Channel for emitting timeline events during parsing.
pub trait EventEmitter: Send + Sync {
    /// Emit a single timeline event. Must not block.
    fn emit(&self, event: TimelineEvent) -> Result<(), RtError>;
    /// Emit a batch of events (preferred for performance).
    fn emit_batch(&self, events: Vec<TimelineEvent>) -> Result<(), RtError>;
}

/// Data source abstraction (file, memory-mapped region, or stream).
pub trait DataSource: Send + Sync {
    fn len(&self) -> u64;
    fn is_empty(&self) -> bool { self.len() == 0 }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError>;
}

/// Parse statistics returned after a successful parse.
#[derive(Debug, Clone)]
pub struct ParseStats {
    pub events_emitted: u64,
    pub bytes_processed: u64,
    pub errors_recovered: u64,
    pub duration: std::time::Duration,
}

/// Core trait all forensic parsers must implement.
///
/// Parsers are registered at compile time via the `inventory` crate.
/// The pipeline discovers and dispatches to them based on `supported_artifacts()`.
pub trait ForensicParser: Send + Sync {
    /// Human-readable parser name (e.g., "USN Journal Parser").
    fn name(&self) -> &str;

    /// Artifact types this parser can handle.
    fn supported_artifacts(&self) -> &[ArtifactType];

    /// Parse the data source, emitting events through the emitter.
    ///
    /// # Errors
    /// Returns `RtError` on unrecoverable parse failures.
    /// Recoverable errors should be logged and counted in `ParseStats`.
    fn parse(
        &self,
        input: &dyn DataSource,
        emitter: &dyn EventEmitter,
    ) -> Result<ParseStats, RtError>;

    /// Advertise parser capabilities for orchestration decisions.
    fn capabilities(&self) -> ParserCapabilities;
}
```

### 3.2 Compile-Time Registration

```rust
// crates/issen-core/src/plugin/registry.rs

use super::traits::ForensicParser;

/// Registration entry for the parser inventory.
pub struct ParserRegistration {
    pub create: fn() -> Box<dyn ForensicParser>,
}

inventory::collect!(ParserRegistration);

/// Discover all registered parsers at runtime (zero-cost enumeration).
pub fn all_parsers() -> Vec<Box<dyn ForensicParser>> {
    inventory::iter::<ParserRegistration>()
        .map(|reg| (reg.create)())
        .collect()
}
```

### 3.3 Default Constants

```rust
// crates/issen-core/src/config.rs

/// Default buffer size for streaming reads (64 KiB).
pub const DEFAULT_BUFFER_SIZE: usize = 64 * 1024;

/// Maximum events per batch emit.
pub const MAX_BATCH_SIZE: usize = 10_000;

/// Default DuckDB in-memory threshold before spill to disk (512 MiB).
pub const DUCKDB_MEMORY_LIMIT: &str = "512MB";

/// Rayon thread pool size (0 = auto-detect CPU count).
pub const RAYON_THREADS: usize = 0;

/// Pipeline timeout per artifact (5 minutes).
pub const ARTIFACT_TIMEOUT_SECS: u64 = 300;
```

---

## 4. Parser Implementations

### 4.1 Example Parser: USN Journal

```rust
// crates/parsers/issen-parser-usnjrnl/src/lib.rs

use rt_core::artifacts::ArtifactType;
use rt_core::error::RtError;
use rt_core::plugin::registry::ParserRegistration;
use rt_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParserCapabilities, ParseStats,
};
use rt_core::timeline::event::TimelineEvent;

pub struct UsnJrnlParser;

impl ForensicParser for UsnJrnlParser {
    fn name(&self) -> &str {
        "USN Journal Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::UsnJournal]
    }

    fn parse(
        &self,
        input: &dyn DataSource,
        emitter: &dyn EventEmitter,
    ) -> Result<ParseStats, RtError> {
        let mut stats = ParseStats {
            events_emitted: 0,
            bytes_processed: 0,
            errors_recovered: 0,
            duration: std::time::Duration::ZERO,
        };
        let start = std::time::Instant::now();

        let mut offset = 0u64;
        let mut buf = vec![0u8; 64 * 1024];
        let mut batch = Vec::with_capacity(1000);

        while offset < input.len() {
            let bytes_read = input.read_at(offset, &mut buf)?;
            if bytes_read == 0 {
                break;
            }

            // Parse USN_RECORD_V2/V3 structures from buffer
            // (actual parsing logic here -- version detection, field extraction)
            let records = self.parse_records(&buf[..bytes_read], &mut stats);

            for record in records {
                let event = TimelineEvent::from_usn_record(record);
                batch.push(event);

                if batch.len() >= 1000 {
                    stats.events_emitted += batch.len() as u64;
                    emitter.emit_batch(std::mem::take(&mut batch))?;
                }
            }

            offset += bytes_read as u64;
            stats.bytes_processed = offset;
        }

        // Flush remaining
        if !batch.is_empty() {
            stats.events_emitted += batch.len() as u64;
            emitter.emit_batch(batch)?;
        }

        stats.duration = start.elapsed();
        Ok(stats)
    }

    fn capabilities(&self) -> ParserCapabilities {
        ParserCapabilities {
            max_memory_bytes: Some(128 * 1024 * 1024), // 128 MiB
            streaming: true,
            deterministic: true,
        }
    }
}

// Compile-time registration -- no central enum needed
inventory::submit! {
    ParserRegistration { create: || Box::new(UsnJrnlParser) }
}
```

### 4.2 Pipeline Orchestrator (Parallel Dispatch)

```rust
// crates/issen-pipeline/src/orchestrator.rs

use rayon::prelude::*;
use rt_core::plugin::registry::all_parsers;
use rt_core::plugin::traits::ParseStats;
use rt_core::vfs::VirtualFilesystem;
use crate::progress::ProgressReporter;

pub struct PipelineOrchestrator {
    progress: ProgressReporter,
}

impl PipelineOrchestrator {
    /// Run all applicable parsers in parallel against the VFS.
    pub fn execute(&self, vfs: &VirtualFilesystem) -> Vec<Result<ParseStats, rt_core::error::RtError>> {
        let parsers = all_parsers();
        let artifacts = vfs.discover_artifacts();

        artifacts
            .par_iter()
            .flat_map(|artifact| {
                parsers
                    .iter()
                    .filter(|p| p.supported_artifacts().contains(&artifact.artifact_type))
                    .map(move |parser| {
                        self.progress.start(parser.name(), &artifact.path);
                        let result = parser.parse(&artifact.data_source, &artifact.emitter);
                        self.progress.finish(parser.name(), &result);
                        result
                    })
            })
            .collect()
    }
}
```

---

## 5. CLI Interface (API Routes Equivalent)

Issen is CLI-first. The CLI subcommands serve the same role as API routes in a web application.

### 5.1 Main Entry Point

```rust
// crates/issen-cli/src/main.rs

use clap::Parser;

mod commands;
mod output;

#[derive(Parser)]
#[command(name = "rt", version, about = "Issen forensic analysis platform")]
struct Cli {
    #[command(subcommand)]
    command: commands::Command,

    /// Output format
    #[arg(long, global = true, default_value = "table")]
    format: output::OutputFormat,

    /// Verbose logging
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize tracing based on verbosity
    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    match cli.command {
        commands::Command::Ingest(args) => commands::ingest::run(args, cli.format),
        commands::Command::Timeline(args) => commands::timeline::run(args, cli.format),
        commands::Command::Parse(args) => commands::parse::run(args, cli.format),
        commands::Command::Info(args) => commands::info::run(args, cli.format),
    }
}
```

### 5.2 Subcommands

```rust
// crates/issen-cli/src/commands/mod.rs

pub mod ingest;
pub mod timeline;
pub mod parse;
pub mod info;

#[derive(clap::Subcommand)]
pub enum Command {
    /// Ingest evidence sources into a timeline
    Ingest(ingest::IngestArgs),
    /// Query and export timeline data
    Timeline(timeline::TimelineArgs),
    /// Parse a single artifact file
    Parse(parse::ParseArgs),
    /// Display evidence source metadata
    Info(info::InfoArgs),
}
```

### 5.3 Health Check Equivalent (Info Command)

```rust
// crates/issen-cli/src/commands/info.rs

use rt_core::plugin::registry::all_parsers;

#[derive(clap::Args)]
pub struct InfoArgs {
    /// Show registered parsers
    #[arg(long)]
    parsers: bool,

    /// Evidence source path (optional)
    path: Option<std::path::PathBuf>,
}

pub fn run(args: InfoArgs, format: super::super::output::OutputFormat) -> anyhow::Result<()> {
    if args.parsers {
        let parsers = all_parsers();
        println!("Registered parsers: {}", parsers.len());
        for parser in &parsers {
            println!(
                "  {} -- artifacts: {:?}, streaming: {}",
                parser.name(),
                parser.supported_artifacts(),
                parser.capabilities().streaming
            );
        }
        return Ok(());
    }

    if let Some(path) = args.path {
        // Display evidence metadata (file type, size, hash, etc.)
        let metadata = rt_pipeline::inspect_evidence(&path)?;
        super::super::output::render(&metadata, format)?;
    }

    Ok(())
}
```

---

## 6. Configuration

### 6.1 Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `RT_LOG` | No | `warn` | Log level filter (`trace`, `debug`, `info`, `warn`, `error`) |
| `RT_LOG_FORMAT` | No | `pretty` | Log format (`pretty`, `json`, `compact`) |
| `RT_THREADS` | No | `0` (auto) | Rayon thread pool size |
| `RT_MEMORY_LIMIT` | No | `512MB` | DuckDB memory limit before spill |
| `RT_TEMP_DIR` | No | System temp | Temporary file directory for spill |
| `RT_PLUGIN_DIR` | No | None | Additional plugin search directory |
| `OLLAMA_HOST` | No | `http://localhost:11434` | Ollama server URL (pro features) |
| `RT_LICENSE_KEY` | No | None | License key for Professional/Enterprise (pro) |

### 6.2 Configuration File (`rt.toml`)

```toml
# Optional configuration file (searched in CWD, then ~/.config/issen/)

[pipeline]
threads = 0                     # 0 = auto-detect
buffer_size = 65536             # 64 KiB
artifact_timeout_secs = 300     # 5 minutes per artifact

[timeline]
memory_limit = "512MB"
default_export_format = "sqlite"

[output]
format = "table"                # table | json | csv
color = true
```

### 6.3 Configuration Validation (Startup)

```rust
// crates/issen-core/src/config.rs

use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Invalid memory limit: {0}")]
    InvalidMemoryLimit(String),
    #[error("Thread count must be 0-256, got {0}")]
    InvalidThreadCount(usize),
    #[error("Temp directory does not exist: {0}")]
    TempDirNotFound(PathBuf),
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub threads: usize,
    pub buffer_size: usize,
    pub memory_limit: String,
    pub temp_dir: PathBuf,
    pub log_level: String,
    pub log_format: String,
}

impl RuntimeConfig {
    /// Load from environment variables and optional config file, validate.
    pub fn load() -> Result<Self, ConfigError> {
        let config = Self {
            threads: std::env::var("RT_THREADS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(RAYON_THREADS),
            buffer_size: DEFAULT_BUFFER_SIZE,
            memory_limit: std::env::var("RT_MEMORY_LIMIT")
                .unwrap_or_else(|_| DUCKDB_MEMORY_LIMIT.to_string()),
            temp_dir: std::env::var("RT_TEMP_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| std::env::temp_dir()),
            log_level: std::env::var("RT_LOG")
                .unwrap_or_else(|_| "warn".to_string()),
            log_format: std::env::var("RT_LOG_FORMAT")
                .unwrap_or_else(|_| "pretty".to_string()),
        };

        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.threads > 256 {
            return Err(ConfigError::InvalidThreadCount(self.threads));
        }
        if !self.temp_dir.exists() {
            return Err(ConfigError::TempDirNotFound(self.temp_dir.clone()));
        }
        Ok(())
    }
}
```

---

## 7. CI/CD Pipeline

### 7.1 Primary CI (`ci.yml`)

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: "-D warnings"

jobs:
  check:
    name: Check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt
      - uses: Swatinem/rust-cache@v2

      - name: Format check
        run: cargo fmt --all -- --check

      - name: Clippy
        run: cargo clippy --workspace --all-targets --all-features -- -D warnings

      - name: Check (no default features)
        run: cargo check --workspace --no-default-features

  test:
    name: Test (${{ matrix.os }})
    needs: check
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2

      - name: Run tests
        run: cargo test --workspace --all-features

      - name: Run doc tests
        run: cargo test --workspace --doc

  coverage:
    name: Coverage
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2

      - name: Install cargo-tarpaulin
        run: cargo install cargo-tarpaulin

      - name: Generate coverage
        run: cargo tarpaulin --workspace --all-features --out xml --output-dir coverage/

      - name: Upload coverage
        uses: codecov/codecov-action@v4
        with:
          files: coverage/cobertura.xml
          fail_ci_if_error: false

  deny:
    name: Supply Chain
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: EmbarkStudios/cargo-deny-action@v2
```

### 7.2 Nightly Audit (`audit.yml`)

```yaml
# .github/workflows/audit.yml
name: Security Audit

on:
  schedule:
    - cron: '0 6 * * *'   # Daily at 06:00 UTC
  workflow_dispatch:

jobs:
  audit:
    name: cargo-audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rustsec/audit-check@v2
        with:
          token: ${{ secrets.GITHUB_TOKEN }}

  vet:
    name: cargo-vet
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Install cargo-vet
        run: cargo install cargo-vet
      - name: Check supply chain
        run: cargo vet
```

### 7.3 Benchmark Regression (`bench.yml`)

```yaml
# .github/workflows/bench.yml
name: Benchmarks

on:
  pull_request:
    branches: [main]
    paths:
      - 'crates/**'
      - 'benches/**'

jobs:
  benchmark:
    name: Performance Regression Check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2

      - name: Run benchmarks
        run: cargo bench --workspace -- --output-format bencher | tee output.txt

      - name: Store benchmark result
        uses: benchmark-action/github-action-benchmark@v1
        with:
          tool: 'cargo'
          output-file-path: output.txt
          fail-on-alert: true
          aleissen-threshold: '120%'     # Fail if 20% regression
          comment-on-alert: true
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

---

## 8. Supply Chain Security

### 8.1 `deny.toml` (cargo-deny)

```toml
[advisories]
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
vulnerability = "deny"
unmaintained = "warn"
yanked = "warn"

[licenses]
allow = [
    "MIT",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-3.0",
    "Zlib",
    "BSL-1.0",
    "CC0-1.0",
]
copyleft = "deny"
default = "deny"

[[licenses.exceptions]]
allow = ["MPL-2.0"]
crates = ["duckdb"]            # DuckDB uses MPL-2.0

[bans]
multiple-versions = "warn"
wildcards = "deny"
highlight = "all"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = []
```

### 8.2 `supply-chain/config.toml` (cargo-vet)

```toml
[cargo-vet]
version = "0.9"

[imports.bytecode-alliance]
url = "https://raw.githubusercontent.com/nickel-org/nickel.rs/main/supply-chain/audits.toml"

[imports.google]
url = "https://chromium.googlesource.com/chromiumos/third_party/rust_crates/+/refs/heads/main/cargo-vet/audits.toml?format=TEXT"

[imports.mozilla]
url = "https://raw.githubusercontent.com/nickel-org/nickel.rs/main/supply-chain/audits.toml"

[policy.issen-core]
audit-as-crates-io = false
criteria = "safe-to-deploy"

[policy.issen-pipeline]
audit-as-crates-io = false
criteria = "safe-to-deploy"
```

---

## 9. Pre-Commit Hooks

### 9.1 `.pre-commit-config.yaml`

```yaml
repos:
  - repo: local
    hooks:
      - id: cargo-fmt
        name: cargo fmt
        entry: cargo fmt --all --
        language: system
        types: [rust]
        pass_filenames: false

      - id: cargo-clippy
        name: cargo clippy
        entry: cargo clippy --workspace --all-targets --all-features -- -D warnings
        language: system
        types: [rust]
        pass_filenames: false

      - id: cargo-test
        name: cargo test (fast)
        entry: cargo test --workspace --lib --quiet
        language: system
        types: [rust]
        pass_filenames: false
        stages: [pre-push]

      - id: cargo-deny
        name: cargo deny check
        entry: cargo deny check
        language: system
        pass_filenames: false
        stages: [pre-push]

      - id: no-proprietary-imports
        name: Reject proprietary imports in public crates
        entry: "!grep -rn 'rt_report\\|rt_correlation\\|rt_intel\\|rt_tui\\|rt_gui\\|rt_web\\|rt_license' crates/"
        language: system
        types: [rust]
        pass_filenames: false
```

---

## 10. xtask Build Automation

The `xtask` pattern provides project-specific build commands without external tooling.

### 10.1 `xtask/Cargo.toml`

```toml
[package]
name = "xtask"
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
clap = { version = "4", features = ["derive"] }
anyhow = "1"
xshell = "0.2"
```

### 10.2 `xtask/src/main.rs`

```rust
use clap::Parser;

mod codegen;
mod dist;
mod bench_report;
mod test_data;

#[derive(Parser)]
enum Xtask {
    /// Generate code (schema DDL, parser stubs)
    Codegen,
    /// Build release packages
    Dist(dist::DistArgs),
    /// Compare benchmark results
    BenchReport,
    /// Download and validate test fixtures
    TestData,
    /// Run full CI checks locally
    Ci,
}

fn main() -> anyhow::Result<()> {
    match Xtask::parse() {
        Xtask::Codegen => codegen::run(),
        Xtask::Dist(args) => dist::run(args),
        Xtask::BenchReport => bench_report::run(),
        Xtask::TestData => test_data::run(),
        Xtask::Ci => ci(),
    }
}

fn ci() -> anyhow::Result<()> {
    let sh = xshell::Shell::new()?;
    xshell::cmd!(sh, "cargo fmt --all -- --check").run()?;
    xshell::cmd!(sh, "cargo clippy --workspace --all-targets --all-features -- -D warnings").run()?;
    xshell::cmd!(sh, "cargo test --workspace --all-features").run()?;
    xshell::cmd!(sh, "cargo deny check").run()?;
    println!("All CI checks passed.");
    Ok(())
}
```

---

## 11. Toolchain Configuration

### 11.1 `rust-toolchain.toml`

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy", "rust-src"]
targets = ["x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "aarch64-apple-darwin", "x86_64-pc-windows-msvc"]
```

### 11.2 `.cargo/config.toml`

```toml
[alias]
xtask = "run --package xtask --"

[build]
# Faster linking on macOS
[target.x86_64-apple-darwin]
rustflags = ["-C", "link-arg=-fuse-ld=/usr/local/bin/zld"]

[target.aarch64-apple-darwin]
rustflags = ["-C", "link-arg=-fuse-ld=/usr/local/bin/zld"]

# Faster linking on Linux
[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "link-arg=-fuse-ld=lld"]

[net]
git-fetch-with-cli = true
```

---

## 12. Developer Quickstart: git clone to Running Tests

This section is the step-by-step path from a fresh clone to a passing test suite.

### Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Rust toolchain | 1.80+ | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| DuckDB C library | 1.x | Bundled via `duckdb` crate (no system install needed) |
| `cargo-deny` | latest | `cargo install cargo-deny` |
| `cargo-vet` | latest | `cargo install cargo-vet` |
| `cargo-tarpaulin` | latest | `cargo install cargo-tarpaulin` (optional, coverage) |
| `pre-commit` | latest | `pip install pre-commit` or `brew install pre-commit` |

### Step-by-Step

```bash
# 1. Clone the repository
git clone https://github.com/h4x0r/issen.git
cd issen

# 2. Verify toolchain (rust-toolchain.toml auto-installs via rustup)
rustc --version    # Should be >= 1.80
cargo --version

# 3. Install development tools
cargo install cargo-deny cargo-vet
pip install pre-commit    # or: brew install pre-commit

# 4. Set up pre-commit hooks
pre-commit install
pre-commit install --hook-type pre-push

# 5. Download test fixtures (small, committed fixtures exist; large ones downloaded)
cargo xtask test-data

# 6. Build the workspace (first build compiles DuckDB — takes ~3-5 min)
cargo build --workspace
#   If you see DuckDB build errors on macOS, ensure Xcode CLT is installed:
#   xcode-select --install

# 7. Run the full test suite
cargo test --workspace --all-features
#   Expected: all tests pass, ~30 seconds on modern hardware

# 8. Run a single crate's tests (faster iteration)
cargo test -p issen-core
cargo test -p issen-parser-usnjrnl

# 9. Run clippy (must pass with zero warnings)
cargo clippy --workspace --all-targets --all-features -- -D warnings

# 10. Run the full local CI suite
cargo xtask ci

# 11. Run benchmarks (optional, baseline)
cargo bench --workspace

# 12. Verify supply chain
cargo deny check
cargo vet

# 13. Try the CLI
cargo run -p issen-cli -- info --parsers
cargo run -p issen-cli -- parse --artifact usnjrnl tests/fixtures/usnjrnl/sample.bin
```

### First-Build Troubleshooting

| Problem | Solution |
|---------|----------|
| DuckDB build fails (macOS) | Install Xcode CLT: `xcode-select --install` |
| DuckDB build fails (Linux) | Install build essentials: `apt install build-essential cmake` |
| `cargo vet` fails | Run `cargo vet regenerate imports` to refresh trusted imports |
| Linking is slow | Install `lld` (Linux) or `zld` (macOS) for faster linking |
| Test fixtures missing | Run `cargo xtask test-data` to download |
| Clippy warns on nightly | Pin to stable channel via `rust-toolchain.toml` |

### Development Workflow

```
1. Create feature branch:   git checkout -b feat/parser-shellbags
2. Implement changes:        Edit crates/parsers/issen-parser-shellbags/src/lib.rs
3. Run targeted tests:       cargo test -p issen-parser-shellbags
4. Run lint:                 cargo clippy -p issen-parser-shellbags -- -D warnings
5. Run full suite:           cargo xtask ci
6. Commit:                   git commit  (pre-commit hooks run fmt + clippy)
7. Push:                     git push    (pre-push hooks run tests + deny)
8. PR:                       gh pr create
```

---

## Appendix A: Crate Dependency Graph

```
issen-core (pure, no deps)
├── issen-plugin-sdk (re-exports issen-core traits)
├── issen-pipeline (depends on issen-core)
│   └── issen-parser-* (each depends on issen-core via issen-plugin-sdk)
├── issen-timeline (depends on issen-core + duckdb)
├── issen-ewf (standalone, MIT)
├── issen-shrinkpath (standalone, MIT)
└── issen-cli (depends on issen-core, issen-pipeline, issen-timeline)

--- proprietary (separate repo) ---
issen-report (depends on issen-core, issen-timeline)
issen-correlation (depends on issen-core, issen-timeline)
issen-intel (depends on issen-core, issen-timeline, ollama-rs, yara-x, lancedb)
issen-tui (depends on issen-core, issen-timeline, ratatui)
issen-gui (depends on issen-core, issen-timeline, issen-report, tauri)
issen-web (depends on issen-core, issen-timeline, issen-report, axum, leptos)
issen-license (standalone)
```

---

## Appendix B: Cargo Feature Matrix

| Crate | Feature | Default | Description |
|-------|---------|---------|-------------|
| `issen-core` | `repoissen-hooks` | No | Extension points for report engine |
| `issen-core` | `correlation-hooks` | No | Extension points for correlation engine |
| `issen-core` | `intel-hooks` | No | Extension points for intelligence layer |
| `issen-core` | `simd` | No | SIMD-accelerated parsing |
| `issen-pipeline` | `all-parsers` | Yes | Include all first-party parsers |
| `issen-pipeline` | `parser-usnjrnl` | Yes (via all) | USN Journal parser |
| `issen-pipeline` | `parser-mft` | Yes (via all) | MFT parser |
| `issen-pipeline` | `parser-evtx` | Yes (via all) | Windows Event Log parser |
| `issen-pipeline` | `parser-prefetch` | Yes (via all) | Prefetch parser |
| `issen-pipeline` | `parser-registry` | Yes (via all) | Windows Registry parser |
| `issen-cli` | `color` | Yes | Colored terminal output |
| `issen-cli` | `json-output` | No | JSON output format |
