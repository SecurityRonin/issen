# Issen: Pipeline Orchestration

> **Deep Architecture Document** -- Defines the orchestration model for Issen's multi-layer evidence ingestion pipeline: how parsers are scheduled, how parallelism is managed, how progress is reported, how errors propagate, and how incremental processing avoids redundant work.

| Field | Value |
|-------|-------|
| **Parent** | [ARCHITECTURE_BLUEPRINT.md](../ARCHITECTURE_BLUEPRINT.md) |
| **Component** | `issen-pipeline` |
| **Version** | 0.1.0 |
| **Last Updated** | 2026-03-20 |
| **TARR Budget** | Parse-to-Timeline Latency < 10 minutes |

---

## 1. State Schema

### 1.1 Core State Definition

The pipeline state tracks the progress of a single evidence ingestion session. All state is owned by the `PipelineOrchestrator` and passed immutably to each layer.

```rust
// issen-pipeline/src/state.rs

use std::collections::HashSet;
use std::path::PathBuf;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Top-level state for a single ingestion session.
#[derive(Debug, Clone)]
pub struct PipelineState {
    // ---- Session identification ----
    pub session_id: Uuid,
    pub case_id: Uuid,

    // ---- Input ----
    pub evidence_sources: Vec<EvidenceSource>,

    // ---- Layer outputs (populated progressively) ----
    pub storage_handles: Vec<StorageHandle>,          // Layer 0 output
    pub image_readers: Vec<ImageReader>,              // Layer 1 output
    pub volume_map: Vec<VolumeDescriptor>,            // Layer 2 output
    pub filesystem_accessors: Vec<FilesystemMount>,   // Layer 3 output
    pub parse_results: Vec<ParseResult>,              // Layer 4 output

    // ---- Aggregated outputs ----
    pub timeline_event_count: u64,
    pub source_fingerprints: HashSet<SourceFingerprint>,

    // ---- Progress & metadata ----
    pub progress: PipelineProgress,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub errors: Vec<PipelineError>,
    pub warnings: Vec<PipelineWarning>,
}

/// A single evidence source to ingest.
#[derive(Debug, Clone)]
pub struct EvidenceSource {
    pub path: PathBuf,
    pub source_type: SourceType,          // E01, RawDd, KapeCollection, VelociraptorFlow, CloudLog
    pub label: String,                     // User-provided label (e.g., "laptop", "server-dc01")
    pub fingerprint: SourceFingerprint,    // Blake3 hash of metadata for dedup
}

/// Opaque fingerprint for incremental processing.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct SourceFingerprint(pub [u8; 32]);

/// Tracks per-layer and per-parser progress.
#[derive(Debug, Clone, Default)]
pub struct PipelineProgress {
    pub current_layer: u8,                 // 0-4
    pub current_phase: PipelinePhase,
    pub layers_completed: [bool; 5],
    pub parsers_total: usize,
    pub parsers_completed: usize,
    pub parsers_failed: usize,
    pub bytes_processed: u64,
    pub bytes_total: Option<u64>,          // None if unknown (streaming)
    pub events_emitted: u64,
}

#[derive(Debug, Clone, Default)]
pub enum PipelinePhase {
    #[default]
    Idle,
    StorageDiscovery,      // Layer 0
    ImageDecoding,         // Layer 1
    VolumeDetection,       // Layer 2
    FilesystemTraversal,   // Layer 3
    ArtifactParsing,       // Layer 4
    Finalizing,
    Complete,
    Failed,
}
```

### 1.2 Layer-Specific Schemas

Each pipeline layer produces typed output that feeds the next layer:

```rust
// Layer 0: Storage I/O
pub struct StorageHandle {
    pub source: EvidenceSource,
    pub provider: Box<dyn StorageProvider>,   // Trait object: read_at(offset, len) -> &[u8]
    pub size_bytes: Option<u64>,
}

// Layer 1: Image Format
pub struct ImageReader {
    pub format: ImageFormat,                  // E01, RawDd, Vmdk, Vhd, Aff4
    pub block_size: u32,
    pub total_blocks: u64,
    pub reader: Box<dyn BlockReader>,         // Trait object: read_block(idx) -> &[u8]
    pub verified: bool,                       // Hash verification passed
}

// Layer 2: Volume / Partition
pub struct VolumeDescriptor {
    pub scheme: PartitionScheme,              // Gpt, Mbr, Lvm, AppleMap, Dynamic
    pub partitions: Vec<Partition>,
}

pub struct Partition {
    pub index: u32,
    pub offset_bytes: u64,
    pub size_bytes: u64,
    pub fs_type_hint: Option<FilesystemType>,
    pub label: Option<String>,
}

// Layer 3: Filesystem
pub struct FilesystemMount {
    pub mount_point: String,                  // VFS path (e.g., "/disk/C:")
    pub fs_type: FilesystemType,              // Ntfs, Ext4, Apfs, Fat32, ExFat
    pub accessor: Box<dyn FilesystemAccessor>, // enumerate_files(), read_file(), stat()
    pub file_count: Option<u64>,
}

// Layer 4: Artifact Parsing
pub struct ParseResult {
    pub parser_name: String,
    pub artifact_path: String,
    pub events_emitted: u64,
    pub duration: std::time::Duration,
    pub status: ParseStatus,                  // Success, PartialSuccess, Failed, Skipped
    pub errors: Vec<String>,
}

pub enum ParseStatus {
    Success,
    PartialSuccess { records_ok: u64, records_failed: u64 },
    Failed(String),
    Skipped(String),  // e.g., "Artifact not present in this evidence"
}
```

---

## 2. Pipeline Orchestrator

### 2.1 Orchestrator Interface

```rust
// issen-pipeline/src/orchestrator.rs

/// Configuration for a pipeline run.
pub struct PipelineConfig {
    /// Overall timeout for the entire pipeline (default: 10 minutes per TARR budget).
    pub total_timeout: Duration,

    /// Per-layer timeouts.
    pub layer_timeouts: [Duration; 5],

    /// Per-parser timeout (default: 60s).
    pub parser_timeout: Duration,

    /// Maximum rayon parallelism for Layer 4 parsing.
    /// Defaults to num_cpus::get() - 1 to leave headroom.
    pub max_parser_parallelism: usize,

    /// Enable incremental mode: skip sources already fingerprinted.
    pub incremental: bool,

    /// Continue on parser failure (default: true).
    /// If false, a single parser failure aborts the pipeline.
    pub continue_on_error: bool,

    /// Progress callback interval.
    pub progress_interval: Duration,
}

/// Result of a complete pipeline run.
pub struct PipelineResult {
    pub state: PipelineState,
    pub success: bool,
    pub execution_time: Duration,
    pub layer_timings: [Duration; 5],
    pub parser_results: Vec<ParseResult>,
    pub fingerprint: SourceFingerprint,       // Composite fingerprint of all sources
}
```

### 2.2 Orchestrator Implementation

The pipeline is **strictly sequential across layers** (Layer 0 must complete before Layer 1 begins) but **massively parallel within Layer 4** (artifact parsers run concurrently via rayon). This matches forensic data dependencies: you cannot parse NTFS artifacts until you have mounted the NTFS filesystem, but once mounted, all artifact parsers are independent.

```rust
// issen-pipeline/src/orchestrator.rs

use rayon::prelude::*;
use tokio::sync::watch;
use std::sync::Arc;

pub struct PipelineOrchestrator {
    config: PipelineConfig,
    parser_registry: Arc<ParserRegistry>,
    progress_tx: watch::Sender<PipelineProgress>,
}

impl PipelineOrchestrator {
    pub fn new(
        config: PipelineConfig,
        parser_registry: Arc<ParserRegistry>,
    ) -> (Self, watch::Receiver<PipelineProgress>) {
        let (progress_tx, progress_rx) = watch::channel(PipelineProgress::default());
        (
            Self { config, parser_registry, progress_tx },
            progress_rx,
        )
    }

    /// Execute the full pipeline. Sequential across layers, parallel within Layer 4.
    pub async fn execute(
        &self,
        sources: Vec<EvidenceSource>,
        timeline: &dyn TimelineSink,
    ) -> Result<PipelineResult, PipelineError> {
        let deadline = Instant::now() + self.config.total_timeout;
        let mut state = PipelineState::new(sources);

        // ---- Layer 0: Storage Discovery ----
        self.update_phase(PipelinePhase::StorageDiscovery);
        state.storage_handles = self.execute_layer_0(&state.evidence_sources, deadline).await?;

        // ---- Incremental check ----
        if self.config.incremental {
            state.evidence_sources.retain(|src| {
                !timeline.is_source_processed(&src.fingerprint)
            });
            if state.evidence_sources.is_empty() {
                return Ok(PipelineResult::already_processed(state));
            }
        }

        // ---- Layer 1: Image Format Decoding ----
        self.update_phase(PipelinePhase::ImageDecoding);
        state.image_readers = self.execute_layer_1(&state.storage_handles, deadline).await?;

        // ---- Layer 2: Volume / Partition Detection ----
        self.update_phase(PipelinePhase::VolumeDetection);
        state.volume_map = self.execute_layer_2(&state.image_readers, deadline).await?;

        // ---- Layer 3: Filesystem Mounting ----
        self.update_phase(PipelinePhase::FilesystemTraversal);
        let vfs = self.execute_layer_3(&state.volume_map, deadline).await?;

        // ---- Layer 4: Artifact Parsing (parallel via rayon) ----
        self.update_phase(PipelinePhase::ArtifactParsing);
        state.parse_results = self.execute_layer_4_parallel(&vfs, timeline, deadline)?;

        // ---- Finalize ----
        self.update_phase(PipelinePhase::Finalizing);
        state.completed_at = Some(Utc::now());
        state.timeline_event_count = state.parse_results.iter()
            .map(|r| r.events_emitted)
            .sum();

        self.update_phase(PipelinePhase::Complete);
        Ok(PipelineResult::from(state))
    }
}
```

---

## 3. Execution Patterns

### 3.1 Parallel Execution: Layer 4 Artifact Parsing

Layer 4 is the most computationally expensive phase. Issen uses **rayon's work-stealing thread pool** for data parallelism across parsers.

```rust
impl PipelineOrchestrator {
    /// Discover artifacts on the VFS, match to registered parsers, and run in parallel.
    fn execute_layer_4_parallel(
        &self,
        vfs: &VirtualFilesystem,
        timeline: &dyn TimelineSink,
        deadline: Instant,
    ) -> Result<Vec<ParseResult>, PipelineError> {
        // Step 1: Discover all parseable artifacts
        let artifacts: Vec<ArtifactMatch> = self.parser_registry
            .discover_artifacts(vfs)?;

        let total = artifacts.len();
        self.update_progress(|p| {
            p.parsers_total = total;
            p.parsers_completed = 0;
        });

        // Step 2: Execute parsers in parallel via rayon
        let completed = AtomicUsize::new(0);
        let failed = AtomicUsize::new(0);

        let results: Vec<ParseResult> = artifacts
            .into_par_iter()
            .map(|artifact_match| {
                // Per-parser timeout guard
                let result = std::panic::catch_unwind(|| {
                    self.run_single_parser(
                        &artifact_match,
                        vfs,
                        timeline,
                        self.config.parser_timeout,
                    )
                });

                let parse_result = match result {
                    Ok(Ok(r)) => r,
                    Ok(Err(e)) => ParseResult::failed(
                        &artifact_match.parser_name,
                        &artifact_match.artifact_path,
                        format!("Parser error: {e}"),
                    ),
                    Err(_panic) => ParseResult::failed(
                        &artifact_match.parser_name,
                        &artifact_match.artifact_path,
                        "Parser panicked (caught)".to_string(),
                    ),
                };

                // Update progress atomically
                if parse_result.status.is_success() {
                    completed.fetch_add(1, Ordering::Relaxed);
                } else {
                    failed.fetch_add(1, Ordering::Relaxed);
                }

                parse_result
            })
            .collect();

        Ok(results)
    }

    /// Run a single parser with timeout and streaming event emission.
    fn run_single_parser(
        &self,
        artifact_match: &ArtifactMatch,
        vfs: &VirtualFilesystem,
        timeline: &dyn TimelineSink,
        timeout: Duration,
    ) -> Result<ParseResult, PipelineError> {
        let parser = self.parser_registry.get(&artifact_match.parser_name)?;
        let reader = vfs.open(&artifact_match.artifact_path)?;

        // Streaming: parser emits events via callback, never buffers full artifact
        let emitter = StreamingEventEmitter::new(timeline, &artifact_match);
        let start = Instant::now();

        // Timeout wrapper
        let status = match run_with_timeout(timeout, || parser.parse(reader, &emitter)) {
            Ok(Ok(())) => ParseStatus::Success,
            Ok(Err(e)) => {
                let ok = emitter.events_emitted();
                if ok > 0 {
                    ParseStatus::PartialSuccess {
                        records_ok: ok,
                        records_failed: e.record_count(),
                    }
                } else {
                    ParseStatus::Failed(e.to_string())
                }
            }
            Err(_timeout) => ParseStatus::Failed(format!(
                "Parser timed out after {}s", timeout.as_secs()
            )),
        };

        Ok(ParseResult {
            parser_name: artifact_match.parser_name.clone(),
            artifact_path: artifact_match.artifact_path.clone(),
            events_emitted: emitter.events_emitted(),
            duration: start.elapsed(),
            status,
            errors: emitter.drain_errors(),
        })
    }
}
```

### 3.2 Sequential Execution: Layers 0-3

Layers 0 through 3 execute strictly sequentially because each layer depends on the output of the previous layer. However, **within** each layer, multiple evidence sources can be processed in parallel.

```rust
impl PipelineOrchestrator {
    /// Layer 0: Open storage providers for each evidence source.
    async fn execute_layer_0(
        &self,
        sources: &[EvidenceSource],
        deadline: Instant,
    ) -> Result<Vec<StorageHandle>, PipelineError> {
        let mut handles = Vec::with_capacity(sources.len());

        for source in sources {
            let remaining = deadline.duration_since(Instant::now());
            let handle = tokio::time::timeout(remaining, async {
                match source.source_type {
                    SourceType::E01 => EwfStorage::open(&source.path).await,
                    SourceType::RawDd => RawStorage::open(&source.path).await,
                    SourceType::KapeCollection => DirectoryStorage::open(&source.path).await,
                    SourceType::VelociraptorFlow => ZipStorage::open(&source.path).await,
                    SourceType::CloudLog => CloudLogStorage::open(&source.path).await,
                }
            }).await
            .map_err(|_| PipelineError::Timeout { layer: 0 })?
            .map_err(|e| PipelineError::StorageOpen {
                source: source.path.clone(),
                cause: e,
            })?;

            handles.push(handle);
        }

        Ok(handles)
    }

    /// Layer 1: Detect and initialize image format readers.
    async fn execute_layer_1(
        &self,
        handles: &[StorageHandle],
        deadline: Instant,
    ) -> Result<Vec<ImageReader>, PipelineError> {
        let mut readers = Vec::new();

        for handle in handles {
            // KAPE / Velociraptor / cloud logs skip Layer 1 (no disk image)
            if handle.source.source_type.is_raw_collection() {
                continue;
            }

            let reader = ImageFormatDetector::detect_and_open(&handle.provider).await?;
            readers.push(reader);
        }

        Ok(readers)
    }

    // Layer 2 and Layer 3 follow the same sequential-with-per-source pattern.
}
```

### 3.3 Conditional Execution: Layer Skipping

Not all evidence sources traverse all five layers. KAPE collections and Velociraptor flows are already extracted file trees -- they enter at Layer 3 (filesystem) or even Layer 4 (artifact parsing) directly.

```rust
/// Determines which layers an evidence source traverses.
pub fn layer_entry_point(source_type: SourceType) -> u8 {
    match source_type {
        SourceType::E01 | SourceType::RawDd | SourceType::Vmdk | SourceType::Vhd => 0,
        SourceType::KapeCollection | SourceType::VelociraptorFlow => 3,
        SourceType::CloudLog => 4,
    }
}
```

The orchestrator routes each evidence source to its entry layer:

```rust
// In PipelineOrchestrator::execute():
// Sources are partitioned by entry layer, then processed appropriately.
let (disk_images, collections, cloud_logs) = partition_by_entry_layer(&sources);

// Disk images: Layer 0 -> 1 -> 2 -> 3 -> 4
// Collections: Layer 3 -> 4 (skip storage/image/volume)
// Cloud logs: Layer 4 only (already structured events)
```

---

## 4. Self-Correction Patterns

### 4.1 Forensic Integrity Gate

Unlike typical software pipelines where retry-on-failure is appropriate, forensic pipelines must be **deterministic**. Retrying a parser on the same corrupted data will produce the same result. Instead, Issen uses a **degradation-with-audit** pattern.

```rust
/// Quality gate that validates parser output without retry.
/// Forensic data is immutable -- retrying produces identical results.
pub struct ForensicIntegrityGate;

impl ForensicIntegrityGate {
    /// Evaluate a parse result and decide how to proceed.
    pub fn evaluate(&self, result: &ParseResult) -> GateDecision {
        match &result.status {
            ParseStatus::Success => GateDecision::Accept,

            ParseStatus::PartialSuccess { records_ok, records_failed } => {
                let failure_rate = *records_failed as f64
                    / (*records_ok + *records_failed) as f64;

                if failure_rate > 0.5 {
                    // >50% failure: flag for examiner review, but keep partial results
                    GateDecision::AcceptWithWarning(format!(
                        "High failure rate ({:.0}%) for {} -- partial results included. \
                         Examiner should verify artifact integrity.",
                        failure_rate * 100.0, result.parser_name,
                    ))
                } else {
                    // Minor corruption: accept and note
                    GateDecision::Accept
                }
            }

            ParseStatus::Failed(reason) => {
                // Never discard silently. Log the failure so it appears in the report.
                GateDecision::RecordFailure(format!(
                    "Parser '{}' failed on '{}': {}. \
                     This artifact is excluded from the timeline.",
                    result.parser_name, result.artifact_path, reason,
                ))
            }

            ParseStatus::Skipped(reason) => GateDecision::Accept,
        }
    }
}

pub enum GateDecision {
    Accept,
    AcceptWithWarning(String),
    RecordFailure(String),
}
```

**Why no retries?** Axiom: *Correctness > Speed*. Forensic evidence is immutable. If a parser fails on byte sequence X, it will fail again on the same byte sequence. The only correct action is to document the failure, include partial results, and alert the examiner. This differs from the template's generic retry pattern because forensic data has no non-determinism to retry around.

### 4.2 Hash Verification Gate

For E01/EWF images, Layer 1 can verify segment hashes against the embedded hash table. This is a **pre-parsing integrity check**.

```rust
/// Verify E01 image integrity before proceeding to Layer 2.
pub struct HashVerificationGate;

impl HashVerificationGate {
    pub fn verify(&self, reader: &ImageReader) -> Result<(), PipelineError> {
        if reader.format != ImageFormat::E01 {
            return Ok(()); // Only E01 has embedded hashes
        }

        match reader.verify_hashes() {
            Ok(true) => Ok(()),
            Ok(false) => Err(PipelineError::IntegrityFailure {
                source: reader.source_path().to_owned(),
                detail: "E01 hash verification failed -- evidence may be tampered or corrupted. \
                         Pipeline will continue but findings should be treated with caution."
                    .to_string(),
            }),
            Err(e) => {
                // Hash verification itself failed (e.g., missing hash table)
                // Log warning but continue -- some E01 tools omit hashes
                tracing::warn!(
                    "Could not verify E01 hashes for {}: {}. Proceeding without verification.",
                    reader.source_path().display(), e,
                );
                Ok(())
            }
        }
    }
}
```

---

## 5. Performance Optimization

### 5.1 Timeout Management

Timeouts are structured hierarchically to ensure the pipeline fits within the TARR budget.

| Component | Timeout | Rationale |
|-----------|---------|-----------|
| **Pipeline Total** | 600s (10 min) | Parse-to-Timeline TARR budget |
| **Layer 0: Storage** | 30s | Opening files/images is fast; slow = I/O problem |
| **Layer 1: Image Format** | 60s | EWF decompression index build; large images take longer |
| **Layer 2: Volume** | 15s | Partition table parsing is trivial |
| **Layer 3: Filesystem** | 120s | NTFS MFT parsing on large volumes |
| **Layer 4: Parsing (total)** | 360s | Bulk of time; parallelism amortizes across parsers |
| **Per-parser** | 60s | No single parser should dominate |

```rust
impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            total_timeout: Duration::from_secs(600),
            layer_timeouts: [
                Duration::from_secs(30),   // Layer 0
                Duration::from_secs(60),   // Layer 1
                Duration::from_secs(15),   // Layer 2
                Duration::from_secs(120),  // Layer 3
                Duration::from_secs(360),  // Layer 4
            ],
            parser_timeout: Duration::from_secs(60),
            max_parser_parallelism: num_cpus::get().saturating_sub(1).max(1),
            incremental: true,
            continue_on_error: true,
            progress_interval: Duration::from_millis(500),
        }
    }
}
```

### 5.2 Memory-Mapped I/O and Streaming

Issen **never loads entire evidence into memory**. This is non-negotiable for terabyte-scale evidence.

```rust
/// StorageProvider uses memory-mapped I/O for local files.
pub struct MmapStorageProvider {
    mmap: memmap2::Mmap,
    size: u64,
}

impl StorageProvider for MmapStorageProvider {
    fn read_at(&self, offset: u64, len: usize) -> &[u8] {
        &self.mmap[offset as usize..offset as usize + len]
    }

    fn size(&self) -> u64 {
        self.size
    }
}

/// Parsers use streaming iteration, never buffering full artifacts.
pub trait ForensicParser: Send + Sync {
    fn name(&self) -> &str;

    /// Parse artifact data from the reader, emitting events via the emitter.
    /// The parser MUST NOT buffer all records -- it streams them.
    fn parse(
        &self,
        reader: Box<dyn Read + Send>,
        emitter: &dyn EventEmitter,
    ) -> Result<(), ParseError>;

    /// Artifact file patterns this parser handles (e.g., "$MFT", "*.evtx").
    fn artifact_patterns(&self) -> &[&str];
}
```

### 5.3 Early Exit on Critical Failure

Certain failures should terminate the pipeline immediately rather than burning through the timeout budget.

```rust
/// Failures that warrant immediate pipeline termination.
pub fn is_critical_failure(error: &PipelineError) -> bool {
    matches!(error,
        // Cannot read evidence at all
        PipelineError::StorageOpen { .. } |
        // No partitions found (evidence is likely not a disk image)
        PipelineError::NoVolumesDetected { .. } |
        // DuckDB timeline sink is broken
        PipelineError::TimelineSinkError { .. }
    )
}
```

### 5.4 Rayon Thread Pool Configuration

The pipeline uses a **dedicated rayon thread pool** separate from the global pool, to avoid contention with other async tasks (e.g., progress reporting, TUI rendering).

```rust
/// Create a dedicated thread pool for Layer 4 parsing.
pub fn build_parser_pool(config: &PipelineConfig) -> rayon::ThreadPool {
    rayon::ThreadPoolBuilder::new()
        .num_threads(config.max_parser_parallelism)
        .thread_name(|idx| format!("issen-parser-{idx}"))
        .stack_size(4 * 1024 * 1024) // 4 MiB stack for deep parser recursion
        .build()
        .expect("Failed to build parser thread pool")
}
```

---

## 6. Progress Reporting

### 6.1 Progress Channel Architecture

Progress is reported via a `tokio::sync::watch` channel. The orchestrator updates progress atomically; frontends (CLI, TUI, GUI) subscribe to the receiver and render at their own cadence.

```rust
/// Progress update flow:
///
///   PipelineOrchestrator (producer)
///         |
///         v
///   watch::Sender<PipelineProgress>
///         |
///     +---+---+---+
///     |   |   |   |
///     v   v   v   v
///   CLI  TUI  GUI  Web
///   (subscribers render independently)

impl PipelineOrchestrator {
    fn update_progress<F: FnOnce(&mut PipelineProgress)>(&self, f: F) {
        self.progress_tx.send_modify(f);
    }

    fn update_phase(&self, phase: PipelinePhase) {
        self.update_progress(|p| p.current_phase = phase);
    }
}
```

### 6.2 Frontend Rendering Examples

```rust
// CLI: Simple progress bar via indicatif
async fn render_cli_progress(mut rx: watch::Receiver<PipelineProgress>) {
    let pb = indicatif::ProgressBar::new(0);
    pb.set_style(indicatif::ProgressStyle::default_bar()
        .template("{spinner} [{bar:40}] {pos}/{len} parsers | {msg}")
        .unwrap());

    while rx.changed().await.is_ok() {
        let p = rx.borrow();
        pb.set_length(p.parsers_total as u64);
        pb.set_position(p.parsers_completed as u64);
        pb.set_message(format!("Layer {} -- {:?}", p.current_layer, p.current_phase));
    }
    pb.finish_with_message("Pipeline complete");
}

// TUI: ratatui widget reads from the same channel
// GUI: Tauri event bridge forwards watch updates to the frontend
```

---

## 7. Incremental Processing

### 7.1 Source Fingerprinting

Each evidence source gets a `SourceFingerprint` computed from its metadata (not content hash -- that would require reading the entire file).

```rust
impl SourceFingerprint {
    /// Compute fingerprint from file metadata.
    /// Uses Blake3 over: canonical path + file size + modification time.
    /// This is fast (no content read) and sufficient for change detection.
    pub fn compute(path: &Path) -> Result<Self, std::io::Error> {
        let metadata = std::fs::metadata(path)?;
        let canonical = std::fs::canonicalize(path)?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(canonical.to_string_lossy().as_bytes());
        hasher.update(&metadata.len().to_le_bytes());
        hasher.update(
            &metadata.modified()?
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .to_le_bytes(),
        );

        Ok(Self(*hasher.finalize().as_bytes()))
    }
}
```

### 7.2 Deduplication Flow

```
rt ingest --source laptop.E01 --source ./kape/
         |
         v
  Compute fingerprints for each source
         |
         v
  Query timeline: "Which fingerprints already exist?"
         |
         +---> Already processed --> Skip (return IngestStats::already_processed)
         |
         +---> New source --> Execute full pipeline (Layer 0-4)
         |
         v
  On success, record fingerprint in timeline metadata
```

```rust
impl dyn TimelineSink {
    /// Check if a source has already been ingested.
    fn is_source_processed(&self, fingerprint: &SourceFingerprint) -> bool;

    /// Record a source as successfully processed.
    fn mark_source_processed(&self, fingerprint: &SourceFingerprint, stats: &IngestStats);
}
```

---

## 8. Error Taxonomy

### 8.1 Error Types

Errors are categorized by severity and recoverability to guide the orchestrator's behavior.

```rust
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    // ---- Critical (pipeline halts) ----
    #[error("Cannot open evidence at {source}: {cause}")]
    StorageOpen { source: PathBuf, cause: std::io::Error },

    #[error("No volumes detected in {source} -- is this a disk image?")]
    NoVolumesDetected { source: PathBuf },

    #[error("Timeline sink error: {0}")]
    TimelineSinkError(String),

    #[error("Pipeline timeout at Layer {layer}")]
    Timeout { layer: u8 },

    // ---- Degraded (pipeline continues) ----
    #[error("Parser '{parser}' failed on '{artifact}': {cause}")]
    ParserFailed { parser: String, artifact: String, cause: String },

    #[error("Filesystem mount failed for partition {partition}: {cause}")]
    FilesystemMountFailed { partition: String, cause: String },

    #[error("E01 integrity check failed for {source}: {detail}")]
    IntegrityFailure { source: PathBuf, detail: String },

    // ---- Informational (logged, no action) ----
    #[error("Artifact not found: {path}")]
    ArtifactNotFound { path: String },

    #[error("Parser '{parser}' skipped: {reason}")]
    ParserSkipped { parser: String, reason: String },
}

impl PipelineError {
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            Self::StorageOpen { .. }
            | Self::NoVolumesDetected { .. }
            | Self::TimelineSinkError(_)
            | Self::Timeout { .. } => ErrorSeverity::Critical,

            Self::ParserFailed { .. }
            | Self::FilesystemMountFailed { .. }
            | Self::IntegrityFailure { .. } => ErrorSeverity::Degraded,

            Self::ArtifactNotFound { .. }
            | Self::ParserSkipped { .. } => ErrorSeverity::Informational,
        }
    }
}

pub enum ErrorSeverity {
    Critical,       // Pipeline halts immediately
    Degraded,       // Pipeline continues, failure recorded
    Informational,  // Logged only
}
```

### 8.2 Error Propagation Strategy

```
Parser Error
    |
    v
catch_unwind (catch panics)
    |
    v
ForensicIntegrityGate::evaluate()
    |
    +---> Accept --> continue
    |
    +---> AcceptWithWarning --> add to state.warnings, continue
    |
    +---> RecordFailure --> add to state.errors, continue (if continue_on_error)
                        --> halt (if !continue_on_error)

Layer Error
    |
    v
is_critical_failure()?
    |
    +---> true  --> return Err immediately
    +---> false --> add to state.errors, try next source
```

---

## 9. Integration Example

End-to-end example showing the full pipeline for Sarah Chen's typical workflow: ingesting a laptop E01 image alongside a KAPE triage collection.

```rust
use rt_pipeline::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Configure pipeline
    let config = PipelineConfig {
        incremental: true,
        continue_on_error: true,
        ..Default::default()
    };

    // 2. Register Tier 1 parsers
    let registry = ParserRegistry::new()
        .register(MftParser::new())
        .register(UsnJournalParser::new())
        .register(EventLogParser::new())
        .register(PrefetchParser::new())
        .register(RegistryParser::new())
        .register(AmcacheParser::new())
        .register(LnkParser::new())
        .register(JumplistParser::new())
        .register(BamParser::new())
        .register(SrumParser::new())
        .register(BrowserHistoryParser::new());

    // 3. Open timeline store
    let timeline = DuckDbTimeline::open_or_create("./cases/2024-IR-0042/timeline.duckdb")?;

    // 4. Define evidence sources
    let sources = vec![
        EvidenceSource::new("./evidence/laptop.E01", SourceType::E01, "laptop"),
        EvidenceSource::new("./evidence/kape-output/", SourceType::KapeCollection, "kape-triage"),
    ];

    // 5. Execute pipeline with progress reporting
    let (orchestrator, progress_rx) = PipelineOrchestrator::new(
        config,
        Arc::new(registry),
    );

    // Spawn progress reporter
    let progress_handle = tokio::spawn(render_cli_progress(progress_rx));

    // Run pipeline
    let result = orchestrator.execute(sources, &timeline).await?;

    progress_handle.await?;

    // 6. Report results
    println!("Pipeline complete in {:.1}s", result.execution_time.as_secs_f64());
    println!("  Events: {}", result.state.timeline_event_count);
    println!("  Parsers: {} ok, {} failed",
        result.parser_results.iter().filter(|r| r.status.is_success()).count(),
        result.parser_results.iter().filter(|r| !r.status.is_success()).count(),
    );

    for warning in &result.state.warnings {
        eprintln!("  WARNING: {}", warning);
    }
    for error in &result.state.errors {
        eprintln!("  ERROR: {}", error);
    }

    Ok(())
}
```

---

## Cross-Reference Index

| Reference | Source | Value |
|-----------|--------|-------|
| Product Name | Brand Guidelines | Issen |
| North Star Metric | NORTHSTAR.md | Time-to-Attorney-Ready Report (TARR) |
| TARR Target | NORTHSTAR.md | < 4 hours |
| Parse-to-Timeline Budget | NORTHSTAR.md | < 10 minutes |
| Architecture Pattern | ARCHITECTURE_BLUEPRINT.md | Hexagonal (Crux-inspired) |
| Pipeline Component | ARCHITECTURE_BLUEPRINT.md | issen-pipeline |
| Timeline Store | ARCHITECTURE_BLUEPRINT.md | DuckDB (TIMESTAMP_NS) |
| Parallelism | ARCHITECTURE_BLUEPRINT.md | rayon (work-stealing) |
| Plugin Tiers | ARCHITECTURE_BLUEPRINT.md | Tier 1 (compile) / Tier 2 (WASM) / Tier 3 (gRPC) |
| Primary Persona | NORTHSTAR.md | Sarah Chen, Solo IR Practitioner |
| Correctness Axiom | North Star Extract | Correctness > Speed |
| Report Axiom | North Star Extract | Report is the Product |
