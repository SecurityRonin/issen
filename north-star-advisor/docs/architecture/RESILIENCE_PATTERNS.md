# Issen: Resilience Patterns

> **Axiom**: *Correctness > Speed* -- When parsing speed conflicts with forensic accuracy, choose accuracy. Rust lets us have both, but when forced to pick, correctness wins.
>
> **Axiom**: *Report is the Product* -- The report is the deliverable, not a byproduct. Every pipeline stage is measured by its contribution to TARR.

**Cross-references**: [Architecture Blueprint](../ARCHITECTURE_BLUEPRINT.md) | [North Star](../NORTHSTAR.md) | [Brand Guidelines](../BRAND_GUIDELINES.md)

---

## 1. Circuit Breaker Pattern

Forensic evidence is inherently unreliable -- corrupted disk images, truncated logs, partially overwritten artifacts. Every component in the Issen pipeline must tolerate upstream failures without cascading collapse. Circuit breakers prevent a single corrupted evidence source from consuming all resources and blocking the entire pipeline.

### 1.1 Circuit Breaker Configuration

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Failure Threshold | 5 consecutive failures | Allows transient corruption without triggering; catches systemic parser issues |
| Success Threshold | 3 successes | Confirms recovery is stable before restoring full throughput |
| Half-Open Max Requests | 2 | Probe corrupted source cautiously without committing resources |
| Reset Timeout | 30 seconds | Fast enough for interactive use; slow enough for disk I/O recovery |
| Monitoring Window | 60 seconds | Sliding window for failure rate calculation |
| Failure Rate Threshold | 50% | Opens circuit when half of recent operations fail |

### 1.2 Per-Component Circuit Breaker Configuration

| Component | Failure Threshold | Reset Timeout | Rationale |
|-----------|-------------------|---------------|-----------|
| `issen-pipeline` (Layer 0: Container) | 3 failures | 10s | E01/VHDX container errors are usually fatal for that image; fail fast |
| `issen-pipeline` (Layer 1: Filesystem) | 5 failures | 30s | NTFS/ext4 corruption may be localized; allow more attempts |
| `issen-pipeline` (Layer 2: Artifact) | 5 failures | 30s | Individual artifact files may be corrupted but siblings are fine |
| `issen-pipeline` (Layer 3: Parser) | 10 failures | 60s | Parsers process many records; high threshold for per-record failures |
| `issen-pipeline` (Layer 4: Enrichment) | 3 failures | 15s | LLM/enrichment failures should degrade gracefully, not block |
| `issen-timeline` (DuckDB) | 3 failures | 10s | Database errors are usually systemic; fast circuit break |
| `issen-intel` (ForensicLLM) | 3 failures | 60s | Model inference failures may need cooldown; longer reset |
| `issen-report` (Report Engine) | 3 failures | 15s | Report generation failures should not retry aggressively |
| `issen-correlation` | 5 failures | 30s | Correlation operates on partial data; tolerate some failures |
| WASM Plugin (Tier 2) | 3 failures | 30s | Sandboxed plugin failures are isolated; moderate reset |
| gRPC Plugin (Tier 3) | 3 failures | 45s | External process may need restart time |

### 1.3 Implementation

```rust
// src/resilience/circuit_breaker.rs

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CircuitState {
    Closed,   // Normal operation -- requests flow through
    Open,     // Failures exceeded threshold -- requests rejected immediately
    HalfOpen, // Probing -- limited requests allowed to test recovery
}

pub struct CircuitBreaker {
    state: Mutex<CircuitState>,
    failure_count: AtomicU64,
    success_count: AtomicU64,
    failure_threshold: u64,
    success_threshold: u64,
    half_open_max: u64,
    half_open_active: AtomicU64,
    reset_timeout: Duration,
    last_failure_time: Mutex<Option<Instant>>,
    /// Component identifier for diagnostics and health reporting
    component_id: String,
}

impl CircuitBreaker {
    pub fn new(component_id: &str, failure_threshold: u64, success_threshold: u64, reset_timeout: Duration) -> Self {
        Self {
            state: Mutex::new(CircuitState::Closed),
            failure_count: AtomicU64::new(0),
            success_count: AtomicU64::new(0),
            failure_threshold,
            success_threshold,
            half_open_max: 2,
            half_open_active: AtomicU64::new(0),
            reset_timeout,
            last_failure_time: Mutex::new(None),
            component_id: component_id.to_string(),
        }
    }

    /// Check if a request is allowed through the circuit.
    /// Returns Ok(()) if allowed, Err(CircuitOpenError) if blocked.
    pub fn check(&self) -> Result<CircuitGuard, CircuitOpenError> {
        let mut state = self.state.lock().unwrap();
        match *state {
            CircuitState::Closed => Ok(CircuitGuard::new(self)),
            CircuitState::Open => {
                // Check if reset timeout has elapsed
                if let Some(last_failure) = *self.last_failure_time.lock().unwrap() {
                    if last_failure.elapsed() >= self.reset_timeout {
                        *state = CircuitState::HalfOpen;
                        self.half_open_active.store(0, Ordering::SeqCst);
                        tracing::info!(
                            component = %self.component_id,
                            "Circuit breaker transitioning to half-open"
                        );
                        Ok(CircuitGuard::new(self))
                    } else {
                        Err(CircuitOpenError {
                            component: self.component_id.clone(),
                            retry_after: self.reset_timeout - last_failure.elapsed(),
                        })
                    }
                } else {
                    Err(CircuitOpenError {
                        component: self.component_id.clone(),
                        retry_after: self.reset_timeout,
                    })
                }
            }
            CircuitState::HalfOpen => {
                let active = self.half_open_active.fetch_add(1, Ordering::SeqCst);
                if active < self.half_open_max {
                    Ok(CircuitGuard::new(self))
                } else {
                    self.half_open_active.fetch_sub(1, Ordering::SeqCst);
                    Err(CircuitOpenError {
                        component: self.component_id.clone(),
                        retry_after: Duration::from_secs(1),
                    })
                }
            }
        }
    }

    /// Record a successful operation -- may close circuit from half-open.
    pub fn record_success(&self) {
        self.success_count.fetch_add(1, Ordering::SeqCst);
        self.failure_count.store(0, Ordering::SeqCst);

        let mut state = self.state.lock().unwrap();
        if *state == CircuitState::HalfOpen {
            if self.success_count.load(Ordering::SeqCst) >= self.success_threshold {
                *state = CircuitState::Closed;
                tracing::info!(
                    component = %self.component_id,
                    "Circuit breaker closed -- component recovered"
                );
            }
        }
    }

    /// Record a failed operation -- may open circuit from closed.
    pub fn record_failure(&self) {
        self.failure_count.fetch_add(1, Ordering::SeqCst);
        self.success_count.store(0, Ordering::SeqCst);
        *self.last_failure_time.lock().unwrap() = Some(Instant::now());

        let mut state = self.state.lock().unwrap();
        match *state {
            CircuitState::Closed => {
                if self.failure_count.load(Ordering::SeqCst) >= self.failure_threshold {
                    *state = CircuitState::Open;
                    tracing::warn!(
                        component = %self.component_id,
                        threshold = self.failure_threshold,
                        "Circuit breaker OPEN -- failures exceeded threshold"
                    );
                }
            }
            CircuitState::HalfOpen => {
                *state = CircuitState::Open;
                tracing::warn!(
                    component = %self.component_id,
                    "Circuit breaker re-opened -- half-open probe failed"
                );
            }
            _ => {}
        }
    }

    pub fn get_state(&self) -> CircuitState {
        *self.state.lock().unwrap()
    }
}
```

**Forensic-specific design decisions:**
- **Per-layer circuit breakers** in `issen-pipeline` rather than per-component, because a single corrupted NTFS volume should not shut down parsing of registry hives or event logs from the same image.
- **High threshold for Layer 3 (Parser)** because parsers process thousands of records and individual record corruption is common -- only systemic parser failure should trip the circuit.
- **Fast reset for Layer 0 (Container)** because container-level failures (bad E01 segment, truncated VHDX) are almost always unrecoverable, so quick detection prevents wasted time.

---

## 2. Fallback Chains

Issen follows the axiom *"the tool must NEVER lose already-parsed data if a later parser crashes."* Fallback chains ensure every component degrades to a safe state that preserves work completed so far. In a forensic context, partial results with integrity metadata are infinitely more valuable than no results.

### 2.1 Fallback Strategy

```
Primary Operation -> Simplified Operation -> Cached/Partial Results -> Safe Default with Metadata
```

Every fallback chain ends in a **safe default** that:
1. Preserves all previously parsed data intact
2. Records what failed and why (for the examiner's notes)
3. Marks the gap in coverage so the report flags it explicitly
4. Never silently drops evidence -- missing data is always surfaced

### 2.2 Per-Component Fallback Configuration

| Component | Level 1 (Primary) | Level 2 (Simplified) | Level 3 (Cached/Partial) | Level 4 (Safe Default) |
|-----------|-------------------|----------------------|--------------------------|------------------------|
| `issen-pipeline` Layer 0 | Parse container (E01/VHDX/raw) | Try alternate parser/raw fallback | Return metadata-only (image hash, size) | Log "container unreadable" + preserve hash |
| `issen-pipeline` Layer 1 | Full filesystem walk | Targeted path extraction (known artifact locations) | File listing from MFT-only parse | Log "filesystem damaged" + raw byte offsets |
| `issen-pipeline` Layer 2 | Extract artifact file | Copy raw bytes without interpretation | Return file metadata (path, timestamps, hash) | Log "artifact inaccessible" + record location |
| `issen-pipeline` Layer 3 | Full parser (structured output) | Lenient parser (skip malformed records) | Raw text extraction (strings) | Log "parser failed" + preserve raw bytes |
| `issen-pipeline` Layer 4 | LLM enrichment (ForensicLLM) | Smaller model (7B classification) | Rule-based enrichment (YARA/Sigma only) | Pass through unenriched with flag |
| `issen-timeline` | DuckDB columnar insert | Batch insert with conflict resolution | Append to overflow log (CSV fallback) | In-memory buffer with periodic flush attempt |
| `issen-intel` | Large model narrative (70B+) | Small model summary (7B-13B) | Template-based output | Raw findings list (no narrative) |
| `issen-report` | Full dual-format (HTML + DOCX) | HTML-only report | Markdown export | Structured JSON dump of all findings |
| `issen-correlation` | Full cross-artifact correlation | Pairwise correlation (reduced scope) | Timestamp-only correlation | Individual artifact timelines (no cross-ref) |
| WASM Plugin (Tier 2) | Execute in sandbox | Execute with tighter resource limits | Return plugin metadata + error | Skip plugin, log gap in coverage |
| gRPC Plugin (Tier 3) | Call external process | Retry with timeout backoff | Return cached result if available | Skip plugin, log gap in coverage |

### 2.3 Fallback Implementation

```rust
// src/resilience/fallback.rs

use std::future::Future;
use std::pin::Pin;

/// A fallback level with a label for diagnostics and audit trail.
pub struct FallbackLevel<T> {
    pub label: &'static str,
    pub execute: Box<dyn Fn() -> Pin<Box<dyn Future<Output = Result<T, FallbackError>> + Send>> + Send + Sync>,
}

/// Execute a chain of fallbacks, returning the first success.
/// Records which level was used for the forensic audit trail.
pub async fn execute_fallback_chain<T>(
    component: &str,
    chain: Vec<FallbackLevel<T>>,
) -> FallbackResult<T> {
    let mut errors = Vec::new();
    let total_levels = chain.len();

    for (idx, level) in chain.into_iter().enumerate() {
        match (level.execute)().await {
            Ok(result) => {
                if idx > 0 {
                    tracing::warn!(
                        component = %component,
                        level = level.label,
                        attempts = idx + 1,
                        "Fallback chain resolved at level {}/{}: {}",
                        idx + 1, total_levels, level.label
                    );
                }
                return FallbackResult {
                    value: result,
                    level_used: idx,
                    level_label: level.label.to_string(),
                    degraded: idx > 0,
                    errors,
                };
            }
            Err(e) => {
                tracing::debug!(
                    component = %component,
                    level = level.label,
                    error = %e,
                    "Fallback level failed: {}",
                    level.label
                );
                errors.push((level.label.to_string(), e));
            }
        }
    }

    // This should never happen if chain ends in a safe default,
    // but we handle it defensively.
    panic!(
        "Fallback chain exhausted for {} -- chain must end in infallible safe default",
        component
    );
}

/// Result of a fallback chain execution, including audit metadata.
pub struct FallbackResult<T> {
    pub value: T,
    pub level_used: usize,
    pub level_label: String,
    /// True if we degraded below Level 0 (primary).
    pub degraded: bool,
    /// All errors encountered before resolution.
    pub errors: Vec<(String, FallbackError)>,
}
```

### 2.4 Parser Fallback Example

This illustrates the forensic-specific fallback for a parser processing a corrupted Windows Event Log (.evtx):

```rust
// Example: EVTX parser fallback chain

fn evtx_fallback_chain(path: &Path) -> Vec<FallbackLevel<ParseResult>> {
    vec![
        FallbackLevel {
            label: "full_structured_parse",
            execute: Box::new(move || Box::pin(async move {
                // Full parse: XML structure, event IDs, timestamps, parameters
                evtx::parse_structured(path).await
            })),
        },
        FallbackLevel {
            label: "lenient_parse_skip_malformed",
            execute: Box::new(move || Box::pin(async move {
                // Skip individual corrupted records, parse what we can
                evtx::parse_lenient(path, SkipPolicy::MalformedRecords).await
            })),
        },
        FallbackLevel {
            label: "binary_record_extraction",
            execute: Box::new(move || Box::pin(async move {
                // Carve record boundaries from binary, extract timestamps + raw XML
                evtx::carve_records(path).await
            })),
        },
        FallbackLevel {
            label: "strings_extraction",
            execute: Box::new(move || Box::pin(async move {
                // Last resort: extract UTF-16/UTF-8 strings with timestamps
                strings::extract_with_context(path, StringsConfig::forensic_default()).await
            })),
        },
        FallbackLevel {
            label: "metadata_only",
            execute: Box::new(move || Box::pin(async move {
                // Infallible: file metadata + hash + "parse failed" marker
                Ok(ParseResult::metadata_only(path, "EVTX parser exhausted all strategies"))
            })),
        },
    ]
}
```

**Critical invariant**: The `metadata_only` level is infallible. It always succeeds, recording:
- File path and size
- SHA-256 hash of the raw bytes (evidence integrity)
- Timestamps from filesystem metadata
- Explicit marker that this artifact was not successfully parsed
- All error messages from prior attempts (examiner's notes)

---

## 3. Timeout Handling

Issen's north star metric TARR (Time-to-Attorney-Ready Report) targets under 4 hours for a standard IR triage case. Timeout budgets enforce this ceiling and prevent any single component from consuming the entire budget. The pipeline must always produce *something* within the time budget -- partial results with clear coverage gaps are acceptable; hanging indefinitely is not.

### 3.1 Timeout Configuration

| Component | Timeout | Rationale |
|-----------|---------|-----------|
| **Pipeline Total** | 3 hours | Leaves 1 hour buffer for report generation within 4-hour TARR target |
| **Layer 0: Container** | 30 minutes | Large E01 images (500GB+) need time for container parsing; fail fast if truly corrupted |
| **Layer 1: Filesystem** | 20 minutes | MFT/inode table parsing for large volumes; parallelized via rayon |
| **Layer 2: Artifact** | 5 minutes per artifact | Individual file extraction; should be fast |
| **Layer 3: Parser** (per artifact type) | 15 minutes | Complex parsers (registry hive, EVTX) may process millions of records |
| **Layer 3: Parser** (per record) | 100ms | Individual record parse; prevents single corrupt record from stalling |
| **Layer 4: Enrichment** (LLM) | 30 seconds per call | Local LLM inference; includes model loading if cold |
| **Layer 4: Enrichment** (YARA/Sigma) | 5 minutes total | Rule scanning across all artifacts |
| `issen-timeline` (DuckDB insert batch) | 60 seconds | Batch insert of parsed events; DuckDB is fast |
| `issen-intel` (Narrative generation) | 5 minutes | LLM narrative drafting for report sections |
| `issen-report` (Full generation) | 30 minutes | HTML + DOCX rendering, template expansion, chart generation |
| `issen-correlation` (Full analysis) | 20 minutes | Cross-artifact pattern detection across timeline |
| WASM Plugin (Tier 2) | 60 seconds | Sandboxed execution with strict resource limits |
| gRPC Plugin (Tier 3) | 30 seconds | External process call with connection timeout |

### 3.2 Timeout Decorator

```rust
// src/resilience/timeout.rs

use std::time::Duration;
use tokio::time::timeout;

/// Execute an async operation with a timeout, falling back on expiration.
/// The fallback receives the elapsed duration for diagnostic reporting.
pub async fn with_timeout<T, F, Fut, G, GFut>(
    component: &str,
    duration: Duration,
    operation: F,
    fallback: G,
) -> TimeoutResult<T>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
    G: FnOnce(Duration) -> GFut,
    GFut: Future<Output = T>,
{
    match timeout(duration, operation()).await {
        Ok(result) => TimeoutResult {
            value: result,
            timed_out: false,
            elapsed: None,
        },
        Err(_) => {
            tracing::warn!(
                component = %component,
                timeout_ms = duration.as_millis(),
                "Operation timed out -- executing fallback"
            );
            let value = fallback(duration).await;
            TimeoutResult {
                value,
                timed_out: true,
                elapsed: Some(duration),
            }
        }
    }
}

pub struct TimeoutResult<T> {
    pub value: T,
    pub timed_out: bool,
    pub elapsed: Option<Duration>,
}
```

### 3.3 Graceful Degradation on Timeout

The pipeline uses a **progressive timeout strategy**: when the total pipeline budget is running low, remaining components receive reduced budgets and are told to produce simplified output.

```rust
// src/pipeline/budget.rs

pub struct TimeBudget {
    total: Duration,
    started_at: Instant,
    /// Reserved buffer for report generation -- never consumed by parsing
    report_reserve: Duration,
}

impl TimeBudget {
    pub fn new(total: Duration, report_reserve: Duration) -> Self {
        Self {
            total,
            started_at: Instant::now(),
            report_reserve,
        }
    }

    /// Remaining time available for parsing operations.
    pub fn remaining_for_parsing(&self) -> Duration {
        let elapsed = self.started_at.elapsed();
        let available = self.total.saturating_sub(elapsed);
        available.saturating_sub(self.report_reserve)
    }

    /// What percentage of budget has been consumed?
    pub fn utilization(&self) -> f64 {
        self.started_at.elapsed().as_secs_f64() / self.total.as_secs_f64()
    }

    /// Should we switch to simplified output?
    /// Triggers at 70% budget consumed.
    pub fn should_simplify(&self) -> bool {
        self.utilization() > 0.70
    }

    /// Should we skip non-essential enrichment?
    /// Triggers at 85% budget consumed.
    pub fn should_skip_enrichment(&self) -> bool {
        self.utilization() > 0.85
    }

    /// Emergency: produce output NOW with whatever we have.
    /// Triggers at 95% budget consumed.
    pub fn emergency_flush(&self) -> bool {
        self.utilization() > 0.95
    }
}
```

**Budget thresholds and their effects:**

| Budget Consumed | Action | Impact on TARR |
|-----------------|--------|----------------|
| 0-70% | Normal operation: full parsing, enrichment, correlation | Full quality report |
| 70-85% | Simplified mode: skip lenient re-parsing, reduce correlation depth | Slightly less cross-artifact detail |
| 85-95% | Skip enrichment: no LLM narrative, YARA/Sigma only if cached | Raw findings without narrative polish |
| 95-100% | Emergency flush: write report from whatever is parsed so far | Partial report with clear coverage gaps |

---

## 4. Idempotency Patterns

Forensic evidence processing must be **reproducible**. Running the same evidence through the pipeline twice must produce identical results (modulo timestamps of the run itself). Idempotency also enables **checkpoint/resume** -- if a long-running parse crashes at hour 2 of 3, the examiner should be able to resume from where it left off, not start over.

### 4.1 Idempotency Key Generation

Every operation in the pipeline is keyed by a deterministic identifier derived from its inputs:

```rust
// src/resilience/idempotency.rs

use sha2::{Sha256, Digest};

/// Generate a deterministic idempotency key for a parse operation.
/// The key is a function of: evidence source hash + artifact path + parser version.
pub fn parse_idempotency_key(
    evidence_hash: &[u8; 32],   // SHA-256 of the evidence source
    artifact_path: &str,         // Path within the evidence (e.g., "C:/Windows/System32/winevt/Logs/Security.evtx")
    parser_id: &str,             // Parser identifier (e.g., "evtx-parser")
    parser_version: &str,        // Semantic version (e.g., "0.3.1")
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(evidence_hash);
    hasher.update(artifact_path.as_bytes());
    hasher.update(parser_id.as_bytes());
    hasher.update(parser_version.as_bytes());
    hasher.finalize().into()
}

/// Generate idempotency key for an enrichment operation.
/// Includes the parsed-data hash so enrichment reruns when parsing changes.
pub fn enrichment_idempotency_key(
    parsed_data_hash: &[u8; 32],
    enrichment_type: &str,       // e.g., "forensic-llm", "yara-scan", "sigma-match"
    enrichment_version: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(parsed_data_hash);
    hasher.update(enrichment_type.as_bytes());
    hasher.update(enrichment_version.as_bytes());
    hasher.finalize().into()
}
```

### 4.2 Checkpoint/Resume Store

```rust
// src/resilience/checkpoint.rs

use std::path::PathBuf;

/// Checkpoint store backed by SQLite (the exchange database).
/// Survives crashes and allows pipeline resumption.
pub struct CheckpointStore {
    db: rusqlite::Connection,
}

impl CheckpointStore {
    pub fn open(case_dir: &Path) -> Result<Self> {
        let db_path = case_dir.join(".issen/checkpoints.db");
        let db = rusqlite::Connection::open(&db_path)?;
        db.execute_batch("
            CREATE TABLE IF NOT EXISTS checkpoints (
                idempotency_key BLOB PRIMARY KEY,
                component TEXT NOT NULL,
                artifact_path TEXT NOT NULL,
                status TEXT NOT NULL,  -- 'complete', 'partial', 'failed'
                result_hash BLOB,
                records_processed INTEGER DEFAULT 0,
                records_total INTEGER,
                last_offset INTEGER DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                error_message TEXT,
                fallback_level INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_checkpoints_component
                ON checkpoints(component, status);
        ")?;
        Ok(Self { db })
    }

    /// Check if an operation has already completed successfully.
    pub fn is_complete(&self, key: &[u8; 32]) -> Result<bool> {
        let count: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM checkpoints WHERE idempotency_key = ?1 AND status = 'complete'",
            [key.as_slice()],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Get the resume offset for a partially completed operation.
    pub fn get_resume_point(&self, key: &[u8; 32]) -> Result<Option<ResumePoint>> {
        self.db.query_row(
            "SELECT last_offset, records_processed FROM checkpoints
             WHERE idempotency_key = ?1 AND status = 'partial'",
            [key.as_slice()],
            |row| Ok(ResumePoint {
                offset: row.get(0)?,
                records_processed: row.get(1)?,
            }),
        ).optional()
    }

    /// Record progress for checkpoint/resume.
    pub fn update_progress(
        &self,
        key: &[u8; 32],
        component: &str,
        artifact_path: &str,
        records_processed: u64,
        last_offset: u64,
    ) -> Result<()> {
        self.db.execute(
            "INSERT INTO checkpoints (idempotency_key, component, artifact_path, status, records_processed, last_offset, updated_at)
             VALUES (?1, ?2, ?3, 'partial', ?4, ?5, datetime('now'))
             ON CONFLICT(idempotency_key) DO UPDATE SET
                records_processed = ?4, last_offset = ?5, updated_at = datetime('now')",
            rusqlite::params![key.as_slice(), component, artifact_path, records_processed, last_offset],
        )?;
        Ok(())
    }

    /// Mark an operation as complete.
    pub fn mark_complete(&self, key: &[u8; 32], result_hash: &[u8; 32]) -> Result<()> {
        self.db.execute(
            "UPDATE checkpoints SET status = 'complete', result_hash = ?2, updated_at = datetime('now')
             WHERE idempotency_key = ?1",
            rusqlite::params![key.as_slice(), result_hash.as_slice()],
        )?;
        Ok(())
    }

    /// Get pipeline progress summary for the examiner.
    pub fn progress_summary(&self) -> Result<PipelineProgress> {
        // Returns counts of complete/partial/failed by component
        // Used by CLI progress bars and TUI status display
        todo!()
    }
}

pub struct ResumePoint {
    pub offset: u64,
    pub records_processed: u64,
}
```

### 4.3 Evidence Integrity Verification

Every stage of the pipeline verifies evidence integrity using cryptographic hashes. This is non-negotiable for forensic admissibility.

```rust
// src/resilience/integrity.rs

/// Evidence integrity record, maintained at every pipeline stage.
pub struct IntegrityRecord {
    /// SHA-256 of the original evidence source (never changes)
    pub source_hash: [u8; 32],
    /// SHA-256 of the artifact file as extracted
    pub artifact_hash: [u8; 32],
    /// SHA-256 of the parsed output
    pub output_hash: [u8; 32],
    /// Chain of custody: each transformation is logged
    pub chain: Vec<IntegrityLink>,
}

pub struct IntegrityLink {
    pub stage: String,           // e.g., "layer-1-extract", "layer-3-parse"
    pub input_hash: [u8; 32],
    pub output_hash: [u8; 32],
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub component_version: String,
}

/// Verify the integrity chain from source through all transformations.
/// Returns Err if any link in the chain has a hash mismatch.
pub fn verify_chain(record: &IntegrityRecord) -> Result<(), IntegrityViolation> {
    let mut expected_input = record.source_hash;

    for (idx, link) in record.chain.iter().enumerate() {
        if link.input_hash != expected_input {
            return Err(IntegrityViolation {
                stage_index: idx,
                stage_name: link.stage.clone(),
                expected_hash: expected_input,
                actual_hash: link.input_hash,
            });
        }
        expected_input = link.output_hash;
    }

    if expected_input != record.output_hash {
        return Err(IntegrityViolation {
            stage_index: record.chain.len(),
            stage_name: "final_output".to_string(),
            expected_hash: expected_input,
            actual_hash: record.output_hash,
        });
    }

    Ok(())
}
```

---

## 5. Retry Strategies

Retries in a forensic context must be carefully bounded. Retrying a corrupted evidence parse is usually futile -- the data is damaged, not transiently unavailable. Retries are appropriate for:
- **Transient I/O errors**: Disk timeouts, NFS hiccups, USB disconnects
- **LLM inference**: Model server load spikes, OOM on large context
- **External services**: gRPC plugin connections, cloud model API calls
- **Database writes**: DuckDB lock contention during parallel inserts

Retries are **not** appropriate for:
- Corrupted evidence (will fail identically on retry)
- Parser logic errors (bugs, not transient)
- Out-of-memory on evidence parsing (need different strategy, not retry)

### 5.1 Exponential Backoff with Jitter

```rust
// src/resilience/retry.rs

use rand::Rng;
use std::time::Duration;

pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
    /// Jitter factor (0.0 - 1.0). Prevents thundering herd on shared resources.
    pub jitter_factor: f64,
}

impl RetryConfig {
    /// Default for I/O operations (disk, filesystem)
    pub fn io_default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            backoff_multiplier: 2.0,
            jitter_factor: 0.25,
        }
    }

    /// Default for LLM inference calls
    pub fn llm_default() -> Self {
        Self {
            max_retries: 2,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 3.0,
            jitter_factor: 0.5,
        }
    }

    /// Default for external service calls (gRPC plugins, APIs)
    pub fn external_service_default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(15),
            backoff_multiplier: 2.0,
            jitter_factor: 0.3,
        }
    }

    /// Default for database operations (DuckDB, SQLite)
    pub fn database_default() -> Self {
        Self {
            max_retries: 5,
            initial_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(2),
            backoff_multiplier: 2.0,
            jitter_factor: 0.1,
        }
    }

    /// No retries -- for operations on corrupted evidence
    pub fn no_retry() -> Self {
        Self {
            max_retries: 0,
            initial_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
            backoff_multiplier: 1.0,
            jitter_factor: 0.0,
        }
    }
}

pub async fn retry_with_backoff<T, E, F, Fut>(
    component: &str,
    config: &RetryConfig,
    operation: F,
) -> Result<T, RetryExhausted<E>>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut last_error = None;
    let mut delay = config.initial_delay;
    let mut rng = rand::thread_rng();

    for attempt in 0..=config.max_retries {
        match operation().await {
            Ok(result) => {
                if attempt > 0 {
                    tracing::info!(
                        component = %component,
                        attempt = attempt + 1,
                        "Retry succeeded after {} attempts",
                        attempt + 1
                    );
                }
                return Ok(result);
            }
            Err(e) => {
                tracing::warn!(
                    component = %component,
                    attempt = attempt + 1,
                    max_retries = config.max_retries,
                    error = %e,
                    "Operation failed (attempt {}/{})",
                    attempt + 1,
                    config.max_retries + 1
                );
                last_error = Some(e);

                if attempt < config.max_retries {
                    // Add jitter to prevent thundering herd
                    let jitter = rng.gen_range(0.0..config.jitter_factor);
                    let jittered_delay = delay.mul_f64(1.0 + jitter);
                    tokio::time::sleep(jittered_delay).await;
                    delay = Duration::from_secs_f64(
                        (delay.as_secs_f64() * config.backoff_multiplier).min(config.max_delay.as_secs_f64())
                    );
                }
            }
        }
    }

    Err(RetryExhausted {
        component: component.to_string(),
        attempts: config.max_retries + 1,
        last_error: last_error.unwrap(),
    })
}
```

### 5.2 Retry Classification

Not all errors deserve retries. The pipeline classifies errors to decide the appropriate strategy:

```rust
// src/resilience/error_classification.rs

pub enum ErrorClass {
    /// Transient: retry with backoff (I/O timeout, connection reset, lock contention)
    Transient,
    /// Corrupted: do not retry, fall back immediately (bad data, CRC mismatch)
    Corrupted,
    /// ResourceExhausted: retry with longer delay + reduced scope (OOM, disk full)
    ResourceExhausted,
    /// Bug: do not retry, report immediately (assertion failure, logic error)
    ProgramError,
    /// External: retry with backoff (API rate limit, service unavailable)
    ExternalService,
}

pub fn classify_error(error: &PipelineError) -> ErrorClass {
    match error {
        PipelineError::IoTimeout(_) | PipelineError::ConnectionReset(_) => ErrorClass::Transient,
        PipelineError::CrcMismatch { .. } | PipelineError::MalformedData { .. } => ErrorClass::Corrupted,
        PipelineError::OutOfMemory { .. } | PipelineError::DiskFull { .. } => ErrorClass::ResourceExhausted,
        PipelineError::AssertionFailed { .. } => ErrorClass::ProgramError,
        PipelineError::ApiRateLimit { .. } | PipelineError::ServiceUnavailable { .. } => ErrorClass::ExternalService,
        _ => ErrorClass::Transient, // Default to transient for unknown errors
    }
}

pub fn retry_config_for_class(class: ErrorClass) -> RetryConfig {
    match class {
        ErrorClass::Transient => RetryConfig::io_default(),
        ErrorClass::Corrupted => RetryConfig::no_retry(),
        ErrorClass::ResourceExhausted => RetryConfig {
            max_retries: 2,
            initial_delay: Duration::from_secs(5),
            max_delay: Duration::from_secs(60),
            backoff_multiplier: 3.0,
            jitter_factor: 0.5,
        },
        ErrorClass::ProgramError => RetryConfig::no_retry(),
        ErrorClass::ExternalService => RetryConfig::external_service_default(),
    }
}
```

---

## 6. Memory Pressure Handling

Forensic evidence can be enormous -- 500GB+ disk images, millions of event log records, hundreds of thousands of registry keys. Issen must handle memory pressure gracefully without losing parsed data.

### 6.1 Memory Budget and Monitoring

```rust
// src/resilience/memory.rs

use sysinfo::System;

pub struct MemoryBudget {
    /// Maximum RSS the pipeline should consume (default: 80% of available RAM)
    max_rss_bytes: u64,
    /// Threshold for reducing parser parallelism
    high_watermark: f64,  // 0.70
    /// Threshold for emergency spill-to-disk
    critical_watermark: f64,  // 0.85
    /// Threshold for halting new parser starts
    emergency_watermark: f64,  // 0.95
}

pub enum MemoryPressure {
    /// Normal: full parallelism, in-memory buffering
    Normal,
    /// High: reduce rayon thread pool, flush DuckDB buffers more frequently
    High,
    /// Critical: spill intermediate results to disk, single-threaded parsing
    Critical,
    /// Emergency: halt new work, flush everything, GC WASM instances
    Emergency,
}

impl MemoryBudget {
    pub fn check_pressure(&self) -> MemoryPressure {
        let sys = System::new_all();
        let used = sys.used_memory();
        let total = sys.total_memory();
        let utilization = used as f64 / total as f64;

        match utilization {
            u if u >= self.emergency_watermark => MemoryPressure::Emergency,
            u if u >= self.critical_watermark => MemoryPressure::Critical,
            u if u >= self.high_watermark => MemoryPressure::High,
            _ => MemoryPressure::Normal,
        }
    }
}
```

### 6.2 Pressure Response Actions

| Pressure Level | Rayon Threads | Buffer Strategy | WASM Instances | DuckDB Flush | New Parsers |
|---------------|---------------|-----------------|----------------|--------------|-------------|
| Normal | All cores | In-memory | Up to 4 concurrent | Every 10K records | Unrestricted |
| High | 50% cores | In-memory, smaller batches | Up to 2 concurrent | Every 5K records | Throttled |
| Critical | 1 thread | Spill to disk (temp files) | 1 at a time | Every 1K records | Queued |
| Emergency | 1 thread | Direct disk writes | Suspended | Immediate flush | Halted |

### 6.3 Streaming Architecture

The pipeline never loads an entire evidence source into memory. All processing is streaming:

```rust
// Conceptual: streaming parser pattern

pub trait StreamingParser {
    type Record;

    /// Parse the next record from the stream.
    /// Returns None at end-of-stream.
    /// Returns Err for corrupted records (skip and continue).
    fn next_record(&mut self) -> Result<Option<Self::Record>, ParseError>;

    /// Estimated total records (for progress reporting).
    fn estimated_total(&self) -> Option<u64>;

    /// Current byte offset in the source (for checkpoint/resume).
    fn current_offset(&self) -> u64;
}

/// Process a streaming parser with memory-aware batching.
pub async fn process_streaming<P: StreamingParser>(
    parser: &mut P,
    budget: &MemoryBudget,
    checkpoint: &CheckpointStore,
    key: &[u8; 32],
    timeline: &TimelineWriter,
) -> ProcessResult {
    let mut batch = Vec::with_capacity(1000);
    let mut processed = 0u64;
    let mut skipped = 0u64;
    let batch_size = match budget.check_pressure() {
        MemoryPressure::Normal => 10_000,
        MemoryPressure::High => 5_000,
        MemoryPressure::Critical => 1_000,
        MemoryPressure::Emergency => 100,
    };

    loop {
        match parser.next_record() {
            Ok(Some(record)) => {
                batch.push(record);
                if batch.len() >= batch_size {
                    timeline.write_batch(&batch).await?;
                    processed += batch.len() as u64;
                    batch.clear();

                    // Checkpoint progress
                    checkpoint.update_progress(
                        key, "parser", "", processed, parser.current_offset()
                    )?;
                }
            }
            Ok(None) => break, // End of stream
            Err(e) => {
                tracing::warn!(offset = parser.current_offset(), error = %e, "Skipping corrupted record");
                skipped += 1;
                continue; // Skip corrupted records, keep going
            }
        }
    }

    // Flush remaining batch
    if !batch.is_empty() {
        timeline.write_batch(&batch).await?;
        processed += batch.len() as u64;
    }

    ProcessResult { processed, skipped }
}
```

---

## 7. Plugin Crash Isolation

Issen supports three tiers of plugins. Each tier has different isolation guarantees:

### 7.1 Plugin Tier Isolation Matrix

| Tier | Mechanism | Crash Impact | Memory Isolation | CPU Limits | File Access |
|------|-----------|--------------|------------------|------------|-------------|
| **Tier 1: Native** | Rust trait (`dyn ParserPlugin`) | Process crash (same address space) | None (shared heap) | None (same thread pool) | Full |
| **Tier 2: WASM** | wasmtime sandbox | Trapped (WASM instance terminated) | Complete (linear memory) | Fuel-based metering | Capability-based (WASI) |
| **Tier 3: gRPC** | Subprocess via gRPC | Process killed (separate PID) | Complete (separate process) | OS cgroup/rlimit | Sandboxed working dir |

### 7.2 WASM Plugin Sandbox Configuration

```rust
// src/plugins/wasm_sandbox.rs

use wasmtime::*;

pub struct WasmPluginConfig {
    /// Maximum linear memory (bytes). Default: 256MB.
    pub max_memory_bytes: u64,
    /// Fuel limit (instruction count proxy). Default: 1 billion.
    pub fuel_limit: u64,
    /// Execution timeout. Default: 60 seconds.
    pub timeout: Duration,
    /// Allowed WASI capabilities.
    pub wasi_caps: WasiCapabilities,
}

pub struct WasiCapabilities {
    /// Read-only access to the evidence directory
    pub evidence_dir_read: bool,
    /// Write access to plugin output directory only
    pub output_dir_write: bool,
    /// No network access
    pub network: bool,
    /// No environment variables
    pub env_vars: bool,
}

impl Default for WasmPluginConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 256 * 1024 * 1024,  // 256MB
            fuel_limit: 1_000_000_000,              // ~1B instructions
            timeout: Duration::from_secs(60),
            wasi_caps: WasiCapabilities {
                evidence_dir_read: true,
                output_dir_write: true,
                network: false,
                env_vars: false,
            },
        }
    }
}

/// Execute a WASM plugin with full isolation.
/// Returns parsed results or error -- never panics, never leaks.
pub async fn execute_wasm_plugin(
    module_path: &Path,
    config: &WasmPluginConfig,
    input: &PluginInput,
) -> Result<PluginOutput, PluginError> {
    let engine = Engine::new(
        Config::new()
            .consume_fuel(true)
            .epoch_interruption(true)
    )?;

    let module = Module::from_file(&engine, module_path)?;

    let mut store = Store::new(&engine, ());
    store.set_fuel(config.fuel_limit)?;

    // WASI configuration with minimal capabilities
    let wasi_ctx = build_wasi_context(&config.wasi_caps)?;

    let instance = Instance::new(&mut store, &module, &[])?;

    // Execute with timeout
    let result = with_timeout(
        "wasm-plugin",
        config.timeout,
        || async { invoke_plugin(&mut store, &instance, input).await },
        |_| async { Err(PluginError::Timeout) },
    ).await;

    // Instance is dropped here -- all WASM memory is freed
    result.value
}
```

### 7.3 gRPC Plugin Process Isolation

```rust
// src/plugins/grpc_sandbox.rs

use std::process::Command;

pub struct GrpcPluginConfig {
    /// Maximum RSS for the subprocess. Default: 512MB.
    pub max_memory_bytes: u64,
    /// CPU time limit. Default: 60 seconds.
    pub cpu_time_limit: Duration,
    /// Working directory (sandboxed)
    pub working_dir: PathBuf,
    /// gRPC port (assigned dynamically)
    pub port: u16,
}

/// Launch a gRPC plugin as a sandboxed subprocess.
pub async fn launch_grpc_plugin(
    binary_path: &Path,
    config: &GrpcPluginConfig,
) -> Result<GrpcPluginHandle, PluginError> {
    let child = Command::new(binary_path)
        .arg("--port")
        .arg(config.port.to_string())
        .arg("--working-dir")
        .arg(&config.working_dir)
        .current_dir(&config.working_dir)
        // Resource limits (macOS/Linux)
        .env("RAPIDTRIAGE_MEMORY_LIMIT", config.max_memory_bytes.to_string())
        .spawn()?;

    // Wait for gRPC health check
    let client = wait_for_grpc_ready(config.port, Duration::from_secs(10)).await?;

    Ok(GrpcPluginHandle {
        child,
        client,
        config: config.clone(),
    })
}

impl Drop for GrpcPluginHandle {
    fn drop(&mut self) {
        // Ensure subprocess is terminated on handle drop
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
```

### 7.4 Plugin Crash Recovery

When a plugin crashes, the pipeline must:

1. **Preserve all data parsed before the crash** (already in DuckDB/checkpoint store)
2. **Record the crash** in the case audit trail
3. **Mark the gap** in evidence coverage
4. **Continue processing** other artifacts/plugins
5. **Never restart the crashed plugin automatically** for the same input (it will crash again)

```rust
// src/plugins/recovery.rs

pub async fn execute_plugin_with_recovery<T>(
    plugin_id: &str,
    plugin_type: PluginTier,
    input: &PluginInput,
    checkpoint: &CheckpointStore,
) -> PluginResult<T> {
    let key = plugin_idempotency_key(plugin_id, input);

    // Check if we already tried and failed this exact input
    if let Some(prev_failure) = checkpoint.get_failure(&key)? {
        tracing::info!(
            plugin = %plugin_id,
            prev_error = %prev_failure.error,
            "Skipping plugin -- previously crashed on identical input"
        );
        return PluginResult::PreviouslyFailed {
            error: prev_failure.error,
            timestamp: prev_failure.timestamp,
        };
    }

    let result = match plugin_type {
        PluginTier::Native => execute_native_plugin(plugin_id, input).await,
        PluginTier::Wasm => execute_wasm_plugin_safe(plugin_id, input).await,
        PluginTier::Grpc => execute_grpc_plugin_safe(plugin_id, input).await,
    };

    match result {
        Ok(output) => {
            checkpoint.mark_complete(&key, &hash_output(&output))?;
            PluginResult::Success(output)
        }
        Err(e) => {
            checkpoint.mark_failed(&key, &e.to_string())?;
            tracing::error!(
                plugin = %plugin_id,
                error = %e,
                "Plugin crashed -- recording failure, continuing pipeline"
            );
            PluginResult::Failed {
                error: e.to_string(),
                data_preserved: true,
            }
        }
    }
}
```

---

## 8. LLM Fallback Chains

The `issen-intel` component uses LLMs for narrative generation, classification, and enrichment. LLM availability is inherently unreliable -- models may be loading, GPU memory may be exhausted, or the user may not have a large model available. Issen implements a multi-tier LLM fallback chain aligned with the architecture's model routing strategy.

### 8.1 LLM Fallback Tiers

| Tier | Model | Use Case | Latency | Quality |
|------|-------|----------|---------|---------|
| **Tier 1** | Large local (70B+, e.g., Llama 3 70B) | Full narrative generation, complex reasoning | 10-30s/call | Highest |
| **Tier 2** | Medium local (13B-30B, e.g., Mistral Medium) | Structured summarization, pattern explanation | 3-10s/call | Good |
| **Tier 3** | Small local (7B, e.g., Llama 3 8B) | Classification, entity extraction, tagging | 1-3s/call | Adequate |
| **Tier 4** | Cloud fallback (API, if configured) | Complex narrative when local models unavailable | 2-5s/call | Highest |
| **Tier 5** | Rule-based (YARA/Sigma matches only) | Deterministic enrichment, no LLM required | <100ms | Structured only |
| **Tier 6** | AI-free pass-through | Raw findings without any enrichment | 0ms | Raw data |

### 8.2 ForensicLLM Fallback Implementation

```rust
// src/intel/llm_fallback.rs

pub struct ForensicLlmChain {
    /// Available models, ordered by preference
    models: Vec<ModelConfig>,
    /// Whether cloud fallback is permitted for this case
    cloud_allowed: bool,
    /// Circuit breakers per model
    breakers: HashMap<String, CircuitBreaker>,
}

impl ForensicLlmChain {
    /// Generate a forensic narrative with automatic fallback.
    pub async fn generate_narrative(
        &self,
        findings: &[Finding],
        context: &CaseContext,
    ) -> NarrativeResult {
        // Try each model tier in order
        for model in &self.models {
            if !self.cloud_allowed && model.is_cloud {
                continue; // Skip cloud models if not permitted
            }

            let breaker = &self.breakers[&model.id];
            if breaker.get_state() == CircuitState::Open {
                continue; // Skip models with open circuits
            }

            match self.try_model(model, findings, context).await {
                Ok(narrative) => {
                    breaker.record_success();
                    return NarrativeResult {
                        text: narrative,
                        model_used: model.id.clone(),
                        tier: model.tier,
                        degraded: model.tier > 1,
                    };
                }
                Err(e) => {
                    breaker.record_failure();
                    tracing::warn!(
                        model = %model.id,
                        tier = model.tier,
                        error = %e,
                        "LLM model failed -- trying next tier"
                    );
                }
            }
        }

        // Tier 5: Rule-based fallback (no LLM)
        let rule_output = self.rule_based_enrichment(findings).await;
        if !rule_output.matches.is_empty() {
            return NarrativeResult {
                text: format_rule_matches(&rule_output),
                model_used: "rule-engine".to_string(),
                tier: 5,
                degraded: true,
            };
        }

        // Tier 6: AI-free pass-through
        NarrativeResult {
            text: format_raw_findings(findings),
            model_used: "none".to_string(),
            tier: 6,
            degraded: true,
        }
    }
}
```

### 8.3 AI-Free Mode

Issen must function completely without any AI/LLM. This is both a resilience requirement and a user choice (some forensic labs prohibit AI processing of evidence).

When running in AI-free mode:
- All LLM fallback chains immediately resolve to Tier 6 (pass-through)
- YARA and Sigma rule matching still operates (deterministic, not AI)
- Reports use template-based narrative instead of generated narrative
- The examiner is expected to write their own narrative sections
- TARR increases but all other pipeline stages function identically

---

## 9. Health Checks

### 9.1 Component Health Status

```rust
// src/resilience/health.rs

#[derive(Debug, Clone, Serialize)]
pub struct SystemHealth {
    pub overall: HealthStatus,
    pub components: Vec<ComponentHealth>,
    pub pipeline_progress: PipelineProgress,
    pub memory_pressure: MemoryPressure,
    pub uptime: Duration,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComponentHealth {
    pub id: String,
    pub status: HealthStatus,
    pub circuit_state: CircuitState,
    pub last_success: Option<chrono::DateTime<chrono::Utc>>,
    pub last_failure: Option<chrono::DateTime<chrono::Utc>>,
    pub success_rate: f64,
    pub active_operations: u64,
    pub fallback_level: u32,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub enum HealthStatus {
    Healthy,   // All systems nominal
    Degraded,  // Operating with fallbacks active
    Unhealthy, // Component unavailable, circuit open
}

pub fn compute_system_health(components: &[ComponentHealth]) -> HealthStatus {
    if components.iter().any(|c| c.status == HealthStatus::Unhealthy) {
        // Any critical component unhealthy = system degraded (not unhealthy,
        // because the pipeline continues via fallbacks)
        HealthStatus::Degraded
    } else if components.iter().any(|c| c.status == HealthStatus::Degraded) {
        HealthStatus::Degraded
    } else {
        HealthStatus::Healthy
    }
}
```

### 9.2 Per-Component Health Checks

| Component | Health Check Method | Healthy Criteria | Degraded Criteria |
|-----------|-------------------|------------------|-------------------|
| `issen-pipeline` | Layer completion rate | All layers processing | Any layer using fallbacks |
| `issen-timeline` | DuckDB query latency | Query < 100ms | Query 100ms-1s |
| `issen-intel` | Model inference test | Primary model responds | Fallback model in use |
| `issen-report` | Template render test | Full render < 5s | Render 5-30s |
| `issen-correlation` | Pattern match test | All patterns evaluated | Subset of patterns |
| WASM Plugins | Instance creation test | Instance starts < 1s | Instance starts 1-5s |
| gRPC Plugins | gRPC health check | Response < 100ms | Response 100ms-1s |
| DuckDB | Write throughput | > 100K records/s | 10K-100K records/s |
| Disk I/O | Write bandwidth | > 100 MB/s | 10-100 MB/s |
| Memory | RSS utilization | < 70% budget | 70-85% budget |

### 9.3 Health Reporting for Examiners

The TUI and CLI display real-time pipeline health using a simplified status model:

```
Issen Pipeline Status
============================
Evidence:    case-2026-0319.E01 (47.2 GB)
TARR Budget: 02:15:30 remaining (43% used)
Memory:      Normal (4.2 GB / 12.8 GB)

  Layer 0 (Container)  [DONE]  E01 parsed in 3m 12s
  Layer 1 (Filesystem) [DONE]  NTFS: 847,291 files indexed
  Layer 2 (Artifacts)  [=====>    ]  72% (1,247 / 1,731 artifacts)
  Layer 3 (Parsers)    [===>      ]  41% -- 3 parsers active
    EVTX:     [DONE]  24,891 events
    Registry: [=====>]  78% (hive 3/4)
    Prefetch: [DEGRADED] Using lenient parser (12 corrupted entries skipped)
    $MFT:     [QUEUED]
  Layer 4 (Enrichment) [WAITING]
    LLM:      Llama 3 70B loaded (Tier 1)
    YARA:     247 rules loaded
    Sigma:    189 rules loaded

  Warnings:
    ! Prefetch parser fell back to lenient mode (12 records corrupted)
    ! 3 EVTX records skipped (CRC mismatch at offsets 0x4A210, 0x8F100, 0xC3400)
```

---

## 10. Resilience Testing Strategy

### 10.1 Chaos Testing for Forensic Scenarios

Issen includes a built-in chaos testing framework that simulates the kinds of failures forensic tools actually encounter:

| Test Scenario | Injection Method | Expected Behavior |
|---------------|-----------------|-------------------|
| Corrupted E01 segment | Flip random bytes in segment | Container parser falls back to raw read |
| Truncated EVTX file | Truncate file mid-record | EVTX parser returns partial results |
| Malformed registry hive | Corrupt cell headers | Registry parser uses lenient mode |
| WASM plugin OOM | Set fuel limit to 1000 | WASM sandbox catches trap, returns error |
| DuckDB disk full | Mount tmpfs with 1MB limit | DuckDB writes fail, spill to overflow CSV |
| LLM model not available | Kill Ollama before inference | Fallback to rule-based enrichment |
| Network drop during gRPC | iptables DROP on plugin port | gRPC timeout, plugin skipped |
| Memory pressure | Allocate 90% RAM before pipeline | Pipeline reduces parallelism, spills to disk |
| Mid-parse crash | SIGKILL pipeline process | Resume from checkpoint on restart |
| Simultaneous parser failures | Corrupt 3+ artifact types | Circuit breakers open, partial report generated |

### 10.2 Invariants Under Test

These invariants must hold under ALL failure scenarios:

1. **Data preservation**: Previously parsed data is never lost due to a later failure
2. **Hash integrity**: Evidence hash chain is valid from source to output
3. **Checkpoint consistency**: Pipeline can resume from any checkpoint without data duplication
4. **Report generation**: The pipeline always produces *some* output, even if degraded
5. **Audit trail completeness**: Every failure, fallback, and skip is recorded
6. **Idempotent reruns**: Re-running the pipeline on the same evidence produces identical results
7. **Memory bounds**: RSS never exceeds the configured budget (within 10% tolerance)
8. **Timeout compliance**: Total pipeline time never exceeds TARR budget + 5% tolerance

---

## Cross-Reference Summary

| Document | Referenced Fields | Usage in This Document |
|----------|-------------------|------------------------|
| Architecture Blueprint | `components[]`, `tech_stack`, `pattern` | Circuit breaker per-component config, timeout budgets, plugin tiers |
| North Star | `metric` (TARR), `target` (<4 hours) | Timeout budget derivation, graceful degradation thresholds |
| Brand Guidelines | `beliefs` (Correctness > Speed) | Retry classification (no retry on corruption), AI-free mode |
| Competitive Landscape | `key_differentiators` | Resilience as differentiator vs. tools that crash on corrupted evidence |
