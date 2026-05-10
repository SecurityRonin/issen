# Issen: Observability

> **Parent**: [ARCHITECTURE_BLUEPRINT.md](../ARCHITECTURE_BLUEPRINT.md)
> **Created**: 2026-03-20
> **Status**: Active

Structured tracing, pipeline metrics, TARR instrumentation, forensic audit logging, and local-first dashboards for air-gapped forensic environments.

**Design Constraint**: Issen operates in air-gapped forensic labs. All observability infrastructure runs locally -- no cloud telemetry, no external endpoints. Every metric, trace, and audit log is stored in local DuckDB or on-disk files.

---

## 1. Trace Architecture

### 1.1 Trace Hierarchy

Issen's trace tree mirrors the evidence processing pipeline. Each case execution produces a single root trace that fans out through the data pipeline layers.

```
Case Trace (root span)
|
+-- Ingest Span
|   +-- VFS Mount Span
|   |   +-- E01 Reader Span (issen-ewf)
|   |   +-- Raw Image Reader Span
|   |   +-- KAPE Output Reader Span
|   +-- Source Fingerprint Span
|   +-- Evidence Registration Span (hash + chain-of-custody)
|
+-- Parse Span
|   +-- Parallel Parser Pool Span (rayon)
|   |   +-- issen-parser-evtx Span
|   |   +-- issen-parser-mft Span
|   |   +-- issen-parser-usnjrnl Span
|   |   +-- issen-parser-prefetch Span
|   |   +-- issen-parser-registry Span
|   |   +-- issen-parser-lnk Span
|   |   +-- issen-parser-amcache Span
|   |   +-- issen-parser-bam Span
|   |   +-- issen-parser-browser Span
|   |   +-- issen-parser-jumplists Span
|   |   +-- issen-parser-srum Span
|   +-- DuckDB Timeline Write Span
|
+-- Correlate Span (issen-correlation)
|   +-- Cross-Artifact Correlation Span
|   +-- Attack Pattern Detection Span
|   +-- YARA-X Scan Span
|   +-- Sigma Rule Evaluation Span
|
+-- Intelligence Span (issen-intel, optional)
|   +-- RAG Query Span
|   +-- LLM Narrative Generation Span
|   +-- Grounded Citation Verification Span
|
+-- Report Span (issen-report)
|   +-- HTML Report Generation Span
|   +-- DOCX Report Generation Span
|   +-- Report Hash + Signing Span
|
+-- Audit Finalization Span
    +-- Chain-of-Custody Record Span
    +-- Case Metadata Persistence Span
```

### 1.2 Event Types

| Event | Description | Attributes |
|-------|-------------|------------|
| `case.start` | Case processing begins | `case_id`, `evidence_sources[]`, `examiner_id` |
| `case.end` | Case processing completes | `duration_ms`, `success`, `tarr_elapsed_ms` |
| `ingest.start` | Evidence ingestion begins | `case_id`, `source_path`, `source_type` |
| `ingest.end` | Evidence ingestion completes | `duration_ms`, `bytes_read`, `source_hash_sha256` |
| `vfs.mount` | Virtual filesystem mounted | `source_type`, `layers_detected[]` |
| `parser.start` | Individual parser begins | `parser_id`, `artifact_type`, `input_path` |
| `parser.end` | Individual parser completes | `duration_ms`, `events_emitted`, `bytes_processed`, `errors` |
| `parser.error` | Parser encounters error | `parser_id`, `error_type`, `artifact_path`, `is_corruption` |
| `timeline.write` | Events written to DuckDB | `event_count`, `batch_size`, `duration_ms` |
| `correlate.start` | Correlation engine begins | `case_id`, `event_count`, `rule_count` |
| `correlate.match` | Correlation pattern matched | `pattern_id`, `confidence`, `event_ids[]` |
| `yara.scan` | YARA-X rule scan executed | `rules_loaded`, `files_scanned`, `matches` |
| `sigma.evaluate` | Sigma rule evaluation | `rules_evaluated`, `matches`, `duration_ms` |
| `llm.request` | LLM API call (Ollama) | `model`, `prompt_tokens`, `temperature` |
| `llm.response` | LLM response received | `completion_tokens`, `latency_ms`, `model` |
| `rag.query` | RAG retrieval executed | `store` (case/cross-case/reference), `results_count`, `latency_ms` |
| `report.generate` | Report generation starts | `format` (html/docx/pdf), `template_id` |
| `report.complete` | Report file written | `format`, `file_size_bytes`, `content_hash_sha256`, `duration_ms` |
| `audit.record` | Audit log entry created | `action`, `examiner_id`, `case_id`, `timestamp_utc` |
| `integrity.violation` | Data integrity check failed | `check_type`, `expected_hash`, `actual_hash`, `artifact_path` |

### 1.3 Span Attributes (Common)

Every span carries these baseline attributes for forensic traceability:

| Attribute | Type | Description |
|-----------|------|-------------|
| `case_id` | `String` | Unique case identifier |
| `examiner_id` | `String` | Examiner identity (for audit) |
| `evidence_source` | `String` | Source evidence container path |
| `hostname` | `String` | Processing workstation hostname |
| `rt_version` | `String` | Issen build version |
| `pipeline_stage` | `String` | Current stage: ingest, parse, correlate, intel, report |

---

## 2. Tracing Handlers

### 2.1 Handler Architecture

Issen uses the Rust `tracing` crate as its instrumentation backbone with multiple `tracing-subscriber` layers. Each handler consumes structured span and event data independently.

```rust
// src/observability/handler.rs

use tracing_subscriber::{Layer, Registry};
use tracing_subscriber::layer::SubscriberExt;

/// All trace handlers implement tracing_subscriber::Layer<Registry>.
/// Handlers are composed via the subscriber layer stack.

pub trait TraceHandler: Send + Sync + 'static {
    /// Human-readable name for diagnostics
    fn name(&self) -> &'static str;

    /// Whether this handler should be active in the current mode
    fn is_enabled(&self, config: &ObservabilityConfig) -> bool;
}

/// Composed subscriber with all active handlers
pub fn init_tracing(config: &ObservabilityConfig) -> impl tracing::Subscriber {
    let json_layer = JsonLogLayer::new(&config.log_config);
    let metrics_layer = MetricsLayer::new(&config.metrics_config);
    let audit_layer = AuditLayer::new(&config.audit_config);
    let tarr_layer = TarrInstrumentationLayer::new(&config.tarr_config);

    Registry::default()
        .with(json_layer)
        .with(metrics_layer)
        .with(audit_layer)
        .with(tarr_layer)
}
```

### 2.2 JSON Structured Log Handler

Primary logging handler. Outputs structured JSON to local files with rotation.

```rust
// src/observability/handlers/json_log.rs

use tracing_subscriber::fmt;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_appender::rolling::{RollingFileAppender, Rotation};

pub struct JsonLogLayer {
    appender: RollingFileAppender,
}

impl JsonLogLayer {
    pub fn new(config: &LogConfig) -> Self {
        let appender = RollingFileAppender::new(
            Rotation::DAILY,
            &config.log_dir,       // e.g., "./cases/{case_id}/logs"
            "issen.log",
        );
        Self { appender }
    }
}

// Output format (one JSON object per line):
// {
//   "timestamp": "2026-03-20T14:32:01.847Z",
//   "level": "INFO",
//   "target": "rt_pipeline::parsers::evtx",
//   "span": { "name": "parser.evtx", "case_id": "CASE-2026-0042" },
//   "fields": { "events_emitted": 14832, "duration_ms": 1247 },
//   "message": "EVTX parser completed"
// }
```

### 2.3 Metrics Aggregation Handler

Captures numeric measurements and stores them in a local DuckDB metrics database for querying and dashboarding.

```rust
// src/observability/handlers/metrics.rs

use duckdb::Connection;

pub struct MetricsLayer {
    conn: Connection,
}

impl MetricsLayer {
    pub fn new(config: &MetricsConfig) -> Self {
        let conn = Connection::open(&config.metrics_db_path)
            .expect("Failed to open metrics DuckDB");

        // Create metrics tables on init
        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS pipeline_metrics (
                timestamp    TIMESTAMP DEFAULT current_timestamp,
                case_id      VARCHAR NOT NULL,
                stage        VARCHAR NOT NULL,
                metric_name  VARCHAR NOT NULL,
                metric_value DOUBLE NOT NULL,
                unit         VARCHAR,
                attributes   JSON
            );

            CREATE TABLE IF NOT EXISTS parser_metrics (
                timestamp       TIMESTAMP DEFAULT current_timestamp,
                case_id         VARCHAR NOT NULL,
                parser_id       VARCHAR NOT NULL,
                events_emitted  BIGINT,
                bytes_processed BIGINT,
                duration_ms     DOUBLE,
                error_count     INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS tarr_measurements (
                timestamp       TIMESTAMP DEFAULT current_timestamp,
                case_id         VARCHAR NOT NULL,
                stage           VARCHAR NOT NULL,
                stage_start_ms  BIGINT,
                stage_end_ms    BIGINT,
                stage_duration_ms DOUBLE,
                cumulative_ms   DOUBLE
            );
        ").expect("Failed to create metrics tables");

        Self { conn }
    }
}
```

### 2.4 Audit Log Handler

Forensic chain-of-custody logging. Every examiner action and automated processing step is recorded with cryptographic integrity.

```rust
// src/observability/handlers/audit.rs

use ring::digest::{digest, SHA256};
use serde::Serialize;

#[derive(Serialize)]
pub struct AuditEntry {
    pub sequence_number: u64,
    pub timestamp_utc: String,
    pub case_id: String,
    pub examiner_id: String,
    pub action: AuditAction,
    pub detail: String,
    pub previous_hash: String,    // Hash chain for tamper detection
    pub entry_hash: String,       // SHA-256 of this entry
}

pub enum AuditAction {
    EvidenceIngested,
    ParserExecuted,
    TimelineQueried,
    CorrelationRun,
    FindingAnnotated,
    ReportGenerated,
    ReportExported,
    CaseOpened,
    CaseClosed,
    ConfigChanged,
}

pub struct AuditLayer {
    log_path: PathBuf,            // e.g., "./cases/{case_id}/audit.jsonl"
    sequence: AtomicU64,
    last_hash: Mutex<String>,
}

// Audit entries form a hash chain:
// entry_hash = SHA-256(sequence_number || timestamp || action || detail || previous_hash)
// This allows tamper detection without external infrastructure.
```

---

## 3. Local Observability Backend

### 3.1 Architecture (Air-Gap Compliant)

Issen replaces cloud telemetry with a fully local observability stack:

```
+-------------------+     +-------------------+     +-------------------+
|  tracing crate    |---->|  Layer Stack      |---->|  Local Storage    |
|  (instrumentation)|     |  (subscribers)    |     |  (DuckDB + files) |
+-------------------+     +-------------------+     +-------------------+
                                |   |   |   |
                     +----------+   |   |   +-----------+
                     |              |   |               |
                     v              v   v               v
              JSON Log Files   Metrics DB  Audit Chain   TARR DB
              (daily rotation) (DuckDB)    (JSONL+hash)  (DuckDB)
                     |              |           |            |
                     v              v           v            v
              +------------------------------------------------------+
              |            TUI Dashboard (issen-tui)                     |
              |   Real-time pipeline monitor + metric explorer        |
              +------------------------------------------------------+
```

**No network dependencies.** All data stays on the examiner's workstation or network share.

### 3.2 Storage Layout

```
cases/{case_id}/
+-- logs/
|   +-- issen.log           # JSON structured logs (daily rotation)
|   +-- issen.log.2026-03-19
+-- audit/
|   +-- audit.jsonl               # Hash-chained audit log
|   +-- audit.jsonl.sig           # Optional GPG signature
+-- metrics/
|   +-- metrics.duckdb            # Pipeline + parser metrics
|   +-- tarr.duckdb               # TARR stage measurements
+-- evidence/
|   +-- hashes.sha256             # Evidence file hashes
+-- reports/
    +-- report.html
    +-- report.docx
    +-- report_hash.sha256        # Report content integrity hash
```

### 3.3 Bootstrap

```rust
// src/observability/bootstrap.rs

use tracing_subscriber::EnvFilter;

pub struct ObservabilityConfig {
    pub log_dir: PathBuf,
    pub metrics_db_path: PathBuf,
    pub audit_log_path: PathBuf,
    pub tarr_db_path: PathBuf,
    pub sanitization_mode: SanitizationMode,
    pub log_level: String,         // default: "info", overridable via RUST_LOG
}

pub fn init_observability(config: ObservabilityConfig) -> ObservabilityGuard {
    let subscriber = init_tracing(&config);
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set tracing subscriber");

    tracing::info!(
        case_dir = %config.log_dir.display(),
        "Issen observability initialized"
    );

    ObservabilityGuard { config }
}

/// Guard ensures flush on drop
pub struct ObservabilityGuard {
    config: ObservabilityConfig,
}

impl Drop for ObservabilityGuard {
    fn drop(&mut self) {
        tracing::info!("Observability shutting down, flushing handlers");
        // Flush all layers
    }
}
```

---

## 4. Pipeline Stage Metrics

### 4.1 Per-Stage Instrumentation

Every pipeline stage is instrumented with `#[tracing::instrument]` and emits standardized metrics:

```rust
// src/pipeline/instrumented.rs

use tracing::instrument;
use std::time::Instant;

#[instrument(
    name = "ingest",
    skip(evidence_source),
    fields(
        case_id = %case_id,
        source_type = %evidence_source.source_type(),
        bytes_total = tracing::field::Empty,
        duration_ms = tracing::field::Empty,
    )
)]
pub async fn ingest_evidence(
    case_id: &str,
    evidence_source: &EvidenceSource,
) -> Result<IngestResult> {
    let start = Instant::now();

    let result = do_ingestion(evidence_source).await?;

    let elapsed = start.elapsed();
    tracing::Span::current()
        .record("bytes_total", result.bytes_read)
        .record("duration_ms", elapsed.as_millis() as u64);

    metrics::counter!("ingest.bytes_total", result.bytes_read as u64);
    metrics::histogram!("ingest.duration_ms", elapsed.as_millis() as f64);
    metrics::counter!("ingest.sources_processed", 1);

    Ok(result)
}
```

### 4.2 Parser Performance Tracking

Each parser in the rayon parallel pool reports granular metrics:

| Metric | Type | Unit | Description |
|--------|------|------|-------------|
| `parser.duration_ms` | Histogram | ms | Wall-clock time per parser execution |
| `parser.events_emitted` | Counter | events | Timeline events produced |
| `parser.bytes_processed` | Counter | bytes | Input data consumed |
| `parser.errors` | Counter | errors | Parse failures (non-fatal) |
| `parser.events_per_sec` | Gauge | events/s | Throughput (computed) |
| `parser.bytes_per_sec` | Gauge | bytes/s | I/O throughput (computed) |

### 4.3 Throughput Metrics

```sql
-- Query: Parser throughput comparison for current case
SELECT
    parser_id,
    SUM(events_emitted) AS total_events,
    SUM(bytes_processed) AS total_bytes,
    AVG(duration_ms) AS avg_duration_ms,
    SUM(events_emitted) / (SUM(duration_ms) / 1000.0) AS events_per_sec,
    SUM(bytes_processed) / (SUM(duration_ms) / 1000.0) AS bytes_per_sec
FROM parser_metrics
WHERE case_id = ?
GROUP BY parser_id
ORDER BY total_events DESC;
```

---

## 5. TARR Instrumentation

### 5.1 Automated Stage Timing

TARR (Time-to-Attorney-Ready Report) is the North Star metric. Every pipeline stage's contribution to TARR is automatically tracked.

```rust
// src/observability/tarr.rs

use duckdb::Connection;
use std::time::Instant;

pub struct TarrTracker {
    case_id: String,
    case_start: Instant,
    conn: Connection,
}

#[derive(Debug, Clone, Copy)]
pub enum TarrStage {
    Ingest,          // Target: 2 minutes
    Parse,           // Target: 8 minutes
    Correlate,       // Target: 5 minutes
    Intelligence,    // Target: 15 minutes (optional, AI-assisted)
    ReportDraft,     // Target: 30 minutes (narrative generation)
    ExaminerReview,  // Target: 60 minutes (human review + annotation)
    ReportFinalize,  // Target: 10 minutes (final render + hash)
}

impl TarrTracker {
    pub fn new(case_id: &str, tarr_db_path: &Path) -> Self {
        let conn = Connection::open(tarr_db_path).unwrap();
        Self {
            case_id: case_id.to_string(),
            case_start: Instant::now(),
            conn,
        }
    }

    pub fn record_stage(&self, stage: TarrStage, start: Instant, end: Instant) {
        let stage_duration = end.duration_since(start);
        let cumulative = end.duration_since(self.case_start);

        self.conn.execute(
            "INSERT INTO tarr_measurements VALUES (
                current_timestamp, ?, ?, ?, ?, ?, ?
            )",
            params![
                self.case_id,
                stage.as_str(),
                start.elapsed().as_millis() as i64,
                end.elapsed().as_millis() as i64,
                stage_duration.as_millis() as f64,
                cumulative.as_millis() as f64,
            ],
        ).unwrap();

        tracing::info!(
            case_id = %self.case_id,
            stage = stage.as_str(),
            stage_duration_ms = stage_duration.as_millis(),
            cumulative_ms = cumulative.as_millis(),
            "TARR stage completed"
        );
    }

    pub fn finalize(&self) -> TarrResult {
        let total_ms = self.case_start.elapsed().as_millis() as f64;
        let target_ms = 4.0 * 60.0 * 60.0 * 1000.0; // 4 hours

        TarrResult {
            case_id: self.case_id.clone(),
            total_duration_ms: total_ms,
            target_ms,
            met_target: total_ms <= target_ms,
            reduction_vs_baseline: 1.0 - (total_ms / (16.0 * 60.0 * 60.0 * 1000.0)),
        }
    }
}
```

### 5.2 TARR Budget Tracking

| TARR Stage | Budget | Metric | Alert If Exceeds |
|------------|--------|--------|------------------|
| Ingest | 2 min | `tarr.ingest.duration_ms` | 5 min |
| Parse | 8 min | `tarr.parse.duration_ms` | 15 min |
| Correlate | 5 min | `tarr.correlate.duration_ms` | 10 min |
| Intelligence | 15 min | `tarr.intel.duration_ms` | 30 min |
| Report Draft | 30 min | `tarr.report_draft.duration_ms` | 60 min |
| Examiner Review | 60 min | `tarr.review.duration_ms` | 120 min (warning only) |
| Report Finalize | 10 min | `tarr.finalize.duration_ms` | 20 min |
| **Total TARR** | **< 4 hours** | `tarr.total_duration_ms` | **4 hours** |

### 5.3 TARR Queries

```sql
-- TARR breakdown for a specific case
SELECT
    stage,
    stage_duration_ms,
    cumulative_ms,
    ROUND(stage_duration_ms / 60000.0, 1) AS stage_minutes,
    ROUND(cumulative_ms / 60000.0, 1) AS cumulative_minutes
FROM tarr_measurements
WHERE case_id = ?
ORDER BY stage_start_ms;

-- TARR trend across cases (are we improving?)
SELECT
    case_id,
    MAX(cumulative_ms) / 60000.0 AS total_minutes,
    CASE WHEN MAX(cumulative_ms) <= 14400000 THEN 'MET' ELSE 'MISSED' END AS target_status
FROM tarr_measurements
GROUP BY case_id
ORDER BY timestamp DESC
LIMIT 20;

-- Stage-level bottleneck identification
SELECT
    stage,
    AVG(stage_duration_ms) / 60000.0 AS avg_minutes,
    MAX(stage_duration_ms) / 60000.0 AS max_minutes,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY stage_duration_ms) / 60000.0 AS p95_minutes
FROM tarr_measurements
GROUP BY stage
ORDER BY avg_minutes DESC;
```

---

## 6. Forensic Audit & Chain of Custody

### 6.1 Audit Requirements

Forensic evidence handling requires defensible chain-of-custody documentation. Every automated action and examiner interaction is recorded in a tamper-evident log.

| Requirement | Implementation |
|-------------|----------------|
| Who | `examiner_id` from case config or OS username |
| What | `AuditAction` enum (evidence ingested, parser run, report generated, etc.) |
| When | UTC timestamp with millisecond precision |
| Integrity | SHA-256 hash chain linking each entry to its predecessor |
| Non-repudiation | Optional GPG signature on audit file at case close |
| Portability | JSONL format, one entry per line, readable by any tool |

### 6.2 Hash Chain Implementation

```rust
// Each audit entry's hash depends on the previous entry:
//
// entry[0].hash = SHA-256("0|2026-03-20T14:00:00Z|CaseOpened|...|GENESIS")
// entry[1].hash = SHA-256("1|2026-03-20T14:00:01Z|EvidenceIngested|...|{entry[0].hash}")
// entry[N].hash = SHA-256("N|timestamp|action|detail|{entry[N-1].hash}")
//
// Verification: replay the chain and confirm each hash matches.
// Any tampering breaks the chain from the modification point forward.

pub fn verify_audit_chain(audit_path: &Path) -> Result<AuditVerification> {
    let file = File::open(audit_path)?;
    let reader = BufReader::new(file);
    let mut expected_prev_hash = "GENESIS".to_string();
    let mut entry_count = 0;

    for line in reader.lines() {
        let entry: AuditEntry = serde_json::from_str(&line?)?;

        if entry.previous_hash != expected_prev_hash {
            return Ok(AuditVerification {
                valid: false,
                entries_verified: entry_count,
                failure_at: Some(entry.sequence_number),
            });
        }

        let computed_hash = compute_entry_hash(&entry);
        if computed_hash != entry.entry_hash {
            return Ok(AuditVerification {
                valid: false,
                entries_verified: entry_count,
                failure_at: Some(entry.sequence_number),
            });
        }

        expected_prev_hash = entry.entry_hash.clone();
        entry_count += 1;
    }

    Ok(AuditVerification {
        valid: true,
        entries_verified: entry_count,
        failure_at: None,
    })
}
```

### 6.3 Evidence Integrity Tracking

```rust
// Every evidence source is hashed at ingestion and verified before processing.

pub struct EvidenceIntegrity {
    pub source_path: String,
    pub sha256_hash: String,
    pub file_size_bytes: u64,
    pub verified_at: DateTime<Utc>,
    pub verification_result: VerificationResult,
}

pub enum VerificationResult {
    Verified,                          // Hash matches
    FirstSeen { hash: String },        // Initial registration
    Mismatch { expected: String, actual: String },  // Integrity violation
}

// On mismatch, emit:
// tracing::error!(
//     check_type = "evidence_integrity",
//     expected_hash = %expected,
//     actual_hash = %actual,
//     artifact_path = %path,
//     "INTEGRITY VIOLATION: Evidence file hash mismatch"
// );
```

---

## 7. PII Sanitization

### 7.1 Forensic Context

Forensic data contains sensitive information: usernames, SIDs, email addresses, file paths with personal data, browser history URLs, and registry values with credentials. Sanitization must balance investigative utility with data protection.

### 7.2 Sanitization Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `strict` | Hash all PII fields, redact file content from logs | Multi-tenant / shared infrastructure |
| `moderate` | Hash external PII, preserve case-internal identifiers | Default for case processing |
| `permissive` | Log everything including PII | Local development, single-examiner workstation |

### 7.3 PII Field Classification

| Category | Fields | Sanitization (strict/moderate) |
|----------|--------|-------------------------------|
| **Examiner Identity** | `examiner_id`, `examiner_email` | Hash (strict), Preserve (moderate) |
| **Evidence Subject** | `user_account`, `hostname`, `sid` | Hash (strict), Hash (moderate) |
| **File Paths** | `artifact_path`, `source_path` | Redact user segments (strict), Preserve (moderate) |
| **Content** | `description`, `metadata` JSON values | Truncate + hash (strict), Preserve (moderate) |
| **Network** | IP addresses, URLs from browser history | Hash (strict), Hash (moderate) |
| **Credentials** | Registry credential entries, cached passwords | Always redact in logs, never log plaintext |

### 7.4 Implementation

```rust
// src/observability/sanitization.rs

use ring::digest::{digest, SHA256};

#[derive(Debug, Clone, Copy)]
pub enum SanitizationMode {
    Strict,
    Moderate,
    Permissive,
}

pub struct Sanitizer {
    mode: SanitizationMode,
}

impl Sanitizer {
    pub fn sanitize_field(&self, category: PiiCategory, value: &str) -> String {
        match self.mode {
            SanitizationMode::Permissive => value.to_string(),
            SanitizationMode::Moderate => match category {
                PiiCategory::ExaminerIdentity => value.to_string(),
                PiiCategory::EvidenceSubject => self.hash_value(value),
                PiiCategory::FilePath => self.redact_user_segments(value),
                PiiCategory::Content => value.to_string(),
                PiiCategory::Network => self.hash_value(value),
                PiiCategory::Credential => "[REDACTED]".to_string(),
            },
            SanitizationMode::Strict => match category {
                PiiCategory::Credential => "[REDACTED]".to_string(),
                PiiCategory::Content => self.truncate_and_hash(value, 32),
                _ => self.hash_value(value),
            },
        }
    }

    fn hash_value(&self, value: &str) -> String {
        let hash = digest(&SHA256, value.as_bytes());
        format!("sha256:{}", hex::encode(&hash.as_ref()[..8]))
    }

    fn redact_user_segments(&self, path: &str) -> String {
        // Replace /Users/xxx/ or C:\Users\xxx\ with /Users/[REDACTED]/
        let re = regex::Regex::new(r"(?i)(users[/\\])[^/\\]+").unwrap();
        re.replace_all(path, "${1}[REDACTED]").to_string()
    }

    fn truncate_and_hash(&self, value: &str, max_len: usize) -> String {
        if value.len() <= max_len {
            self.hash_value(value)
        } else {
            format!("{}...{}", &value[..max_len], self.hash_value(value))
        }
    }
}
```

---

## 8. Error Tracking & Diagnostics

### 8.1 Error Classification

| Error Category | Severity | Action | Example |
|----------------|----------|--------|---------|
| **Parser Failure** | Warning | Skip artifact, continue pipeline | Corrupted EVTX file |
| **Corrupted Data** | Warning | Log integrity violation, continue | Truncated MFT record |
| **Integrity Violation** | Critical | Halt processing, alert examiner | Evidence hash mismatch |
| **Resource Exhaustion** | Error | Degrade gracefully, alert | DuckDB out of disk space |
| **Configuration Error** | Error | Fail fast with clear message | Invalid case config |
| **LLM Failure** | Warning | Fall back to AI-free mode | Ollama timeout |
| **Report Generation Failure** | Error | Retry once, then alert | Template rendering error |

### 8.2 Structured Error Events

```rust
// All errors emit structured tracing events with consistent fields:

tracing::error!(
    error_category = "parser_failure",
    parser_id = "issen-parser-evtx",
    artifact_path = "/evidence/Windows/System32/winevt/Logs/Security.evtx",
    error_message = "Invalid record header at offset 0x1A3F00",
    is_corruption = true,
    recoverable = true,
    records_before_error = 14832,
    "Parser encountered corrupted record, skipping remainder"
);
```

### 8.3 Error Aggregation Queries

```sql
-- Error summary for current case
SELECT
    metric_name AS error_category,
    COUNT(*) AS occurrences,
    MIN(timestamp) AS first_seen,
    MAX(timestamp) AS last_seen
FROM pipeline_metrics
WHERE case_id = ? AND metric_name LIKE 'error.%'
GROUP BY metric_name
ORDER BY occurrences DESC;

-- Parser reliability over time
SELECT
    parser_id,
    COUNT(*) AS total_runs,
    SUM(error_count) AS total_errors,
    ROUND(1.0 - (SUM(error_count)::DOUBLE / NULLIF(SUM(events_emitted), 0)), 4) AS reliability
FROM parser_metrics
GROUP BY parser_id
ORDER BY reliability ASC;
```

---

## 9. North Star Instrumentation

### 9.1 TARR as Primary Dashboard Metric

The North Star metric (TARR) is prominently tracked and displayed. Every observability view anchors on TARR performance.

```rust
// src/observability/northstar.rs

pub struct NorthStarMetrics {
    /// Primary: Time-to-Attorney-Ready Report
    pub tarr_duration_ms: f64,
    pub tarr_target_ms: f64,       // 4 hours = 14_400_000 ms
    pub tarr_met: bool,

    /// Input metric: Parse-to-Timeline Latency
    pub parse_to_timeline_ms: f64,
    pub parse_to_timeline_target_ms: f64,   // 10 min = 600_000 ms

    /// Input metric: Findings-to-Narrative Time
    pub findings_to_narrative_ms: f64,
    pub findings_to_narrative_target_ms: f64, // 2 hours = 7_200_000 ms

    /// Input metric: Report Acceptance Rate (tracked across cases)
    pub report_acceptance_rate: f64,
    pub report_acceptance_target: f64,        // 0.80 (80%)

    /// Health metrics
    pub pipeline_error_rate: f64,
    pub parser_reliability: f64,
}

pub fn calculate_northstar_metrics(
    conn: &Connection,
    case_id: Option<&str>,
) -> NorthStarMetrics {
    // Query tarr_measurements and pipeline_metrics tables
    // Aggregate across case_id if provided, or all recent cases
    // Return populated NorthStarMetrics
    todo!()
}
```

### 9.2 Input Metric Collection Points

| Input Metric | Collection Point | Calculation |
|-------------|-----------------|-------------|
| Parse-to-Timeline Latency | `ingest.start` to `timeline.write` (last batch) | `timeline_write.end_ms - ingest.start_ms` |
| Findings-to-Narrative Time | `correlate.end` to `report.complete` | `report_complete.end_ms - correlate.end_ms` |
| Report Acceptance Rate | Manual feedback entry (examiner marks report as accepted/revised) | `accepted_reports / total_reports` over rolling 30-day window |

### 9.3 TARR Contribution Waterfall

For each case, generate a waterfall showing each stage's contribution to TARR:

```
Case CASE-2026-0042: TARR = 3h 12m (Target: < 4h) [MET]

Ingest       |##              |   1.5 min  (0.8%)
Parse        |########        |   7.2 min  (3.7%)
Correlate    |#####           |   4.8 min  (2.5%)
Intelligence |###########     |  12.1 min  (6.3%)
Report Draft |########################|  28.4 min (14.7%)
Review       |##################################################|  118.2 min (61.4%)
Finalize     |###             |   4.1 min  (2.1%)
             0               30              60              90             120 min

Bottleneck: Examiner Review (61.4% of TARR)
Recommendation: Improve report draft quality to reduce review cycles
```

---

## 10. Dashboards & Alerts

### 10.1 TUI Dashboard (issen-tui)

The primary dashboard is an interactive TUI built with `ratatui`, providing real-time pipeline monitoring without leaving the terminal.

```yaml
# TUI Dashboard Layout

panels:
  - name: "TARR Status"
    position: top-center
    width: full
    content:
      - Current case TARR elapsed vs. target (progress bar)
      - Stage-by-stage timing (live updates during processing)
      - Historical TARR trend (last 10 cases, sparkline)

  - name: "Pipeline Progress"
    position: left
    width: 40%
    content:
      - Active pipeline stage indicator
      - Parser execution progress (X/Y parsers complete)
      - Events emitted counter (live)
      - Bytes processed counter (live)
      - Estimated time remaining

  - name: "Parser Performance"
    position: right-top
    width: 60%
    content:
      - Per-parser events/sec (bar chart)
      - Per-parser bytes/sec (bar chart)
      - Error count by parser (highlighted if > 0)

  - name: "Error Feed"
    position: right-bottom
    width: 60%
    content:
      - Scrolling list of warnings and errors
      - Color-coded by severity (yellow=warning, red=error, magenta=critical)
      - Corruption and integrity alerts pinned to top

  - name: "Resource Usage"
    position: bottom
    width: full
    content:
      - DuckDB disk usage
      - Memory consumption
      - CPU utilization (per-core, rayon thread pool)
```

### 10.2 Key Metrics Summary

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `tarr.total_duration_ms` | Total TARR for current case | > 14,400,000 ms (4 hours) |
| `tarr.parse_to_timeline_ms` | Parse-to-Timeline input metric | > 600,000 ms (10 minutes) |
| `pipeline.error_rate` | Errors / total events processed | > 1% |
| `parser.failure_count` | Parsers that failed completely | > 0 |
| `integrity.violation_count` | Evidence integrity check failures | > 0 (critical) |
| `parser.events_per_sec` | Aggregate parser throughput | < 1,000 events/sec (degraded) |
| `duckdb.disk_usage_bytes` | Timeline database size | > 90% of available disk |
| `llm.latency_p95` | Ollama response time (95th pct) | > 30,000 ms |
| `report.generation_duration_ms` | Time to render final report | > 600,000 ms (10 minutes) |

### 10.3 Alert Delivery (Local)

Since cloud alerting is unavailable in air-gapped environments:

| Alert Channel | Mechanism | Use Case |
|---------------|-----------|----------|
| TUI Notification | In-app alert banner in issen-tui | Real-time during processing |
| Desktop Notification | `notify-rust` crate (OS-native) | Background processing alerts |
| Log File | `WARN`/`ERROR` level in structured log | Post-processing review |
| Audit Entry | Critical events recorded in audit chain | Forensic defensibility |
| Exit Code | Non-zero exit on critical failures | CI/automation integration |

---

## 11. Performance Profiling

### 11.1 Large Evidence Container Profiling

For evidence sets exceeding 50GB, Issen provides built-in profiling:

```rust
// Enable with: RAPIDTRIAGE_PROFILE=1 issen-cli ingest --case CASE-ID /evidence

// Produces:
// - Flame graph (via tracing-flame or pprof-rs)
// - Per-parser memory high-water marks
// - DuckDB query plan analysis for slow timeline queries
// - rayon thread pool utilization report

pub struct ProfilingConfig {
    pub enabled: bool,
    pub flame_graph_path: Option<PathBuf>,
    pub memory_tracking: bool,
    pub query_plans: bool,
}
```

### 11.2 Benchmark Metrics

| Benchmark | Measurement | Target |
|-----------|-------------|--------|
| EVTX parsing (1M events) | events/sec | > 100,000 |
| MFT parsing (500K records) | records/sec | > 200,000 |
| DuckDB timeline insert | events/sec (batch) | > 500,000 |
| DuckDB time-range query | latency (1M events, 1-hour window) | < 100 ms |
| Full pipeline (50GB evidence) | end-to-end | < 10 minutes |
| Report generation (HTML, 10K events) | render time | < 30 seconds |

---

*Document generated by North Star Advisor*
