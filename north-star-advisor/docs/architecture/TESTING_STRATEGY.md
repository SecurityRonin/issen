# Issen: Testing Strategy

> **Parent**: [ARCHITECTURE_BLUEPRINT.md](../ARCHITECTURE_BLUEPRINT.md)
> **Created**: 2026-03-20
> **Status**: Active

Comprehensive testing strategy for a forensic triage platform where correctness is non-negotiable. Every parsed timestamp, every correlated event, and every generated report may be scrutinized under Daubert challenge. This document defines test categories, configurations, golden datasets, component tests, integration tests, performance benchmarks, and CI/CD integration -- all tailored to Issen's Rust-native, hexagonal architecture.

---

## 1. Test Categories

### 1.1 Test Pyramid (Forensic-Adapted)

```
                        ┌──────────────┐
                        │  NIST CFTT   │  ← External validation suites
                       ─┴──────────────┴─
                      ┌──────────────────┐
                      │   E2E / Report   │  ← Evidence-to-deliverable flows
                     ─┴──────────────────┴─
                   ┌────────────────────────┐
                   │  Pipeline Integration  │  ← Multi-layer ingestion, DuckDB round-trip
                  ─┴────────────────────────┴─
                ┌────────────────────────────────┐
                │  Property & Fuzz (proptest +   │  ← Parser robustness against
                │       cargo-fuzz)              │     malformed / adversarial input
               ─┴────────────────────────────────┴─
             ┌────────────────────────────────────────┐
             │        Parser Unit / Golden Dataset    │  ← Known-good artifacts
            ─┴────────────────────────────────────────┴─
          ┌────────────────────────────────────────────────┐
          │          Core Unit (issen-core pure logic)        │  ← Event types, schemas, traits
         ─┴────────────────────────────────────────────────┴─
```

### 1.2 Coverage Targets

| Category | Target | Focus | Rationale |
|----------|--------|-------|-----------|
| Core Unit (`issen-core`) | 95% | Pure functions, event types, schema validation | Side-effect-free core; no excuses for gaps |
| Parser Unit | 90% | Each parser against known-good artifacts | Existing `tl` baseline: 88% -- maintain or exceed |
| Property/Fuzz | N/A (hours) | Continuous fuzzing budget per parser | Discover edge cases, not line coverage |
| Pipeline Integration | 80% | Layer 0-4 ingestion, DuckDB writes, query | Multi-component data path correctness |
| Report Integration | 75% | HTML/DOCX generation, chain-of-custody metadata | Attorney-ready output must be verifiable |
| E2E | Critical paths | Evidence ingest -> timeline -> report | End-to-end TARR measurement |
| NIST CFTT | Pass/Fail | External validation suite compliance | Daubert admissibility |

**Overall target: >= 88% line coverage** (matching existing `tl` codebase baseline).

### 1.3 Daubert Compliance Requirements

Every test execution produces auditable records for expert witness testimony:

| Daubert Factor | Testing Response |
|----------------|-----------------|
| **Testable / Falsifiable** | Golden dataset with known-correct outputs; any failure is a measurable deviation |
| **Peer Review** | Open-source parsers (Apache 2.0) subject to community review; test fixtures published |
| **Known Error Rate** | CI tracks false-positive and false-negative rates per parser across golden datasets |
| **Standards Compliance** | NIST CFTT test suite integration; results archived per release |
| **General Acceptance** | Test methodology follows SWGDE best practices and ASTM E2916 |

---

## 2. Test Configuration

### 2.1 Rust Test Framework Configuration

Issen uses Rust's built-in test framework augmented with specialized crates:

```toml
# Cargo.toml (workspace root) -- test dependencies
[workspace.dependencies]
# Property-based testing
proptest = "1.4"
proptest-derive = "0.4"

# Fuzzing (separate cargo-fuzz targets)
arbitrary = { version = "1", features = ["derive"] }

# Performance benchmarks
criterion = { version = "0.5", features = ["html_reports"] }

# Snapshot testing for report output
insta = { version = "1.38", features = ["yaml", "json"] }

# Test fixtures / temp directories
tempfile = "3.10"
assert_fs = "1.1"

# Mocking for trait-based DI
mockall = "0.12"

# Coverage
# cargo-llvm-cov (installed via cargo install)

# Golden dataset deserialization
serde_yaml = "0.9"
```

### 2.2 Test Directory Structure

```
tests/
├── unit/                          # Per-crate unit tests (also in src/ via #[cfg(test)])
│   ├── core/                      # issen-core pure logic tests
│   ├── parsers/                   # Per-parser correctness tests
│   │   ├── usnjrnl_tests.rs
│   │   ├── mft_tests.rs
│   │   ├── evtx_tests.rs
│   │   └── ...
│   └── timeline/                  # DuckDB schema and query tests
├── integration/                   # Multi-crate integration tests
│   ├── pipeline_tests.rs          # Layer 0-4 end-to-end
│   ├── timeline_roundtrip.rs      # Parse -> store -> query -> verify
│   ├── report_generation.rs       # Timeline -> HTML/DOCX output
│   └── correlation_tests.rs       # Cross-artifact correlation
├── golden/                        # Golden dataset tests
│   ├── golden_runner.rs           # Parameterized test runner
│   └── datasets/                  # YAML golden case definitions
│       ├── usnjrnl.yml
│       ├── mft.yml
│       ├── evtx.yml
│       └── pipeline_e2e.yml
├── fuzz/                          # cargo-fuzz targets (separate workspace)
│   ├── fuzz_usnjrnl.rs
│   ├── fuzz_mft.rs
│   ├── fuzz_evtx.rs
│   ├── fuzz_ewf.rs
│   └── fuzz_registry.rs
├── property/                      # proptest strategies and tests
│   ├── event_properties.rs
│   ├── timestamp_properties.rs
│   └── parser_roundtrip.rs
├── benches/                       # criterion benchmarks
│   ├── parser_throughput.rs
│   ├── timeline_query.rs
│   ├── report_generation.rs
│   └── e2e_pipeline.rs
├── fixtures/                      # Test data management
│   ├── README.md                  # Fixture provenance documentation
│   ├── synthetic/                 # Programmatically generated test artifacts
│   │   ├── generators/            # Rust programs that produce test data
│   │   └── artifacts/             # Generated output (gitignored, rebuilt in CI)
│   ├── reference/                 # NIST / public-domain reference samples
│   │   ├── cftt/                  # NIST CFTT test images (downloaded in CI)
│   │   └── public/                # Public-domain forensic samples
│   ├── minimal/                   # Hand-crafted minimal valid artifacts (committed)
│   │   ├── usnjrnl_v2_3records.bin
│   │   ├── mft_single_entry.bin
│   │   ├── evtx_single_record.evtx
│   │   └── ...
│   └── snapshots/                 # insta snapshot files
└── nist_cftt/                     # NIST CFTT validation runner
    ├── cftt_runner.rs
    └── expected_results/
```

### 2.3 Test Setup and Shared Utilities

```rust
// tests/common/mod.rs -- Shared test infrastructure

use tempfile::TempDir;
use duckdb::Connection;
use rt_core::timeline::TimelineEvent;

/// Create an ephemeral DuckDB instance with the timeline schema applied.
/// Destroyed when TempDir drops.
pub fn setup_test_timeline() -> (Connection, TempDir) {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("test_timeline.duckdb");
    let conn = Connection::open(&db_path).expect("open DuckDB");
    rt_timeline::schema::create_tables(&conn).expect("create schema");
    (conn, dir)
}

/// Load golden dataset from YAML file.
pub fn load_golden_dataset(path: &str) -> Vec<GoldenTestCase> {
    let content = std::fs::read_to_string(path).expect("read golden dataset");
    serde_yaml::from_str(&content).expect("parse golden dataset")
}

/// Assert that two event sets match, ignoring event_id assignment order.
/// Compares on (timestamp_ns, source_type, artifact_path, message).
pub fn assert_events_equivalent(actual: &[TimelineEvent], expected: &[TimelineEvent]) {
    let normalize = |events: &[TimelineEvent]| -> Vec<EventFingerprint> {
        let mut fps: Vec<_> = events.iter().map(EventFingerprint::from).collect();
        fps.sort();
        fps
    };
    assert_eq!(normalize(actual), normalize(expected),
        "Timeline events do not match expected golden output");
}

/// Verify chain-of-custody metadata in generated reports.
pub fn assert_chain_of_custody(report_path: &std::path::Path) {
    let content = std::fs::read_to_string(report_path).unwrap();
    assert!(content.contains("SHA-256"), "Report missing hash verification");
    assert!(content.contains("Processing Audit Log"), "Report missing audit log");
}
```

---

## 3. Golden Datasets

### 3.1 Golden Dataset Structure

Golden datasets are YAML files that define input artifacts and expected parser output. They serve as the ground truth for Daubert compliance -- every golden case documents a known-correct interpretation of a forensic artifact.

```yaml
# tests/golden/datasets/usnjrnl.yml

metadata:
  parser: "issen-parser-usnjrnl"
  artifact_type: "USN Journal ($UsnJrnl:$J)"
  version: "2.0"
  provenance: "Synthetically generated by tests/fixtures/synthetic/generators/gen_usnjrnl.rs"
  last_validated: "2026-03-20"

cases:
  - id: "usnjrnl-001"
    category: "happy_path"
    description: "Standard file creation event with expected MACB timestamps"
    priority: "critical"
    input:
      fixture: "fixtures/minimal/usnjrnl_v2_3records.bin"
      config:
        volume_offset: 0
    expected:
      event_count: 3
      events:
        - timestamp_ns: 1710892800000000000  # 2024-03-20T00:00:00Z
          timestamp_desc: "USN_REASON_FILE_CREATE"
          source_type: "USN"
          artifact_path: "Users/test/Documents/report.docx"
          message: "File created: report.docx"
      constraints:
        all_timestamps_utc: true
        no_duplicate_event_ids: true

  - id: "usnjrnl-002"
    category: "edge_case"
    description: "Truncated journal page boundary -- parser must handle partial records"
    priority: "high"
    input:
      fixture: "fixtures/minimal/usnjrnl_v2_truncated.bin"
    expected:
      event_count: 2
      parse_stats:
        records_parsed: 2
        records_skipped: 1
        errors: 0
      constraints:
        must_not_panic: true

  - id: "usnjrnl-003"
    category: "adversarial"
    description: "Journal with corrupted reason flags -- must not produce false events"
    priority: "critical"
    input:
      fixture: "fixtures/minimal/usnjrnl_v2_corrupt_flags.bin"
    expected:
      constraints:
        must_not_panic: true
        must_not_contain: ["UNKNOWN_REASON"]
        error_count_max: 5
```

### 3.2 Golden Dataset Categories

| Category | Purpose | Minimum Cases | Parser Coverage |
|----------|---------|---------------|-----------------|
| Happy Path | Correct parsing of well-formed artifacts | 5 per parser | All 11 first-party parsers |
| Edge Cases | Boundary conditions (truncation, page boundaries, max values) | 5 per parser | All parsers |
| Adversarial | Corrupted, malformed, or crafted-to-confuse input | 3 per parser | All parsers |
| Cross-Version | Different artifact format versions (USN v2 vs v3, EVTX v3.1) | 2 per parser | Where applicable |
| Large Scale | Performance-relevant sizes (100K+ records) | 1 per parser | Top 5 parsers |
| NIST Reference | Mapped from NIST CFTT expected results | Per CFTT suite | As available |

**Minimum total: 60+ golden cases** across all parsers.

### 3.3 Test Fixture Management

Forensic test data requires careful handling -- real evidence must never enter the repository.

```
Fixture Tiers:

1. COMMITTED (fixtures/minimal/)
   - Hand-crafted binary files, typically < 10KB
   - Contain NO real PII, case data, or evidence
   - Documented provenance in fixture README
   - Git LFS for any file > 100KB

2. GENERATED (fixtures/synthetic/)
   - Rust generator programs committed; output artifacts gitignored
   - CI rebuilds from generators on each run (deterministic via fixed seeds)
   - Generators produce known-correct output for golden comparison
   - Example: gen_usnjrnl --records 1000 --seed 42 > artifacts/usnjrnl_1k.bin

3. DOWNLOADED (fixtures/reference/)
   - NIST CFTT images and public-domain samples
   - Downloaded by CI setup step (cached in GitHub Actions)
   - URLs and SHA-256 checksums committed in fixtures/reference/manifest.yml
   - Never committed to repo (gitignored)

4. PRIVATE (not in repo)
   - Real-world samples for manual validation only
   - Used by maintainers on local machines
   - Never referenced in automated tests
   - Documented in CONTRIBUTING.md as optional validation
```

```yaml
# fixtures/reference/manifest.yml
sources:
  - name: "NIST CFTT NTFS Reference Image"
    url: "https://www.cftt.nist.gov/disk_imaging/ntfs_ref.E01"
    sha256: "abc123..."  # actual hash
    size_bytes: 52428800
    download_dir: "fixtures/reference/cftt/"

  - name: "Digital Corpora M57 Sample"
    url: "https://downloads.digitalcorpora.org/corpora/scenarios/2009-m57-patents/..."
    sha256: "def456..."
    download_dir: "fixtures/reference/public/"
```

### 3.4 AI Evaluation Tests

> See also [INTELLIGENCE_LAYER.md](INTELLIGENCE_LAYER.md) for detailed evaluation framework.

#### Retrieval Quality Tests (RAG -- Modular RAG per architecture)

| Test | Target | Method |
|------|--------|--------|
| Retrieval precision (case-specific) | >= 0.85 | Query with known timeline events, verify top-5 results contain expected events |
| Context relevance (reference store) | >= 0.80 | ATT&CK technique query returns relevant technique descriptions |
| Answer faithfulness | >= 0.90 | Every claim in ForensicLLM output must cite a verifiable event_id |
| Grounding rate | 100% critical | No hallucinated timestamps or artifact paths in reports |

#### ForensicLLM Output Tests

```rust
#[cfg(test)]
mod forensic_llm_tests {
    use rt_intel::forensic_llm::ForensicLLM;
    use rt_core::timeline::TimelineEvent;

    /// ForensicLLM must ground every claim to a specific event_id.
    #[test]
    fn output_contains_only_grounded_claims() {
        let events = load_golden_timeline("fixtures/golden/timeline_sample.json");
        let llm = ForensicLLM::new_test_mode(); // deterministic mock
        let narrative = llm.generate_narrative(&events);

        for claim in narrative.claims() {
            assert!(
                claim.cited_event_ids().iter().all(|id| events.contains_id(*id)),
                "Claim '{}' references event_id not in input timeline",
                claim.text()
            );
        }
    }

    /// AI-free mode must produce equivalent structure (without narrative).
    #[test]
    fn ai_free_mode_produces_valid_report() {
        let events = load_golden_timeline("fixtures/golden/timeline_sample.json");
        let report = generate_report_ai_free(&events);

        assert!(report.timeline_table().is_some());
        assert!(report.chain_of_custody().is_some());
        // Narrative section absent in AI-free mode
        assert!(report.ai_narrative().is_none());
    }
}
```

#### Evaluation Pyramid Integration

Tiered evaluation approach for the intelligence layer:

1. **Unit** (no LLM): Deterministic tests on RAG retrieval logic, embedding indexing, Sigma rule compilation, YARA-X pattern matching
2. **Integration** (mock LLM): Pipeline tests with `ForensicLLM::new_test_mode()` returning canned structured output
3. **Tool eval** (domain evaluators): Custom evaluators scoring grounding rate, citation accuracy, ATT&CK mapping correctness against seeded case data
4. **Agent eval** (real LLM via Ollama): End-to-end narrative generation with structured output validation; run nightly, not on every PR

---

## 4. Component Unit Tests

### 4.1 Parser Unit Test Pattern

Every first-party parser follows an identical test structure. The `ForensicParser` trait enables uniform testing.

```rust
// tests/unit/parsers/usnjrnl_tests.rs

use rt_core::plugin::{ForensicParser, ArtifactType};
use rt_parser_usnjrnl::UsnJrnlParser;
use std::io::Cursor;

#[test]
fn parses_known_good_usnjrnl_v2() {
    let parser = UsnJrnlParser::new();
    let fixture = include_bytes!("../../fixtures/minimal/usnjrnl_v2_3records.bin");
    let mut events = Vec::new();
    let stats = parser.parse(
        &mut Cursor::new(fixture),
        &mut |event| events.push(event),
    ).expect("parse should succeed");

    assert_eq!(events.len(), 3);
    assert_eq!(stats.records_parsed, 3);
    assert_eq!(stats.errors, 0);

    // Verify first event matches golden expectation
    assert_eq!(events[0].source_type, "USN");
    assert_eq!(events[0].timestamp_desc, "USN_REASON_FILE_CREATE");
    assert!(events[0].artifact_path.contains("report.docx"));
}

#[test]
fn handles_truncated_input_without_panic() {
    let parser = UsnJrnlParser::new();
    let fixture = include_bytes!("../../fixtures/minimal/usnjrnl_v2_truncated.bin");
    let mut events = Vec::new();

    // Must not panic -- graceful degradation
    let result = parser.parse(
        &mut Cursor::new(fixture),
        &mut |event| events.push(event),
    );

    assert!(result.is_ok());
    let stats = result.unwrap();
    assert!(stats.records_skipped > 0, "Should report skipped records");
}

#[test]
fn reports_supported_artifact_types() {
    let parser = UsnJrnlParser::new();
    let types = parser.supported_artifacts();
    assert!(types.contains(&ArtifactType::UsnJournal));
}

#[test]
fn empty_input_returns_zero_events() {
    let parser = UsnJrnlParser::new();
    let mut events = Vec::new();
    let stats = parser.parse(
        &mut Cursor::new(&[] as &[u8]),
        &mut |event| events.push(event),
    ).expect("empty input should not error");

    assert_eq!(events.len(), 0);
    assert_eq!(stats.records_parsed, 0);
}
```

### 4.2 Core Logic Unit Tests (issen-core)

```rust
// issen-core/src/timeline/event.rs -- inline tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeline_event_ordering_by_timestamp() {
        let e1 = TimelineEvent::builder()
            .timestamp_ns(1000)
            .source_type("USN")
            .build();
        let e2 = TimelineEvent::builder()
            .timestamp_ns(2000)
            .source_type("MFT")
            .build();

        assert!(e1 < e2);
    }

    #[test]
    fn event_fingerprint_excludes_event_id() {
        let e1 = TimelineEvent::builder()
            .event_id(1)
            .timestamp_ns(1000)
            .message("test")
            .build();
        let e2 = TimelineEvent::builder()
            .event_id(999)
            .timestamp_ns(1000)
            .message("test")
            .build();

        assert_eq!(e1.fingerprint(), e2.fingerprint(),
            "Fingerprint should be content-based, not id-based");
    }

    #[test]
    fn nanosecond_precision_preserved() {
        // Forensic timestamps require nanosecond precision -- TIMESTAMP_NS
        let ts = 1710892800_123456789_u64; // 2024-03-20T00:00:00.123456789Z
        let event = TimelineEvent::builder()
            .timestamp_ns(ts)
            .build();

        assert_eq!(event.timestamp_ns(), ts);
        // Verify sub-second component preserved
        assert_eq!(event.timestamp_ns() % 1_000_000_000, 123456789);
    }

    #[test]
    fn record_hash_is_deterministic() {
        let event = TimelineEvent::builder()
            .timestamp_ns(1000)
            .source_type("USN")
            .message("file created")
            .build();

        let hash1 = event.record_hash();
        let hash2 = event.record_hash();
        assert_eq!(hash1, hash2, "Same content must produce same hash");
    }
}
```

### 4.3 Timeline Store Tests (issen-timeline)

```rust
// tests/unit/timeline/duckdb_store_tests.rs

use rt_timeline::store::TimelineStore;
use crate::common::setup_test_timeline;

#[test]
fn insert_and_query_round_trip() {
    let (conn, _dir) = setup_test_timeline();
    let store = TimelineStore::new(conn);

    let events = vec![
        test_event(1000, "USN", "file.txt", "File created"),
        test_event(2000, "MFT", "file.txt", "MFT entry allocated"),
        test_event(3000, "EVTX", "Security.evtx", "Logon event 4624"),
    ];

    store.insert_batch(&events).expect("insert batch");

    let queried = store.query_time_range(0, 4000).expect("query");
    assert_eq!(queried.len(), 3);
    assert_events_equivalent(&queried, &events);
}

#[test]
fn time_range_query_filters_correctly() {
    let (conn, _dir) = setup_test_timeline();
    let store = TimelineStore::new(conn);

    store.insert_batch(&vec![
        test_event(1000, "USN", "a.txt", "early"),
        test_event(5000, "USN", "b.txt", "middle"),
        test_event(9000, "USN", "c.txt", "late"),
    ]).unwrap();

    let result = store.query_time_range(4000, 6000).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].message, "middle");
}

#[test]
fn sqlite_export_preserves_all_events() {
    let (conn, dir) = setup_test_timeline();
    let store = TimelineStore::new(conn);

    let events = generate_test_events(100);
    store.insert_batch(&events).unwrap();

    let sqlite_path = dir.path().join("export.sqlite");
    store.export_sqlite(&sqlite_path).unwrap();

    // Verify via direct SQLite read
    let sqlite_conn = rusqlite::Connection::open(&sqlite_path).unwrap();
    let count: i64 = sqlite_conn
        .query_row("SELECT COUNT(*) FROM timeline_events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 100);
}

#[test]
fn handles_100k_events_within_latency_budget() {
    let (conn, _dir) = setup_test_timeline();
    let store = TimelineStore::new(conn);

    let events = generate_test_events(100_000);
    let start = std::time::Instant::now();
    store.insert_batch(&events).unwrap();
    let insert_time = start.elapsed();

    // Parse-to-Timeline target: < 10 minutes for 50GB evidence
    // 100K events should insert in < 5 seconds
    assert!(insert_time.as_secs() < 5,
        "100K event insert took {:?}, exceeds 5s budget", insert_time);

    let start = std::time::Instant::now();
    let _result = store.query_time_range(0, u64::MAX).unwrap();
    let query_time = start.elapsed();

    assert!(query_time.as_secs() < 2,
        "100K event full scan took {:?}, exceeds 2s budget", query_time);
}
```

---

## 5. Property-Based and Fuzz Testing

### 5.1 Property-Based Tests (proptest)

Property-based tests verify invariants that must hold for ALL inputs, not just golden examples. This is where forensic parser robustness is proven.

```rust
// tests/property/parser_roundtrip.rs

use proptest::prelude::*;
use rt_core::timeline::TimelineEvent;
use rt_parser_usnjrnl::UsnJrnlParser;

/// Strategy to generate arbitrary USN Journal records.
fn arb_usn_record() -> impl Strategy<Value = Vec<u8>> {
    // Generate valid USN_RECORD_V2 structures with arbitrary field values
    (
        any::<u32>(),              // record_length
        (2u16..=3u16),             // major_version
        any::<u64>(),              // file_reference_number
        any::<u64>(),              // parent_reference_number
        any::<u64>(),              // usn
        any::<u64>(),              // timestamp (FILETIME)
        any::<u32>(),              // reason flags
        any::<u32>(),              // source_info
        prop::collection::vec(any::<u8>(), 0..255), // filename bytes
    ).prop_map(|(_, ver, fref, pref, usn, ts, reason, src, name)| {
        build_usn_record(ver, fref, pref, usn, ts, reason, src, &name)
    })
}

proptest! {
    /// Parser must never panic on any well-structured input.
    #[test]
    fn parser_never_panics_on_valid_structure(records in prop::collection::vec(arb_usn_record(), 0..100)) {
        let input = concatenate_records(&records);
        let parser = UsnJrnlParser::new();
        let mut events = Vec::new();

        // Must not panic -- may return error, that is acceptable
        let _ = parser.parse(
            &mut std::io::Cursor::new(&input),
            &mut |event| events.push(event),
        );
    }

    /// All emitted timestamps must be valid (not in the future, not before 1601).
    #[test]
    fn all_timestamps_in_valid_range(records in prop::collection::vec(arb_usn_record(), 1..50)) {
        let input = concatenate_records(&records);
        let parser = UsnJrnlParser::new();
        let mut events = Vec::new();

        let _ = parser.parse(
            &mut std::io::Cursor::new(&input),
            &mut |event| events.push(event),
        );

        let min_ts = filetime_to_ns(1601, 1, 1); // Windows FILETIME epoch
        let max_ts = filetime_to_ns(2100, 1, 1); // Reasonable upper bound

        for event in &events {
            prop_assert!(event.timestamp_ns() >= min_ts,
                "Timestamp before FILETIME epoch: {}", event.timestamp_ns());
            prop_assert!(event.timestamp_ns() <= max_ts,
                "Timestamp unreasonably far in future: {}", event.timestamp_ns());
        }
    }

    /// Event count must be <= record count (parser cannot create events from nothing).
    #[test]
    fn event_count_bounded_by_input(records in prop::collection::vec(arb_usn_record(), 0..100)) {
        let record_count = records.len();
        let input = concatenate_records(&records);
        let parser = UsnJrnlParser::new();
        let mut events = Vec::new();

        let _ = parser.parse(
            &mut std::io::Cursor::new(&input),
            &mut |event| events.push(event),
        );

        prop_assert!(events.len() <= record_count,
            "Emitted {} events from {} input records", events.len(), record_count);
    }
}
```

### 5.2 Fuzz Testing (cargo-fuzz)

Continuous fuzzing catches crashes, hangs, and memory issues that property tests may miss. Every parser gets a fuzz target.

```rust
// fuzz/fuzz_targets/fuzz_usnjrnl.rs

#![no_main]
use libfuzzer_sys::fuzz_target;
use rt_parser_usnjrnl::UsnJrnlParser;
use rt_core::plugin::ForensicParser;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let parser = UsnJrnlParser::new();
    let mut events = Vec::new();

    // Must never panic, regardless of input
    let _ = parser.parse(
        &mut Cursor::new(data),
        &mut |event| events.push(event),
    );

    // Post-conditions even on garbage input:
    for event in &events {
        // No empty source types
        assert!(!event.source_type.is_empty());
        // Timestamp is set (even if nonsensical for garbage input)
        let _ = event.timestamp_ns();
    }
});
```

**Fuzz targets for all parsers:**

| Target | Crate | Corpus Seed | Focus |
|--------|-------|-------------|-------|
| `fuzz_usnjrnl` | issen-parser-usnjrnl | minimal/usnjrnl_*.bin | Record boundary parsing |
| `fuzz_mft` | issen-parser-mft | minimal/mft_*.bin | MFT entry attribute parsing |
| `fuzz_evtx` | issen-parser-evtx | minimal/evtx_*.evtx | XML chunk decompression |
| `fuzz_ewf` | issen-ewf | minimal/ewf_*.E01 | Segment header / table parsing |
| `fuzz_prefetch` | issen-parser-prefetch | minimal/prefetch_*.pf | Compressed prefetch v26/v30 |
| `fuzz_registry` | issen-parser-registry | minimal/registry_*.reg | Hive bin / cell parsing |
| `fuzz_lnk` | issen-parser-lnk | minimal/lnk_*.lnk | Shell link header / target |
| `fuzz_browser` | issen-parser-browser | minimal/browser_*.sqlite | SQLite history parsing |

**CI integration**: Fuzz targets run for 10 minutes per parser on nightly builds. Any crash automatically creates a GitHub issue with the reproducer input.

---

## 6. Integration Tests

### 6.1 Pipeline Integration Test (Layer 0-4)

```rust
// tests/integration/pipeline_tests.rs

use rt_pipeline::Pipeline;
use rt_timeline::store::TimelineStore;
use tempfile::TempDir;

/// Full evidence ingestion: raw artifact file -> parser -> DuckDB timeline.
#[test]
fn pipeline_ingests_kape_output_directory() {
    let dir = TempDir::new().unwrap();
    let evidence_dir = create_mock_kape_output(&dir);
    let timeline_db = dir.path().join("timeline.duckdb");

    let pipeline = Pipeline::builder()
        .evidence_path(&evidence_dir)
        .output_path(&timeline_db)
        .build()
        .unwrap();

    let result = pipeline.run().unwrap();

    assert!(result.total_events > 0);
    assert_eq!(result.errors.len(), 0);
    assert!(result.parsers_invoked.contains(&"issen-parser-usnjrnl"));
    assert!(result.parsers_invoked.contains(&"issen-parser-evtx"));

    // Verify data landed in DuckDB
    let store = TimelineStore::open(&timeline_db).unwrap();
    let events = store.query_time_range(0, u64::MAX).unwrap();
    assert_eq!(events.len(), result.total_events as usize);
}

/// Parser failure in one artifact must not abort the entire pipeline.
#[test]
fn pipeline_continues_on_single_parser_failure() {
    let dir = TempDir::new().unwrap();
    let evidence_dir = create_mock_kape_output_with_corrupt_artifact(&dir);
    let timeline_db = dir.path().join("timeline.duckdb");

    let pipeline = Pipeline::builder()
        .evidence_path(&evidence_dir)
        .output_path(&timeline_db)
        .build()
        .unwrap();

    let result = pipeline.run().unwrap();

    // Pipeline completes despite one corrupt artifact
    assert!(result.total_events > 0);
    assert!(result.errors.len() > 0, "Should report the corrupt artifact");
    assert!(result.errors[0].contains("corrupt"), "Error should identify the issue");
}

/// Parallel ingestion via rayon must produce identical results to sequential.
#[test]
fn parallel_and_sequential_produce_identical_output() {
    let dir = TempDir::new().unwrap();
    let evidence_dir = create_mock_kape_output(&dir);

    let sequential_db = dir.path().join("sequential.duckdb");
    let parallel_db = dir.path().join("parallel.duckdb");

    Pipeline::builder()
        .evidence_path(&evidence_dir)
        .output_path(&sequential_db)
        .parallelism(1)
        .build().unwrap()
        .run().unwrap();

    Pipeline::builder()
        .evidence_path(&evidence_dir)
        .output_path(&parallel_db)
        .parallelism(8)
        .build().unwrap()
        .run().unwrap();

    let seq_store = TimelineStore::open(&sequential_db).unwrap();
    let par_store = TimelineStore::open(&parallel_db).unwrap();

    let seq_events = seq_store.query_time_range(0, u64::MAX).unwrap();
    let par_events = par_store.query_time_range(0, u64::MAX).unwrap();

    assert_events_equivalent(&seq_events, &par_events);
}
```

### 6.2 Report Generation Integration Test

```rust
// tests/integration/report_generation.rs

use rt_report::{HtmlReport, DocxReport, ReportConfig};
use rt_timeline::store::TimelineStore;
use tempfile::TempDir;

#[test]
fn html_report_is_self_contained() {
    let (store, _dir) = setup_populated_timeline(50);
    let output_dir = TempDir::new().unwrap();
    let html_path = output_dir.path().join("report.html");

    HtmlReport::generate(&store, &ReportConfig::default(), &html_path).unwrap();

    let content = std::fs::read_to_string(&html_path).unwrap();

    // Self-contained: no external CDN, no external CSS/JS
    assert!(!content.contains("https://"), "HTML report must be self-contained");
    assert!(!content.contains("http://"), "HTML report must be self-contained");
    assert!(content.contains("<style>"), "CSS must be inline");
    assert!(content.contains("<script>"), "JS must be inline");

    // Chain of custody present
    assert_chain_of_custody(&html_path);
}

#[test]
fn docx_report_uses_multilevel_numbering() {
    let (store, _dir) = setup_populated_timeline(50);
    let output_dir = TempDir::new().unwrap();
    let docx_path = output_dir.path().join("report.docx");

    DocxReport::generate(&store, &ReportConfig::default(), &docx_path).unwrap();

    // Verify DOCX structure (per CLAUDE.md: headings use w:numPr, no literal numbers)
    let docx_bytes = std::fs::read(&docx_path).unwrap();
    let docx_xml = extract_document_xml(&docx_bytes);

    // Headings must use numbering system, not hardcoded numbers
    assert!(!regex::Regex::new(r"<w:t>\d+\.\d+").unwrap().is_match(&docx_xml),
        "Heading text must not contain literal section numbers");
    assert!(docx_xml.contains("w:numPr"),
        "Headings must use Word multilevel list numbering");
}

#[test]
fn report_content_hash_is_deterministic() {
    let (store, _dir) = setup_populated_timeline(50);
    let output_dir = TempDir::new().unwrap();

    let path1 = output_dir.path().join("report1.html");
    let path2 = output_dir.path().join("report2.html");

    let config = ReportConfig {
        deterministic_mode: true,
        ..Default::default()
    };

    HtmlReport::generate(&store, &config, &path1).unwrap();
    HtmlReport::generate(&store, &config, &path2).unwrap();

    let hash1 = sha256_file(&path1);
    let hash2 = sha256_file(&path2);
    assert_eq!(hash1, hash2, "Deterministic reports must produce identical hashes");
}
```

### 6.3 NIST CFTT Validation

```rust
// tests/nist_cftt/cftt_runner.rs

use rt_pipeline::Pipeline;
use std::path::Path;

/// NIST Computer Forensic Tool Testing (CFTT) validation.
/// Downloads reference images (cached) and verifies parser output matches
/// NIST-published expected results.
///
/// These tests are tagged #[ignore] for normal CI and run on nightly / release.
#[test]
#[ignore = "requires NIST CFTT images (run with --ignored)"]
fn cftt_disk_imaging_ntfs_reference() {
    let cftt_dir = download_cftt_image("ntfs_ref");
    let expected = load_cftt_expected_results("ntfs_ref");

    let dir = TempDir::new().unwrap();
    let timeline_db = dir.path().join("cftt.duckdb");

    let result = Pipeline::builder()
        .evidence_path(&cftt_dir)
        .output_path(&timeline_db)
        .build().unwrap()
        .run().unwrap();

    // Verify against NIST expected results
    for expected_artifact in &expected.artifacts {
        let store = TimelineStore::open(&timeline_db).unwrap();
        let events = store.query_by_source(&expected_artifact.source_type).unwrap();

        assert!(
            events.len() >= expected_artifact.min_events,
            "CFTT {}: expected >= {} events, got {}",
            expected_artifact.name, expected_artifact.min_events, events.len()
        );

        // Verify specific expected timestamps exist
        for expected_ts in &expected_artifact.expected_timestamps {
            assert!(
                events.iter().any(|e| e.timestamp_ns() == *expected_ts),
                "CFTT {}: missing expected timestamp {}",
                expected_artifact.name, expected_ts
            );
        }
    }
}

/// Track and report error rates for Daubert compliance.
fn cftt_error_rate_report(test_name: &str, expected: &CfttExpected, actual: &[TimelineEvent]) {
    let false_positives = actual.iter()
        .filter(|e| !expected.contains_event(e))
        .count();
    let false_negatives = expected.events.iter()
        .filter(|e| !actual.iter().any(|a| a.matches_expected(e)))
        .count();

    let total = expected.events.len();
    let fp_rate = false_positives as f64 / actual.len() as f64;
    let fn_rate = false_negatives as f64 / total as f64;

    // Write error rates to test-results/ for archival
    write_error_rate_report(test_name, fp_rate, fn_rate, total);

    // Fail if error rates exceed thresholds
    assert!(fp_rate < 0.01, "False positive rate {:.2}% exceeds 1% threshold", fp_rate * 100.0);
    assert!(fn_rate < 0.005, "False negative rate {:.2}% exceeds 0.5% threshold", fn_rate * 100.0);
}
```

---

## 7. Performance Benchmarks

### 7.1 Criterion Benchmarks

```rust
// benches/parser_throughput.rs

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use rt_parser_usnjrnl::UsnJrnlParser;
use rt_core::plugin::ForensicParser;

fn bench_usnjrnl_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("usnjrnl_parser");

    for size in [100, 1_000, 10_000, 100_000] {
        let input = generate_usnjrnl_fixture(size);
        group.throughput(Throughput::Elements(size as u64));

        group.bench_with_input(
            BenchmarkId::new("parse", size),
            &input,
            |b, input| {
                let parser = UsnJrnlParser::new();
                b.iter(|| {
                    let mut events = Vec::new();
                    parser.parse(
                        &mut std::io::Cursor::new(input),
                        &mut |event| events.push(event),
                    ).unwrap();
                });
            },
        );
    }
    group.finish();
}

fn bench_duckdb_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("duckdb_insert");

    for size in [1_000, 10_000, 100_000] {
        let events = generate_test_events(size);
        group.throughput(Throughput::Elements(size as u64));

        group.bench_with_input(
            BenchmarkId::new("batch_insert", size),
            &events,
            |b, events| {
                b.iter_batched(
                    || setup_test_timeline(),
                    |(conn, _dir)| {
                        let store = TimelineStore::new(conn);
                        store.insert_batch(events).unwrap();
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_timeline_query(c: &mut Criterion) {
    let mut group = c.benchmark_group("timeline_query");
    let (conn, _dir) = setup_test_timeline();
    let store = TimelineStore::new(conn);
    let events = generate_test_events(100_000);
    store.insert_batch(&events).unwrap();

    group.bench_function("full_scan_100k", |b| {
        b.iter(|| {
            store.query_time_range(0, u64::MAX).unwrap()
        });
    });

    group.bench_function("narrow_range_100k", |b| {
        b.iter(|| {
            // Query 1% of time range
            store.query_time_range(49_000, 51_000).unwrap()
        });
    });

    group.bench_function("source_filter_100k", |b| {
        b.iter(|| {
            store.query_by_source("USN").unwrap()
        });
    });

    group.finish();
}

criterion_group!(benches, bench_usnjrnl_throughput, bench_duckdb_insert, bench_timeline_query);
criterion_main!(benches);
```

### 7.2 Performance Budgets

Performance budgets tie directly to the North Star metric (TARR < 4 hours). Parse-to-Timeline Latency target: < 10 minutes for 50GB evidence.

| Operation | Target (P95) | Measurement | Alert Threshold |
|-----------|-------------|-------------|-----------------|
| USN Journal parse | > 500K records/sec | criterion bench | < 400K records/sec |
| MFT parse | > 200K entries/sec | criterion bench | < 150K entries/sec |
| EVTX parse | > 100K records/sec | criterion bench | < 80K records/sec |
| DuckDB batch insert | > 500K events/sec | criterion bench | < 400K events/sec |
| DuckDB time-range query (1M events) | < 200ms | criterion bench | > 500ms |
| SQLite export (1M events) | < 30s | criterion bench | > 60s |
| HTML report generation (10K events) | < 5s | criterion bench | > 10s |
| DOCX report generation (10K events) | < 10s | criterion bench | > 20s |
| Full pipeline (KAPE triage, 5GB) | < 3 min | integration bench | > 5 min |

**Regression detection**: CI runs criterion benchmarks on every PR against `main` baseline. A 10% regression on any budget triggers a warning; a 25% regression blocks merge.

---

## 8. Regression Testing

### 8.1 Snapshot Testing (insta)

Report output and structured data are snapshot-tested to catch unintended changes.

```rust
// tests/integration/report_snapshots.rs

use insta::assert_yaml_snapshot;
use rt_report::HtmlReport;

#[test]
fn html_report_structure_snapshot() {
    let (store, _dir) = setup_populated_timeline(10);
    let report = HtmlReport::render_to_string(&store, &ReportConfig::default()).unwrap();

    // Extract structural elements (not content, which varies)
    let structure = extract_html_structure(&report);
    assert_yaml_snapshot!("html_report_structure", structure);
}

#[test]
fn timeline_query_result_snapshot() {
    let (store, _dir) = setup_deterministic_timeline();
    let events = store.query_time_range(0, u64::MAX).unwrap();

    let summary: Vec<_> = events.iter().map(|e| EventSummary {
        source: &e.source_type,
        desc: &e.timestamp_desc,
        path: &e.artifact_path,
    }).collect();

    assert_yaml_snapshot!("timeline_query_10_events", summary);
}
```

### 8.2 Regression Test Protocol

When a bug is found in production:

1. **Reproduce**: Create a minimal fixture that triggers the bug
2. **Add golden case**: Add to the appropriate parser's golden dataset YAML with `category: regression`
3. **Fix**: Implement the fix
4. **Verify**: Golden test passes, existing tests still pass
5. **Tag**: Label the golden case with the issue number (e.g., `regression_gh_42`)

```yaml
# Added to tests/golden/datasets/usnjrnl.yml
  - id: "usnjrnl-reg-042"
    category: "regression"
    description: "GH#42: Parser mishandled reason flag 0x80000000 (CLOSE) as 0x00"
    priority: "critical"
    issue: "https://github.com/h4x0r/issen/issues/42"
    input:
      fixture: "fixtures/minimal/usnjrnl_gh42_close_flag.bin"
    expected:
      events:
        - timestamp_desc: "USN_REASON_CLOSE"
      constraints:
        must_contain: ["CLOSE"]
        must_not_contain: ["UNKNOWN"]
```

---

## 9. Test Utilities

### 9.1 Mock Factories

```rust
// tests/common/factories.rs

use rt_core::timeline::TimelineEvent;
use rt_core::plugin::{ParseStats, ParserCapabilities};

/// Generate a test event with sensible defaults.
pub fn test_event(ts: u64, source: &str, path: &str, msg: &str) -> TimelineEvent {
    TimelineEvent::builder()
        .timestamp_ns(ts)
        .source_type(source.to_string())
        .artifact_path(path.to_string())
        .message(msg.to_string())
        .timestamp_desc("Test".to_string())
        .build()
}

/// Generate N deterministic test events spread across a time range.
pub fn generate_test_events(count: usize) -> Vec<TimelineEvent> {
    (0..count).map(|i| {
        let sources = ["USN", "MFT", "EVTX", "PREFETCH", "REGISTRY"];
        test_event(
            (i as u64) * 1000,
            sources[i % sources.len()],
            &format!("artifact_{}.dat", i),
            &format!("Test event {}", i),
        )
    }).collect()
}

/// Create a mock KAPE output directory structure with synthetic artifacts.
pub fn create_mock_kape_output(base: &tempfile::TempDir) -> std::path::PathBuf {
    let kape_dir = base.path().join("kape_output");
    std::fs::create_dir_all(kape_dir.join("C/\\$Extend")).unwrap();
    std::fs::create_dir_all(kape_dir.join("C/Windows/System32/winevt/Logs")).unwrap();

    // Write minimal valid artifacts
    std::fs::write(
        kape_dir.join("C/\\$Extend/\\$UsnJrnl_\\$J.bin"),
        include_bytes!("../fixtures/minimal/usnjrnl_v2_3records.bin"),
    ).unwrap();

    std::fs::write(
        kape_dir.join("C/Windows/System32/winevt/Logs/Security.evtx"),
        include_bytes!("../fixtures/minimal/evtx_single_record.evtx"),
    ).unwrap();

    kape_dir
}
```

### 9.2 Test Helpers

```rust
// tests/common/helpers.rs

use sha2::{Sha256, Digest};

/// Compute SHA-256 hash of a file for determinism checks.
pub fn sha256_file(path: &std::path::Path) -> String {
    let bytes = std::fs::read(path).unwrap();
    let hash = Sha256::digest(&bytes);
    format!("{:x}", hash)
}

/// Assert latency is within budget (with 10% tolerance for CI variance).
pub fn assert_within_latency_budget(actual: std::time::Duration, budget: std::time::Duration) {
    let max_allowed = budget.mul_f64(1.1); // 10% CI tolerance
    assert!(actual <= max_allowed,
        "Latency {:?} exceeds budget {:?} (with 10% tolerance: {:?})",
        actual, budget, max_allowed);
}

/// Extract document.xml from a DOCX file for structural validation.
pub fn extract_document_xml(docx_bytes: &[u8]) -> String {
    let reader = std::io::Cursor::new(docx_bytes);
    let mut archive = zip::ZipArchive::new(reader).unwrap();
    let mut document = archive.by_name("word/document.xml").unwrap();
    let mut xml = String::new();
    std::io::Read::read_to_string(&mut document, &mut xml).unwrap();
    xml
}
```

---

## 10. CI/CD Integration

### 10.1 GitHub Actions Workflow

```yaml
# .github/workflows/test.yml

name: Test

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: "-D warnings"

jobs:
  unit-tests:
    name: Unit Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: llvm-tools-preview
      - uses: Swatinem/rust-cache@v2

      - name: Install cargo-llvm-cov
        uses: taiki-e/install-action@cargo-llvm-cov

      - name: Run unit tests with coverage
        run: cargo llvm-cov --workspace --lcov --output-path lcov.info

      - name: Check coverage threshold
        run: |
          COVERAGE=$(cargo llvm-cov --workspace --summary-only 2>&1 | grep -oP '\d+\.\d+%' | head -1 | tr -d '%')
          echo "Coverage: ${COVERAGE}%"
          if (( $(echo "$COVERAGE < 88.0" | bc -l) )); then
            echo "::error::Coverage ${COVERAGE}% is below 88% threshold"
            exit 1
          fi

      - name: Upload coverage
        uses: codecov/codecov-action@v4
        with:
          files: lcov.info

  property-tests:
    name: Property Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2

      - name: Run proptest suite
        run: cargo test --test property -- --test-threads=4
        env:
          PROPTEST_CASES: 1000  # More cases in CI than local dev

  golden-tests:
    name: Golden Dataset Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2

      - name: Generate synthetic fixtures
        run: cargo run --bin gen-fixtures -- --all --seed 42

      - name: Run golden dataset tests
        run: cargo test --test golden_runner

  integration-tests:
    name: Integration Tests
    runs-on: ubuntu-latest
    needs: [unit-tests]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2

      - name: Generate synthetic fixtures
        run: cargo run --bin gen-fixtures -- --all --seed 42

      - name: Run integration tests
        run: cargo test --test '*' -- --test-threads=2
        timeout-minutes: 15

  benchmarks:
    name: Performance Benchmarks
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
        with:
          ref: main
          path: main-branch
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2

      - name: Run benchmarks (PR)
        run: cargo bench --bench '*' -- --output-format bencher | tee pr-bench.txt

      - name: Run benchmarks (main)
        run: |
          cd main-branch
          cargo bench --bench '*' -- --output-format bencher | tee ../main-bench.txt

      - name: Compare benchmarks
        run: |
          # Check for >25% regression
          python3 scripts/compare_benchmarks.py main-bench.txt pr-bench.txt --threshold 25

  nightly-fuzz:
    name: Fuzz Testing
    runs-on: ubuntu-latest
    if: github.event_name == 'schedule'
    strategy:
      matrix:
        target: [fuzz_usnjrnl, fuzz_mft, fuzz_evtx, fuzz_ewf, fuzz_prefetch, fuzz_registry]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz

      - name: Run fuzzer
        run: cargo fuzz run ${{ matrix.target }} -- -max_total_time=600
        # 10 minutes per parser

      - name: Upload crash artifacts
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: fuzz-crash-${{ matrix.target }}
          path: fuzz/artifacts/${{ matrix.target }}/

  nightly-cftt:
    name: NIST CFTT Validation
    runs-on: ubuntu-latest
    if: github.event_name == 'schedule'
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2

      - name: Download NIST CFTT images
        run: cargo run --bin download-cftt -- --manifest fixtures/reference/manifest.yml
        # Cached via actions/cache

      - name: Run CFTT validation suite
        run: cargo test --test cftt_runner -- --ignored

      - name: Archive error rate reports
        uses: actions/upload-artifact@v4
        with:
          name: cftt-error-rates
          path: test-results/cftt/
```

### 10.2 CI Job Responsibilities

| Job | Trigger | Duration | Gate? |
|-----|---------|----------|-------|
| `unit-tests` | Every push/PR | 2-4 min | Yes -- blocks merge |
| `property-tests` | Every push/PR | 3-5 min | Yes -- blocks merge |
| `golden-tests` | Every push/PR | 1-2 min | Yes -- blocks merge |
| `integration-tests` | Every push/PR | 5-15 min | Yes -- blocks merge |
| `benchmarks` | PR only | 5-10 min | Warning at 10%, block at 25% regression |
| `nightly-fuzz` | Nightly schedule | 60 min (10 min x 6 parsers) | Creates issue on crash |
| `nightly-cftt` | Nightly schedule | 15-30 min | Creates issue on failure |

### 10.3 Coverage Enforcement

```yaml
# .codecov.yml
coverage:
  status:
    project:
      default:
        target: 88%      # Match existing tl baseline
        threshold: 2%     # Allow 2% fluctuation
    patch:
      default:
        target: 85%       # New code must be well-tested
  flags:
    issen-core:
      paths: ["crates/issen-core/"]
      target: 95%
    parsers:
      paths: ["crates/issen-parser-*/"]
      target: 90%
    pipeline:
      paths: ["crates/issen-pipeline/"]
      target: 80%
```

---

## 11. Test Data Governance

### 11.1 Evidence Handling Policy

Forensic test data governance is not optional -- it directly impacts admissibility.

| Rule | Implementation |
|------|---------------|
| **No real evidence in repo** | `.gitignore` blocks `fixtures/reference/`, `fixtures/private/`; CI pre-commit hook scans for PII patterns |
| **Synthetic by default** | All committed fixtures are programmatically generated with documented seeds |
| **Provenance documented** | Every fixture has a `README.md` documenting: source, generation method, what it tests |
| **Deterministic generation** | Fixture generators use fixed seeds (`--seed 42`) for reproducibility |
| **Reference data hashed** | Downloaded NIST/public data verified via SHA-256 before use |
| **LFS for binaries > 100KB** | `.gitattributes` routes binary fixtures to Git LFS |

### 11.2 .gitignore for Test Data

```gitignore
# Test fixtures -- generated and downloaded
tests/fixtures/synthetic/artifacts/
tests/fixtures/reference/cftt/
tests/fixtures/reference/public/
tests/fixtures/private/

# Fuzz corpus and artifacts
fuzz/corpus/
fuzz/artifacts/

# Benchmark results (local)
target/criterion/

# Coverage output
lcov.info
coverage/

# Error rate reports
test-results/
```

---

*Document generated by North Star Advisor*
