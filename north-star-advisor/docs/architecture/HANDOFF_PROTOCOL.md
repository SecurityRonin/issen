# Issen: Handoff Protocol

> Defines context-passing contracts between development agents (AI coding agents working on different crates), between runtime pipeline stages (Layer 0-4), across the open-source/proprietary boundary, and for community contributor workflows.

---

## 1. Handoff Protocol Overview

Issen operates at two distinct handoff levels:

1. **Development-time handoffs** -- how AI coding agents (and human contributors) pass context when transitioning work between crates (e.g., pipeline-agent finishing Layer 0-2 work and handing off to timeline-agent for DuckDB ingestion).
2. **Runtime handoffs** -- how data flows through the five-layer evidence pipeline, how events are emitted between crates, and how errors propagate across the open-source/proprietary boundary.

Both levels share a common principle: **every handoff carries a typed contract, a trace ID, and enough context for the receiver to proceed without consulting the sender.**

```
                     DEVELOPMENT-TIME HANDOFF FLOW
 ┌──────────────┐    HandoffRequest     ┌───────────────┐
 │ pipeline-agent├─────────────────────►│ timeline-agent │
 │  (issen-pipeline)│                      │  (issen-timeline) │
 └──────┬───────┘  ◄─────────────────  └───────┬────────┘
        │           HandoffResponse             │
        │                                       │
        ▼                                       ▼
  Updated CHANGELOG         Updated CHANGELOG + migration notes
  Passing CI gate           Passing CI gate
  Cross-crate test green    Integration test green

                      RUNTIME DATA FLOW
 ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌──────────┐   ┌──────────┐
 │ Layer 0  │──►│ Layer 1  │──►│ Layer 2  │──►│ Layer 3   │──►│ Layer 4   │
 │ Storage  │   │ Image    │   │ Volume/FS│   │ Artifact  │   │ Semantic  │
 │ Provider │   │ Format   │   │ Accessor │   │ Parser    │   │ Analysis  │
 └─────────┘   └─────────┘   └─────────┘   └──────────┘   └──────────┘
     StorageProvider   ImageFormat   VolumeSystem    Parser trait   AnalysisEngine
      trait             trait     FilesystemAccessor   (issen-core)     (issen-intel)
     (issen-core)        (issen-core)     trait (issen-core)                  proprietary
```

---

## 2. Handoff Schema

### 2.1 Development-Time HandoffRequest Schema

Used when an AI coding agent (or human contributor) completes work on one crate and needs another agent/contributor to continue.

```yaml
# src/pipeline/handoff/schema
HANDOFF_SCHEMA_VERSION: '1.0.0'

DevHandoffRequest:
  schemaVersion: '1.0.0'      # literal
  traceId: uuid                # unique per handoff chain
  timestamp: datetime          # ISO 8601

  # Source agent
  sourceAgent: enum
    - pipeline-agent
    - timeline-agent
    - analysis-agent
    - intel-agent
    - repoissen-agent
    - frontend-agent
    - infra-agent
  sourceCrate: string          # e.g., "issen-pipeline"

  sourceContext:
    branch: string             # git branch name
    commitSha: string          # HEAD at handoff time
    ciStatus: enum [passing, failing, skipped]
    changedFiles: string[]     # paths modified
    publicApiChanges: boolean  # did the crate's public API change?
    breakingChanges: boolean   # semver-breaking?

  # What the target needs to do
  handoffTo: enum [agent_ids + 'human' + 'community-reviewer']
  reason: enum
    - crate_boundary_crossed
    - expertise_mismatch
    - requires_human_decision
    - ci_gate_dependency
    - license_boundary          # open-source <-> proprietary transition
  reasonDetail: string

  # Context payload
  contextForTarget:
    summary: string            # 2-3 sentence description of what was done
    dependencyChanges:         # Cargo.toml changes in the source crate
      added: string[]
      removed: string[]
      updated: string[]
    newTraits: string[]        # new traits/types the target crate must implement
    newEvents: string[]        # new event types the target must handle
    migrationRequired: boolean # does issen-timeline need a schema migration?
    testCommands: string[]     # commands to verify the handoff is clean
    relevantDocs: string[]     # paths to updated docs/ADRs

  # Requirements before handoff is accepted
  prerequisites:
    testsPass: string[]        # specific test suites that must be green
    docsUpdated: string[]      # docs that must be current
    changelogEntry: boolean    # CHANGELOG.md entry required
    rfcRequired: boolean       # RFC needed for issen-core changes

  priority: enum [low, medium, high, critical]
  timeoutMs: number            # optional; 0 = no timeout
```

### 2.2 Runtime HandoffRequest Schema

Used at runtime when data flows between pipeline layers or when a processing stage delegates to another.

```yaml
RuntimeHandoffRequest:
  schemaVersion: '1.0.0'
  traceId: uuid              # spans the entire evidence-to-report pipeline
  spanId: uuid               # this specific handoff
  timestamp: datetime

  sourceLayer: enum [0, 1, 2, 3, 4]
  sourceCrate: string
  targetLayer: enum [0, 1, 2, 3, 4]
  targetCrate: string

  # Payload contract
  payload:
    type: enum
      - StorageHandle          # Layer 0 -> 1: handle to raw bytes
      - ImageStream            # Layer 1 -> 2: parsed image with partition table
      - FilesystemIterator     # Layer 2 -> 3: iterator over files/metadata
      - TimelineEventBatch     # Layer 3 -> 4: batch of parsed events
      - AnalysisResult         # Layer 4 -> report: findings with citations
    sizeHint: number           # estimated bytes, for back-pressure
    streamable: boolean        # can the receiver consume this as a stream?

  # Error context (if this is a retry or escalation)
  errorContext:
    priorAttempts: number
    lastError: string
    degraded: boolean          # is the source operating in degraded mode?

  # Back-pressure signal
  backPressure:
    receiverReady: boolean
    bufferUtilization: float   # 0.0 to 1.0
    suggestedBatchSize: number
```

### 2.3 HandoffResponse Schema

```yaml
HandoffResponse:
  schemaVersion: '1.0.0'
  traceId: uuid               # same as request
  timestamp: datetime

  respondingAgent: string      # agent ID or 'human'
  status: enum [accepted, resolved, partial, failed, escalated]

  # For development handoffs
  dev:
    branch: string             # target agent's working branch
    commitSha: string          # commit after completing the work
    testsAdded: string[]       # new tests written
    docsUpdated: string[]      # docs modified

  # For runtime handoffs
  runtime:
    eventsEmitted: number      # count of timeline events produced
    errorsEncountered: number
    degradedFields: string[]   # fields that have fallback values

  # For partial/failed
  unresolved: string[]
  failureReason: string

  # Execution metadata
  executionTimeMs: number
  recommendations: string[]    # suggestions for the source agent
```

### 2.4 HandoffDecision Schema

Used by an agent to quickly determine whether it can handle a request or must delegate.

```yaml
HandoffDecision:
  canHandle: boolean
  confidence: float            # 0.0 to 1.0
  handoffTo: string            # if canHandle is false
  reason: string               # why delegation is needed
  missingInputs: string[]      # what the agent lacks
```

---

## 3. Handoff Routes

### 3.1 Valid Development-Time Handoff Paths

These are the sanctioned transitions between development agents. Each has a specific contract.

| # | Source Agent | Target Agent | Trigger | Contract |
|---|-------------|-------------|---------|----------|
| 1 | pipeline-agent | timeline-agent | New event types defined in issen-core | Target implements DuckDB column mappings for new types; migration SQL provided |
| 2 | pipeline-agent | analysis-agent | New parser emits events that need correlation rules | Target adds correlation patterns in issen-correlation for the new artifact type |
| 3 | timeline-agent | repoissen-agent | New query/view added to timeline | Target updates report templates to include new timeline view |
| 4 | analysis-agent | intel-agent | New finding type needs RAG context or LLM narrative | Target adds prompt template and retrieval strategy for finding type |
| 5 | intel-agent | repoissen-agent | New narrative section generated | Target integrates narrative into report layout with proper citation format |
| 6 | Any agent | infra-agent | CI/CD change needed (new benchmark, dependency update) | Target updates GitHub Actions, Cargo workspace config, or Nix flake |
| 7 | Any agent | frontend-agent | New CLI command or TUI/GUI view needed | Target implements UI for new pipeline capability |
| 8 | community-contributor | community-reviewer | Plugin PR submitted | Reviewer runs plugin test harness, checks WIT conformance, reviews security |

### 3.2 Valid Runtime Handoff Paths

Data flows strictly downward through pipeline layers. Feedback flows upward only as error signals or back-pressure.

| Source | Target | Payload Type | Error Behavior |
|--------|--------|-------------|----------------|
| Layer 0 (Storage) | Layer 1 (Image) | `StorageHandle` | Retry with alternate provider; fail if evidence unreadable |
| Layer 1 (Image) | Layer 2 (Volume/FS) | `ImageStream` | Skip corrupted partitions; emit warning events |
| Layer 2 (Volume/FS) | Layer 3 (Artifact) | `FilesystemIterator` | Skip unreadable files; log with path and error |
| Layer 3 (Artifact) | Layer 4 (Semantic) | `TimelineEventBatch` | Batch with degraded=true for unparseable artifacts |
| Layer 4 (Semantic) | Report | `AnalysisResult` | Omit uncorroborated findings; flag confidence level |

**Back-pressure protocol**: Layer N+1 signals `receiverReady: false` when its buffer utilization exceeds 0.8. Layer N pauses emission until the signal clears. This prevents OOM on large evidence sets (50GB+ E01 images).

### 3.3 Invalid Handoff Paths (Anti-patterns)

| Invalid Path | Why Prohibited |
|--------------|----------------|
| repoissen-agent -> pipeline-agent | Reports never trigger re-ingestion; examiner re-runs pipeline manually |
| intel-agent -> pipeline-agent | Intelligence layer never modifies raw evidence processing |
| timeline-agent -> pipeline-agent (runtime) | Timeline queries never cause re-parsing; immutable append-only events |
| Any proprietary -> Any open-source (runtime dependency) | Open-source crates NEVER depend on proprietary crates at compile time |
| Circular: A -> B -> A (same traceId) | Infinite loop; blocked by HandoffManager circular detection |
| Layer 3 -> Layer 1 (runtime) | No backward data flow; layers are strictly sequential |

### 3.4 Handoff Limits

| Limit | Value | Rationale |
|-------|-------|-----------|
| Max handoffs per pipeline run | 20 | Prevents runaway delegation chains |
| Max dev handoff chain depth | 5 | Forces agents to break work into bounded units |
| Handoff timeout (dev, default) | 30 minutes | Aligns with TARR budget (<4 hours total) |
| Handoff timeout (runtime) | 10,000ms | Layer transitions must be fast; total pipeline <10 min |
| Max retry attempts (runtime) | 3 | After 3 failures, degrade gracefully or escalate |
| Circular detection window | Per traceId | Same traceId cannot revisit the same agent |

---

## 4. Handoff Implementation

### 4.1 HandoffManager

The HandoffManager is the central coordinator for all handoff operations. In development context, it is a conceptual protocol enforced by CI gates and agent prompts. At runtime, it is a Rust struct in `issen-pipeline`.

```rust
// issen-pipeline/src/handoff/manager.rs

use std::collections::HashSet;
use uuid::Uuid;

pub struct HandoffManager {
    /// Active handoff trace IDs and the agents they have visited
    active_chains: DashMap<Uuid, HashSet<String>>,
    /// Maximum handoffs per trace
    max_chain_depth: usize,
    /// Handoff metrics emitter
    metrics: HandoffMetrics,
}

impl HandoffManager {
    pub fn new(max_chain_depth: usize) -> Self {
        Self {
            active_chains: DashMap::new(),
            max_chain_depth,
            metrics: HandoffMetrics::new(),
        }
    }

    /// Process a runtime handoff request.
    /// Returns Err if circular detected or chain depth exceeded.
    pub fn process_handoff(
        &self,
        request: &RuntimeHandoffRequest,
    ) -> Result<HandoffResponse, HandoffError> {
        let trace_id = request.trace_id;
        let target = &request.target_crate;

        // Circular detection
        let mut visited = self.active_chains
            .entry(trace_id)
            .or_insert_with(HashSet::new);

        if visited.contains(target) {
            self.metrics.record_circular_blocked(trace_id, target);
            return Err(HandoffError::CircularDetected {
                trace_id,
                agent: target.clone(),
                chain: visited.iter().cloned().collect(),
            });
        }

        // Chain depth check
        if visited.len() >= self.max_chain_depth {
            self.metrics.record_depth_exceeded(trace_id);
            return Err(HandoffError::ChainDepthExceeded {
                trace_id,
                depth: visited.len(),
                max: self.max_chain_depth,
            });
        }

        // Record visit
        visited.insert(target.clone());

        // Route to target layer
        let span = tracing::info_span!("handoff",
            handoff.trace_id = %trace_id,
            handoff.source = %request.source_crate,
            handoff.target = %target,
            handoff.payload_type = %request.payload.type_name(),
        );

        let _guard = span.enter();
        tracing::info!("Handoff initiated: {} -> {}", request.source_crate, target);

        // Delegate to the target layer's handler
        self.route_to_handler(request)
    }

    /// Clean up completed trace chains
    pub fn complete_trace(&self, trace_id: Uuid) {
        self.active_chains.remove(&trace_id);
        self.metrics.record_chain_completed(trace_id);
    }

    fn route_to_handler(
        &self,
        request: &RuntimeHandoffRequest,
    ) -> Result<HandoffResponse, HandoffError> {
        match request.target_layer {
            0 => Err(HandoffError::InvalidRoute {
                reason: "Cannot hand off to Layer 0 (storage is entry point only)".into(),
            }),
            1 => self.handle_image_handoff(request),
            2 => self.handle_filesystem_handoff(request),
            3 => self.handle_parser_handoff(request),
            4 => self.handle_analysis_handoff(request),
            _ => Err(HandoffError::InvalidRoute {
                reason: format!("Unknown layer: {}", request.target_layer),
            }),
        }
    }
}
```

### 4.2 Development-Time Agent Handoff Integration

Each development agent follows this protocol when it determines a handoff is needed:

```
DEVELOPMENT HANDOFF CHECKLIST (enforced by agent system prompts)

Before initiating handoff, the source agent MUST:

1. COMMIT & PUSH
   [ ] All changes committed to feature branch
   [ ] Branch name follows convention: {agent-id}/{crate}/{description}
   [ ] CI pipeline passing (or documented known failures)

2. UPDATE DOCUMENTATION
   [ ] CHANGELOG.md entry added (unreleased section)
   [ ] If public API changed: update rustdoc on affected items
   [ ] If new trait added: add trait documentation with examples
   [ ] If issen-core changed: RFC document in docs/rfcs/

3. WRITE CROSS-CRATE TESTS
   [ ] Integration test demonstrating the handoff interface
   [ ] Test in tests/integration/ that exercises source->target contract
   [ ] If new event type: golden test with expected DuckDB row

4. CREATE HANDOFF REQUEST
   [ ] Fill DevHandoffRequest with all required fields
   [ ] Include test commands the target agent should run first
   [ ] List any migration steps (SQL, config changes)
   [ ] Set priority based on TARR impact

5. TAG THE HANDOFF
   [ ] Git tag: handoff/{source-agent}/{target-agent}/{timestamp}
   [ ] PR description includes handoff context block
```

### 4.3 Open-Source / Proprietary Boundary Protocol

The boundary between open-source and proprietary crates requires special handling because of the hard rule: **open-source crates NEVER depend on proprietary crates.**

```
                    DEPENDENCY DIRECTION (ENFORCED)

    ┌─────────────────────────────────────────────────┐
    │               PROPRIETARY CRATES                 │
    │  issen-report  issen-intel  issen-correlation  issen-tui     │
    │  issen-gui     issen-web                               │
    │                                                  │
    │  Can depend on any open-source crate             │
    │  Can depend on other proprietary crates          │
    └──────────────────────┬──────────────────────────┘
                           │ depends on (compile-time)
                           ▼
    ┌─────────────────────────────────────────────────┐
    │               OPEN-SOURCE CRATES                 │
    │  issen-core  issen-pipeline  issen-timeline  issen-cli       │
    │  issen-plugin-sdk  issen-ewf                           │
    │                                                  │
    │  NEVER depend on proprietary crates              │
    │  Communicate via traits defined in issen-core       │
    └─────────────────────────────────────────────────┘

BOUNDARY HANDOFF RULES:

1. Data crosses the boundary ONLY through issen-core trait objects
   - TimelineEvent (issen-core) is the universal exchange type
   - AnalysisPort trait (issen-core) defines the analysis interface
   - ReportPort trait (issen-core) defines the report interface

2. Open-source crates expose trait implementations, never concrete types
   from proprietary crates

3. Feature flags gate proprietary functionality:
   - `cargo build` (default) = open-source only
   - `cargo build --features pro` = includes proprietary crates
   - CI tests BOTH configurations

4. Plugin SDK (issen-plugin-sdk) re-exports ONLY from issen-core
   - Community plugin developers never see proprietary types
   - Plugin trait: Parser, Analyzer, Reporter (all in issen-core)
```

### 4.4 Community Plugin Handoff Protocol

For community contributors developing plugins (Tier 2 WASM plugins, v0.3+):

```
COMMUNITY PLUGIN SUBMISSION WORKFLOW

1. CONTRIBUTOR develops plugin
   ├── Uses issen-plugin-sdk (Apache 2.0)
   ├── Implements Parser trait via WIT interface
   ├── Includes test fixtures and golden output
   └── Submits PR to github.com/h4x0r/issen

2. AUTOMATED CHECKS (CI gate)
   ├── WIT interface conformance check
   ├── WASM size limit (<10MB compiled)
   ├── Memory limit test (64MB WASM linear memory)
   ├── Execution timeout test (<30s per artifact)
   ├── No filesystem access outside sandbox
   └── Fuzz test with malformed input (1000 iterations)

3. COMMUNITY REVIEWER handoff
   ├── Receives: PR link, CI results, plugin metadata
   ├── Reviews: code quality, security implications, test coverage
   ├── Verifies: output matches expected TimelineEvent schema
   ├── Checks: no duplicate functionality with existing parsers
   └── Decision: approve, request changes, or reject with rationale

4. MERGE & PUBLISH
   ├── Plugin added to community plugin registry
   ├── Version tagged in plugin manifest
   ├── Announcement in release notes
   └── Plugin author credited in CONTRIBUTORS.md
```

---

## 5. Handoff Observability

### 5.1 Trace Attributes

All handoffs -- both development and runtime -- are instrumented with structured tracing spans.

```yaml
# Runtime handoff span attributes (OpenTelemetry compatible)
handoff_span_attributes:
  'handoff.trace_id': uuid
  'handoff.span_id': uuid
  'handoff.source_crate': 'issen-pipeline'
  'handoff.target_crate': 'issen-timeline'
  'handoff.source_layer': 3
  'handoff.target_layer': 4
  'handoff.payload_type': 'TimelineEventBatch'
  'handoff.payload_size_bytes': number
  'handoff.status': 'resolved'       # accepted | resolved | partial | failed | escalated
  'handoff.execution_time_ms': number
  'handoff.events_emitted': number
  'handoff.errors_encountered': number
  'handoff.back_pressure_pauses': number
  'handoff.degraded': boolean

# Development handoff attributes (logged in CI and agent traces)
dev_handoff_attributes:
  'handoff.source_agent': 'pipeline-agent'
  'handoff.target_agent': 'timeline-agent'
  'handoff.reason': 'crate_boundary_crossed'
  'handoff.branch': 'pipeline-agent/issen-pipeline/add-evtx-parser'
  'handoff.commit_sha': string
  'handoff.ci_status': 'passing'
  'handoff.breaking_changes': boolean
  'handoff.priority': 'high'
```

### 5.2 Metrics

```yaml
# Counter metrics
handoff_total:
  labels: [source_crate, target_crate, status]
  description: "Total handoffs by source, target, and outcome"

handoff_failed_total:
  labels: [source_crate, target_crate, reason]
  description: "Failed handoffs by failure reason"

handoff_circular_blocked_total:
  labels: [source_crate, target_crate]
  description: "Handoffs blocked by circular detection"

handoff_escalated_total:
  labels: [source_crate]
  description: "Handoffs escalated to human decision"

# Histogram metrics
handoff_duration_ms:
  labels: [source_crate, target_crate]
  buckets: [1, 5, 10, 50, 100, 500, 1000, 5000, 10000]
  description: "Handoff execution time distribution"

handoff_payload_size_bytes:
  labels: [payload_type]
  buckets: [1024, 65536, 1048576, 10485760, 104857600]
  description: "Handoff payload size distribution"

handoff_chain_depth:
  labels: [initial_source]
  buckets: [1, 2, 3, 5, 10, 20]
  description: "Number of handoffs in a single trace chain"

# Gauge metrics
handoff_active_chains:
  description: "Currently active handoff chains"

handoff_buffer_utilization:
  labels: [layer]
  description: "Current buffer utilization per pipeline layer (0.0-1.0)"
```

### 5.3 Alerting Thresholds

| Condition | Severity | Action |
|-----------|----------|--------|
| `handoff_failed_total` > 5 in 5 min | Warning | Investigate target agent/layer health |
| `handoff_escalated_total` > 3 in 1 hr | Info | Review escalation patterns; consider automation |
| `handoff_circular_blocked_total` > 0 | Warning | Review handoff routing logic; likely a bug |
| `handoff_duration_ms` p95 > 5000ms | Warning | Optimize target handler; check back-pressure |
| `handoff_buffer_utilization` > 0.9 for 30s | Critical | Increase buffer or reduce batch size |
| `handoff_chain_depth` > 15 | Warning | Approaching max (20); review delegation pattern |
| Dev handoff unresolved > 24 hours | Warning | Agent may be stuck; escalate to human |

---

## 6. Error Recovery

### 6.1 Runtime Handoff Failure Handling

```rust
// issen-pipeline/src/handoff/recovery.rs

pub enum RecoveryAction {
    RetryDifferentTarget { new_target: String, reason: String },
    ProceedPartial { missing_fields: Vec<String>, reason: String },
    EscalateToHuman { reason: String, context: HandoffContext },
    SkipAndContinue { skipped_item: String, reason: String },
    FallbackDefault { default_value: Box<dyn Any>, reason: String },
}

pub fn handle_handoff_failure(
    request: &RuntimeHandoffRequest,
    response: &HandoffResponse,
    attempt: usize,
) -> RecoveryAction {
    match response.status {
        // Strategy 1: Retry with orchestrator as fallback target
        HandoffStatus::Failed if attempt < 3 => {
            RecoveryAction::RetryDifferentTarget {
                new_target: next_fallback_target(request, attempt),
                reason: format!(
                    "Primary target {} failed (attempt {}): {}",
                    request.target_crate, attempt,
                    response.failure_reason.as_deref().unwrap_or("unknown")
                ),
            }
        }

        // Strategy 2: Partial data -- proceed if non-critical fields missing
        HandoffStatus::Partial => {
            let critical_missing: Vec<_> = response.unresolved.iter()
                .filter(|field| CRITICAL_FIELDS.contains(&field.as_str()))
                .cloned()
                .collect();

            if critical_missing.is_empty() {
                RecoveryAction::ProceedPartial {
                    missing_fields: response.unresolved.clone(),
                    reason: "Non-critical fields missing; proceeding with degraded output".into(),
                }
            } else {
                RecoveryAction::EscalateToHuman {
                    reason: format!("Critical fields missing: {:?}", critical_missing),
                    context: HandoffContext::from_request(request),
                }
            }
        }

        // Strategy 3: All retries exhausted -- escalate
        HandoffStatus::Failed => {
            RecoveryAction::EscalateToHuman {
                reason: format!(
                    "All {} retry attempts exhausted for {} -> {}",
                    attempt, request.source_crate, request.target_crate
                ),
                context: HandoffContext::from_request(request),
            }
        }

        // Strategy 4: Already escalated upstream
        HandoffStatus::Escalated => {
            RecoveryAction::SkipAndContinue {
                skipped_item: request.target_crate.clone(),
                reason: "Target escalated; skipping to avoid blocking pipeline".into(),
            }
        }

        _ => RecoveryAction::FallbackDefault {
            default_value: Box::new(()),
            reason: "Unexpected response status; using default".into(),
        },
    }
}

/// Determine fallback targets in order of preference.
fn next_fallback_target(request: &RuntimeHandoffRequest, attempt: usize) -> String {
    let fallbacks = match request.target_layer {
        1 => vec!["issen-pipeline-fallback", "raw-byte-passthrough"],
        2 => vec!["issen-pipeline-flat-fs", "skip-filesystem"],
        3 => vec!["issen-core-generic-parser", "skip-artifact"],
        4 => vec!["issen-core-basic-analysis", "skip-analysis"],
        _ => vec!["skip"],
    };
    fallbacks.get(attempt.saturating_sub(1))
        .unwrap_or(&"skip")
        .to_string()
}
```

### 6.2 Development-Time Failure Recovery

| Failure Mode | Detection | Recovery Strategy |
|-------------|-----------|-------------------|
| CI fails after handoff | GitHub Actions status check | Source agent fixes; does NOT amend -- creates new commit |
| Target agent cannot fulfill request | HandoffResponse with status=failed | Escalate to human; decompose into smaller handoffs |
| Cross-crate test regression | Integration test suite | Both agents coordinate via shared branch; bisect to find breaking change |
| License boundary violation | `cargo deny check` in CI | Block merge; source agent moves code to correct crate |
| Plugin WIT conformance failure | Automated WIT validator | Community reviewer provides specific fix guidance |
| Merge conflict on shared types (issen-core) | Git merge conflict | RFC process; both agents rebase on main after issen-core merge |

### 6.3 Recovery Strategies Summary

| Strategy | When to Use | Trade-off |
|----------|-------------|-----------|
| **Retry Different Target** | Primary handler failed but alternatives exist | Increased latency (up to 3x single handoff) |
| **Proceed Partial** | Non-critical data missing; core pipeline can continue | Lower quality output; degraded fields flagged in report |
| **Escalate to Human** | Critical decision, legal implication, or all retries exhausted | Blocks pipeline until human responds |
| **Skip and Continue** | Optional enhancement failed (e.g., YARA scan timeout) | Missing enhancement noted in report |
| **Fallback Default** | All else fails; need some output | Generic/conservative response; clearly marked |
| **Decompose and Retry** | Handoff too large for single agent | More handoff overhead but higher success rate |

---

## 7. Onboarding Handoff Protocol

### 7.1 New Contributor Onboarding

When a new contributor joins the open-source repository, the onboarding handoff ensures they have context without requiring synchronous communication.

```
NEW CONTRIBUTOR ONBOARDING CHECKLIST

1. ENTRY POINT
   └── README.md -> CONTRIBUTING.md -> north-star-advisor/docs/INDEX.md

2. CONTEXT LOADING (self-serve, no handoff needed)
   ├── Read: north-star-advisor/ai-context.yml (strategic context)
   ├── Read: north-star-advisor/docs/ARCHITECTURE_BLUEPRINT.md (system design)
   ├── Read: docs/rfcs/ (design decisions and rationale)
   └── Run: cargo test (verify local setup)

3. FIRST CONTRIBUTION HANDOFF
   ├── Contributor picks issue tagged "good first issue"
   ├── Issue contains: crate scope, expected trait/type changes, test expectations
   ├── Contributor opens draft PR early (signals intent, enables feedback)
   └── Maintainer (or infra-agent) provides: review within 48 hours

4. GRADUATION TO CRATE OWNER
   ├── After 3+ merged PRs in a single crate
   ├── Maintainer handoff: write access to crate, CI reviewer role
   └── Added to CODEOWNERS for that crate's path
```

### 7.2 Community Plugin Developer Onboarding

```
PLUGIN DEVELOPER FAST PATH

1. Install SDK:    cargo add issen-plugin-sdk
2. Scaffold:       cargo issen-plugin new my-parser
3. Implement:      Parser trait (3 required methods)
4. Test locally:   cargo issen-plugin test --fixtures ./test-data/
5. Submit PR:      gh pr create --label "community-plugin"

HANDOFF TO REVIEWER:
   - Automated: CI runs WIT conformance, fuzz tests, size checks
   - Human: Reviewer assigned from CODEOWNERS[plugins/]
   - SLA: First review within 72 hours
   - Iteration: Max 3 review rounds before maintainer pair-programs
```

---

## Validation Checklist

- [x] HandoffRequest, HandoffResponse, and HandoffDecision schemas defined (Sections 2.1-2.4)
- [x] Valid handoff routes cover all agent combinations (Section 3.1, 3.2)
- [x] Invalid routes (anti-patterns) documented with rationale (Section 3.3)
- [x] Circular handoff detection implemented in HandoffManager (Section 4.1)
- [x] Human escalation path defined (Section 6.1, Strategy 3)
- [x] Observability: traces and metrics defined (Section 5.1, 5.2)
- [x] Open-source/proprietary boundary protocol specified (Section 4.3)
- [x] Community contributor and plugin developer onboarding covered (Section 7)
- [x] Recovery strategies >= 3 defined (Section 6.3: 6 strategies)
- [x] All schemas use semver versioning (HANDOFF_SCHEMA_VERSION = '1.0.0')
- [x] Limits align with architecture latency budget: runtime timeout 10s << TARR 4hr budget (Section 3.4)
