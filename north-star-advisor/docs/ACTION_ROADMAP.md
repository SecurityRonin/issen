# Issen: Action Roadmap

<!-- GENERATION: Phase 12 of 13. Requires outputs from STRATEGIC_RECOMMENDATION, NORTHSTAR, ARCHITECTURE_BLUEPRINT, BRAND_GUIDELINES, COMPETITIVE_LANDSCAPE. -->

> **Tier**: 1 --- Execution Authority
> **Created**: 2026-03-20
> **Status**: Active
> **Generation Step**: 12 of 13
> **Recommended Path**: B --- Report Engine First
> **North Star**: TARR < 4 hours (from ~16hr baseline)

---

## Part 1: Strategic Context

### 1.1 Where We Are

Issen is a forensic triage platform that transforms digital forensic artifacts into attorney-ready reports. The founder is a solo practitioner with direct consulting experience in the forensic-to-legal translation gap. Development is bootstrapped through consulting revenue.

**Current Assets:**

| Asset | Status | Role in Roadmap |
|-------|--------|-----------------|
| `usnjrnl-forensic` v0.6 | Published crate | Port to `issen-parser-usnjrnl` (ForensicParser trait) |
| `tl` v0.1 | Published crate | Timeline merge/query foundation for `issen-timeline` |
| `ewf` v0.1 | Published crate | E01 evidence format reader for `issen-pipeline` Layer 0 |
| `shrinkpath` v0.1 | Published crate | Memory-efficient path handling for artifact storage |
| Architecture decision | Hexagonal (Crux-inspired) | Side-effect-free `issen-core` with port/adapter frontends |
| Strategic recommendation | Path B selected | Report Engine First --- ship the differentiator from day one |

### 1.2 Where We Need to Be

**90-Day Target State:** A working end-to-end pipeline that ingests KAPE collections containing USN Journal, MFT, and EventLog artifacts; produces a unified DuckDB timeline; and generates dual-format attorney-ready reports (interactive HTML + Word document) with optional AI-assisted narrative generation.

**North Star Metric:** Time-to-Attorney-Ready Report (TARR) < 4 hours for a standard 3-parser IR triage case, down from ~16 hours manual baseline.

### 1.3 Why Path B (Report Engine First)

Path B was selected with a weighted score of 4.50/5.00 against strategic priorities (Path A: 2.15, Path C: 2.30). The reasoning:

1. **TARR is the North Star, and the report IS the bottleneck.** 80% of engagement time is report writing. A report engine reduces TARR by 8--12 hours. Faster parsers reduce TARR by ~2 hours.
2. **No competitor has attorney-ready output.** The "Full Workflow + Practitioner-Friendly" quadrant is empty. Magnet AXIOM has AI triage but poor reports. X-Ways has fast parsing but zero reports. This is the only genuine gap.
3. **Revenue from day one.** The proprietary report engine is the monetizable product. Path A builds the free tier first; Path B builds the paid product first.
4. **3 parsers cover 60--70% of typical IR triage.** USN Journal (file activity), MFT (file system metadata), and EventLog (authentication/execution events) handle the majority of standard incident response engagements.

### 1.4 Competitive Timing

The market window is 12--18 months before Magnet adds AI-powered reporting to AXIOM. PE consolidation (Thoma Bravo/Magnet $1.8B acquisition) is squeezing practitioners. Open-source positioning exploits this frustration. Court pressure on deliverable quality (Daubert challenges +35%) makes attorney-ready output table stakes.

**Positioning shorthand:** X-Ways speed + AXIOM coverage + attorney-ready reports nobody else built.

---

## Part 2: 30-Day Focus (Days 1--30) --- "Foundation Sprint"

**Theme:** Wire the Pipeline End-to-End

**Start Date:** 2026-03-21
**End Date:** 2026-04-19
**Owner:** Solo founder

The goal is simple: get a single artifact type flowing through the entire pipeline from evidence ingestion to a viewable HTML report. This validates the hexagonal architecture, the DuckDB timeline schema, and the report rendering path before adding complexity.

### Focus 1: issen-core + issen-pipeline Foundation

**TARR Stage Impacted:** Analysis automation (parser infrastructure)
**Estimated TARR Contribution:** Enables all downstream TARR reduction

| Deliverable | Acceptance Criteria | Notes |
|-------------|---------------------|-------|
| `TimelineEvent` schema defined | DuckDB table + Rust struct with: `event_id`, `timestamp_ns`, `source_type`, `artifact_path`, `description`, `raw_data`, `evidence_id`, `case_id` | Canonical schema shared by all parsers. Changes here ripple everywhere --- get it right. |
| Layer 0--4 pipeline skeleton | Sequential processing (no parallelism): format detection -> source mounting -> artifact discovery -> parsing -> timeline insertion | Correctness first. Parallelism (rayon) comes in 60-day phase. |
| `issen-parser-usnjrnl` | Port `usnjrnl-forensic` v0.6 into ForensicParser trait. Emit `TimelineEvent` structs into DuckDB timeline. | Reuse existing parsing logic. The port is about the trait interface, not rewriting the parser. |
| KAPE-to-timeline wire-up | `issen-cli ingest ./kape-output` populates DuckDB timeline with USN Journal events | Happy path only. Error handling for malformed evidence is 60-day scope. |

**Definition of Done:** `issen-cli ingest ./kape-output` produces a populated DuckDB timeline from a real KAPE collection. All USN Journal events have correct timestamps verified against EZ Tools (MFTECmd) reference output.

**Resource Allocation:** 40% of 30-day budget

### Focus 2: issen-timeline Query Engine

**TARR Stage Impacted:** Analysis (navigable timeline reduces manual artifact correlation)
**Estimated TARR Contribution:** -0.5 to -1 hour

| Deliverable | Acceptance Criteria | Notes |
|-------------|---------------------|-------|
| Time-range queries | `issen-cli timeline --from "2026-01-01" --to "2026-01-31"` returns filtered events | DuckDB SQL under the hood. Expose through clean Rust API. |
| Source-type filtering | `issen-cli timeline --source usnjrnl --from --to` | Filter by parser origin. |
| SQLite export | `issen-cli export --format sqlite ./case.db` | Portable case file. Enables offline review. |
| Event count summary | `issen-cli timeline --summary` shows event counts by source type and date range | Quick sanity check for examiners. |

**Definition of Done:** `issen-cli timeline --from --to` returns filtered events. SQLite export produces a valid, queryable database.

**Resource Allocation:** 20% of 30-day budget

### Focus 3: issen-report MVP (HTML Only)

**TARR Stage Impacted:** Report writing (manual -> automated) --- the primary TARR bottleneck
**Estimated TARR Contribution:** -3 to -4 hours (HTML only, narrative manual)

| Deliverable | Acceptance Criteria | Notes |
|-------------|---------------------|-------|
| Askama HTML template | Self-contained single-file output. Embedded CSS/JS. No external dependencies (no CDN, no network). | Attorney opens file in browser, it works. Period. |
| Timeline visualization | Interactive timeline with zoom, pan, filter. Events color-coded by source type. | Use embedded JavaScript (D3.js or custom). Self-contained. |
| Filterable event table | Sortable, searchable table of all timeline events. Column filters for source type, date range, keyword. | Core navigation for examiners reviewing the timeline. |
| Evidence summary | Case metadata, evidence sources, hash values (SHA-256), examiner identity, generation timestamp. | Chain-of-custody foundation. |
| Findings placeholder | Section for examiner-entered findings with manual text entry. No AI yet. | Structure is ready for AI-assisted narrative generation in 90-day phase. |

**Definition of Done:** `issen-cli report --format html` produces an attorney-browseable HTML file from the DuckDB timeline. The report is self-contained, opens offline, and an attorney can navigate the timeline and event table without technical assistance.

**Resource Allocation:** 30% of 30-day budget

### 30-Day Success Criteria

| Criterion | Target | How to Measure |
|-----------|--------|----------------|
| Pipeline completeness | USN Journal events flowing from KAPE collection to HTML report | `issen-cli ingest && issen-cli report --format html` produces viewable output |
| TARR (USN-only) | < 30 minutes (with manual findings entry) | Stopwatch from `ingest` command to examiner-reviewed HTML report |
| External dependencies | Zero for core pipeline (no cloud, no AI, no network) | `cargo build --release` produces single binary; report works offline |
| Code quality | All code compiles, tests pass, CI green | `cargo test --workspace && cargo clippy --workspace` |
| Parser accuracy | 100% timestamp accuracy vs. EZ Tools reference | Automated regression test against known-good KAPE output |

### 30-Day Buffer

10% of the 30-day budget is reserved for:
- Unexpected DuckDB Rust binding issues (fallback: SQLite for timeline storage)
- Build system / CI setup (GitHub Actions: fmt + clippy + test + coverage)
- Writing initial integration tests

---

## Part 3: What to Avoid (30-Day Scope)

Every item on this list traces to a strategic rationale. Violating this list means scope creep that delays the core differentiator.

| Avoid Item | Rationale | When It Becomes Relevant |
|------------|-----------|--------------------------|
| **Building TUI/GUI** | CLI-only validates the pipeline without frontend complexity. Desktop GUI (Tauri) is Phase 2. | After TARR < 4hr validated on CLI |
| **Adding AI/LLM features** | Report engine first, intelligence later. AI narrative without a report engine has nowhere to render. | 90-day phase (issen-intel MVP) |
| **Multiple parser types** | USN-only for pipeline validation. Adding MFT/EVTX before the pipeline is proven means debugging parser bugs and pipeline bugs simultaneously. | 60-day phase (Focus 1) |
| **Enterprise features (SSO, teams, audit)** | Solo practitioner first. Enterprise features serve a persona (James Okafor, CISO) that is Phase 3+. | After first paying user (M3) |
| **WASM plugin system** | Compile-time traits only for MVP. WASM (Wasmtime + WIT) is tier-2 plugin system for community contributions. | 90-day phase (Plugin SDK) |
| **Optimizing performance** | Correctness first. A correct parser that processes 1GB/min is shippable. An incorrect parser that processes 10GB/min is dangerous. Aligns with "Correctness Over Speed" axiom. | After 3-parser accuracy validated |
| **Building a website/marketing** | Product first. Marketing an unfinished product wastes the first impression. Community launch is the 90-day phase. | After `issen-cli` produces attorney-reviewed output |
| **DOCX/PDF report format** | HTML-only for 30-day. Word generation adds significant complexity (multilevel numbering, page layout, styling). HTML proves the report content works before adding format complexity. | 60-day phase (Focus 2) |
| **Parallelism (rayon)** | Sequential processing for 30-day. Correctness of the pipeline matters more than throughput. Single-artifact ingestion does not need parallelism. | 60-day phase (3-parser pipeline) |
| **Database migrations / schema versioning** | The TimelineEvent schema will change. Accept breaking changes during MVP. Schema versioning adds complexity for zero users. | After alpha release to consulting clients |

---

## Part 4: 60-Day Focus (Days 31--60) --- "Parser Breadth + DOCX Reports"

**Theme:** Three Parsers, Two Formats

**Start Date:** 2026-04-20
**End Date:** 2026-05-19
**Owner:** Solo founder

The 30-day sprint proved the pipeline works for a single artifact type. Now expand to the three artifact types that cover 60--70% of IR triage cases and add the attorney-critical Word document output format.

### Focus 1: MFT and EventLog Parsers

**TARR Stage Impacted:** Analysis breadth (more artifacts = fewer manual lookups)
**Estimated TARR Contribution:** -1 hour combined

| Deliverable | Acceptance Criteria | Notes |
|-------------|---------------------|-------|
| `issen-parser-mft` | Parse Master File Table. Emit `TimelineEvent` structs. File metadata: timestamps (MACE), path, size, flags (resident/non-resident), parent directory. | Validate against MFTECmd reference output. 100% timestamp accuracy on NIST test images. |
| `issen-parser-evtx` | Parse Windows Event Logs (EVTX format). Security, System, PowerShell/Operational channels. Emit structured `TimelineEvent` with EID, channel, provider, and parsed XML data. | Validate against EVTX-ATTACK-SAMPLES reference dataset. Cover the top 50 forensically-relevant Event IDs. |
| ForensicParser trait validation | Both new parsers implement the same `ForensicParser` trait as USN. Zero trait modifications needed. | If the trait needs modification, the 30-day architecture was wrong. Fix the trait, then proceed. |
| Parallel ingestion | rayon-based parallel parsing. USN, MFT, and EVTX parse concurrently from the same KAPE collection. | Correctness verified: identical timeline output in sequential vs. parallel mode. |
| Unified timeline | `issen-cli ingest ./kape-output` produces a single DuckDB timeline with events from all three parsers, properly interleaved by timestamp. | Cross-source event ordering must be correct. Nanosecond timestamp precision prevents ties. |

**Definition of Done:** 3 parsers produce a unified, correctly-ordered timeline from a real KAPE collection. Each parser passes accuracy validation against reference tools.

### Focus 2: DOCX Report Generation

**TARR Stage Impacted:** Report formatting and delivery (-1 to -2 hours), legal formatting (-0.5 to -1 hour)
**Estimated TARR Contribution:** -1.5 to -3 hours

| Deliverable | Acceptance Criteria | Notes |
|-------------|---------------------|-------|
| Word document output | `issen-cli report --format docx` produces a .docx file from the same data as the HTML report | Use docx-rs for Rust-native generation. python-docx subprocess fallback if complex formatting exceeds docx-rs capabilities. |
| Multilevel heading numbering | Heading numbers come from Word's `w:abstractNum` + `w:numPr` system. Never embed literal section numbers in heading text. | Per CLAUDE.md global directive. Non-sequential numbering uses `w:startOverride`. |
| Examiner findings section | Structured section with placeholder text for examiner-authored narrative. Clearly labeled "EXAMINER FINDINGS --- COMPLETE BEFORE SUBMISSION." | Attorney-ready template that the examiner fills in. Structure guides the narrative. |
| Chain-of-custody page | Evidence source list, SHA-256 hashes for each evidence file, examiner identity, tool version, processing timestamps. | Legal requirement. Must match the evidence hashes computed during ingestion. |
| Exhibit numbering | Automatic exhibit numbering for timeline screenshots, key artifacts, and findings references. Cross-references work when document is regenerated. | Legal formatting requirement. Attorneys expect exhibit references in narrative. |
| Executive summary page | One-page summary: case overview, key findings (bullet points), timeline span, evidence sources, TARR measurement. | First thing the attorney reads. Must stand alone. |

**Definition of Done:** `issen-cli report --format docx` produces a Word document that an attorney confirms as "usable without reformatting." Heading numbering is correct. Exhibit cross-references work.

### Focus 3: Open-Source First Parsers

**TARR Stage Impacted:** Community ecosystem (long-term TARR reduction through contributed parsers)
**Estimated TARR Contribution:** Indirect; enables community parser contributions

| Deliverable | Acceptance Criteria | Notes |
|-------------|---------------------|-------|
| Publish `issen-parser-usnjrnl` | Separate crate on crates.io. Apache 2.0 license. CI/CD. Documented API with examples. | First open-source crate. Sets the quality bar for all subsequent releases. |
| Publish `issen-parser-mft` | Same quality standard as USN crate. | Second crate. Demonstrates the pattern is repeatable. |
| Publish `issen-parser-evtx` | Same quality standard. | Third crate. Three published crates shows commitment. |
| GitHub repository | `github.com/h4x0r/issen`. Cargo workspace monorepo. Apache 2.0 license. README with quick start. | The public-facing repository. First impressions matter. |
| Open-core boundary | Public crates never depend on proprietary crates. Proprietary `issen-report` (DOCX/PDF) lives in `issen-pro`. | Enforce with `cargo deny` or CI check. |

**Definition of Done:** Three parser crates published on crates.io with passing CI, documentation, and examples. GitHub repository is public with Apache 2.0 license.

### 60-Day Milestones

| Milestone | Target | How to Measure |
|-----------|--------|----------------|
| 3-parser unified timeline | Correct, interleaved timeline from real KAPE collection | Automated test: event ordering verified across source types |
| Dual-format output | HTML + DOCX from same pipeline | `issen-cli report --format html` and `issen-cli report --format docx` both produce valid output |
| Public GitHub repo | Apache 2.0 parsers published | Repo accessible at `github.com/h4x0r/issen` |
| TARR (3-parser) | < 2 hours (with manual findings entry) | Stopwatch on real consulting engagement KAPE collection |
| Parser accuracy | All 3 parsers pass reference validation | CI regression tests vs. EZ Tools and EVTX-ATTACK-SAMPLES |

---

## Part 5: 90-Day Focus (Days 61--90) --- "Intelligence + Community"

**Theme:** AI-Assisted Findings, Community First Impression

**Start Date:** 2026-05-20
**End Date:** 2026-06-18
**Owner:** Solo founder

The pipeline works. Three parsers feed a unified timeline. Dual-format reports ship. Now add the intelligence layer that automates narrative generation and prepare for community launch.

### Focus 1: issen-intel MVP

**TARR Stage Impacted:** Finding-to-prose translation (-2 to -3 hours)
**Estimated TARR Contribution:** -2 to -3 hours

| Deliverable | Acceptance Criteria | Notes |
|-------------|---------------------|-------|
| Ollama integration | Local LLM generates finding narratives from structured timeline data. No cloud dependency. No API keys. | Use `ForensicLLM` trait to abstract the LLM provider. Ollama is the default; provider-agnostic design. |
| Grounded generation | Template+fill approach: narrative templates with slots filled from TimelineEvent data. Every claim cites specific `event_id` references. | No hallucinated facts. Every statement in the generated narrative must trace to a specific timeline event. Factual accuracy > 95%. |
| AI-free mode | Toggle `--no-ai` flag. All features work without LLM. Report generates with structured template placeholders instead of AI narrative. | Non-negotiable. Examiners must be able to use the tool without any AI dependency. Aligns with "zero external dependencies" principle. |
| Narrative quality | Attorney reviews AI-generated narrative and confirms: readable, factually grounded, cites evidence correctly. | User testing with consulting clients. Threshold: > 80% of narrative sections usable without rewriting. |
| Findings auto-detection | Basic heuristic detection of significant events (failed logins, file deletions, service installations, PowerShell execution). Proposed as findings for examiner review. | Examiner approves/rejects each proposed finding. AI suggests; human decides. |

**Definition of Done:** `issen-cli report --format docx --ai` produces a Word document with AI-generated narrative sections that an attorney finds readable and an examiner finds factually accurate. `--no-ai` flag disables all AI features and the report still generates correctly.

### Focus 2: Plugin SDK + Community Preparation

**TARR Stage Impacted:** Parser coverage (community-contributed parsers expand artifact coverage)
**Estimated TARR Contribution:** Indirect; multiplies development velocity beyond solo founder capacity

| Deliverable | Acceptance Criteria | Notes |
|-------------|---------------------|-------|
| `issen-plugin-sdk` crate | Published crate with `ForensicParser` trait, `EventEmitter` trait, type definitions, and test harness. | Third-party developers can implement a parser without reading issen-core source code. |
| Example plugin: `issen-parser-prefetch` | Windows Prefetch parser implemented using only the public SDK. Demonstrates the full plugin lifecycle: parse -> emit -> timeline integration. | Proof that the SDK is sufficient. If the example plugin needs internal APIs, the SDK is incomplete. |
| Test harness | `issen-plugin-sdk` includes a test harness that validates parser output against expected schema. Runs golden-file tests. | Contributors run `cargo test` on their parser and get clear pass/fail without understanding the pipeline. |
| Contribution guide | `CONTRIBUTING.md` with: how to add a parser, trait requirements, test expectations, CI integration, code review process. | Lower the barrier to contribution. Every friction point is a lost contributor. |
| Plugin documentation | API docs for `issen-plugin-sdk` on docs.rs. Tutorial: "Build Your First Issen Parser in 30 Minutes." | Documentation is the product for community contributors. |

**Definition of Done:** A developer with Rust experience but no Issen knowledge can implement a parser using only the published `issen-plugin-sdk` crate and documentation.

### Focus 3: Community Launch

**TARR Stage Impacted:** Long-term ecosystem growth (more parsers = broader artifact coverage = lower TARR)
**Estimated TARR Contribution:** Strategic; positions Issen for sustained TARR reduction

| Deliverable | Acceptance Criteria | Notes |
|-------------|---------------------|-------|
| DFIR community announcement | Blog post or forum post introducing Issen. TARR demo (video or GIF). Honest about what it does and does not do. | Target channels: DFIR Slack, r/computerforensics, forensicfocus.com, Forensic Lunch. |
| GitHub Discussions | Enabled on the repository. Seeded with: FAQ, feature request template, parser request template. | Community interaction happens on GitHub, not in private channels. |
| README with impact | Quick start (< 5 minutes to first report), screenshots of HTML and DOCX output, TARR measurement results. | The README is the landing page. It must demonstrate value in 30 seconds. |
| Demo KAPE collection | Synthetic (no real evidence) KAPE collection included in the repo for testing and demonstration. | Contributors and evaluators need evidence to test against. Synthetic avoids legal issues. |

**Definition of Done:** Public announcement made. GitHub repo has README, CONTRIBUTING.md, Discussions enabled, and a demo KAPE collection. At least one person outside the founder's immediate network has tried the tool.

### 90-Day Phase Gate

| Decision | Criteria | Action |
|----------|----------|--------|
| **Proceed to Phase 2** | TARR < 4 hours for 3-parser case AND 10+ GitHub stars AND 1+ community PR or issue | Proceed to desktop GUI (Tauri), additional parsers, and professional polish |
| **Iterate on Phase 1** | TARR > 4 hours but < 8 hours, OR no community engagement despite marketing effort | Diagnose TARR bottleneck. Is it parsing, report generation, or AI narrative? Fix the bottleneck stage before expanding. |
| **Pivot** | TARR > 8 hours, OR zero external interest after 30 days of community marketing | Fundamental re-evaluation. Consider: (a) the problem is not as painful as believed, (b) the solution approach is wrong, (c) the market is smaller than estimated. |

---

## Part 6: Risk Management

### 6.1 Risk Register

| # | Risk | Probability | Impact | Mitigation | Trigger for Escalation |
|---|------|-------------|--------|------------|------------------------|
| R1 | **Solo founder bandwidth collapse** | Medium | Critical | Consulting revenue provides runway. Scope ruthlessly to 30-day increments. No feature creep. Accept imperfect releases. | Consulting commitments exceed 30 hours/week for 3+ consecutive weeks |
| R2 | **DuckDB Rust bindings immaturity** | Medium | High | SQLite fallback path exists. The `tl` crate already supports SQLite. DuckDB is preferred (columnar, analytical queries) but not mandatory. | DuckDB binding causes data corruption or > 5 blocking bugs in 30-day sprint |
| R3 | **DOCX generation complexity** | Medium | Medium | python-docx subprocess fallback for complex formatting. Start with simple templates. Multilevel numbering is the known hard part (per CLAUDE.md). | docx-rs cannot produce correct multilevel heading numbering after 1 week of effort |
| R4 | **Zero community uptake** | Medium | Medium | Conference talks (DFIR community events), DFIR Slack promotion, practitioner network outreach. Consulting clients are guaranteed first users. | Fewer than 10 GitHub stars and zero external issues after 30 days of public availability |
| R5 | **Magnet announces AI-powered reporting** | Low-Medium | High | Accelerate. Ship faster with less polish. Issen advantages (open-source, Rust performance, offline-first, no vendor lock-in) persist even if Magnet adds reporting. | Magnet product announcement or user reviews mention report quality improvements |
| R6 | **3-parser coverage too narrow** | Medium | Medium | USN + MFT + EVTX cover 60--70% of standard IR triage. If real engagements consistently require Registry or Prefetch, accelerate those parsers. Community plugin SDK enables external contributions. | > 40% of real engagements require artifacts outside the 3-parser set |
| R7 | **Local LLM narrative quality insufficient** | Medium | Low | Fall back to structured template-based reports (fill-in-the-blank). Still faster than manual, just less polished. AI narrative becomes Phase 2 feature when models improve. Adjust TARR target to < 6 hours. | Attorney feedback consistently rejects AI narratives; > 50% of sections require manual rewriting |
| R8 | **TimelineEvent schema churn** | Low | Medium | Accept breaking changes during MVP. No external users depend on the schema yet. Stabilize before community launch (90-day phase). | Schema changes required more than 3 times during the 60-day phase |

### 6.2 Dependency Map

```
30-Day Deliverables
  issen-core (TimelineEvent schema)
    |-- issen-pipeline (Layer 0-4 skeleton)
    |     |-- issen-parser-usnjrnl (ForensicParser trait)
    |-- issen-timeline (DuckDB query engine)
    |-- issen-report (HTML template)
    |     |-- Depends on: issen-timeline (query data), issen-core (types)

60-Day Deliverables
  issen-parser-mft -------|
  issen-parser-evtx ------|--> Unified timeline (depends on 30-day pipeline)
  issen-report DOCX ------|--> Depends on: 30-day HTML report (shared data model)
  Open-source publish --|--> Depends on: passing CI, documentation

90-Day Deliverables
  issen-intel (Ollama) -------|--> Depends on: 60-day timeline + report
  issen-plugin-sdk -----------|--> Depends on: validated ForensicParser trait (60-day)
  Community launch ---------|--> Depends on: published crates, README, demo data
```

### 6.3 Critical Path

The critical path runs through:

1. **TimelineEvent schema** (blocks everything)
2. **issen-pipeline skeleton** (blocks parser integration)
3. **issen-parser-usnjrnl port** (validates pipeline)
4. **issen-report HTML** (validates report rendering)
5. **3-parser unified timeline** (validates architecture at scale)
6. **issen-report DOCX** (delivers the attorney-ready differentiator)

If any critical-path item slips, the downstream schedule shifts. Non-critical items (SQLite export, AI narrative, community launch) can be deferred without affecting TARR validation.

---

## Part 7: Resource Allocation

### 7.1 30-Day Budget (Days 1--30)

| Category | Allocation | Hours/Week (est. 20hr/wk dev) | Key Outputs |
|----------|------------|-------------------------------|-------------|
| **issen-core + issen-pipeline** | 40% | 8 hrs/wk | TimelineEvent schema, Layer 0-4 skeleton, USN parser port |
| **issen-timeline** | 20% | 4 hrs/wk | DuckDB queries, SQLite export |
| **issen-report (HTML)** | 30% | 6 hrs/wk | Askama template, timeline visualization, event table |
| **Buffer / testing** | 10% | 2 hrs/wk | CI setup, integration tests, DuckDB fallback investigation |

### 7.2 60-Day Budget (Days 31--60)

| Category | Allocation | Hours/Week (est. 20hr/wk dev) | Key Outputs |
|----------|------------|-------------------------------|-------------|
| **MFT + EVTX parsers** | 35% | 7 hrs/wk | Two new parsers, parallel ingestion, unified timeline |
| **issen-report (DOCX)** | 35% | 7 hrs/wk | Word generation, multilevel numbering, exhibit cross-refs |
| **Open-source publishing** | 20% | 4 hrs/wk | 3 crates on crates.io, GitHub repo, documentation |
| **Buffer / testing** | 10% | 2 hrs/wk | Parser accuracy validation, regression tests |

### 7.3 90-Day Budget (Days 61--90)

| Category | Allocation | Hours/Week (est. 20hr/wk dev) | Key Outputs |
|----------|------------|-------------------------------|-------------|
| **issen-intel (AI narrative)** | 35% | 7 hrs/wk | Ollama integration, grounded generation, AI-free mode |
| **Plugin SDK** | 25% | 5 hrs/wk | issen-plugin-sdk crate, example parser, test harness |
| **Community launch** | 25% | 5 hrs/wk | Announcement, README, demo data, GitHub Discussions |
| **Buffer / testing** | 15% | 3 hrs/wk | Attorney user testing, TARR measurement on real cases |

### 7.4 Assumptions

- **Development hours:** ~20 hours/week available for Issen development (remainder is consulting revenue work)
- **Consulting constraint:** If consulting commitments exceed 30 hours/week for 3+ consecutive weeks, roadmap timelines extend proportionally
- **No hired help:** All development is solo founder. No contractors, no contributors until community launch
- **Infrastructure cost:** $0 for MVP. No cloud services. Ollama runs locally. GitHub free tier for public repo.

---

## Part 8: Review Schedule

### 8.1 Weekly Review (Every Friday)

| Review Item | Question | Data Source |
|-------------|----------|-------------|
| **Progress vs. plan** | Are we on track for the current 30-day focus? | Task completion rate |
| **Blockers** | What is preventing progress? Is it a risk from the register? | Development log |
| **TARR measurement** | What is current TARR for the available pipeline? | Stopwatch test on latest build |
| **Scope creep check** | Did anything from the Avoid List sneak in this week? | Code review of week's commits |

### 8.2 30-Day Checkpoint (Day 30: 2026-04-19)

**Formal review against 30-Day Success Criteria.**

| Criterion | Pass | Fail Action |
|-----------|------|-------------|
| USN events in HTML report | Pipeline works end-to-end | Diagnose: is the bottleneck in parsing, timeline, or report? Fix before proceeding. |
| TARR < 30 min (USN-only) | On track | Review pipeline performance. Is DuckDB the bottleneck? Switch to SQLite fallback. |
| Zero external dependencies | Single binary, offline report | Remove any cloud/network dependencies that crept in. |
| CI green | Code quality maintained | Fix CI before adding new features. Broken CI compounds. |

**Decision:** Proceed to 60-day phase OR iterate on 30-day foundations if criteria not met.

### 8.3 60-Day Checkpoint (Day 60: 2026-05-19)

**Formal review against 60-Day Milestones.**

| Criterion | Pass | Fail Action |
|-----------|------|-------------|
| 3-parser unified timeline | Correct cross-source ordering | Debug timestamp handling. This is a correctness issue --- do not proceed until fixed. |
| Dual-format output (HTML + DOCX) | Attorney reviews DOCX as "usable" | If DOCX is blocking, ship HTML-only to consulting clients and iterate on DOCX in background. |
| TARR < 2 hours (3-parser) | TARR reduction on track for < 4hr target | Identify which pipeline stage consumes the most time. Focus 90-day effort on that stage. |
| Public GitHub repo | Parsers published, repo accessible | If not published, community launch in 90-day is blocked. Prioritize publishing. |

**Decision:** Proceed to 90-day phase OR extend 60-day work if DOCX or parser accuracy not ready.

### 8.4 90-Day Phase Gate (Day 90: 2026-06-18)

**Formal phase gate with proceed/iterate/pivot decision.**

| Gate | Criteria | Outcome |
|------|----------|---------|
| **Proceed** | TARR < 4 hours (3-parser case) + 10+ GitHub stars + 1+ community PR/issue | Move to Phase 2: Desktop GUI (Tauri), additional parsers (Registry, Prefetch), professional polish |
| **Iterate** | TARR 4--8 hours OR community engagement below threshold | Fix TARR bottleneck. Extend community outreach. Re-evaluate in 30 days. |
| **Pivot** | TARR > 8 hours OR zero external interest after marketing | Full strategic review. Revisit Path selection. Consider alternative market positioning. |

### 8.5 Strategic Review Triggers (Anytime)

These triggers cause an immediate strategic review regardless of scheduled checkpoints:

| Trigger | Threshold | Action |
|---------|-----------|--------|
| **TARR not improving** | TARR > 8 hours after 8 weeks of development | Stop and diagnose. Is the bottleneck in parsing, report generation, or AI narrative? |
| **Competitor signal** | Any major competitor announces attorney-ready report capability | Emergency strategy session. Evaluate whether to accelerate, differentiate, or pivot. |
| **AI narrative failure** | Local LLM quality does not reach "attorney-acceptable" after 4 weeks | Descope AI narrative to Phase 2. Ship template-based reports. Adjust TARR target to < 6 hours. |
| **Revenue validation failure** | Zero paying users after 6 months of availability | Fundamental business model review. |
| **Consulting revenue pressure** | Consulting exceeds 30 hours/week for 3+ weeks | Reduce consulting load or accept slower development timeline. |

---

## Part 9: Strategic Milestones (Beyond 90 Days)

For context, these are the macro milestones from the Strategic Recommendation. The 90-day roadmap above covers the work leading to M1.

| Milestone | Target Date | Success Criterion | Kill Criterion |
|-----------|-------------|-------------------|----------------|
| **M1: First attorney-ready report** | End of Q2 2026 | One complete report from evidence-to-deliverable pipeline, used on a real engagement | Cannot produce a report that an attorney accepts without manual rework |
| **M2: TARR < 4 hours validated** | End of Q3 2026 | 3 real engagements completed with TARR < 4 hours, measured end-to-end | Average TARR > 6 hours across 3 engagements |
| **M3: First paying user (non-consulting)** | End of Q4 2026 | Revenue from a practitioner who is not the founder's consulting client | Zero external revenue by end of Q4 2026 |
| **M4: Community parser contribution** | End of Q1 2027 | At least 1 community-contributed parser merged and integrated | Zero community contributions after 6 months of open-source availability |

---

## Appendix A: TARR Reduction Traceability

Every roadmap item traces to a specific TARR reduction. This table maps focus areas to the North Star metric.

| Focus Area | Phase | TARR Stage | Estimated Reduction | Cumulative TARR |
|------------|-------|------------|---------------------|-----------------|
| Baseline (manual workflow) | --- | --- | --- | ~16 hours |
| issen-pipeline + USN parser | 30-day | Evidence ingestion | -0.5 hr | ~15.5 hours |
| issen-timeline query engine | 30-day | Analysis navigation | -0.5 hr | ~15 hours |
| issen-report HTML | 30-day | Report structure | -3 hr | ~12 hours |
| MFT + EVTX parsers | 60-day | Analysis breadth | -1 hr | ~11 hours |
| DOCX report generation | 60-day | Formatting/delivery | -2 hr | ~9 hours |
| Exhibit numbering + citations | 60-day | Legal formatting | -1 hr | ~8 hours |
| AI narrative generation | 90-day | Finding-to-prose | -2.5 hr | ~5.5 hours |
| Cross-artifact correlation | 90-day (stretch) | Manual cross-referencing | -1.5 hr | ~4 hours |

**Target achieved:** TARR < 4 hours at the end of the 90-day roadmap, with AI-assisted narrative generation providing the final reduction from ~5.5 hours to ~4 hours.

---

## Appendix B: Cross-Reference Index

| Document | Key Fields Referenced |
|----------|----------------------|
| `BRAND_GUIDELINES.md` | Product name, beliefs (5 axioms), kill list, positioning statement |
| `NORTHSTAR.md` | TARR metric definition, input metrics, personas (Sarah Chen, Marcus Webb, Diana Reyes), phase boundaries, validation gates |
| `COMPETITIVE_LANDSCAPE.md` | Direct competitors (Magnet AXIOM, Autopsy, X-Ways, FTK), market window (12--18 months), positioning shorthand |
| `ARCHITECTURE_BLUEPRINT.md` | Hexagonal architecture, crate topology, pipeline layers, report engine (Askama), plugin system (3-tier) |
| `STRATEGIC_RECOMMENDATION.md` | Path B rationale, focus areas traced to TARR, avoid list, strategic milestones, confidence assessment |
| `SECURITY_ARCHITECTURE.md` | Trust boundaries, malicious evidence handling, AI hallucination safeguards, Daubert compliance |

---

## Document History

| Date | Version | Change |
|------|---------|--------|
| 2026-03-20 | 1.0 | Initial generation from North Star Advisor Phase 12 |
