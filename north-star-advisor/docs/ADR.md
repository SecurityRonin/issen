# Issen: Architecture Decision Records

> **Tier**: 2 --- Strategic Reference
> **Created**: 2026-03-20
> **Status**: Active
> **Covers**: Phases 1--8 decisions

---

## ADR Index

| ADR | Title | Status | Date | Phase |
|-----|-------|--------|------|-------|
| [ADR-0001](#adr-0001-attorney-ready-reports-as-primary-differentiator) | Attorney-Ready Reports as Primary Differentiator | Accepted | 2026-03-20 | 1 |
| [ADR-0002](#adr-0002-tarr-as-north-star-metric) | TARR as North Star Metric | Accepted | 2026-03-20 | 2 |
| [ADR-0003](#adr-0003-permissive-open-source-licensing-apache-20--mit) | Permissive Open-Source Licensing (Apache 2.0 / MIT) | Accepted | 2026-03-20 | 1 |
| [ADR-0004](#adr-0004-hexagonal-architecture-crux-inspired) | Hexagonal Architecture (Crux-Inspired) | Accepted | 2026-03-20 | 6 |
| [ADR-0005](#adr-0005-duckdb-primary--sqlite-exchange) | DuckDB Primary + SQLite Exchange | Accepted | 2026-03-20 | 6 |
| [ADR-0006](#adr-0006-three-tier-plugin-system) | Three-Tier Plugin System | Accepted | 2026-03-20 | 6 |
| [ADR-0007](#adr-0007-hybrid-publicprivate-repository) | Hybrid Public/Private Repository | Accepted | 2026-03-20 | 1 |
| [ADR-0008](#adr-0008-local-first-ai-via-ollama) | Local-First AI via Ollama | Accepted | 2026-03-20 | 6 |
| [ADR-0009](#adr-0009-dual-repoissen-output-html--docx) | Dual Report Output (HTML + DOCX) | Accepted | 2026-03-20 | 6 |
| [ADR-0010](#adr-0010-grounded-ai-generation-only) | Grounded AI Generation Only | Accepted | 2026-03-20 | 7 |
| [ADR-0011](#adr-0011-no-retry-on-corrupted-evidence) | No Retry on Corrupted Evidence | Accepted | 2026-03-20 | 7d |
| [ADR-0012](#adr-0012-per-pipeline-layer-circuit-breakers) | Per-Pipeline-Layer Circuit Breakers | Accepted | 2026-03-20 | 7d |
| [ADR-0013](#adr-0013-rust-sealed-traits-as-inter-component-authentication) | Rust Sealed Traits as Inter-Component Authentication | Accepted | 2026-03-20 | 8 |
| [ADR-0014](#adr-0014-practitioner-first-enterprise-later) | Practitioner-First, Enterprise-Later | Accepted | 2026-03-20 | 2 |

---

## ADR-0001: Attorney-Ready Reports as Primary Differentiator

**Status**: Accepted
**Date**: 2026-03-20
**Phase**: 1 (Brand Guidelines)

### Context

The digital forensics market (~$9B, ~12% CAGR) has mature tools competing on three axes: parse speed (X-Ways), artifact coverage (Magnet AXIOM), and price (Autopsy/TSK). Despite this maturity, every forensic engagement follows the same pattern: ~20% of effort goes to forensic analysis and ~80% goes to manual report writing, evidence reprocessing, and attorney back-and-forth. This happens because every forensic tool produces engineer-oriented output --- CSV timelines, raw artifact dumps, screenshot galleries --- that attorneys cannot use directly. The forensic-to-legal translation gap is the dominant cost driver in digital forensics engagements, yet no tool addresses it as a primary concern.

### Decision

Issen will compete on the forensic-to-legal translation gap by producing attorney-ready deliverables as its primary output. The report is the product, not a byproduct. Every pipeline stage --- from evidence ingestion through correlation to final output --- is designed and measured by its contribution to producing a deliverable that attorneys can use without examiner hand-holding.

### Alternatives Rejected

| Alternative | Reason for Rejection |
|-------------|----------------------|
| **Compete on parse speed (X-Ways approach)** | X-Ways has 20+ years of optimization and a loyal user base. Speed alone is insufficient differentiation; the bottleneck is report writing, not parsing. Rust gives us competitive speed without making it the selling point. |
| **Compete on artifact coverage (AXIOM approach)** | AXIOM covers 800+ artifact types. Coverage is an arms race with diminishing returns. Adding the 801st parser does not meaningfully reduce engagement time if the report still takes 12 hours to write. |
| **Compete on price (Autopsy approach)** | Autopsy is free and has wide adoption in training and budget-constrained environments. Competing on price in a market with a free option requires a different value proposition entirely. Price competition also undermines the ability to fund continued development as a solo founder. |

### Consequences

**Positive**:
- Creates a defensible market position that no current competitor occupies
- Aligns the entire product around a measurable outcome (time-to-deliverable) rather than a feature checklist
- Directly addresses the highest-cost activity in forensic engagements
- Enables premium pricing justified by time savings (an 8-hour reduction at $300/hr examiner rate = $2,400/engagement saved)

**Trade-offs**:
- Requires deep understanding of legal requirements and attorney workflows, not just forensic technical knowledge
- Report quality becomes the primary attack surface for competitors --- any formatting error, citation gap, or legal terminology mistake is immediately visible to a non-technical audience
- Limits initial market to engagements that produce reports (excludes pure research, malware analysis, and internal-only investigations that never reach legal counsel)

---

## ADR-0002: TARR as North Star Metric

**Status**: Accepted
**Date**: 2026-03-20
**Phase**: 2 (North Star Specification)

### Context

A North Star metric must capture the full value chain from evidence to deliverable, be measurable and time-bound, predict business outcomes (engagement profitability, examiner capacity), and be actionable by every component of the system. Candidate metrics included engagement count, parser count, NPS, artifact coverage percentage, and parse throughput. The project needed a single metric that reflects the brand promise of attorney-ready output and decomposes into actionable input metrics for each pipeline stage.

### Decision

Adopt **Time-to-Attorney-Ready Report (TARR)** as the North Star metric. Definition: elapsed time from evidence ingestion to a completed, attorney-ready deliverable (interactive HTML report or polished Word/PDF expert witness report). Baseline: ~16 hours for a standard IR case using manual workflows. Target: < 4 hours (50%+ reduction). TARR decomposes into three input metrics: Parse-to-Timeline Latency (< 10 min), Findings-to-Narrative Time (< 2 hr), and Report Acceptance Rate (> 80%).

### Alternatives Rejected

| Alternative | Reason for Rejection |
|-------------|----------------------|
| **Engagement count** | A vanity metric that does not distinguish between successful and failed engagements. High engagement count with poor report quality is worse than fewer engagements with excellent output. |
| **Parser count** | Measures capability breadth, not value delivered. Adding parsers is necessary but insufficient --- a tool with 500 parsers and no report engine has a TARR of infinity. |
| **Net Promoter Score (NPS)** | Lagging indicator that is difficult to measure pre-launch and does not decompose into actionable engineering metrics. NPS cannot tell you which pipeline stage to optimize. |
| **Parse throughput (events/sec)** | Optimizes one stage of the pipeline while ignoring the report generation bottleneck that consumes 80% of engagement time. A 10x parsing improvement yields marginal TARR improvement if narrative generation remains manual. |

### Consequences

**Positive**:
- Every team member and every component can trace their work to TARR improvement
- Leading indicator: TARR predicts engagement profitability and examiner capacity before revenue materializes
- Customer-centric: measures value delivered to the examiner, not features shipped
- Decomposition into Parse-to-Timeline, Findings-to-Narrative, and Report Acceptance creates clear ownership boundaries for each crate

**Trade-offs**:
- TARR is influenced by evidence complexity (a 500GB image takes longer than a 10GB KAPE collection), requiring normalization or case-type stratification for meaningful comparison
- Optimizing TARR may create pressure to sacrifice report quality for speed, directly violating the "Correctness > Speed" axiom --- the metric framework must include Report Acceptance Rate as a quality gate
- Measuring TARR requires instrumenting the full pipeline end-to-end, adding telemetry overhead to every stage

---

## ADR-0003: Permissive Open-Source Licensing (Apache 2.0 / MIT)

**Status**: Accepted
**Date**: 2026-03-20
**Phase**: 1 (Brand Guidelines)

### Context

Issen has existing open-source crates (usnjrnl-forensic v0.6, tl v0.1, ewf v0.1, shrinkpath v0.1) already published under Apache 2.0 / MIT dual license. The project needs a licensing strategy for new parsers and the proprietary integration layer. Copyleft licensing (AGPL) could protect against cloud providers repackaging the work, but the forensic community values transparency and code inspection for courtroom admissibility ("you can inspect the code that parsed this evidence"). The primary moat is integration quality, not parser exclusivity.

### Decision

All open-source parsers and utilities use **Apache 2.0 (parsers) / MIT (utilities)** dual permissive licensing. The proprietary integration layer (pipeline, report engine, correlation, UI, enterprise features) remains closed source. A strict dependency rule applies: open-source crates NEVER depend on proprietary crates.

### Alternatives Rejected

| Alternative | Reason for Rejection |
|-------------|----------------------|
| **AGPL dual license (open + commercial)** | Google bans AGPL dependencies internally, which eliminates contributions from the largest employer of software engineers. Corporate legal departments at consulting firms (a primary customer segment) flag AGPL as high-risk. The existing crates are already Apache 2.0/MIT, making a license change disruptive to current users. |
| **Single private repository (all proprietary)** | Eliminates the courtroom transparency benefit ("the code is open, inspect it yourself"). Destroys community contribution potential. Conflicts with the "Open Parsers, Proprietary Integration" brand belief. Solo founder cannot match the testing surface area of community contributors. |
| **Business Source License (BSL)** | BSL's delayed open-source conversion adds legal complexity. The time-delay mechanism confuses potential contributors and corporate adopters. It signals distrust of the community rather than partnership. |

### Consequences

**Positive**:
- Maximizes community adoption potential (no license friction for any organization)
- Enables courtroom transparency for parsed evidence
- Attracts contributors who may become customers of the proprietary layer
- Consistent with existing crate licenses (no migration required)
- Google, Microsoft, and consulting firms can adopt and contribute without legal review escalation

**Trade-offs**:
- Cloud providers or competitors could fork and redistribute parsers without contributing back --- mitigated by the fact that parsers alone are not the product; integration is
- No license-based revenue from open-source components --- requires the proprietary layer to carry all monetization
- Community expectations for open governance (roadmap transparency, issue triage responsiveness) increase operational burden on a solo founder

---

## ADR-0004: Hexagonal Architecture (Crux-Inspired)

**Status**: Accepted
**Date**: 2026-03-20
**Phase**: 6 (Architecture Blueprint)

### Context

Issen must support multiple rendering surfaces: CLI (clap v4), TUI (ratatui), desktop GUI (Tauri v2), and web UI (axum + Leptos). The core analysis logic --- timeline schema, event types, plugin traits, correlation, and reporting --- must produce identical results regardless of which frontend drives it. Side effects (file I/O, database access, network calls) must be isolated to enable deterministic testing of the analysis engine. The Crux framework (cross-platform Rust apps) demonstrates this pattern effectively for multi-surface applications.

### Decision

Adopt a **hexagonal (ports-and-adapters) architecture** inspired by Crux. The `issen-core` crate is a side-effect-free pure analysis engine. All I/O, storage, and rendering are handled by port/adapter crates (`issen-pipeline`, `issen-timeline`, `issen-report`, `issen-cli`, `issen-tui`, `issen-gui`, `issen-web`). The core defines traits (ports); adapters implement them. Frontends are thin shells that translate user input into core commands and core output into rendered views.

### Alternatives Rejected

| Alternative | Reason for Rejection |
|-------------|----------------------|
| **MVC (Model-View-Controller)** | MVC couples the controller to a specific UI framework, making multi-surface rendering require duplicated controller logic. The forensic analysis logic would leak into framework-specific code. |
| **Microservices** | Massively over-architected for a solo founder. Introduces network latency, deployment complexity, and distributed system failure modes. Forensic workstations are often air-gapped, making service discovery and inter-service communication impractical. |
| **Monolith (single crate)** | Prevents independent compilation and testing of components. A change to the TUI would trigger recompilation of the entire analysis engine. Makes the open-source / proprietary boundary impossible to enforce at the crate level. |

### Consequences

**Positive**:
- Identical analysis results across CLI, TUI, GUI, and web --- critical for forensic reproducibility
- Pure `issen-core` enables deterministic property-based testing without I/O mocking
- Clean crate boundaries enforce the open-source / proprietary licensing split at compile time
- New frontends (mobile, embedded) can be added by implementing the port traits without modifying core logic

**Trade-offs**:
- Steeper initial learning curve for contributors unfamiliar with hexagonal architecture
- Trait-heavy design increases compile times (Rust monomorphization) and can produce opaque error messages
- Requires disciplined enforcement of the "no side effects in core" rule --- a single `std::fs::read` in `issen-core` breaks the entire architecture's guarantees

---

## ADR-0005: DuckDB Primary + SQLite Exchange

**Status**: Accepted
**Date**: 2026-03-20
**Phase**: 6 (Architecture Blueprint)

### Context

Forensic timeline analysis involves querying datasets of 100M+ events with temporal predicates, aggregations, and window functions. The storage engine must support `TIMESTAMP_NS` (nanosecond precision is required for filesystem timestamps), columnar scans for analytical queries, and zone maps for predicate pushdown. Simultaneously, forensic cases must be portable for legal hold, peer review, and courtroom presentation on systems without specialized software. The analytical workload and the portability requirement have fundamentally different optimization targets.

### Decision

Use **DuckDB as the primary analytical store** for the hot path (in-process, columnar, `TIMESTAMP_NS`, zone maps) and **SQLite as the cold exchange format** for portable case export and legal hold compliance. `issen-timeline` manages DuckDB during active analysis; case export produces a self-contained SQLite database that any tool (DB Browser, Python, Excel via ODBC) can open.

### Alternatives Rejected

| Alternative | Reason for Rejection |
|-------------|----------------------|
| **SQLite-only** | SQLite is row-oriented and lacks columnar scan optimizations. A `SELECT * FROM events WHERE timestamp BETWEEN x AND y` on 100M rows is orders of magnitude slower without zone maps and vectorized execution. SQLite also lacks native `TIMESTAMP_NS`. |
| **PostgreSQL** | Requires a running server process, which violates the single-binary constraint. Cannot run on air-gapped forensic workstations without installation privileges. Adds operational complexity inappropriate for a desktop analysis tool. |
| **Arrow/Parquet files (no database)** | Excellent for batch analytics but lacks transaction support, concurrent query capabilities, and the SQL interface that examiners can use for ad-hoc investigation. Requires building a custom query layer. |

### Consequences

**Positive**:
- DuckDB's columnar engine with zone maps enables sub-second queries on 100M+ event timelines
- `TIMESTAMP_NS` preserves full forensic precision without epoch conversion hacks
- In-process embedding (no server) maintains the single-binary deployment constraint
- SQLite export produces universally readable case files (legal hold, peer review, courtroom)
- Clear separation: DuckDB for speed during analysis, SQLite for portability after analysis

**Trade-offs**:
- Two storage engines mean two sets of schema migrations, two query dialects (minor differences), and two code paths to maintain
- DuckDB is a younger project than SQLite with a smaller ecosystem --- breaking changes between versions are possible
- Case export (DuckDB to SQLite) adds a serialization step that must preserve all event data without precision loss

---

## ADR-0006: Three-Tier Plugin System

**Status**: Accepted
**Date**: 2026-03-20
**Phase**: 6 (Architecture Blueprint)

### Context

Issen needs an extensibility mechanism for forensic parsers. The DFIR community is diverse: individual contributors write parsers in Rust, Python, Go, and C. Enterprise customers need to integrate proprietary parsers that cannot be open-sourced. The plugin system must balance performance (parsers process millions of records), security (parsers handle untrusted evidence), and accessibility (contributors should not need deep Rust expertise for simple parsers).

### Decision

Implement a **three-tier plugin system** with progressive capability and isolation:

- **Tier 1 (v0.1+)**: Compile-time Rust traits. Maximum performance, zero overhead, type-safe. Requires Rust knowledge. Used for all core parsers.
- **Tier 2 (v0.3+)**: WASM sandboxed plugins. Near-native performance, zero ambient authority, language-agnostic (any language that compiles to WASM). Used for community parsers.
- **Tier 3 (v0.5+)**: gRPC remote plugins. Network-boundary isolation, any language, any deployment model. Used for enterprise proprietary parsers that cannot be compiled into the binary.

### Alternatives Rejected

| Alternative | Reason for Rejection |
|-------------|----------------------|
| **WASM-only from start** | WASM tooling for Rust is maturing but still has rough edges (component model stability, WASI preview versions). Starting with WASM adds complexity to v0.1 when all initial parsers are Rust crates anyway. Tier 1 traits are simpler, faster, and sufficient for MVP. |
| **Dynamic library / FFI** | `dlopen`/FFI is unsafe, platform-specific, and provides no sandboxing. A malicious or buggy parser could corrupt the host process memory. The forensic context (parsing untrusted evidence) makes this risk unacceptable. |
| **Single-tier (compile-time only)** | Limits the contributor pool to Rust developers and prevents enterprise integration of proprietary parsers. The forensic community uses Python, Go, and C extensively; excluding those languages limits adoption. |

### Consequences

**Positive**:
- Tier 1 delivers maximum performance for core parsers with zero plugin overhead
- Tier 2 (WASM) provides a safe sandbox for community parsers from any language
- Tier 3 (gRPC) enables enterprise integration without exposing proprietary code
- Progressive rollout reduces v0.1 complexity while providing a clear extensibility roadmap

**Trade-offs**:
- Three plugin tiers means three integration surfaces to document, test, and maintain
- Tier 2 and Tier 3 parsers will have measurably higher latency than Tier 1 (WASM: ~2x overhead, gRPC: network round-trip) --- this is acceptable because parsing is not the TARR bottleneck
- The trait interface defined in Tier 1 constrains what Tier 2 and Tier 3 can express --- the trait must be designed with all three tiers in mind from v0.1

---

## ADR-0007: Hybrid Public/Private Repository

**Status**: Accepted
**Date**: 2026-03-20
**Phase**: 1 (Brand Guidelines)

### Context

Issen has open-source parsers (Apache 2.0/MIT) and proprietary integration components. The repository strategy must enforce the licensing boundary at the code level, prevent accidental proprietary code leakage into public repositories, and allow community contributions to parsers without exposing the integration layer. CI/CD must build both public and private components, and the dependency direction must be strictly enforced.

### Decision

Maintain a **separate public monorepo** (Apache 2.0/MIT licensed, containing all open-source crates) and a **private repository** (proprietary, containing the integration layer, report engine, UI, and enterprise features). Strict rule: open-source crates NEVER depend on proprietary crates. The private repo depends on the public repo as a git dependency or published crates. CI validates the dependency direction on every commit.

### Alternatives Rejected

| Alternative | Reason for Rejection |
|-------------|----------------------|
| **Single AGPL repository** | See ADR-0003. AGPL licensing conflicts with the community adoption strategy. A single repo also makes it impossible to have different contribution agreements for different components. |
| **Single private repository** | Prevents community contributions entirely. Requires manual extraction and publication of open-source components, which is error-prone and delays releases. Contributors cannot fork, modify, and submit PRs. |
| **Business Source License (BSL) single repo** | BSL's time-delayed conversion creates ambiguity about which code is currently open and which is not. Contributors may be reluctant to contribute to code that is temporarily proprietary. |

### Consequences

**Positive**:
- Licensing boundary is enforced at the repository level --- no ambiguity about which code is open and which is proprietary
- Community contributors fork and PR against the public repo without ever seeing proprietary code
- CI can validate the dependency direction automatically (public crates must compile independently)
- Public repo serves as a portfolio and trust signal for the forensic community

**Trade-offs**:
- Two repositories require synchronized releases, coordinated CI, and careful dependency version management
- Features that span the boundary (e.g., a new parser that also needs a new correlation rule) require coordinated PRs across repos
- Solo founder must manage two sets of issues, PRs, and release notes

---

## ADR-0008: Local-First AI via Ollama

**Status**: Accepted
**Date**: 2026-03-20
**Phase**: 6 (Architecture Blueprint)

### Context

Issen's intelligence layer (`issen-intel`) uses LLMs for classification, entity extraction, narrative drafting, and cross-case correlation. Forensic evidence is legally sensitive: chain-of-custody requirements, client confidentiality, and air-gapped lab environments all constrain how and where AI processing can occur. The AI capability must add value without creating legal liability or evidence handling violations.

### Decision

Deploy AI via **local Ollama** as the default and only out-of-the-box option. Multi-model routing: 80% small models (7B-13B, Qwen2.5/Phi-3) for classification and extraction, 20% large models (70B+, Llama 3/Mixtral) for narrative drafting. **AI-free mode is mandatory**: a global toggle that disables all Ollama dependencies, producing reports using template-only generation. Cloud API fallback is available but opt-in only, requiring explicit examiner consent per case.

### Alternatives Rejected

| Alternative | Reason for Rejection |
|-------------|----------------------|
| **Cloud-only AI (OpenAI, Anthropic, etc.)** | Sending forensic evidence to cloud APIs violates chain-of-custody requirements in many jurisdictions. Air-gapped labs have no internet access. Client contracts frequently prohibit transmitting evidence to third parties. Latency and cost are unpredictable. |
| **Hybrid-default (local + cloud)** | Defaulting to cloud fallback creates a "soft dependency" that practitioners may not realize is transmitting evidence. The default must be the most secure option. Opt-in cloud is acceptable; opt-out cloud is not. |
| **No AI** | Ignores the market trend toward AI-assisted triage (Magnet.AI, BelkaGPT). AI-powered narrative drafting is the primary mechanism for reducing Findings-to-Narrative Time from hours to minutes. Omitting AI forfeits the largest TARR improvement opportunity. |

### Consequences

**Positive**:
- Evidence never leaves the examiner's machine by default --- full chain-of-custody compliance
- Works in air-gapped forensic labs without modification
- Multi-model routing optimizes hardware utilization (most tasks use small, fast models)
- AI-free mode ensures the tool is usable without any ML infrastructure
- Local deployment means zero per-case AI cost

**Trade-offs**:
- Requires examiners to have capable hardware (16GB+ RAM for 7B models, 32GB+ for 13B) --- mitigated by AI-free mode as fallback
- Local models have lower capability ceilings than frontier cloud models (GPT-4, Claude) --- mitigated by the constrained forensic domain where smaller fine-tuned models can match larger general models
- Ollama is a dependency that must be installed separately, partially violating the single-binary constraint --- mitigated by making it optional and providing an ONNX runtime fallback for embeddings

---

## ADR-0009: Dual Report Output (HTML + DOCX)

**Status**: Accepted
**Date**: 2026-03-20
**Phase**: 6 (Architecture Blueprint)

### Context

Attorney-ready output serves two distinct use cases in forensic engagements. During investigation, attorneys and examiners need interactive exploration: clickable timelines, filterable event tables, expandable evidence details, and hyperlinked cross-references. For court filings and formal records, they need polished, paginated documents with proper legal formatting: numbered headings, exhibit references, chain-of-custody tables, and signatures. No single format serves both needs.

### Decision

Generate **dual-format reports**: interactive HTML (self-contained, single-file, no external dependencies) for exploration and investigation, and couissen-ready DOCX (with PDF export) for formal filings. Technology: Askama templates for HTML generation, docx-rs with python-docx for DOCX generation, headless Chrome for PDF conversion from HTML. Both formats are generated from the same underlying report data model in `issen-report`.

### Alternatives Rejected

| Alternative | Reason for Rejection |
|-------------|----------------------|
| **HTML-only** | Attorneys filing court documents need Word/PDF. Courts have specific formatting requirements (numbered paragraphs, margins, fonts) that HTML cannot reliably satisfy across print environments. Many law firms have document management systems that require DOCX. |
| **DOCX/PDF-only** | Static documents cannot provide the interactive exploration (filtering, searching, drill-down) that makes triage efficient during investigation. Examiners would still need to maintain a separate interactive view alongside the report. |
| **LaTeX** | Produces excellent PDF output but has a steep learning curve, requires a TeX distribution (violates single-binary goal), and produces output that attorneys cannot edit. DOCX is the universal exchange format in legal workflows. |

### Consequences

**Positive**:
- Addresses both investigation-phase and couissen-filing-phase needs from a single analysis run
- Self-contained HTML (no external dependencies) works on any device, including courtroom presentation laptops with restricted software
- DOCX output integrates directly into law firm document management workflows
- Single underlying data model ensures both formats contain identical findings

**Trade-offs**:
- Two rendering pipelines (HTML + DOCX) must be maintained with feature parity --- a finding visible in HTML must appear in DOCX and vice versa
- DOCX generation via docx-rs/python-docx is complex (Word's OOXML format has extensive quirks, especially for multilevel numbering and table formatting)
- PDF conversion via headless Chrome adds an optional dependency for users who need PDF output from HTML

---

## ADR-0010: Grounded AI Generation Only

**Status**: Accepted
**Date**: 2026-03-20
**Phase**: 7 (Agent Prompts)

### Context

LLMs hallucinate. Published research documents hallucination rates of 17--34% in general-purpose generation tasks. In forensic reporting, a hallucinated timestamp, artifact attribution, or causal claim is not merely incorrect --- it can result in wrongful conviction, case dismissal, examiner decertification, and malpractice liability. The Daubert standard requires that expert testimony be based on sufficient facts and reliable methods. An AI-generated claim that cannot be traced to a specific evidence artifact fails Daubert scrutiny.

### Decision

**Every AI-generated finding must cite a specific, verifiable TimelineEvent.** No free-form AI generation is permitted. The architecture enforces this through: (1) a template+fill pattern where AI populates structured fields rather than generating prose from scratch, (2) mandatory citation of source event IDs for every claim, (3) dual-model verification where a second model validates citations against the timeline database, and (4) confidence scoring (0.0--1.0) with a threshold of 0.7 for inclusion in reports. Target hallucination rate: < 2% (vs. 17--34% baseline).

### Alternatives Rejected

| Alternative | Reason for Rejection |
|-------------|----------------------|
| **Unrestricted AI generation** | Hallucination rates of 17--34% are career-ending in forensic work. A single fabricated finding in a court report destroys the examiner's credibility and the tool's reputation permanently. The risk-reward ratio is catastrophically negative. |
| **AI suggestions with manual review** | Shifts the burden to the examiner without reducing it. Reviewing AI-generated prose for subtle hallucinations is arguably harder than writing the prose manually, because the examiner must verify each claim against evidence rather than constructing claims from evidence. |
| **No AI in reports** | Forfeits the largest TARR improvement opportunity. Template+fill with grounded generation preserves the speed benefit while constraining the hallucination surface. AI-free mode remains available for examiners who prefer zero AI involvement. |

### Consequences

**Positive**:
- Every AI-generated claim is traceable to a specific evidence artifact, satisfying Daubert requirements
- Dual-model verification catches citation errors before they reach the report
- Confidence scoring provides transparency --- examiners see how certain the AI is about each finding
- Template+fill constrains the generation surface area, making hallucination detection tractable
- Hallucination rate target (< 2%) is measurable and auditable

**Trade-offs**:
- Template+fill produces less "creative" narrative than free-form generation --- reports may feel formulaic (mitigated by template variety and examiner-editable sections)
- Dual-model verification doubles inference cost for narrative sections
- The citation requirement means AI cannot generate insights that span multiple evidence sources unless the correlation engine has already linked them as a composite event

---

## ADR-0011: No Retry on Corrupted Evidence

**Status**: Accepted
**Date**: 2026-03-20
**Phase**: 7d (Deep Templates --- Resilience)

### Context

Forensic evidence is immutable by definition. An examiner works from a forensic image (E01, VMDK, raw) that is hash-verified against the original media. If a parser encounters corruption --- a truncated MFT record, a malformed USN journal entry, an invalid registry hive header --- the data will not change on retry. The corruption is a property of the evidence, not a transient error. Retry logic designed for network services or distributed systems does not apply.

### Decision

**No retry on corrupted evidence.** When a parser encounters corruption, it immediately degrades through the fallback chain: attempt partial parsing, emit what was recovered, log the corruption with evidence hash, offset, and expected-vs-actual values in the audit trail, and continue with the next artifact. The audit entry preserves forensic completeness --- the examiner knows exactly what was skipped and why. Transient I/O errors (disk timeout, memory pressure) use standard exponential backoff (3 attempts, 100ms base) because these are system errors, not evidence errors.

### Alternatives Rejected

| Alternative | Reason for Rejection |
|-------------|----------------------|
| **Retry with exponential backoff (for all errors)** | Retrying a corrupted MFT record 3 times with backoff wastes 700ms+ and produces the identical failure each time. In a pipeline processing millions of records, even small per-record delays accumulate to minutes of wasted time. More importantly, retries on immutable data are logically meaningless. |
| **Fail-fast (abort entire pipeline)** | A single corrupted artifact should not prevent analysis of the remaining evidence. A corrupted NTFS MFT does not invalidate the Windows Event Logs, Registry hives, or Prefetch files. Failing fast discards recoverable evidence. |
| **Silent skip (no audit)** | Skipping corrupted data without logging violates forensic completeness requirements. An examiner must be able to account for every artifact in the evidence --- including those that could not be parsed. Silent skips create gaps that opposing counsel can exploit. |

### Consequences

**Positive**:
- Zero wasted time on provably futile retries
- Maximum evidence recovery --- every parseable artifact is processed regardless of corruption elsewhere
- Complete audit trail satisfies forensic disclosure requirements ("we attempted to parse X, encountered corruption at offset Y, recovered Z records")
- Clear distinction between evidence errors (no retry) and system errors (retry with backoff) simplifies error handling code

**Trade-offs**:
- Requires every parser to implement graceful degradation rather than simply returning `Err` --- increases per-parser implementation complexity
- The "no retry" policy must be clearly documented to prevent contributors from adding retry logic in PRs (violating the architecture)
- Partial parse results may confuse examiners if the degradation is not clearly surfaced in the report (mitigated by explicit degradation markers in the timeline)

---

## ADR-0012: Per-Pipeline-Layer Circuit Breakers

**Status**: Accepted
**Date**: 2026-03-20
**Phase**: 7d (Deep Templates --- Resilience)

### Context

Issen's pipeline has five layers: Layer 0 (Storage I/O), Layer 1 (Image Format), Layer 2 (Volume/Partition), Layer 3 (Filesystem), and Layer 4 (Artifact Parsing). Failures in one layer should not cascade to unrelated layers. A corrupted NTFS volume (Layer 3) should not prevent registry parsing from a second volume, and a failing Event Log parser (Layer 4) should not block Prefetch parsing. The circuit breaker pattern from distributed systems applies, but the granularity must match the pipeline's layer structure.

### Decision

Implement **per-pipeline-layer circuit breakers**. Each layer maintains independent failure tracking. After 3 consecutive failures within a layer, the circuit opens: that layer is skipped for the current evidence source, a degradation audit entry is recorded, and processing continues with the next layer or evidence source. Circuit state is per-evidence-source (a corrupted Volume 1 does not open the circuit for Volume 2). Breakers reset when a new evidence source begins processing.

### Alternatives Rejected

| Alternative | Reason for Rejection |
|-------------|----------------------|
| **Per-component circuit breakers** | Too granular. Forensic pipelines have hundreds of individual parsers; maintaining per-parser circuit state adds memory overhead and configuration complexity. Layer-level granularity matches the pipeline's natural fault domains (a corrupted filesystem affects all parsers on that filesystem). |
| **Global circuit breaker** | Too coarse. A global breaker that trips on filesystem corruption would halt the entire pipeline, including parsers that read from unrelated evidence sources. This discards recoverable evidence. |
| **No circuit breakers (fail or succeed per-item)** | Without breakers, a systematically corrupted evidence source (e.g., every record in a damaged MFT) generates thousands of individual error log entries and consumes processing time before the pipeline moves on. Breakers provide early termination for pathological inputs. |

### Consequences

**Positive**:
- Fault isolation: a corrupted NTFS volume does not block registry, event log, or prefetch parsing from the same image
- Early termination: 3 consecutive failures trigger skip rather than processing thousands of doomed records
- Degradation audit: the examiner knows exactly which layers were skipped and why
- Per-evidence-source scoping prevents one bad volume from affecting analysis of other volumes

**Trade-offs**:
- The threshold (3 consecutive failures) is a heuristic --- too low risks skipping recoverable layers after transient issues; too high wastes time on genuinely corrupted layers. The threshold should be configurable per deployment.
- Circuit breakers add state management to each pipeline layer, increasing code complexity
- Layer-level granularity may be too coarse in rare cases where only one parser within a layer is failing but others in the same layer would succeed (mitigated by `catch_unwind` per-parser isolation within each layer)

---

## ADR-0013: Rust Sealed Traits as Inter-Component Authentication

**Status**: Accepted
**Date**: 2026-03-20
**Phase**: 8 (Security Architecture)

### Context

Issen's crates communicate through trait interfaces. In a multi-crate Rust workspace, any crate can potentially call any public function in any other crate. The security model requires trust boundaries: untrusted code (evidence parsers, WASM plugins) should not be able to directly invoke privileged operations (audit log writes, license verification, hash verification). Runtime authentication (tokens, capability objects) adds overhead and complexity. Rust's type system and module visibility rules can enforce these boundaries at compile time with zero runtime cost.

### Decision

Use **compile-time crate visibility and sealed traits** as the inter-component authentication mechanism. Privileged traits are defined in internal modules (`pub(crate)` or `pub(in crate::path)`) that are only visible to authorized crates. The sealed trait pattern (a trait with a private supertrait that external crates cannot implement) prevents unauthorized implementations. Trust boundaries map to crate visibility:

- **TB0 (Untrusted)**: Evidence files, WASM plugins, Ollama models --- interact only through sanitized input traits
- **TB1 (Semi-Trusted)**: `issen-pipeline` --- can call parsing traits but not audit or reporting traits
- **TB2 (Trusted)**: `issen-core`, `issen-timeline`, `issen-correlation`, `issen-report`, `issen-intel` --- full access to internal traits
- **TB3 (Privileged)**: Audit logs, license keys, hash verification --- sealed traits with `pub(crate)` visibility

### Alternatives Rejected

| Alternative | Reason for Rejection |
|-------------|----------------------|
| **Runtime authentication tokens** | Adds latency to every cross-component call. Tokens can be leaked, replayed, or forged if the token generation logic has bugs. Adds a runtime failure mode (expired token, revoked token) that does not exist with compile-time enforcement. |
| **Capability objects (runtime)** | Similar to tokens but with object-oriented overhead. Capabilities must be passed through call chains, adding parameters to every function signature. Runtime capabilities can be cloned or forwarded, weakening the security boundary. |
| **No inter-component authentication** | Relies on developer discipline to respect trust boundaries. A single careless `pub` declaration exposes privileged operations to untrusted code. Compile-time enforcement makes violations impossible rather than merely discouraged. |

### Consequences

**Positive**:
- Zero runtime cost --- trust boundaries are enforced entirely by the Rust compiler
- Violations are compile errors, not runtime security incidents
- The type system documentation (trait visibility, sealed trait hierarchies) serves as the security architecture specification
- No authentication infrastructure to deploy, configure, rotate, or audit at runtime

**Trade-offs**:
- Sealed traits and visibility modifiers add complexity to the crate dependency graph --- refactoring crate boundaries requires careful visibility adjustment
- Compile-time enforcement does not extend to WASM plugins (Tier 2) or gRPC plugins (Tier 3), which require runtime sandboxing (WASM: zero ambient authority; gRPC: network-level isolation)
- New contributors must understand Rust's module visibility system to work effectively with the codebase --- this is a higher bar than runtime authentication patterns familiar from other languages

---

## ADR-0014: Practitioner-First, Enterprise-Later

**Status**: Accepted
**Date**: 2026-03-20
**Phase**: 2 (North Star Specification)

### Context

Issen's user research identified four personas: Sarah Chen (solo IR practitioner), Marcus Webb (forensic examiner at a consulting firm), Diana Reyes (litigation support analyst), and James Okafor (CISO/IR manager). Enterprise features (SSO/SAML, RBAC, team case assignment, audit dashboards, partner integrations) serve James Okafor and large organizations. Solo practitioner features (fast setup, minimal configuration, single-binary deployment, affordable pricing) serve Sarah Chen. These feature sets compete for development resources and frequently conflict in design decisions (e.g., SSO requires network connectivity; solo practitioners work air-gapped).

### Decision

**Design for Sarah Chen first.** Enterprise features (SSO, RBAC, team workflows, audit dashboards, partner integrations) are deferred to Phase 3 (v0.4+), after product-market fit is proven with solo practitioners and small teams. The filtering axiom: "If a feature helps James Okafor (CISO) but slows Sarah Chen (solo IR), defer it." Solo constraints (single binary, air-gapped, minimal config, affordable) produce better software because they force simplicity.

### Alternatives Rejected

| Alternative | Reason for Rejection |
|-------------|----------------------|
| **Enterprise-first development** | Enterprise sales cycles are 6--12 months with procurement, security review, and pilot phases. A solo founder cannot sustain a year without revenue while building enterprise features. Enterprise-first also produces bloated software (configuration screens, admin panels, integration wizards) that solo practitioners reject. |
| **Simultaneous practitioner + enterprise** | Splits development focus for a solo founder. Every feature decision becomes a negotiation between two conflicting user needs. The result is a product that serves neither audience well --- too complex for solo practitioners, too incomplete for enterprises. |
| **Enterprise-only (SaaS model)** | Ignores the forensic community's preference for local, owned tools. Forensic evidence handling requirements make SaaS deployment legally complex in many jurisdictions. Eliminates the open-source community adoption strategy. |

### Consequences

**Positive**:
- Solo-practitioner constraints (single binary, air-gapped, minimal config) force architectural simplicity that benefits all users
- Faster time-to-market: v0.1 ships without SSO, RBAC, or team infrastructure
- Community adoption builds reputation and validates product-market fit before enterprise sales
- Solo practitioners are more forgiving of rough edges and more willing to provide direct feedback than enterprise procurement committees

**Trade-offs**:
- Enterprise customers who discover Issen early may evaluate and reject it due to missing SSO/RBAC, creating a negative first impression that is difficult to overcome later
- Deferring enterprise features means deferring enterprise revenue --- the product must sustain itself on practitioner-tier pricing ($0--$500/year) through Phase 1 and Phase 2
- Some architectural decisions made for solo practitioners (e.g., OS-level auth, local-only storage) may require rework when enterprise features are added in Phase 3

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-03-20 | North Star Advisor | Initial ADR document covering Phases 1--8 decisions |
