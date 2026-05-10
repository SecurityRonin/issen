# Research Summary

## Generated
2026-03-20T03:15:00Z

## Project Context
- **Name:** Issen
- **Type:** Integrated forensic triage platform
- **Users:** IR practitioners, forensic examiners, litigation support teams
- **Preferred Stack:** Rust (usnjrnl-forensic v0.6, tl v0.1, ewf v0.1, shrinkpath v0.1)

---

## Technology Stack

### Recommended / Validated
| Layer | Recommendation | Rationale |
|-------|---------------|-----------|
| Binary Parsing | binrw (structs) + nom (streaming) | binrw is declarative and ergonomic for forensic records; nom handles complex conditional logic |
| Forensic Framework | forensic-rs traits or custom ForensicParser trait | Trait-based abstraction for plugin architecture |
| NTFS | ntfs crate (Colin Finck) | Stable, Apache 2.0/MIT, pure Rust |
| E01 Images | ewf (existing) — fills genuine ecosystem void | No other pure-Rust E01 reader exists |
| Plugin System | abi_stable/stabby (native, 7x faster) + Wasmtime/WIT (sandboxed community) | Dual-layer: compile-time for first-party, WASM for untrusted third-party |
| Timeline DB | DuckDB via duckdb-rs (columnar, 10-100x faster analytics) OR SQLite via rusqlite (proven at 4.2M events/sec) | DuckDB for analytical queries at billion-event scale; SQLite as proven fallback |
| HTML Reports | Askama (compile-time, built-in) + Tera (runtime, user-customizable) | Type-safe templates for production + hot-reload for customization |
| PDF Generation | Headless Chrome via HTML | Full CSS3 control, attorney-quality output |
| DOCX Generation | docx-rs + python-docx subprocess for expert witness reports | Complex Word features (multilevel numbering, TOC) need python-docx |
| Charts | Charming (interactive HTML, ECharts) + Plotters (static, embedded in PDF/DOCX) | Interactive for exploration, static for print |
| TUI | ratatui | Industry standard, aligns with existing tl codebase |
| Desktop GUI | Tauri v2 (deferred) | Reuses HTML report investment, small binary vs Electron |
| Web Backend | Axum + Tokio | Tokio team, SSE/WebSocket for real-time dashboards |
| Parallelism | rayon (CPU) + tokio (async I/O) + memmap2 (memory-mapped forensic images) | Proven pattern for large-scale forensic processing |

### Key Libraries
- `inventory` or `linkme`: Zero-cost static plugin registration
- `crossbeam`: Lock-free data structures for pipeline parallelism
- `cargo-deny`: License compliance for mixed Apache 2.0/MIT/proprietary
- `cargo-nextest`: Fast workspace test execution
- `xtask`: Build automation pattern for releases
- `kamadak-exif`: EXIF metadata extraction for image provenance
- `image-hasher`: Perceptual hashing (dHash/pHash) for image series detection
- `yara-x`: VirusTotal's pure Rust YARA engine for malware scanning

### Best Practices
- Use `resolver = "2"` in Cargo workspace to prevent feature unification
- Static linking (musl/cissen-static) for IR field deployment
- `#[cfg(target_os)]` for OS-specific artifact parsers
- Feature flags for tier gating (community/professional/enterprise)
- Memory-mapped I/O for forensic images, streaming iterators with `par_bridge()` for multi-GB evidence

---

## Features & UX

### Expected Features
Users of forensic triage platforms typically expect:
1. Multi-format forensic image ingestion (E01, raw, AFF4, VMDK, VHDX)
2. File system parsing (NTFS, FAT/exFAT, HFS+, APFS, ext4)
3. Keyword search, hash calculation/matching, NSRL hash set filtering
4. Timeline generation from filesystem metadata + artifact-specific timestamps
5. Deleted file recovery and data carving
6. Registry analysis, browser artifact extraction, event log parsing
7. Case management with chain of custody documentation
8. Bookmark/tag evidence items for report inclusion
9. Export in multiple formats (CSV, JSON, SQLite, HTML, PDF)
10. AI-assisted triage and artifact categorization (emerging table-stakes)

### UX Patterns
- **Timeline navigation**: Scoped timeframes + strategic pivot points + MACB/source-type faceted filtering + keyword tagging + color-coding by source type
- **Event density heatmap**: Zoomable visualization for anomaly detection (activity bursts indicate automated/malicious behavior)
- **Progressive/virtualized rendering**: Essential for million-event timelines
- **Dark mode**: Major industry gap — no forensic tool advertises WCAG compliance or dark mode; easy differentiation
- **Expert witness report structure**: Qualifications → Scope → Evidence list (with hashes) → Methodology (tools + versions) → Findings → Opinions → Glossary → Exhibits

### Accessibility Requirements
- Color-coding must not be sole information channel (combine with icons/text labels)
- Screen reader support for HTML report outputs (proper ARIA labels)
- Keyboard-navigable timeline and evidence views
- High-contrast mode for long analysis sessions

---

## Architecture

### Recommended Pattern
**Hybrid Monorepo + Private Repo with Hexagonal Architecture**

Public Cargo workspace monorepo (Apache 2.0/MIT) for parsers, core types, timeline engine, CLI, and plugin SDK. Separate private repo for proprietary crates (report engine, correlation, GUI, enterprise). Dependency flow is strictly one-directional: proprietary depends on open-source, never reverse.

### Three-Tier Plugin System
1. **Tier 1 (Compile-time)**: Trait-based with `inventory`/`linkme` for static registration — zero overhead, all first-party parsers
2. **Tier 2 (WASM)**: Wasmtime + WASIp2 Component Model for sandboxed community plugins (~3x native, +14MB binary). Defer to v0.3+
3. **Tier 3 (gRPC/IPC)**: HashiCorp go-plugin style subprocess model for cross-language and enterprise integrations. Defer to v0.5+

### Data Pipeline (Multi-Layer Accessor Abstraction)
```
Layer 4: Artifact Parser        (USN Journal, Event Log, Registry, etc.)
Layer 3: Filesystem Accessor    (NTFS, ext4, APFS, FAT32)
Layer 2: Volume/Partition       (GPT, MBR, LVM, APFS Container)
Layer 1: Image Format           (E01/EWF, raw/dd, VMDK, VHDX, AFF4)
Layer 0: Storage I/O            (local file, S3, network share, split files)
```

Key innovation: **VirtualFilesystem** that fuses multiple acquisition types into unified view (KAPE triage + full disk image + memory dump + cloud logs), so the same parsers work on both live and dead systems without modification. Inspired by Velociraptor's accessor/remapping model.

### Timeline Storage
- **Primary**: DuckDB (columnar, vectorized execution, zone maps auto-skip, larger-than-memory natively, billions of rows)
- **Schema**: TIMESTAMP_NS precision, partitioned by date, JSON extra_data for parser-specific fields
- **Incremental processing**: Source fingerprinting — add new evidence without reprocessing
- **Full-text search**: DuckDB FTS extension or external tantivy index

### Open-Core Boundary (Buyer-Based Open Core)
| Tier | Audience | License | Content |
|------|----------|---------|---------|
| Open Source | Individual practitioners | Apache 2.0 / MIT | Parsers, CLI, timeline engine, plugin SDK |
| Professional | Solo consultants / small teams | Proprietary | Report engine, correlation, desktop GUI |
| Enterprise | Organizations / firms | Proprietary (paid) | Web UI, RBAC, audit logs, case management |

### Scalability Progression
CLI (clap) → TUI (ratatui) → Desktop GUI (Tauri 2) → Web UI (axum + React/Leptos) → Enterprise multi-user. Single `issen-core` crate with ports/adapters pattern (Crux-inspired, side-effect-free core) ensures all frontends share identical analysis logic.

---

## Pitfalls to Avoid

### Common Mistakes
1. **Timestamp parsing is the #1 courtroom attack vector** → Store ALL timestamps as UTC nanoseconds with original timezone metadata. Build a format registry with unit tests for every known format (Unix, WebKit, Cocoa, FILETIME, FAT). Implement clock skew detection.
2. **Daubert challenges target tool validation** → Publish validation against NIST CFTT test datasets, document known error rates, keep extraction code open-source for peer review.
3. **Chain of custody failures make evidence inadmissible** → Auto-generate audit logs with cryptographic verification at every stage. A single mismatched hash is enough to exclude evidence.
4. **Feature creep is fatal in forensics** → Every new feature is a new Daubert attack surface. Stick to anti-goals: not a collection tool, not eDiscovery, not a SIEM.
5. **EnCase's decline validates "stay responsive" strategy** → After OpenText acquisition, quality and customer service declined. Magnet won on responsiveness. Solo founder's direct customer relationships are competitive advantage.

### Security Concerns
- **Forensic tools are attack targets**: bulk_extractor heap overflow via crafted RAR in disk images; Wireshark CVE-2025-5601. Rust's memory safety is defensive advantage — enforce no `unsafe` in parser code.
- **CSAM handling**: Adam Walsh Act prohibits duplication. Build detection workflows and data minimization from the start.
- **Privilege material**: Courts narrowing privilege protections for forensic reports. Build privilege review workflows early.
- **Plugin sandboxing**: WASM isolation for community plugins is non-negotiable. Untrusted code must never access filesystem or network beyond explicit grants.

### Performance Gotchas
- **E01 compression creates performance ceilings**: CPU overhead limits throughput to 100-255 MB/s. Implement block-level caching, consider AFF4 support.
- **100M+ MFT entries**: Streaming parsers with rayon parallelism, never buffer entire artifact sets in memory.
- **I/O bottlenecks with compressed containers**: Memory-mapped I/O + LRU block cache (ewf already implements this).

### Business Model Pitfalls
- **Subscription fatigue is real**: Investigators report 10x cost increases. Offer perpetual + subscription options.
- **Autopsy failed commercially**: Despite being free — incomplete filesystem support, poor performance, courtroom credibility gaps. Validates Issen's attorney-ready output focus.
- **plaso failed on usability**: Dependency hell, no good UI, noisy results. Validates Rust's zero-dependency deployment and UX focus.

---

## Intelligence Layer

### Recommended Retrieval Approach
Dual RAG system: (1) Case-specific RAG per investigation for natural language evidence queries, (2) Cross-case knowledge-base RAG for pattern matching and forensic methodology. Hybrid search (keyword + vector) is essential because forensic data combines identifiers (hashes, IPs) with natural language.

### Model Selection Guidance
| Task Type | Recommended Model | Deployment | Rationale |
|-----------|------------------|------------|-----------|
| Report narrative drafting | ForensicLLM (LLaMA-3.1-8B fine-tuned) or Llama 3.3 70B | Local (Ollama) | 86.6% source attribution; must run locally for evidence confidentiality |
| Artifact description | 7-8B model (Llama 3.2 8B) | Local | Boilerplate generation, 80% of tasks |
| Cross-artifact correlation | 70B+ model | Local (Mac M2 Ultra / 2x RTX 4090) | Complex reasoning requires larger models |
| Expert witness draft review | Claude/GPT-4 class | API (if allowed) or local 70B | Highest accuracy needed; human review mandatory |

### Key Considerations
- **Air-gapped operation is mandatory**: Most forensic data CANNOT go to cloud APIs. Ollama + local models is the primary deployment.
- **Hallucination is existential risk**: Stanford found RAG-focused legal AI hallucinates 17-34%. 1,093 documented court cases of AI hallucination reliance. Mitigation: grounded generation only (every sentence cites specific artifact), template+fill pattern, dual-model verification, confidence scoring, deterministic fallback.
- **Human-in-the-loop is non-negotiable**: Multi-tiered review workflow with approval gates, append-only audit trail.
- **AI-free mode required**: Some jurisdictions/clients prohibit AI assistance. The platform must work fully without AI features.
- **Model routing saves 60-70% cost**: Route 80% of tasks to small models, reserve large models for complex reasoning.

### Detection Stack
- Sigma rules (existing in tl) → extend with ATT&CK TTP tagging
- YARA via `yara-x` (VirusTotal's pure Rust engine) for malware detection
- Custom correlation rules engine
- ML anomaly detection (deep autoencoders: 94% F1 / 96.7% accuracy per Studiawan et al.)
- LLM-assisted analysis (highest tier, human-reviewed)

### Perceptual Hashing for Image Series
- dHash (fast pre-filter) + pHash (robust matching) via `image-hasher` crate
- EXIF via `kamadak-exif` for provenance chain reconstruction
- OCR via Tesseract bindings or `ocrs` (pure Rust ML-based) for screenshot text extraction

---

## Generation Guidance

These findings should inform:
- **Phase 1 (BRAND_GUIDELINES):** "By IR practitioners, for IR practitioners" — brand built on practitioner credibility, courtroom-ready output, Rust performance
- **Phase 2 (NORTHSTAR):** North Star metric = time from evidence receipt to attorney-ready report delivery. Success = 50%+ reduction in repoissen-to-delivery cycle
- **Phase 3 (COMPETITIVE_LANDSCAPE):** Magnet AXIOM ($$$, slow parsing), Autopsy (free but poor reports/UX), X-Ways (fast but dated/no reports), Cellebrite (mobile-focused), Belkasoft (emerging with BelkaGPT), Velociraptor (collection not analysis), Eric Zimmerman tools (free CLI, no integration), plaso (powerful but unusable)
- **Phase 6 (ARCHITECTURE_BLUEPRINT):** Hexagonal architecture with three-tier plugin system, DuckDB timeline store, multi-layer data pipeline with VirtualFilesystem fusion, Crux-inspired side-effect-free core. Intelligence layer: local-first AI with grounded generation, ForensicLLM for report drafting, dual RAG, model routing for cost optimization
- **Phase 7 (AGENT_PROMPTS):** Pipeline orchestrator, parser coordinator, timeline analyst, report generator, evidence integrity validator, intelligence enricher
- **Phase 8 (SECURITY_ARCHITECTURE):** Evidence integrity (read-only access, hash verification at load+report time), plugin sandboxing (WASM isolation), CSAM detection workflows, privilege material handling, chain of custody automation, supply chain security (cargo-deny, cargo-vet), air-gapped AI deployment
- **Phase 7d (INTELLIGENCE_LAYER):** Full intelligence research — ForensicLLM, Ollama deployment, dual RAG architecture, MITRE ATT&CK mapping, CTI integration (MISP + OpenCTI), YARA-X, perceptual hashing, anomaly detection, model routing, 4-phase implementation roadmap
