# Issen: Intelligence Layer Architecture

> **Version**: 1.0
> **Date**: 2026-03-20
> **Component**: `issen-intel`
> **Status**: Architecture Specification
> **Classification**: Proprietary

---

## Executive Summary

The intelligence layer (`issen-intel`) is Issen's AI-powered analytical brain -- and the source of its next-generation competitive differentiation. It provides AI-assisted forensic report drafting, automated threat detection, threat intelligence enrichment, image series analysis, and anomaly detection. Every AI feature is **optional** -- the platform operates fully without them via a global AI-free toggle.

The architecture follows three non-negotiable principles:

1. **Local-first**: All AI processing runs on-premise via Ollama. Cloud APIs are opt-in, explicit, and never default.
2. **Grounded generation only**: Every AI-generated sentence traces to specific forensic artifacts. No free-form generation. No hallucination-tolerant paths.
3. **Evidence integrity**: The intelligence layer is read-only against evidence stores. It produces analysis artifacts that are clearly marked as AI-generated and require human review before inclusion in reports.

---

## Table of Contents

1. [Intelligence Assessment](#1-intelligence-assessment)
2. [Retrieval Architecture](#2-retrieval-architecture)
3. [Model Routing & Fallback](#3-model-routing--fallback)
4. [Embedding Design](#4-embedding-design)
5. [Grounded Generation & Citation Validation](#5-grounded-generation--citation-validation)
6. [Detection Engine](#6-detection-engine)
7. [Threat Intelligence Integration](#7-threat-intelligence-integration)
8. [Image & Media Analysis](#8-image--media-analysis)
9. [Anomaly Detection & Correlation](#9-anomaly-detection--correlation)
10. [Evaluation Framework](#10-evaluation-framework)
11. [Data Pipeline](#11-data-pipeline)
12. [AI-Free Mode](#12-ai-free-mode)

---

## 1. Intelligence Assessment

### 1.1 Knowledge Requirements

What knowledge does `issen-intel` need beyond model training data?

| Function | Knowledge Domain | Data Source | Format | Volume | Update Cadence |
|----------|-----------------|-------------|--------|--------|----------------|
| Report drafting | Forensic methodology, legal terminology | Examiner templates, case law references | Unstructured text | ~50MB | On case open |
| ATT&CK mapping | MITRE ATT&CK techniques | ATT&CK STIX data, Atomic Red Team | Structured JSON/STIX | ~15MB | Quarterly |
| IOC enrichment | Threat intelligence feeds | MISP, OpenCTI, AlienVault OTX | STIX 2.1, CSV, JSON | ~500MB | Daily (online) / weekly (offline) |
| YARA detection | Malware signatures | YARA rule repositories, custom rules | YARA rules | ~20MB | Monthly + custom |
| Sigma detection | Event log attack patterns | SigmaHQ, custom rules | Sigma YAML | ~10MB | Monthly + custom |
| Similar case matching | Historical case patterns | Anonymized past case embeddings | Vectors (f32) | ~2GB (growing) | On case close |
| Forensic artifact docs | Windows internals, artifact locations | SANS posters, forensic references | Unstructured text | ~100MB | Quarterly |

### 1.2 Intelligence Gaps

| Gap | Impact | Mitigation |
|-----|--------|------------|
| No training data for ForensicLLM fine-tuning | Report drafting quality limited to base model capability | Phase 1: prompt engineering + RAG. Phase 2: fine-tune on examiner-approved reports |
| Limited forensic-specific embedding benchmarks | Uncertain retrieval quality for forensic terminology | Build custom eval dataset from NIST CFReDS + real case data |
| No standardized forensic report corpus | Cross-case RAG has cold-start problem | Seed with SANS case studies + examiner-contributed templates |
| Evolving ATT&CK framework | Technique mappings become stale | Automated quarterly sync with MITRE STIX repository |

### 1.3 Requirements Matrix

| Requirement | Priority | Phase | Dependency |
|-------------|----------|-------|------------|
| Grounded narrative drafting | P0 | Phase 2 | issen-timeline query API |
| YARA-X file scanning | P0 | Phase 2 | issen-pipeline extracted files |
| Sigma event matching | P0 | Phase 2 | issen-timeline DuckDB store |
| Case-specific RAG | P1 | Phase 2 | Embedding pipeline, lancedb |
| MITRE ATT&CK auto-mapping | P1 | Phase 2 | ATT&CK STIX data loader |
| IOC extraction + enrichment | P1 | Phase 2 | TI abstraction layer |
| Cross-case RAG | P2 | Phase 3 | Anonymization pipeline |
| Image series detection | P2 | Phase 3 | Perceptual hashing library |
| Anomaly detection | P2 | Phase 3 | Statistical model training |
| ForensicLLM fine-tuning | P3 | Phase 4 | Training data collection |

---

## 2. Retrieval Architecture

### 2.1 Dual RAG Pipeline Design

Issen implements a **modular dual RAG architecture** with three distinct knowledge stores, each with its own retrieval pipeline, merged at generation time with mandatory source attribution.

```
                    ┌────────────────────────────────────────────────┐
                    │            Context Assembly Layer              │
                    │  (merge + deduplicate + rerank + truncate)     │
                    └──────┬──────────────┬──────────────┬──────────┘
                           │              │              │
                    ┌──────▼──────┐┌──────▼──────┐┌──────▼──────┐
                    │  Case-      ││  Cross-Case ││  Reference  │
                    │  Specific   ││  Persistent ││  Static     │
                    │  Ephemeral  ││  Store      ││  Store      │
                    │  RAG        ││             ││             │
                    └──────┬──────┘└──────┬──────┘└──────┬──────┘
                           │              │              │
                    ┌──────▼──────┐┌──────▼──────┐┌──────▼──────┐
                    │  lancedb    ││  lancedb    ││  lancedb    │
                    │  per-case   ││  global     ││  global     │
                    │  ephemeral  ││  persistent ││  immutable  │
                    └─────────────┘└─────────────┘└─────────────┘
```

#### Store 1: Case-Specific Ephemeral RAG

- **Purpose**: Index all parsed artifacts, timeline events, examiner annotations, and bookmarked findings for the current investigation
- **Lifecycle**: Created on case open, destroyed on case archive (or exported with case package)
- **Indexing trigger**: Real-time -- every parsed artifact and examiner annotation is embedded on creation
- **Query examples**: "What network connections occurred within 5 minutes of the malware execution?", "Show all USB device insertions for user jsmith"
- **Chunking strategy**: One chunk per `TimelineEvent` record. Each chunk includes: timestamp, event type, source artifact path, parsed fields, examiner annotations if present
- **Chunk size**: Variable (50-500 tokens per event). No splitting -- forensic events are atomic units
- **Metadata attached**: `{ timestamp_ns, event_type, source_parser, artifact_path, case_id, bookmarked }`

#### Store 2: Cross-Case Persistent RAG

- **Purpose**: Historical case patterns, known attack sequences, organizational TTP library, anonymized report narratives
- **Lifecycle**: Persistent across cases. Grows over time as cases close
- **Indexing trigger**: On case close -- examiner-approved findings are anonymized and indexed
- **Query examples**: "Have we seen this persistence mechanism in previous cases?", "What report language did we use for similar ransomware incidents?"
- **Chunking strategy**: By semantic section -- report paragraphs, technique descriptions, case summaries
- **Chunk size**: 256-512 tokens with 64-token overlap
- **Anonymization**: All PII, case numbers, client names, and specific dates are stripped before indexing. Only forensic patterns and methodology are preserved

#### Store 3: Reference Static RAG

- **Purpose**: MITRE ATT&CK technique descriptions, forensic artifact documentation, Windows internals references, SANS forensic guides
- **Lifecycle**: Immutable between quarterly updates. Version-controlled
- **Indexing trigger**: On quarterly update cycle (or manual refresh)
- **Query examples**: "What artifacts indicate T1547.001 Registry Run Keys?", "How does NTFS USN Journal record file deletions?"
- **Chunking strategy**: By logical section -- one chunk per ATT&CK technique, one per artifact type description, one per methodology step
- **Chunk size**: 256-512 tokens

### 2.2 Chunking Strategy

| Store | Unit | Size | Overlap | Rationale |
|-------|------|------|---------|-----------|
| Case-specific | TimelineEvent | 50-500 tokens (variable) | None | Forensic events are atomic; splitting destroys context |
| Cross-case | Semantic section | 256-512 tokens | 64 tokens | Report narratives benefit from overlap for continuity |
| Reference | Logical section | 256-512 tokens | 32 tokens | Reference docs have clear section boundaries |

**Special handling:**

- **Structured data** (registry entries, network connections): Serialized to natural language before embedding. `"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\malware.exe"` becomes `"Registry Run key persistence at HKLM Software Microsoft Windows CurrentVersion Run pointing to malware.exe"`
- **Timeline events**: Embedded with temporal context. Each event includes its +-2 neighbors' summaries as context for temporal reasoning
- **Long artifacts** (memory dumps, large logs): Summarized to key findings before embedding. Raw data stays in DuckDB; only analytical summaries enter the vector store

### 2.3 Hybrid Search

Each RAG store supports hybrid search combining vector similarity with structured filters:

```
┌──────────────────────────────────────────────────┐
│                  Hybrid Search                    │
│                                                   │
│  1. Vector similarity (cosine, top-50 candidates) │
│  2. Metadata filter (time range, event type,      │
│     source parser, bookmarked status)             │
│  3. BM25 keyword boost (exact artifact names,     │
│     registry paths, IP addresses)                 │
│  4. Reciprocal Rank Fusion (merge vector + BM25)  │
│  5. Rerank top-20 → return top-5                  │
└──────────────────────────────────────────────────┘
```

**Why hybrid**: Pure vector search misses exact matches on forensic identifiers (IP addresses, file hashes, registry paths). BM25 catches these. Reciprocal Rank Fusion combines both without manual weight tuning.

### 2.4 Knowledge Store Design

| Property | Case-Specific | Cross-Case | Reference |
|----------|--------------|------------|-----------|
| Engine | lancedb (embedded) | lancedb (embedded) | lancedb (embedded) |
| Location | `{case_dir}/.rt/vectors/` | `~/.issen/knowledge/` | `~/.issen/reference/` |
| Dimensions | 768 (nomic-embed-text) | 768 (nomic-embed-text) | 768 (nomic-embed-text) |
| Distance metric | Cosine | Cosine | Cosine |
| Expected records | 10K-500K per case | 50K-2M (growing) | ~20K (stable) |
| Index type | IVF-PQ (>100K) / Flat (<100K) | IVF-PQ | Flat (small enough) |
| Backup | Included in case export | Separate backup schedule | Reproducible from source |

---

## 3. Model Routing & Fallback

### 3.1 Multi-Model Routing Architecture

Issen uses a **local-first multi-model routing** strategy: 80% of AI tasks use small, fast models (7B-13B parameters); 20% of complex tasks route to larger models (70B) or cloud APIs (only with explicit user consent).

```
┌──────────────────────────────────────────────────────────────────┐
│                      Model Router                                │
│                                                                  │
│  Input: (task_type, complexity_score, latency_budget, user_prefs)│
│                                                                  │
│  ┌─────────┐   ┌──────────┐   ┌──────────┐   ┌──────────────┐  │
│  │ Tier 1  │   │ Tier 2   │   │ Tier 3   │   │ Tier 4       │  │
│  │ Small   │   │ Medium   │   │ Large    │   │ Cloud (opt)  │  │
│  │ 7B-8B   │   │ 13B-34B  │   │ 70B-Q4   │   │ GPT-4/Claude │  │
│  │ <1s     │   │ 2-5s     │   │ 10-30s   │   │ 3-10s        │  │
│  └─────────┘   └──────────┘   └──────────┘   └──────────────┘  │
│                                                                  │
│  Routing rules:                                                  │
│  - classify/extract → Tier 1                                     │
│  - draft narrative  → Tier 2 (default) / Tier 3 (complex)       │
│  - complex analysis → Tier 3 (local) / Tier 4 (if consented)    │
│  - embedding only   → nomic-embed-text (no generative model)    │
└──────────────────────────────────────────────────────────────────┘
```

### 3.2 Task-to-Model Mapping

| Task | Model Tier | Primary Model | VRAM Required | Typical Latency |
|------|-----------|---------------|---------------|-----------------|
| Timeline event classification | Tier 1 (7B) | Llama 3.1 8B-Q8 | 8GB | <500ms |
| IOC extraction from text | Tier 1 (7B) | Fine-tuned Phi-3 | 4GB | <300ms |
| Entity recognition | Tier 1 (7B) | Llama 3.1 8B-Q8 | 8GB | <500ms |
| ATT&CK technique mapping | Tier 1 (7B) | Llama 3.1 8B-Q8 + RAG | 8GB | <1s |
| Report section drafting | Tier 2 (13B-34B) | Llama 3.1 70B-Q4 | 32GB | 5-15s |
| Complex narrative generation | Tier 2/3 | ForensicLLM (future) | 16-32GB | 5-30s |
| Cross-artifact correlation | Tier 3 (70B) | Llama 3.1 70B-Q4 | 40GB | 15-30s |
| Similar case analysis | Embedding | nomic-embed-text | 2GB | <200ms |
| Report quality review | Tier 2 (13B) | Llama 3.1 70B-Q4 | 32GB | 10-20s |

### 3.3 Fallback Chains

| Task Category | Primary | Fallback 1 | Fallback 2 | Trigger |
|---------------|---------|------------|------------|---------|
| Classification | Llama 3.1 8B | Phi-3 Mini | Rule-based classifier | Timeout >2s / Ollama unavailable |
| Narrative draft | Llama 3.1 70B-Q4 | Llama 3.1 8B (shorter output) | Template-only (no AI) | Timeout >60s / OOM |
| IOC extraction | Fine-tuned Phi-3 | Regex-based extraction | Manual extraction | Model load failure |
| ATT&CK mapping | LLM + RAG | Rule-based lookup table | Manual mapping | RAG store unavailable |
| Embedding | nomic-embed-text (Ollama) | nomic-embed-text (ONNX fallback) | Disable vector search | Ollama unavailable |

**Fallback behavior**: Each fallback reduces capability gracefully. The examiner is notified of degraded mode via a status indicator in the UI. All fallbacks eventually reach a non-AI path -- the platform never blocks on AI availability.

### 3.4 ForensicLLM Roadmap (Phase 4)

**ForensicLLM** is a fine-tuned LLaMA derivative optimized for forensic report generation. It is a Phase 4 initiative -- not required for initial launch.

| Property | Specification |
|----------|--------------|
| Base model | Llama 3.1 8B or 70B (TBD based on hardware survey) |
| Fine-tuning method | QLoRA (4-bit quantized LoRA) |
| Training data | Examiner-approved report sections, forensic methodology docs, NIST guidelines |
| Training data size | Target: 5,000+ report sections across 500+ cases |
| Expected improvement | Forensic terminology accuracy, legal-safe language patterns, citation format consistency |
| Deployment | LoRA adapter loaded via Ollama custom Modelfile |
| Validation | Blind comparison against base model by 3+ certified examiners |
| Risk mitigation | LoRA adapter only -- base model unchanged. Easy rollback by removing adapter |

**Training data collection strategy:**

1. **Phase 2-3**: Collect examiner edits to AI-drafted reports (diff between AI draft and approved version)
2. **Phase 3**: Build golden dataset of examiner-approved report sections with citation quality annotations
3. **Phase 4**: Fine-tune with DPO (Direct Preference Optimization) using examiner preference pairs

---

## 4. Embedding Design

### 4.1 Embedding Model Selection

| Property | Selection |
|----------|----------|
| Model | `nomic-embed-text` v1.5 |
| Dimensions | 768 |
| Max tokens | 8192 |
| Deployment | Ollama (local) |
| ONNX fallback | Yes (for Ollama-unavailable environments) |
| Matryoshka support | Yes (can truncate to 256/512 dims for speed) |

**Why nomic-embed-text:**

- **Local-first**: Runs via Ollama, no cloud dependency
- **Long context**: 8192 tokens handles multi-event forensic chunks without truncation
- **Matryoshka dimensions**: Can use 256-dim for fast approximate search, 768-dim for precision
- **Performance**: Competitive with OpenAI ada-002 on MTEB benchmarks at a fraction of the cost
- **License**: Apache 2.0 -- no commercial restrictions

### 4.2 Embedding Pipeline

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌─────────────┐
│ Source Data  │────►│ Preprocessor │────►│ Embedder     │────►│ Vector Store│
│             │     │              │     │              │     │ (lancedb)   │
└─────────────┘     └──────────────┘     └──────────────┘     └─────────────┘

Preprocessor steps:
1. Format normalization (structured → natural language)
2. Context enrichment (add temporal neighbors for timeline events)
3. Metadata extraction (timestamp, source, type, path)
4. Token count estimation → skip if >8192 (summarize first)

Embedder configuration:
- Batch size: 64 (tuned for 16GB VRAM)
- Concurrency: 1 model instance, async queue
- Prefix: "search_document: " for indexing, "search_query: " for queries
- Quantization: f32 storage, matryoshka truncation for search if latency-constrained
```

### 4.3 Embedding Refresh Strategy

| Store | Trigger | Strategy |
|-------|---------|----------|
| Case-specific | New artifact parsed / annotation added | Incremental -- embed only new/modified records |
| Cross-case | Case closed and approved | Batch -- embed all new case findings in background |
| Reference | Quarterly update | Full rebuild -- small enough to rebuild from scratch (~20K records, ~30 min) |

**Staleness detection**: Each embedding record stores the source content hash. On query, if the source has been modified since embedding, the record is flagged as stale and re-embedded before inclusion in results.

---

## 5. Grounded Generation & Citation Validation

> **This is the single most critical section of the intelligence layer.**
> A hallucinated fact in an expert witness report can lead to Daubert challenges, examiner sanctions, career termination, and compromised case outcomes. Stanford research shows general-purpose LLMs hallucinate 58-88% of the time on legal queries. Even RAG-focused legal AI tools produce incorrect information 17-34% of the time.

### 5.1 Grounded Generation Architecture

Every AI-generated sentence in Issen traces to specific forensic artifacts. There is no free-form generation path.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    Grounded Generation Pipeline                          │
│                                                                          │
│  1. Template Selection                                                   │
│     ├─ Report section template (methodology, findings, timeline, etc.)  │
│     └─ Required citation density: minimum 1 citation per factual claim  │
│                                                                          │
│  2. Evidence Retrieval                                                   │
│     ├─ Query case-specific RAG for relevant artifacts                   │
│     ├─ Query reference RAG for forensic methodology context             │
│     └─ Assemble context window with source metadata preserved           │
│                                                                          │
│  3. Constrained Generation                                               │
│     ├─ System prompt enforces: "Only state facts supported by the       │
│     │   provided evidence. Every factual claim must include [SOURCE:    │
│     │   artifact_path, timestamp] inline citation."                     │
│     ├─ Template + fill pattern (not free-form prose)                    │
│     └─ Output format: structured JSON with text + citations array       │
│                                                                          │
│  4. Citation Validation (CRITICAL)                                       │
│     ├─ Parse all [SOURCE:...] citations from generated text             │
│     ├─ Verify each citation resolves to a real artifact in the case     │
│     ├─ Verify cited timestamps exist in the timeline (+-1s tolerance)   │
│     ├─ Verify cited content matches the source (semantic similarity     │
│     │   >0.85 between claim and source)                                 │
│     └─ Flag or reject sentences with unresolvable citations             │
│                                                                          │
│  5. Dual-Model Verification                                              │
│     ├─ Second model (different from generator) reviews each claim       │
│     │   against raw evidence                                            │
│     ├─ Specifically checks: causal claims, temporal ordering,           │
│     │   attribution statements, quantitative claims                     │
│     └─ Verdicts: VERIFIED / UNVERIFIABLE / CONTRADICTED                 │
│                                                                          │
│  6. Confidence Scoring                                                   │
│     ├─ Each paragraph receives: citation_density, verification_ratio,   │
│     │   semantic_similarity_avg                                         │
│     ├─ Composite confidence score: 0.0 - 1.0                           │
│     └─ Score < 0.7 → mandatory human review flag                       │
│                                                                          │
│  7. Human Review Gate                                                    │
│     ├─ ALL AI-generated content marked with visual indicator            │
│     ├─ Low-confidence sections highlighted in amber                     │
│     ├─ Contradicted claims highlighted in red with explanation          │
│     └─ Examiner must explicitly approve each section before inclusion   │
└──────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Prohibited Generation Patterns

The following are **never** generated by AI -- they are always examiner-authored:

| Category | Examples | Rationale |
|----------|----------|-----------|
| Legal conclusions | "The suspect committed...", "This constitutes a violation of..." | Legal conclusions are attorney work product |
| Causal attribution | "User X performed action Y" | Must be "The account associated with X was used to perform Y" -- AI cannot determine who was at the keyboard |
| Opinion statements | "This is likely malicious", "The examiner believes..." | Expert opinion must come from the certified examiner |
| Temporal causation | "X caused Y" | Temporal correlation is not causation; AI cannot make this determination |
| Completeness claims | "All evidence was examined", "No other artifacts exist" | AI cannot verify completeness of evidence |
| Chain of custody | Any custody-related statements | Must be documented by the examining human |

### 5.3 Citation Format

Every AI-generated factual claim uses inline citations:

```
The file "invoice_q3.pdf.exe" was created at 2024-11-15T14:23:07Z in the user's
Downloads directory [SOURCE: USN Journal, C:\Users\jsmith\Downloads\invoice_q3.pdf.exe,
MFT Entry #48823, Create timestamp]. The file was subsequently executed at
2024-11-15T14:23:41Z as evidenced by the Prefetch artifact [SOURCE: Prefetch,
INVOICE_Q3.PDF.EXE-A1B2C3D4.pf, Last Run Time #1].
```

**Citation validation rules:**

1. Every `[SOURCE: ...]` must resolve to a real artifact in the case evidence
2. Timestamps in citations must match the timeline store (+-1 second tolerance for clock skew)
3. File paths must exist in the virtual filesystem
4. At least one citation per factual sentence
5. Sentences with zero citations are flagged as "unsupported" and excluded from final output

### 5.4 Human-in-the-Loop Workflow

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│ AI Draft │────►│ Citation │────►│ Dual-    │────►│ Examiner │
│ Generated│     │ Validated│     │ Model    │     │ Review   │
│          │     │          │     │ Verified │     │ Queue    │
└──────────┘     └──────────┘     └──────────┘     └──────────┘
                                                         │
                                                    ┌────▼────┐
                                              ┌─────┤ Decision├─────┐
                                              │     └─────────┘     │
                                         ┌────▼────┐          ┌────▼────┐
                                         │ Approve │          │ Reject/ │
                                         │ (as-is  │          │ Edit    │
                                         │  or with│          │         │
                                         │  edits) │          │         │
                                         └────┬────┘          └────┬────┘
                                              │                    │
                                         ┌────▼────────────────────▼────┐
                                         │  Training Data Collection    │
                                         │  (approved vs. edited diffs  │
                                         │   feed ForensicLLM Phase 4)  │
                                         └─────────────────────────────┘
```

**Approval levels:**

- **Auto-approvable** (confidence >= 0.9, all citations verified, no prohibited patterns): Presented as "ready for review" with green indicator
- **Review required** (confidence 0.7-0.9, minor issues): Presented with amber indicator, specific concerns highlighted
- **Manual only** (confidence < 0.7, failed citations, prohibited patterns detected): Rejected from auto-draft, examiner must write manually

---

## 6. Detection Engine

### 6.1 YARA-X Integration

**YARA-X** is the Rust-native rewrite of YARA, used for file-based signature detection against extracted evidence files.

| Property | Configuration |
|----------|--------------|
| Engine | YARA-X (Rust native, compiled rules) |
| Rule sources | Built-in rules (common malware families, webshells, stealer logs), community rules (YARA-Forge, Malpedia), custom examiner rules |
| Scan targets | All files extracted by `issen-pipeline` Layer 1-3 handlers |
| Execution | Parallel scan via rayon thread pool, one rule set compiled once per case |
| Output | Detection hits written as `DetectionResult` events tagged on matching `TimelineEvent` records |
| Performance target | Scan 100K files in <60 seconds on 8-core machine |

**Rule management:**

```
~/.issen/rules/yara/
├── builtin/          # Ships with Issen, versioned
│   ├── malware/      # Known malware families
│   ├── webshells/    # PHP/ASP/JSP webshells
│   ├── stealers/     # Infostealer artifacts
│   └── tools/        # Attacker tooling (Mimikatz, Cobalt Strike, etc.)
├── community/        # Auto-updated from YARA-Forge
└── custom/           # Examiner-authored rules
```

**Detection metadata attached to timeline events:**

```json
{
  "detection_type": "yara",
  "rule_name": "CobaltStrike_Beacon_x64",
  "rule_source": "builtin/malware/cobaltstrike.yar",
  "confidence": "high",
  "matched_strings": ["$beacon_config", "$sleep_mask"],
  "file_path": "/evidence/Users/admin/AppData/Local/Temp/update.exe",
  "file_hash_sha256": "a1b2c3..."
}
```

### 6.2 Sigma Rule Engine

**Sigma rules** match against parsed timeline events in DuckDB, providing behavioral detection on event log patterns.

| Property | Configuration |
|----------|--------------|
| Engine | Custom Sigma-to-DuckDB SQL transpiler (ported from tl v0.1) |
| Rule sources | SigmaHQ repository (2000+ rules), custom examiner rules |
| Target | `TimelineEvent` records in `issen-timeline` DuckDB store |
| Execution | Batch SQL execution against DuckDB -- inherits DuckDB's columnar scan performance |
| Output | Detection hits tagged on matching events (`sigma-hit` tag) with rule metadata |

**Sigma-to-SQL transpilation:**

```
# Sigma rule (YAML)              # DuckDB SQL (generated)
detection:                   →   SELECT * FROM timeline_events
  selection:                 →   WHERE source = 'Security.evtx'
    EventID: 4688            →     AND json_extract(metadata, '$.EventID') = 4688
    CommandLine|contains:    →     AND json_extract(metadata, '$.CommandLine')
      - 'whoami'             →         LIKE '%whoami%'
      - 'net user'           →      OR LIKE '%net user%'
  condition: selection       →   ;
```

**Combined detection output**: Both YARA and Sigma hits are unified under the `DetectionResult` type, enabling cross-engine correlation (e.g., "YARA detected Cobalt Strike binary AND Sigma detected matching beacon activity in event logs").

### 6.3 Detection Correlation

```
┌──────────────────────────────────────────────┐
│         Detection Correlation Engine          │
│                                               │
│  YARA hit: CobaltStrike_Beacon in update.exe │
│            ↕ correlates with                  │
│  Sigma hit: Suspicious Named Pipe Creation    │
│            ↕ correlates with                  │
│  Sigma hit: Network Connection to C2 IP       │
│            ↕ enriches with                    │
│  ATT&CK:   T1071.001 (Web Protocols)         │
│            ↕ enriches with                    │
│  TI Feed:  C2 IP in MISP threat feed         │
│                                               │
│  Output: Correlated Attack Chain with         │
│          confidence score and ATT&CK mapping  │
└──────────────────────────────────────────────┘
```

---

## 7. Threat Intelligence Integration

### 7.1 TI Abstraction Layer

Issen implements a pluggable threat intelligence abstraction layer supporting both online (API) and offline (exported feed file) modes for air-gapped forensic labs.

```rust
/// Trait for threat intelligence backends
pub trait ThreatIntelProvider: Send + Sync {
    /// Enrich a single IOC with threat context
    async fn enrich_ioc(&self, ioc: &Ioc) -> Result<TiEnrichment>;
    /// Batch enrich multiple IOCs
    async fn enrich_batch(&self, iocs: &[Ioc]) -> Result<Vec<TiEnrichment>>;
    /// Check if provider is available (online check)
    async fn is_available(&self) -> bool;
    /// Provider name for attribution
    fn name(&self) -> &str;
}
```

### 7.2 Supported Backends

| Backend | Protocol | Mode | Data Format | Priority |
|---------|----------|------|-------------|----------|
| MISP | REST API | Online + Offline (export files) | STIX 1.x/2.0, JSON, CSV | P1 |
| OpenCTI | GraphQL API | Online | STIX 2.1 | P2 |
| AlienVault OTX | REST API | Online | OTX Pulse JSON | P1 (free) |
| VirusTotal | REST API | Online | VT JSON | P2 (paid) |
| AbuseCH | CSV feeds | Offline (daily download) | CSV | P1 (free) |
| Custom feeds | File-based | Offline | CSV, STIX, JSON | P1 |

### 7.3 IOC Extraction Pipeline

IOCs are automatically extracted during artifact parsing by `issen-pipeline` and enriched by `issen-intel`:

```
┌─────────────────┐     ┌──────────────┐     ┌──────────────┐     ┌───────────┐
│ Parsed Artifact │────►│ IOC Extractor│────►│ Local Cache  │────►│ Enriched  │
│ (TimelineEvent) │     │ (regex +     │     │ Check        │     │ IOC       │
│                 │     │  NER model)  │     │              │     │           │
└─────────────────┘     └──────────────┘     └──────┬───────┘     └───────────┘
                                                     │ miss
                                              ┌──────▼───────┐
                                              │ TI Provider  │
                                              │ Query        │
                                              │ (parallel    │
                                              │  all enabled │
                                              │  backends)   │
                                              └──────────────┘
```

**IOC types extracted:**

| IOC Type | Extraction Method | Sources |
|----------|------------------|---------|
| File hashes (MD5/SHA1/SHA256) | Computed on extraction | Filesystem artifacts |
| IP addresses | Regex + validation | Browser history, DNS cache, network connections, event logs |
| Domains | Regex + TLD validation | Browser history, DNS cache, email headers |
| Email addresses | Regex | Email artifacts, browser autofill |
| Registry keys | Pattern matching | Registry hive parsing |
| File paths (suspicious) | Pattern matching against known malware paths | Filesystem, Prefetch, USN Journal |
| Mutex names | Memory analysis | Memory dump parsing |
| Certificate thumbprints | X.509 parsing | Signed executable analysis |

### 7.4 MITRE ATT&CK Mapping

#### Artifact-Level Mapping (Automated, Rule-Based)

Deterministic mapping from forensic artifacts to ATT&CK techniques:

| Artifact Pattern | ATT&CK Technique | Confidence |
|-----------------|-------------------|------------|
| Registry Run/RunOnce keys with suspicious values | T1547.001 (Registry Run Keys) | High |
| Scheduled tasks with encoded PowerShell | T1053.005 (Scheduled Task) | High |
| LSASS memory access (Sysmon EID 10) | T1003.001 (LSASS Memory) | High |
| WMI event subscriptions | T1546.003 (WMI Event Subscription) | High |
| Prefetch for known attacker tools | Mapped per tool (e.g., mimikatz → T1003) | Medium |
| Suspicious service installations | T1543.003 (Windows Service) | Medium |
| PowerShell script block logging with encoded commands | T1059.001 (PowerShell) | High |

#### Behavioral-Level Mapping (AI-Assisted)

For complex multi-artifact attack chains:

1. **Cluster** related detection hits and correlated events into candidate attack sequences
2. **Map** each cluster to ATT&CK tactics progression (Initial Access -> Execution -> Persistence -> Privilege Escalation -> ...)
3. **Identify gaps** in the chain that suggest missed artifacts (e.g., "We see Persistence and Lateral Movement but no Initial Access -- look for phishing artifacts or exploit evidence")
4. **Visualize** on ATT&CK Navigator layer with confidence-weighted coloring

### 7.5 Infostealer Log Integration

Infostealer log parsing and correlation is a high-value feature for modern incident response:

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│ Stealer Log     │────►│ Parser           │────►│ Correlation      │
│ (Redline/Vidar/ │     │ (extract creds,  │     │ (match against   │
│  Raccoon/etc.)  │     │  cookies, system │     │  case artifacts) │
│                 │     │  info, wallets)  │     │                  │
└─────────────────┘     └──────────────────┘     └──────────────────┘

Output:
- Compromised credentials → correlate with case user accounts
- Stolen cookies → correlate with browser artifacts
- System fingerprints → match against case machine profiles
- Cryptocurrency wallets → flag for financial investigation
```

---

## 8. Image & Media Analysis

### 8.1 Perceptual Hashing for Image Series Detection

A critical capability for mobile forensic cases: detecting that an original photo (HEIC), its edited copy (Snapseed JPEG), and its shared version (Instagram cache) are the same image.

#### Algorithm Pipeline

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────────┐
│ Image    │────►│ dHash    │────►│ Candidate│────►│ pHash        │
│ Decoded  │     │ (fast    │     │ Pairs    │     │ (robust      │
│          │     │  filter) │     │ (HD < 5) │     │  verification│
│          │     │ 128-bit  │     │          │     │  HD < 3)     │
└──────────┘     └──────────┘     └──────────┘     └──────┬───────┘
                                                          │
                                                   ┌──────▼───────┐
                                                   │ EXIF Chain   │
                                                   │ Reconstruction│
                                                   │ (provenance) │
                                                   └──────────────┘
```

| Stage | Algorithm | Hash Size | Threshold | Purpose |
|-------|-----------|-----------|-----------|---------|
| Pre-filter | dHash | 128-bit | Hamming distance < 5 | Fast elimination of obviously different images |
| Verification | pHash (DCT) | 128-bit | Hamming distance < 3 | Robust cross-format/resolution matching |
| Future | DINOHash | N/A | Configurable | Heavy crops, adversarial modifications |

**Rust implementation**: `image-hasher` crate for dHash, `phash` crate for pHash. Both compute Hamming distance for similarity scoring.

### 8.2 EXIF/Metadata Provenance Chain

For each image series detected via perceptual hashing, reconstruct the provenance chain:

```
[IMG_1234.HEIC]                    [IMG_1234_snapseed.jpg]         [cache/img_abc123.jpg]
├─ Camera: iPhone 15 Pro           ├─ Software: Snapseed 2.x      ├─ No EXIF (stripped)
├─ DateTime: 2024-11-15 09:23:41   ├─ DateTime: 2024-11-15 10:15  ├─ File created: 2024-11-15 10:32
├─ GPS: 40.7128, -74.0060          ├─ GPS: stripped                ├─ Directory: com.instagram/cache
├─ Dimensions: 4032x3024           ├─ Dimensions: 3024x3024       ├─ Dimensions: 1080x1080
└─ Size: 3.2MB                     └─ Size: 1.1MB                 └─ Size: 245KB

Reconstructed chain:
  Original (HEIC, full EXIF) → Edited (Snapseed, cropped, GPS stripped) → Shared (Instagram, resized, EXIF stripped)
```

### 8.3 OCR for Screenshots and Document Images

| Property | Configuration |
|----------|--------------|
| Primary engine | Tesseract 5.x via Rust bindings (`tesseract` crate v0.15) |
| Fallback engine | `ocrs` (pure Rust, ML-based, Latin only) |
| Preprocessing | Grayscale -> CLAHE contrast enhancement -> Gaussian blur -> Otsu thresholding -> upscale to 300 DPI |
| Output | Plain text + bounding boxes (hOCR) |
| Use cases | Chat screenshots, document images, application screenshots in mobile forensic cases |
| Indexing | OCR text is embedded and indexed in case-specific RAG store |

---

## 9. Anomaly Detection & Correlation

### 9.1 Statistical Anomaly Detection in Timelines

Detect unusual patterns in forensic timelines that warrant examiner attention:

| Method | Application | Implementation |
|--------|-------------|----------------|
| Event frequency analysis | Detect bursts of activity (e.g., 500 file deletions in 30 seconds) | Rolling window statistics on DuckDB aggregates |
| Time-of-day profiling | Identify activity outside normal hours for the user | Build per-user activity profile, flag outliers (>2 sigma) |
| Inter-event timing | Detect automated activity (regular intervals suggest scripting) | Compute inter-event time distribution, flag low-variance clusters |
| Volumetric anomalies | Detect unusual data transfer volumes | SRUM network usage aggregated by process, flag >3 sigma |
| First-seen analysis | Identify programs/connections never seen before the incident | Compare Prefetch/network artifacts against baseline period |

### 9.2 Event Clustering for Activity Reconstruction

```
┌─────────────────────────────────────────────────────────────────┐
│                  Event Clustering Pipeline                       │
│                                                                  │
│  1. Temporal proximity clustering                                │
│     └─ Group events within configurable time windows (default:  │
│        30s for automated activity, 5min for human activity)     │
│                                                                  │
│  2. Entity-based clustering                                      │
│     └─ Group events sharing: user account, file path, process   │
│        name, IP address, domain                                 │
│                                                                  │
│  3. Causal chain inference                                       │
│     └─ Connect events by known cause-effect patterns:           │
│        download → file creation → execution → persistence →     │
│        network connection                                       │
│                                                                  │
│  4. Session reconstruction                                       │
│     └─ Group into user sessions: login → activity → logout      │
│        Use logon events (4624/4634) + RDP sessions + screen     │
│        lock events as session boundaries                        │
│                                                                  │
│  5. Attack chain assembly                                        │
│     └─ Merge detection hits + clusters into candidate attack    │
│        chains, map to ATT&CK kill chain phases                  │
└─────────────────────────────────────────────────────────────────┘
```

### 9.3 Cross-Artifact Correlation Rules

Deterministic correlation rules that connect artifacts across different parsers:

| Source Artifact | Correlated Artifact | Correlation Key | Insight |
|----------------|--------------------|-----------------| --------|
| Browser download (Chrome History) | File creation (USN Journal) | File path + time proximity | Confirms download actually created the file |
| File creation (USN Journal) | Process execution (Prefetch) | Executable path | Confirms downloaded file was executed |
| Process execution (Prefetch) | Network connection (SRUM) | Process name + time | Shows what the executed file connected to |
| Network connection (SRUM) | DNS cache entry | Domain/IP | Resolves IP to domain name |
| Registry modification | Scheduled task XML | Task name/path | Confirms persistence mechanism |
| Logon event (4624) | File access (USN Journal) | User SID + time window | Attributes file access to user session |

---

## 10. Evaluation Framework

### 10.1 Evaluation Pyramid

```
                    ┌───────────┐
                    │  Human    │  ← Expert examiner review (sampled)
                    │  Review   │     Frequency: 10% of generated content
                    ├───────────┤
                    │  Domain   │  ← Forensic-specific validation
                    │  Evals    │     Citation accuracy, legal-safe language,
                    │           │     ATT&CK mapping precision
                    ├───────────┤
                    │  LLM-as-  │  ← Automated quality assessment
                    │  Judge    │     Faithfulness, relevance, coherence
                    │           │     (second model, different from generator)
                    ├───────────┤
                    │  Unit     │  ← Deterministic correctness checks
                    │  Evals    │     Schema validation, citation resolution,
                    │           │     prohibited pattern detection
                    └───────────┘
```

### 10.2 Evaluation Methods

| Method | Purpose | When to Use | Implementation |
|--------|---------|-------------|----------------|
| Citation resolver | Verify every [SOURCE:...] traces to real evidence | Every generation | Parse citations, query issen-timeline for existence |
| Prohibited pattern detector | Catch legal conclusions, causal attribution | Every generation | Regex + NLI model for semantic detection |
| LLM-as-judge (faithfulness) | Score how grounded output is in retrieved context | Every generation | Second model compares output against context |
| LLM-as-judge (coherence) | Score readability and logical flow | Report drafts | Second model rates on 1-5 scale |
| Golden dataset comparison | Ground truth comparison for ATT&CK mapping | Weekly regression | NIST CFReDS cases with known-correct mappings |
| Boundary testing | Verify off-topic/out-of-scope rejection | Release testing | Test suite of adversarial prompts |
| Schema validation | Verify structured output correctness | Every structured generation | JSON Schema validation against output types |
| Human expert review | Certified examiner scores AI output quality | Sampled 10% | Blind review, scoring rubric, feedback collected |

### 10.3 Quality Metrics

| Metric | Target | Measurement | Alert Threshold |
|--------|--------|-------------|-----------------|
| Citation accuracy | >98% | Citations that resolve to real artifacts / total citations | <95% |
| Answer faithfulness | >95% | LLM-judge faithfulness score (0-1) | <90% |
| Prohibited pattern rate | 0% | Prohibited patterns detected / total generations | >0% (any occurrence) |
| ATT&CK mapping precision | >85% | Correct technique IDs / total mapped techniques (vs golden set) | <80% |
| Retrieval precision@5 | >80% | Relevant chunks in top-5 / 5 | <70% |
| Generation latency P50 | <5s | Measured per-section generation time | >10s |
| Generation latency P95 | <30s | Measured per-section generation time | >60s |
| Embedding latency P95 | <200ms | Per-event embedding time | >500ms |
| Cost per case (local) | $0 | Hardware amortized | N/A |
| Cost per case (cloud fallback) | <$5 | Cloud API spend per case | >$10 |
| Human override rate | Tracking | Sections where examiner rewrites >50% of AI text | >30% (triggers model review) |

---

## 11. Data Pipeline

### 11.1 Ingestion Flows

```
┌───────────────────────────────────────────────────────────────────┐
│                    Intelligence Data Pipeline                     │
│                                                                   │
│  ┌─────────────┐     ┌──────────────┐     ┌─────────────────┐   │
│  │ issen-pipeline │────►│ Event Stream │────►│ Embedding Queue │   │
│  │ (parsed     │     │ (channel)    │     │ (async, batched)│   │
│  │  artifacts) │     └──────┬───────┘     └────────┬────────┘   │
│  └─────────────┘            │                      │            │
│                       ┌─────▼──────┐         ┌─────▼──────┐    │
│                       │ IOC        │         │ lancedb    │    │
│                       │ Extractor  │         │ Case Store │    │
│                       └─────┬──────┘         └────────────┘    │
│                             │                                   │
│                       ┌─────▼──────┐                           │
│                       │ TI Enricher│                           │
│                       │ (parallel  │                           │
│                       │  backends) │                           │
│                       └─────┬──────┘                           │
│                             │                                   │
│                       ┌─────▼──────┐                           │
│                       │ Detection  │                           │
│                       │ Engine     │                           │
│                       │(YARA+Sigma)│                           │
│                       └────────────┘                           │
└───────────────────────────────────────────────────────────────────┘
```

### 11.2 Freshness Guarantees

| Data Type | Freshness Target | Mechanism |
|-----------|-----------------|-----------|
| Case artifacts → vector store | <5s after parsing | Streaming embed on parse completion |
| Examiner annotations → vector store | <2s after save | Immediate embed on annotation save |
| IOC enrichment | <30s for cache hit, <5s for local lookup | Local cache with TTL, async TI query |
| Detection results | <60s after ingest complete | Batch YARA scan + Sigma query post-ingest |
| Cross-case knowledge | On case close | Batch job triggered by case status change |
| Reference data | Quarterly | Manual trigger with progress indicator |

### 11.3 Context Assembly

How retrieved context is assembled before passing to the generative model:

1. **Retrieval**: Query all relevant stores (case-specific, cross-case, reference) in parallel. Collect top-50 candidates per store.
2. **Source deduplication**: Remove near-duplicate chunks across stores (cosine similarity >0.95).
3. **Reranking**: Use cross-encoder reranker to reorder merged results by query relevance. Top-20 survive.
4. **Metadata enrichment**: Attach source store label, confidence score, and freshness timestamp to each chunk.
5. **Token budgeting**: Allocate context window budget: 60% evidence chunks, 20% reference context, 10% system prompt, 10% generation headroom. Truncate lowest-ranked chunks to fit.
6. **Ordering**: Evidence chunks ordered chronologically (forensic narratives must respect temporal order). Reference chunks grouped by topic.
7. **Template injection**: Merge assembled context into the generation prompt template with clear section delimiters (`### EVIDENCE CONTEXT ###`, `### REFERENCE CONTEXT ###`).

---

## 12. AI-Free Mode

### 12.1 Design Principle

All AI features are behind a global toggle (`config.ai.enabled = false`). When disabled, the platform operates as a pure deterministic forensic pipeline. This is not a degraded mode -- it is the **baseline product** that must be fully functional.

### 12.2 Feature Toggle Matrix

| Feature | AI Enabled | AI Disabled | Fallback |
|---------|-----------|-------------|----------|
| Evidence ingestion & parsing | Full | Full | No change -- parsers are deterministic |
| Timeline construction | Full | Full | No change -- DuckDB queries are deterministic |
| YARA-X scanning | Full | Full | No change -- YARA is deterministic rule matching |
| Sigma rule matching | Full | Full | No change -- Sigma-to-SQL is deterministic |
| IOC extraction | AI + regex | Regex only | Regex patterns for common IOC formats |
| IOC enrichment | TI platform queries | Manual / offline feeds | CSV import of TI feeds |
| ATT&CK mapping | AI-assisted + rule-based | Rule-based only | Deterministic artifact-to-technique mapping |
| Report drafting | AI narrative + human review | Template-only (examiner writes) | Report templates with placeholder sections |
| Anomaly detection | Statistical + AI correlation | Statistical only | Rolling window statistics, threshold alerts |
| Similar case matching | Vector similarity search | Disabled | Manual keyword search in case notes |
| Image series detection | Perceptual hashing | Perceptual hashing | No change -- hashing is deterministic |
| OCR | Tesseract | Tesseract | No change -- OCR is not LLM-dependent |
| Event clustering | AI + temporal + entity | Temporal + entity only | Deterministic clustering rules |

### 12.3 AI-Free Guarantees

1. **No Ollama dependency**: The application launches and runs without Ollama installed
2. **No model downloads**: No automatic model downloads occur in AI-free mode
3. **No network calls for AI**: No API calls to cloud AI providers
4. **Full feature parity for core forensics**: Parsing, timeline, detection, and reporting templates all work identically
5. **Configuration persistence**: AI-free preference is stored in `~/.issen/config.toml` and survives upgrades
6. **Per-feature granularity**: Advanced users can enable specific AI features while keeping others disabled (e.g., enable OCR but disable narrative generation)

---

## Appendix A: Technology Reference

| Component | Technology | Version | License | Purpose |
|-----------|-----------|---------|---------|---------|
| LLM Runtime | Ollama | Latest | MIT | Local model serving |
| Vector Store | lancedb | 0.x | Apache 2.0 | Embedded vector database |
| Embedding Model | nomic-embed-text | v1.5 | Apache 2.0 | Text embedding |
| YARA Engine | YARA-X | Latest | BSD-3 | File signature scanning |
| Sigma Engine | Custom (Rust) | N/A | Proprietary | Event log rule matching |
| Perceptual Hashing | image-hasher + phash crates | Latest | MIT / Apache 2.0 | Image series detection |
| OCR | Tesseract (Rust bindings) | 5.x | Apache 2.0 | Text extraction from images |
| OCR (fallback) | ocrs | Latest | Apache 2.0 | Pure Rust OCR |
| Base LLM (small) | Llama 3.1 8B | Q8 | Llama Community | Classification, extraction |
| Base LLM (medium) | Llama 3.1 70B | Q4 | Llama Community | Narrative drafting |
| IOC extraction | Fine-tuned Phi-3 | Mini | MIT | Structured IOC extraction |

## Appendix B: Glossary

| Term | Definition |
|------|-----------|
| **Grounded generation** | LLM output where every factual claim traces to a specific source artifact |
| **Citation validation** | Automated verification that inline source references resolve to real evidence |
| **Dual-model verification** | Using a second, different model to verify claims made by the generation model |
| **ForensicLLM** | Planned fine-tuned LLaMA derivative optimized for forensic report generation |
| **Modular RAG** | Separate retrieval pipelines per knowledge source, merged at generation time |
| **AI-free mode** | Global configuration toggle that disables all AI/ML features |
| **Perceptual hashing** | Image fingerprinting algorithms resistant to format conversion and resizing |
| **Matryoshka embeddings** | Embedding model that supports truncation to lower dimensions without retraining |

## Appendix C: References

- [Anomaly Detection in a Forensic Timeline with Deep Autoencoders](https://www.sciencedirect.com/science/article/abs/pii/S2214212621002076)
- [SoK: Timeline-Based Event Reconstruction for Digital Forensics (2025)](https://www.sciencedirect.com/science/article/pii/S266628172500071X)
- [Effective Near-Duplicate Image Detection Using Perceptual Hashing and Deep Learning (2025)](https://www.sciencedirect.com/science/article/abs/pii/S0306457325000287)
- [Using Local LLMs for Criminal Intelligence Report Generation](https://alessandro-negro.medium.com/using-local-deployment-of-open-source-llms-for-criminal-intelligence-repoissen-generation-ddb8db944620)
- [CASE: Cyber-investigation Analysis Standard Expression](https://caseontology.org/)
- [UCO: Unified Cybersecurity Ontology](https://unifiedcyberontology.org/)
- [MalChela: Rust-based MITRE ATT&CK toolkit](https://github.com/target/malchela)
- [YARA-X: Rust implementation of YARA](https://github.com/VirusTotal/yara-x)
- [SigmaHQ Rule Repository](https://github.com/SigmaHQ/sigma)
- [nomic-embed-text](https://huggingface.co/nomic-ai/nomic-embed-text-v1.5)
- [LanceDB](https://lancedb.com/)
