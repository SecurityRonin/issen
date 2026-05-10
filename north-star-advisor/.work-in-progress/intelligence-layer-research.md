# Issen Intelligence Layer — Research & Recommendations

> Research date: 2026-03-20
> Scope: AI/ML integration strategy for the Issen forensic triage platform

---

## Table of Contents

1. [AI-Assisted Forensic Report Generation](#1-ai-assisted-forensic-repoissen-generation)
2. [Forensic Intelligence / CTI Integration](#2-forensic-intelligence--cti-integration)
3. [Embedding & RAG for Forensic Data](#3-embedding--rag-for-forensic-data)
4. [Correlation & Pattern Detection](#4-correlation--pattern-detection)
5. [Image / Media Analysis](#5-image--media-analysis)
6. [Model Selection & Deployment](#6-model-selection--deployment)
7. [Sigma Rules & Detection Engineering](#7-sigma-rules--detection-engineering)
8. [Recommended Architecture](#8-recommended-architecture)
9. [Implementation Roadmap](#9-implementation-roadmap)
10. [Sources](#10-sources)

---

## 1. AI-Assisted Forensic Report Generation

### 1.1 State of the Art (2025-2026)

The intersection of LLMs and digital forensics is now a serious research field with peer-reviewed publications at DFRWS and ICDF2C.

**ForensicLLM** (DFRWS EU 2025) is a 4-bit quantized LLaMA-3.1-8B model fine-tuned on forensic Q&A data. Key results:
- Outperformed both base LLaMA-3.1-8B and RAG-augmented models
- 86.6% source attribution accuracy; 81.2% include both authors and title
- Designed specifically for resource-constrained environments (runs locally)
- Published in *Forensic Science International: Digital Investigation* (2025)

**Comprehensive Survey** (Chernyshev et al., March 2026): Systematic review of 33 peer-reviewed works found:
- LLMs achieve 85-98% accuracy across diverse forensic tasks
- Probabilistic LLM outputs fundamentally conflict with deterministic forensic requirements
- Three strategic integration points: pattern recognition (examination phase), evidence analysis (analysis phase), evidence presentation (presentation phase)
- Critical gaps in validation frameworks and standardized evaluation protocols

**Best Paper at EAI ICDF2C 2025**: Evaluated 12 LLMs across 1,046 simulated attack scenarios:
- Claude 3.7 Sonnet: 86% accuracy capturing critical forensic entities
- GPT-4o: remarkable consistency in generating executable code for timeline reconstruction
- Key insight: LLM-assisted analysis augments investigators, not replaces them

### 1.2 Narrative Generation from Timeline Data

The core use case for Issen is transforming technical timelines into attorney-readable narratives. The research shows this is feasible but requires careful design:

**What works well:**
- Text summarization of forensic findings
- Automating boilerplate report sections (methodology, tool descriptions, chain of custody templates)
- Generating initial draft narratives from structured timeline data
- Translating technical artifacts into plain English descriptions

**What requires human oversight:**
- Causal claims ("X caused Y") — LLMs may infer causation from correlation
- Temporal reasoning — LLMs can misinterpret timezone-shifted timestamps
- Legal conclusions — must never be AI-generated
- Attribution statements — "the user performed action X" vs. "the account associated with user X was used to perform action X"

### 1.3 Hallucination Prevention (Critical for Expert Witness Reports)

This is the single most important concern for Issen. A hallucinated fact in an expert witness report can:
- Lead to sanctions against the examiner
- Trigger Daubert challenges that exclude the entire report
- End the examiner's career
- Compromise the case outcome

**Scale of the problem:**
- Stanford research: general-purpose LLMs hallucinate 58-88% of the time on legal queries
- Even RAG-focused legal AI tools produce incorrect information 17-34% of the time
- 1,093 documented cases where courts found parties relied on hallucinated AI content

**Recommended mitigation architecture for Issen:**

1. **Grounded generation only**: Every LLM-generated sentence must trace to specific artifacts in the evidence. No free-form generation.
2. **Template + fill pattern**: LLM fills structured templates, not free-form prose. Templates enforce correct legal language.
3. **Citation-required architecture**: Every factual claim includes an inline reference to the source artifact (file path, registry key, log entry, timestamp).
4. **Dual-model verification**: Generate with one model, verify claims with a second model against the raw evidence.
5. **Confidence scoring**: Each generated paragraph gets a confidence score; low-confidence sections are flagged for mandatory human review.
6. **Never self-verify**: Never ask the same LLM to check its own output — it will double down on hallucinations.
7. **Deterministic fallback**: If the LLM cannot generate a grounded statement, fall back to structured data presentation (tables, timelines) rather than narrative.

### 1.4 Legal / Ethical Considerations

- **Proposed Federal Rule of Evidence 707**: Would subject machine-generated evidence to the same reliability standards as human expert testimony
- **Disclosure obligation**: Many jurisdictions now require disclosure of AI use in legal filings
- **Chain of custody for AI**: Must document which model, version, prompt, and parameters were used for each generation
- **Non-determinism**: Same input may produce different output — run reports through deterministic post-processing
- **Bias in training data**: LLMs may reflect biases from their training corpus; forensic reports must be objective

**Recommendation for Issen:**
- Always label AI-assisted sections explicitly: "This narrative summary was generated with AI assistance and reviewed by [examiner name]"
- Store the full generation provenance (model, prompt, raw output, edits) as part of the case file
- Implement an "AI-free mode" for jurisdictions or clients that prohibit AI assistance
- The examiner's signature on the report means they have verified every statement — the AI is a drafting tool, not an author

### 1.5 Human-in-the-Loop Patterns

The forensic report workflow demands a multi-tiered review pattern:

**Recommended workflow for Issen:**

```
[Artifact Analysis] → [AI Draft Generation] → [Examiner Review Gate]
                                                      ↓
                                              [Approve / Edit / Reject]
                                                      ↓
                                           [Senior Review Gate (optional)]
                                                      ↓
                                              [Attorney Review Gate]
                                                      ↓
                                              [Final Report Generation]
```

**Design principles:**
- **Approval gates**: Formal breakpoints where autonomous processing stops until human approval
- **Append-only audit trail**: Every action (generate, edit, approve, reject) logged with timestamp, user identity, and rationale
- **Cryptographic linking**: Each review decision is cryptographically linked to the report version it approved
- **Risk tiering**: Classify report sections by risk level:
  - **High risk** (conclusions, attribution, legal findings): Mandatory human authorship, no AI generation
  - **Medium risk** (narrative summaries, timeline descriptions): AI draft + mandatory human review
  - **Low risk** (methodology boilerplate, tool descriptions, exhibit lists): AI generation with periodic audit
- **Precedent tracking**: When a reviewer approves a pattern, capture the rationale for future similar cases
- **Defense in depth**: First-pass review by examiner, optional senior review, attorney review, and periodic expert spot checks

---

## 2. Forensic Intelligence / CTI Integration

### 2.1 MITRE ATT&CK Mapping from Forensic Artifacts

MITRE ATT&CK provides the common language between forensic findings and threat intelligence. For Issen, automated mapping should work at two levels:

**Artifact-level mapping** (automated):
- Registry persistence locations → T1547 (Boot or Logon Autostart Execution)
- Suspicious scheduled tasks → T1053 (Scheduled Task/Job)
- LSASS memory access patterns → T1003 (OS Credential Dumping)
- WMI event subscriptions → T1546.003 (WMI Event Subscription)
- Prefetch entries for known attacker tools → mapped to relevant techniques

**Behavioral-level mapping** (AI-assisted):
- Clustering related artifacts into attack chains
- Mapping chains to ATT&CK tactics progression (Initial Access → Execution → Persistence → ...)
- Identifying gaps in the chain that suggest missed artifacts

**Recommended tools/data sources:**
- [ATT&CK Navigator](https://attack.mitre.org/) for visualization
- ATT&CK STIX data (machine-readable) for programmatic mapping
- Atomic Red Team test definitions for understanding technique signatures
- MalChela (Rust-based toolkit) as architectural reference — combines YARA scanning, hash generation, string extraction with MITRE ATT&CK mapping, and threat intelligence integration

### 2.2 IOC Extraction and Enrichment

Issen should extract IOCs automatically during artifact parsing:

**IOC types to extract:**
- File hashes (MD5, SHA1, SHA256) from filesystem artifacts
- IP addresses and domains from browser history, DNS cache, network connections
- Email addresses from email artifacts and browser autofill
- Registry keys associated with malware persistence
- File paths matching known malware patterns
- Mutex names from memory analysis
- Certificate thumbprints from signed executables

**Enrichment pipeline:**
```
[Extracted IOC] → [Local cache check] → [TI platform query] → [Enriched IOC]
                                              ↓
                              [VirusTotal / AlienVault OTX / MISP / OpenCTI]
```

### 2.3 Threat Intelligence Platform Integration

**MISP** (Malware Information Sharing Platform):
- Best for: IOC sharing, malware analysis, lightweight threat intelligence
- API: REST API with JSON, STIX 1.x/2.0, CSV, OpenIOC export
- Outputs: IDS rules (Suricata, Snort, Zeek), RPZ zones, forensic tool formats
- Free-text import: Automatically detect and convert IOCs from unstructured reports
- Heavily used by government CERTs and ISACs

**OpenCTI**:
- Best for: Structured graph-based CTI management, threat actor tracking, STIX 2.1 compliance
- API: GraphQL API with STIX 2.1 native support
- Connectors: AlienVault OTX, VulnCheck, MISP, MITRE ATT&CK, AbuseCH (free feeds)
- Integration: Bi-directional sync with MISP via native connector

**Recommended integration strategy for Issen:**
- Implement a TI abstraction layer with pluggable backends (MISP, OpenCTI, VirusTotal, custom)
- Support both online (API query) and offline (exported feed file) modes for air-gapped labs
- Cache enrichment results locally to minimize API calls and support offline analysis
- Export Issen findings back to MISP/OpenCTI for sharing within trusted communities

### 2.4 Dark Web Monitoring Integration

For infostealer and credential exposure checks:

**Integration points:**
- Flare.io API for stealer log monitoring
- BreachSense API for credential exposure checks
- Have I Been Pwned API for email/domain breach checks
- Custom Telegram channel monitoring (where trading has shifted post-Genesis Market takedown)

**Note**: Dark web monitoring is primarily a SaaS integration play — Issen should consume enrichment data from these platforms, not build its own dark web scraping capability.

### 2.5 Infostealer Log Parsing and Correlation

The infostealer ecosystem is critical for modern IR cases:

**Market landscape (2025-2026):**
- Russian Market: 5M+ logs for sale, 670% growth over two years, now dominant marketplace
- Genesis Market: Taken down by law enforcement, but Tor site remains; trading shifted to Telegram
- Lumma (LummaC2): 92% of Russian Market credential log alerts in Q4 2024; taken down May 2025
- Acreed: Emerging as next dominant infostealer post-Lumma takedown

**Log parsing challenges:**
- Format varies significantly between infostealers (Lumma, RedLine, Raccoon, Vidar, Acreed)
- Quality and recency of stolen data is highly heterogeneous
- Parsing tools are needed to normalize formats across different stealers
- Key data fields: credentials (URL, username, password), cookies, autofill data, browser history, cryptocurrency wallets, system info

**Recommended capability for Issen:**
- Infostealer log parser plugin that normalizes common formats (RedLine, Raccoon, Lumma, Vidar, Acreed)
- Correlation engine: match extracted credentials/cookies against the organization's domain inventory
- Timeline integration: when were credentials stolen? (system info timestamps from the stealer log)
- Risk scoring: prioritize by corporate access, privileged accounts, MFA-enrolled status
- Research shows 1.91% of stealer logs contain corporate application access — this is the high-value signal

---

## 3. Embedding & RAG for Forensic Data

### 3.1 Embedding Models for Forensic Artifacts

Standard text embeddings may not capture the semantic meaning of forensic artifacts well. Forensic data has unique characteristics:

**Challenges:**
- File paths have hierarchical structure (`C:\Users\John\AppData\Local\Temp\malware.exe`)
- Registry keys are semi-structured (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`)
- Log entries combine timestamps, structured fields, and free text
- IOCs (hashes, IPs, domains) are essentially identifiers, not natural language

**Recommended approach:**
- **Hybrid embedding**: Combine structural parsing (extract path components, registry hive/key/value) with text embedding
- **Domain-specific fine-tuning**: Fine-tune an embedding model on forensic report corpus (ForensicLLM's approach with LLaMA is a good precedent)
- **Multi-modal embedding**: Different embedding strategies for different artifact types
- **Metadata-enriched embedding**: Embed not just the artifact value but its context (artifact type, source, timestamp, associated user)

### 3.2 RAG Architecture for Forensic Knowledge

**Two distinct RAG use cases for Issen:**

**Case-specific RAG** (per investigation):
- Index all artifacts, parsed results, and examiner notes for the current case
- Enable natural language queries: "What network connections did the user make after the malware was executed?"
- Supports report drafting by retrieving relevant evidence for each report section
- Chunking strategy: by artifact record (each USN Journal entry, each browser history entry, each event log entry)

**Knowledge-base RAG** (cross-case):
- Index known malware behaviors, ATT&CK technique descriptions, forensic methodology documents
- Enable pattern matching: "Have we seen this persistence mechanism before?"
- Index past case reports (anonymized) for template and precedent retrieval
- Chunking strategy: by section (technique description, case narrative paragraph, methodology step)

**Recommended RAG pipeline:**
```
[Forensic Artifacts] → [Structured Parsing] → [Chunking] → [Embedding] → [Vector Store]
                                                                              ↓
[User Query / Report Template] → [Embed Query] → [Hybrid Search] → [Top-K Results]
                                                                         ↓
                                                              [Reranking] → [LLM Generation]
                                                                                   ↓
                                                                         [Grounded Output with Citations]
```

### 3.3 Vector Search for Similar Incident Matching

**Use case**: "Have we seen this attack pattern before across all our cases?"

**Implementation approach:**
- Embed attack pattern signatures (combination of ATT&CK techniques, IOCs, behavioral indicators)
- Use cosine similarity to find similar historical incidents
- Combine with knowledge graph traversal for relationship-based matching

**Recommended vector databases (local/air-gapped compatible):**
- **Qdrant** (Rust-native): Best fit for Issen's Rust stack; supports hybrid search, can run embedded or as a service
- **LanceDB** (Rust-native): Embedded vector database, serverless, good for single-machine deployments
- **SQLite with vector extensions**: Minimal dependency for simple cases
- **Milvus Lite**: Embedded mode for development, full cluster for production

### 3.4 Forensic Knowledge Graphs

Knowledge graphs complement vector search by modeling explicit relationships:

**Key ontologies and standards:**
- **CASE (Cyber-investigation Analysis Standard Expression)**: Specification language for forensic data; covers digital forensic science, incident response, counter-terrorism, criminal justice
- **UCO (Unified Cybersecurity Ontology)**: Links STIX, CAPEC, MAEC, CWE, CVE, CVSS, CybOX, CPE, OpenIOC
- **STIX 2.1**: Foundation for threat intelligence knowledge graphs
- **CRATELO**: Specifically targets cyber incident and forensic data representation

**Recommended graph structure for Issen:**
```
[User Account] ──uses──→ [Device]
       ↓                      ↓
   accesses              contains
       ↓                      ↓
  [Application] ←──runs── [Process] ──connects──→ [Network Endpoint]
       ↓                      ↓                          ↓
   generates             modifies               resolves_to
       ↓                      ↓                          ↓
   [Artifact]            [File]                   [IP Address]
                           ↓                          ↓
                      has_hash                 enriched_by
                           ↓                          ↓
                     [Hash Value]              [TI Report]
```

**Graph database options (Rust-compatible):**
- **Neo4j** (via Bolt protocol): Most mature, extensive query language (Cypher)
- **Apache AGE** (PostgreSQL extension): GraphQL on PostgreSQL, simpler deployment
- **Custom in-memory graph**: For case-specific graphs that don't need persistence beyond the case

---

## 4. Correlation & Pattern Detection

### 4.1 Statistical Anomaly Detection in Timelines

Research validates several approaches for forensic timeline anomaly detection:

**Deep Autoencoders** (Studiawan et al., 2021):
- Establish baseline for "normal" log activity using deep autoencoders
- Anomalous events produce high reconstruction errors compared to baseline
- Results: F1 score 94.036%, accuracy 96.720%
- Well-suited for detecting unusual activity patterns in large timelines

**Graph-Based Clustering** (MajorClust adaptation):
- Parameter-free clustering of access control log events
- Anomaly scoring based on cluster size, event frequency, and inter-arrival time
- Results: 70.59% sensitivity, 82.21% specificity, 83.14% accuracy
- Advantage: automatically generates analysis reports for investigators

**Recommended approach for Issen:**
- **Temporal density analysis**: Identify time periods with unusual activity volume (e.g., burst of file modifications at 3 AM)
- **Behavioral baselining**: Learn normal patterns for a user/system, flag deviations
- **Inter-arrival time analysis**: Detect automated/scripted activity (inhuman speed between events)
- **Timestamp manipulation detection**: Identify anti-forensic timestomping (e.g., file created after it was modified)

### 4.2 Clustering Related Events

**Cross-artifact correlation is Issen's core differentiator.** Example correlation chain:

```
Browser download (Chrome History) → File creation (USN Journal) →
Process execution (Prefetch) → Network connection (SRUM) →
Registry modification (Registry hive) → Scheduled task creation (Task XML)
```

**Clustering algorithms for forensic events:**
- **Temporal proximity clustering**: Events within configurable time windows
- **Entity-based clustering**: Events sharing common entities (user, file path, process, IP)
- **Causal chain inference**: Events connected by known cause-effect patterns (download → execute → persist)
- **Session reconstruction**: Group events into user sessions (login → activity → logout)

### 4.3 User Activity Reconstruction

**SigDiff framework** (automated user activity reconstruction):
- Extracts user activities from digital artifacts automatically
- Addresses limitations of manual analysis (investigator knowledge gaps, human errors)
- Compares artifact signatures before and after known activities to identify patterns

**System Syndicate** (2026):
- Nine workflow modules: NTFS exploration, high-resolution timelines, browser/activity extraction, static malware detection, credential enumeration
- Deterministic, artifact-driven analysis for objectively demonstrable outputs

**Recommendation for Issen:**
- Build activity reconstruction as a first-class feature
- Map activities to human-readable descriptions: "User John opened malicious.docx from email at 14:32, which spawned PowerShell at 14:33, which downloaded payload.exe at 14:34"
- This is exactly the forensic-to-legal translation that is Issen's differentiator

### 4.4 Network of Artifacts Visualization

**Recommended visualization types:**
- **Timeline view**: Horizontal scrollable timeline with artifact type color coding and zoom
- **Entity relationship graph**: Interactive graph showing connections between files, processes, users, network endpoints
- **ATT&CK heatmap**: Color-coded ATT&CK Navigator showing detected techniques
- **Geolocation map**: For cases involving network connections or mobile device location data
- **Treemap**: File system visualization showing modified/suspicious areas
- **Sankey diagram**: Data flow visualization (user → application → network destination)

---

## 5. Image / Media Analysis

### 5.1 Image Series Grouping (HEIC Original → Snapseed → Instagram)

This is a specific and valuable use case for mobile forensic cases. The workflow:

```
[Original Photo (HEIC)] → [Edited Copy (Snapseed JPEG)] → [Shared Copy (Instagram cache)]
```

**Detection approach:**
1. **Perceptual hashing** to identify visually similar images across different formats/resolutions
2. **EXIF/metadata analysis** to establish provenance chain (creation dates, editing software tags, GPS data)
3. **File naming patterns** to correlate (IMG_1234.HEIC → IMG_1234_snapseed.jpg)
4. **Directory context** to identify source application (e.g., `/com.instagram.android/cache/`)

### 5.2 Perceptual Hashing

**Algorithm comparison:**

| Algorithm | Speed | Robustness | Best For |
|-----------|-------|------------|----------|
| aHash (Average Hash) | Fastest | Low | Quick pre-filter |
| dHash (Difference Hash) | Fast | Medium | Near-duplicate detection in controlled sets |
| pHash (DCT-based) | Medium | High | Cross-format/resolution matching |
| wHash (Wavelet) | Medium | High | Textured image comparison |
| DINOHash (2025 SOTA) | Slow | Highest | Heavy crops, compression, adversarial attacks |

**Rust implementations:**
- `image-hasher` crate: Supports dHash and other algorithms, well-maintained
- `phash` crate: Perceptual hash with Hamming distance comparison
- Both use Hamming distance for similarity scoring; threshold of 2-5 bits on 128-bit hash for near-duplicates

**Recommended approach for Issen:**
- Use dHash as fast pre-filter (eliminates obviously different images)
- Use pHash for robust matching of candidates
- Combine with EXIF metadata analysis for provenance chain reconstruction
- Store hashes in case database for cross-case matching
- Consider DINOHash integration for challenging cases (heavy edits, crops)

### 5.3 EXIF/Metadata Analysis

Key metadata fields for forensic provenance:
- `DateTimeOriginal`: When the photo was taken
- `DateTimeDigitized`: When it was digitized
- `DateTime`: Last modification
- `Software`: Editing application (Snapseed, Lightroom, etc.)
- `GPSInfo`: Location data (if not stripped)
- `Make`/`Model`: Camera/device identification
- `ImageUniqueID`: Unique identifier (if present)
- `XMP:History`: Edit history in Adobe XMP format

**Rust libraries:**
- `kamadak-exif` crate: EXIF parsing
- `rexiv2` crate: XMP/IPTC/EXIF (wraps gexiv2)

### 5.4 OCR for Screenshots and Document Images

**Rust OCR options:**

1. **Tesseract via Rust bindings** (`tesseract` crate v0.15):
   - Most mature, 100+ languages
   - Requires preprocessing (grayscale, thresholding, 300+ DPI)
   - Output formats: plain text, hOCR, PDF, TSV, ALTO
   - Good for: scanned documents, chat screenshots, browser screenshots

2. **`ocrs`** (pure Rust, ML-based):
   - Uses ONNX neural network models
   - Less preprocessing needed than Tesseract
   - Currently Latin alphabet only
   - Early preview stage but promising

**Recommended for Issen:**
- Tesseract bindings for production use (mature, multilingual)
- `ocrs` as experimental option for environments where Tesseract installation is problematic
- Preprocessing pipeline: grayscale → contrast enhancement (CLAHE) → Gaussian blur → Otsu thresholding → upscaling
- Use case: Extract text from chat screenshots, document images, application screenshots in mobile forensic cases

---

## 6. Model Selection & Deployment

### 6.1 On-Premise vs. Cloud

**Forensic data CANNOT go to cloud APIs in most cases:**
- Chain of custody requirements: data must stay on controlled systems
- Client confidentiality: law firm privilege, NDA, PII
- Law enforcement cases: evidence handling rules prohibit cloud processing
- Even cloud providers that claim no data retention may log data for operational purposes
- Many forensic labs are air-gapped networks

**Recommendation: Local-first with optional cloud for non-sensitive tasks.**

### 6.2 Local LLM Options

**Primary recommendation: Ollama**
- Built on llama.cpp, adds model management and API layer
- Supports macOS (Apple Silicon), Linux, Windows
- Automatic hardware detection and optimization
- Supports fully air-gapped operation (pre-download models via physical media)
- REST API compatible with OpenAI API format (easy integration)
- Real-world validation: Law enforcement intelligence report generation on MacBook Pro M4 Max / 64GB (documented case study)

**Alternative: llama.cpp direct**
- Zero dependencies, maximum control
- Custom compilation flags, fine-grained layer offloading
- Runs on anything: laptops, ARM devices, Raspberry Pi
- Requires manual model conversion and quantization
- Best for embedded/edge deployments

**Hardware requirements (Q4_K_M quantization, ~0.6-0.7 GB VRAM per billion parameters):**

| Model Size | VRAM Required | Suitable Hardware | Quality Level |
|------------|---------------|-------------------|---------------|
| 7-8B | 4-6 GB | Any modern laptop | Basic summarization, formatting |
| 13-14B | 8-10 GB | Gaming laptop, Mac M1+ | Good summarization, some reasoning |
| 30-34B | 20-24 GB | Mac M2 Pro+, RTX 4090 | Strong reasoning, report drafting |
| 70B | 40-48 GB | Mac M2 Ultra, 2x RTX 4090 | Near-cloud quality, complex analysis |

### 6.3 Model Routing Strategy

**Not every forensic task needs a 70B model.** Implement a task router:

| Task | Model Tier | Rationale |
|------|-----------|-----------|
| Artifact description (single item) | Small (7-8B) | Templated, low complexity |
| Boilerplate generation | Small (7-8B) | Repetitive, well-defined |
| IOC extraction from text | Small (7-8B) | Pattern matching, not reasoning |
| Timeline narrative summarization | Medium (13-34B) | Requires coherence and context |
| Cross-artifact correlation explanation | Large (70B+) | Complex reasoning across evidence |
| Expert witness report drafting | Large (70B+) | Nuanced language, legal precision |
| ATT&CK technique mapping | Medium (13-34B) | Requires domain knowledge |

**Routing implementation:**
- Rule-based router for initial version (task type → model mapping table)
- Complexity classifier for v2 (small model classifies query complexity, routes accordingly)
- Estimated cost savings: 60-70% reduction by routing 80% of tasks to smaller models

**For cloud-allowed scenarios** (e.g., sanitized data, non-privileged cases):
- Use model routing across providers: simple tasks → Claude Haiku or GPT-4o-mini; complex tasks → Claude Opus or GPT-4o
- This can cut API costs by 60%+ while maintaining quality on complex tasks

### 6.4 ForensicLLM as a Starting Point

The ForensicLLM project provides a blueprint for Issen:
- Fine-tuned LLaMA-3.1-8B on forensic domain data
- 4-bit quantization for resource-constrained environments
- RAG comparison baseline
- Published methodology for creating forensic training data

**Recommendation:** Consider fine-tuning a model on Issen's specific output format and forensic vocabulary, using the ForensicLLM approach as a template.

---

## 7. Sigma Rules & Detection Engineering

### 7.1 Sigma Rules Integration

Issen's `tl` (timeline) tool already has Sigma support. To deepen this:

**Current state of Sigma:**
- Generic, open YAML-based signature format for log events
- "Sigma is for log files what Snort is for network traffic and YARA is for files"
- 2/3 of Windows rules are based on Sysmon events
- SigmaHQ repository provides community-maintained rule sets

**Integration pattern (modeled on Timesketch):**
- Run Sigma analyzer against timeline entries
- Tag matching entries with rule name and ATT&CK TTP
- Aggregate results into detection summary for reports
- Support custom Sigma rules for organization-specific detections

### 7.2 YARA Rules Integration

**YARA capabilities relevant to Issen:**
- Malware detection in filesystem images (scan mounted E01/raw images)
- IOC detection: file names, registry keys, network artifacts
- Memory dump analysis
- File type classification
- Pattern matching across forensic images

**Reference implementation: THOR APT Scanner**
- 30,000+ YARA signatures + 4,000 Sigma rules + anomaly detection rules + IOCs
- Scans live systems, disk images, EVTX files, memory dumps, registry hives
- This is the gold standard for combined Sigma+YARA forensic scanning

**Reference implementation: MalChela** (Rust-based)
- Combines YARA scanning, file analysis, hash generation
- String extraction with MITRE ATT&CK mapping
- VirusTotal and Malware Bazaar API integration
- NSRL database queries for known-good filtering
- Written in Rust — directly relevant architecture reference for Issen

### 7.3 Custom Rule Engine

Issen should support a layered detection approach:

```
Layer 1: Sigma rules (log/event-based detection)
Layer 2: YARA rules (file/memory pattern matching)
Layer 3: Custom correlation rules (cross-artifact patterns)
Layer 4: ML-based anomaly detection (behavioral baselines)
Layer 5: LLM-assisted analysis (natural language pattern description)
```

---

## 8. Recommended Architecture

### 8.1 Intelligence Layer Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Issen Intelligence Layer                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │  LLM Router  │  │  RAG Engine  │  │  Detection Engine        │  │
│  │              │  │              │  │                          │  │
│  │ Task Router  │  │ Case RAG     │  │ Sigma Rule Evaluator     │  │
│  │ Model Pool   │  │ Knowledge RAG│  │ YARA Scanner             │  │
│  │ Fallback     │  │ Hybrid Search│  │ Correlation Rules        │  │
│  │ Chain        │  │ Reranker     │  │ Anomaly Detector         │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────────┘  │
│         │                 │                      │                  │
│  ┌──────┴─────────────────┴──────────────────────┴───────────────┐  │
│  │                    Enrichment Pipeline                         │  │
│  │                                                               │  │
│  │  IOC Extractor → TI Lookup → ATT&CK Mapper → Risk Scorer     │  │
│  │  (MISP, OpenCTI, VirusTotal, AlienVault OTX, local cache)     │  │
│  └──────────────────────────┬────────────────────────────────────┘  │
│                             │                                       │
│  ┌──────────────────────────┴────────────────────────────────────┐  │
│  │                    Knowledge Store                             │  │
│  │                                                               │  │
│  │  Vector DB (Qdrant)  │  Knowledge Graph  │  Case Database     │  │
│  │  - Artifact embeddings│  - Entity relations│  - Evidence store │  │
│  │  - Incident patterns │  - ATT&CK mapping │  - Report versions │  │
│  │  - Report templates  │  - IOC enrichment │  - Audit trail     │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                    Media Analysis Pipeline                     │  │
│  │                                                               │  │
│  │  Perceptual Hashing  │  EXIF Extraction  │  OCR Engine        │  │
│  │  (dHash + pHash)     │  (kamadak-exif)   │  (Tesseract)       │  │
│  │  Image grouping      │  Provenance chain │  Screenshot text   │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                    Report Generation Engine                    │  │
│  │                                                               │  │
│  │  Template Engine  │  Narrative Generator  │  HITL Workflow     │  │
│  │  (per engagement  │  (grounded LLM with   │  (approval gates, │  │
│  │   type)           │   citation tracking)  │   audit trail)    │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  LLM Backend: Ollama (local) │ OpenAI-compatible API (cloud opt.)  │
│  Vector DB: Qdrant (embedded) │ Graph: Neo4j or custom in-memory   │
│  Deployment: Air-gapped capable │ Model format: GGUF (quantized)   │
└─────────────────────────────────────────────────────────────────────┘
```

### 8.2 Key Design Principles

1. **Local-first**: Every AI feature must work without internet connectivity
2. **Grounded generation**: Every LLM output must cite specific evidence artifacts
3. **Human-in-the-loop**: No AI output reaches the final report without examiner approval
4. **Pluggable backends**: Support multiple LLM providers (Ollama, llama.cpp, OpenAI API, Anthropic API)
5. **Graceful degradation**: Platform works fully without AI features; AI enhances but is not required
6. **Audit everything**: Full provenance chain for every AI-generated content
7. **Deterministic fallback**: When AI fails or confidence is low, fall back to structured data presentation

### 8.3 Rust Crate Ecosystem

| Capability | Crate | Notes |
|-----------|-------|-------|
| HTTP client (LLM API) | `reqwest` | Async, OpenAI-compatible API calls to Ollama |
| Perceptual hashing | `image-hasher`, `phash` | dHash and pHash support |
| EXIF parsing | `kamadak-exif` | Pure Rust EXIF reader |
| OCR | `tesseract` (bindings) | Requires Tesseract system install |
| Vector search | `qdrant-client` | Rust client for Qdrant |
| Embeddings (local) | `candle` / `ort` | Run ONNX embedding models locally |
| YARA | `yara-x` (by VirusTotal) | Pure Rust YARA engine |
| Sigma | Custom (already in `tl`) | Extend existing implementation |
| JSON/STIX parsing | `serde_json`, `stix2` | STIX 2.1 object handling |
| Graph operations | `petgraph` | In-memory graph data structure |
| Tokenization | `tokenizers` | HuggingFace tokenizer for chunking |

---

## 9. Implementation Roadmap

### Phase 1: Foundation (Months 1-3)
- [ ] LLM abstraction layer (Ollama backend, OpenAI-compatible API)
- [ ] Basic report template engine with LLM-assisted fill
- [ ] IOC extraction from parsed artifacts
- [ ] Sigma rule evaluation (extend existing `tl` capability)
- [ ] Perceptual hashing for image grouping (dHash + pHash)

### Phase 2: Enrichment (Months 4-6)
- [ ] TI platform integration (VirusTotal API, MISP export import)
- [ ] MITRE ATT&CK automatic mapping from artifacts
- [ ] YARA scanning integration (yara-x crate)
- [ ] EXIF metadata extraction and provenance chain
- [ ] OCR for screenshots (Tesseract bindings)

### Phase 3: Intelligence (Months 7-9)
- [ ] Vector database integration (Qdrant embedded)
- [ ] Case-specific RAG pipeline
- [ ] Cross-artifact correlation engine
- [ ] Temporal anomaly detection (density analysis, inter-arrival time)
- [ ] Knowledge graph for entity relationships

### Phase 4: Advanced (Months 10-12)
- [ ] Model routing (task-based model selection)
- [ ] Knowledge-base RAG (cross-case pattern matching)
- [ ] Advanced narrative generation with HITL workflow
- [ ] Infostealer log parser plugins
- [ ] DINOHash integration for robust image matching
- [ ] Fine-tuned forensic model (ForensicLLM-style)

---

## 10. Sources

### AI-Assisted Forensic Report Generation
- [ForensicLLM: A Local Large Language Model for Digital Forensics (DFRWS EU 2025)](https://dfrws.org/presentation/forensicllm-a-local-large-language-model-for-digital-forensics/)
- [ForensicLLM Paper (PDF)](https://dfrws.org/wp-content/uploads/2025/03/ForensicLLM-A-local-large-language-mod_2025_Forensic-Science-International-.pdf)
- [Large Language Models in Digital Forensics: Capabilities, Challenges and Future Directions (March 2026)](https://www.sciencedirect.com/science/article/pii/S2666281725001830)
- [LLM-Assisted Digital Forensics: Best Paper at EAI ICDF2C 2025](https://eai.eu/blog/llm-assisted-digital-forensics-eai-icdf2c-2025/)
- [Digital Forensics in the Age of Large Language Models](https://arxiv.org/html/2504.02963v1)
- [ForensicsData: A Digital Forensics Dataset for Large Language Models](https://arxiv.org/pdf/2509.05331)
- [LangurTrace: Forensic Analysis of Local LLM Applications](https://www.sciencedirect.com/science/article/pii/S2666281725001271)

### Hallucination Prevention & Legal Considerations
- [A Legal Practitioner's Guide to AI & Hallucinations (NCSC)](https://www.ncsc.org/resources-courts/legal-practitioners-guide-ai-hallucinations)
- [Four Strategies for Legal Professionals to Reduce AI Hallucinations (ABA)](https://www.americanbar.org/groups/law_practice/resources/law-practice-today/2025/october-2025/reduce-ai-hallucinations/)
- [AI on Trial: Legal Models Hallucinate in 1 out of 6 or More (Stanford HAI)](https://hai.stanford.edu/news/ai-trial-legal-models-hallucinate-1-out-6-or-more-benchmarking-queries)
- [AI Hallucination Cases Database (1,093 documented cases)](https://www.damiencharlotin.com/hallucinations/)
- [Understanding the Risks of AI-Generated Evidence in Litigation](https://www.revealdata.com/blog/understanding-the-risks-of-ai-generated-evidence-in-litigation)
- [AI, Liability, and Hallucinations (Stanford Law)](https://law.stanford.edu/stanford-legal/ai-liability-and-hallucinations-in-a-changing-tech-and-law-environment/)

### Human-in-the-Loop Patterns
- [Trustworthy AI Agents: Human-in-the-Loop Governance (Sakura Sky)](https://www.sakurasky.com/blog/missing-primitives-for-trustworthy-ai-part-16/)
- [Human-in-the-Loop Review Workflows for LLM Applications (Comet)](https://www.comet.com/site/blog/human-in-the-loop/)
- [Enabling Regulatory-Grade Human in the Loop Workflows (John Snow Labs)](https://www.johnsnowlabs.com/enabling-regulatory-grade-human-in-the-loop-workflows-with-the-generative-ai-lab/)
- [Human-in-the-Loop in Agentic Workflows (Orkes)](https://orkes.io/blog/human-in-the-loop/)

### MITRE ATT&CK & IOC Extraction
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Focus Investigations With MITRE ATT&CK Insights (Forensic Focus)](https://www.forensicfocus.com/news/focus-investigations-with-mitre-attck-insights/)
- [Forensic Detection of MITRE ATT&CK Techniques](https://cloudyforensics.medium.com/forensic-detection-of-mitre-att-ck-techniques-83940f3b86ec)
- [MITRE ATT&CK: State of the Art and Way Forward (ACM Computing Surveys)](https://dl.acm.org/doi/10.1145/3687300)
- [ATT&CK Data & Tools](https://attack.mitre.org/resources/attack-data-and-tools/)

### Threat Intelligence Platforms
- [MISP vs. OpenCTI: Updated 2025 Guide (Cosive)](https://www.cosive.com/misp-vs-opencti)
- [OpenCTI vs MISP Threat Intelligence (RootSwarm)](https://rootswarm.com/2025/02/opencti-vs-misp-threat-intelligence/)
- [MISP Project](https://www.misp-project.org/)
- [OpenCTI Platform (GitHub)](https://github.com/OpenCTI-Platform/opencti)
- [Leveraging OpenCTI: An MSSP's Journey (Filigran)](https://filigran.io/mssps-journey-through-cti-maturation/)

### Infostealer Ecosystem
- [Infostealer Malware Surges: Stolen Logs Up 670% on Russian Market (Infosecurity Magazine)](https://www.infosecurity-magazine.com/news/infostealer-malware-stolen-logs/)
- [Overview of the Russian-speaking Infostealer Ecosystem (Sekoia)](https://blog.sekoia.io/overview-of-the-russian-speaking-infostealer-ecosystem-the-logs/)
- [The Growing Threat from Infostealers (Secureworks)](https://www.secureworks.com/research/the-growing-threat-from-infostealers)
- [Stealer Logs & Corporate Access (Flare)](https://flare.io/learn/resources/blog/threat-spotlight-stealer-logs-corporate-access/)
- [The Infostealer Pipeline (ReliaQuest)](https://reliaquest.com/blog/infostealer-pipeline-stolen-credential-attacks-russian-marketplace/)

### RAG & Embeddings
- [RAG Explained: Understanding Embeddings, Similarity, and Retrieval](https://towardsdatascience.com/rag-explained-understanding-embeddings-similarity-and-retrieval/)
- [Knowledge Graph vs. Vector Database for RAG (Meilisearch)](https://www.meilisearch.com/blog/knowledge-graph-vs-vector-database-for-rag)
- [Beyond Vector Search: RAG Without Embeddings (DigitalOcean)](https://www.digitalocean.com/community/tutorials/beyond-vector-databases-rag-without-embeddings)

### Anomaly Detection & Timeline Analysis
- [Anomaly Detection in a Forensic Timeline with Deep Autoencoders (ScienceDirect)](https://www.sciencedirect.com/science/article/abs/pii/S2214212621002076)
- [Graph Clustering and Anomaly Detection of Access Control Log (ScienceDirect)](https://www.sciencedirect.com/science/article/abs/pii/S1742287617301433)
- [SoK: Timeline-Based Event Reconstruction for Digital Forensics (2025)](https://www.sciencedirect.com/science/article/pii/S266628172500071X)
- [Digital Forensic Framework for Automated User Activity Reconstruction (SigDiff)](https://link.springer.com/chapter/10.1007/978-3-642-38033-4_19)

### Perceptual Hashing & Image Analysis
- [Effective Near-Duplicate Image Detection Using Perceptual Hashing and Deep Learning (2025)](https://www.sciencedirect.com/science/article/abs/pii/S0306457325000287)
- [pHash in Rust](https://ssojet.com/hashing/phash-in-rust)
- [dHash in Rust](https://compile7.org/hashing/how-to-use-dhash-in-rust/)
- [pHash.org](https://www.phash.org/)
- [Perceptual Hashing (Wikipedia)](https://en.wikipedia.org/wiki/Perceptual_hashing)

### OCR
- [Building a Rust-Powered OCR Tool (Medium)](https://medium.com/@siddheshmhatrecodes1808/building-a-rust-powered-ocr-tool-for-image-text-extraction-and-link-detection-504bd705d76e)
- [ocrs: Rust OCR Library (GitHub)](https://github.com/robertknight/ocrs)
- [Tesseract OCR Engine (GitHub)](https://github.com/tesseract-ocr/tesseract)
- [OCR Crates on crates.io](https://crates.io/keywords/ocr)

### Sigma & YARA
- [SigmaHQ Repository (GitHub)](https://github.com/SigmaHQ/sigma)
- [Sigma Rules in Timesketch (HackMag)](https://hackmag.com/security/sigma-timesketch)
- [YARA Rules: A Complete 2025 Guide (Picus Security)](https://www.picussecurity.com/resource/glossary/what-is-a-yara-rule)
- [THOR APT Scanner (Nextron Systems)](https://www.nextron-systems.com/thor/)
- [MalChela: Rust-Based Malware Analysis Toolkit](https://bakerstreetforensics.com/category/yara/)

### Knowledge Graphs & Ontologies
- [Cybersecurity Knowledge Graphs (Springer)](https://link.springer.com/article/10.1007/s10115-023-01860-3)
- [CyberKG: Constructing a Cybersecurity Knowledge Graph (MDPI 2025)](https://www.mdpi.com/2227-9709/12/3/100)
- [Beyond STIX: Next-Level Cyber-Threat Intelligence (AllegroGraph)](https://allegrograph.com/beyond-stix-next-level-cyber-threat-intelligence/)
- [MITRE D3FEND Knowledge Graph (PDF)](https://d3fend.mitre.org/resources/D3FEND.pdf)

### Local LLM Deployment
- [Local LLM Deployment: Privacy-First AI Guide (DigitalApplied)](https://www.digitalapplied.com/blog/local-llm-deployment-privacy-guide-2025)
- [Using Local LLMs for Criminal Intelligence Report Generation (Medium)](https://alessandro-negro.medium.com/using-local-deployment-of-open-source-llms-for-criminal-intelligence-repoissen-generation-ddb8db944620)
- [Self-hosted Llama Deployments for Regulated Industries (Meta)](https://www.llama.com/docs/deployment/regulated-industry-self-hosting/)
- [Run LLMs Locally with Ollama (Cohorte)](https://www.cohorte.co/blog/run-llms-locally-with-ollama-privacy-first-ai-for-developers-in-2025)
- [Self-Hosted LLM Guide: Setup, Tools & Cost Comparison 2026 (PremAI)](https://blog.premai.io/self-hosted-llm-guide-setup-tools-cost-comparison-2026/)

### Model Routing
- [Multi-Model Routing: Choosing the Best LLM per Task (DasRoot, March 2026)](https://dasroot.net/posts/2026/03/multi-model-routing-llm-selection/)
- [LLM Cost Optimization and Multi-Model Routing (Atlosz)](https://atlosz.hu/en/blog/llm-koltsegoptimalizalas-routing-strategia/)
- [LLM Routing for Quality, Low-Cost Responses (IBM Research)](https://research.ibm.com/blog/LLM-routers)
- [Task-Based LLM Routing (Portkey)](https://portkey.ai/blog/task-based-llm-routing/)
- [Building an LLM Router (Anyscale)](https://www.anyscale.com/blog/building-an-llm-router-for-high-quality-and-cost-effective-responses)
