# Issen: User Journey Maps

> **Parent**: [../NORTHSTAR_EXTRACT.md](../NORTHSTAR_EXTRACT.md)
> **Created**: 2026-03-20
> **Status**: Draft
> **Generation Step**: 5a of 13 --- Requires `northstar.personas[]`, `brand.voice`
> **Principle Alignment**: Clarity (map user journeys to understand context and emotion)

Visual journey maps with emotional states for core user flows.

## Document Purpose

This document maps the critical user journeys through Issen, anchored to the North Star Metric: **Time-to-Attorney-Ready Report (TARR) < 4 hours**. Each journey traces the examiner's path from evidence intake through attorney-ready deliverable, identifying emotional states, friction points, and design opportunities that directly reduce TARR.

Issen is a CLI-first forensic triage platform (with TUI via ratatui and a future Tauri GUI). These journeys reflect a terminal-native workflow, not a browser-based SaaS experience. The primary interaction model is command invocation, pipeline composition, and TUI-based review --- not point-and-click forms.

**Cross-references:**
- Personas: [NORTHSTAR.md](../NORTHSTAR.md) Section 3
- Brand voice: [BRAND_GUIDELINES.md](../BRAND_GUIDELINES.md) Section 4
- Competitive gaps: [COMPETITIVE_LANDSCAPE.md](../COMPETITIVE_LANDSCAPE.md) Section 2
- Design axioms: [NORTHSTAR_EXTRACT.md](../NORTHSTAR_EXTRACT.md) Section 1

---

## 1. Evidence Intake to Attorney-Ready Report (The Core TARR Journey)

> **Persona**: Sarah Chen --- Solo IR Practitioner
> **Trigger**: Receives KAPE collection or E01 image from client attorney
> **Success**: Attorney reviews report without calling Sarah back
> **TARR Target**: < 4 hours (baseline: ~16 hours manual)

### 1.1 Journey Overview

```
+-----------------------------------------------------------------------------+
|                    EVIDENCE TO ATTORNEY-READY REPORT                         |
+-----------------------------------------------------------------------------+
|                                                                              |
|  INGEST           PARSE            REVIEW           REPORT          DELIVER  |
|     |                |                |                |                |    |
|     v                v                v                v                v    |
|  +-------+      +---------+     +---------+      +---------+     +-------+  |
|  | KAPE/ |----->| Unified |---->| Filter/ |----->| Generate|---->| Send  |  |
|  | E01   |      | Timeline|     | Bookmark|      | HTML+PDF|     | Atty  |  |
|  +-------+      +---------+     +---------+      +---------+     +-------+  |
|                                                                              |
|  EMOTION:        EMOTION:         EMOTION:         EMOTION:       EMOTION:  |
|  Cautious/       Relief/          Focused/         Anticipation/  Confident/|
|  Hopeful         Impressed        Analytical       Excited        Done      |
|                                                                              |
|  TIME: ~2 min    TIME: ~8 min     TIME: ~90 min    TIME: ~30 min  TIME: ~5m|
|                                                                              |
+-----------------------------------------------------------------------------+
  Total TARR Target: < 4 hours (including examiner analysis and narrative review)
```

### 1.2 Detailed Journey Map

| Phase | User Action | Emotional State | System Response | Friction Points | Mitigation |
|-------|-------------|-----------------|-----------------|-----------------|------------|
| **Ingest** | `rt ingest ./kape-output/` or `rt ingest evidence.E01` | Cautious, hopeful --- "Will this tool actually handle my collection?" | Auto-detects source type (KAPE, Velociraptor, E01). Progress bar shows files discovered. Prints summary: "Ingested 47,832 artifacts from KAPE collection (12.3 GB)" | Unsupported collection format; unclear what was ingested | Clear error messages naming the format; `--dry-run` flag to preview without committing; structured ingest summary |
| **Parse** | Waits; watches TUI progress panel | Relief building --- "It's actually parsing all of this automatically" | Parallel parser execution with per-artifact-type progress bars. Shows: `[Registry] 12,847/12,847 done [Prefetch] 1,234/1,234 done [EventLog] 33,751/33,751 done`. Unified timeline materializes in real-time | Parser failure on corrupted artifact; extremely large evidence sets causing slowness | Per-parser error isolation (one failure does not halt others); streaming results so timeline is browsable before parsing completes; `rt status` shows parser health |
| **Timeline Review** | Opens TUI: `rt timeline` or auto-launches after parse | Focused, analytical --- in flow state | Full-screen TUI with unified timeline. Faceted filtering by artifact type, time range, keyword. Density heatmap shows activity clusters. Keyboard-driven navigation | Information overload (50K+ events); finding the needle | Smart density view surfaces high-activity periods; faceted filters reduce noise; bookmarking (`b` key) to mark findings; scoped timeframes with `[` and `]` keys |
| **Bookmark Findings** | Presses `b` on key events, adds notes via `n` | Building confidence --- constructing the narrative mentally | Bookmarked events highlighted in amber. Running count in status bar: "7 findings bookmarked". Notes attached to timeline entries | Forgetting to bookmark; losing context of why something matters | Bookmark panel (`F2`) shows all findings with notes; export bookmarks as standalone list; undo support |
| **Generate Report** | `rt report --format html,docx --findings bookmarked` | Anticipation --- "This is the part that usually takes me two days" | Generates interactive HTML report (expandable timeline, filterable evidence, linked artifacts) AND polished Word/PDF with narrative sections, Bates-ready numbering, examiner methodology section. Progress: "Generating narrative... Formatting exhibits... Writing report" | Report does not match attorney expectations; missing context | Template system with firm-specific customization; `--template` flag; preview in TUI before writing; report includes "How to Read This Report" section for attorneys |
| **Review Output** | Opens HTML report in browser; opens Word doc for review | Excited, then validating --- checking quality | HTML report is self-contained (single file, no server). Word report has table of contents, executive summary, technical findings, methodology, chain of custody notes. Both reference the same evidence with consistent numbering | Narrative phrasing needs adjustment; missing an artifact | `rt report --edit` opens narrative sections for tweaking without regenerating everything; `rt report --append` adds specific findings |
| **Deliver** | Emails/uploads HTML + Word to attorney | Confident --- "This is solid work" | Reports include examiner contact info, case metadata, report generation timestamp, tool version for reproducibility | Attorney asks follow-up questions requiring re-examination | See Journey 3: Attorney Follow-Up. Report includes section anchors so attorney can reference specific findings |

### 1.3 Emotional Arc Visualization

```
CONFIDENCE
    ^
    |                                                          *---* DELIVER
    |                                                         /     (confident)
    |                                            *---*---*   /
    |                                           / REPORT GEN
    |                                          /  (anticipation)
    |                         *---*---*---*   /
    |                        / TIMELINE     */
    |                       /  REVIEW
    |                      /   (focused, in flow)
    |           *---*     /
    |          / PARSE   /
    |    *    / (relief)/
    |   / \  /         /
    |  / INGEST       * (brief anxiety: "is the report good enough?")
    | / (cautious)
    |/
----+-----------------------------------------------------------------> TIME
    |   2 min    8 min       ~90 min          ~30 min        5 min
    v
ANXIETY
```

**Critical Moments:**
1. **Ingest acceptance**: Must immediately confirm "I understand your evidence format" --- first trust moment
2. **Parse completion**: The "wow" moment where 16 hours of manual artifact extraction happens in minutes
3. **Report generation**: Highest emotional stakes --- this is the part that usually takes days
4. **Attorney acceptance**: Delayed gratification --- Sarah finds out later that the attorney did not call back with questions

### 1.4 TARR Breakdown by Phase

| Phase | Target Time | Manual Baseline | Reduction |
|-------|-------------|-----------------|-----------|
| Ingest | 2 minutes | 30 minutes (manual file organization) | 93% |
| Parse to Timeline | 8 minutes | 4-6 hours (multiple tools, manual correlation) | 97% |
| Timeline Review + Bookmarking | 90 minutes | 2-3 hours (same, but with better tools) | 50% |
| Report Generation | 30 minutes | 6-8 hours (manual Word writing) | 93% |
| Review + Deliver | 5 minutes | 30 minutes | 83% |
| **Total** | **~2.5 hours** | **~16 hours** | **84%** |

---

## 2. Multi-Source Evidence Fusion Journey

> **Persona**: Sarah Chen / Marcus Webb
> **Trigger**: Case involves multiple evidence sources (disk image + endpoint collection + cloud logs)
> **Success**: Single unified timeline across all sources with cross-source correlation
> **TARR Impact**: Eliminates manual evidence merging (saves 2-4 hours per multi-source case)

### 2.1 Journey Overview

```
+-----------------------------------------------------------------------------+
|                      MULTI-SOURCE FUSION JOURNEY                             |
+-----------------------------------------------------------------------------+
|                                                                              |
|  SOURCE A         SOURCE B         SOURCE C         FUSED VIEW              |
|  (E01)            (Velociraptor)   (Cloud logs)     (VirtualFS)             |
|     |                |                |                |                     |
|     v                v                v                v                     |
|  +-------+      +---------+     +---------+      +----------+              |
|  |Ingest |      | Ingest  |     | Ingest  |      | Unified  |              |
|  |disk   |----->| endpoint|---->| cloud   |----->| Timeline |              |
|  |image  |      | collect.|     | export  |      | + Correl.|              |
|  +-------+      +---------+     +---------+      +----------+              |
|                                                                              |
|  EMOTION:        EMOTION:         EMOTION:         EMOTION:                 |
|  Organized/      Building/        Skeptical/       Impressed/               |
|  Methodical      Momentum         "Will it merge?" Powerful                 |
|                                                                              |
+-----------------------------------------------------------------------------+
```

### 2.2 Detailed Journey Map

| Phase | User Action | Emotional State | System Response | Friction Points | Mitigation |
|-------|-------------|-----------------|-----------------|-----------------|------------|
| **Create Case** | `rt case new "Incident-2026-0142"` | Organized, planning ahead | Case workspace created with metadata (client, date range, custodians). All subsequent commands scoped to case | Unclear case structure | `rt case new --interactive` walks through setup; sensible defaults |
| **Ingest Source A** | `rt ingest --source disk ./image.E01` | Methodical --- starting the assembly | Labels source, begins parsing. Shows: "Source A (disk): 23,441 artifacts parsed" | Large E01 takes time | Background processing with `--background`; notification on completion; partial results available immediately |
| **Ingest Source B** | `rt ingest --source endpoint ./velociraptor-collection/` | Building momentum --- "This is coming together" | Adds to existing case. Cross-references against Source A automatically. Shows: "Source B (endpoint): 8,123 artifacts. 342 correlated with Source A" | Different artifact schemas from different collectors | VirtualFilesystem normalizes formats; correlation engine identifies shared artifacts by hash, timestamp, path |
| **Ingest Source C** | `rt ingest --source cloud ./azure-signin-logs.json` | Skeptical turning hopeful --- "Will cloud logs actually merge with disk artifacts?" | Cloud log parser normalizes timestamps to case timezone. Shows: "Source C (cloud): 5,891 events. 87 correlated with Sources A+B (login events match logon artifacts)" | Timezone mismatches; different identifier formats (UPN vs SID vs hostname) | Automatic timezone normalization; entity resolution across sources (maps UPN to SID to hostname); correlation confidence scores |
| **Review Fused Timeline** | `rt timeline --all-sources` | Impressed, powerful --- "I can see the whole picture" | Unified timeline with source-colored indicators. Events from all three sources interleaved chronologically. Correlation links shown as connected entries. Filter by source, artifact type, entity | Overwhelming volume; distinguishing sources | Color-coded source indicators in TUI; `--source disk` to filter; correlation panel shows related events across sources; density heatmap reveals activity bursts |
| **Cross-Source Analysis** | Navigates to a suspicious event, presses `x` for cross-source view | Deep analysis mode --- connecting dots | Shows all events from all sources within a configurable time window around the selected event. Highlights causal chains (e.g., cloud login at 14:01 -> RDP logon artifact at 14:02 -> file creation at 14:03) | False correlations from coincidental timing | Correlation confidence scores; examiner can dismiss false links; manual correlation mode for edge cases |
| **Generate Fused Report** | `rt report --format html,docx --all-sources` | Confident --- evidence tells a complete story | Report includes source attribution for every finding. Cross-source correlation section shows how evidence from different sources corroborates the narrative. Chain of custody documented per source | Attorney confused by multi-source references | Report "Evidence Source Summary" section explains each source; consistent Bates-style numbering across sources |

### 2.3 Multi-Source Efficiency Curve

```
ANALYSIS POWER
    ^
    |                                              *------* 3 SOURCES
    |                                             / (full picture)
    |                                            /
    |                         *---------*-------*
    |                        / 2 SOURCES (cross-correlation unlocked)
    |                       /
    |           *----------*
    |          / 1 SOURCE (baseline analysis)
    |         /
    |--------*
    |
----+-----------------------------------------------------------------> SOURCES
    |        1              2                    3
```

Each additional source provides more than additive value: cross-source correlation reveals patterns invisible in any single source.

---

## 3. Attorney Follow-Up Journey (Iterative Reporting)

> **Persona**: Sarah Chen (responding to attorney), Diana Reyes (reformatting for court)
> **Trigger**: Attorney asks a targeted question about existing case
> **Success**: Targeted mini-report delivered in minutes, not hours
> **TARR Impact**: Reduces follow-up turnaround from 2-4 hours to 10-15 minutes

### 3.1 Journey Overview

```
+-----------------------------------------------------------------------------+
|                      ATTORNEY FOLLOW-UP JOURNEY                              |
+-----------------------------------------------------------------------------+
|                                                                              |
|  REQUEST          OPEN CASE       FILTER           MINI-REPORT    DELIVER   |
|     |                |                |                |             |       |
|     v                v                v                v             v       |
|  +--------+     +---------+     +---------+      +---------+   +--------+  |
|  |Attorney|---->|  Resume |---->|  Scoped |----->| Targeted|-->|  Send  |  |
|  |  email |     |  case   |     | timeline|      |  report |   | report |  |
|  +--------+     +---------+     +---------+      +---------+   +--------+  |
|                                                                              |
|  EMOTION:        EMOTION:         EMOTION:         EMOTION:     EMOTION:    |
|  Interrupted/    Oriented/        Precise/         Satisfied/   Professional|
|  Pressured       Confident        Efficient        Fast         /Reliable   |
|                                                                              |
|  TIME: 0 min     TIME: ~1 min     TIME: ~5 min     TIME: ~3 min TIME: ~1m  |
|                                                                              |
+-----------------------------------------------------------------------------+
  Total: ~10 minutes (baseline: 2-4 hours)
```

### 3.2 Detailed Journey Map

| Phase | User Action | Emotional State | System Response | Friction Points | Mitigation |
|-------|-------------|-----------------|-----------------|-----------------|------------|
| **Request Arrives** | Reads attorney email: "What happened between 2pm and 4pm on March 15?" | Interrupted --- was working on another case; mild pressure to respond quickly | N/A (external trigger) | Context switch cost; remembering case details | Case state fully preserved; no mental reconstruction needed |
| **Open Case** | `rt case open "Incident-2026-0142"` | Orienting --- quickly recalling context | Case loads with full state: last session's bookmarks, filters, notes. Status bar shows case summary. "Last opened 3 days ago. 7 bookmarks. 3 sources." | Forgetting which case; case name mismatch | `rt case list --recent` shows recent cases; fuzzy search on case names; case aliases |
| **Scoped Timeline** | `rt timeline --range "2026-03-15 14:00..16:00"` | Precise, efficient --- "I know exactly what the attorney needs" | Filtered timeline showing only events in the 2-hour window. Source-colored entries. Bookmark indicators for previously flagged items. Event count: "143 events in range" | Time range syntax; timezone confusion | Natural language time parsing ("March 15 2pm to 4pm"); timezone displayed in status bar; `--tz` override |
| **Quick Review** | Scans filtered timeline, bookmarks 3 new relevant events | Analytical but fast --- not deep-diving, just answering the question | Bookmarks added. Notes: "Attorney requested --- March 15 afternoon activity" | Over-analyzing; scope creep | Scoped view keeps focus narrow; `--findings new` shows only new bookmarks |
| **Generate Mini-Report** | `rt report --range "2026-03-15 14:00..16:00" --findings new --format html,docx --brief` | Satisfied --- "This took 5 minutes instead of 3 hours" | Generates focused mini-report covering only the requested window. Executive summary auto-generated. Includes only relevant evidence with the 3 new findings highlighted. References parent report for full context | Mini-report lacks context; attorney confused by partial view | Mini-report header: "Supplemental Report --- See [Parent Report] for full analysis"; consistent numbering with parent report |
| **Deliver** | Emails mini-report to attorney | Professional, reliable --- "I responded within 15 minutes" | Report metadata includes "Supplemental to Report #[X], generated [timestamp]" | Attorney wants changes to mini-report | `rt report --amend` for quick edits without regeneration |

### 3.3 Follow-Up Emotional Arc

```
CONFIDENCE
    ^
    |              *-------*-------*-------* DELIVER
    |             / (efficient, fast,        (professional)
    |            /   in control)
    |     *-----*
    |    / OPEN CASE
    |   /  (oriented quickly)
    |  /
    | * REQUEST
    |  (interrupted, pressured)
    |
----+-----------------------------------------------------------------> TIME
    |  0 min    1 min        5 min       8 min      10 min
```

**Key Design Insight**: The attorney follow-up journey depends entirely on case state preservation. If the examiner has to reconstruct the case from scratch, the time savings evaporate. Case persistence is a P0 requirement.

---

## 4. Plugin Development Journey (Community Contributor)

> **Persona**: Community Developer (forensic tool author, DFIR researcher)
> **Trigger**: Wants to add a parser for a new artifact type (e.g., a new browser's history database)
> **Success**: Parser accepted into community registry, used by other examiners
> **TARR Impact**: Indirect --- expands artifact coverage, reducing manual parsing for future cases

### 4.1 Journey Overview

```
+-----------------------------------------------------------------------------+
|                      PLUGIN DEVELOPMENT JOURNEY                              |
+-----------------------------------------------------------------------------+
|                                                                              |
|  DISCOVER         SCAFFOLD       IMPLEMENT        TEST           PUBLISH    |
|     |                |                |              |              |        |
|     v                v                v              v              v        |
|  +--------+     +---------+     +---------+     +--------+    +--------+   |
|  | Browse |---->| rt plug |---->| Impl    |---->| rt plug|    | Submit |   |
|  | registry|    | new     |     | Parser  |     | test   |--->| to     |   |
|  +--------+     +---------+     | trait   |     +--------+    | registry|  |
|                                 +---------+                    +--------+   |
|                                                                              |
|  EMOTION:        EMOTION:         EMOTION:        EMOTION:     EMOTION:     |
|  Curious/        Empowered/       Focused/        Anxious/     Proud/       |
|  Evaluating      Guided           Building        Validating   Contributing |
|                                                                              |
+-----------------------------------------------------------------------------+
```

### 4.2 Detailed Journey Map

| Phase | User Action | Emotional State | System Response | Friction Points | Mitigation |
|-------|-------------|-----------------|-----------------|-----------------|------------|
| **Discover** | Browses plugin registry; reads docs | Curious, evaluating --- "Can I contribute to this ecosystem?" | Registry website lists existing parsers, coverage gaps, "wanted" list. API docs for `ForensicParser` trait are clear and well-documented | Unclear contribution path; intimidating codebase | Standalone plugin crate; no need to fork main repo; "Getting Started" guide; "Wanted Parsers" list |
| **Scaffold** | `rt plugin new --name browser-brave --type parser` | Empowered --- "The tooling helps me get started" | Generates plugin project skeleton: `Cargo.toml` with correct dependencies, `src/lib.rs` implementing `ForensicParser` trait with TODO markers, sample test data directory, CI config | Rust unfamiliar to some DFIR developers; dependency issues | Scaffold includes extensive code comments; `ForensicParser` trait is minimal (3 required methods); example implementations linked; `rt plugin new --lang python` for Python FFI bridge (future) |
| **Implement** | Writes parser logic implementing `ForensicParser` trait | Focused, building --- standard development flow | Trait requires: `fn name()`, `fn can_parse(&self, path: &Path) -> bool`, `fn parse(&self, source: &dyn VirtualFile) -> Result<Vec<TimelineEntry>>`. Strong types guide implementation | Complex artifact formats; unclear output schema | `TimelineEntry` struct is well-documented; sample parsers serve as reference; `rt plugin validate-output` checks conformance |
| **Test** | `rt plugin test --sample-data ./brave-test-data/` | Anxious, then relieved --- "Do my outputs match expectations?" | Runs parser against sample data. Validates output schema. Compares against expected results if provided. Shows: "23 timeline entries parsed. Schema valid. 0 warnings." Generates coverage report | Test data creation; edge cases; cross-platform paths | `rt plugin generate-test-data` creates minimal test fixtures from real artifacts (with PII scrubbing); property-based test framework for edge cases |
| **Integration Test** | `rt plugin test --integration` | Validating --- "Does it work within the full pipeline?" | Ingests test data through full Issen pipeline. Verifies entries appear in timeline. Generates sample report section. Shows plugin in context | Plugin works in isolation but fails in pipeline | Integration test harness runs full ingest-parse-report cycle; clear error messages when pipeline contract violated |
| **Publish** | `rt plugin publish` | Proud, contributing --- "I've added something to the community" | Submits to community registry. Includes: parser metadata, test results, sample output, coverage claim. Appears in registry after review | Review delay; rejection without explanation | Automated pre-submission checks; clear acceptance criteria; reviewer feedback within 48 hours; "draft" publish for community testing before full acceptance |

### 4.3 Plugin Developer Efficiency Curve

```
DEVELOPMENT SPEED
    ^
    |                                    *---*---*---* EXPERIENCED
    |                               *---*             (knows patterns)
    |                          *---*
    |                     *---*
    |                *---*
    |           *---*
    |      *---*
    | *---* FIRST PLUGIN
    |       (learning curve)
----+-----------------------------------------------------------------> PLUGINS
    |     1    2    3    4    5    6    7    8    9   10
```

**Key Design Insight**: The `ForensicParser` trait must be minimal enough that a competent Rust developer can implement a basic parser in under 2 hours. Complexity belongs in the pipeline, not the plugin interface.

---

## 5. Persona-Specific Journey Variations

### 5.1 Sarah Chen --- Solo IR Practitioner (Primary)

| Journey | Behavior Difference | Why This Persona Differs | UX Accommodation |
|---------|---------------------|--------------------------|-------------------|
| **Core TARR** | Runs end-to-end alone; needs fastest possible path from evidence to deliverable | Solo practice means she is the analyst, report writer, and client manager. Every hour saved is an hour she can bill or reclaim | CLI pipeline composition: `rt ingest . && rt report --auto` for cases matching known patterns. Template library for common case types (ransomware, BEC, insider threat) |
| **Multi-Source** | Often receives evidence piecemeal as attorney gets court orders | Cannot wait for all evidence before starting; needs to add sources incrementally | Incremental ingestion: `rt ingest --append` adds new source to existing case and re-correlates without reprocessing existing sources |
| **Attorney Follow-Up** | This is her most frequent journey --- attorneys call constantly | Small firm attorneys ask many questions because they lack forensic literacy | "Attorney FAQ" report section generated automatically; common attorney questions pre-answered in deliverable; quick follow-up report with `--brief` flag |
| **Plugin Development** | Unlikely to develop plugins herself, but will request them | Time-constrained; community consumer, not contributor | Simple `rt plugin install` from registry; `rt plugin request` to submit feature requests for the community |

### 5.2 Marcus Webb --- Firm Forensic Examiner (Secondary)

| Journey | Behavior Difference | Why This Persona Differs | UX Accommodation |
|---------|---------------------|--------------------------|-------------------|
| **Core TARR** | Must conform to firm report templates; partner reviews everything before client delivery | Firm has established format standards; deviation risks partner rejection and rework | Firm-level template system: `rt config set template-dir /firm/templates/`; report metadata includes "Prepared by / Reviewed by" fields; diff view for partner review annotations |
| **Multi-Source** | Evidence handed to him pre-collected; always multi-source | Works cases assigned by partners; collection already done by IR team | Batch ingest: `rt ingest --manifest case-evidence.yml` reads a case manifest listing all sources and metadata; reduces setup to a single command |
| **Attorney Follow-Up** | Partner mediates attorney communication; Marcus generates what partner requests | Never talks to attorney directly; partner is the audience for his work product | "Internal Review" report variant with technical detail level appropriate for forensic partner (vs. attorney-facing which is narrative-focused) |
| **Plugin Development** | More likely contributor; has firm R&D time | Firm encourages tooling contributions for community reputation | Plugin authorship attribution in registry; firm badge support; contribution metrics for performance reviews |

### 5.3 Diana Reyes --- Litigation Support Analyst (Tertiary)

| Journey | Behavior Difference | Why This Persona Differs | UX Accommodation |
|---------|---------------------|--------------------------|-------------------|
| **Core TARR** | Receives output from forensic examiner; reformats for court submission | Her input is someone else's output; she is the forensic-to-legal translator | Couissen-ready export: `rt report --format court --bates-start "EX-0001"` generates Bates-numbered exhibits, exhibit index, testimony-ready summaries |
| **Multi-Source** | Needs to track chain of custody across all sources for court admissibility | Legal requirements for evidence provenance are strict; any gap is exploitable by opposing counsel | Chain of custody report section: automated source tracking, hash verification at every stage, examiner attestation fields |
| **Attorney Follow-Up** | Most frequent follow-up: "Generate exhibit for [specific event] with Bates number [X]" | Court filings require precise formatting, numbering, and cross-referencing | Single-event exhibit generation: `rt exhibit --event [ID] --bates "EX-0047"` produces couissen-ready single-page exhibit with metadata, hash, and chain of custody |
| **Plugin Development** | Will not develop plugins; will request legal output format plugins | Needs templates for specific court jurisdictions and filing requirements | Legal template marketplace; jurisdiction-specific formatting rules; `rt report --jurisdiction "SDNY"` applies local court formatting requirements |

---

## 6. Journey Metrics

### 6.1 Key Performance Indicators

| KPI | Journey Phase | Measurement | Target | Why It Matters |
|-----|---------------|-------------|--------|----------------|
| **Ingest-to-Timeline (ITL)** | Core TARR: Ingest + Parse | Time from `rt ingest` to navigable timeline | < 10 minutes (50GB evidence) | First value delivery; determines first impression |
| **Findings-to-Report (FTR)** | Core TARR: Review + Report | Time from first bookmark to completed report | < 2 hours | The "last 80%" that defines TARR |
| **Follow-Up Turnaround (FUT)** | Attorney Follow-Up | Time from attorney request to mini-report delivery | < 15 minutes | Repeat value; builds attorney trust and examiner reputation |
| **Report Acceptance Rate (RAR)** | Core TARR: Deliver | Percentage of reports accepted without substantive rework | > 80% first-pass | Measures actual attorney satisfaction, not just speed |
| **Multi-Source Fusion Time (MFT)** | Multi-Source: All | Additional time per source added to case | < 5 minutes per additional source | Multi-source should not multiply TARR linearly |
| **Plugin Time-to-First-Parse (PTFP)** | Plugin Dev: Implement + Test | Time from scaffold to first successful test run | < 2 hours | Determines whether developers complete their first plugin |
| **Error Recovery Time (ERT)** | Error Recovery (all) | Time from error occurrence to productive work resumption | < 30 seconds | Errors should be speed bumps, not roadblocks |

### 6.2 Emotional Measurement

| Touchpoint | Measurement Method | Signal |
|------------|-------------------|--------|
| Post-first-report | In-CLI feedback prompt (optional) | "Did this report meet your quality bar?" --- initial TARR satisfaction |
| Post-ingest | Automatic timing metric | Ingest-to-Timeline latency logged per run; regression detection |
| Post-error | Error recovery tracking | Time-to-resolution logged; patterns surface UX improvements |
| 7-day follow-up | Email survey (opt-in) | Sustained value: "Has Issen changed your reporting workflow?" |
| 30-day milestone | Usage analytics (opt-in) | Power user development: report count, case count, plugin usage |
| Attorney feedback | Indirect via examiner | "Has your attorney called you back less about reports?" |

---

## 7. Error Recovery Journey

> **Principle**: Errors never blame the user. Errors preserve work. Errors explain what happened and what to do next.
> **Brand alignment**: Technically honest, quietly confident. If something went wrong, say what it was.

### 7.1 Journey Overview

```
+-----------------------------------------------------------------------------+
|                         ERROR RECOVERY JOURNEY                               |
+-----------------------------------------------------------------------------+
|                                                                              |
|  ERROR              INFORM           RECOVER          RESUME                |
|  OCCURS             USER             STATE            WORK                  |
|     |                 |                 |                |                   |
|     v                 v                 v                v                   |
|  +--------+      +---------+      +---------+      +---------+             |
|  | System |----->|  Clear  |----->|  Auto/  |----->| Continue|             |
|  | detects|      |  error  |      |  manual |      |  where  |             |
|  |  issue |      |  message|      |  fix    |      |  left   |             |
|  +--------+      +---------+      +---------+      |  off    |             |
|                                                     +---------+             |
|  EMOTION:         EMOTION:          EMOTION:         EMOTION:               |
|  Surprise/        Understanding/    Relieved/        Confident/             |
|  Frustration      Oriented          Recovering       Reassured              |
|                                                                              |
+-----------------------------------------------------------------------------+
```

### 7.2 Error Type Mapping

| Error Type | User Sees | Emotional Impact | Recovery Path | System Behavior |
|------------|-----------|------------------|---------------|-----------------|
| **Unsupported Evidence Format** | `Error: Unrecognized format in './data.xyz'. Supported: KAPE, Velociraptor, E01, raw. Run 'rt ingest --help formats' for details.` | Mild frustration --- "I need to check my input" | Clear list of supported formats; `--force-type` override for edge cases | No data loss; nothing ingested; case state unchanged |
| **Corrupted Artifact** | `Warning: Registry hive 'SYSTEM' appears truncated (expected 14MB, got 2MB). Parsing partial data. 847/~4000 entries recovered.` | Concern --- "Is my evidence damaged?" | Partial parsing continues; corrupted artifact flagged in report; `rt verify` for evidence integrity check | Parser isolates failure; other artifacts unaffected; partial results included with "[PARTIAL]" marker |
| **Parser Failure** | `Error: EventLog parser failed on 'Security.evtx': invalid record at offset 0x1A2F. Skipping file. Other parsers unaffected.` | Worry --- "Am I losing evidence?" | Skip + continue (default); `--strict` flag to halt on any error; `rt parse --retry` for transient failures | Error logged with full context for bug reporting; case state preserved; other parsers continue independently |
| **Disk Full** | `Error: Insufficient disk space. Need ~8GB for timeline database, have 2GB free. Case state saved.` | Panic --- "Did I lose my work?" | Clear space requirement stated; `--output-dir` to redirect to another volume; case state preserved, resume with `rt resume` | All work saved before halting; atomic operations prevent half-written state |
| **Timeout / Long Processing** | `Note: Large evidence set (127GB). Estimated completion: ~45 minutes. Progress: 23%. Press 'q' to background, 'Ctrl+C' to pause.` | Impatience --- "Is it stuck?" | Background processing; pause/resume; partial results available during processing | Streaming results: timeline is browsable while parsing continues; progress updates every 5 seconds |
| **Report Template Error** | `Error: Template 'firm-standard.toml' references field 'custodian_title' not found in case metadata. Add with 'rt case set custodian_title "..."'` | Annoyance --- "I just want the report" | Specific field name and command to fix; `--skip-missing` to generate with blanks; `--interactive` to fill in on the spot | Report generation paused, not failed; template error is fixable without re-running pipeline |
| **Plugin Compatibility** | `Warning: Plugin 'browser-brave' v0.2 targets Issen 0.8. You are running 0.9. May have compatibility issues. Run 'rt plugin update browser-brave' or use '--compat-mode'.` | Uncertainty --- "Should I trust this plugin?" | Update command provided; compatibility mode available; `rt plugin test` to verify locally before use | Plugin sandboxed; failures in plugin do not affect core parsers |

### 7.3 Error Recovery Emotional Design

**Principles:**
1. **Never blame the user.** "Unrecognized format" not "Invalid input."
2. **State what happened, not what went wrong.** "Parser recovered 847 of ~4000 entries" not "Parser failed."
3. **Always provide a next step.** Every error message includes a recovery command or suggestion.
4. **Preserve all work.** No error should cause data loss. Atomic operations, checkpointing, case state persistence.
5. **Be technically honest.** If data is partial, say so. If recovery is uncertain, say so. Examiners need to know what they can and cannot rely on for testimony.

---

## 7. Implementation Priorities

### 7.1 Critical Path Items

| Priority | Journey Element | Component | Status |
|----------|-----------------|-----------|--------|
| **P0** | Evidence ingest with format auto-detection | Core Engine: `rt ingest` | Planned |
| **P0** | Unified timeline with filtering and bookmarking | TUI: `rt timeline` | Planned |
| **P0** | Dual-format report generation (HTML + Word/PDF) | Report Engine: `rt report` | Planned |
| **P0** | Case state persistence and resume | Core Engine: `rt case` | Planned |
| **P0** | Error messages with recovery paths | All CLI commands | Planned |
| **P1** | Multi-source ingestion and correlation | Core Engine: VirtualFilesystem | Planned |
| **P1** | Scoped mini-report generation (attorney follow-up) | Report Engine: `--range`, `--brief` | Planned |
| **P1** | Firm template system | Report Engine: `--template` | Planned |
| **P2** | Plugin scaffold and test harness | Plugin SDK: `rt plugin` | Planned |
| **P2** | Community plugin registry | Infrastructure | Planned |
| **P2** | Couissen-ready exhibit generation (Bates numbering) | Report Engine: `rt exhibit` | Planned |
| **P3** | Python FFI bridge for plugin development | Plugin SDK | Planned |
| **P3** | Attorney FAQ auto-generation | Report Engine | Planned |

### 7.2 Accessibility Considerations per Journey

> **Full accessibility patterns**: See ACCESSIBILITY.md (to be generated in Phase 6) for comprehensive patterns and testing protocols.

| Journey Phase | Primary Concern | Design Consideration |
|---------------|-----------------|----------------------|
| **All phases** | TUI color contrast | Slate Blue (#475569) primary + Amber (#D97706) accent tested for WCAG AA contrast; `--no-color` flag; `NO_COLOR` env var respected |
| **All phases** | Screen reader compatibility | TUI outputs semantic text; `--plain` mode for screen reader users produces structured plaintext; all commands support `--json` for programmatic consumption |
| **Timeline review** | Keyboard navigation | Full keyboard-driven TUI (no mouse required); vim-style keybindings; customizable key mappings |
| **Processing wait** | Non-visual progress | Progress percentages logged to stderr; completion notifications via system bell or OS notification (`--notify`) |
| **Error recovery** | Clear error communication | Error messages are self-contained sentences (no codes without explanation); `--verbose` for technical detail; errors written to both stderr and log file |
| **Report output** | Document accessibility | Generated HTML reports include ARIA labels, semantic headings, alt text for timeline visualizations; Word reports use proper heading styles for screen reader navigation |
| **Dark mode** | Visual comfort during long sessions | TUI defaults to dark theme (terminal-native); HTML reports include dark mode CSS; unoccupied competitive space --- no forensic tool offers this |

---

## Validation Checklist

- [x] First-time user journey mapped with emotional states (Section 1: Core TARR Journey)
- [x] Returning user patterns identified (Section 3: Attorney Follow-Up; Section 5: Persona Variations)
- [x] Error recovery journey with 7 error types mapped (Section 7: Error Recovery)
- [x] Persona-specific journey variations for all 3 personas (Section 5)
- [x] Journey metrics with 7 KPIs defined (Section 6)
- [x] Implementation priorities mapped to journey elements (Section 7.1)
- [x] Accessibility considerations per journey phase (Section 7.2)
- [x] All journeys tied to TARR reduction (quantified in Section 1.4)
- [x] Brand voice alignment: direct, technically honest, outcome-oriented
- [x] Cross-references to NORTHSTAR.md, BRAND_GUIDELINES.md, COMPETITIVE_LANDSCAPE.md, NORTHSTAR_EXTRACT.md
