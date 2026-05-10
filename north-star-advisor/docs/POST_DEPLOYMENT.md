# Issen: Post-Deployment Operations

> **Tier**: 2 --- Operational Authority
> **Created**: 2026-03-20
> **Status**: Active
> **North Star**: TARR (Time-to-Attorney-Ready Report) < 4 hours
> **Context**: Desktop forensic application, solo founder, local-first architecture

---

## Document Purpose

This document defines the post-deployment operations framework for Issen --- a desktop forensic triage platform, not a cloud SaaS. Every operational practice is filtered through a single question: **Does this reduce TARR for our practitioners?**

Operations are designed for a solo founder running a bootstrapped, open-core desktop application. There are no servers to monitor, no on-call rotations, and no auto-scaling policies. Instead, this document covers: local metrics instrumentation, community feedback loops, model maintenance for local LLM infrastructure, incident response for software bugs and data integrity issues, forensic compliance validation, cost tracking for hardware and optional cloud resources, and iteration planning tied to the North Star.

**Cross-references**:
- `NORTHSTAR.md` --- North Star metric definition, input metrics, personas
- `ARCHITECTURE_BLUEPRINT.md` --- Agent topology, crate structure, technology stack
- `BRAND_GUIDELINES.md` --- Beliefs, kill list, voice
- `AGENT_PROMPTS.md` --- Per-agent specifications and success criteria
- `SECURITY_ARCHITECTURE.md` --- Threat model, supply chain security

---

## 1. Monitoring Dashboard

> **Adaptation**: "Dashboard" means the TUI-based real-time pipeline monitor built with ratatui, not a cloud observability platform. All metrics are stored in per-case DuckDB databases locally. No telemetry leaves the examiner's machine without explicit opt-in.

### 1.1 TARR Tracking Per Case

Every case processed by Issen records end-to-end TARR timing. The TUI dashboard displays a persistent top-center progress bar:

```
+---------------------------------------------------------------------+
|  TARR: Case #2026-0142                                              |
|  Elapsed: ██████████░░░░░░░░░░ 2h 47m   Budget: <4hr   Status: OK  |
|  Stage: Findings-to-Narrative (issen-intel)                            |
+---------------------------------------------------------------------+
```

**TARR decomposition per case**:

| Phase | Crate | Metric | Target | Instrumentation |
|-------|-------|--------|--------|-----------------|
| Evidence Ingestion | issen-pipeline | Ingest wall-clock time | < 2 min | `tracing` span: `pipeline.ingest` |
| Parsing (Layer 0-4) | issen-pipeline | Parse-to-Timeline Latency | < 10 min | `tracing` span per layer: `pipeline.layer.{0-4}` |
| Timeline Construction | issen-timeline | Merge + index time | < 60s for 10M events | `tracing` span: `timeline.merge` |
| Correlation | issen-correlation | Pattern detection wall-clock | < 5 min | `tracing` span: `correlation.detect` |
| Narrative Generation | issen-intel | Findings-to-Narrative Time | < 2 hr | `tracing` span: `intel.narrative` |
| Report Rendering | issen-report | Format generation time | < 30s per format | `tracing` span: `report.render.{html,docx,pdf}` |

**Storage**: Each case writes timing metrics to its DuckDB case database in a `_rt_metrics` table. Historical TARR data accumulates across cases in `~/.issen/metrics.duckdb` for trend analysis.

### 1.2 Pipeline Stage Timing

The TUI pipeline monitor panel shows real-time throughput for each active stage:

| Metric | Crate | Unit | Display |
|--------|-------|------|---------|
| Parse throughput | issen-pipeline | events/sec | Sparkline chart |
| Parser success rate | issen-pipeline | % per parser | Color-coded bar (green > 99%, yellow > 95%, red < 95%) |
| Layer 0-4 individual timing | issen-pipeline | seconds | Stacked bar per layer |
| DuckDB query latency | issen-timeline | ms P50/P95 | Numeric with trend arrow |
| Event count | issen-timeline | total events ingested | Counter |
| LLM response time | issen-intel | seconds per request | Rolling average |
| Grounding accuracy | issen-intel | % grounded vs hallucinated | Percentage bar |
| RAG retrieval quality | issen-intel | relevance score (0-1) | Numeric |
| Pattern detection rate | issen-correlation | patterns/case | Counter |
| Cross-artifact match count | issen-correlation | matches found | Counter |

### 1.3 Resource Monitoring

| Resource | Measurement | Alert Threshold | Action |
|----------|-------------|-----------------|--------|
| Process RSS memory | `sysinfo` crate | > 80% system RAM | Warn in TUI; suggest closing other applications |
| DuckDB memory usage | DuckDB `pragma memory_limit` | > 4 GB per case | Reduce query parallelism; warn user |
| Disk space (evidence) | `fs` checks | < 10 GB free | Block new case creation; warn user |
| Disk space (Ollama models) | `~/.ollama/models` | > 50 GB | Suggest pruning unused models |
| CPU utilization | `sysinfo` crate per-core | Sustained > 95% all cores | Informational (expected during parsing) |

### 1.4 Weekly Self-Review Protocol

As a solo founder, there is no team to review dashboards. Instead, Issen generates a weekly metrics digest automatically:

**Every Monday at first launch**:
1. Aggregate TARR across all cases processed in the past 7 days
2. Compare against target (< 4 hours) and trend (improving/stable/degrading)
3. Highlight any pipeline stage that consumed > 40% of total TARR
4. Flag any parser with success rate < 99%
5. Display in TUI as a dismissible summary panel
6. Write to `~/.issen/weekly-digest/{date}.json` for longitudinal tracking

**Monthly**: Export digest to markdown for inclusion in development log and ADR reviews.

---

## 2. Feedback Loops

> **Adaptation**: No in-app analytics dashboards, no A/B testing infrastructure. Feedback comes from the forensic practitioner community through direct channels. "Release channels" replace web experiments.

### 2.1 Direct Feedback Channels

| Channel | Frequency | Signal Type | TARR Relevance |
|---------|-----------|-------------|----------------|
| **GitHub Issues** | Continuous | Bug reports, feature requests, parser accuracy reports | Direct: parser bugs increase TARR; feature requests indicate workflow gaps |
| **GitHub Discussions** | Weekly | Workflow questions, use-case sharing, template requests | Indirect: reveals how practitioners actually use reports |
| **Community Discord** | Daily | Real-time troubleshooting, feature polling, beta feedback | Direct: fastest signal for blocking issues |
| **DFIR Conference Feedback** | Quarterly | In-person demos, practitioner interviews, competitive intelligence | Strategic: validates positioning, reveals unmet needs |
| **Direct User Interviews** | Monthly (3-5) | Structured interviews with Sarah/Marcus/Diana persona representatives | Direct: qualitative TARR measurement, report quality assessment |

### 2.2 Implicit Signals

| Signal | Collection Method | Opt-In | What It Reveals |
|--------|-------------------|--------|-----------------|
| Crash reports | `human-panic` crate with opt-in submission | Explicit opt-in per crash | Parser stability, edge cases in evidence formats |
| Usage telemetry | Aggregate, anonymized, local-only by default | Explicit opt-in in settings | Which parsers are used, average case size, TARR distribution |
| Report format preferences | Local metrics DB | Automatic (local only) | HTML vs DOCX vs PDF usage ratio, informs development priority |
| Command frequency | Local metrics DB | Automatic (local only) | Which CLI/TUI commands are used most, UX optimization signal |
| Parser error patterns | Structured error logs | Automatic (local only) | Which evidence formats cause failures, parser priority |

### 2.3 Feedback-to-Action Pipeline

```
Signal received (issue / crash / interview)
     |
     v
Triage: Does this affect TARR?
     |
     +-- Yes, directly --> Priority queue (fix within current sprint)
     |
     +-- Yes, indirectly --> Backlog with TARR-impact label
     |
     +-- No, but on-brand --> Backlog with "quality-of-life" label
     |
     +-- No, off-brand/kill-list --> Close with explanation referencing BRAND_GUIDELINES.md
```

### 2.4 Release Channels (Replaces A/B Testing)

| Channel | Audience | Update Cadence | Purpose |
|---------|----------|----------------|---------|
| **Nightly** | Developer, adventurous contributors | Daily | Rapid iteration, fuzz testing integration |
| **Beta** | Engaged community members (< 50) | Bi-weekly | Feature validation, TARR measurement on real cases |
| **Stable** | All users | Monthly | Proven improvements, regression-free releases |

**Rollout protocol**: Feature lands in nightly, soaks for 1 week with fuzz testing, promotes to beta with 2-week feedback window, promotes to stable after zero regressions confirmed.

---

## 3. Model Maintenance

> **Adaptation**: "Model maintenance" means managing local Ollama models, YARA-X detection rules, and Sigma rules --- not swapping cloud API endpoints. All inference runs locally. Optional cloud LLM is a fallback, not the default.

### 3.1 Ollama Model Updates

Issen uses a multi-model local-first routing strategy: 80% of LLM calls go to small models (7B-13B) for classification and extraction, 20% go to large models (70B+) for narrative drafting.

| Model Role | Current Default | Update Cadence | Evaluation Before Update |
|------------|----------------|----------------|--------------------------|
| Classification (small) | `mistral:7b` | Monthly check | Run ForensicLLM eval suite (see 3.2); must match or exceed current accuracy |
| Extraction (small) | `mistral:7b` | Monthly check | Structured output accuracy on 20 golden cases |
| Narrative (large) | `mixtral:8x7b` / `llama3:70b` | Quarterly check | Blind comparison: 5 reports generated with old vs new model, rated by examiner |
| Embedding | `nomic-embed-text` | Quarterly check | RAG retrieval quality on golden query set; cosine similarity threshold > 0.85 |

**Update procedure**:
1. `ollama pull {model}:latest` on development machine
2. Run ForensicLLM evaluation suite (Section 3.2)
3. Compare metrics against current baseline
4. If improvement confirmed: update `issen-intel` default config, document in ADR
5. If regression: pin to current version, file issue for investigation

**AI-free mode**: Issen must function without any LLM. All model-dependent features degrade gracefully: narrative generation falls back to template-based summaries, classification falls back to rule-based heuristics. AI-free mode is tested in CI on every commit.

### 3.2 ForensicLLM Evaluation Suite

The evaluation suite validates LLM performance on forensic-specific tasks:

| Test Category | Golden Cases | Pass Criteria | Frequency |
|---------------|-------------|---------------|-----------|
| Timeline narrative accuracy | 20 cases with known-good narratives | ROUGE-L > 0.6 against reference | Before any model change |
| Finding extraction precision | 30 annotated evidence sets | Precision > 0.9, Recall > 0.85 | Before any model change |
| Hallucination detection | 15 cases with planted false signals | Zero hallucinated findings in output | Before any model change |
| Grounding verification | 20 narratives | Every claim traceable to specific evidence | Before any model change |
| Attorney readability | 10 reports | Flesch-Kincaid grade level 12-16 | Quarterly |
| Latency budget | Full pipeline | LLM phase < 2 hours of TARR budget | Before any model change |

### 3.3 Detection Rule Updates

| Rule Set | Source | Update Cadence | Validation |
|----------|--------|----------------|------------|
| YARA-X rules | Community + custom | Weekly pull from curated feeds | Run against golden malware corpus; FP rate < 1% |
| Sigma rules | SigmaHQ repository | Weekly pull | Map to available evidence types; run against golden EVTX corpus |
| Custom forensic rules | Internal development | As-needed | Peer review in PR; golden case validation |
| NCMEC hash lists | NCMEC distribution | Monthly (when available) | Hash format validation; no test against real content |

**Rule update procedure**:
1. Pull latest rules from upstream
2. Run validation suite against golden corpus
3. Review any new FP/FN
4. If clean: merge to nightly, promote per release channel cadence
5. If issues: isolate problematic rules, file upstream issue

### 3.4 Embedding Model Refresh

The RAG pipeline uses `nomic-embed-text` via lancedb for forensic knowledge retrieval. Embedding model changes require full re-indexing.

**Quarterly evaluation**:
1. Run golden query set (50 forensic questions) against current index
2. Measure retrieval relevance (MRR@5 > 0.8)
3. If a newer embedding model shows > 5% improvement on golden queries: schedule re-index
4. Re-index is a background operation; old index remains active until new index passes validation

---

## 4. Incident Response

> **Adaptation**: "Incidents" are software bugs, data corruption, report accuracy issues, and legal-sensitive evidence encounters --- not server outages or DDoS attacks. The "on-call rotation" is a solo founder checking GitHub notifications and Discord.

### 4.1 Severity Levels

| Severity | Definition | Response Time | Examples |
|----------|------------|---------------|---------|
| **P0 --- Critical** | Evidence integrity compromised or legal liability risk | < 4 hours (drop everything) | Evidence file modified by tool; CSAM encountered without proper handling; parser produces incorrect timestamps used in court |
| **P1 --- High** | TARR regression > 2x or data loss | < 24 hours | Pipeline crash on valid evidence; report generation fails; DuckDB corruption; crash on common artifact type |
| **P2 --- Medium** | Feature degradation but workaround exists | < 1 week | Specific parser fails on edge case; LLM narrative quality degraded; TUI rendering glitch |
| **P3 --- Low** | Cosmetic or minor inconvenience | Next release cycle | Typo in report template; non-critical warning messages; minor UX friction |

### 4.2 Crash Dump Analysis

When Issen crashes, the `human-panic` handler captures:

| Data | Purpose | PII Handling |
|------|---------|-------------|
| Stack trace | Identify crash location | No PII (code paths only) |
| Panic message | Understand failure reason | Scrubbed of file paths and evidence content |
| OS + hardware info | Reproduce environment | Non-identifying |
| Issen version + config | Reproduce configuration | Non-identifying |
| Active parser + evidence type | Narrow root cause | Artifact type only, no content |

**Analysis workflow**:
1. User opts in to send crash report (or copies from `~/.issen/crash-reports/`)
2. Crash report lands in GitHub issue (auto-filed or manually)
3. Reproduce with golden dataset matching artifact type
4. Fix, add regression test, release via appropriate channel

### 4.3 Evidence Corruption Detection

Issen must never modify evidence. Detection mechanisms:

| Check | When | Action on Failure |
|-------|------|-------------------|
| SHA-256 hash verification at ingestion | Every case start | Block processing; alert user; log to audit trail |
| Read-only file handle enforcement | Runtime | `O_RDONLY` on all evidence access; any write attempt = immediate abort |
| Post-processing hash re-verification | After pipeline completion | If hash mismatch: **P0 incident**; quarantine case; alert user; halt all processing |
| Audit trail integrity | Continuous | Hash-chained JSONL; any chain break = **P0 incident** |

### 4.4 Report Accuracy Issues

When an examiner reports that a generated report contains inaccurate information:

1. **Immediate**: Classify as parser error (wrong data extracted) or narrative error (LLM misrepresented data)
2. **Parser error path**: Compare parser output against manual analysis of same artifact; add to golden test corpus; patch parser; release as P1
3. **Narrative error path**: Compare LLM narrative against raw findings data; identify grounding failure; add to hallucination test suite; adjust prompts or model; release as P2
4. **Both paths**: Update ForensicLLM evaluation suite with new test case

### 4.5 CSAM Legal Workflow

> **Legal obligation**: Under 18 U.S.C. Section 2258A (Adam Walsh Act), tools must not create unnecessary copies of CSAM. Issen is a forensic analysis tool, not an ESP, but practitioners using it may encounter CSAM.

**Workflow when CSAM indicators are detected**:
1. **Detection**: PhotoDNA/NCMEC hash list match during evidence processing
2. **Immediate action**: Flag in TUI with unmissable alert; halt further processing of flagged files
3. **No duplication**: Flagged content is never copied, cached, thumbnailed, or included in reports
4. **Audit entry**: Record detection event (hash only, no content) in hash-chained audit log
5. **Examiner responsibility**: Issen surfaces the detection; the examiner follows their jurisdiction's reporting obligations and organizational CSAM policy
6. **Report handling**: Flagged items appear in report as "[CSAM Flagged --- See Separate Handling Procedures]" with hash and file path only

---

## 5. Security and Compliance

> **Adaptation**: Compliance means Daubert admissibility, chain-of-custody integrity, and NIST CFTT validation --- not GDPR, SOC 2, or HIPAA. The threat model is adversarial opposing counsel, not nation-state hackers.

### 5.1 Daubert Compliance Validation

For Issen output to be admissible as evidence supporting expert testimony, it must satisfy Daubert factors:

| Daubert Factor | Issen Compliance | Validation Method | Cadence |
|----------------|----------------------|-------------------|---------|
| **Testable methodology** | Open-source parsers with published test suites; methodology section auto-generated in every report | Verify methodology section accurately describes actual processing steps | Every release |
| **Peer review** | Open-source parser code on GitHub; community review; conference presentations | Track GitHub PRs with external review; maintain presentation log | Continuous |
| **Known error rate** | FP < 1%, FN < 0.5% per parser against NIST CFTT reference data | Nightly CFTT validation runs in CI | Nightly |
| **Standards adherence** | NIST SP 800-86 (forensic process), NIST CFTT (tool testing) | Annual mapping review: NIST requirements vs Issen capabilities | Annually |
| **General acceptance** | Track adoption metrics, conference citations, peer tool comparisons | GitHub stars, download counts, citation tracking | Quarterly |

### 5.2 NIST CFTT Validation

The Computer Forensic Tool Testing (CFTT) program provides reference datasets and expected results:

| Parser | CFTT Test Set | Pass Criteria | Current Status |
|--------|---------------|---------------|----------------|
| USN Journal | CFTT NTFS reference images | 100% match on all test records | Nightly CI |
| MFT | CFTT NTFS reference images | 100% match on file metadata | Phase 1 target |
| Event Log | CFTT Windows Event Log set | 100% match on parsed fields | Phase 2 target |
| Registry | CFTT Windows Registry set | 100% match on key/value extraction | Phase 2 target |
| Prefetch | CFTT Prefetch reference set | 100% match on execution records | Phase 2 target |

**CFTT nightly CI workflow**:
1. Download/cache CFTT reference images
2. Process through each parser
3. Compare output against known-good reference
4. Report FP rate, FN rate, error rate
5. Fail CI build if any parser exceeds error thresholds

### 5.3 Supply Chain Security

| Tool | Purpose | Cadence | Action on Finding |
|------|---------|---------|-------------------|
| `cargo-audit` | Known vulnerability detection in dependencies | Daily (CI) + nightly (cron) | P1 for critical CVE, P2 for high, P3 for medium/low |
| `cargo-deny` | License compliance + duplicate detection | Every PR | Block merge on copyleft license in open-source crates; block on known-bad advisories |
| `cargo-vet` | Supply chain trust verification | Every PR | Block merge on unvetted new dependencies; require review |
| `cargo-fuzz` | Parser fuzzing for memory safety | Nightly (10 min per parser) | Any crash = P1; add crashing input to corpus |
| `proptest` | Property-based testing for parser invariants | Every PR | Failure = block merge; add shrunk case to unit tests |

### 5.4 Chain-of-Custody Verification

Issen maintains a hash-chained JSONL audit log for every case:

```json
{"seq": 1, "ts": "2026-03-20T14:22:01Z", "event": "evidence_ingested", "hash": "sha256:abc...", "prev_hash": "sha256:000..."}
{"seq": 2, "ts": "2026-03-20T14:22:03Z", "event": "parse_started", "parser": "usnjrnl", "prev_hash": "sha256:abc..."}
{"seq": 3, "ts": "2026-03-20T14:35:47Z", "event": "parse_completed", "records": 1847293, "prev_hash": "sha256:def..."}
```

**Verification protocol**:
- Every report includes a chain-of-custody appendix with full audit trail
- Any break in the hash chain triggers a P0 incident
- Audit logs are write-once: append-only file with OS-level permissions
- Verification command: `issen verify-chain --case {case_id}`

### 5.5 Parser Fuzz Testing Schedule

| Parser | Fuzz Harness | Duration/Night | Corpus Size | Last Crash |
|--------|-------------|----------------|-------------|------------|
| USN Journal | `fuzz_usnjrnl` | 10 min | Growing | Track in CI |
| MFT | `fuzz_mft` | 10 min | Growing | Track in CI |
| EVTX | `fuzz_evtx` | 10 min | Growing | Track in CI |
| Registry | `fuzz_registry` | 10 min | Growing | Track in CI |
| EWF (E01) | `fuzz_ewf` | 10 min | Growing | Track in CI |

Fuzz testing uses `cargo-fuzz` with `libFuzzer`. Coverage-guided fuzzing ensures each nightly run explores new code paths. Any crash input is minimized with `cargo fuzz tmin` and added to the regression corpus.

---

## 6. Cost and Resource Tracking

> **Adaptation**: No cloud infrastructure costs. Costs are: hardware amortization, Ollama model storage, optional cloud LLM usage, and development time. This is a bootstrapped, solo-founder operation.

### 6.1 Hardware Requirements

| Component | Minimum | Recommended | Purpose |
|-----------|---------|-------------|---------|
| CPU | 4 cores | 8+ cores | Parser parallelism (rayon), LLM inference |
| RAM | 8 GB | 32 GB | DuckDB in-memory processing, LLM model loading |
| Storage | 256 GB SSD | 1 TB NVMe | Evidence images, Ollama models (~5-40 GB each), case databases |
| GPU | None (CPU inference) | NVIDIA with 8+ GB VRAM | Dramatically faster Ollama inference; not required |

**Examiner cost**: Issen itself is free (open-source CLI) or licensed (professional/enterprise). The primary cost is the hardware the examiner already owns for forensic work.

### 6.2 Ollama Model Storage

| Model | Size on Disk | RAM When Loaded | Use Frequency |
|-------|-------------|-----------------|---------------|
| `mistral:7b` | ~4 GB | ~5 GB | Every case (classification + extraction) |
| `mixtral:8x7b` | ~26 GB | ~28 GB | Every case with narrative (large model) |
| `nomic-embed-text` | ~275 MB | ~300 MB | Every case (RAG embedding) |
| **Total baseline** | **~30 GB** | **~33 GB** | |

**Storage management**: `issen models list` shows installed models and disk usage. `issen models prune` removes models not referenced in any active configuration.

### 6.3 Optional Cloud LLM Costs

For practitioners who opt into cloud LLM for higher-quality narratives:

| Provider | Model | Est. Cost/Case | Monthly (20 cases) | When to Use |
|----------|-------|-----------------|---------------------|-------------|
| Anthropic | Claude Sonnet | ~$0.50-$2.00 | $10-$40 | Complex narrative generation, multi-artifact correlation narratives |
| OpenAI | GPT-4o | ~$0.30-$1.50 | $6-$30 | Alternative to Anthropic |
| Local only | Ollama | $0 | $0 | Default; no cost; slightly lower narrative quality |

**Monthly budget cap**: Configurable in `~/.issen/config.toml`. Default: $0 (local only). Maximum recommended: $150/month for heavy users.

**Cost tracking**: `issen costs show --month` displays cloud API spending with per-case breakdown. Alerts when approaching budget cap at 80%.

### 6.4 Development Time Allocation

As a solo founder, time is the scarcest resource. Weekly time budget (target 40 hours):

| Activity | Hours/Week | % | TARR Impact |
|----------|-----------|---|-------------|
| Core development (parsers, pipeline, reports) | 20 | 50% | Direct |
| Testing + CI maintenance | 6 | 15% | Direct (prevents regressions) |
| Community engagement (issues, Discord, PRs) | 4 | 10% | Indirect (feedback loop) |
| Documentation + ADRs | 3 | 7.5% | Indirect (Daubert compliance) |
| Model evaluation + rule updates | 3 | 7.5% | Direct (intelligence layer quality) |
| Business (marketing, conferences, licensing) | 2 | 5% | Indirect (adoption) |
| Operations (this document's checklists) | 2 | 5% | Meta (keeps everything on track) |

---

## 7. Iteration Planning

> **Adaptation**: Iteration planning for a solo founder means quarterly strategy reviews, not sprint ceremonies. Every decision filters through: "Does this reduce TARR?"

### 7.1 Quarterly Strategy Review

**Cadence**: First Monday of each quarter (January, April, July, October).

**Review agenda**:

1. **TARR trend analysis**: Plot TARR across all cases in the quarter. Is the trend improving? If not, identify the bottleneck stage.
2. **Input metrics review**:
   - Parse-to-Timeline Latency: trending toward < 10 min?
   - Findings-to-Narrative Time: trending toward < 2 hr?
   - Report Acceptance Rate: > 80%? (Measured via user interviews and GitHub feedback)
3. **Course correction triggers** (from NORTHSTAR.md):
   - TARR not improving after 3 months? Audit pipeline bottlenecks.
   - Report acceptance < 40%? Pause features, fix report quality.
   - Zero community engagement after 3 months? Reassess open-source strategy.
   - Parse correctness regression? Halt features, fix regression.
4. **Persona check-in**: Are Sarah, Marcus, and Diana's workflows better served than last quarter?
5. **Kill list review**: Has anything on the kill list been accidentally built or crept into the backlog?
6. **Competitive landscape update**: Any new entrants? Feature parity shifts?

### 7.2 Kill List Maintenance

The kill list (BRAND_GUIDELINES.md / NORTHSTAR.md Section 2.2) is a living document:

| Item | Status | Last Reviewed |
|------|--------|---------------|
| Evidence collection agent/tool | KILL | Quarterly |
| eDiscovery / document review platform | KILL | Quarterly |
| Real-time detection / SIEM functionality | KILL | Quarterly |
| Enterprise-first feature prioritization | KILL | Quarterly |
| AI-generated expert opinions | KILL | Quarterly |
| Mobile device forensics | KILL | Quarterly |

**Review process**: Each quarterly review, read every kill list item and ask: "Has the market changed enough to reconsider?" If yes, write an ADR documenting the analysis and decision. The default answer is "No."

### 7.3 Roadmap Updates

Roadmap lives in `north-star-advisor/docs/ROADMAP.md` (Phase 12 deliverable). Updates follow this process:

1. Collect all feedback from Section 2 channels
2. Score each potential feature/improvement by TARR impact (High/Medium/Low)
3. Filter through kill list (discard anything that matches)
4. Prioritize: High TARR impact > Parser correctness > Report quality > UX polish > Nice-to-have
5. Update roadmap with quarterly commitments
6. Publish changelog for community visibility

### 7.4 ADR (Architecture Decision Record) Creation

Every non-trivial technical decision gets an ADR in `docs/adrs/`:

| Trigger | ADR Required? | Example |
|---------|---------------|---------|
| New parser added | Yes | "ADR-015: Add Prefetch parser using X approach" |
| Model changed | Yes | "ADR-016: Switch narrative model from Mixtral to Llama3 70B" |
| Dependency added | Yes | "ADR-017: Add lancedb for vector storage" |
| Architecture change | Yes | "ADR-018: Split issen-intel into issen-llm and issen-rag" |
| Kill list item reconsidered | Yes | "ADR-019: Reassess mobile forensics --- decision: still kill" |
| Bug fix | No (unless architectural) | |

**ADR template**: Status, Context, Decision, Consequences, TARR Impact.

---

## 8. Runbook Quick Reference

> **Adaptation**: These are checklists for a solo founder, not team procedures. Designed for rapid execution during the time allocated in Section 6.4.

### 8.1 Daily Checklist (15 minutes)

```
[ ] Check GitHub notifications (issues, PRs, security advisories)
[ ] Scan Discord for urgent questions or crash reports
[ ] Review nightly CI results:
    [ ] cargo-audit: any new advisories?
    [ ] cargo-fuzz: any new crashes?
    [ ] CFTT validation: all parsers green?
    [ ] ForensicLLM eval: all metrics within threshold?
[ ] If any CI failures: triage severity (Section 4.1) and respond
```

### 8.2 Weekly Checklist (2 hours --- Monday)

```
[ ] Review weekly TARR digest (auto-generated on first launch)
    [ ] Identify TARR bottleneck stage for the week
    [ ] Log bottleneck in development journal
[ ] Process GitHub issues:
    [ ] Label and triage new issues
    [ ] Close resolved issues
    [ ] Update roadmap if patterns emerge
[ ] Pull latest detection rules:
    [ ] YARA-X community rules
    [ ] Sigma rules from SigmaHQ
    [ ] Run validation suite against golden corpus
    [ ] Merge if clean; investigate if not
[ ] Review crash reports (if any):
    [ ] Reproduce on development machine
    [ ] File as P1/P2 and add to sprint
[ ] Discord community engagement:
    [ ] Answer outstanding questions
    [ ] Share weekly development update
[ ] Pipeline health check:
    [ ] Run full pipeline on reference case (50 GB evidence set)
    [ ] Verify TARR within budget
    [ ] Check memory usage against baseline
```

### 8.3 Monthly Checklist (4 hours --- first Friday)

```
[ ] Conduct 3-5 user interviews (Section 2.1)
    [ ] At least 1 from each active persona group
    [ ] Document TARR feedback and report quality feedback
    [ ] File actionable items as GitHub issues
[ ] Ollama model check:
    [ ] Check for new model releases relevant to forensic tasks
    [ ] If promising: run ForensicLLM evaluation suite (Section 3.2)
    [ ] If improvement confirmed: schedule update for next beta release
[ ] Embedding model evaluation (quarterly --- see Section 3.4)
[ ] Cost review (Section 6.3):
    [ ] Check cloud LLM spending against budget
    [ ] Review development time allocation against targets
[ ] Release stable channel:
    [ ] Promote from beta after 2-week soak
    [ ] Write release notes
    [ ] Update documentation
[ ] Supply chain audit:
    [ ] Review cargo-deny output for new license issues
    [ ] Review cargo-vet for unaudited dependencies
    [ ] Update vet exemptions if justified (with ADR)
```

### 8.4 Quarterly Checklist (1 day --- first Monday of quarter)

```
[ ] Full strategy review (Section 7.1):
    [ ] TARR trend analysis across all cases
    [ ] Input metrics review (parse latency, narrative time, acceptance rate)
    [ ] Course correction triggers check
    [ ] Persona check-in
[ ] Kill list review (Section 7.2):
    [ ] Read every item
    [ ] Challenge each with current market context
    [ ] Write ADR if any item is reconsidered
[ ] Roadmap update (Section 7.3):
    [ ] Score backlog by TARR impact
    [ ] Set quarterly commitments
    [ ] Publish updated roadmap
[ ] Competitive landscape refresh:
    [ ] Check competitor releases (Magnet, OpenText, Cellebrite, Autopsy)
    [ ] Note any feature parity shifts
    [ ] Update COMPETITIVE_LANDSCAPE.md if significant
[ ] Daubert compliance check (Section 5.1):
    [ ] Verify CFTT pass rates
    [ ] Review methodology documentation accuracy
    [ ] Ensure error rates are documented and current
[ ] Conference planning:
    [ ] Identify upcoming DFIR conferences for demo/talk submissions
    [ ] Prepare demo materials using latest stable release
[ ] Annual NIST mapping review (if Q1):
    [ ] Map NIST SP 800-86 requirements to Issen capabilities
    [ ] Document gaps and remediation plan
```

---

## Appendix A: Metrics Reference

### Per-Crate Metric Catalog

| Crate | Metric | Type | Unit | TARR Component |
|-------|--------|------|------|----------------|
| issen-pipeline | `pipeline.ingest.duration` | Timer | seconds | Evidence Ingestion |
| issen-pipeline | `pipeline.layer.{0-4}.duration` | Timer | seconds | Parse-to-Timeline |
| issen-pipeline | `pipeline.parser.{name}.throughput` | Gauge | events/sec | Parse-to-Timeline |
| issen-pipeline | `pipeline.parser.{name}.success_rate` | Gauge | percentage | Parse-to-Timeline |
| issen-pipeline | `pipeline.parser.{name}.error_count` | Counter | count | Parse-to-Timeline |
| issen-timeline | `timeline.merge.duration` | Timer | seconds | Timeline Construction |
| issen-timeline | `timeline.query.latency` | Histogram | ms | Query Performance |
| issen-timeline | `timeline.event_count` | Gauge | count | Case Complexity |
| issen-timeline | `timeline.duckdb.memory_usage` | Gauge | bytes | Resource Health |
| issen-report | `report.render.{format}.duration` | Timer | seconds | Report Generation |
| issen-report | `report.render.{format}.success` | Counter | count | Report Reliability |
| issen-report | `report.word_count` | Gauge | count | Report Completeness |
| issen-intel | `intel.llm.response_time` | Histogram | seconds | Findings-to-Narrative |
| issen-intel | `intel.llm.grounding_accuracy` | Gauge | percentage | Narrative Quality |
| issen-intel | `intel.llm.hallucination_rate` | Gauge | percentage | Narrative Quality |
| issen-intel | `intel.rag.retrieval_quality` | Gauge | score (0-1) | RAG Effectiveness |
| issen-intel | `intel.rag.query_latency` | Histogram | ms | RAG Performance |
| issen-correlation | `correlation.pattern_count` | Counter | count | Detection Effectiveness |
| issen-correlation | `correlation.cross_artifact_matches` | Counter | count | Correlation Depth |
| issen-correlation | `correlation.duration` | Timer | seconds | Correlation Phase |
| issen-cli | `cli.command.{name}.duration` | Timer | seconds | UX Responsiveness |
| issen-tui | `tui.session.duration` | Timer | seconds | User Engagement |
| issen-tui | `tui.render.fps` | Gauge | frames/sec | TUI Performance |

### TARR Budget Allocation

```
Total TARR Budget: < 4 hours (240 minutes)
+------------------------------------------------------------------+
| Evidence Ingestion          |##|                           2 min  |
| Parse-to-Timeline           |########|                   10 min  |
| Timeline Construction       |#|                            1 min  |
| Correlation                 |#####|                        5 min  |
| Findings-to-Narrative       |#################################| 120 min  |
| Report Rendering            |#|                            1 min  |
| Examiner Review + Edit      |####################|       100 min  |
| Buffer                      |#|                            1 min  |
+------------------------------------------------------------------+
                                              Total:       240 min
```

---

## Appendix B: Tool and Command Reference

| Command | Purpose | When |
|---------|---------|------|
| `issen metrics show` | Display TARR and input metrics for current/recent cases | Weekly review |
| `issen metrics export --format json` | Export metrics for external analysis | Monthly |
| `issen verify-chain --case {id}` | Verify chain-of-custody integrity | Before court submission |
| `issen models list` | Show installed Ollama models and disk usage | Monthly |
| `issen models prune` | Remove unused Ollama models | As needed |
| `issen costs show --month` | Display cloud LLM spending | Monthly |
| `issen health check` | Run self-diagnostic (parsers, models, storage) | Weekly or after update |
| `cargo audit` | Check dependency vulnerabilities | Daily (CI) |
| `cargo deny check` | License and advisory compliance | Every PR |
| `cargo vet` | Supply chain trust verification | Every PR |
| `cargo fuzz run fuzz_{parser}` | Fuzz test a specific parser | Nightly (CI) |

---

*This document is a living operational guide. Review and update quarterly as part of the iteration planning cycle (Section 7.1). Every section must earn its place by contributing to the North Star: TARR < 4 hours.*
