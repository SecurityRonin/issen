# Issen: North Star Specification

<!-- GENERATION: This is Step 2 of 13. Requires outputs from BRAND_GUIDELINES. See GENERATION_MANIFEST.md -->

> **Tier**: 1 --- Strategic Authority
> **Created**: 2026-03-20
> **Status**: Active
> **Generation Step**: 2 of 13 --- Requires `brand.beliefs[]` and `brand.kill_list[]` from Step 1

---

## Document Purpose

This specification defines **what Issen must achieve** and **how we measure success**. Implementation details exist in supporting documents; this document answers:

1. What is our North Star metric?
2. Who are we building for?
3. What differentiates us?
4. What is in scope for each phase?
5. How do we know we're winning?

**Decision Rule**: If a feature, architecture choice, or initiative doesn't measurably improve the North Star metric, it doesn't ship.

---

# Part 1: Strategic Foundation

## 1.1 North Star Metric

### The Metric

> **Time-to-Attorney-Ready Report (TARR)**

**Definition**: The elapsed time from evidence ingestion to a completed, attorney-ready deliverable (interactive HTML report or polished Word/PDF expert witness report) measured in hours, with a target of 50%+ reduction compared to the practitioner's current manual workflow.

### Why This Metric

| Criterion | How TARR Satisfies It |
|-----------|------------------------------|
| **Leading** | Faster report delivery predicts case throughput, client satisfaction, and repeat engagements. A practitioner who cuts report time takes on more cases and evangelizes the tool. |
| **Actionable** | Every engineering decision --- parser coverage, template quality, report rendering --- directly reduces TARR. The team can measure the impact of each feature on the clock. |
| **Customer-centric** | Measures value delivered to the examiner's client (the attorney or organization), not vanity metrics like logins or artifacts parsed. The deliverable is the product. |
| **Understandable** | Anyone can explain it: "How long from getting the evidence to handing the attorney a finished report?" |

### What This Metric Rejects

| Anti-Metric | Why We Reject It |
|-------------|------------------|
| **Artifacts parsed per second** | Optimizing parse speed without improving report quality is an implementation detail, not user value. An examiner with fast parsing but manual report writing still loses days. |
| **Number of registered users** | Vanity metric that conflates downloads with value delivery. A user who installs but never finishes a report got zero value. |
| **Feature count / artifact type coverage** | Breadth without depth leads to "jack of all trades, master of none." Adding EVTX parsing means nothing if the examiner still rewrites findings by hand. |
| **Revenue per user** | Premature optimization for extraction. Community adoption and practitioner trust come first; monetization follows credibility. |

---

## 1.2 Input Metrics Hierarchy

The North Star decomposes into input metrics that teams can directly influence:

```
                              NORTH STAR
                   Time-to-Attorney-Ready Report (TARR)
                         Target: <4 hours
                              |
          +-------------------+-------------------+
          |                   |                   |
          v                   v                   v
   +--------------+    +--------------+    +--------------+
   | Parse-to-    |    | Findings-to- |    | Report       |
   | Timeline     |    | Narrative    |    | Acceptance   |
   | Latency      |    | Time         |    | Rate         |
   |              |    |              |    |              |
   | Target: <10m |    | Target: <2hr |    | Target: >80% |
   +--------------+    +--------------+    +--------------+
```

### Input Metrics Definitions

| Metric | Definition | Target | Owner |
|--------|------------|--------|-------|
| **Parse-to-Timeline Latency** | Time from evidence ingestion (E01/raw/KAPE output) to a navigable, unified timeline view | < 10 minutes for 50GB evidence set | Core Engine |
| **Findings-to-Narrative Time** | Time from examiner identifying key artifacts to having a structured written narrative with citations | < 2 hours per engagement | Report Engine |
| **Report Acceptance Rate** | Percentage of generated reports accepted by the attorney/client without requesting substantive rework | > 80% first-pass acceptance | Templates / UX |

### Metrics We Track But Don't Optimize

| Metric | Why Track | Why Not Optimize |
|--------|-----------|------------------|
| **Artifact type coverage** | Diagnostic: shows which evidence types cause fallback to manual tools | Optimizing for coverage leads to shallow parsers. Depth on core artifacts (USN Journal, MFT, Event Logs, Registry, Prefetch) matters more than breadth. |
| **Community GitHub stars** | Signals awareness and interest in the open-source parsers | Optimizing for stars leads to marketing-driven decisions instead of practitioner-driven ones. |
| **Raw processing throughput (GB/min)** | Monitors performance regressions | Rust already provides the speed floor. Over-optimizing throughput at the expense of correctness violates core belief: "Correctness Over Speed." |

---

## 1.3 Positioning

### Positioning Statement

> **Issen is a forensic triage platform** that transforms digital forensic artifacts into attorney-ready reports and interactive explorations for IR practitioners, forensic examiners, and litigation support teams who spend 80% of engagement time on manual report writing and evidence reprocessing. Unlike Magnet AXIOM, Autopsy, or X-Ways, we treat the deliverable as the product --- not an afterthought.

### What Makes Us Different

| Dimension | Alternatives | Our Approach |
|-----------|--------------|--------------|
| **Report output** | Manual export to CSV/PDF, then hours of Word formatting (AXIOM, X-Ways, Autopsy) | Attorney-ready HTML + Word/PDF reports generated directly from analysis, with proper citations and exhibit numbering |
| **Integration model** | Monolithic tools that own the entire pipeline from collection to reporting (AXIOM, Cellebrite) | Ingests output from any collector (KAPE, Velociraptor, ACQUIRE); focuses exclusively on the triage-to-deliverable gap |
| **Pricing and access** | $3,000-$10,000/year per seat (AXIOM, Cellebrite, X-Ways) or free-but-unusable reports (Autopsy) | Open-source parsers, accessible platform. Solo practitioner can start for free; pay for integration and report features |
| **Technology foundation** | Python/Java tools with known performance ceilings (Autopsy/plaso) or legacy C++ (X-Ways) | Rust-native parsers (usnjrnl-forensic, tl, ewf) providing correctness and performance without tradeoffs |

### Value Proposition

| User Need | Current Pain | Our Solution |
|-----------|--------------|--------------|
| Get from evidence to deliverable fast | Analysis takes 20% of time; report writing, reformatting, and attorney back-and-forth takes 80% | Integrated pipeline: parse, triage, narrate, deliver --- one tool, one workflow |
| Produce couissen-admissible reports | Manual copy-paste between tools breaks chain-of-custody documentation; attorneys question methodology | Automated chain-of-custody tracking, standardized methodology documentation, exhibit-ready formatting |
| Handle multiple concurrent cases | Each case requires rebuilding analysis environment, finding templates, remembering tool workflows | Case-centric workspace with persistent state, reusable templates, and consistent methodology across engagements |

---

## 1.4 Target Users

### Primary Persona: Sarah Chen, Solo IR Practitioner

```
"I spend two days analyzing the evidence and five days writing the report.
 My clients don't pay me for the report --- they pay me for the answer.
 But the report IS the answer, and it has to be perfect."

Demographics: 34, independent DFIR consultant, GCFE/GCFA certified,
  runs a 1-person consultancy out of Denver. Juggles 3-5 active cases.
  Left a Big 4 firm to go solo two years ago.
Current State: Collects with KAPE, analyzes in AXIOM + Timeline Explorer +
  manual registry parsing. Exports to CSV, copies into Word templates she
  built herself. Spends 60-70% of billable hours on report writing and
  attorney revisions. Uses Eric Zimmerman tools for USN Journal and MFT.
Access Barriers: Cannot afford $10K/yr AXIOM license renewal and $5K/yr
  Cellebrite on solo revenue. Free tools (Autopsy) produce reports she
  would be embarrassed to hand an attorney. No time to build custom tooling.

Functional Jobs:
  * Ingest KAPE/Velociraptor output and produce a unified timeline in minutes, not hours
  * Generate a Word report that an attorney can file without asking "what does this mean?"
  * Track chain-of-custody from evidence receipt through final deliverable
  * Maintain consistent methodology documentation across all cases

Emotional Jobs:
  * Feel confident that the report represents her professional reputation
  * Feel like she's doing analysis, not clerical formatting work
  * Feel that going solo was the right call --- more cases, less overhead

Social Jobs:
  * Appear methodical and thorough to attorneys and opposing counsel
  * Be seen as a credible expert witness if called to testify
  * Maintain reputation in the DFIR community as someone who ships quality work

Success Signals:
  * "I handed the attorney the report and she didn't have a single question about formatting or terminology."
  * "I finished the deliverable the same week I got the evidence. That used to take three weeks."
  * "I took on a fifth concurrent case because I'm not buried in report writing anymore."
```

### Secondary Persona: Marcus Webb, Forensic Examiner at a Consulting Firm

```
"The partners assign me cases and expect deliverables on their timeline.
 I do good analysis, but the report always becomes a bottleneck because
 the partner rewrites half of it for the client anyway."

Demographics: 28, forensic examiner at a mid-size litigation support firm
  (15 people), EnCE certified, 4 years of experience. Works cases assigned
  by senior partners. Has access to AXIOM and Cellebrite through firm licenses.
Current State: Analyzes in AXIOM, exports findings, writes reports in the
  firm's Word template. Partners review and heavily edit for client audience.
  Report revision cycles add 3-5 days per engagement. Feels like a junior
  despite solid technical skills because reports don't "look senior."
Access Barriers: Firm has tool licenses but no budget for new platforms.
  Any new tool must prove ROI to partners. Cannot change firm methodology
  unilaterally. Needs to work within existing evidence handling procedures.

Functional Jobs:
  * Produce reports that survive partner review with minimal redlines
  * Standardize output format so every examiner's work looks consistent
  * Reduce the revision cycle from days to hours

Emotional Jobs:
  * Feel like his technical work is valued, not overshadowed by formatting issues
  * Feel confident presenting findings to clients directly
  * Feel less like a "report monkey" and more like an analyst

Social Jobs:
  * Appear competent and senior to firm partners
  * Produce work that the firm is proud to put its name on
  * Be the person who brought a better workflow to the team

Success Signals:
  * "The partner read my report and said 'ship it' without changes for the first time."
  * "Our revision cycle dropped from five rounds to one."
  * "I showed the interactive timeline to the client and they actually understood the incident."
```

### Tertiary Persona: Diana Reyes, Litigation Support Analyst

```
"I'm the translator between the forensic team and the legal team.
 Half my job is reformatting technical findings into something
 a judge would accept as an exhibit."

Demographics: 31, litigation support analyst at an Am Law 200 firm,
  paralegal background with forensic technology training. Manages the
  evidence-to-courtroom pipeline for 10-15 matters at a time.
Current State: Receives forensic reports from internal examiners or
  outside consultants. Reformats findings into couissen-filing format,
  creates exhibit lists, ensures Bates numbering, and prepares
  deposition binders. Uses Relativity for document review but
  forensic artifacts arrive as raw CSVs or poorly formatted PDFs.
Access Barriers: Does not control which forensic tools are used.
  Must work with whatever output the examiner produces. Budget
  decisions made by partners, not by her.

Functional Jobs:
  * Receive forensic output in a format that maps directly to court exhibit requirements
  * Generate exhibit-ready artifacts without manual reformatting
  * Maintain a clear chain from raw evidence to final court filing

Emotional Jobs:
  * Feel like a valued part of the legal team, not a formatting service
  * Feel confident that exhibits will survive opposing counsel scrutiny

Social Jobs:
  * Be seen as the person who makes the technical evidence "work" in court
  * Maintain credibility with both the forensic and legal teams

Success Signals:
  * "The forensic report came in and I could submit it as an exhibit with minimal changes."
  * "The attorney stopped asking me to 'make this make sense' --- it already did."
```

### Future Persona: James Okafor, CISO / IR Manager (Phase 3+)

```
"I need to know where every case stands, that our team follows
 a consistent methodology, and that our reports can withstand
 regulatory scrutiny."

Demographics: 42, CISO at a mid-market financial services company
  (2,000 employees), manages a 4-person IR team. Reports to the
  board on security posture quarterly.
Current State: Team uses a mix of tools with no standardization.
  Case status tracked in spreadsheets. Reports vary wildly in
  quality depending on which examiner wrote them. Audit preparation
  is a scramble.
Access Barriers: Needs enterprise features (SSO, audit logs, role-based
  access, centralized case management) that don't exist in Phase 1-2.

[Full persona development deferred to Phase 3 enterprise planning]
```

---

## 1.5 Forces of Progress Analysis

Understanding what drives users toward Issen and what holds them back.

### Push Forces (Away from Current State)

| Force | Evidence | Strength |
|-------|----------|----------|
| Report writing consumes 60-80% of engagement time | Consistent across DFIR community surveys; confirmed by founder's consulting experience | Strong |
| Expensive tool licenses ($3K-$10K/seat/year) unsustainable for solo practitioners | AXIOM Cyber ~$3,500/yr, Cellebrite UFED ~$9,000/yr; solo consultants billing $150-250/hr feel the squeeze | Strong |
| Attorney back-and-forth adds days per engagement | Average 3-5 revision cycles per report; attorneys unfamiliar with forensic terminology request rewrites | Strong |
| Free tools (Autopsy) produce unusable reports | Autopsy HTML reports are raw data dumps; no narrative, no exhibit formatting, no attorney-ready output | Medium |
| No integrated triage-to-report pipeline exists | Examiners chain 4-7 tools (KAPE + EZ Tools + Timeline Explorer + AXIOM + Word + manual formatting) per case | Strong |

### Pull Forces (Toward Issen)

| Force | Promise | Evidence |
|-------|---------|----------|
| Attorney-ready output eliminates the translation gap | Reports generated with proper terminology, exhibit numbering, and narrative structure | Will prove through beta user report acceptance rates |
| Open-source parsers build trust and allow verification | Examiners can inspect and validate parsing logic --- critical for courtroom credibility | Open-source forensic tools (Volatility, Autopsy, EZ Tools) have strong community adoption patterns |
| Rust-native performance removes the speed/correctness tradeoff | Parse 50GB evidence sets in minutes, not hours, without sacrificing accuracy | usnjrnl-forensic benchmarks already demonstrate 10x+ improvement over Python equivalents |
| Integrated pipeline reduces tool-chaining friction | One tool from evidence ingestion to final deliverable | Directly addresses the 4-7 tool workflow pain point |

### Anxiety of Change

| Concern | User Verbalization | Mitigation |
|---------|-------------------|------------|
| "Will it parse my evidence correctly?" | "I can't afford errors in a court case. One wrong timestamp and opposing counsel destroys my credibility." | Open-source parsers with published test suites. Correctness-first design philosophy. Community validation of parsing logic. |
| "Can I trust a new tool for court work?" | "I need to explain my methodology on the stand. I can't say 'this tool I found on GitHub said so.'" | Methodology documentation generated with every report. Transparent chain-of-custody tracking. Daubert/Frye compliance documentation. |
| "What if it doesn't support my evidence types?" | "I mostly work NTFS artifacts and Windows Event Logs. If it can't handle those, it's useless." | Phase 1 focuses on the core Windows artifact set (USN Journal, MFT, Event Logs, Registry, Prefetch) that covers 70%+ of IR engagements. |
| "Lock-in risk for a bootstrapped tool" | "What if the developer disappears? I've been burned by forensic startups before." | Open-source parsers remain open permanently (ethical commitment). Standard output formats (HTML, DOCX, PDF). No proprietary evidence formats. |

### Habit of the Present

| Current Habit | Switching Cost | Strategy |
|---------------|----------------|----------|
| KAPE + EZ Tools + manual workflow | Deep muscle memory; 100+ hours invested in personal templates and scripts | Issen ingests KAPE output natively. Existing workflow becomes the input, not a replacement. Augment, don't replace. |
| AXIOM as primary analysis tool | Firm licenses paid annually; training investment; case history in AXIOM format | Position as complement for report generation, not AXIOM replacement. "Analyze in AXIOM, deliver with Issen." Phase 2 adds direct analysis to reduce dependency. |
| Custom Word templates for reports | Hours of formatting work baked into personal templates; each examiner's template is different | Import existing Word templates as Issen report templates. Migration path, not abandonment. |
| Spreadsheet-based case tracking | Simple, understood, no learning curve | Phase 1 does not replace case management. Focus on the deliverable, not the workflow wrapper. |

---

# Part 2: Scope Definition

## 2.1 Phase Boundaries

### Phase 1: MVP

**Theme**: "Evidence in, attorney-ready report out"

**Objective**: Deliver a working pipeline from forensic artifact ingestion (KAPE/Velociraptor triage output) to a polished, attorney-ready HTML and Word report for the core Windows artifact set, usable by a solo practitioner on a single case.

**In Scope**:

| Feature | Acceptance Criteria | Why Essential |
|---------|---------------------|---------------|
| **KAPE/Velociraptor output ingestion** | Accepts standard triage collection output; parses without manual preprocessing | This is how every IR practitioner starts --- the collection output is the input |
| **USN Journal parsing (usnjrnl-forensic)** | Parses $UsnJrnl:$J with full record type support; matches or exceeds MFTECmd accuracy | USN Journal is the single most valuable Windows triage artifact for timeline reconstruction |
| **Unified timeline generation (tl)** | Merges parsed artifacts into a single, sortable, filterable timeline view | Timeline is the core analytical view; everything flows from temporal ordering |
| **Interactive HTML report** | Navigable HTML report with timeline visualization, artifact drill-down, and executive summary | The "wow" deliverable --- attorneys can explore evidence without examiner hand-holding |
| **Word/PDF expert witness report** | Formatted .docx with methodology section, findings narrative, exhibit references, and chain-of-custody appendix | The couissen-filing deliverable --- what the attorney actually submits |
| **E01/raw disk image support (ewf)** | Reads EnCase E01 format and raw disk images directly | E01 is the de facto standard evidence container in DFIR; not supporting it is a non-starter |
| **Chain-of-custody documentation** | Automated hash verification at ingestion; documented methodology in every report | Courtroom credibility requires documented chain-of-custody from evidence receipt through analysis |

**Out of Scope for Phase 1**:

| Feature | Why Deferred |
|---------|--------------|
| **Multi-case management** | Solo founder constraint; one case at a time is sufficient to prove the pipeline works |
| **Browser artifact parsing** | High value but large surface area; Phase 2 after core Windows artifacts are bulletproof |
| **Collaborative features** | Phase 1 targets solo practitioner; team features require infrastructure (auth, permissions, sync) |
| **GUI/desktop application** | CLI + report output first. GUI is Phase 2. Practitioners are comfortable with CLI. |
| **Cloud/SaaS deployment** | Forensic evidence cannot leave examiner's machine in most engagements. Local-first is both simpler and required. |
| **Mobile artifact support** | Different evidence domain (Cellebrite territory). Windows-first strategy. |
| **AI/LLM-assisted narrative generation** | Tempting but risky for couissen-admissible work. Must nail deterministic report generation first. |

**Phase 1 Success Criteria**:

| Metric | Target | Kill Threshold |
|--------|--------|----------------|
| **TARR (core artifact set)** | < 4 hours for a standard IR triage case | > 8 hours (no meaningful improvement over manual workflow) |
| **Report acceptance rate** | > 70% of beta testers say report is "usable as-is or with minor edits" | < 40% (report quality doesn't meet professional standard) |
| **Parse correctness** | 100% accuracy on regression test suite vs. EZ Tools reference output | Any correctness regression (non-negotiable for court work) |
| **Beta user adoption** | 25 active beta testers completing at least one end-to-end case | < 10 (insufficient product-market signal) |
| **Community engagement** | 100+ GitHub stars on open-source parsers; 5+ community bug reports or PRs | < 25 stars after 3 months (no community interest) |

---

### Phase 2: Professional Polish

**Theme**: "From CLI tool to professional platform"

**Objective**: Add GUI, expanded artifact coverage, and template customization to make Issen a daily-driver tool for small IR teams (2-5 people).

**Unlocked By**: Phase 1 success criteria met

**In Scope**:

| Feature | Acceptance Criteria | Why Now |
|---------|---------------------|---------|
| **Desktop GUI (Tauri/Rust)** | Native application with case workspace, timeline viewer, and report preview | Phase 1 proved the pipeline; GUI makes it accessible to non-CLI users and expands addressable market |
| **Browser artifact parsing** | Chrome/Firefox/Edge history, downloads, cookies, cache with full timestamp support | Second most requested artifact type after Windows filesystem artifacts |
| **Event Log deep parsing** | Windows Event Log (EVTX) with full provider support and MITRE ATT&CK mapping | Critical for IR narratives; transforms raw events into attack story |
| **Registry hive analysis** | SAM, SYSTEM, SOFTWARE, NTUSER.DAT with key forensic artifact extraction | Completes the "core Windows" artifact set |
| **Custom report templates** | User-defined Word/HTML templates with variable substitution and conditional sections | Every firm has its own report format; customization drives adoption at firm level |
| **Multi-case workspace** | Switch between cases; persistent state per case; case metadata tracking | Small teams run 5-15 concurrent cases; single-case limitation blocks daily use |

**Phase 2 Success Criteria**:

| Metric | Target | Kill Threshold |
|--------|--------|----------------|
| **TARR (full artifact set)** | < 3 hours for standard IR case with expanded artifacts | > 6 hours (GUI added friction, not speed) |
| **Paid conversions** | 50 paying users at $50-100/mo (professional tier) | < 15 paying users (value not sufficient to monetize) |
| **Artifact coverage** | Covers 80%+ of artifacts encountered in standard Windows IR engagement | < 60% (still requires fallback to other tools too often) |
| **Team adoption** | 5 firms (2+ examiners each) using Issen as primary report tool | < 2 firms (solo-only tool, not team-viable) |

---

### Phase 3: Enterprise and Ecosystem

**Theme**: "Team workflows and partner integrations"

**Objective**: Add enterprise features (SSO, audit logs, role-based access, case assignment) and partner integrations (Relativity, Nuix) to address the CISO/IR Manager persona and litigation support workflows.

**Unlocked By**: Phase 2 success criteria met

**In Scope**:

| Feature | Acceptance Criteria | Why Now |
|---------|---------------------|---------|
| **Enterprise authentication (SSO/SAML)** | SAML 2.0 / OIDC integration with major identity providers | Enterprise procurement requirement; blocking for firms with > 10 users |
| **Role-based access control** | Examiner, reviewer, admin roles with appropriate permissions | Partners need review workflows; compliance requires access controls |
| **Audit logging** | Immutable audit trail of all case actions for compliance | Regulatory requirement for financial services and healthcare IR |
| **Relativity/Nuix export** | Direct export of evidence packages to eDiscovery platforms | Litigation support persona needs seamless handoff to legal review tools |
| **MITRE ATT&CK report mapping** | Findings automatically mapped to ATT&CK techniques in report narrative | Standardized threat language expected by enterprise clients and regulators |
| **API for integration** | RESTful API for programmatic evidence ingestion and report generation | Enables integration into existing firm workflows and automation pipelines |

**Phase 3 Success Criteria**:

| Metric | Target | Kill Threshold |
|--------|--------|----------------|
| **Enterprise contracts** | 5 enterprise contracts ($500+/mo) | < 2 (enterprise value proposition not proven) |
| **TARR (enterprise workflow)** | < 2 hours including review and approval cycle | > 5 hours (enterprise overhead negates time savings) |
| **Integration adoption** | 3+ firms actively using Relativity/Nuix export | < 1 (integration value not realized) |

---

## 2.2 Explicit Kill List (Never Build)

These features are explicitly out of scope regardless of phase. They represent scope creep, premature optimization, or strategic misalignment.

| Feature | Rationale for Rejection |
|---------|------------------------|
| **Evidence collection agent/tool** | Collection is solved (KAPE, Velociraptor, ACQUIRE). Building a collector fragments focus and competes with established, trusted tools. Issen ingests their output. (Brand: "Not a collection tool") |
| **eDiscovery / document review platform** | Different problem, different users, different regulatory requirements. Issen produces evidence for Relativity/Nuix; it does not replace them. (Brand: "Not an eDiscovery platform") |
| **Real-time detection / SIEM functionality** | Post-incident forensic analysis, not real-time monitoring. Alert fatigue and detection engineering are entirely different domains. (Brand: "Not a SIEM/SOC tool") |
| **Enterprise-first feature prioritization** | Solo examiner and small IR team first. Enterprise features come in Phase 3 after product-market fit is proven with practitioners. (Brand: "Not enterprise-first") |
| **AI-generated expert opinions** | The examiner provides expert opinion; the tool eliminates translation work. Generating forensic conclusions via LLM is ethically and legally dangerous for couissen-admissible work. (Brand: "Not a competitor to the examiner") |
| **Mobile device forensics** | Cellebrite and MSAB own this market with hardware-level extraction. Mobile is a different evidence domain requiring different parsers, different legal frameworks, and different expertise. |
| **Memory forensics** | Volatility/Rekall are excellent and open-source. Memory analysis is a specialized skill; integrating it adds massive complexity without improving the deliverable pipeline. |
| **Malware analysis / sandboxing** | Separate discipline with dedicated tools (Cuckoo, ANY.RUN, Joe Sandbox). Issen may reference malware findings but does not perform dynamic analysis. |
| **Cloud forensics (AWS/Azure/GCP)** | Cloud IR requires platform-specific APIs and is rapidly evolving. Phase 3+ consideration at earliest, and only if the triage-to-report pattern applies. |

---

## 2.3 Licensing & Ethics

### License Choice

**License**: Dual --- Apache 2.0 (parsers and utilities) / Proprietary (integration, reports, UI, enterprise features)

**Rationale**: Open-source parsers (usnjrnl-forensic, tl, ewf, shrinkpath) build community trust, enable courtroom transparency ("you can inspect the code that parsed this evidence"), and attract contributors. Proprietary integration layer funds continued development. This mirrors the "Open Parsers, Integrated Platform" brand belief --- parsers commoditize; integration differentiates.

### Ethical Constraints

| Constraint Type | Specification |
|-----------------|---------------|
| **Prohibited Uses** | Issen must never be used to fabricate, alter, or misrepresent forensic evidence. The tool must not generate false findings or manipulate timestamps. No feature may compromise chain-of-custody integrity. |
| **Required Behaviors** | Every report must include methodology documentation sufficient for Daubert/Frye admissibility challenges. Hash verification at ingestion is mandatory and cannot be bypassed. All parsing logic must be deterministic and reproducible. |
| **Data Principles** | Evidence never leaves the examiner's machine without explicit action. No telemetry on evidence content. Usage analytics (if any) are opt-in and contain no case data. Open-source parsers remain open permanently --- this commitment is irrevocable. |

---

# Part 3: Success Measurement

## 3.1 Metrics Dashboard

### North Star (Weekly Review)

```
+---------------------------------------------------------------------+
|  NORTH STAR: Time-to-Attorney-Ready Report (TARR)                   |
|                                                                     |
|  Current: ████████████████░░░░ ~8hr   Target: <4hr    Trend: --     |
|  (Baseline: manual workflow ~16hr for standard IR case)             |
+---------------------------------------------------------------------+
```

### Input Metrics (Daily Review)

| Metric | Current | Target | Status |
|--------|---------|--------|--------|
| Parse-to-Timeline Latency | Baseline TBD | < 10 min | Pre-launch |
| Findings-to-Narrative Time | Baseline TBD | < 2 hr | Pre-launch |
| Report Acceptance Rate | Baseline TBD | > 80% | Pre-launch |

### Health Metrics (Weekly Review)

| Metric | Current | Threshold | Status |
|--------|---------|-----------|--------|
| Parse Correctness (vs. reference) | 100% | 100% (zero tolerance) | Healthy |
| CLI Error Rate | TBD | < 2% of invocations | Pre-launch |
| Report Generation Failures | TBD | < 1% of attempts | Pre-launch |

---

## 3.2 Validation Gates

Before committing significant resources, validate assumptions:

| Gate | Question | Evidence Required | Decision |
|------|----------|-------------------|----------|
| **Problem** | Do examiners actually spend 60-80% of time on report writing? | 10+ practitioner interviews confirming the ratio; founder's own consulting data | Proceed (validated through consulting experience) |
| **Solution** | Does an integrated pipeline actually reduce TARR by 50%+? | 5 beta users complete end-to-end case; measure actual TARR vs. their baseline | Proceed / Pivot |
| **Retention** | Do examiners use Issen for their second case? | > 60% of beta users who complete case 1 start case 2 within 30 days | Proceed / Pivot |
| **Scale** | Can this grow beyond solo practitioners to teams? | 3+ firms express interest in multi-user deployment after Phase 1 launch | Proceed to Phase 2 / Stay solo-focused |

---

## 3.3 Course Correction Triggers

| Signal | Threshold | Observation Period | Response |
|--------|-----------|-------------------|----------|
| TARR not improving over manual | > 8 hours after 3 months of development | 3 months post-beta | Audit pipeline bottlenecks; consider whether report generation approach is fundamentally wrong |
| Report acceptance rate below standard | < 40% of beta testers find reports usable | 6 weeks post-beta | Pause feature development; focus exclusively on report template quality and attorney feedback |
| Zero community engagement | < 25 GitHub stars on parsers after 3 months public | 3 months post-launch | Reassess open-source strategy; consider whether the problem is marketing, discoverability, or product-market fit |
| Parse correctness regression | Any validated correctness bug in released parser | Immediate | Halt new feature development; fix regression; add to test suite; post-mortem |
| Safety incident | Evidence integrity compromised by tool bug | Immediate | Pause development; full audit; public disclosure if any user affected |

---

# Part 4: MVP Architecture Summary

## 4.1 Agent Topology

> **Note**: Full implementation details are in `ARCHITECTURE_BLUEPRINT.md`. This section provides strategic context.

```
EVIDENCE INPUT (E01 / Raw / KAPE output / Velociraptor output)
     |
     v
+------------------+
|  Evidence Ingest  |  <- Hash verification, format detection, chain-of-custody init
+------------------+
     |
     +--------+--------+--------+
     v        v        v        v
  +------+ +------+ +------+ +------+
  | USN  | | MFT  | | EVTX | | REG  |   <- Parallel artifact parsers (Rust)
  | Jrnl | |      | | (P2) | | (P2) |
  +------+ +------+ +------+ +------+
     |        |        |        |
     +--------+--------+--------+
              |
              v
     +------------------+
     | Timeline Merger   |  <- Unified timeline (tl crate)
     | (tl)             |
     +------------------+
              |
              v
     +------------------+
     | Report Generator  |  <- Template engine: HTML + DOCX + PDF
     +------------------+
              |
              v
     DELIVERABLE OUTPUT (Interactive HTML / Word / PDF)
```

### Agent Specifications (MVP)

| Component | Technology | Constraint | Responsibility |
|-----------|-----------|---------|----------------|
| **Evidence Ingest** | Rust (ewf crate) | < 30s for format detection | E01/raw image mounting, hash verification, artifact extraction |
| **USN Journal Parser** | Rust (usnjrnl-forensic v0.6) | < 60s for 1GB $UsnJrnl | Parse $UsnJrnl:$J records with full type support |
| **Timeline Merger** | Rust (tl v0.1) | < 120s for 10M events | Merge parsed artifacts into unified, sorted timeline |
| **Report Generator** | Rust + Tera templates | < 30s for report render | Generate HTML/DOCX/PDF from timeline + findings + metadata |

### Latency Budget

- **Total**: < 10 minutes P95 for complete pipeline (50GB evidence set, USN Journal + MFT)
- **Parse phase**: < 5 minutes (parallelized across artifact types)
- **Report generation**: < 30 seconds (template rendering, not a bottleneck)

---

## 4.2 Technology Stack (MVP)

| Layer | Choice | Rationale |
|-------|--------|-----------|
| **Core Language** | Rust | Correctness (memory safety, type system) + performance (no GC pauses) + single binary distribution. Aligns with "Correctness Over Speed (But Aim for Both)" belief. |
| **Evidence Format** | ewf crate (v0.1) | Native E01 support without libewf dependency. Pure Rust for cross-platform builds. |
| **Timeline Engine** | tl crate (v0.1) | Custom timeline merge/query library. Handles 10M+ events efficiently. |
| **Path Handling** | shrinkpath (v0.1) | Compact path representation for memory-efficient artifact storage. |
| **Report Templates** | Tera (Rust template engine) | Jinja2-compatible syntax; mature Rust library; supports HTML and text output. |
| **Word Generation** | rust-docx or python-docx subprocess | .docx generation for attorney deliverables. May use Python subprocess for complex formatting until Rust docx ecosystem matures. |
| **Distribution** | Single binary (cargo build --release) | Zero-dependency install. Examiner downloads one file, runs it. No Python environment, no Java, no Docker. |

### Deferred Technology (Phase 2+)

| Technology | Phase | Why Deferred |
|------------|-------|--------------|
| Tauri (Desktop GUI) | Phase 2 | CLI proves the pipeline; GUI adds development cost without validating core value proposition |
| SQLite (case database) | Phase 2 | Multi-case management requires persistent storage; Phase 1 is single-case, file-based |
| WebSocket (live preview) | Phase 2 | Real-time report preview in GUI; not needed for CLI-first approach |
| SAML/OIDC (enterprise auth) | Phase 3 | Enterprise authentication not needed until team features exist |

---

## 4.3 Technology Constraints

| Constraint | Requirement | Rationale |
|------------|-------------|-----------|
| **Correctness** | 100% parse accuracy vs. reference tools (EZ Tools, AXIOM) | Couissen-admissible work has zero tolerance for parsing errors. One wrong timestamp destroys credibility. |
| **Single binary** | No runtime dependencies (no Python, Java, .NET, Docker) | Examiners work on locked-down forensic workstations. Complex installs are adoption killers. |
| **Local-first** | Evidence never transmitted over network by default | Forensic evidence is legally sensitive. Many engagements prohibit cloud processing. Client trust requires local processing. |
| **Cross-platform** | Windows primary, macOS/Linux secondary | Forensic workstations are predominantly Windows. Rust enables cross-platform from single codebase. |
| **Evidence integrity** | Read-only evidence access; hash verification at every stage | Chain-of-custody requirements. Tool must never modify source evidence. |

---

# Part 5: Operations

## 5.1 Launch Plan

### Phase 1 Launch

**Launch Type**: Closed Beta (invite-only practitioners)

**Target Users**: 25-50 IR practitioners from founder's professional network, DFIR Discord communities, and SANS alumni network

**Launch Sequence**:

| Week | Action |
|------|--------|
| -4 | Complete core pipeline (ingest -> parse -> timeline -> HTML report). Internal dogfooding on 3 real cases. |
| -2 | Add Word/PDF report output. Create getting-started documentation. Record walkthrough video. |
| -1 | Open-source parser crates (usnjrnl-forensic, tl, ewf, shrinkpath) on GitHub. Announce on DFIR Twitter/Mastodon and forensic Discords. |
| 0 | Release closed beta binary to first 25 practitioners. Create private feedback channel (Discord or Slack). |
| +1 | Daily monitoring of beta feedback. Hotfix parse correctness issues within 24 hours. Weekly beta user check-ins. |
| +2 | First TARR measurements from beta users. Identify top 3 friction points. |
| +4 | Beta retrospective. Decide: proceed to open beta (Phase 1 success criteria met) or iterate (criteria not met). |
| +8 | Open beta release if criteria met. Conference talk submission (SANS DFIR Summit, OSDFCon, BSides). |

---

## 5.2 Risk Monitoring

### Safety Risks

| Risk | Monitoring | Threshold | Action |
|------|------------|-----------|--------|
| Parse incorrectness leads to wrong forensic conclusions | Automated regression suite vs. EZ Tools reference output; beta user accuracy reports | Any confirmed parsing error in released version | Immediate patch release; public advisory if users may have been affected; add to regression suite |
| Evidence integrity compromise | Hash verification at ingestion + post-processing; read-only evidence access | Any evidence file modification detected | Halt releases; full audit; notify affected users; post-mortem |
| Report contains misleading methodology claim | Template review by practicing examiners; methodology section peer review | Any methodology statement that misrepresents the tool's actual process | Update templates; re-generate affected reports; document corrective action |

### Technical Risks

| Risk | Monitoring | Threshold | Action |
|------|------------|-----------|--------|
| Solo founder burnout / bus factor | Weekly development velocity tracking; community contributor pipeline | 2+ consecutive weeks of zero commits; no community contributors after 6 months | Prioritize contributor onboarding documentation; consider paissen-time contract help funded by consulting revenue |
| Rust ecosystem gaps (docx generation, complex formatting) | Track blocking issues in rust-docx and alternative libraries | Word report generation requires > 50% Python subprocess calls | Invest in Rust docx library contribution or accept Python dependency for report generation |
| Evidence format incompatibility | Beta user evidence ingestion success rate | > 10% of beta evidence sets fail to ingest | Prioritize format support; add specific error messages guiding workarounds |
| Performance regression on large evidence sets | Benchmark suite on 10GB, 50GB, 100GB evidence sets | P95 pipeline time exceeds 2x target | Profile and optimize; consider streaming/incremental processing |

---

# Part 6: Document Hierarchy

This North Star specification is the **strategic anchor**. Implementation details live in supporting documents:

```
NORTHSTAR.md (this document)
+-- Strategic decisions
+-- Scope boundaries
+-- Success metrics
+-- MVP architecture summary

Supporting Documentation
+-- NORTHSTAR_EXTRACT.md: Design DNA (immutable patterns)
+-- ARCHITECTURE_BLUEPRINT.md: Multi-agent system design
+-- SECURITY_ARCHITECTURE.md: Authentication, safety
+-- BRAND_GUIDELINES.md: Identity and voice
+-- ADR.md: Architecture decision records
+-- INDEX.md: Document hierarchy and relationships
```

---

# Appendix A: Glossary

| Term | Definition |
|------|------------|
| **TARR** | Time-to-Attorney-Ready Report. The North Star metric measuring elapsed time from evidence ingestion to completed deliverable. |
| **Attorney-ready** | A report that an attorney can file, submit as an exhibit, or use in proceedings without substantive reformatting or clarification. |
| **Triage** | Rapid forensic analysis focused on key artifacts to answer specific investigative questions, as opposed to comprehensive full-disk forensic examination. |
| **KAPE** | Kroll Artifact Parser and Extractor. A widely-used forensic collection tool that gathers artifacts from live systems or mounted images. Issen's primary input format. |
| **Velociraptor** | An open-source endpoint monitoring and forensic collection tool. Alternative collection source supported by Issen. |
| **E01** | EnCase Evidence File format. The de facto standard forensic disk image container. Supported by the ewf crate. |
| **USN Journal** | Update Sequence Number Journal ($UsnJrnl:$J). An NTFS filesystem artifact that records file system changes. Primary artifact for timeline reconstruction. |
| **Chain-of-custody** | Documented chronological history of evidence handling from collection through analysis to presentation, required for court admissibility. |
| **Daubert/Frye** | Legal standards for admissibility of expert testimony and scientific evidence in US courts. Reports must document methodology sufficient to satisfy these standards. |
| **EZ Tools** | Eric Zimmerman's Tools. A suite of free forensic utilities (MFTECmd, PECmd, etc.) widely used as reference implementations for artifact parsing. |

---

**End of North Star Specification**

*This document should be reviewed monthly and updated when strategic decisions change.*

---

*Document generated by North Star Advisor*
