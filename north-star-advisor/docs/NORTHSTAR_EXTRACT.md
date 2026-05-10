# Issen: North Star Extract

<!-- GENERATION: Step 4 of 13. Derived from BRAND_GUIDELINES, NORTHSTAR, and COMPETITIVE_LANDSCAPE. -->

> Your project's design DNA — the decisions that should NOT be re-litigated.
> **Generation Step**: 4 of 13

**Project:** Issen
**Created:** 2026-03-20
**Last Updated:** 2026-03-20

---

## How to Use This Document

This is the **decision filter** for Issen. When you face a design choice, feature request, or architecture question, check this document first.

- **Before adding a feature**: Does it reduce TARR? If not, why are we building it?
- **Before choosing between two approaches**: Which axiom applies? Follow it.
- **Before expanding scope**: Is it on the kill list? If yes, stop.
- **When values conflict**: The axiom hierarchy resolves it. No debate needed.

Tape this to your monitor. Read it before every sprint. If a decision contradicts this document, either change the decision or formally update this document first — never silently drift.

---

## Core Axioms

These constraints govern every major decision. They are non-negotiable.

| # | Axiom | What It Means | When It Bites |
|---|-------|---------------|---------------|
| 1 | **Correctness > Speed** | When forensic accuracy and processing speed conflict, choose accuracy. An incorrect timeline is worse than a slow one. Evidence must withstand Daubert challenges. | You will be tempted to skip validation passes to hit parse-time targets. Do not. A fast wrong answer destroys examiner trust permanently. |
| 2 | **Report is the Product** | The deliverable — not the parser, not the timeline, not the UI — is the unit of value. Every feature must trace to a shorter, better TARR. Parsing without reporting is zero value delivered. | When someone proposes "just add another artifact parser," ask: does this change the report? If no, it waits. The last 80% (reporting) is the real problem. |
| 3 | **Practitioner First, Enterprise Later** | Design for Sarah Chen (solo IR, 1-person firm) before James Okafor (CISO, 50-person team). Solo practitioner constraints produce better software. Enterprise features come after community adoption proves the core. | You will get enterprise feature requests (SSO, RBAC, team dashboards) before you have 100 active users. Resist. Solo practitioners who love the tool will drag it into their enterprises. |
| 4 | **Open Parsers, Proprietary Integration** | Parsers are Apache 2.0 / MIT. The integration layer, pipeline, report engine, and UI are proprietary. Community trust comes from open parsers. Revenue comes from the integration that makes them useful together. | When deciding where a feature lives: if it parses a forensic artifact, it is open source. If it orchestrates, renders reports, or provides UX, it is proprietary. No exceptions. |
| 5 | **Evidence Tells a Story** | Every feature is filtered through: does this help the examiner tell the story to the attorney? If a capability does not improve narrative clarity, citation accuracy, or evidence presentation, it does not ship. | You will want to build cool visualizations, advanced analytics, and ML classifiers. Ask: does the attorney understand the output? If only the examiner understands it, it is an internal tool, not a product feature. |

---

## Explicit Non-Goals

### Features We Will Never Build

These are permanently out of scope. They are not "future phases" — they are kill list items.

| Non-Goal | Rationale | What We Do Instead |
|----------|-----------|-------------------|
| **Evidence collection / acquisition** | Collection is solved. KAPE, Velociraptor, and ACQUIRE own this space. Building collection competes with partners and dilutes focus. | Ingest KAPE/Velociraptor/ACQUIRE output as first-class evidence sources. |
| **eDiscovery platform features** | Different problem, different users, different regulatory framework. Relativity and Nuix own this. | Produce output that feeds into Relativity/Nuix workflows. Be the bridge, not the destination. |
| **Real-time SIEM / SOC monitoring** | Post-incident forensic analysis is our lane. Real-time detection is a fundamentally different architecture and buyer. | Accept evidence from SIEM exports. Analyze after the incident, not during. |
| **Mobile forensics extraction** | Cellebrite owns mobile extraction with years of reverse-engineering investment measured in millions. Not our fight. | Ingest Cellebrite exports as evidence sources. Parse mobile artifacts from collection output, never collect. |
| **Memory forensics / malware analysis** | Volatility owns memory forensics. Specialized malware analysis (sandboxing, detonation) is a different discipline entirely. | Ingest memory analysis results as supplementary evidence. Do not replicate Volatility. |
| **Cloud forensics acquisition (MVP)** | Cloud evidence collection requires API integrations with M365, Google Workspace, AWS — each a project unto itself. | Phase 2+ via plugins. Collection stays out of scope; ingest cloud exports. |
| **Competing on artifact parser count** | Magnet and Belkasoft have 800-1000+ parsers built over a decade. Competing on breadth is losing. | Compete on depth (report quality). Community plugin ecosystem closes breadth gap over time. |

### Technical Approaches We Rejected

| Rejected Approach | Why It Was Tempting | Why It Is Wrong |
|-------------------|--------------------|-----------------|
| **Enterprise-first sales motion** | Enterprise deals are larger. Firms have budgets. | Requires team features, SSO, compliance certs, and a sales team. Solo founder, bootstrapped. Practitioner adoption creates organic enterprise pull. |
| **Freemium SaaS model** | Recurring revenue, easy distribution. | Forensic evidence cannot leave the examiner's environment. Chain-of-custody requirements prohibit cloud processing. Desktop-first is non-negotiable. |
| **Cloud-first architecture** | Modern, scalable, lower barrier to trial. | Same chain-of-custody problem. Evidence stays on examiner's machine. Local-first with optional cloud sync for non-evidence data only. |
| **Compete on parse speed alone** | X-Ways is the speed benchmark; Rust can match it. | Speed without reporting is X-Ways. We already have that. The differentiator is what happens after parsing. Speed is necessary but not sufficient. |
| **AI-first marketing** | "AI-powered" is the current hype cycle. | Brand voice: no AI-powered claims. Practitioners are skeptical of AI hype. AI is an implementation detail in the reporting pipeline, not a headline feature. Quietly confident, not buzzword-driven. |

---

## Structural Patterns

### The TARR Pipeline

Every design decision maps to a stage in the TARR pipeline. If a feature does not improve a stage, it does not reduce TARR, and it does not ship.

```
Evidence Ingest → Parse → Unify Timeline → Identify Findings → Generate Narrative → Render Report
     |                |           |                |                    |                |
  KAPE/Velo      < 10 min    Unified view    Examiner-guided    AI-assisted      HTML + Word/PDF
  imports        for 50GB     across all       with suggested     with examiner    attorney-ready
                              artifact types   findings           review/edit      deliverable
```

**When to use**: Every feature proposal. Map it to a pipeline stage. No stage = no ship.

### Fallback Chain

When components fail, degrade gracefully. A partial report is infinitely better than no report.

```
Full AI Narrative → Template-Based Narrative → Structured Findings List → Raw Timeline Export → Error with Context
```

- Partial response is better than timeout
- Template fallback is better than failure
- A structured findings list an attorney can read is better than a crash
- Even raw timeline export gives the examiner something to work with

**When to use**: Every error-handling decision. Never fail to produce output.

### Conflict Resolution Hierarchy

When design values conflict, resolve in this order:

```
Correctness > Usability > Performance > Features > Polish
```

- Forensic correctness is non-negotiable (Daubert, chain of custody)
- Usability for the practitioner beats raw speed
- Performance beats feature count (do fewer things faster)
- Features beat polish (working > pretty)

---

## What We Always Do

Behaviors that must remain consistent across every release, every feature, every interaction.

| Behavior | Example |
|----------|---------|
| **Trace every feature to TARR** | Before merging any PR: "Which TARR stage does this improve and by how much?" If the answer is "it doesn't," the PR waits. |
| **Produce attorney-readable output** | Every report section must pass the "Diana Reyes test" — can a litigation support analyst understand this without calling the examiner? |
| **Maintain chain-of-custody integrity** | Every evidence transformation is logged. Hash verification at ingest. Provenance metadata in every report. No silent data modification. |
| **Ship open parsers under permissive license** | Every new artifact parser is Apache 2.0. No exceptions, no "we'll open-source it later." Community trust is built on this promise. |
| **Design for Sarah Chen first** | Solo practitioner, 3-5 active cases, needs evidence-to-deliverable fast. If it does not work for a one-person firm with no IT department, it is not ready. |
| **Use practitioner voice** | SANS DFIR Summit peer conversation tone. No marketing superlatives, no "AI-powered" claims, no startup jargon. Technically honest, quietly confident. |

---

## What We Never Do

Behaviors that are explicitly prohibited. Violating these requires a formal document update — not a "just this once."

| Behavior | Why |
|----------|-----|
| **Ship a report with unverified forensic claims** | A wrong report in court is career-ending for the examiner and legally dangerous for the attorney. Correctness > speed, always. |
| **Gate core functionality behind enterprise pricing** | Solo practitioners are our primary users. The free/affordable tier must be genuinely useful for real cases, not a crippled demo. |
| **Send evidence data to cloud services** | Chain-of-custody requirements are non-negotiable. Evidence processing is local-only. Cloud features (if any) handle metadata, licensing, and updates — never evidence. |
| **Claim AI-generated findings as examiner conclusions** | AI assists narrative generation. The examiner reviews, edits, and owns every finding. The report clearly attributes AI-assisted sections. No black-box conclusions. |
| **Break backward compatibility on open parsers** | Community contributors and downstream tools depend on parser APIs. Semver is enforced. Breaking changes require major version bumps with migration guides. |
| **Optimize for vanity metrics** | Not artifacts-parsed-per-second, not registered users, not feature count, not revenue-per-user. TARR is the metric. Everything else is a distraction. |

---

## When to Re-evaluate

This document is not permanent — but changes require deliberate decision-making, not drift.

### Metric Triggers

| Signal | Threshold | What to Do |
|--------|-----------|------------|
| TARR plateaus above 4 hours | For 3 consecutive release cycles despite pipeline improvements | Re-examine pipeline architecture. The bottleneck has shifted — find it. |
| Report Acceptance Rate below 60% | Attorneys requesting rework on > 40% of reports for 4+ weeks | Report format or narrative quality is failing. Pause features, fix report engine. |
| Community parser contributions stall | Fewer than 2 community PRs per quarter after 6 months post-launch | Open-source strategy is not working. Evaluate developer experience, documentation, or licensing friction. |
| Parse-to-Timeline exceeds 10 min target | For standard 50GB evidence sets across 3 test cases | Core engine performance regression. Profile and fix before adding features. |

### External Triggers

| Signal | What to Do |
|--------|------------|
| A competitor ships attorney-ready reports | Our primary differentiator is threatened. Evaluate their quality. Accelerate report engine innovation. Consider pivoting differentiator to speed + quality combination. |
| Daubert challenge standards shift significantly | Update report templates and citation formats. Legal compliance is non-negotiable — this is an emergency priority. |
| PE firm acquires a major open-source DFIR tool | Validates our open-core model. Monitor for license changes. Accelerate community building to become the trusted alternative. |
| Major collection tool changes export format | KAPE/Velociraptor format changes break ingest. Fix immediately — ingest is the pipeline entry point. |

### Strategic Triggers

| Signal | What to Do |
|--------|------------|
| Solo founder capacity ceiling reached | Evaluate: hire first employee vs. raise funding vs. reduce scope. The constraint "solo founder, bootstrapped" may need to evolve. |
| Enterprise demand exceeds 20% of inbound interest | The practitioner-first strategy is generating enterprise pull. Begin scoping Phase 2 enterprise features (team, RBAC, audit trail). Do not abandon practitioner-first — layer enterprise on top. |
| Consulting revenue insufficient to fund development | The bootstrap model is stalling. Evaluate: accelerate paid tier launch, seek strategic investment, or find consulting-development synergies. |

---

## Document Governance

| Aspect | Rule |
|--------|------|
| **Owner** | Founder (sole decision-maker for strategic direction) |
| **Review Cadence** | Every 90 days or when a trigger above fires |
| **Change Process** | Update this document first, then change code. Never the reverse. |
| **Scope** | This document governs product decisions. Technical implementation details live in ARCHITECTURE_BLUEPRINT. |
| **Derived From** | BRAND_GUIDELINES (beliefs, voice, kill list), NORTHSTAR (metric, personas, phases), COMPETITIVE_LANDSCAPE (positioning, rejected moves, market shifts) |
