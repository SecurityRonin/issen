# Issen Documentation Hub

> **Integrated forensic triage platform with attorney-ready output**

This index is the entry point to all Issen strategic and technical documentation.
Every document listed here was generated during the North Star Advisor planning process
and is the authoritative reference for the project.

**Last updated**: 2026-03-20
**Documents**: 23 (12 core + 4 UX + 7 deep architecture)
**Status**: All documents Active

---

## Table of Contents

1. [Document Hierarchy](#1-document-hierarchy)
2. [Architecture Blueprint Modules](#2-architecture-blueprint-modules)
3. [Design Documents](#3-design-documents)
4. [Quick Reference](#4-quick-reference)
5. [Decision Authority](#5-decision-authority)
6. [Document Dependencies](#6-document-dependencies)
7. [Current State](#7-current-state)
8. [Contributing to Documentation](#8-contributing-to-documentation)

---

## 1. Document Hierarchy

Documents are organized into three authority tiers. When documents conflict,
the lower tier number wins.

```
                    ┌─────────────────────────────────────┐
                    │          TIER 1 — STRATEGIC          │
                    │            (Authority: Highest)       │
                    │                                       │
                    │   NORTHSTAR.md          (43KB)        │
                    │   COMPETITIVE_LANDSCAPE.md (50KB)     │
                    │   NORTHSTAR_EXTRACT.md  (14KB)        │
                    │   STRATEGIC_RECOMMENDATION.md (33KB)  │
                    │   ACTION_ROADMAP.md     (37KB)        │
                    └──────────────────┬──────────────────┘
                                       │
                    ┌──────────────────▼──────────────────┐
                    │       TIER 2 — IMPLEMENTATION        │
                    │          (Authority: Medium)          │
                    │                                       │
                    │   ARCHITECTURE_BLUEPRINT.md (53KB)    │
                    │   SECURITY_ARCHITECTURE.md (56KB)     │
                    │   ADR.md                   (45KB)     │
                    │   POST_DEPLOYMENT.md       (36KB)     │
                    │   architecture/*       (7 documents)  │
                    │   design/*             (4 documents)  │
                    └──────────────────┬──────────────────┘
                                       │
                    ┌──────────────────▼──────────────────┐
                    │        TIER 3 — SUPPORTING           │
                    │           (Authority: Lowest)         │
                    │                                       │
                    │   BRAND_GUIDELINES.md   (18KB)        │
                    └─────────────────────────────────────┘
```

---

## 2. Architecture Blueprint Modules

The `architecture/` subdirectory expands on [ARCHITECTURE_BLUEPRINT.md](./ARCHITECTURE_BLUEPRINT.md)
with deep-dive documents covering each implementation concern.

```
ARCHITECTURE_BLUEPRINT.md (53KB)
│
├── architecture/
│   ├── AGENT_PROMPTS.md            (40KB)  — 6 agent system prompts with TARR budgets
│   ├── PIPELINE_ORCHESTRATION.md   (34KB)  — Layer 0-4 pipeline, state schema, execution
│   ├── RESILIENCE_PATTERNS.md      (57KB)  — Circuit breakers, fallback chains, timeouts
│   ├── IMPLEMENTATION_SCAFFOLD.md  (44KB)  — Directory structure, Cargo workspace, CI/CD
│   ├── OBSERVABILITY.md            (34KB)  — Tracing, TARR instrumentation, TUI dashboard
│   ├── TESTING_STRATEGY.md         (52KB)  — Golden datasets, fuzz testing, Daubert validation
│   ├── HANDOFF_PROTOCOL.md         (32KB)  — Dev-time and runtime handoff contracts
│   └── INTELLIGENCE_LAYER.md       (60KB)  — RAG, model routing, grounded generation
│
└── SECURITY_ARCHITECTURE.md (56KB)         — Threat model, trust boundaries, kill switches
```

**Reading order for implementers**: ARCHITECTURE_BLUEPRINT -> PIPELINE_ORCHESTRATION ->
IMPLEMENTATION_SCAFFOLD -> HANDOFF_PROTOCOL -> RESILIENCE_PATTERNS -> OBSERVABILITY ->
TESTING_STRATEGY -> INTELLIGENCE_LAYER -> AGENT_PROMPTS -> SECURITY_ARCHITECTURE

---

## 3. Design Documents

The `design/` subdirectory covers user experience from journey maps through pixel-level
wireframes.

```
design/
├── USER_JOURNEYS.md      (41KB)  — 4 journey maps (Core TARR, Multi-Source, Attorney, Plugin Dev)
├── UI_DESIGN_SYSTEM.md   (44KB)  — Multi-surface tokens (CSS + Rust TUI), 12 artifact colors
├── ACCESSIBILITY.md      (48KB)  — WCAG 2.1 AA, multi-surface matrix, 3-phase implementation
└── WIREFRAMES.md         (70KB)  — ASCII wireframes for CLI, TUI, HTML report, Tauri GUI
```

**Reading order for designers**: USER_JOURNEYS -> UI_DESIGN_SYSTEM -> WIREFRAMES -> ACCESSIBILITY

---

## 4. Quick Reference

| # | Document | Tier | Size | Purpose | When to Use |
|---|----------|------|------|---------|-------------|
| 1 | [BRAND_GUIDELINES.md](./BRAND_GUIDELINES.md) | 3 | 18KB | Brand identity, voice, visual standards, licensing model | Naming decisions, marketing copy, license questions |
| 2 | [NORTHSTAR.md](./NORTHSTAR.md) | 1 | 43KB | North Star metric (TARR), personas, phases, success criteria | Prioritization disputes, defining "done", scope questions |
| 3 | [COMPETITIVE_LANDSCAPE.md](./COMPETITIVE_LANDSCAPE.md) | 1 | 50KB | 10 competitors, market sizing, timing windows, positioning | Feature prioritization, "build vs. buy", market positioning |
| 4 | [NORTHSTAR_EXTRACT.md](./NORTHSTAR_EXTRACT.md) | 1 | 14KB | 5 axioms, non-goals, patterns, always/never behaviors | Quick strategic checks, code review alignment |
| 5 | [ARCHITECTURE_BLUEPRINT.md](./ARCHITECTURE_BLUEPRINT.md) | 2 | 53KB | Hexagonal architecture, 13 crates, DuckDB+SQLite, plugins, AI, open-core | System design, crate boundaries, tech stack questions |
| 6 | [architecture/AGENT_PROMPTS.md](./architecture/AGENT_PROMPTS.md) | 2 | 40KB | 6 specialized development agent prompts with TARR budgets | Agent development, prompt engineering, TARR allocation |
| 7 | [SECURITY_ARCHITECTURE.md](./SECURITY_ARCHITECTURE.md) | 2 | 56KB | 6 threat scenarios, 4 trust boundaries, 8 defense layers, 5 kill switches | Security reviews, threat modeling, trust boundary questions |
| 8 | [ADR.md](./ADR.md) | 2 | 45KB | 14 architecture decision records from planning phases | Understanding "why" behind decisions, revisiting past choices |
| 9 | [POST_DEPLOYMENT.md](./POST_DEPLOYMENT.md) | 2 | 36KB | Operations runbook for desktop forensic app, solo founder | Release process, monitoring, incident response |
| 10 | [STRATEGIC_RECOMMENDATION.md](./STRATEGIC_RECOMMENDATION.md) | 1 | 33KB | Path B (Report Engine First) with decision matrix | Build-order disputes, strategic pivots, investment decisions |
| 11 | [ACTION_ROADMAP.md](./ACTION_ROADMAP.md) | 1 | 37KB | 90-day plan: Foundation, Breadth, Intelligence+Community | Sprint planning, milestone tracking, resource allocation |
| 12 | [INDEX.md](./INDEX.md) | — | — | This document: documentation hub and navigation | Finding any document, understanding doc relationships |
| 13 | [design/USER_JOURNEYS.md](./design/USER_JOURNEYS.md) | 2 | 41KB | 4 journey maps (Core TARR, Multi-Source, Attorney, Plugin Dev) | UX decisions, feature scoping, persona alignment |
| 14 | [design/UI_DESIGN_SYSTEM.md](./design/UI_DESIGN_SYSTEM.md) | 2 | 44KB | Multi-surface tokens (CSS + Rust TUI), 12 artifact colors | UI implementation, theming, component design |
| 15 | [design/ACCESSIBILITY.md](./design/ACCESSIBILITY.md) | 2 | 48KB | WCAG 2.1 AA, multi-surface matrix, 3-phase implementation | Accessibility audits, compliance verification |
| 16 | [design/WIREFRAMES.md](./design/WIREFRAMES.md) | 2 | 70KB | ASCII wireframes for CLI, TUI, HTML report, Tauri GUI | Layout decisions, component placement, surface parity |
| 17 | [architecture/PIPELINE_ORCHESTRATION.md](./architecture/PIPELINE_ORCHESTRATION.md) | 2 | 34KB | Layer 0-4 pipeline, state schema, execution patterns | Pipeline implementation, layer contracts, state management |
| 18 | [architecture/RESILIENCE_PATTERNS.md](./architecture/RESILIENCE_PATTERNS.md) | 2 | 57KB | Circuit breakers, fallback chains, timeout handling | Error handling, degradation strategy, reliability work |
| 19 | [architecture/IMPLEMENTATION_SCAFFOLD.md](./architecture/IMPLEMENTATION_SCAFFOLD.md) | 2 | 44KB | Directory structure, Cargo workspace, CI/CD | Project setup, CI pipeline, build configuration |
| 20 | [architecture/OBSERVABILITY.md](./architecture/OBSERVABILITY.md) | 2 | 34KB | Tracing, TARR instrumentation, TUI dashboard | Telemetry, debugging, performance monitoring |
| 21 | [architecture/TESTING_STRATEGY.md](./architecture/TESTING_STRATEGY.md) | 2 | 52KB | Golden datasets, fuzz testing, Daubert validation | Test planning, validation approach, legal defensibility |
| 22 | [architecture/HANDOFF_PROTOCOL.md](./architecture/HANDOFF_PROTOCOL.md) | 2 | 32KB | Dev-time and runtime handoff contracts | Agent boundaries, typed contracts, delegation rules |
| 23 | [architecture/INTELLIGENCE_LAYER.md](./architecture/INTELLIGENCE_LAYER.md) | 2 | 60KB | RAG, model routing, grounded generation, evaluation | AI/ML integration, LLM orchestration, retrieval design |

**Additional files** (not numbered documents, but useful references):

| File | Purpose |
|------|---------|
| [../ai-context.yml](../ai-context.yml) | Progressive strategic context (machine-readable YAML) |
| [../research/summary.md](../research/summary.md) | Synthesized domain research from planning phases |

---

## 5. Decision Authority

When documents disagree, the higher-authority tier wins:

```
TIER 1  >  TIER 2  >  TIER 3
(Strategic)  (Implementation)  (Supporting)
```

### Rules

1. **Tier 1 overrides everything.** If NORTHSTAR.md says the metric is TARR and
   ARCHITECTURE_BLUEPRINT.md measures something else, TARR wins.

2. **Within a tier, specificity wins.** A targeted statement in SECURITY_ARCHITECTURE.md
   about encryption overrides a general statement in ARCHITECTURE_BLUEPRINT.md about
   data handling, because both are Tier 2 but Security is more specific on that topic.

3. **Newer ADR overrides older ADR.** Architecture Decision Records in [ADR.md](./ADR.md)
   are numbered chronologically. Later decisions supersede earlier ones on the same topic.

4. **NORTHSTAR_EXTRACT.md is the quick-check filter.** Its axioms and always/never lists
   are distilled from NORTHSTAR.md. If something violates an axiom, it violates the
   North Star, full stop.

5. **STRATEGIC_RECOMMENDATION.md resolves path ambiguity.** When ACTION_ROADMAP.md and
   ARCHITECTURE_BLUEPRINT.md could support multiple build orders, the Strategic
   Recommendation (Path B: Report Engine First) is the tiebreaker.

6. **design/ documents are authoritative for UX.** Within Tier 2, design documents
   override architecture documents on user-facing decisions (layout, interaction,
   accessibility). Architecture documents override on system internals.

---

## 6. Document Dependencies

The following diagram shows how documents reference and depend on each other.
Arrows point from the dependent document to its dependency.

```
                         ┌──────────────┐
                         │  NORTHSTAR   │
                         │   (43KB)     │
                         └──────┬───────┘
                                │
              ┌─────────────────┼──────────────────┐
              │                 │                   │
              ▼                 ▼                   ▼
   ┌──────────────────┐ ┌──────────────┐ ┌──────────────────┐
   │   COMPETITIVE    │ │  NORTHSTAR   │ │    STRATEGIC     │
   │   LANDSCAPE      │ │  EXTRACT     │ │  RECOMMENDATION  │
   │    (50KB)        │ │   (14KB)     │ │     (33KB)       │
   └────────┬─────────┘ └──────┬───────┘ └────────┬─────────┘
            │                  │                   │
            └─────────┬────────┘                   │
                      │                            │
                      ▼                            ▼
           ┌──────────────────┐         ┌──────────────────┐
           │   ARCHITECTURE   │         │  ACTION_ROADMAP  │
           │   BLUEPRINT      │         │     (37KB)       │
           │    (53KB)        │         └────────┬─────────┘
           └────────┬─────────┘                  │
                    │                            │
       ┌────────────┼────────────┐               │
       │            │            │               │
       ▼            ▼            ▼               ▼
┌────────────┐┌──────────┐┌──────────────┐┌──────────────┐
│architecture/││ design/  ││  SECURITY    ││    POST      │
│ (7 docs)   ││ (4 docs) ││ ARCHITECTURE ││ DEPLOYMENT   │
│            ││          ││   (56KB)     ││   (36KB)     │
└────────────┘└──────────┘└──────────────┘└──────────────┘
       │            │            │               │
       └────────────┼────────────┘               │
                    │                            │
                    ▼                            │
              ┌──────────┐                       │
              │  ADR.md  │◄──────────────────────┘
              │  (45KB)  │
              └──────────┘
                    │
                    ▼
           ┌──────────────┐      ┌──────────────────┐
           │ BRAND        │      │  ai-context.yml   │
           │ GUIDELINES   │      │  (machine-readable│
           │  (18KB)      │      │   summary of all) │
           └──────────────┘      └──────────────────┘
```

### Key Dependency Chains

- **Strategic chain**: NORTHSTAR -> NORTHSTAR_EXTRACT -> STRATEGIC_RECOMMENDATION -> ACTION_ROADMAP
- **Architecture chain**: ARCHITECTURE_BLUEPRINT -> PIPELINE_ORCHESTRATION -> RESILIENCE_PATTERNS -> OBSERVABILITY
- **Implementation chain**: IMPLEMENTATION_SCAFFOLD -> TESTING_STRATEGY -> HANDOFF_PROTOCOL
- **AI chain**: INTELLIGENCE_LAYER -> AGENT_PROMPTS
- **UX chain**: USER_JOURNEYS -> UI_DESIGN_SYSTEM -> WIREFRAMES -> ACCESSIBILITY
- **Cross-cutting**: SECURITY_ARCHITECTURE references both architecture and design chains

---

## 7. Current State

All documents were generated during the North Star Advisor planning process on 2026-03-20.

| # | Document | Status | Date | Phase |
|---|----------|--------|------|-------|
| 1 | BRAND_GUIDELINES.md | Active | 2026-03-20 | Phase 1 |
| 2 | NORTHSTAR.md | Active | 2026-03-20 | Phase 2 |
| 3 | COMPETITIVE_LANDSCAPE.md | Active | 2026-03-20 | Phase 3 |
| 4 | NORTHSTAR_EXTRACT.md | Active | 2026-03-20 | Phase 4 |
| 5 | ARCHITECTURE_BLUEPRINT.md | Active | 2026-03-20 | Phase 6 |
| 6 | architecture/AGENT_PROMPTS.md | Active | 2026-03-20 | Phase 7 |
| 7 | SECURITY_ARCHITECTURE.md | Active | 2026-03-20 | Phase 8 |
| 8 | ADR.md | Active | 2026-03-20 | Phase 9 |
| 9 | POST_DEPLOYMENT.md | Active | 2026-03-20 | Phase 10 |
| 10 | STRATEGIC_RECOMMENDATION.md | Active | 2026-03-20 | Phase 11 |
| 11 | ACTION_ROADMAP.md | Active | 2026-03-20 | Phase 12 |
| 12 | INDEX.md | Active | 2026-03-20 | Phase 13 |
| 13 | design/USER_JOURNEYS.md | Active | 2026-03-20 | Phase 5a |
| 14 | design/UI_DESIGN_SYSTEM.md | Active | 2026-03-20 | Phase 5b |
| 15 | design/ACCESSIBILITY.md | Active | 2026-03-20 | Phase 5c |
| 16 | design/WIREFRAMES.md | Active | 2026-03-20 | Phase 5d |
| 17 | architecture/PIPELINE_ORCHESTRATION.md | Active | 2026-03-20 | Phase 7d |
| 18 | architecture/RESILIENCE_PATTERNS.md | Active | 2026-03-20 | Phase 7d |
| 19 | architecture/IMPLEMENTATION_SCAFFOLD.md | Active | 2026-03-20 | Phase 7d |
| 20 | architecture/OBSERVABILITY.md | Active | 2026-03-20 | Phase 7d |
| 21 | architecture/TESTING_STRATEGY.md | Active | 2026-03-20 | Phase 7d |
| 22 | architecture/HANDOFF_PROTOCOL.md | Active | 2026-03-20 | Phase 7d |
| 23 | architecture/INTELLIGENCE_LAYER.md | Active | 2026-03-20 | Phase 7d |

**Total documentation**: ~900KB across 23 documents.

---

## 8. Contributing to Documentation

### Updating Existing Documents

1. **Check the tier** of the document you are modifying (see [Section 1](#1-document-hierarchy)).
   Changes to Tier 1 documents require more scrutiny because they cascade into Tier 2 and 3.

2. **Search for cross-references.** Other documents may reference the section you are changing.
   Use `grep -r "document_name" north-star-advisor/docs/` to find inbound references.

3. **Update ai-context.yml** if your change affects any field already captured there.
   This file is the machine-readable summary consumed by AI agents.

4. **Update this INDEX.md** if you add, remove, or rename a document.

### Adding New Documents

1. **Determine the tier.** Strategic documents go in Tier 1 (rare — requires strong justification).
   Most new documents will be Tier 2 implementation documents.

2. **Choose the right subdirectory:**
   - `docs/` — Core documents that stand alone
   - `docs/architecture/` — Deep dives on architecture topics, referenced by ARCHITECTURE_BLUEPRINT.md
   - `docs/design/` — UX and design documents, referenced by the design chain

3. **Follow naming conventions:**
   - Use `SCREAMING_SNAKE_CASE.md` for document filenames
   - Use descriptive names that indicate the document's primary concern
   - Keep filenames under 30 characters

4. **Register the document:**
   - Add an entry to the Quick Reference table in this INDEX.md
   - Add an entry to the Current State table
   - Update the relevant tree diagram (architecture or design)
   - Add to ai-context.yml if it contains machine-relevant data

5. **Include standard front matter:**
   - Document title as H1
   - One-line purpose statement
   - Date and version
   - Table of contents for documents over 20KB

### Document Lifecycle

| Status | Meaning |
|--------|---------|
| Active | Current and authoritative |
| Draft | Work in progress, not yet authoritative |
| Superseded | Replaced by a newer document (link to replacement) |
| Archived | No longer relevant but preserved for history |

### Style Guidelines

- Write in active voice with concrete, specific language
- Avoid generic filler ("best practices", "industry standard") without backing specifics
- Use ASCII art for diagrams to keep documents portable and diff-friendly
- Include "When to use this document" guidance in every new document
- Cross-reference related documents with relative links
- Every table should have a header row and be properly aligned

---

*This documentation hub was generated as Phase 13 of 13 in the North Star Advisor planning process for Issen.*
