# Issen™: Brand Guidelines

<!-- GENERATION: This is Step 1 of 13 in the generation order. See GENERATION_MANIFEST.md -->

> **Tier**: 3 — Supporting (see [INDEX.md](INDEX.md))
> **Created**: 2026-03-20
> **Status**: Active
> **Generation Step**: 1 of 13 — Generate this FIRST before all other templates

Identity, positioning, and principles for the Issen brand.

---

## Brand Essence

**Issen** — from two forensic fundamentals: *rapid* (speed under pressure) and *triage* (prioritized analysis when you can't examine everything). The name is the methodology.

An integrated forensic triage platform that bridges the forensic-to-legal translation gap, turning raw artifacts into attorney-ready deliverables.

### Positioning Statement

> **Issen is a forensic triage platform** that transforms digital forensic artifacts into attorney-ready reports and interactive explorations for IR practitioners, forensic examiners, and litigation support teams. Unlike EnCase, Autopsy, and other forensic tools that produce engineer-oriented output requiring hours of manual translation, Issen produces deliverables that attorneys can actually use — without calling the examiner back.

### Core Tagline

> "Evidence tells a story."

---

## Brand Identity

### The Name

**Issen** is one word, capital R, capital T. Never "Rapid Triage" (two words), never "issen" (all lowercase), never "RAPIDTRIAGE" (all caps except in headings that are stylistically all-caps).

The name works because every DFIR practitioner already thinks in these terms. You land on-site, you have limited time, you triage. The name is not marketing — it is the job.

### Logo

The logo has not been finalized. When designed, it should follow these principles:

| Element | Meaning |
|---------|---------|
| **Wordmark** | Clean, monospaced or semi-monospaced type reflecting terminal/CLI heritage |
| **Accent mark** | A subtle visual element evoking a timeline or signal extraction from noise |
| **Monochrome variant** | Must work in pure black on white for printed court exhibits |

**Usage Requirements:**
- Always include the ™ symbol on first use in any document or page
- Minimum clear space: the height of the "R" on all sides
- Never place the logo on busy backgrounds — courtroom credibility demands clarity
- Logo assets will be available at `brand/` in the repository root once finalized

### Color Philosophy

**Primary: Slate Blue (#475569)**

We chose slate blue over alternatives for strategic reasons:

| Color Option | Why We Rejected It |
|--------------|-------------------|
| Red / Orange | Signals alarm, urgency, danger — we are the calm after the storm, not the storm |
| Bright Blue (#3B82F6) | Too SaaS-startup, too "dashboard product" — we are a practitioner tool |
| Black / Dark Gray | Too stark, feels like a hacker tool — we need courtroom credibility, not edginess |

**Slate blue signals:**
- Professional authority without corporate stuffiness
- Calm analytical clarity — the examiner's mindset
- Trustworthiness in contexts where evidence presentation matters (courtrooms, boardrooms)

**Accent: Amber (#D97706)** — Used sparingly for warnings, key findings, and critical timeline events. Amber is the universal "pay attention" signal that works for both analysts (flagged artifacts) and attorneys (key evidence).

**Accessibility:** All color combinations meet WCAG AA standards (4.5:1 minimum contrast ratio). Reports destined for print or court use must also pass in grayscale.

### Typography

| Use | Font | Character |
|-----|------|-----------|
| Headlines | Inter or system sans-serif | Clean, professional, reads well in reports and slides |
| Body | Inter or system sans-serif | High readability at small sizes; works in dense forensic tables |
| Code / Artifacts | JetBrains Mono or system monospace | Distinguishes file paths, registry keys, and artifact values from narrative text |

---

## Voice & Tone

### Personality

| Trait | Expression |
|-------|------------|
| **Practitioner-first** | Write like you are explaining to a peer at SANS DFIR Summit, not pitching to a CTO |
| **Direct** | State what it does. Skip the preamble. Examiners do not have time for fluff |
| **Technically honest** | If a parser is experimental, say so. Never oversell capability — credibility is non-negotiable in forensics |
| **Quietly confident** | The work speaks. We do not need superlatives or exclamation marks |
| **Outcome-oriented** | Features matter less than what the examiner can now hand to the attorney |

### Writing Principles

**Do:**
- Use forensic terminology correctly — MFT, USN Journal, prefetch, not "system files" or "digital clues"
- Lead with the outcome: "Produce a timeline the attorney can filter by custodian" not "Advanced timeline generation capabilities"
- Acknowledge limitations honestly: "Currently parses Windows NTFS artifacts; macOS and Linux support is on the roadmap"
- Write in second person when addressing practitioners: "You run the parser, you get the report"

**Don't:**
- Use marketing superlatives: "revolutionary," "game-changing," "next-generation," "AI-powered"
- Dumb down forensic concepts for the sake of broader appeal — our users know what a USN Journal is
- Promise capabilities that are not shipped: if it is on the roadmap, say "planned" not "supports"
- Use passive voice to hide limitations: say "Issen does not yet parse APFS" not "APFS parsing may be available in future releases"

### Language Examples

| Instead of... | Write... |
|---------------|----------|
| "Leverage our cutting-edge forensic analysis engine" | "Parse artifacts. Build timelines. Hand the report to counsel." |
| "Seamlessly integrates with your workflow" | "Reads KAPE and Velociraptor output directly — no reprocessing" |
| "AI-powered intelligent analysis" | "Sigma rule matching against unified timeline events" |
| "Enterprise-grade reporting solution" | "Word and PDF reports formatted for expert witness submission" |

---

## Core Beliefs

These beliefs shape every brand decision:

### Evidence Tells a Story

Raw forensic data is noise. Thousands of MFT entries, tens of thousands of USN Journal records, scattered prefetch files — none of that is useful until an examiner identifies the signal and constructs a narrative. Issen exists to help examiners build that narrative faster. Every feature decision is filtered through: "Does this help the examiner tell the story of what happened on this system?" If the answer is no, it does not ship.

### The Last 80% Is the Real Problem

Forensic analysis is roughly 20% of an engagement's cost. The other 80% is report writing, evidence reprocessing into attorney-digestible formats, and back-and-forth where counsel asks "what does this mean?" and the examiner translates. Every other forensic tool treats the analysis as the product and the report as an afterthought. We treat the report — the thing the attorney actually reads, the thing the jury actually sees — as the product. Analysis is the means; the deliverable is the end.

### By Practitioners, For Practitioners

Issen is built by someone who has been on-site at 2 AM imaging drives and spent the next three weeks writing the report. The tool reflects real workflow, not theoretical workflow. This means: ingest what KAPE and Velociraptor actually produce (not some idealized input format), output what attorneys actually need (not what looks good in a demo), and never require the examiner to fight the tool to get work done. If a feature does not map to something an examiner actually does during an investigation, it is scope creep.

### Open Parsers, Integrated Platform

Individual artifact parsers should be open source. The forensic community benefits when anyone can parse a USN Journal or read an E01 image. But the integration — the unified pipeline that correlates across artifact types, builds timelines, and produces attorney-ready reports — that is the product. Open-source the building blocks; the architecture is the moat. This is not an ideology compromise; it is the correct engineering and business decision. Parsers commoditize. Integration differentiates.

### Correctness Over Speed (But Aim for Both)

In forensics, a wrong result is worse than no result. If a parser produces inaccurate timestamps or misattributes file activity, that error ends up in a court filing. Issen will never sacrifice correctness for performance. That said, "correct and slow" is not acceptable either — Rust was chosen specifically because it does not force that tradeoff. The goal is correct results at speeds that make triage practical on multi-terabyte evidence stores.

---

## What We're Not

| We Are Not | Why This Matters |
|------------|------------------|
| **Not a collection tool** | Issen ingests output from KAPE, Velociraptor, Magnet ACQUIRE, and other collectors. It does not touch endpoints. Collection is a solved problem with excellent existing tools — we start where they finish. |
| **Not an eDiscovery platform** | We produce evidence packages that feed into Relativity, Nuix, and similar platforms. We do not replace document review, predictive coding, or legal hold workflows. Different problem, different users. |
| **Not a SIEM or SOC tool** | Issen is post-incident forensic analysis, not real-time detection or monitoring. By the time Issen is involved, the incident has already happened and someone needs to figure out what occurred. |
| **Not an "enterprise platform" first** | We are building for the solo examiner and the small IR team first. Enterprise features (SSO, team collaboration, audit trails) come later. The tool must be excellent for one person before it scales to fifty. |
| **Not a competitor to the examiner** | Issen does not replace forensic expertise. It eliminates the tedious translation work so the examiner can focus on analysis and expert opinion — the parts that actually require a human. |

---

## Design Principles

### Visual Aesthetic

| Principle | Expression |
|-----------|------------|
| **Dense but organized** | Forensic data is inherently dense. Do not hide it behind progressive disclosure — show it in well-structured tables and timelines. Examiners want to see the data, not click through wizards to find it. |
| **Print-ready** | Every visual element must work when printed in black and white on letter-size paper. Court exhibits do not have hover states. |
| **Monospace where it matters** | File paths, registry keys, hashes, and timestamps in monospace. Narrative text in proportional. The visual distinction between "data" and "analysis" should be immediate. |
| **Minimal chrome** | Reduce UI elements that are not data or controls. The examiner's attention should be on the evidence, not on the application's visual design. |

### Why These Choices?

**Dense information display over progressive disclosure:**
Forensic examiners are trained to scan large datasets. Hiding data behind clicks and expandable sections slows them down. The aesthetic reference is a well-organized forensic report or an analyst's spreadsheet — not a consumer dashboard.

**Courtroom-credible visual design:**
Issen output may be projected in a courtroom, printed as an exhibit, or attached to a declaration. Every visual choice must survive the question: "Would this look professional and credible to a judge?" Flashy gradients, dark themes with neon accents, and playful illustrations fail this test.

**Rust-native CLI aesthetic:**
The brand reflects its technical foundation. Clean terminal output, structured logging, and composable CLI tools are the interface philosophy. A GUI may come later, but the soul of the tool is `issen parse --source /evidence/kape-output --report expeissen-witness.docx`.

---

## Anti-Patterns

What we explicitly avoid in brand expression:

| Anti-Pattern | Why We Avoid It |
|--------------|-----------------|
| "AI-powered" or "machine learning" claims | Forensic findings must be explainable and defensible. Black-box claims undermine courtroom credibility. If we use ML, we describe what it does specifically, not wave the AI flag. |
| Startup jargon ("disrupt," "10x," "paradigm shift") | Our audience builds forensic reports that get cross-examined. They have zero tolerance for hype. |
| Stock photos of hooded hackers or green Matrix text | This aesthetic signals "we do not understand the field." Real forensics is spreadsheets, timelines, and hex editors — not Hollywood. |
| Feature-count marketing ("50+ parsers! 100+ artifacts!") | Quantity claims invite the question "how well does each one work?" Lead with quality and correctness, not counts. |
| "Enterprise-ready" as a primary selling point | Signals bloat, procurement-driven design, and six-figure price tags. We are practitioner-ready first. |
| Dark/hacker-themed UI | Undermines the courtroom-credibility goal. The output must look as professional as a Big Four consulting deliverable, not a CTF challenge. |

---

## Social Positioning

How users describe Issen to others matters. We design for the moment when someone asks "What's Issen?"

### What Users Tell Others

Different audiences need different framings:

| Audience | Preferred Framing |
|----------|-------------------|
| Fellow DFIR examiner | "It's a triage platform — you point it at KAPE output, it builds the timeline and produces a report you can hand directly to the attorney." |
| Litigation support / paralegal | "The forensic examiner's tool that produces reports we can actually read without calling them back to explain every line." |
| Attorney / partner | "It translates forensic findings into exhibits and reports formatted for court. Interactive HTML for exploration, polished Word docs for the record." |
| IT manager / CISO | "Forensic triage tool that cuts engagement time. The examiner spends more time analyzing and less time writing." |
| Open-source community | "Rust-based forensic parsers (Apache 2.0 / MIT) with a commercial integration layer. Like how Elastic built on open-source components." |

### Addressing Skepticism

Users may encounter skepticism about a new forensic tool. Provide language that reframes:

| Skepticism | Reframe |
|------------|---------|
| "Why not just use EnCase/FTK/Autopsy?" | "Those tools are great at analysis. Issen is great at everything that happens after analysis — the report writing, the attorney back-and-forth, the exhibit preparation. Use both." |
| "How can a solo-founded tool be reliable enough for court?" | "The open-source parsers are community-reviewed and field-tested. usnjrnl-forensic has been used in real investigations since v0.3. Reliability comes from Rust's safety guarantees and forensic validation suites, not team size." |
| "Another forensic tool nobody asked for?" | "Practitioners asked for it every time they spent three weeks writing a report for a two-day analysis. The analysis tools exist. The reporting gap does not have a solution." |

### Brand Voice in Social Context

When users share or discuss Issen publicly:

**Do:**
- Share specific outcomes: "Reduced report writing from 3 weeks to 3 days on a 4TB evidence set"
- Reference real forensic workflows and artifact types
- Credit the open-source community and upstream projects
- Engage technically — answer questions with specifics, not hand-waving

**Don't:**
- Make broad claims about "transforming digital forensics"
- Compare by denigrating other tools — the community is small and people remember
- Use engagement-bait or meme formats — credibility is the brand's most valuable asset
- Reveal client investigation details, even anonymized, without explicit permission

### Social Proof Strategy

We let the work demonstrate quality but do emphasize:
- Real-world investigation use: parsers tested against forensic images from actual engagements (never client data — always lab-generated or CTF datasets for public demos)
- Community contributions: PRs, issues, and forks as evidence that practitioners trust the code
- Conference presence: SANS DFIR Summit, OSDFCon, and similar practitioner-focused venues — not generic tech conferences
- Examiner testimonials over executive endorsements: the person who used the tool at 2 AM matters more than the VP who approved the purchase order

---

## Licensing & Ethics

### Dual License: Open Source Components + Proprietary Platform

We chose a dual-licensing model — Apache 2.0 and MIT for open-source components, proprietary closed-source for the integration platform — because it aligns with how the forensic community actually works.

**Why this model?**

Forensic practitioners need to trust their tools. Open-source parsers mean any examiner can read the code, verify the logic, and testify about how the tool produced its output. "I used a proprietary parser and I cannot explain how it works" is a losing answer on cross-examination. Open parsers are not generosity — they are a forensic requirement.

The integration layer — the unified pipeline, correlation engine, and report generator — is proprietary because that is where the engineering investment and competitive moat live. Individual parsers are commodities; the platform that ties them together and produces attorney-ready output is the product.

**Open-source components (Apache 2.0 / MIT):**
- Artifact parsers (USN Journal, MFT, Prefetch, Event Logs, etc.)
- Data source readers (E01, raw disk, file system)
- Utility libraries (path handling, timestamp normalization)
- Permissive licenses maximize adoption — any forensic tool can use these parsers

**Proprietary components (closed source):**
- Unified analysis pipeline and correlation engine
- Report generation engine (interactive HTML, Word/PDF)
- User interface and visualization layer
- Enterprise features (SSO, team collaboration, audit)

**Ethical commitments:**
- Never build features designed to fabricate, alter, or misrepresent forensic evidence
- Never implement "audit-proof" or evidence-hiding capabilities
- Maintain chain-of-custody integrity in all output — every finding is traceable to its source artifact
- Open-source parsers will remain open-source permanently — no license rug-pulls

---

## Brand Governance

### Trademark

**Issen™** is a trademark of its creator.

The ™ symbol should be used consistently across:
- Website header and footer
- Page titles and metadata
- Documentation (first use per page)
- Marketing materials

### Questions?

Brand-related questions, logo requests, and partnership inquiries: open an issue on the Issen GitHub repository or contact the maintainer directly through GitHub (@h4x0r).

---

*Document generated by North Star Advisor*
