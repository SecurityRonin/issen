# Issen: Wireframes

> **Parent**: [UI_DESIGN_SYSTEM.md](UI_DESIGN_SYSTEM.md)
> **Related**: [USER_JOURNEYS.md](USER_JOURNEYS.md), [ACCESSIBILITY.md](ACCESSIBILITY.md), [../BRAND_GUIDELINES.md](../BRAND_GUIDELINES.md)
> **Generation Step**: 5d of 13 -- Requires `journeys.*`, `ui.*`, `a11y.*`, `brand.*`
> **Created**: 2026-03-20
> **Status**: Active
> **Platform**: Multi-surface -- CLI (clap) / TUI (ratatui 0.29) / HTML Reports / Desktop GUI (Tauri v2)

ASCII wireframe specifications synthesizing user journeys, design system, and accessibility into visual screen layouts. Issen is a forensic triage platform optimized for the Evidence-to-Attorney-Ready-Report pipeline (TARR < 4 hours).

---

## Document Purpose

This document provides **visual wireframe specifications** that synthesize:

1. Emotional states and friction points from USER_JOURNEYS.md (core TARR journey, multi-source fusion, first-time setup)
2. Design tokens and components from UI_DESIGN_SYSTEM.md (Slate Blue / Amber palette, Inter + JetBrains Mono, 12 artifact-source colors)
3. Accessibility requirements from ACCESSIBILITY.md (WCAG 2.1 AA for HTML/GUI, best-effort TUI, `--no-color`/`--plain` CLI flags)
4. Brand voice and identity from BRAND_GUIDELINES.md (Practitioner-First Forensic Tool archetype)

**Relationship to Other Documents:**
- **USER_JOURNEYS.md** defines the emotional arc we design for (cautious ingest -> analytical review -> confident delivery)
- **UI_DESIGN_SYSTEM.md** provides the tokens we reference (`--color-*`, `--text-*`, `--space-*`, `--font-*`)
- **ACCESSIBILITY.md** provides per-screen requirements (keyboard nav, color independence, screen reader support)
- **BRAND_GUIDELINES.md** provides voice validation criteria (evidence tells a story, report is the product)
- **This document** translates strategy into visual specifications across all four surfaces

---

## 1. Overview

### 1.1 Critical Brand Gaps Addressed

| Gap | Issue | Solution | Applied In |
|-----|-------|----------|------------|
| Report as afterthought | Competitors treat reports as expoissen-only; no in-tool preview | Dedicated HTML Report wireframe with interactive timeline and live preview in TUI report panel | HTML Report, TUI Report Generation |
| Information overload | 50K+ timeline events overwhelm examiners without visual density cues | Timeline density heatmap with anomaly highlighting; progressive disclosure via expandable rows | TUI Dashboard, HTML Report Timeline |
| No artifact-source visual language | Other tools use plain text lists with no color coding by source type | 12-color artifact-source palette with icon + text prefix for color independence | All surfaces |
| CLI as second-class citizen | Forensic tools assume GUI; CLI output is unstructured dump | Structured CLI output with progress bars, columnar alignment, and `--json`/`--plain` modes | CLI Output screens |
| Trust deficit at ingest | Examiners distrust tools that don't show hash verification upfront | Hash verification status prominently displayed during and after ingest | CLI Ingest, TUI Dashboard status bar |

### 1.2 Design Token References

All specifications reference tokens from `UI_DESIGN_SYSTEM.md`:

- **Colors**: `--color-primary` (#475569), `--color-accent` (#D97706), `--color-bg` (#0F172A dark), `--color-surface` (#1E293B dark), `--color-artifact-*` (12 source types)
- **Typography**: `--text-base` (16px), `--font-display` (Inter), `--font-mono` (JetBrains Mono)
- **Spacing**: `--space-N` (4px base increments: 0-80px scale)
- **Components**: Timeline Row, Evidence Card, Finding Summary, Data Table, Density Heatmap, Buttons (Primary/Secondary/Ghost/Danger)

---

## 2. Color Extensions

Beyond the base palette defined in UI_DESIGN_SYSTEM.md, these semantic colors are needed for wireframe-specific states:

| Token | Light Mode | Dark Mode | Usage |
|-------|------------|-----------|-------|
| `--color-density-cold` | `#DBEAFE` (blue-100) | `#1E3A5F` (blue-900) | Heatmap: low event density cells |
| `--color-density-warm` | `#FDE68A` (amber-200) | `#92400E` (amber-800) | Heatmap: moderate event density |
| `--color-density-hot` | `#FCA5A5` (red-300) | `#991B1B` (red-800) | Heatmap: high density / anomaly spike |
| `--color-density-peak` | `#EF4444` (red-500) | `#F87171` (red-400) | Heatmap: peak anomaly (pulsing border in TUI) |
| `--color-bookmark` | `#F59E0B` (amber-500) | `#FBBF24` (amber-400) | Bookmarked / flagged finding indicator |
| `--color-hash-verified` | `#059669` (emerald-600) | `#34D399` (emerald-400) | Hash verification passed |
| `--color-hash-mismatch` | `#DC2626` (red-600) | `#F87171` (red-400) | Hash verification failed |
| `--color-cli-heading` | N/A | `#F59E0B` (amber-500) | CLI section headings (ANSI bold + color) |
| `--color-cli-progress` | N/A | `#475569` (slate-600) | CLI progress bar fill |
| `--color-repoissen-cover-bg` | `#F8FAFC` (slate-50) | N/A | HTML report cover page background (always light) |

---

## 3. Brand Visual Identity Elements

### 3.1 Evidence Integrity Badge

The Evidence Integrity Badge is the visual signature element expressing Issen's core brand belief: "Correctness over speed." It appears on every surface to communicate chain-of-custody integrity.

```
CLI:
  [VERIFIED] SHA-256: a3f2...7b91  (green text)
  [MISMATCH] SHA-256: a3f2...7b91  Expected: b4c1...8e02  (red text, bold)

TUI:
  ┌──────────────────────────────────────────────┐
  │  [shield]  Evidence Integrity: VERIFIED      │
  │  SHA-256  a3f2c891...7b91e4d2                │
  │  Sources: 3 ingested | 0 errors | 0 warnings │
  └──────────────────────────────────────────────┘

HTML Report:
  ┌──────────────────────────────────────────────────────┐
  │  [shield-icon]  Chain of Custody Verification        │
  │                                                      │
  │  Evidence Hash    SHA-256: a3f2c891...7b91e4d2       │
  │  Verification     PASSED                [green dot]  │
  │  Ingested         2026-03-20 14:32 UTC               │
  │  Tool Version     Issen v0.4.1                 │
  └──────────────────────────────────────────────────────┘
```

**Specifications:**
- Max Width: 100% container (CLI: terminal width, TUI: panel width, HTML: `max-width: 640px`)
- Padding: `--space-4` (16px) all sides
- Border Radius: `--radius-md` (0.375rem) for HTML/GUI; single-line box for TUI
- Background: `--color-surface` (dark mode), `--color-bg` with 1px `--color-hash-verified` left border
- Font: `--font-mono` for hashes, `--font-display` for labels
- Shield icon: 16x16 inline SVG (HTML), Unicode U+1F6E1 or `[V]` (TUI/CLI)

### 3.2 Artifact Source Indicator

The colored dot + prefix label system that identifies artifact types across all surfaces.

```
TUI/CLI prefix format:
  [FS]   Filesystem    (#60A5FA blue-400)
  [REG]  Registry      (#A78BFA violet-400)
  [EVT]  Event Log     (#34D399 emerald-400)
  [PF]   Prefetch      (#FBBF24 amber-400)
  [BR]   Browser       (#22D3EE cyan-400)
  [ML]   Email         (#F87171 red-400)
  [NET]  Network       (#818CF8 indigo-400)
  [PERS] Persistence   (#F472B6 pink-400)
  [MEM]  Memory        (#C084FC purple-400)
  [CLD]  Cloud         (#2DD4BF teal-400)
  [USB]  USB           (#FB923C orange-400)
  [USR]  User Activity (#94A3B8 slate-400)

HTML Report format:
  [colored dot] [icon] [label] -- inline with artifact description
```

**Color Independence:** Every artifact type encodes identity through three independent channels -- color, icon, and text prefix. Under deuteranopia/protanopia/tritanopia simulations, adjacent palette colors remain perceptually distinct. When they cannot be distinguished, the icon + text label always provides the information.

---

## 4. Core Screen Wireframes

---

### 4.1 CLI: Evidence Ingest (`rt ingest`)

**Purpose:** Ingest evidence sources (KAPE collections, E01 images, loose files), verify hashes, and launch parallel parsing. This is the entry point to the TARR pipeline.
**Emotional State:** Cautious, hopeful (per USER_JOURNEYS.md -- "first trust moment")
**Critical Requirement:** Show hash verification status immediately; surface errors without hiding them behind walls of text. Build trust through transparency.

```
$ rt ingest ./evidence/case-2024-0042/

  Issen v0.4.1                                    Case: 2024-0042
  ─────────────────────────────────────────────────────────────────────

  Evidence Source: ./evidence/case-2024-0042/
  Type detected:   KAPE Collection (triage package)
  Size:            14.2 GB across 3,847 files

  Hash Verification
  ──────────────────
  [VERIFIED] SHA-256: a3f2c891d4e5...7b91e4d2   (2.1s)

  Parsing Evidence
  ──────────────────
  [FS]  MFT             ████████████████████████████████████████  done   142,891 entries
  [FS]  USN Journal      ████████████████████████████████████████  done    89,442 entries
  [REG] SYSTEM           ████████████████████████████████████████  done     4,201 keys
  [REG] SOFTWARE         ████████████████████████████████████████  done    12,847 keys
  [REG] NTUSER.DAT       ████████████████████████████████████████  done     8,933 keys
  [EVT] Security.evtx    ██████████████████████████████░░░░░░░░░░  72%    31,204 events
  [EVT] System.evtx      ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  queued
  [PF]  Prefetch          ████████████████████████████████████████  done       247 files
  [BR]  Chrome History    ████████████████████████████████████████  done     2,891 URLs
  [USR] LNK Files         ████████████████████████████████████████  done       634 links

  Progress: 8/12 parsers complete | 293,290 events indexed | Elapsed: 4m 12s
  Estimated: ~2 minutes remaining

  ─────────────────────────────────────────────────────────────────────
  Next: rt timeline                    View parsed timeline
        rt timeline --filter "evtx"    Filter by artifact type
        rt report generate             Generate attorney-ready report
```

**Component Specifications:**

| Element | Token/Size | Notes |
|---------|------------|-------|
| Header line | `--font-mono`, `--text-base`, bold + `--color-cli-heading` | Version + case name right-aligned |
| Section dividers | Unicode box-drawing `─` or ASCII `-` in `--plain` mode | Full terminal width |
| Progress bars | 40-char width, `--color-cli-progress` fill, `░` empty | Determinate with percentage |
| Artifact prefix | `--font-mono`, artifact source color (ANSI 256) | `[XX]` format, 5-char padded |
| Hash verification | `--color-hash-verified` or `--color-hash-mismatch` | `[VERIFIED]` / `[MISMATCH]` prefix |
| Entry counts | `--font-mono`, right-aligned, `--color-text-secondary` | Tabular number formatting |
| Next steps | `--color-accent` for commands, `--color-text-secondary` for descriptions | Shown after completion |

**Accessibility Requirements:**
- [x] `--no-color` flag suppresses all ANSI codes; honors `NO_COLOR` env var
- [x] `--plain` flag uses ASCII-only characters (no Unicode box drawing, no progress bar graphics)
- [x] `--json` flag outputs structured JSON for programmatic consumption and screen reader pipelines
- [x] `--verbose` flag outputs linear text descriptions of progress (e.g., "Parsing MFT: 72% complete, 142891 entries") suitable for screen reader announcement
- [x] Error messages use stderr with clear prefix `[ERROR]` / `[WARN]`

**Brand Voice Validation:**
- [x] Uses specific counts ("142,891 entries") not vague ("many entries")
- [x] Shows "Next:" suggestions -- practitioner workflow guidance, not help text
- [x] Hash verification is the first thing shown after detection -- correctness over speed
- [x] No jargon translation needed; speaks the examiner's language (MFT, USN Journal, NTUSER.DAT)

---

### 4.2 TUI: Main Dashboard

**Purpose:** The primary interactive analysis workspace. Three-pane layout for navigating evidence, reviewing timeline events, and managing findings. This is where examiners spend 60-90 minutes of the TARR pipeline.
**Emotional State:** Focused, analytical (per USER_JOURNEYS.md -- "the deep work phase")
**Critical Requirement:** Handle 50K+ events without information overload. Progressive disclosure: density heatmap surfaces anomalies, drill-down reveals detail.

```
┌─ Issen ── Case: 2024-0042 ── 47,231 events ── TARR: 1h 42m ─────────┐
│                                                                              │
│ ┌─ Evidence ──────┐ ┌─ Timeline ─────────────────────────────────────────┐  │
│ │                  │ │                                                    │  │
│ │ v Case 2024-0042│ │  Density   |    . :..:|||:..  :. .  .   |         │  │
│ │   v Disk Image   │ │  Mar 15    ├─────────────────────────────┤ Mar 20 │  │
│ │     [FS] MFT     │ │                         ^anomaly                  │  │
│ │     [FS] USN     │ │                                                    │  │
│ │     [REG] SYSTEM │ │  Timestamp        Source  Artifact     Description│  │
│ │     [REG] NTUSER │ │  ─────────────────────────────────────────────────│  │
│ │   v Event Logs   │ │  03/17 14:32:01   [FS]   MFT         Created:    │  │
│ │     [EVT] SecEvt │ │                                       C:\Users\.. │  │
│ │     [EVT] SysEvt │ │  03/17 14:32:04   [REG]  NTUSER      Modified:   │  │
│ │   v Browser      │ │                                       UserAssist  │  │
│ │     [BR] Chrome  │ │> 03/17 14:33:11   [EVT]  Security    4688: Proc  │  │
│ │   v User Activity│ │                                       cmd.exe /c  │  │
│ │     [USR] LNK    │ │  03/17 14:33:15   [PF]   Prefetch    MIMIKATZ.EXE│  │
│ │     [USR] JumpLst│ │  03/17 14:33:18   [EVT]  Security    4624: Logon │  │
│ │                  │ │  03/17 14:34:02   [NET]  Firewall    Outbound:   │  │
│ │  Findings (4)    │ │                                       185.143.x.x│  │
│ │  ────────────── │ │  03/17 14:35:44   [PERS] SchTask     Created:    │  │
│ │  * Mimikatz exec │ │                                       UpdateSvc   │  │
│ │  * Lateral move  │ │  03/17 14:38:22   [FS]   MFT         Deleted:    │  │
│ │  * Data staging  │ │                                       C:\Temp\... │  │
│ │  * Exfil connect │ │                                                    │  │
│ │                  │ │  Showing 47,231 events | Filter: none | Sort: time│  │
│ ├──────────────────┤ └───────────────────────────────────────────────────┘  │
│ │ [V] Integrity OK │                                                        │
│ └──────────────────┘                                                        │
│                                                                              │
│ ┌─ Command ──────────────────────────────────────────────────────────────┐  │
│ │ > /filter type:evtx time:2024-03-17T14:30..14:40 keyword:mimikatz    │  │
│ └────────────────────────────────────────────────────────────────────────┘  │
│  j/k:navigate  Enter:detail  x:add finding  /:search  f:filter  ?:help    │
│  Tab:switch pane  r:report  Space:bookmark  q:back                         │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Component Specifications:**

| Element | Token/Size | Notes |
|---------|------------|-------|
| Title bar | `--font-mono`, bold, `--color-accent` for case name | Shows TARR elapsed timer |
| Evidence tree (left pane) | 20-char width, `--color-surface` bg | Collapsible with h/l keys; artifact prefix colors |
| Density heatmap | 1-row horizontal bar, `--color-density-*` gradient | Highlights anomaly clusters with `\|` peaks |
| Timeline table | Variable columns, `--font-mono`, `--leading-snug` | Virtualized scroll for 50K+ rows; selected row `>` indicator |
| Artifact prefix | Colored `[XX]` per artifact source palette | Color + text prefix for independence |
| Findings sidebar | Below evidence tree, `--color-bookmark` markers | `*` prefix for bookmarked items |
| Command bar | Bottom input, `--font-mono`, `/` to activate | Faceted filter syntax: `type:`, `time:`, `keyword:` |
| Status bar | Bottom row, `--color-text-muted`, `--text-sm` | Keyboard shortcut reference |
| Integrity badge | `--color-hash-verified`, bottom of left pane | Compact `[V] Integrity OK` format |

**Accessibility Requirements:**
- [x] Vim-style keyboard navigation: `j`/`k` move rows, `h`/`l` collapse/expand tree, `g`/`G` jump first/last
- [x] `Tab` cycles focus between panes (evidence tree -> timeline -> command bar)
- [x] Color independence: every artifact type has `[XX]` text prefix alongside color
- [x] Density heatmap uses character variation (`.`, `:`, `|`) alongside color gradient
- [x] `?` shows full keybinding reference overlay
- [x] `Ctrl+d`/`Ctrl+u` for half-page scroll; `Ctrl+f`/`Ctrl+b` for full page
- [x] Focus indicator: selected row uses `>` prefix + inverse highlight

**Brand Voice Validation:**
- [x] TARR timer in title bar reinforces "report is the product" -- elapsed time keeps examiner aware of pipeline progress
- [x] Findings sidebar uses examiner's own bookmarks, not auto-generated suggestions -- "by practitioners, for practitioners"
- [x] Filter syntax mirrors forensic query patterns, not search-engine patterns
- [x] No tutorial overlays or tooltips on launch -- respects practitioner expertise

---

### 4.3 TUI: Timeline Density Heatmap (Detail View)

**Purpose:** Expanded heatmap visualization showing event distribution over time with per-source-type breakdown. Surfaces temporal anomalies that guide the examiner to investigatively significant time windows.
**Emotional State:** Curious, pattern-seeking (transition from broad scanning to focused investigation)
**Critical Requirement:** Clearly distinguish normal baseline activity from anomaly spikes. Must work in monochrome terminals.

```
┌─ Timeline Density ── 2024-03-15 to 2024-03-20 ── 47,231 events ─────────┐
│                                                                            │
│  All Sources                                                               │
│  Mar 15   Mar 16   Mar 17   Mar 18   Mar 19   Mar 20                     │
│  ........ ........ .:||:... ........ ........ ........   Events/hour       │
│                      ^^^^                                                  │
│                      anomaly: 2,847 events in 2h window                   │
│                                                                            │
│  By Source Type:                                                           │
│  [FS]  MFT/USN   ........ ........ .:|:.... ........ ........             │
│  [REG] Registry  ........ ........ .:...... ........ ........             │
│  [EVT] Events    ........ ........ .::||:.. ........ ........             │
│  [PF]  Prefetch  ........ ........ ..:..... ........ ........             │
│  [BR]  Browser   ........ ........ ........ ........ ........             │
│  [NET] Network   ........ ........ ..:|:... ........ ........             │
│  [PERS] Persist  ........ ........ ...:.... ........ ........             │
│  [USR] User      ........ ........ ........ ........ ........             │
│                                                                            │
│  Legend: . = <10/hr  : = 10-50/hr  | = 50-200/hr  # = >200/hr            │
│                                                                            │
│  [Enter] Drill into time window   [f] Filter to selected source           │
│  [h/l]   Shrink/expand time range [q] Back to main dashboard              │
└────────────────────────────────────────────────────────────────────────────┘
```

**Component Specifications:**

| Element | Token/Size | Notes |
|---------|------------|-------|
| Heatmap characters | `--font-mono`, fixed-width cells | `.` `:` `\|` `#` for density quartiles |
| Anomaly annotation | `--color-density-hot`, `^` pointer | Inline annotation below spike |
| Source breakdown rows | Artifact prefix color + `--font-mono` | One row per active source type |
| Legend | `--color-text-muted`, `--text-sm` equivalent | Always visible at bottom |
| Time axis | `--color-text-secondary`, date labels | Auto-scales to selected range |

**Accessibility Requirements:**
- [x] Character-based density encoding works without color (`.` `:` `|` `#`)
- [x] Anomaly annotation uses text label with count, not just visual highlight
- [x] `h`/`l` adjusts time granularity (zoom in/out); keyboard-only interaction
- [x] Source type rows include `[XX]` text prefix for color independence

**Brand Voice Validation:**
- [x] Annotation uses specific counts ("2,847 events in 2h window") not vague alerts
- [x] Practitioner language: "Events/hour" not "activity score" or "risk level"
- [x] Evidence tells a story: temporal clustering guides the examiner to the narrative

---

### 4.4 TUI: Findings Panel (Detail View)

**Purpose:** Manage examiner-bookmarked findings with notes, linked events, and severity classification. These findings flow directly into the report narrative.
**Emotional State:** Confident, building the case (per USER_JOURNEYS.md -- assembling evidence for delivery)
**Critical Requirement:** Findings must link to specific timeline events with timestamps. Notes use the examiner's own words -- no auto-generated summaries that could misrepresent evidence.

```
┌─ Findings ── Case 2024-0042 ── 4 findings ──────────────────────────────┐
│                                                                           │
│  # Finding                    Severity  Events  Time Window              │
│  ──────────────────────────────────────────────────────────────────────  │
│  1 Credential theft (Mimikatz) Critical  12      03/17 14:33 - 14:35     │
│  2 Lateral movement            High      8       03/17 14:36 - 14:42     │
│  3 Data staging                High      23      03/17 14:45 - 15:12     │
│  4 Exfiltration connection     Critical  3       03/17 15:15 - 15:18     │
│                                                                           │
│  ═══════════════════════════════════════════════════════════════════════  │
│  Finding #1: Credential theft (Mimikatz)                                 │
│  Severity: Critical                                                       │
│  Time Window: 2024-03-17 14:33:11 -- 14:35:44 UTC                        │
│                                                                           │
│  Linked Events:                                                           │
│    14:33:11  [EVT] Security 4688  Process Create: cmd.exe /c mimikatz    │
│    14:33:15  [PF]  Prefetch       MIMIKATZ.EXE-1A2B3C4D.pf              │
│    14:33:18  [EVT] Security 4624  Logon Type 9 (NewCredentials)          │
│    14:34:02  [REG] SECURITY       LSA secrets accessed                    │
│    ... 8 more events                                                      │
│                                                                           │
│  Examiner Notes:                                                          │
│  > Mimikatz sekurlsa::logonpasswords executed via cmd.exe. Attacker       │
│  > obtained domain admin credentials. Corroborated by Event 4624          │
│  > showing NewCredentials logon 7 seconds after execution.                │
│                                                                           │
│  [e] Edit notes  [a] Add event  [d] Remove event  [s] Set severity      │
│  [Enter] View event detail      [r] Include in report  [q] Back          │
└───────────────────────────────────────────────────────────────────────────┘
```

**Component Specifications:**

| Element | Token/Size | Notes |
|---------|------------|-------|
| Findings table | `--font-mono`, `--leading-snug` | Sortable by severity, time, event count |
| Severity badge | `--color-severity-critical` / `high` / `medium` / `low` | Text label, not just color |
| Linked events list | `--font-mono`, artifact prefix colors | Timestamp + source + description |
| Examiner notes | `--font-mono`, `>` prefix, `--color-text-primary` | Free-text, examiner's own words |
| Action bar | `--color-text-muted`, bottom of panel | Single-key shortcuts |

**Accessibility Requirements:**
- [x] Findings table navigable with `j`/`k`; `Enter` expands detail
- [x] Severity uses text label ("Critical", "High") alongside color
- [x] Linked events maintain artifact prefix for color independence
- [x] Notes editing uses standard terminal input (no special modes)

**Brand Voice Validation:**
- [x] Notes are the examiner's words -- tool never auto-generates or modifies them
- [x] "By practitioners, for practitioners" -- findings structure matches how examiners think about cases
- [x] Linked events show specific artifacts and timestamps, not summaries
- [x] Report inclusion is explicit (`r` to include) -- examiner controls the narrative

---

### 4.5 HTML Report: Cover Page and Executive Summary

**Purpose:** The attorney-facing deliverable. This is the primary output of the TARR pipeline -- the product, not a byproduct. Self-contained HTML with embedded CSS/JS, no external dependencies.
**Emotional State:** Anticipation, excited (per USER_JOURNEYS.md -- "highest emotional stakes")
**Critical Requirement:** Must be professional enough that an attorney accepts it without calling the examiner back. Clean typography, clear hierarchy, verifiable chain of custody.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│                          FORENSIC ANALYSIS REPORT                       │
│                          ════════════════════════                        │
│                                                                         │
│                          Case: 2024-0042                                │
│                          Incident Response: Unauthorized Access          │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                                                                  │  │
│  │  Prepared by:    Sarah Chen, GCFE, EnCE                          │  │
│  │  Organization:   Chen Digital Forensics LLC                      │  │
│  │  Date:           March 20, 2026                                  │  │
│  │  Classification: Attorney-Client Privileged                      │  │
│  │                                                                  │  │
│  │  ┌──────────────────────────────────────────────────────────┐   │  │
│  │  │ [shield] Chain of Custody Verification                   │   │  │
│  │  │                                                          │   │  │
│  │  │ Evidence Hash   SHA-256: a3f2c891...7b91e4d2             │   │  │
│  │  │ Verification    PASSED                                   │   │  │
│  │  │ Tool            Issen v0.4.1                       │   │  │
│  │  │ Generated       2026-03-20 16:42 UTC                     │   │  │
│  │  └──────────────────────────────────────────────────────────┘   │  │
│  │                                                                  │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  Skip to: [Executive Summary] [Timeline] [Findings] [Methodology]      │
│                                                                         │
│  ───────────────────────────────────────────────────────────────────── │
│                                                                         │
│  EXECUTIVE SUMMARY                                                      │
│  ─────────────────                                                      │
│                                                                         │
│  On March 17, 2024, unauthorized access was detected on the             │
│  corporate network. Analysis of forensic artifacts from the             │
│  affected workstation (DESKTOP-ABC123) revealed:                        │
│                                                                         │
│  Key Findings (4):                                                      │
│  ┌────────────────────────────────────────────────────────────────┐    │
│  │ [!] CRITICAL  Credential theft via Mimikatz        See: F-001 │    │
│  │ [!] CRITICAL  Data exfiltration to 185.143.x.x    See: F-004 │    │
│  │ [^] HIGH      Lateral movement across 3 hosts     See: F-002 │    │
│  │ [^] HIGH      Data staging in C:\Temp              See: F-003 │    │
│  └────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  Timeline Span: March 15-20, 2024 | Total Events Analyzed: 47,231     │
│  Evidence Sources: 12 artifact types from KAPE collection              │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Component Specifications:**

| Element | Token/Size | Notes |
|---------|------------|-------|
| Report title | `--font-display`, `--text-2xl` (33.2px), `--font-bold` | Centered, light mode always for reports |
| Case metadata | `--font-body`, `--text-base`, `--color-text-primary` on `--color-repoissen-cover-bg` | Card with subtle border |
| Integrity badge | `--font-mono` for hash, `--color-hash-verified` accent | Prominent placement below metadata |
| Skip links | `--font-body`, `--text-sm`, `--color-primary` underlined | 6 targets: summary, timeline, findings, methodology, appendices, glossary |
| Executive summary | `--font-body`, `--text-base`, `--leading-relaxed` (1.625) | Narrative paragraph style |
| Findings summary | `--font-mono` for codes, severity colors with text labels | `[!]` Critical, `[^]` High, `[-]` Medium, `[.]` Low prefixes |
| Cross-references | `--color-primary` links, `See: F-001` format | Hyperlinks to finding detail sections |

**Accessibility Requirements:**
- [x] Skip links at top: "Skip to Executive Summary", "Skip to Timeline", "Skip to Findings", "Skip to Methodology", "Skip to Appendices", "Skip to Glossary"
- [x] Semantic HTML: `<h1>` report title, `<h2>` sections, `<table>` for data, `<nav>` for skip links
- [x] Landmark regions: `<header>`, `<main>`, `<nav>`, `<footer>` with ARIA labels
- [x] Findings summary uses `[!]`/`[^]`/`[-]`/`[.]` text indicators alongside severity colors
- [x] Contrast: all text pairs verified AA+ on light background (see UI_DESIGN_SYSTEM.md contrast table)
- [x] Print stylesheet: removes interactive elements, optimizes for A4/Letter, includes page breaks between sections

**Brand Voice Validation:**
- [x] "Report is the product" -- professional layout rivaling manually crafted deliverables
- [x] Chain of Custody verification is above the fold -- correctness over speed
- [x] Findings use examiner's language and reference specific evidence artifacts
- [x] No marketing language or tool branding in the report body (Issen name only in methodology)
- [x] Classification banner ("Attorney-Client Privileged") reflects real-world legal practice

---

### 4.6 HTML Report: Interactive Timeline

**Purpose:** Collapsible, filterable timeline view within the HTML report. Allows attorneys and reviewers to explore events without requiring Issen installed.
**Emotional State:** Review and verification (attorney's perspective -- needs to understand the narrative without forensic expertise)
**Critical Requirement:** Must degrade gracefully with JavaScript disabled (static table fallback). Self-contained -- no CDN dependencies.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│  TIMELINE OF EVENTS                                                     │
│  ──────────────────                                                     │
│                                                                         │
│  ┌─ Filter ──────────────────────────────────────────────────────────┐ │
│  │ Source: [All v]  Severity: [All v]  Time: [Mar 17 14:00 - 16:00] │ │
│  │ Search: [________________________]   [Apply]  [Clear]             │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                                                         │
│  ┌─ Density ─────────────────────────────────────────────────────────┐ │
│  │  Mar 17 14:00            15:00            16:00                   │ │
│  │  .........:||||::......................:..........                 │ │
│  │           ^14:33 peak (credential theft + lateral movement)       │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                                                         │
│  Showing 847 of 47,231 events (filtered)                               │
│                                                                         │
│  v  Mar 17, 2024 14:33 -- Credential Theft Cluster (12 events)         │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │ Time       Source     Artifact        Description        Finding │ │
│  │ ────────── ────────── ─────────────── ────────────────── ─────── │ │
│  │ 14:33:11   [EVT]      Security 4688   Process Created:   F-001  │ │
│  │                                        cmd.exe /c ...           │ │
│  │ 14:33:15   [PF]       Prefetch        MIMIKATZ.EXE       F-001  │ │
│  │ 14:33:18   [EVT]      Security 4624   Logon Type 9       F-001  │ │
│  │ 14:34:02   [REG]      SECURITY        LSA secrets        F-001  │ │
│  │ ...8 more events (click to expand)                               │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                                                         │
│  >  Mar 17, 2024 14:36 -- Lateral Movement (8 events)                  │
│  >  Mar 17, 2024 14:45 -- Data Staging (23 events)                     │
│  >  Mar 17, 2024 15:15 -- Exfiltration (3 events)                      │
│                                                                         │
│  ┌─────────────────────────────────────┐                               │
│  │  [<< Prev Page]   [Next Page >>]   │                               │
│  └─────────────────────────────────────┘                               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Component Specifications:**

| Element | Token/Size | Notes |
|---------|------------|-------|
| Filter bar | `--font-body`, `--text-sm`, `--color-surface` bg | Dropdowns + text input + date range |
| Density minimap | `--font-mono`, character density, inline in report | Same encoding as TUI heatmap |
| Event cluster headers | `--font-display`, `--text-md`, collapsible (`v`/`>`) | Group by time proximity + finding |
| Event table | `--font-mono`, `--text-sm`, `--leading-snug` | Source colored dots, finding cross-refs |
| Finding links | `--color-primary`, `F-001` format | Anchor links to findings section |
| Pagination | `--font-body`, `--text-sm` | Client-side pagination, 50 events/page |

**Accessibility Requirements:**
- [x] `<table>` with proper `<thead>`, `<th scope="col">`, `<caption>` for event tables
- [x] Collapsible sections use `<details>`/`<summary>` for native browser support
- [x] Filter controls have associated `<label>` elements
- [x] Keyboard: `Enter`/`Space` to expand/collapse sections; `Tab` through filter controls
- [x] JavaScript-disabled fallback: full static table with all events visible (no pagination)
- [x] ARIA: `role="region"` on timeline, `aria-expanded` on collapsible headers, `aria-live="polite"` on filter result count

**Brand Voice Validation:**
- [x] Events grouped by narrative cluster, not raw chronological dump -- "evidence tells a story"
- [x] Finding cross-references (`F-001`) connect timeline to conclusions
- [x] Attorney can understand without forensic training: cluster labels use plain language
- [x] No auto-interpretation of events; examiner's findings and notes are the narrative layer

---

### 4.7 HTML Report: Findings with Exhibits

**Purpose:** Detailed findings section with examiner narrative, linked evidence exhibits, and hyperlinked cross-references to the timeline. This is the core deliverable section that attorneys read.
**Emotional State:** High stakes (examiner); trust-building (attorney reader)
**Critical Requirement:** Each finding must be independently verifiable -- linked exhibits, specific timestamps, artifact references. Must withstand Daubert challenge scrutiny.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│  FINDINGS                                                               │
│  ────────                                                               │
│                                                                         │
│  ┌─ Finding F-001: Credential Theft via Mimikatz ──── CRITICAL ──────┐ │
│  │                                                                    │ │
│  │  Time Window: March 17, 2024, 14:33:11 -- 14:35:44 UTC            │ │
│  │  Affected Host: DESKTOP-ABC123                                     │ │
│  │  Evidence Sources: Event Logs, Prefetch, Registry                  │ │
│  │                                                                    │ │
│  │  Narrative:                                                        │ │
│  │  ──────────                                                        │ │
│  │  At 14:33:11 UTC, the attacker executed Mimikatz via cmd.exe      │ │
│  │  to extract credential material from LSASS memory. Prefetch       │ │
│  │  artifacts confirm MIMIKATZ.EXE was executed for the first time   │ │
│  │  on this system. Seven seconds later, a Type 9 (NewCredentials)   │ │
│  │  logon event indicates the harvested credentials were immediately  │ │
│  │  used for network authentication.                                  │ │
│  │                                                                    │ │
│  │  Supporting Evidence:                                              │ │
│  │  ┌─────────────────────────────────────────────────────────────┐  │ │
│  │  │ Exhibit  Artifact            Detail                  Link  │  │ │
│  │  │ ──────── ─────────────────── ──────────────────────  ───── │  │ │
│  │  │ E-001a   Security Event 4688 cmd.exe /c mimikatz     [>>]  │  │ │
│  │  │ E-001b   Prefetch            MIMIKATZ.EXE-1A2B.pf   [>>]  │  │ │
│  │  │ E-001c   Security Event 4624 Type 9 NewCredentials   [>>]  │  │ │
│  │  │ E-001d   SECURITY hive       LSA secret access       [>>]  │  │ │
│  │  └─────────────────────────────────────────────────────────────┘  │ │
│  │                                                                    │ │
│  │  Impact: Domain administrator credentials compromised.             │ │
│  │  This finding directly enabled F-002 (Lateral Movement).          │ │
│  │                                                                    │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                         │
│  ┌─ Finding F-002: Lateral Movement ──── HIGH ───────────────────────┐ │
│  │  ...                                                               │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Component Specifications:**

| Element | Token/Size | Notes |
|---------|------------|-------|
| Finding card | `--color-surface` bg, left border color by severity | `--radius-md`, `--space-6` padding |
| Severity badge | `--font-display`, `--text-sm`, bold, severity color + text | Inline with finding title |
| Narrative text | `--font-body`, `--text-base`, `--leading-relaxed` | Examiner's own words |
| Exhibit table | `--font-mono`, `--text-sm` | Exhibit IDs (`E-001a`), `[>>]` hyperlinks to timeline |
| Cross-finding refs | `--color-primary` links | "This finding directly enabled F-002" links |
| Impact statement | `--font-body`, `--text-base`, bold | One-line summary of consequence |

**Accessibility Requirements:**
- [x] Finding cards use `<article>` with `aria-labelledby` pointing to finding title heading
- [x] Exhibit table uses proper `<table>` with `<caption>` and `<th scope="col">`
- [x] Hyperlinks (`[>>]`) have descriptive `aria-label`: "View Event 4688 in timeline"
- [x] Severity conveyed via text ("CRITICAL") not just color
- [x] Heading hierarchy: `<h2>` Findings, `<h3>` individual findings

**Brand Voice Validation:**
- [x] Narrative is the examiner's own prose -- tool formats but never writes conclusions
- [x] Every claim backed by specific exhibit with hyperlink -- "correctness over speed"
- [x] Cross-finding references build a coherent story -- "evidence tells a story"
- [x] No hedging language or automated confidence scores -- the examiner takes responsibility

---

### 4.8 Future: Tauri Desktop GUI (Target State)

**Purpose:** Desktop application providing the full TUI feature set with richer visual capabilities (drag-and-drop, multi-window, report live preview). This is the future P2 target, not part of the current MVP.
**Emotional State:** Efficient, power-user flow (returning user, advanced analysis)
**Critical Requirement:** Must maintain feature parity with TUI -- the GUI is an enhancement, not a replacement. CLI and TUI remain first-class citizens.

```
┌─ Issen ─────────────────────────────────────────── [_] [O] [X] ─┐
│  File  Edit  View  Case  Evidence  Report  Help                        │
│ ┌─────────────────────────────────────────────────────────────────────┐│
│ │ ┌─ Evidence ──────┐ ┌─ Timeline ───────────────────────────────┐   ││
│ │ │                  │ │                                          │   ││
│ │ │ Case 2024-0042  │ │ [Density Heatmap - full color gradient]  │   ││
│ │ │ > Disk Image     │ │                                          │   ││
│ │ │   > Filesystem   │ │ ┌──────────────────────────────────────┐ │   ││
│ │ │   > Registry     │ │ │ Timestamp  Source  Artifact  Desc    │ │   ││
│ │ │   > Event Logs   │ │ │ (full interactive data table with    │ │   ││
│ │ │ > KAPE Output    │ │ │  column resize, sort, inline filter) │ │   ││
│ │ │   > Browser      │ │ └──────────────────────────────────────┘ │   ││
│ │ │   > Prefetch     │ │                                          │   ││
│ │ │                  │ ├──────────────────────────────────────────┤   ││
│ │ ├──────────────────┤ │ [Event Detail + Hex View]               │   ││
│ │ │ Findings (4)     │ │  Selected event expanded view with      │   ││
│ │ │ > F-001 Critical │ │  raw artifact data and hex dump         │   ││
│ │ │ > F-002 High     │ └──────────────────────────────────────────┘   ││
│ │ │ > F-003 High     │                                                ││
│ │ │ > F-004 Critical │ ┌─ Report Preview ────────────────────────┐   ││
│ │ └──────────────────┘ │  [Live HTML report preview]             │   ││
│ │                      │  Updates as findings are added/edited   │   ││
│ │ ┌─ Integrity ──────┐ │  [Generate]  [Export HTML]  [Export PDF] │   ││
│ │ │ [V] All verified │ └──────────────────────────────────────────┘   ││
│ │ └──────────────────┘                                                ││
│ └─────────────────────────────────────────────────────────────────────┘│
│  Events: 47,231 | Findings: 4 | TARR: 2h 12m          [V] Integrity  │
└───────────────────────────────────────────────────────────────────────┘
```

**Component Specifications:**

| Element | Token/Size | Notes |
|---------|------------|-------|
| Menu bar | `--font-display`, `--text-sm`, native OS styling via Tauri | Standard File/Edit/View/Case/Evidence/Report/Help |
| Evidence tree | Resizable pane, `--font-body`, tree with icons | Drag-and-drop evidence import |
| Timeline table | Full data table with column resize, inline sort/filter | Virtualized for 100K+ rows |
| Heatmap | Canvas/SVG, full color gradient, hover tooltips | Click to zoom into time range |
| Event detail | Bottom split, `--font-mono`, hex viewer toggle | Raw artifact data inspection |
| Report preview | Right panel, embedded webview, live-updating | WYSIWYG preview of HTML report |
| Status bar | `--font-mono`, `--text-xs`, bottom of window | Event count, finding count, TARR timer, integrity badge |

**Accessibility Requirements:**
- [x] Full WCAG 2.1 AA compliance (mandatory for GUI surface per ACCESSIBILITY.md)
- [x] Standard OS keyboard shortcuts (Cmd/Ctrl+F search, Cmd/Ctrl+S save)
- [x] Tab navigation through all panes; `F6` to cycle panes (standard multi-pane pattern)
- [x] Screen reader: ARIA landmarks on all panes, live regions for TARR timer and parsing progress
- [x] High contrast mode support via `forced-colors` media query
- [x] Resizable panes with keyboard (Cmd/Ctrl+Shift+arrows)

**Brand Voice Validation:**
- [x] Layout inspired by Magnet AXIOM's multi-pane design but cleaner -- competitive differentiation
- [x] Report preview is a first-class pane, not hidden in a menu -- "report is the product"
- [x] CLI/TUI commands still accessible via integrated terminal pane (not shown in wireframe)
- [x] No wizard flows or guided tours -- respects practitioner expertise

---

## 5. Screen States

### 5.1 Loading/Processing States

> **Note**: Use human language, never clinical terms like "Processing..." or "Analyzing..."

**Processing Messages (Rotate):**
1. "Reading evidence -- checking integrity first..."
2. "Parsing artifacts across 12 source types..."
3. "Building the timeline -- your evidence is taking shape..."
4. "Almost there -- indexing the last few artifacts..."
5. "Correlating events across sources -- finding the connections..."

**Banned Processing Language:**
- No "Processing..."
- No "Analyzing..."
- No "Please wait..."
- No "Loading..."

```
CLI (determinate progress):
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  Reading evidence -- checking integrity first...               │
│                                                                 │
│  [EVT] Security.evtx   ██████████████████████░░░░░░░░  72%    │
│                         31,204 / 43,339 events                  │
│                                                                 │
│  Elapsed: 4m 12s | ~2 minutes remaining                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

TUI (multi-parser progress):
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  Parsing artifacts across 12 source types...                   │
│                                                                 │
│  [FS]  MFT           ████████████████████████████████  done    │
│  [REG] Registry      ████████████████████████████████  done    │
│  [EVT] Event Logs    ██████████████████████░░░░░░░░░  72%     │
│  [PF]  Prefetch      ████████████████████████████████  done    │
│  [BR]  Browser       ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  queued  │
│                                                                 │
│  8/12 complete | 293,290 events | ~2 min remaining             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

HTML Report generation:
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  Building your report -- assembling 4 findings...              │
│                                                                 │
│  [1/4] Credential theft narrative        done                  │
│  [2/4] Lateral movement narrative        done                  │
│  [3/4] Data staging narrative            in progress           │
│  [4/4] Exfiltration narrative            queued                │
│                                                                 │
│  Timeline rendering:  ████████████████░░░░░░░░░░░░░░  55%     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 Error States

> **Note**: Never blame user. Use collaborative language ("Let's try...").

| Error Type | Icon | Message | Solution |
|------------|------|---------|----------|
| Unsupported evidence format | `[?]` | "I don't recognize this evidence format yet." | "Let's check the supported formats: `rt formats list`. If this should be supported, please file an issue." |
| Parser failure (corrupted artifact) | `[!]` | "This artifact appears to be corrupted or incomplete." | "Let's continue with the remaining evidence. The timeline will note which artifacts couldn't be parsed." |
| Hash mismatch | `[!!]` | "The evidence hash doesn't match the expected value." | "This may indicate the evidence was modified after collection. Let's document this discrepancy in the findings." |
| Permission denied | `[X]` | "I can't read this file -- it may need elevated permissions." | "Let's try running with `sudo rt ingest` or check the file permissions." |
| Out of memory (large evidence) | `[~]` | "This evidence set is larger than available memory." | "Let's try processing in chunks: `rt ingest --chunk-size 2G` to limit memory usage." |
| Report template missing | `[?]` | "I can't find the report template." | "Let's check your templates: `rt report templates list`. You can reset to defaults with `rt report templates reset`." |

**Error Language Rules:**
- Use "I couldn't..." (takes responsibility)
- Use "This sometimes happens when..." (normalizes)
- Use "Let's try..." (collaborative)
- Never "You did something wrong"
- Never "Error code: XXX" as the primary message (codes go to `--verbose` output)
- Never "Failed" / "Invalid" / "Wrong" as standalone messages

```
CLI error example:
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  [!] This artifact appears to be corrupted or incomplete.      │
│                                                                 │
│      File: ./evidence/SYSTEM (Registry hive)                   │
│      Issue: Header signature invalid at offset 0x00            │
│                                                                 │
│  Let's continue with the remaining evidence. The timeline      │
│  will note which artifacts couldn't be parsed.                 │
│                                                                 │
│  Continuing: 11/12 parsers active...                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

TUI error (inline, non-blocking):
┌─────────────────────────────────────────────────────────────────┐
│  [!] 1 artifact couldn't be parsed (SYSTEM hive - corrupted)   │
│      Press 'e' to view details | Timeline continues below      │
└─────────────────────────────────────────────────────────────────┘
```

### 5.3 Empty States

```
TUI: No case loaded
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│                         Issen                             │
│                                                                 │
│          No evidence loaded yet. Let's get started.            │
│                                                                 │
│          rt ingest ./path/to/evidence/                         │
│                                                                 │
│          Supported: KAPE collections, E01 images,              │
│          raw artifact directories                               │
│                                                                 │
│          Press 'i' to ingest or '?' for help                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

TUI: No findings yet
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│          No findings bookmarked yet.                           │
│                                                                 │
│          Press 'x' on any timeline event to mark it            │
│          as a finding. Your findings will appear here           │
│          and flow into the report.                              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

TUI: Filter returns no results
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│          No events match this filter.                          │
│                                                                 │
│          Current filter: type:email time:2024-03-15             │
│                                                                 │
│          Try broadening the time range or removing              │
│          a filter term. Press 'c' to clear all filters.        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 6. Component Quick Reference

### 6.1 Buttons

| Type | Height | Style | Usage |
|------|--------|-------|-------|
| Primary | 48px | `--color-accent` bg (#D97706), white text, `--radius-md` | Main action: "Generate Report", "Apply Filter" (one per screen) |
| Secondary | 48px | Transparent, 1px `--color-accent` border, `--color-accent` text | Supporting: "Export", "Clear", "Cancel" |
| Ghost | 44px | Transparent, `--color-text-secondary` text | Tertiary: "View Details", navigation |
| Danger | 48px | `--color-severity-critical` bg (#991B1B), white text | Destructive: "Delete Finding", "Remove Evidence" |
| CLI action | N/A | `--color-accent` ANSI text, underlined | `rt` command suggestions in CLI output |

### 6.2 Cards

| Type | Left Border | Icon | Usage |
|------|-------------|------|-------|
| Finding (Critical) | 4px `--color-severity-critical` (#991B1B) | `[!]` | Critical severity findings |
| Finding (High) | 4px `--color-severity-high` (#DC2626) | `[^]` | High severity findings |
| Finding (Medium) | 4px `--color-severity-medium` (#D97706) | `[-]` | Medium severity findings |
| Finding (Low) | 4px `--color-severity-low` (#2563EB) | `[.]` | Low severity/informational findings |
| Evidence source | 4px artifact source color | Source icon | Evidence tree items in GUI |
| Integrity badge | 4px `--color-hash-verified` (#059669) | Shield | Chain of custody verification |
| Error notice | 4px `--color-severity-high` (#DC2626) | `[!]` | Non-blocking error notifications |

### 6.3 Forensic Data Elements

| Element | Style | Usage |
|---------|-------|-------|
| Timestamp | `--font-mono`, `--text-sm`, `--color-text-primary`, tabular-nums | All timeline entries; UTC format |
| File path | `--font-mono`, `--text-sm`, `--color-text-secondary`, truncate with `...` | Artifact paths, evidence locations |
| Hash value | `--font-mono`, `--text-xs`, `--color-text-muted`, truncate middle | SHA-256/MD5 display |
| Registry key | `--font-mono`, `--text-sm`, `--color-artifact-registry` | Registry path references |
| Event ID | `--font-mono`, `--text-sm`, bold, `--color-artifact-eventlog` | Windows Event IDs (4688, 4624, etc.) |
| Artifact prefix | `--font-mono`, `--text-sm`, artifact source color, `[XX]` format | Source type identification |
| Severity badge | `--font-display`, `--text-xs`, uppercase, severity color bg + white text | Finding severity labels |
| Exhibit reference | `--font-mono`, `--text-sm`, `--color-primary`, underlined | `E-001a`, `F-001` cross-references |

---

## 7. Brand Voice Validation Checklist

### 7.1 Per-Screen Validation

For every screen, validate:

- [ ] Speaks the examiner's language? (MFT, USN Journal, Event ID 4688 -- no dumbing down)
- [ ] Uses collaborative language for errors? ("Let's try..." not "You failed...")
- [ ] Feedback includes specific counts and timestamps? (not "several events" but "12 events, 14:33-14:35")
- [ ] Avoids automated interpretations? (tool presents evidence; examiner draws conclusions)
- [ ] Actionable next steps provided? (not "see help" but specific `rt` commands)
- [ ] Sounds like a Practitioner-First Forensic Tool, not a consumer app?

### 7.2 Banned Elements (Kill List)

> Elements that must NEVER appear in the UI.

- [ ] No collection features (collection is solved by KAPE/Velociraptor -- not our problem)
- [ ] No eDiscovery workflows (different problem, different users, different tool)
- [ ] No SIEM/SOC real-time alerting (we are post-incident, not real-time)
- [ ] No enterprise administration UI (solo examiner first, enterprise later)
- [ ] No AI-generated conclusions or automated findings (tool assists; examiner decides)
- [ ] No marketing language in reports (Issen name only in methodology section)
- [ ] No "risk scores" or "threat levels" (forensic evidence, not threat intelligence)
- [ ] No subscription nag screens or feature gates in the UI
- [ ] No tutorial wizards or guided tours (respects practitioner expertise)
- [ ] No social features, sharing, or collaboration (examiner works alone; shares reports)

---

## 8. Implementation Priority

### P0 - MVP (CLI + TUI)

> Must have for launch. These screens constitute the minimum TARR pipeline.

1. **CLI: Evidence Ingest** (Section 4.1) -- Entry point to the entire pipeline; first trust moment
2. **CLI: Timeline Output** (columnar `rt timeline` output, subset of 4.1 patterns) -- Enables `rt timeline | grep` workflows
3. **TUI: Main Dashboard** (Section 4.2) -- The primary analysis workspace; 60-90 min of TARR
4. **TUI: Findings Panel** (Section 4.4) -- Bookmarking and note-taking during analysis

### P1 - Core Experience

> Required for complete TARR pipeline and attorney delivery.

5. **HTML Report: Cover + Executive Summary** (Section 4.5) -- The attorney-facing deliverable
6. **HTML Report: Interactive Timeline** (Section 4.6) -- Attorney can explore events independently
7. **HTML Report: Findings with Exhibits** (Section 4.7) -- Core evidentiary documentation
8. **TUI: Density Heatmap** (Section 4.3) -- Anomaly detection acceleration

### P2 - Polish

> Enhancement and refinement after MVP validation.

9. **Desktop GUI** (Section 4.8) -- Tauri v2 multi-pane application for power users
10. **Report Live Preview** (in TUI, showing rendered HTML in terminal or side pane) -- WYSIWYG feedback during analysis
11. **Multi-case management** (case list view, not wireframed) -- For examiners handling multiple concurrent cases

---

*Document generated by North Star Advisor*
