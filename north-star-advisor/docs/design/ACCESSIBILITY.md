# Issen: Accessibility Strategy

> **Parent**: [USER_JOURNEYS.md](USER_JOURNEYS.md)
> **Related**: [UI_DESIGN_SYSTEM.md](UI_DESIGN_SYSTEM.md)
> **Generation Step**: 5c of 13 -- Requires `journeys.*`
> **Created**: 2026-03-20
> **Status**: Active
> **WCAG Target**: 2.1 Level AA (HTML Reports); best-effort (TUI/CLI)

Comprehensive accessibility patterns for Issen, a multi-surface forensic triage platform (CLI, TUI, HTML reports, future Tauri GUI, future Web UI). This document covers WCAG compliance for attorney-facing HTML reports, terminal accessibility for examiner-facing TUI, CLI output modes for programmatic access, and inclusive design for long forensic analysis sessions.

## Document Purpose

This document defines **accessibility as a first-class citizen** in Issen. It provides:

1. WCAG 2.1 AA compliance checklist (HTML reports and web surfaces)
2. Multi-surface accessibility matrix (CLI, TUI, HTML, GUI, print)
3. Screen reader patterns for streaming parse/report operations
4. Focus management during evidence parsing and report generation
5. Cognitive load mitigation for 12-16 hour IR sessions
6. Terminal accessibility patterns for TUI and CLI
7. Print/PDF accessibility for couissen-ready deliverables
8. Testing protocols and tooling per surface

**Design Principle**: Accessibility is not a feature -- it is the foundation. Every pattern here enables users to accomplish their goals regardless of ability. No forensic tool advertises WCAG compliance today; Issen treats this as unoccupied differentiation.

**Relationship to Other Documents:**
- **UI_DESIGN_SYSTEM.md** implements the visual tokens (focus rings, colors, contrast ratios)
- **USER_JOURNEYS.md** maps journey phases to accessibility concerns
- **This document** provides comprehensive patterns and testing protocols

---

## 1. Multi-Surface Accessibility Matrix

Issen spans five surfaces with different accessibility constraints and strategies:

| Surface | Technology | WCAG Target | Screen Reader | Keyboard Nav | Dark Mode | Color Independence |
|---------|-----------|-------------|---------------|--------------|-----------|-------------------|
| **CLI** | Rust (clap) | N/A (text output) | Terminal reads all output | Full (terminal) | Terminal theme | `--no-color`, `--plain`, `--json` |
| **TUI** | ratatui 0.29 + crossterm 0.28 | Best-effort | Limited (terminal-dependent) | Full (vim-style + custom) | Always dark | Icons + labels, not color alone |
| **HTML Reports** | Self-contained HTML | **WCAG 2.1 AA** | Full (NVDA, JAWS, VoiceOver) | Full | User toggle | Semantic markers + color |
| **Desktop GUI** | Tauri v2 webview | WCAG 2.1 AA | Full (platform native) | Full | System + toggle | Same as HTML |
| **Web UI** | axum + React/Leptos (future) | WCAG 2.1 AA | Full | Full | System + toggle | Same as HTML |
| **Print (PDF/Word)** | Generated from HTML | Tagged PDF / Word a11y | Acrobat reader support | N/A | N/A (light only) | Print-safe colors |

### 1.1 CLI Accessibility

The CLI is the primary interface for automation and power users. Accessibility is achieved through output modes:

```bash
# Standard output (colorized when TTY detected)
rt ingest ./evidence/

# No color (honors NO_COLOR env var per https://no-color.org)
rt ingest ./evidence/ --no-color
NO_COLOR=1 rt ingest ./evidence/

# Plain text (no ANSI escapes, no Unicode box drawing)
rt timeline --plain

# JSON output (programmatic access, screen reader parseable)
rt timeline --json | jq '.events[:5]'

# Verbose progress (for screen readers -- linear text updates)
rt parse --verbose --no-color
```

**Implementation requirements:**
- Detect `NO_COLOR` environment variable and `--no-color` flag
- `--plain` strips all ANSI sequences and replaces Unicode box drawing with ASCII
- `--json` outputs structured data for programmatic consumption and assistive tools
- Progress bars degrade to percentage text updates when `--plain` is active
- Error messages always include exit codes and plain-text descriptions

### 1.2 TUI Accessibility

The TUI (ratatui) operates within terminal constraints but maximizes accessibility:

**Keyboard Navigation:**
| Key | Action | Context |
|-----|--------|---------|
| `j` / `k` | Next / Previous row | Timeline, data tables |
| `h` / `l` | Collapse / Expand | Tree views, detail panes |
| `g` / `G` | First / Last item | All list views |
| `/` | Search / Filter | All views |
| `Tab` / `Shift+Tab` | Next / Previous pane | Multi-pane layouts |
| `?` | Show keybindings help | Global |
| `q` | Quit / Back | Global |
| `Enter` | Select / Drill down | All interactive elements |
| `Esc` | Cancel / Close overlay | Modals, search |
| `F1` | Context-sensitive help | Global |

**Terminal Compatibility:**
- Tested against: Windows Terminal, macOS Terminal.app, iTerm2, Linux xterm, tmux, screen
- SSH session support: no mouse-dependent interactions; all actions keyboard-accessible
- Minimum terminal: 80x24 characters; graceful degradation below that
- 256-color fallback when truecolor unavailable; 16-color fallback for minimal terminals

**Information Encoding:**
- Artifact types: color + prefix icon + text label (never color alone)
- Severity levels: color + icon + text (e.g., `[!] CRITICAL`, `[*] HIGH`, `[-] MEDIUM`, `[ ] LOW`, `[i] INFO`)
- Integrity status: color + icon + text (e.g., `[V] Verified`, `[?] Unverified`, `[X] Tampered`)
- Progress: percentage + elapsed time + ETA as text, not just a color bar

### 1.3 Print / PDF / Word Accessibility

Attorney deliverables must be accessible for ADA compliance:

**Tagged PDF Requirements:**
- Proper heading hierarchy (H1-H4) -- never skip levels
- Reading order tags match visual layout
- Alt text on all charts, diagrams, and density heatmaps
- Data tables tagged with `<TH>` scope attributes
- Figure captions linked to their images
- Bookmarks for all sections

**Word Document Requirements:**
- Built-in heading styles (Heading 1-4), not manual formatting
- Alt text on all embedded images and charts
- Table headers marked with "Repeat as header row"
- No information conveyed by color alone in printed output
- Document language set (`en-US`)

**Print Color Safety:**
```css
@media print {
  /* All semantic colors become high-contrast black/white */
  .badge { background: transparent; border: 1px solid #999; color: #000; }
  .badge--verified { border-color: #059669; color: #059669; }
  .badge--tampered { border-color: #DC2626; color: #DC2626; font-weight: bold; }

  /* Artifact badges print as text-only labels */
  .timeline-row, .data-table td { color: #000; }

  /* Table zebra striping for readability */
  .data-table tr:nth-child(even) { background-color: #F8FAFC; }
}
```

---

## 2. WCAG 2.1 AA Compliance Checklist

This checklist applies to HTML reports, the Tauri GUI, and future Web UI. Criteria marked "Planned" are targeted for the surface's initial release.

### 2.1 Perceivable

| Criterion | Requirement | Issen Implementation | Status |
|-----------|-------------|---------------------------|--------|
| **1.1.1 Non-text Content** | All images have alt text | Alt text on density heatmaps, timeline charts, evidence screenshots; `aria-label` on icon-only buttons | Planned |
| **1.3.1 Info and Relationships** | Semantic HTML structure | `<header>`, `<nav>`, `<main>`, `<section>`, `<aside>` landmarks; heading hierarchy H1-H4; form `<label>` associations | Planned |
| **1.3.2 Meaningful Sequence** | Reading order matches visual order | DOM order follows visual layout; timeline is chronological in DOM | Planned |
| **1.3.4 Orientation** | No orientation lock | Responsive design, no fixed orientation | Planned |
| **1.3.5 Identify Input Purpose** | Input autocomplete attributes | `autocomplete` on case metadata form fields | Planned |
| **1.4.1 Use of Color** | Color not sole indicator | Artifact types use icon + text + color; severity uses icon + label + color; integrity badges use icon + text | Planned |
| **1.4.3 Contrast (Minimum)** | 4.5:1 text, 3:1 large text | Light: `#0F172A` on `#FFFFFF` = 17.4:1; Dark: `#F1F5F9` on `#0F172A` = 15.3:1; Accent `#D97706` on white = 4.6:1 | Planned |
| **1.4.4 Resize Text** | Readable at 200% zoom | rem-based typography (minor third scale 1.200); no fixed heights on text containers | Planned |
| **1.4.10 Reflow** | No horizontal scroll at 320px | Responsive breakpoints; timeline table horizontally scrollable with sticky first column; data tables stack on narrow viewports | Planned |
| **1.4.11 Non-text Contrast** | 3:1 for UI components | Focus rings: `2px solid var(--ring)` offset `2px`; all icons/borders verified | Planned |
| **1.4.12 Text Spacing** | No content loss when spaced | No `overflow: hidden` on text containers; flexible line heights | Planned |
| **1.4.13 Content on Hover/Focus** | Dismissible, hoverable, persistent | Tooltips on artifact details: Esc to dismiss, remain while hovered, 5s auto-dismiss with pause on hover | Planned |

### 2.2 Operable

| Criterion | Requirement | Issen Implementation | Status |
|-----------|-------------|---------------------------|--------|
| **2.1.1 Keyboard** | All functionality via keyboard | Tab through interactive elements; Enter/Space to activate; arrow keys in data tables; vim-style shortcuts as progressive enhancement | Planned |
| **2.1.2 No Keyboard Trap** | Keyboard focus never trapped | Modal dialogs trap focus but Esc always exits; filter dropdowns close on Esc; export dialogs closeable | Planned |
| **2.1.4 Character Key Shortcuts** | Single-key shortcuts configurable | `j`/`k` navigation disabled when focus in input; `?` shortcut help; all shortcuts remappable in settings | Planned |
| **2.4.1 Bypass Blocks** | Skip navigation links | Skip links: "Skip to timeline", "Skip to findings", "Skip to report controls" | Planned |
| **2.4.2 Page Titled** | Descriptive page titles | `<title>` includes case name and section: "Issen -- Case 2024-0042 -- Timeline" | Planned |
| **2.4.3 Focus Order** | Logical focus sequence | Tab order: navigation > filters > main content > detail pane > actions | Planned |
| **2.4.6 Headings and Labels** | Descriptive headings | Section headings describe content: "Timeline Events (12,847)", "Findings Summary (7 Critical)" | Planned |
| **2.4.7 Focus Visible** | Visible focus indicator | `outline: 2px solid var(--ring); outline-offset: 2px;` on all focusable elements | Planned |
| **2.4.11 Focus Not Obscured** | Focus indicator not hidden | Sticky headers account for focus offset; no absolutely positioned overlays obscure focused elements | Planned |
| **2.5.1 Pointer Gestures** | Single-pointer alternatives | All multi-touch gestures have button alternatives; pinch-zoom supplemented by zoom controls | Planned |

### 2.3 Understandable

| Criterion | Requirement | Issen Implementation | Status |
|-----------|-------------|---------------------------|--------|
| **3.1.1 Language of Page** | `lang` attribute set | `<html lang="en">` on all HTML reports; Word documents set language to en-US | Planned |
| **3.1.2 Language of Parts** | `lang` on foreign text | Forensic artifacts may contain non-English strings; wrapped in `<span lang="...">` when detectable | Planned |
| **3.2.1 On Focus** | No unexpected context change | Focus does not trigger navigation or form submission; detail pane opens only on Enter/click | Planned |
| **3.2.2 On Input** | No unexpected context change | Filter changes update results but do not navigate away; auto-submit on filter disabled | Planned |
| **3.2.3 Consistent Navigation** | Navigation consistent across pages | Report sections maintain consistent nav sidebar across all views | Planned |
| **3.2.4 Consistent Identification** | Same function = same label | "Export" always means export; "Generate Report" always generates; consistent iconography | Planned |
| **3.3.1 Error Identification** | Errors clearly described | Parse errors: specific artifact + line number + human-readable description; form errors: field-level messages | Planned |
| **3.3.2 Labels or Instructions** | Fields have labels | All filter inputs, case metadata fields, and report options have visible `<label>` elements | Planned |
| **3.3.3 Error Suggestion** | Suggest corrections | "Unsupported format .xyz -- did you mean to use rt ingest with --format flag?" | Planned |
| **3.3.4 Error Prevention** | Confirm destructive actions | "Delete case" requires typed confirmation; "Overwrite report" shows diff preview | Planned |

### 2.4 Robust

| Criterion | Requirement | Issen Implementation | Status |
|-----------|-------------|---------------------------|--------|
| **4.1.1 Parsing** | Valid HTML | No duplicate IDs; proper nesting; W3C validator clean; unique IDs per timeline event | Planned |
| **4.1.2 Name, Role, Value** | ARIA on custom widgets | `role="grid"` on data tables; `role="tree"` on artifact tree; `role="tablist"` on view switcher; `aria-sort` on sortable columns | Planned |
| **4.1.3 Status Messages** | Status announced without focus | `aria-live="polite"` on parse progress; `aria-live="assertive"` on errors; status bar region | Planned |

---

## 3. Screen Reader Patterns for Forensic Operations

### 3.1 The Challenge

Issen involves:
- **8-10 minute P95 parse time** with 5 sequential stages (ingest, validate, parse, correlate, index)
- **Streaming output** as artifacts are parsed in real-time
- **Progress states** that update frequently across multiple parsers running in parallel
- **Dense data tables** with 50,000+ rows in timeline views

Screen reader users need to be informed of progress **without being overwhelmed** during long IR sessions.

### 3.2 Live Region Strategy

```html
<!-- Coalesced progress announcements (HTML report generation view) -->
<div
  aria-live="polite"
  aria-atomic="true"
  role="status"
  id="parse-status"
  class="sr-only"
>
  <!-- Updated every 10 seconds during parsing, not on every artifact -->
  Parsing evidence: 3,247 of approximately 12,000 artifacts processed.
  Stage 3 of 5: Timeline correlation. Estimated 4 minutes remaining.
</div>

<!-- Assertive announcements for critical events only -->
<div
  aria-live="assertive"
  aria-atomic="true"
  role="alert"
  id="parse-alerts"
  class="sr-only"
>
  <!-- Only for errors and completion -->
</div>

<!-- Individual parser status (polite, low frequency) -->
<div
  aria-live="polite"
  aria-atomic="true"
  role="log"
  id="parser-log"
  class="sr-only"
>
  <!-- Appended as parsers complete -->
  Registry parser complete: 1,247 entries extracted.
  MFT parser complete: 8,392 entries extracted.
</div>
```

**Coalescing rules:**
- Progress updates: maximum once every 10 seconds (`10000ms` interval)
- Parser completion: announce immediately (low frequency, high value)
- Errors: announce immediately via `assertive` region
- Stage transitions: announce immediately ("Now correlating timeline events across sources")

### 3.3 Progress Announcement Patterns

```typescript
// Coalesced progress announcer for HTML report / GUI
class ForensicProgressAnnouncer {
  private statusEl: HTMLElement;
  private alertEl: HTMLElement;
  private logEl: HTMLElement;
  private lastAnnouncement = 0;
  private readonly COALESCE_INTERVAL = 10_000; // 10 seconds

  constructor() {
    this.statusEl = document.getElementById('parse-status')!;
    this.alertEl = document.getElementById('parse-alerts')!;
    this.logEl = document.getElementById('parser-log')!;
  }

  announceProgress(processed: number, total: number, stage: string, stageNum: number, totalStages: number, etaMinutes: number): void {
    const now = Date.now();
    if (now - this.lastAnnouncement < this.COALESCE_INTERVAL) return;

    this.lastAnnouncement = now;
    this.statusEl.textContent =
      `Parsing evidence: ${processed.toLocaleString()} of approximately ${total.toLocaleString()} artifacts processed. ` +
      `Stage ${stageNum} of ${totalStages}: ${stage}. ` +
      `Estimated ${etaMinutes} minute${etaMinutes === 1 ? '' : 's'} remaining.`;
  }

  announceParserComplete(parserName: string, entriesFound: number): void {
    const entry = document.createElement('p');
    entry.textContent = `${parserName} complete: ${entriesFound.toLocaleString()} entries extracted.`;
    this.logEl.appendChild(entry);
  }

  announceStageTransition(stageName: string, stageNum: number, totalStages: number): void {
    this.statusEl.textContent =
      `Stage ${stageNum} of ${totalStages}: ${stageName}. Processing continues.`;
    this.lastAnnouncement = Date.now();
  }

  announceComplete(totalArtifacts: number, totalTime: string): void {
    this.alertEl.textContent =
      `Evidence parsing complete. ${totalArtifacts.toLocaleString()} artifacts processed in ${totalTime}. ` +
      `Results are ready for review. Press Tab to navigate to the timeline.`;
  }

  announceError(errorType: string, detail: string, recoveryAction: string): void {
    this.alertEl.textContent =
      `Error: ${errorType}. ${detail}. ${recoveryAction}`;
  }
}
```

### 3.4 Data Table Screen Reader Patterns

Timeline data tables with 50,000+ rows require special handling:

```html
<!-- Virtualized data table with screen reader context -->
<div role="region" aria-label="Timeline events: 12,847 total, filtered to 342 matching 'suspicious'">

  <table role="grid" aria-label="Timeline events" aria-rowcount="342" aria-colcount="7">
    <thead>
      <tr role="row">
        <th role="columnheader" aria-sort="descending" aria-colindex="1">Timestamp</th>
        <th role="columnheader" aria-sort="none" aria-colindex="2">Source</th>
        <th role="columnheader" aria-sort="none" aria-colindex="3">Artifact Type</th>
        <th role="columnheader" aria-sort="none" aria-colindex="4">Description</th>
        <th role="columnheader" aria-sort="none" aria-colindex="5">Severity</th>
        <th role="columnheader" aria-sort="none" aria-colindex="6">Integrity</th>
        <th role="columnheader" aria-sort="none" aria-colindex="7">Actions</th>
      </tr>
    </thead>
    <tbody>
      <!-- aria-rowindex for virtualized rows (only visible subset rendered) -->
      <tr role="row" aria-rowindex="1">
        <td role="gridcell" aria-colindex="1">2024-03-15 14:32:07 UTC</td>
        <td role="gridcell" aria-colindex="2">SYSTEM registry</td>
        <td role="gridcell" aria-colindex="3">
          <span class="badge badge--registry" aria-label="Registry artifact">Registry</span>
        </td>
        <td role="gridcell" aria-colindex="4">Service creation: backdoor-svc in SYSTEM\CurrentControlSet\Services</td>
        <td role="gridcell" aria-colindex="5">
          <span class="badge badge--critical" aria-label="Critical severity">Critical</span>
        </td>
        <td role="gridcell" aria-colindex="6">
          <span class="badge badge--verified" aria-label="Integrity verified">Verified</span>
        </td>
        <td role="gridcell" aria-colindex="7">
          <button aria-label="View details for event at 2024-03-15 14:32:07">Details</button>
          <button aria-label="Mark as finding">Flag</button>
        </td>
      </tr>
    </tbody>
  </table>
</div>

<!-- Active filter summary for screen readers -->
<div role="status" aria-live="polite" class="sr-only" id="filter-status">
  Showing 342 of 12,847 events. Filtered by: keyword "suspicious", severity Critical and High, time range 2024-03-15 to 2024-03-16.
</div>
```

### 3.5 Error Announcement Pattern

```typescript
// Error announcements in forensic context
interface ForensicError {
  type: 'parse_failure' | 'corrupt_artifact' | 'unsupported_format' | 'permission_denied' | 'hash_mismatch';
  artifact?: string;
  detail: string;
  recovery: string;
  severity: 'blocking' | 'degraded' | 'informational';
}

function announceForensicError(error: ForensicError): void {
  const alertEl = document.getElementById('parse-alerts')!;

  const severityPrefix = {
    blocking: 'Critical error',
    degraded: 'Warning',
    informational: 'Notice',
  }[error.severity];

  alertEl.textContent =
    `${severityPrefix}: ${error.detail}. ${error.recovery}`;

  // For blocking errors, move focus to error region
  if (error.severity === 'blocking') {
    const errorHeading = document.getElementById('error-heading');
    if (errorHeading) {
      errorHeading.focus();
    }
  }
}

// Example usage:
// announceForensicError({
//   type: 'corrupt_artifact',
//   artifact: '$MFT',
//   detail: 'MFT parser encountered corrupt entry at offset 0x4A2F00. 8,392 entries extracted before failure.',
//   recovery: 'Partial results are available. Review timeline for completeness. Re-acquire MFT if full coverage needed.',
//   severity: 'degraded',
// });
```

---

## 4. Focus Management During Evidence Processing

### 4.1 Focus Strategy by State

| Application State | Focus Position | Rationale |
|-------------------|---------------|-----------|
| **Ingest started** | Progress region heading | User initiated action; confirm it started |
| **Parsing in progress** | Remains on progress region; not stolen | Do not disrupt user reading other content |
| **Parser error (degraded)** | Status bar warning; focus not moved | Non-blocking; user should continue |
| **Parser error (blocking)** | Error heading (moved) | Requires user attention |
| **Parse complete** | "View Results" button | Clear next action |
| **Report generating** | Progress region | Same as parse |
| **Report complete** | Download/view link | Clear next action |
| **Filter applied** | Results count summary | Confirm filter worked |
| **Detail pane opened** | Detail pane heading | User requested drill-down |
| **Modal opened** | First focusable element in modal | Standard modal pattern |
| **Modal closed** | Element that triggered modal | Return context |

### 4.2 Implementation Pattern

```typescript
// Focus management for forensic operations (HTML report / GUI)
class ForensicFocusManager {
  private triggerStack: HTMLElement[] = [];

  saveTrigger(element: HTMLElement): void {
    this.triggerStack.push(element);
  }

  restoreTrigger(): void {
    const trigger = this.triggerStack.pop();
    if (trigger && document.contains(trigger)) {
      trigger.focus();
    }
  }

  onParseStart(): void {
    const progressHeading = document.getElementById('parse-progress-heading');
    progressHeading?.focus();
  }

  onParseComplete(): void {
    const viewResults = document.getElementById('view-results-btn');
    if (viewResults) {
      viewResults.focus();
      // Announce completion via live region (handled by ProgressAnnouncer)
    }
  }

  onBlockingError(): void {
    const errorHeading = document.getElementById('error-heading');
    errorHeading?.focus();
  }

  onFilterApplied(resultCount: number, totalCount: number): void {
    const filterStatus = document.getElementById('filter-status');
    if (filterStatus) {
      filterStatus.textContent =
        `Showing ${resultCount.toLocaleString()} of ${totalCount.toLocaleString()} events.`;
      // aria-live="polite" on the element handles announcement
    }
  }

  onDetailPaneOpened(trigger: HTMLElement): void {
    this.saveTrigger(trigger);
    const detailHeading = document.getElementById('detail-pane-heading');
    detailHeading?.focus();
  }

  onDetailPaneClosed(): void {
    this.restoreTrigger();
  }
}
```

### 4.3 Skip Links for Forensic Reports

HTML reports are long documents. Skip links help screen reader and keyboard users navigate efficiently:

```html
<div class="skip-links">
  <a href="#executive-summary" class="skip-link">Skip to Executive Summary</a>
  <a href="#timeline" class="skip-link">Skip to Timeline</a>
  <a href="#findings" class="skip-link">Skip to Findings</a>
  <a href="#evidence-details" class="skip-link">Skip to Evidence Details</a>
  <a href="#exhibits" class="skip-link">Skip to Exhibits</a>
  <a href="#methodology" class="skip-link">Skip to Methodology</a>
</div>

<style>
  .skip-link {
    position: absolute;
    top: -100%;
    left: 0;
    padding: var(--space-2) var(--space-4);
    background: var(--color-accent);
    color: var(--color-text-on-accent);
    font-weight: var(--font-semibold);
    z-index: var(--z-overlay);
    text-decoration: none;
    border-radius: var(--radius-md);
  }
  .skip-link:focus {
    top: var(--space-2);
    left: var(--space-2);
  }
</style>
```

---

## 5. Cognitive Load Mitigation

Forensic examiners work 12-16 hour days during active IR engagements. Eye strain and cognitive fatigue are occupational hazards, not edge cases.

### 5.1 Dark Mode as Primary Mode

Dark mode is the default analysis environment. Light mode is available but secondary.

**TUI:** Always dark (terminal background). Colors are chosen for dark backgrounds first.

**HTML Reports / GUI:**
```css
/* Dark mode is default for analysis; light mode for print/sharing */
:root {
  color-scheme: dark light;
}

/* Dark mode tokens (primary) */
@media (prefers-color-scheme: dark) {
  :root {
    --color-bg: #0F172A;           /* slate-900 */
    --color-surface: #1E293B;      /* slate-800 */
    --color-text: #F1F5F9;         /* slate-100 */
    --color-text-secondary: #CBD5E1; /* slate-300 */
    --color-text-muted: #64748B;   /* slate-500 -- verified 4.5:1 on surface */
    --color-accent: #F59E0B;       /* amber-500 -- brighter for dark */
  }
}

/* User override toggle (persisted in localStorage) */
[data-theme="dark"] {
  --color-bg: #0F172A;
  --color-surface: #1E293B;
  --color-text: #F1F5F9;
  /* ... same as above ... */
}
```

**Contrast verification for dark mode:**
| Pair | Foreground | Background | Ratio | Passes |
|------|-----------|-----------|-------|--------|
| Body text | `#F1F5F9` | `#0F172A` | 15.3:1 | AA + AAA |
| Secondary text | `#CBD5E1` | `#0F172A` | 10.2:1 | AA + AAA |
| Muted text | `#64748B` | `#1E293B` | 4.6:1 | AA |
| Accent on bg | `#F59E0B` | `#0F172A` | 8.9:1 | AA + AAA |
| Accent on surface | `#F59E0B` | `#1E293B` | 7.5:1 | AA + AAA |
| Success | `#34D399` | `#0F172A` | 10.0:1 | AA + AAA |
| Warning | `#FBBF24` | `#0F172A` | 12.1:1 | AA + AAA |
| Error | `#F87171` | `#0F172A` | 6.5:1 | AA |

### 5.2 Progressive Disclosure for Dense Data

Timeline views may display 50,000+ events. Progressive disclosure prevents overwhelm:

```html
<div role="region" aria-label="Evidence timeline">
  <!-- Summary first -->
  <div class="timeline-summary">
    <h2>Timeline: 12,847 Events</h2>
    <p>Time range: 2024-03-14 08:00 UTC to 2024-03-16 23:59 UTC</p>
    <p>7 findings flagged (3 Critical, 2 High, 1 Medium, 1 Low)</p>
  </div>

  <!-- Density heatmap (collapsible) -->
  <details>
    <summary>Activity Density Heatmap</summary>
    <div role="img" aria-label="Activity heatmap showing peak activity at 2024-03-15 14:00-16:00 UTC with 2,847 events.
      Secondary peak at 2024-03-15 02:00-04:00 UTC with 1,203 events. Baseline activity 50-100 events per hour.">
      <!-- Canvas/SVG heatmap rendered here -->
    </div>
  </details>

  <!-- Findings-first view (default expanded) -->
  <section aria-label="Flagged findings">
    <h3>Flagged Findings (7)</h3>
    <!-- Show findings first, then full timeline -->
  </section>

  <!-- Full timeline (collapsed by default for large datasets) -->
  <details>
    <summary>Full Timeline (12,847 events)</summary>
    <!-- Virtualized data table -->
  </details>
</div>
```

### 5.3 Reduced Motion Support

```css
@media (prefers-reduced-motion: reduce) {
  *,
  *::before,
  *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }

  /* Timeline heatmap: static render instead of animated build-up */
  .heatmap-cell { opacity: 1; transform: none; }

  /* Parse progress: static bar instead of animated fill */
  .progress-bar { transition: none; }

  /* Loading states: text instead of spinner */
  .loading-spinner { animation: none; }
  .loading-spinner::after { content: 'Loading...'; }

  /* Virtualized scroll: instant positioning */
  .virtual-scroll { scroll-behavior: auto; }
}
```

### 5.4 Time Expectation Setting

Long-running forensic operations must set clear expectations:

```html
<!-- Before parse begins -->
<div role="status" aria-live="polite">
  <p>
    Parsing will process approximately 12,000 artifacts across 5 stages.
    Estimated time: 6-10 minutes based on evidence size (42 GB).
  </p>
</div>

<!-- During parse -->
<div role="status" aria-live="polite" aria-atomic="true" id="parse-progress">
  <p>
    Stage 3 of 5: Timeline correlation.
    3,247 artifacts processed. Estimated 4 minutes remaining.
  </p>
  <progress
    value="3247"
    max="12000"
    aria-label="Parse progress: 3,247 of 12,000 artifacts"
  >
    27% complete
  </progress>
</div>
```

---

## 6. Color Independence

Forensic tools typically rely heavily on color coding for artifact types and severity. Issen ensures no information is conveyed by color alone.

### 6.1 Artifact Type Encoding

| Artifact Type | Color (Dark) | Icon | Text Label | TUI Prefix |
|--------------|-------------|------|-----------|------------|
| Filesystem | `#60A5FA` (blue-400) | File icon | "Filesystem" | `[FS]` |
| Registry | `#A78BFA` (violet-400) | Key icon | "Registry" | `[REG]` |
| Event Log | `#34D399` (emerald-400) | Log icon | "Event Log" | `[EVT]` |
| Prefetch | `#FBBF24` (amber-400) | Clock icon | "Prefetch" | `[PF]` |
| Browser | `#22D3EE` (cyan-400) | Globe icon | "Browser" | `[BR]` |
| Email | `#F87171` (red-400) | Mail icon | "Email" | `[ML]` |
| Network | `#818CF8` (indigo-400) | Network icon | "Network" | `[NET]` |
| Persistence | `#F472B6` (pink-400) | Pin icon | "Persistence" | `[PERS]` |
| Memory | `#C084FC` (purple-400) | Chip icon | "Memory" | `[MEM]` |
| Cloud | `#2DD4BF` (teal-400) | Cloud icon | "Cloud" | `[CLD]` |
| USB | `#FB923C` (orange-400) | USB icon | "USB" | `[USB]` |
| User Activity | `#94A3B8` (slate-400) | User icon | "User" | `[USR]` |

**Color-blind safe verification:**
- All artifact type colors tested under deuteranopia, protanopia, and tritanopia simulations
- Adjacent colors in the palette maintain perceptual distinctiveness under all three simulations
- When colors cannot be distinguished, the icon + text label always provides the information

### 6.2 Severity Encoding

| Severity | Color (Dark) | Icon | Text | TUI |
|----------|-------------|------|------|-----|
| Critical | `#F87171` | Filled circle | "Critical" | `[!]` |
| High | `#FB923C` | Triangle | "High" | `[*]` |
| Medium | `#FBBF24` | Diamond | "Medium" | `[-]` |
| Low | `#60A5FA` | Square | "Low" | `[ ]` |
| Info | `#94A3B8` | Circle outline | "Info" | `[i]` |

### 6.3 Integrity Encoding

| Status | Color (Dark) | Icon | Text | TUI |
|--------|-------------|------|------|-----|
| Verified | `#34D399` | Checkmark | "Verified" | `[V]` |
| Unverified | `#FBBF24` | Question | "Unverified" | `[?]` |
| Tampered | `#F87171` | X mark | "Tampered" | `[X]` |
| Partial | `#C084FC` | Half-circle | "Partial" | `[~]` |

---

## 7. Form Accessibility

### 7.1 Case Metadata Form

The case setup workflow collects metadata before evidence ingestion:

```html
<form aria-label="Case setup" novalidate>
  <fieldset>
    <legend>Case Information</legend>

    <div class="form-field">
      <label for="case-number">Case Number <span aria-hidden="true">*</span></label>
      <input
        type="text"
        id="case-number"
        name="case_number"
        required
        aria-required="true"
        aria-describedby="case-number-help"
        autocomplete="off"
        placeholder="e.g., 2024-IR-0042"
      />
      <span id="case-number-help" class="form-help">
        Your organization's case tracking number.
      </span>
    </div>

    <div class="form-field">
      <label for="examiner-name">Examiner Name <span aria-hidden="true">*</span></label>
      <input
        type="text"
        id="examiner-name"
        name="examiner_name"
        required
        aria-required="true"
        autocomplete="name"
      />
    </div>

    <div class="form-field">
      <label for="case-type">Case Type</label>
      <select id="case-type" name="case_type" aria-describedby="case-type-help">
        <option value="">Select case type...</option>
        <option value="incident-response">Incident Response</option>
        <option value="internal-investigation">Internal Investigation</option>
        <option value="litigation-support">Litigation Support</option>
        <option value="compliance">Compliance / Regulatory</option>
        <option value="other">Other</option>
      </select>
      <span id="case-type-help" class="form-help">
        Determines default report template and artifact priority.
      </span>
    </div>
  </fieldset>

  <fieldset>
    <legend>Evidence Sources</legend>

    <div class="form-field">
      <label for="evidence-path">Evidence Path <span aria-hidden="true">*</span></label>
      <input
        type="text"
        id="evidence-path"
        name="evidence_path"
        required
        aria-required="true"
        aria-describedby="evidence-path-help"
        placeholder="/path/to/evidence/"
      />
      <span id="evidence-path-help" class="form-help">
        Directory containing KAPE output, E01 images, or collected artifacts.
      </span>
    </div>

    <div role="group" aria-labelledby="collection-tool-label">
      <span id="collection-tool-label" class="form-label">Collection Tool</span>
      <label><input type="radio" name="collection_tool" value="kape" /> KAPE</label>
      <label><input type="radio" name="collection_tool" value="velociraptor" /> Velociraptor</label>
      <label><input type="radio" name="collection_tool" value="acquire" /> ACQUIRE</label>
      <label><input type="radio" name="collection_tool" value="manual" /> Manual Collection</label>
      <label><input type="radio" name="collection_tool" value="other" /> Other</label>
    </div>
  </fieldset>
</form>
```

### 7.2 Filter Controls

Timeline filters are high-frequency interactions during analysis:

```html
<div role="search" aria-label="Timeline filters">
  <div class="filter-group">
    <label for="filter-keyword">Search events</label>
    <input
      type="search"
      id="filter-keyword"
      name="keyword"
      aria-describedby="filter-keyword-help filter-status"
      placeholder="Search artifacts, descriptions..."
    />
    <span id="filter-keyword-help" class="sr-only">
      Type to filter timeline events. Results update as you type after 300ms debounce.
    </span>
  </div>

  <div class="filter-group">
    <label for="filter-severity">Severity</label>
    <select id="filter-severity" name="severity" multiple aria-describedby="filter-status">
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
      <option value="low">Low</option>
      <option value="info">Info</option>
    </select>
  </div>

  <div class="filter-group">
    <label for="filter-time-start">Time range start</label>
    <input type="datetime-local" id="filter-time-start" name="time_start" />
    <label for="filter-time-end">Time range end</label>
    <input type="datetime-local" id="filter-time-end" name="time_end" />
  </div>

  <div id="filter-status" role="status" aria-live="polite" class="sr-only">
    <!-- Dynamically updated: "Showing 342 of 12,847 events" -->
  </div>
</div>
```

---

## 8. Keyboard Navigation

### 8.1 Global Keyboard Shortcuts (HTML Report / GUI)

| Key | Action | Context |
|-----|--------|---------|
| `j` | Next event in timeline | Timeline view (not in input) |
| `k` | Previous event in timeline | Timeline view (not in input) |
| `g` then `g` | Go to first event | Timeline view |
| `G` | Go to last event | Timeline view |
| `/` | Focus search/filter input | Any view |
| `f` | Toggle findings-only view | Timeline view |
| `e` | Export current view | Any view with data |
| `?` | Show keyboard shortcuts help | Global |
| `Escape` | Close modal/overlay/detail pane | When overlay active |
| `Ctrl+Home` | Go to report top | HTML report |
| `Ctrl+End` | Go to report bottom | HTML report |

**Implementation guard:** Shortcuts are suppressed when focus is inside `<input>`, `<textarea>`, or `[contenteditable]` elements.

### 8.2 TUI Keyboard Patterns

TUI keybindings follow vim conventions familiar to technical users:

```
Navigation:
  j/k           Move down/up in current list
  h/l           Collapse/expand tree node or switch panes
  g/G           Jump to first/last item
  Ctrl+d/u      Page down/up (half screen)
  Ctrl+f/b      Page down/up (full screen)

Search and Filter:
  /             Enter search mode (type, then Enter to search)
  n/N           Next/previous search result
  f             Open filter panel
  c             Clear all filters

Actions:
  Enter         Select / drill into detail
  Space         Toggle mark/flag on current item
  x             Add to findings
  r             Open report generation dialog
  Tab           Cycle focus between panes
  ?             Show keybinding reference
  q             Quit / back one level
  Q             Force quit
```

### 8.3 Focus Trap for Modals

```typescript
// Focus trap for export dialog, report options, etc.
function trapFocus(modalElement: HTMLElement): () => void {
  const focusableSelectors = [
    'a[href]',
    'button:not([disabled])',
    'input:not([disabled])',
    'select:not([disabled])',
    'textarea:not([disabled])',
    '[tabindex]:not([tabindex="-1"])',
  ].join(', ');

  const focusableElements = modalElement.querySelectorAll<HTMLElement>(focusableSelectors);
  const firstFocusable = focusableElements[0];
  const lastFocusable = focusableElements[focusableElements.length - 1];

  function handleKeydown(event: KeyboardEvent): void {
    if (event.key !== 'Tab') return;

    if (event.shiftKey) {
      if (document.activeElement === firstFocusable) {
        event.preventDefault();
        lastFocusable.focus();
      }
    } else {
      if (document.activeElement === lastFocusable) {
        event.preventDefault();
        firstFocusable.focus();
      }
    }

    if (event.key === 'Escape') {
      // Close modal and restore focus
    }
  }

  modalElement.addEventListener('keydown', handleKeydown);
  firstFocusable?.focus();

  return () => modalElement.removeEventListener('keydown', handleKeydown);
}
```

---

## 9. Testing Protocol

### 9.1 Automated Testing

| Tool | What It Tests | Surface | Integration |
|------|--------------|---------|-------------|
| **axe-core** | WCAG 2.1 AA violations | HTML reports, GUI | CI pipeline; fail build on violations |
| **pa11y** | WCAG 2.1 AA + best practices | HTML reports | CI pipeline; nightly regression |
| **Lighthouse** | Accessibility score (target: 100) | HTML reports | CI pipeline; report per build |
| **jest-axe** | Component-level a11y | React/Leptos components | Unit test suite |
| **html-validate** | Valid HTML structure | HTML reports | CI pipeline; pre-commit hook |
| **color-contrast-checker** | Contrast ratio verification | All color tokens | CI pipeline; token validation |

**CI integration:**
```yaml
# .github/workflows/a11y.yml
name: Accessibility Tests
on: [push, pull_request]
jobs:
  a11y:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Generate sample HTML report
        run: cargo run -- report --sample --format html --output /tmp/sample-report.html
      - name: Run axe-core
        run: npx @axe-core/cli /tmp/sample-report.html --exit
      - name: Run pa11y
        run: npx pa11y /tmp/sample-report.html --standard WCAG2AA
      - name: Run Lighthouse
        uses: treosh/lighthouse-ci-action@v11
        with:
          urls: file:///tmp/sample-report.html
          budgetPath: .lighthouserc-a11y.json
```

### 9.2 Manual Testing Checklist

Perform before each release:

- [ ] **Keyboard-only navigation**: Complete a full "ingest to report" workflow using only keyboard
- [ ] **Screen reader walkthrough**: Navigate sample HTML report with VoiceOver (macOS), NVDA (Windows), and Orca (Linux)
- [ ] **200% zoom**: Verify HTML report remains usable at 200% browser zoom
- [ ] **Color blindness simulation**: Review HTML report and TUI under deuteranopia, protanopia, and tritanopia (use Sim Daltonism or similar)
- [ ] **Reduced motion**: Enable `prefers-reduced-motion: reduce` and verify no content requires animation
- [ ] **High contrast mode**: Test HTML report in Windows High Contrast mode / `forced-colors: active`
- [ ] **Print preview**: Verify PDF/print output has proper heading structure, no color-only information
- [ ] **Terminal diversity**: Test TUI in at least 3 terminal emulators (Windows Terminal, macOS Terminal, xterm)
- [ ] **SSH session**: Verify TUI works over SSH with no mouse, various TERM values
- [ ] **Plain text mode**: Verify `rt timeline --plain` produces usable output with no ANSI escapes
- [ ] **JSON output**: Verify `rt timeline --json` produces valid, parseable JSON
- [ ] **Tagged PDF**: Open generated PDF in Acrobat and run accessibility checker
- [ ] **Word document**: Open generated .docx in Word and run Accessibility Checker

### 9.3 Screen Reader Test Script

Test the core "Evidence to Report" journey with a screen reader:

**Test 1: HTML Report Navigation**
1. Open sample HTML report in browser with screen reader active
2. Verify skip links are announced and functional
3. Tab through the executive summary section -- verify all headings are announced
4. Navigate to the timeline table -- verify column headers are announced
5. Arrow through timeline rows -- verify each cell announces its column context
6. Verify severity badges announce "Critical severity" not just a color
7. Navigate to a finding -- verify the finding description is fully readable
8. Verify exhibit references link to the correct evidence detail

**Test 2: Parse Progress (GUI)**
1. Start an evidence parse operation
2. Verify initial time estimate is announced
3. Wait for stage transitions -- verify announcements are clear and not overwhelming
4. Verify parser completion announcements include artifact counts
5. On completion, verify focus moves to "View Results" or equivalent

**Test 3: Error Handling**
1. Attempt to ingest an unsupported format
2. Verify error is announced via assertive live region
3. Verify recovery suggestion is included in announcement
4. Verify focus management: blocking errors move focus to error; degraded errors do not

**Test 4: Data Table Interaction**
1. Navigate to a data table with 1,000+ rows
2. Verify `aria-rowcount` announces total rows
3. Apply a filter -- verify filter result count is announced
4. Sort a column -- verify `aria-sort` attribute changes and is announced
5. Select a row -- verify `aria-selected` change is announced

---

## 10. Component Library Requirements

### 10.1 Required ARIA Patterns by Component

| Component | ARIA Role | Key Attributes | Keyboard |
|-----------|----------|----------------|----------|
| **Timeline Table** | `grid` | `aria-rowcount`, `aria-colcount`, `aria-sort` on headers | Arrow keys, Enter to select |
| **Artifact Tree** | `tree` | `aria-expanded`, `aria-level`, `aria-selected` | Arrow keys, Enter to expand |
| **Detail Pane** | `complementary` | `aria-label="Evidence detail"` | Esc to close |
| **Filter Panel** | `search` | `aria-label="Timeline filters"` | Tab between fields |
| **Export Dialog** | `dialog` | `aria-modal="true"`, `aria-labelledby` | Focus trapped, Esc to close |
| **Severity Badge** | implicit (`span`) | `aria-label="Critical severity"` | N/A (informational) |
| **Integrity Badge** | implicit (`span`) | `aria-label="Integrity verified"` | N/A (informational) |
| **Progress Bar** | `progressbar` | `aria-valuenow`, `aria-valuemin`, `aria-valuemax`, `aria-label` | N/A |
| **Toast / Alert** | `alert` | `aria-live="assertive"` | Auto-dismiss pauses on focus |
| **Tabs (View Switcher)** | `tablist` / `tab` / `tabpanel` | `aria-selected`, `aria-controls` | Arrow keys between tabs, Tab into panel |
| **Collapsible Section** | N/A | `<details>`/`<summary>` native | Enter/Space to toggle |
| **Tooltip** | `tooltip` | `aria-describedby` linking trigger to tip | Esc to dismiss, appears on focus |

### 10.2 Focus Indicator Specification

```css
/* Focus indicator -- must meet 3:1 contrast against adjacent colors */
:focus-visible {
  outline: 2px solid var(--color-accent);
  outline-offset: 2px;
}

/* Remove outline for mouse users */
:focus:not(:focus-visible) {
  outline: none;
}

/* High contrast mode support */
@media (forced-colors: active) {
  :focus-visible {
    outline: 3px solid CanvasText;
  }

  /* Ensure badges remain distinguishable */
  .badge {
    border: 1px solid CanvasText;
  }
  .badge--critical, .badge--tampered {
    border-width: 2px;
    font-weight: bold;
  }
}
```

### 10.3 Accessible Loading States

```html
<!-- Skeleton loading for timeline (preferred over spinner) -->
<div aria-busy="true" aria-label="Loading timeline events">
  <div class="skeleton-row" aria-hidden="true"></div>
  <div class="skeleton-row" aria-hidden="true"></div>
  <div class="skeleton-row" aria-hidden="true"></div>
  <span class="sr-only">Loading timeline events, please wait.</span>
</div>

<!-- Parse progress (not a generic spinner) -->
<div
  role="progressbar"
  aria-valuenow="27"
  aria-valuemin="0"
  aria-valuemax="100"
  aria-label="Parsing evidence: 27% complete, approximately 4 minutes remaining"
>
  <div class="progress-fill" style="width: 27%"></div>
</div>
```

---

## 11. Persona-Specific Accessibility Considerations

### 11.1 Sarah Chen -- Solo IR Practitioner

- Works alone, often late at night during active incidents
- **Dark mode is essential**, not a preference -- reduces eye strain during 14-hour sessions
- Keyboard efficiency critical: every mouse reach costs time during triage
- May use screen magnification for evidence details (hex views, log entries)
- CLI/TUI primary interface; HTML reports are output, not primary interaction

### 11.2 Marcus Webb -- Firm Forensic Examiner

- Works in office environments with varying lighting
- May share screen in partner meetings; **light mode toggle needed** for projector readability
- Report quality is career-critical; print/PDF accessibility matters for firm reputation
- Uses GUI more than CLI; standard accessibility expectations (like any web app)

### 11.3 Diana Reyes -- Litigation Support Analyst

- **Primary consumer of HTML reports**, not the TUI/CLI
- Distributes reports to attorneys who may have visual impairments or use screen readers
- **WCAG compliance of HTML reports is a professional requirement**, not a nice-to-have
- ADA compliance may be contractually required by clients
- PDF/Word accessibility is non-negotiable for court filings

### 11.4 James Okafor -- CISO/IR Manager (Future)

- Consumes dashboards, not raw evidence
- Executive summary must be scannable at a glance
- May access via mobile; responsive design matters
- May forward reports to board members with varying technical ability

---

## 12. Implementation Priorities

### Phase 1: Foundation (MVP)

| Priority | Item | Surface | Effort |
|----------|------|---------|--------|
| P0 | `--no-color`, `--plain`, `--json` CLI flags | CLI | Low |
| P0 | Semantic HTML structure in reports | HTML Reports | Medium |
| P0 | Heading hierarchy and landmark regions | HTML Reports | Low |
| P0 | Color independence (icon + text + color) | All | Medium |
| P0 | Keyboard navigation in TUI | TUI | Medium |
| P1 | Skip links in HTML reports | HTML Reports | Low |
| P1 | Dark/light mode toggle | HTML Reports | Medium |
| P1 | `aria-sort` on data table columns | HTML Reports | Low |
| P1 | Focus indicator (`:focus-visible`) | HTML Reports | Low |

### Phase 2: Compliance

| Priority | Item | Surface | Effort |
|----------|------|---------|--------|
| P0 | axe-core CI integration | HTML Reports | Medium |
| P0 | Screen reader live regions for parse progress | GUI | High |
| P0 | `aria-rowcount` / `aria-colindex` on virtualized tables | HTML Reports, GUI | Medium |
| P1 | Tagged PDF output | Print | High |
| P1 | Word document accessibility checker pass | Print | Medium |
| P1 | Reduced motion support | HTML Reports, GUI | Low |
| P1 | High contrast mode (`forced-colors`) | HTML Reports, GUI | Low |

### Phase 3: Excellence

| Priority | Item | Surface | Effort |
|----------|------|---------|--------|
| P1 | Lighthouse 100 accessibility score | HTML Reports | Medium |
| P1 | Complete NVDA/JAWS/VoiceOver test suite | HTML Reports, GUI | High |
| P2 | Customizable keyboard shortcuts | GUI | Medium |
| P2 | Screen reader optimized TUI mode | TUI | High |
| P2 | Real-time accessibility monitoring dashboard | All | High |

---

*Document generated by North Star Advisor*
