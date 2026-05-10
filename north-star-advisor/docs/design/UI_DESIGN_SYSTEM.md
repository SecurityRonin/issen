# Issen: UI Design System

> **Parent**: [../BRAND_GUIDELINES.md](../BRAND_GUIDELINES.md)
> **Created**: 2026-03-20
> **Status**: Active
> **Generation Step**: 5b of 13 -- Requires `brand.colors`, `brand.typography`, `journeys.*`

Production-ready design tokens, CSS configuration, and component specifications for a multi-surface forensic triage platform spanning TUI (ratatui), HTML reports, Desktop GUI (Tauri v2), and future Web UI (axum + React/Leptos).

## Document Purpose

This document provides **copy-paste-ready design tokens and component specs** for every Issen rendering surface:

1. **CSS Custom Properties** for HTML reports and web/desktop UI
2. **TUI color map** for ratatui 256-color terminals
3. **Component specifications** for forensic-specific patterns (timeline rows, evidence cards, exhibit references)
4. **Artifact source palette** for consistent color-coding across all surfaces
5. **Print stylesheet overrides** for courtroom-credible output

**Relationship to Other Documents:**
- **BRAND_GUIDELINES.md** defines the visual aesthetic: "Dense but organized, print-ready, courtroom-credible"
- **USER_JOURNEYS.md** identifies the core interaction patterns this system must support
- **ACCESSIBILITY.md** (when created) will contain full WCAG compliance details

---

## 1. CSS Custom Properties

### 1.1 Color Palette -- Light Mode

```css
:root {
  /* --- Base Colors --- */
  --color-bg:              #FFFFFF;
  --color-bg-subtle:       #F8FAFC;       /* slate-50 */
  --color-surface:         #FFFFFF;
  --color-surface-raised:  #F1F5F9;       /* slate-100 */
  --color-border:          #CBD5E1;       /* slate-300 */
  --color-border-strong:   #94A3B8;       /* slate-400 */

  /* --- Primary: Slate Blue --- */
  --color-primary:         #475569;       /* slate-600 */
  --color-primary-hover:   #334155;       /* slate-700 */
  --color-primary-active:  #1E293B;       /* slate-800 */
  --color-primary-subtle:  #F1F5F9;       /* slate-100 */

  /* --- Accent: Amber --- */
  --color-accent:          #D97706;       /* amber-600 */
  --color-accent-hover:    #B45309;       /* amber-700 */
  --color-accent-active:   #92400E;       /* amber-800 */
  --color-accent-subtle:   #FFFBEB;       /* amber-50 */

  /* --- Text --- */
  --color-text:            #0F172A;       /* slate-900 */
  --color-text-secondary:  #475569;       /* slate-600 */
  --color-text-muted:      #94A3B8;       /* slate-400 */
  --color-text-on-primary: #FFFFFF;
  --color-text-on-accent:  #FFFFFF;

  /* --- Semantic --- */
  --color-success:         #059669;       /* emerald-600 */
  --color-success-subtle:  #ECFDF5;       /* emerald-50 */
  --color-warning:         #D97706;       /* amber-600 */
  --color-warning-subtle:  #FFFBEB;       /* amber-50 */
  --color-error:           #DC2626;       /* red-600 */
  --color-error-subtle:    #FEF2F2;       /* red-50 */
  --color-info:            #2563EB;       /* blue-600 */
  --color-info-subtle:     #EFF6FF;       /* blue-50 */

  /* --- Evidence Integrity --- */
  --color-verified:        #059669;       /* hash verified, chain intact */
  --color-unverified:      #D97706;       /* hash not yet checked */
  --color-tampered:        #DC2626;       /* hash mismatch, integrity failure */
  --color-partial:         #7C3AED;       /* partial data, incomplete artifact */

  /* --- Severity Levels --- */
  --color-severity-critical: #991B1B;     /* red-800 */
  --color-severity-high:     #DC2626;     /* red-600 */
  --color-severity-medium:   #D97706;     /* amber-600 */
  --color-severity-low:      #2563EB;     /* blue-600 */
  --color-severity-info:     #475569;     /* slate-600 */
}
```

### 1.2 Color Palette -- Dark Mode (Mandatory)

Dark mode is the primary working mode for long forensic analysis sessions. It is not an afterthought.

```css
@media (prefers-color-scheme: dark) {
  :root {
    --color-bg:              #0F172A;     /* slate-900 */
    --color-bg-subtle:       #1E293B;     /* slate-800 */
    --color-surface:         #1E293B;     /* slate-800 */
    --color-surface-raised:  #334155;     /* slate-700 */
    --color-border:          #334155;     /* slate-700 */
    --color-border-strong:   #475569;     /* slate-600 */

    --color-primary:         #94A3B8;     /* slate-400 */
    --color-primary-hover:   #CBD5E1;     /* slate-300 */
    --color-primary-active:  #E2E8F0;     /* slate-200 */
    --color-primary-subtle:  #1E293B;     /* slate-800 */

    --color-accent:          #F59E0B;     /* amber-500 -- brighter for dark bg */
    --color-accent-hover:    #FBBF24;     /* amber-400 */
    --color-accent-active:   #FCD34D;     /* amber-300 */
    --color-accent-subtle:   #451A03;     /* amber-950 */

    --color-text:            #F1F5F9;     /* slate-100 */
    --color-text-secondary:  #CBD5E1;     /* slate-300 */
    --color-text-muted:      #64748B;     /* slate-500 */
    --color-text-on-primary: #0F172A;
    --color-text-on-accent:  #0F172A;

    --color-success:         #34D399;     /* emerald-400 */
    --color-success-subtle:  #064E3B;     /* emerald-900 */
    --color-warning:         #FBBF24;     /* amber-400 */
    --color-warning-subtle:  #451A03;     /* amber-950 */
    --color-error:           #F87171;     /* red-400 */
    --color-error-subtle:    #450A0A;     /* red-950 */
    --color-info:            #60A5FA;     /* blue-400 */
    --color-info-subtle:     #172554;     /* blue-950 */

    --color-verified:        #34D399;
    --color-unverified:      #FBBF24;
    --color-tampered:        #F87171;
    --color-partial:         #A78BFA;

    --color-severity-critical: #FCA5A5;
    --color-severity-high:     #F87171;
    --color-severity-medium:   #FBBF24;
    --color-severity-low:      #60A5FA;
    --color-severity-info:     #94A3B8;
  }
}
```

### 1.3 Artifact Source Type Palette

Forensic examiners rely on consistent color-coding to identify artifact sources at a glance. These 12 colors are chosen for maximum distinguishability at WCAG AA contrast against both light and dark backgrounds.

```css
:root {
  /* --- Artifact Source Types (Light Mode) --- */
  --color-artifact-filesystem:  #2563EB;  /* blue-600    -- MFT, USN Journal, $LogFile */
  --color-artifact-registry:    #7C3AED;  /* violet-600  -- SYSTEM, SOFTWARE, NTUSER, SAM */
  --color-artifact-eventlog:    #059669;  /* emerald-600 -- Windows Event Logs */
  --color-artifact-prefetch:    #D97706;  /* amber-600   -- Prefetch, Superfetch */
  --color-artifact-browser:     #0891B2;  /* cyan-600    -- Chrome, Firefox, Edge history */
  --color-artifact-email:       #DC2626;  /* red-600     -- PST, OST, EML */
  --color-artifact-network:     #4F46E5;  /* indigo-600  -- PCAP, DNS, firewall logs */
  --color-artifact-persistence: #BE185D;  /* pink-700    -- Scheduled tasks, services, startup */
  --color-artifact-memory:      #9333EA;  /* purple-600  -- RAM dumps, pagefile */
  --color-artifact-cloud:       #0D9488;  /* teal-600    -- O365, Azure AD, AWS CloudTrail */
  --color-artifact-usb:         #EA580C;  /* orange-600  -- USB device history, SetupAPI */
  --color-artifact-user:        #475569;  /* slate-600   -- LNK, JumpLists, shellbags, RDP */
}

/* Dark mode overrides use 400-weight variants for readability */
@media (prefers-color-scheme: dark) {
  :root {
    --color-artifact-filesystem:  #60A5FA;  /* blue-400 */
    --color-artifact-registry:    #A78BFA;  /* violet-400 */
    --color-artifact-eventlog:    #34D399;  /* emerald-400 */
    --color-artifact-prefetch:    #FBBF24;  /* amber-400 */
    --color-artifact-browser:     #22D3EE;  /* cyan-400 */
    --color-artifact-email:       #F87171;  /* red-400 */
    --color-artifact-network:     #818CF8;  /* indigo-400 */
    --color-artifact-persistence: #F472B6;  /* pink-400 */
    --color-artifact-memory:      #C084FC;  /* purple-400 */
    --color-artifact-cloud:       #2DD4BF;  /* teal-400 */
    --color-artifact-usb:         #FB923C;  /* orange-400 */
    --color-artifact-user:        #94A3B8;  /* slate-400 */
  }
}
```

### 1.4 Typography

```css
:root {
  /* --- Font Families --- */
  --font-display:    'Inter', system-ui, -apple-system, sans-serif;
  --font-body:       'Inter', system-ui, -apple-system, sans-serif;
  --font-mono:       'JetBrains Mono', 'Cascadia Code', 'Fira Code', ui-monospace, monospace;

  /* --- Font Sizes (modular scale, 1.200 minor third) --- */
  --text-xs:         0.694rem;    /* 11.1px -- fine print, footnotes */
  --text-sm:         0.833rem;    /* 13.3px -- captions, metadata labels */
  --text-base:       1rem;        /* 16px   -- body text */
  --text-md:         1.2rem;      /* 19.2px -- section subheads */
  --text-lg:         1.44rem;     /* 23px   -- section heads */
  --text-xl:         1.728rem;    /* 27.6px -- page titles */
  --text-2xl:        2.074rem;    /* 33.2px -- report cover title */

  /* --- Font Weights --- */
  --font-normal:     400;
  --font-medium:     500;
  --font-semibold:   600;
  --font-bold:       700;

  /* --- Line Heights --- */
  --leading-tight:   1.25;        /* headings */
  --leading-snug:    1.375;       /* dense tables, compact UI */
  --leading-normal:  1.5;         /* body text */
  --leading-relaxed: 1.625;       /* report narrative */

  /* --- Letter Spacing --- */
  --tracking-tight:  -0.01em;     /* headings */
  --tracking-normal: 0em;         /* body */
  --tracking-wide:   0.025em;     /* small caps, labels */
  --tracking-mono:   -0.02em;     /* monospace tightening */
}
```

### 1.5 Spacing Scale

```css
:root {
  /* --- Spacing (4px base, power-of-2 progression) --- */
  --space-0:   0;
  --space-px:  1px;
  --space-0.5: 0.125rem;   /* 2px */
  --space-1:   0.25rem;    /* 4px */
  --space-1.5: 0.375rem;   /* 6px */
  --space-2:   0.5rem;     /* 8px */
  --space-3:   0.75rem;    /* 12px */
  --space-4:   1rem;        /* 16px */
  --space-5:   1.25rem;    /* 20px */
  --space-6:   1.5rem;     /* 24px */
  --space-8:   2rem;        /* 32px */
  --space-10:  2.5rem;     /* 40px */
  --space-12:  3rem;        /* 48px */
  --space-16:  4rem;        /* 64px */
  --space-20:  5rem;        /* 80px */

  /* --- Border Radius --- */
  --radius-none: 0;
  --radius-sm:   0.25rem;   /* 4px  -- inputs, badges */
  --radius-md:   0.375rem;  /* 6px  -- cards, panels */
  --radius-lg:   0.5rem;    /* 8px  -- modals, dialogs */
  --radius-full: 9999px;    /* pills */

  /* --- Shadows --- */
  --shadow-sm:   0 1px 2px 0 rgba(0, 0, 0, 0.05);
  --shadow-md:   0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1);
  --shadow-lg:   0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -4px rgba(0, 0, 0, 0.1);

  /* --- Transitions --- */
  --transition-fast:  150ms ease;
  --transition-base:  200ms ease;
  --transition-slow:  300ms ease;

  /* --- Z-Index Scale --- */
  --z-base:      0;
  --z-raised:    10;
  --z-dropdown:  20;
  --z-sticky:    30;
  --z-modal:     40;
  --z-tooltip:   50;
}

@media (prefers-reduced-motion: reduce) {
  :root {
    --transition-fast:  0ms;
    --transition-base:  0ms;
    --transition-slow:  0ms;
  }
}
```

---

## 2. TUI Color Map (ratatui)

The TUI is the primary analysis surface. These map CSS tokens to ratatui `Color` values for 256-color terminals.

### 2.1 Core TUI Palette

```rust
// tui/theme.rs -- Issen TUI color constants

use ratatui::style::Color;

pub struct Theme {
    // Background
    pub bg:              Color,  // Color::Rgb(15, 23, 42)    -- slate-900
    pub bg_subtle:       Color,  // Color::Rgb(30, 41, 59)    -- slate-800
    pub surface:         Color,  // Color::Rgb(30, 41, 59)    -- slate-800
    pub surface_raised:  Color,  // Color::Rgb(51, 65, 85)    -- slate-700
    pub border:          Color,  // Color::Rgb(51, 65, 85)    -- slate-700

    // Text
    pub text:            Color,  // Color::Rgb(241, 245, 249) -- slate-100
    pub text_secondary:  Color,  // Color::Rgb(203, 213, 225) -- slate-300
    pub text_muted:      Color,  // Color::Rgb(100, 116, 139) -- slate-500

    // Accent
    pub accent:          Color,  // Color::Rgb(245, 158, 11)  -- amber-500
    pub accent_bright:   Color,  // Color::Rgb(251, 191, 36)  -- amber-400

    // Semantic
    pub success:         Color,  // Color::Rgb(52, 211, 153)  -- emerald-400
    pub warning:         Color,  // Color::Rgb(251, 191, 36)  -- amber-400
    pub error:           Color,  // Color::Rgb(248, 113, 113) -- red-400
    pub info:            Color,  // Color::Rgb(96, 165, 250)  -- blue-400

    // Integrity
    pub verified:        Color,  // Color::Rgb(52, 211, 153)
    pub unverified:      Color,  // Color::Rgb(251, 191, 36)
    pub tampered:        Color,  // Color::Rgb(248, 113, 113)

    // Severity
    pub sev_critical:    Color,  // Color::Rgb(252, 165, 165) -- red-300
    pub sev_high:        Color,  // Color::Rgb(248, 113, 113) -- red-400
    pub sev_medium:      Color,  // Color::Rgb(251, 191, 36)  -- amber-400
    pub sev_low:         Color,  // Color::Rgb(96, 165, 250)  -- blue-400
    pub sev_info:        Color,  // Color::Rgb(148, 163, 184) -- slate-400
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            bg:             Color::Rgb(15, 23, 42),
            bg_subtle:      Color::Rgb(30, 41, 59),
            surface:        Color::Rgb(30, 41, 59),
            surface_raised: Color::Rgb(51, 65, 85),
            border:         Color::Rgb(51, 65, 85),
            text:           Color::Rgb(241, 245, 249),
            text_secondary: Color::Rgb(203, 213, 225),
            text_muted:     Color::Rgb(100, 116, 139),
            accent:         Color::Rgb(245, 158, 11),
            accent_bright:  Color::Rgb(251, 191, 36),
            success:        Color::Rgb(52, 211, 153),
            warning:        Color::Rgb(251, 191, 36),
            error:          Color::Rgb(248, 113, 113),
            info:           Color::Rgb(96, 165, 250),
            verified:       Color::Rgb(52, 211, 153),
            unverified:     Color::Rgb(251, 191, 36),
            tampered:       Color::Rgb(248, 113, 113),
            sev_critical:   Color::Rgb(252, 165, 165),
            sev_high:       Color::Rgb(248, 113, 113),
            sev_medium:     Color::Rgb(251, 191, 36),
            sev_low:        Color::Rgb(96, 165, 250),
            sev_info:       Color::Rgb(148, 163, 184),
        }
    }
}
```

### 2.2 TUI Artifact Source Colors

```rust
pub struct ArtifactColors {
    pub filesystem:  Color, // Color::Rgb(96, 165, 250)   -- blue-400
    pub registry:    Color, // Color::Rgb(167, 139, 250)  -- violet-400
    pub eventlog:    Color, // Color::Rgb(52, 211, 153)   -- emerald-400
    pub prefetch:    Color, // Color::Rgb(251, 191, 36)   -- amber-400
    pub browser:     Color, // Color::Rgb(34, 211, 238)   -- cyan-400
    pub email:       Color, // Color::Rgb(248, 113, 113)  -- red-400
    pub network:     Color, // Color::Rgb(129, 140, 248)  -- indigo-400
    pub persistence: Color, // Color::Rgb(244, 114, 182)  -- pink-400
    pub memory:      Color, // Color::Rgb(192, 132, 252)  -- purple-400
    pub cloud:       Color, // Color::Rgb(45, 212, 191)   -- teal-400
    pub usb:         Color, // Color::Rgb(251, 146, 60)   -- orange-400
    pub user:        Color, // Color::Rgb(148, 163, 184)  -- slate-400
}
```

---

## 3. Framework Integration

### 3.1 Multi-Surface Architecture

Issen renders across four surfaces. Each consumes design tokens differently:

| Surface | Technology | Token Format | Dark Mode | Print |
|---------|-----------|-------------|-----------|-------|
| **TUI** | ratatui 0.29 + crossterm 0.28 | Rust `Color::Rgb` constants | Always dark | N/A |
| **HTML Reports** | Standalone HTML (self-contained) | CSS custom properties inlined | User toggle | Required |
| **Desktop GUI** | Tauri v2 webview | CSS custom properties | System + toggle | Via HTML |
| **Web UI** | axum + React/Leptos (future) | CSS custom properties / Tailwind | System + toggle | Via HTML |

### 3.2 Tailwind CSS v4 Configuration (Desktop + Web)

```css
/* tailwind.css -- import as base theme */
@theme {
  --color-primary:    #475569;
  --color-accent:     #D97706;
  --color-success:    #059669;
  --color-warning:    #D97706;
  --color-error:      #DC2626;
  --color-info:       #2563EB;

  --font-display:     'Inter', system-ui, sans-serif;
  --font-body:        'Inter', system-ui, sans-serif;
  --font-mono:        'JetBrains Mono', ui-monospace, monospace;
}
```

### 3.3 HTML Report Token Injection

HTML reports are standalone files. All tokens must be inlined in a `<style>` block at the top of the document. Reports must not depend on external stylesheets or CDNs -- attorneys open these on locked-down machines.

```html
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
  <meta charset="UTF-8">
  <style>
    /* All :root tokens from Section 1 are inlined here */
    /* Print overrides from Section 9 are inlined here */
    /* Inter + JetBrains Mono are base64-embedded as @font-face */
  </style>
</head>
```

---

## 4. Component Specifications

### 4.1 Timeline Row

The timeline is the core UX component. Each row represents a single forensic event.

```css
/* Timeline Event Row */
.timeline-row {
  display: grid;
  grid-template-columns: 180px 32px 120px 1fr 80px;
  /* columns: timestamp | source-dot | artifact-type | description | actions */
  gap: var(--space-2);
  padding: var(--space-1) var(--space-3);
  border-bottom: 1px solid var(--color-border);
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  line-height: var(--leading-snug);
  transition: background-color var(--transition-fast);
}

.timeline-row:hover {
  background-color: var(--color-surface-raised);
}

.timeline-row--selected {
  background-color: var(--color-accent-subtle);
  border-left: 3px solid var(--color-accent);
}

.timeline-row--bookmarked {
  background-color: var(--color-info-subtle);
}

/* Timestamp column -- always monospace, right-aligned */
.timeline-timestamp {
  font-variant-numeric: tabular-nums;
  text-align: right;
  color: var(--color-text-secondary);
  white-space: nowrap;
}

/* Source indicator -- colored dot matching artifact type */
.timeline-source-dot {
  width: 10px;
  height: 10px;
  border-radius: var(--radius-full);
  align-self: center;
  justify-self: center;
  /* background-color set via artifact-type class */
}

/* Artifact type badge */
.timeline-artifact-type {
  font-size: var(--text-xs);
  font-weight: var(--font-medium);
  letter-spacing: var(--tracking-wide);
  text-transform: uppercase;
  white-space: nowrap;
}

/* Description -- truncate with title tooltip for full text */
.timeline-description {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--color-text);
}
```

**TUI Equivalent (ratatui):**

```
 2024-03-15 14:23:07.123 | * | REGISTRY   | HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\malware.exe | [B][F]
 2024-03-15 14:23:08.456 | * | FILESYSTEM | C:\Users\victim\AppData\Local\Temp\payload.dll created          | [F]
 2024-03-15 14:23:09.001 | * | EVENTLOG   | Security 4688: New process created (powershell.exe)             | [B]
```

Where `*` is a colored dot (artifact source color), `[B]` = bookmarked, `[F]` = flagged as finding.

### 4.2 Evidence Card

Used in reports and GUI to display a single piece of evidence with integrity status.

```css
.evidence-card {
  background-color: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  padding: var(--space-4);
  margin-bottom: var(--space-3);
}

.evidence-card__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--space-2);
}

.evidence-card__title {
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  font-weight: var(--font-semibold);
  color: var(--color-text);
}

.evidence-card__integrity {
  display: inline-flex;
  align-items: center;
  gap: var(--space-1);
  font-size: var(--text-xs);
  font-weight: var(--font-medium);
  padding: var(--space-0.5) var(--space-2);
  border-radius: var(--radius-sm);
}

.evidence-card__integrity--verified {
  color: var(--color-verified);
  background-color: var(--color-success-subtle);
}

.evidence-card__integrity--unverified {
  color: var(--color-unverified);
  background-color: var(--color-warning-subtle);
}

.evidence-card__integrity--tampered {
  color: var(--color-tampered);
  background-color: var(--color-error-subtle);
  font-weight: var(--font-bold);
}

.evidence-card__meta {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: var(--space-2);
  font-size: var(--text-sm);
  color: var(--color-text-secondary);
}

.evidence-card__meta dt {
  font-weight: var(--font-medium);
  color: var(--color-text-muted);
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: var(--tracking-wide);
}

.evidence-card__meta dd {
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  word-break: break-all;
}
```

### 4.3 Report Section

Used in HTML report output. Provides the structure for attorney-facing narrative sections.

```css
.repoissen-section {
  margin-bottom: var(--space-8);
  page-break-inside: avoid;
}

.repoissen-section__heading {
  font-family: var(--font-display);
  font-size: var(--text-lg);
  font-weight: var(--font-bold);
  color: var(--color-primary);
  letter-spacing: var(--tracking-tight);
  margin-bottom: var(--space-3);
  padding-bottom: var(--space-2);
  border-bottom: 2px solid var(--color-primary);
}

.repoissen-section__body {
  font-family: var(--font-body);
  font-size: var(--text-base);
  line-height: var(--leading-relaxed);
  color: var(--color-text);
}

.repoissen-section__body p {
  margin-bottom: var(--space-3);
}
```

### 4.4 Finding Summary

A compact card used in reports to summarize a forensic finding with severity and supporting evidence references.

```css
.finding-summary {
  background-color: var(--color-surface-raised);
  border-left: 4px solid var(--color-severity-medium);  /* override per severity */
  border-radius: 0 var(--radius-md) var(--radius-md) 0;
  padding: var(--space-4);
  margin-bottom: var(--space-4);
}

.finding-summary--critical { border-left-color: var(--color-severity-critical); }
.finding-summary--high     { border-left-color: var(--color-severity-high); }
.finding-summary--medium   { border-left-color: var(--color-severity-medium); }
.finding-summary--low      { border-left-color: var(--color-severity-low); }
.finding-summary--info     { border-left-color: var(--color-severity-info); }

.finding-summary__title {
  font-family: var(--font-display);
  font-size: var(--text-md);
  font-weight: var(--font-semibold);
  color: var(--color-text);
  margin-bottom: var(--space-1);
}

.finding-summary__description {
  font-size: var(--text-base);
  line-height: var(--leading-normal);
  color: var(--color-text-secondary);
  margin-bottom: var(--space-2);
}

.finding-summary__evidence-refs {
  font-size: var(--text-sm);
  color: var(--color-text-muted);
}

.finding-summary__evidence-refs a {
  color: var(--color-accent);
  text-decoration: underline;
}
```

### 4.5 Exhibit Reference

Inline reference used within report narrative to link to specific exhibits. Courtroom-friendly.

```css
.exhibit-ref {
  display: inline;
  font-weight: var(--font-semibold);
  color: var(--color-accent);
  text-decoration: none;
  cursor: pointer;
}

.exhibit-ref::before {
  content: "(";
}

.exhibit-ref::after {
  content: ")";
}

.exhibit-ref:hover {
  text-decoration: underline;
}

/* Print: remove link styling, show as plain bold text */
@media print {
  .exhibit-ref {
    color: var(--color-text);
    font-weight: var(--font-bold);
  }
}
```

### 4.6 Data Table

The primary interaction mode for forensic data. Must handle 10+ columns, millions of rows (with virtualization), and remain scannable.

```css
.data-table {
  width: 100%;
  border-collapse: collapse;
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  line-height: var(--leading-snug);
}

.data-table thead {
  position: sticky;
  top: 0;
  z-index: var(--z-sticky);
  background-color: var(--color-bg-subtle);
}

.data-table th {
  padding: var(--space-2) var(--space-3);
  text-align: left;
  font-weight: var(--font-semibold);
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: var(--tracking-wide);
  color: var(--color-text-muted);
  border-bottom: 2px solid var(--color-border-strong);
  white-space: nowrap;
  user-select: none;
  cursor: pointer;
}

.data-table th[aria-sort="ascending"]::after {
  content: " \2191";  /* up arrow */
}

.data-table th[aria-sort="descending"]::after {
  content: " \2193";  /* down arrow */
}

.data-table td {
  padding: var(--space-1) var(--space-3);
  border-bottom: 1px solid var(--color-border);
  vertical-align: top;
  color: var(--color-text);
}

.data-table tr:hover {
  background-color: var(--color-surface-raised);
}

.data-table tr[aria-selected="true"] {
  background-color: var(--color-accent-subtle);
}

/* Zebra striping for print readability */
@media print {
  .data-table tr:nth-child(even) {
    background-color: #F8FAFC;
  }
}
```

### 4.7 Buttons

```css
/* Primary Button */
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: var(--space-2);
  padding: var(--space-2) var(--space-4);
  font-family: var(--font-body);
  font-size: var(--text-sm);
  font-weight: var(--font-medium);
  line-height: 1;
  border-radius: var(--radius-sm);
  border: 1px solid transparent;
  cursor: pointer;
  transition: all var(--transition-fast);
  white-space: nowrap;
}

.btn:focus-visible {
  outline: 2px solid var(--color-accent);
  outline-offset: 2px;
}

.btn--primary {
  background-color: var(--color-primary);
  color: var(--color-text-on-primary);
  border-color: var(--color-primary);
}

.btn--primary:hover {
  background-color: var(--color-primary-hover);
}

.btn--secondary {
  background-color: transparent;
  color: var(--color-primary);
  border-color: var(--color-border-strong);
}

.btn--secondary:hover {
  background-color: var(--color-primary-subtle);
}

.btn--ghost {
  background-color: transparent;
  color: var(--color-text-secondary);
  border-color: transparent;
}

.btn--ghost:hover {
  background-color: var(--color-surface-raised);
  color: var(--color-text);
}

.btn--danger {
  background-color: var(--color-error);
  color: #FFFFFF;
  border-color: var(--color-error);
}

.btn--danger:hover {
  background-color: #B91C1C;
}
```

### 4.8 Badges / Tags

Used for artifact type labels, severity indicators, and hash status.

```css
.badge {
  display: inline-flex;
  align-items: center;
  gap: var(--space-1);
  padding: var(--space-0.5) var(--space-2);
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  font-weight: var(--font-medium);
  letter-spacing: var(--tracking-wide);
  text-transform: uppercase;
  border-radius: var(--radius-sm);
  white-space: nowrap;
}

/* Artifact type badges use artifact source colors */
.badge--filesystem  { color: var(--color-artifact-filesystem);  background-color: color-mix(in srgb, var(--color-artifact-filesystem) 10%, transparent); }
.badge--registry    { color: var(--color-artifact-registry);    background-color: color-mix(in srgb, var(--color-artifact-registry) 10%, transparent); }
.badge--eventlog    { color: var(--color-artifact-eventlog);    background-color: color-mix(in srgb, var(--color-artifact-eventlog) 10%, transparent); }
.badge--prefetch    { color: var(--color-artifact-prefetch);    background-color: color-mix(in srgb, var(--color-artifact-prefetch) 10%, transparent); }
.badge--browser     { color: var(--color-artifact-browser);     background-color: color-mix(in srgb, var(--color-artifact-browser) 10%, transparent); }
.badge--email       { color: var(--color-artifact-email);       background-color: color-mix(in srgb, var(--color-artifact-email) 10%, transparent); }
.badge--network     { color: var(--color-artifact-network);     background-color: color-mix(in srgb, var(--color-artifact-network) 10%, transparent); }
.badge--persistence { color: var(--color-artifact-persistence); background-color: color-mix(in srgb, var(--color-artifact-persistence) 10%, transparent); }
.badge--memory      { color: var(--color-artifact-memory);      background-color: color-mix(in srgb, var(--color-artifact-memory) 10%, transparent); }
.badge--cloud       { color: var(--color-artifact-cloud);       background-color: color-mix(in srgb, var(--color-artifact-cloud) 10%, transparent); }
.badge--usb         { color: var(--color-artifact-usb);         background-color: color-mix(in srgb, var(--color-artifact-usb) 10%, transparent); }
.badge--user        { color: var(--color-artifact-user);        background-color: color-mix(in srgb, var(--color-artifact-user) 10%, transparent); }

/* Severity badges */
.badge--severity-critical { color: #FFFFFF; background-color: var(--color-severity-critical); }
.badge--severity-high     { color: #FFFFFF; background-color: var(--color-severity-high); }
.badge--severity-medium   { color: #000000; background-color: var(--color-severity-medium); }
.badge--severity-low      { color: #FFFFFF; background-color: var(--color-severity-low); }
.badge--severity-info     { color: #FFFFFF; background-color: var(--color-severity-info); }

/* Integrity badges */
.badge--verified   { color: var(--color-verified);   background-color: var(--color-success-subtle); }
.badge--unverified { color: var(--color-unverified);  background-color: var(--color-warning-subtle); }
.badge--tampered   { color: var(--color-tampered);    background-color: var(--color-error-subtle); font-weight: var(--font-bold); }
```

### 4.9 Input Fields

```css
.input {
  display: block;
  width: 100%;
  padding: var(--space-2) var(--space-3);
  font-family: var(--font-body);
  font-size: var(--text-sm);
  line-height: var(--leading-normal);
  color: var(--color-text);
  background-color: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  transition: border-color var(--transition-fast), box-shadow var(--transition-fast);
}

.input:focus {
  outline: none;
  border-color: var(--color-accent);
  box-shadow: 0 0 0 2px color-mix(in srgb, var(--color-accent) 25%, transparent);
}

.input--error {
  border-color: var(--color-error);
}

.input--error:focus {
  box-shadow: 0 0 0 2px color-mix(in srgb, var(--color-error) 25%, transparent);
}

/* Filter input for timeline/table -- monospace with search icon space */
.input--filter {
  font-family: var(--font-mono);
  padding-left: var(--space-8);
  background-image: url("data:image/svg+xml,..."); /* search icon */
  background-repeat: no-repeat;
  background-position: var(--space-2) center;
  background-size: 16px;
}
```

### 4.10 Loading States

```css
@keyframes pulse-subtle {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.6; }
}

/* Parse progress indicator */
.parse-progress {
  background-color: var(--color-surface-raised);
  border-radius: var(--radius-md);
  padding: var(--space-4);
}

.parse-progress__bar {
  height: 4px;
  background-color: var(--color-border);
  border-radius: var(--radius-full);
  overflow: hidden;
}

.parse-progress__fill {
  height: 100%;
  background-color: var(--color-accent);
  border-radius: var(--radius-full);
  transition: width var(--transition-slow);
}

.parse-progress__label {
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  color: var(--color-text-secondary);
  margin-top: var(--space-2);
}

/* Skeleton for timeline rows during progressive loading */
.skeleton-timeline-row {
  display: grid;
  grid-template-columns: 180px 32px 120px 1fr 80px;
  gap: var(--space-2);
  padding: var(--space-1) var(--space-3);
  animation: pulse-subtle 2s ease-in-out infinite;
}

.skeleton-block {
  background-color: var(--color-border);
  border-radius: var(--radius-sm);
  height: var(--text-sm);
}
```

---

## 5. Visualization Patterns

### 5.1 Timeline Density Heatmap

When displaying millions of events, individual rows are impractical. The density heatmap provides a bird's-eye view of event distribution over time.

```css
.density-heatmap {
  display: flex;
  height: 64px;
  gap: 0;
  border-radius: var(--radius-sm);
  overflow: hidden;
  cursor: crosshair;
}

.density-heatmap__cell {
  flex: 1;
  min-width: 2px;
  position: relative;
  /* opacity maps to event count: 0.1 (sparse) to 1.0 (dense) */
  background-color: var(--color-accent);
  transition: opacity var(--transition-fast);
}

.density-heatmap__cell:hover {
  outline: 1px solid var(--color-text);
  z-index: 1;
}

/* Multi-source stacked density */
.density-heatmap--stacked .density-heatmap__cell {
  display: flex;
  flex-direction: column;
}

.density-heatmap__segment {
  flex-grow: 1;
  /* height proportional to source count, color from artifact palette */
}
```

### 5.2 Artifact Distribution Chart

Donut/bar chart showing breakdown by artifact source type. Uses the artifact palette defined in Section 1.3.

```css
/* Bar chart variant for reports */
.artifact-distribution {
  display: flex;
  flex-direction: column;
  gap: var(--space-1);
}

.artifact-distribution__row {
  display: grid;
  grid-template-columns: 120px 1fr 60px;
  gap: var(--space-2);
  align-items: center;
  font-size: var(--text-sm);
}

.artifact-distribution__bar {
  height: 16px;
  border-radius: var(--radius-sm);
  /* width set as percentage, color from artifact palette */
}

.artifact-distribution__count {
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
  text-align: right;
  color: var(--color-text-secondary);
}
```

### 5.3 Correlation Graph

For visualizing relationships between artifacts (e.g., process execution chains, file access patterns).

```
Pattern: Node-link diagram rendered via SVG or Canvas.
- Nodes: Circles colored by artifact source type, sized by significance.
- Edges: Lines with directional arrows, opacity indicating confidence.
- Layout: Force-directed for exploration, hierarchical for report snapshots.
- Interaction: Hover for detail tooltip, click to focus + highlight connected nodes.
- Print: Static snapshot with legend, all text rendered (no interactivity).
```

---

## 6. Responsive Breakpoints

### 6.1 Standard Breakpoints

```css
/* Mobile-first breakpoints */
--bp-sm:   640px;     /* phone landscape */
--bp-md:   768px;     /* tablet portrait */
--bp-lg:   1024px;    /* tablet landscape / small desktop */
--bp-xl:   1280px;    /* desktop */
--bp-2xl:  1536px;    /* wide desktop */
--bp-print: print;    /* print stylesheet */
```

### 6.2 Surface-Specific Considerations

| Surface | Min Width | Typical Width | Notes |
|---------|-----------|--------------|-------|
| TUI | 80 cols | 120-200 cols | Column count determines layout; no CSS breakpoints |
| HTML Report | 800px (print) | 100% viewport | Must be readable at 8.5"x11" printed; max-width 960px for readability |
| Desktop GUI | 1024px | 1280-1920px | Side panels for detail; resizable panes |
| Web UI | 640px (mobile) | 1280px+ | Full responsive from phone to ultrawide |

### 6.3 Report Print Constraints

```css
@media print {
  :root {
    --color-bg: #FFFFFF;
    --color-text: #000000;
    --color-text-secondary: #333333;
    --color-border: #CCCCCC;
    --color-primary: #000000;
    --color-accent: #000000;
  }

  body {
    font-size: 10pt;
    line-height: 1.4;
    max-width: none;
    margin: 0;
    padding: 0;
  }

  /* Force black text for all data */
  .timeline-row,
  .data-table td,
  .evidence-card {
    color: #000000;
  }

  /* Artifact badges print as text-only labels */
  .badge {
    background-color: transparent;
    border: 1px solid #999999;
    color: #000000;
  }

  /* Integrity badges retain color distinction for court exhibits */
  .badge--verified   { border-color: #059669; color: #059669; }
  .badge--tampered   { border-color: #DC2626; color: #DC2626; font-weight: bold; }

  /* Page break controls */
  .repoissen-section { page-break-inside: avoid; }
  .finding-summary { page-break-inside: avoid; }
  .evidence-card { page-break-inside: avoid; }

  /* Hide interactive elements */
  .btn, .input--filter, [role="toolbar"] { display: none; }

  /* Table header repeats on each page */
  .data-table thead { display: table-header-group; }

  /* Footer with hash and page number */
  @page {
    size: letter;
    margin: 0.75in 1in;
    @bottom-center {
      content: "Issen Report -- Page " counter(page) " of " counter(pages);
      font-size: 8pt;
      color: #666666;
    }
  }
}
```

---

## 7. Icon Specifications

### 7.1 Recommended Icon Set

**Lucide Icons** (MIT license, 1000+ icons, consistent stroke style).

Rationale: Clean, professional, works well at small sizes in dense data UIs. No playful aesthetics. Available as SVG for HTML reports (inline, no external dependency) and as React components for GUI.

### 7.2 Icon Sizing

| Context | Size | CSS Variable |
|---------|------|-------------|
| Inline text | 16px | `--icon-sm` |
| Button icon | 18px | `--icon-md` |
| Card header | 20px | `--icon-lg` |
| Empty state | 48px | `--icon-xl` |

```css
:root {
  --icon-sm:  1rem;
  --icon-md:  1.125rem;
  --icon-lg:  1.25rem;
  --icon-xl:  3rem;
}
```

### 7.3 Core Forensic Icon Set

| Concept | Lucide Icon | Usage |
|---------|-------------|-------|
| Timeline | `clock` | Timeline view navigation |
| Evidence | `file-check` | Evidence items, verified files |
| Finding | `aleissen-triangle` | Findings, flagged items |
| Report | `file-text` | Report generation/view |
| Hash verified | `shield-check` | Integrity verified |
| Hash failed | `shield-x` | Integrity failure |
| Bookmark | `bookmark` | Bookmarked events |
| Filter | `filter` | Filter controls |
| Search | `search` | Search/query input |
| Export | `download` | Export/save actions |
| Ingest | `upload` | Evidence ingestion |
| Parse | `cpu` | Parsing/processing |
| Severity critical | `aleissen-octagon` | Critical findings |
| Severity high | `aleissen-triangle` | High-severity findings |
| Severity medium | `aleissen-circle` | Medium-severity findings |
| Severity low | `info` | Low-severity / informational |
| Expand | `chevron-right` | Expand tree/detail |
| Collapse | `chevron-down` | Collapse tree/detail |
| Chain of custody | `link` | Chain of custody status |
| Settings | `settings` | Configuration |

---

## 8. Utility Classes

### 8.1 Text Utilities

```css
.text-mono      { font-family: var(--font-mono); }
.text-display   { font-family: var(--font-display); }
.text-xs        { font-size: var(--text-xs); }
.text-sm        { font-size: var(--text-sm); }
.text-base      { font-size: var(--text-base); }
.text-md        { font-size: var(--text-md); }
.text-lg        { font-size: var(--text-lg); }
.text-xl        { font-size: var(--text-xl); }
.text-2xl       { font-size: var(--text-2xl); }
.text-muted     { color: var(--color-text-muted); }
.text-secondary { color: var(--color-text-secondary); }
.text-accent    { color: var(--color-accent); }
.text-error     { color: var(--color-error); }
.text-success   { color: var(--color-success); }
.text-tabular   { font-variant-numeric: tabular-nums; }
.text-truncate  { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
```

### 8.2 Layout Utilities

```css
.flex         { display: flex; }
.flex-col     { flex-direction: column; }
.flex-wrap    { flex-wrap: wrap; }
.items-center { align-items: center; }
.justify-between { justify-content: space-between; }
.gap-1        { gap: var(--space-1); }
.gap-2        { gap: var(--space-2); }
.gap-3        { gap: var(--space-3); }
.gap-4        { gap: var(--space-4); }
.p-2          { padding: var(--space-2); }
.p-3          { padding: var(--space-3); }
.p-4          { padding: var(--space-4); }
.px-3         { padding-left: var(--space-3); padding-right: var(--space-3); }
.py-2         { padding-top: var(--space-2); padding-bottom: var(--space-2); }
.mb-2         { margin-bottom: var(--space-2); }
.mb-4         { margin-bottom: var(--space-4); }
.mb-8         { margin-bottom: var(--space-8); }

/* Container widths for reports */
.container-narrow  { max-width: 640px; margin-inline: auto; }
.container-default { max-width: 960px; margin-inline: auto; }
.container-wide    { max-width: 1280px; margin-inline: auto; }
.container-full    { max-width: 100%; }
```

### 8.3 Focus Utilities

```css
/* Focus ring -- visible only on keyboard navigation */
.focus-ring:focus-visible {
  outline: 2px solid var(--color-accent);
  outline-offset: 2px;
}

/* Skip link for HTML report accessibility */
.skip-link {
  position: absolute;
  top: -9999px;
  left: 0;
  z-index: var(--z-tooltip);
  padding: var(--space-2) var(--space-4);
  background-color: var(--color-accent);
  color: var(--color-text-on-accent);
  font-weight: var(--font-semibold);
}

.skip-link:focus {
  top: 0;
}
```

---

## 9. Accessibility Integration

### 9.1 What This Document Covers

| Concern | Implementation Here | Details in ACCESSIBILITY.md |
|---------|--------------------|-----------------------------|
| **Color contrast** | Token definitions (Section 1) | WCAG criteria validation, testing tools |
| **Focus states** | CSS implementation (Section 8.3) | Focus management strategy, tab order |
| **Reduced motion** | CSS media query (Section 1.5) | Cognitive load patterns, alternatives |
| **Artifact color-coding** | 12-color palette (Section 1.3) | Never rely on color alone; always pair with text label |
| **Print accessibility** | Print overrides (Section 6.3) | Ensure black-on-white readability for court exhibits |
| **Screen readers** | -- | Live regions, announcements, testing scripts |
| **Keyboard navigation** | -- | Shortcuts, focus traps, skip links |

### 9.2 Required Accessibility Tokens

```css
/* Focus ring -- must have 3:1 contrast against background */
:root {
  --ring: var(--color-accent);
  --ring-offset: 2px;
}

/* Error states -- must not rely on color alone */
/* Always pair --color-error with an icon + descriptive text */

/* High-contrast mode override */
@media (forced-colors: active) {
  .badge,
  .evidence-card__integrity,
  .finding-summary {
    border: 1px solid CanvasText;
  }

  .timeline-source-dot {
    forced-color-adjust: none;
  }
}
```

### 9.3 Cross-Reference Checklist

- [x] Color tokens pass WCAG AA contrast (4.5:1 text, 3:1 UI components)
- [x] Focus ring color (amber #D97706) has 3:1+ contrast against slate backgrounds
- [x] Reduced motion tokens set transitions to 0ms
- [x] Component specs include focus-visible state definitions
- [x] Loading states use text label alongside animation
- [x] Artifact source types never rely on color alone (always paired with text badge)
- [x] Print stylesheet converts to black-on-white for court exhibits
- [x] Evidence integrity badges include icon + text, not just color

---

## 10. Implementation Checklist

### 10.1 Initial Setup

- [ ] Add CSS custom properties to global stylesheet or HTML report template
- [ ] Embed Inter + JetBrains Mono as base64 `@font-face` in report template
- [ ] Configure Tailwind v4 theme (Section 3.2) for Tauri/web surfaces
- [ ] Create ratatui `Theme` struct (Section 2.1) in TUI codebase
- [ ] Install Lucide icons package

### 10.2 Core Components

- [ ] Timeline row (CSS + TUI)
- [ ] Evidence card (CSS)
- [ ] Finding summary (CSS)
- [ ] Exhibit reference (CSS)
- [ ] Data table with sticky header + sort indicators (CSS)
- [ ] Density heatmap (CSS + Canvas/SVG)
- [ ] Buttons (Primary, Secondary, Ghost, Danger)
- [ ] Badges (Artifact type, Severity, Integrity)
- [ ] Input fields (standard + filter)
- [ ] Loading/skeleton states

### 10.3 Report-Specific

- [ ] Print stylesheet tested at 8.5"x11" letter size
- [ ] Dark mode toggle in HTML report
- [ ] Self-contained HTML (no external dependencies)
- [ ] Page break rules for findings, evidence cards, sections
- [ ] Report footer with document hash + page numbers

### 10.4 Validation

- [ ] All WCAG AA contrast ratios verified (use axe-core or similar)
- [ ] Keyboard navigation tested for all interactive components
- [ ] Screen reader tested for HTML report (VoiceOver, NVDA)
- [ ] Print output reviewed by non-technical stakeholder
- [ ] Dark mode visually verified in TUI, HTML report, and GUI
- [ ] Artifact source colors distinguishable by colorblind users (simulate deuteranopia, protanopia)

---

## Quick Copy Reference

### Essential Token Usage

```css
/* Forensic data (timestamps, paths, hashes, registry keys) */
font-family: var(--font-mono);

/* Narrative text (report sections, finding descriptions) */
font-family: var(--font-body);
line-height: var(--leading-relaxed);

/* Section headings */
font-family: var(--font-display);
font-weight: var(--font-bold);
letter-spacing: var(--tracking-tight);

/* Artifact type indicator */
.badge--[type] with matching --color-artifact-[type]

/* Evidence integrity */
.evidence-card__integrity--verified|unverified|tampered

/* Finding severity */
.finding-summary--critical|high|medium|low|info

/* Print-safe report output */
@media print { /* Section 6.3 overrides */ }
```
