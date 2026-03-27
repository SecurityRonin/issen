# RapidTriage Desktop + Registry Temporal Diff Design

## Overview

**Goal:** Build a Tauri v2 desktop application (`rt-desktop`) with a static plugin architecture that hosts forensic analysis tools — starting with an MFT navigator and a registry temporal diff viewer. Both plugins share a common Svelte component library (`@rapidtriage/ui`). The registry diff engine enables investigators to compare any two registry hive states and zoom in on changes across time.

**Architecture:** Single Tauri v2 app with compile-time plugin registration. Each plugin provides a Rust backend (Tauri IPC commands) and Svelte frontend (views + routes). A shared `@rapidtriage/ui` Svelte package provides reusable forensic UI components (tree views, detail panels, search, diff highlighting). Two new Rust crates — `winreg-diff` (diff engine) and `winreg-discover` (hive source discovery) — power the registry comparison features.

**Tech Stack:**
- **Desktop shell:** Tauri v2 (Rust backend + webview frontend)
- **Frontend:** Svelte 5, TypeScript, Vite
- **Shared components:** `@rapidtriage/ui` (Svelte component library)
- **Build:** pnpm workspace (JS), Cargo workspace (Rust)
- **Rust crates:** winreg-format, winreg-core, winreg-diff (new), winreg-discover (new), rt-mft-tree
- **CLI:** rt-reg (extended with `diff` subcommand)

---

## 1. Plugin Architecture

### 1.1 Design Philosophy

Static plugin architecture — plugins are compiled into the binary, not loaded at runtime. This gives clean organizational boundaries and a well-defined interface without the complexity of dynamic loading (ABI stability, versioning, sandboxing). Third-party contributors fork and add plugins, then rebuild.

### 1.2 Rust Plugin Trait

```rust
/// Every plugin implements this trait and registers at app startup.
pub trait Plugin: Send + Sync {
    /// Unique identifier (e.g., "mft-navigator", "registry-diff").
    fn id(&self) -> &str;

    /// Human-readable name for the sidebar.
    fn name(&self) -> &str;

    /// SVG icon or icon identifier for the sidebar.
    fn icon(&self) -> &str;

    /// Register Tauri IPC commands for this plugin's backend.
    fn register_commands(&self, app: &mut tauri::App);
}
```

The Tauri `main.rs` imports all plugin structs and calls `register_commands` during app setup. No trait objects needed at runtime — just a Vec of concrete plugin instances.

### 1.3 Svelte Plugin Manifest

Each plugin exports a manifest defining its routes and sidebar entries:

```typescript
// plugins/registry-diff/manifest.ts
import DiffView from './views/DiffView.svelte';
import TimelineView from './views/TimelineView.svelte';

export default {
    id: 'registry-diff',
    name: 'Registry Diff',
    icon: 'diff',
    routes: [
        { path: '/registry-diff', component: DiffView },
        { path: '/registry-diff/timeline', component: TimelineView },
    ],
    sidebar: [
        { label: 'Registry Diff', icon: 'diff', route: '/registry-diff' },
    ],
};
```

The shell app (`App.svelte`) imports all manifests at build time, renders a sidebar from their declarations, and uses a simple client-side router to mount the active plugin's view.

### 1.4 Built-in Plugins

1. **MFT Navigator** — Port of rt-navigator's TUI functionality to Svelte. File tree, heuristics, anomaly panel, search.
2. **Registry Diff** — Temporal registry comparison. Unified tree, detail panel, side-by-side toggle, timeline picker, smart discovery.

---

## 2. Diff Engine (`winreg-diff` crate)

### 2.1 Purpose

A pure Rust library crate with zero GUI dependencies. Takes two `Hive<Cursor<Vec<u8>>>` references, produces a structured diff. Used by both the CLI (`rt-reg diff`) and the Tauri backend.

### 2.2 Core Types

```rust
use winreg_format::flags::ValueType;

/// Complete result of comparing two hives.
pub struct DiffResult {
    /// Label for the left hive (e.g., "SYSTEM — VSC-1, 2024-01-15").
    pub left_label: String,
    /// Label for the right hive.
    pub right_label: String,
    /// All detected changes, sorted by key path.
    pub entries: Vec<DiffEntry>,
    /// Summary statistics.
    pub stats: DiffStats,
}

/// Aggregate counts of changes.
pub struct DiffStats {
    pub keys_added: usize,
    pub keys_removed: usize,
    pub keys_modified: usize,
    pub values_added: usize,
    pub values_removed: usize,
    pub values_changed: usize,
}

/// A single key-level change.
pub struct DiffEntry {
    /// Full key path from root (e.g., "ControlSet001\\Services\\SharedAccess").
    pub path: String,
    /// What happened at this key.
    pub kind: DiffKind,
    /// Value-level changes for this key (empty for KeyAdded/KeyRemoved of leaf keys).
    pub details: Vec<ValueDiff>,
}

/// Classification of key-level change.
pub enum DiffKind {
    /// Key exists in right hive but not left.
    KeyAdded,
    /// Key exists in left hive but not right.
    KeyRemoved,
    /// Key exists in both hives but has different values.
    KeyModified,
}

/// A single value-level change within a key.
pub struct ValueDiff {
    /// Value name (empty string for default value).
    pub name: String,
    /// What happened to this value.
    pub kind: ValueDiffKind,
}

/// Classification of value-level change.
pub enum ValueDiffKind {
    /// Value exists in right hive but not left.
    Added { value: ValueSnapshot },
    /// Value exists in left hive but not right.
    Removed { value: ValueSnapshot },
    /// Value exists in both but differs.
    Changed { left: ValueSnapshot, right: ValueSnapshot },
}

/// Snapshot of a registry value at a point in time.
pub struct ValueSnapshot {
    /// Registry value type (REG_SZ, REG_DWORD, etc.).
    pub data_type: ValueType,
    /// Human-readable representation of the value.
    pub display: String,
    /// Raw bytes for optional byte-level diff.
    pub raw: Vec<u8>,
}
```

### 2.3 Algorithm

```
diff_hives(left, right) -> DiffResult:
    1. BFS both hives from root
    2. At each level, collect subkey names from both sides
    3. Sort both name lists, merge-join:
       - Name only in left  → KeyRemoved (recurse into left subtree to list all removed descendants)
       - Name only in right → KeyAdded (recurse into right subtree to list all added descendants)
       - Name in both       → Compare values, then recurse into children
    4. For value comparison within a key:
       - Collect values from both sides, sort by name
       - Merge-join: added / removed / compare raw bytes for changed
    5. A key is KeyModified if any of its values differ
    6. Produce flat Vec<DiffEntry> sorted by path
```

The algorithm is O(n log n) where n is the total number of keys across both hives (dominated by the sort at each level).

### 2.4 Serialization

All diff types derive `serde::Serialize` for JSON/JSONL output in the CLI and for Tauri IPC transfer to the Svelte frontend.

### 2.5 CLI Extension

Add a `diff` subcommand to `rt-reg`:

```
rt-reg diff <hive-a> <hive-b> [--format table|json|jsonl] [--changes-only]
```

- `--changes-only`: Only print changed keys (skip unchanged context).
- Default format: `table` (human-readable, like `git diff --stat`).

---

## 3. Hive Discovery (`winreg-discover` crate)

### 3.1 Purpose

Scan an evidence root (mounted disk image, extracted file system) and locate all copies of registry hives across time sources: live hives, RegBack, Volume Shadow Copies, and transaction logs.

### 3.2 Core Types

```rust
use std::path::PathBuf;
use chrono::{DateTime, Utc};
use winreg_core::detect::HiveType;

/// A discovered registry hive file with provenance metadata.
pub struct HiveSource {
    /// Filesystem path to the hive file.
    pub path: PathBuf,
    /// Detected hive type (SYSTEM, SOFTWARE, NTUSER.DAT, etc.).
    pub hive_type: HiveType,
    /// Where this copy came from.
    pub origin: SourceOrigin,
    /// Timestamp from the BaseBlock header (last write time).
    pub timestamp: Option<DateTime<Utc>>,
    /// File size in bytes.
    pub size: u64,
    /// Whether the hive is clean (no pending transaction logs).
    pub is_clean: bool,
}

/// Provenance of a discovered hive.
pub enum SourceOrigin {
    /// Live hive from Windows/System32/config/.
    Live,
    /// RegBack copy from Windows/System32/config/RegBack/.
    RegBack,
    /// Volume Shadow Copy snapshot.
    Vsc {
        snapshot_id: String,
        creation_time: Option<DateTime<Utc>>,
    },
    /// Transaction log file (.LOG1 or .LOG2).
    TransactionLog { log_num: u8 },
}
```

### 3.3 Discovery Algorithm

```
discover_hives(evidence_root) -> Vec<HiveSource>:
    1. Check standard paths:
       - {root}/Windows/System32/config/{SYSTEM,SOFTWARE,SAM,SECURITY,DEFAULT}
       - {root}/Windows/System32/config/RegBack/*
       - {root}/Users/*/NTUSER.DAT
       - {root}/Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat
    2. For each candidate:
       - Validate REGF signature (first 4 bytes = "regf")
       - Read BaseBlock for timestamp and version
       - Auto-detect hive type via winreg-core::detect
       - Check for companion .LOG1/.LOG2 files
    3. Scan for VSC mount points (if present):
       - {root}/VSC*/ or {root}/$VSC/ patterns
       - Repeat step 1 within each VSC
    4. Sort all discovered sources by (hive_type, timestamp)
    5. Return Vec<HiveSource>
```

### 3.4 CLI Extension

Add a `discover` subcommand to `rt-reg`:

```
rt-reg discover <evidence-root> [--type SYSTEM|SOFTWARE|...] [--format table|json]
```

Lists all discovered hive sources with timestamps, origins, and clean/dirty status.

---

## 4. GUI: Registry Diff Plugin

### 4.1 Views

#### DiffView (default)

**Layout: Unified Tree + Detail Split**

```
┌─────────────────────────────────────────────────────────────┐
│  [Toolbar: Left label | Right label | Filter | View toggle] │
├──────────────────────────────┬──────────────────────────────┤
│                              │                              │
│  Merged Tree                 │  Value Diff Detail           │
│  (union of both hives)       │  (for selected key)          │
│                              │                              │
│  ▼ ControlSet001             │  EnableFirewall (REG_DWORD)  │
│    ▼ Services                │  − 0x00000001                │
│      ▸ SharedAccess ●        │  + 0x00000000                │
│      ▸ Tcpip                 │                              │
│      ▸ SuspiciousSvc ✕       │  DisplayName (REG_SZ)        │
│      ▸ NewService ✚          │    "SharedAccess" (unchanged)│
│                              │                              │
├──────────────────────────────┴──────────────────────────────┤
│  [Status: 3 keys changed, 1 added, 1 removed | 5 values]   │
└─────────────────────────────────────────────────────────────┘
```

- **Change markers:** ✚ green (added), ✕ red (removed), ● yellow (modified)
- **Changes-only filter:** Toggle to hide unchanged keys (like `git diff --stat`)
- **View toggle:** Switch to side-by-side (Layout A) for full tree comparison

#### SideBySide (toggle)

Two synchronized tree panes showing left and right hives. Scroll-locked. Color-coded on both sides. Used when the investigator wants to see the complete state of both hives simultaneously.

#### TimelinePicker

When using smart discovery (GUI "Load Evidence" flow):

```
┌───────────────────────────────────────────────────┐
│  SYSTEM hive — 5 sources found                    │
│                                                   │
│  ○─────●─────────●───────────●──────●─────○       │
│  │     │         │           │      │     │       │
│  Live  RegBack   VSC-1       VSC-2  VSC-3 +LOG1   │
│  dirty 2024-01  2024-01-15  2024-03 2024-06       │
│                                                   │
│  Select two points to compare:                    │
│  Left:  [VSC-1 ▾]    Right: [VSC-2 ▾]           │
│                                                   │
│  [Compare]                                        │
└───────────────────────────────────────────────────┘
```

### 4.2 Tauri IPC Commands

The registry-diff plugin registers these Tauri commands:

```rust
#[tauri::command]
fn diff_hives(left_path: String, right_path: String) -> Result<DiffResult, String>;

#[tauri::command]
fn diff_with_logs(hive_path: String, log_paths: Vec<String>) -> Result<DiffResult, String>;

#[tauri::command]
fn discover_hives(evidence_root: String) -> Result<Vec<HiveSource>, String>;

#[tauri::command]
fn hive_info(path: String) -> Result<HiveInfo, String>;
```

### 4.3 Interaction Flow

1. **Open:** Investigator opens rt-desktop, clicks "Registry Diff" in sidebar
2. **Load:** Either drag-and-drop two hive files, or click "Load Evidence" for smart discovery
3. **Discovery:** If loading evidence root, TimelinePicker shows all discovered hive sources on a timeline
4. **Compare:** Select two points, click Compare. Backend runs `diff_hives()`, returns `DiffResult`
5. **Explore:** Unified tree shows merged view. Click changed keys to see value-level diff in detail panel
6. **Toggle:** Switch to side-by-side view for full tree comparison
7. **Filter:** Toggle changes-only mode to focus on delta
8. **Export:** Export diff as JSON for reporting or further analysis

---

## 5. Shared Components (`@rapidtriage/ui`)

### 5.1 ForensicTree

Generic collapsible tree component. Data-agnostic — accepts a tree data structure and renders it with configurable node rendering.

**Props:**
- `nodes: TreeNode[]` — tree data
- `selected: string | null` — currently selected node ID
- `expanded: Set<string>` — expanded node IDs
- `renderNode: (node: TreeNode) => Snippet` — custom node renderer
- `onSelect: (node: TreeNode) => void`

**Used by:** MFT Navigator (file tree), Registry Diff (merged key tree, side-by-side trees)

### 5.2 DetailPanel

Resizable side panel for displaying detailed information about a selected item.

**Props:**
- `title: string`
- `width: number` (resizable via drag handle)
- `children: Snippet` — content slot

**Used by:** MFT Navigator (file metadata), Registry Diff (value diff display)

### 5.3 SearchBar

Incremental search with debounce and result highlighting.

**Props:**
- `placeholder: string`
- `onSearch: (query: string) => void`
- `resultCount: number | null`

**Used by:** Both plugins for filtering tree contents

### 5.4 DiffHighlight

Inline diff display for value changes. Shows before/after with color coding.

**Props:**
- `left: string` — old value
- `right: string` — new value
- `type: 'added' | 'removed' | 'changed'`

**Used by:** Registry Diff (value detail panel)

### 5.5 HeatMap

Color scale overlay for temporal data. Maps timestamps or ages to a color gradient.

**Props:**
- `value: number` — normalized 0-1
- `scheme: 'age' | 'recency' | 'severity'`

**Used by:** MFT Navigator (file age), Registry Diff (change recency)

### 5.6 TimelineStrip

Horizontal timeline with clickable markers for temporal navigation.

**Props:**
- `points: TimePoint[]` — `{ id, label, timestamp, type }`
- `selected: string[]` — currently selected point IDs (max 2)
- `onSelect: (id: string) => void`

**Used by:** Registry Diff (timeline picker for VSC/RegBack sources)

---

## 6. Workspace Structure

```
rapidtriage/
├── apps/
│   └── rt-desktop/                     # Tauri v2 desktop application
│       ├── src-tauri/
│       │   ├── Cargo.toml              # depends on all Rust crates
│       │   └── src/
│       │       ├── main.rs             # Tauri bootstrap + plugin registration
│       │       └── plugins/
│       │           ├── mod.rs          # Plugin trait definition + registry
│       │           ├── mft_navigator.rs # MFT plugin backend (IPC commands)
│       │           └── registry_diff.rs # Registry diff plugin backend
│       ├── src/                        # Svelte frontend
│       │   ├── App.svelte              # Shell: sidebar + plugin router
│       │   ├── plugins/
│       │   │   ├── mft-navigator/
│       │   │   │   ├── manifest.ts     # Routes + sidebar entries
│       │   │   │   └── views/
│       │   │   │       ├── FileTree.svelte
│       │   │   │       └── AnomalyPanel.svelte
│       │   │   └── registry-diff/
│       │   │       ├── manifest.ts
│       │   │       └── views/
│       │   │           ├── DiffView.svelte        # Unified tree + detail
│       │   │           ├── SideBySide.svelte      # Toggle view
│       │   │           └── TimelinePicker.svelte  # Smart discovery UI
│       │   └── lib/                    # App-level utilities
│       ├── package.json
│       ├── vite.config.ts
│       └── svelte.config.js
├── packages/
│   └── ui/                             # @rapidtriage/ui shared components
│       ├── package.json
│       └── src/
│           ├── index.ts                # barrel export
│           ├── ForensicTree.svelte
│           ├── DetailPanel.svelte
│           ├── SearchBar.svelte
│           ├── DiffHighlight.svelte
│           ├── HeatMap.svelte
│           └── TimelineStrip.svelte
├── crates/                             # Rust library crates
│   ├── winreg-format/                  # Registry binary format types
│   ├── winreg-core/                    # Hive parsing + navigation
│   ├── winreg-diff/                    # NEW: diff engine
│   ├── winreg-discover/                # NEW: hive source discovery
│   ├── winreg-recover/                 # Recovery (future)
│   ├── winreg-carve/                   # Carving (future)
│   ├── winreg-artifacts/               # Artifact decoders (future)
│   ├── winreg-timeline/                # Timeline generation (future)
│   ├── winreg-fuse/                    # FUSE mount (future)
│   ├── winreg-py/                      # Python bindings (future)
│   └── rt-mft-tree/                    # MFT parsing + tree building
├── rt-reg/                             # CLI binary (no GUI dependency)
└── pnpm-workspace.yaml                 # JS workspace config
```

---

## 7. Migration Path

### 7.1 rt-navigator TUI → rt-desktop MFT Plugin

The existing ratatui TUI (`rt-navigator`) remains as the CLI tool for terminal workflows. The new Tauri-based MFT Navigator plugin is a separate frontend that consumes the same Rust crates (`rt-mft-tree`, `rt-signatures`, etc.) via Tauri IPC. No code is deleted — the GUI is additive.

### 7.2 rt-reg CLI → rt-reg + rt-desktop

The `rt-reg` CLI gets `diff` and `discover` subcommands for scripting. The rt-desktop Registry Diff plugin provides the interactive GUI. Both consume the same `winreg-diff` and `winreg-discover` crates.

---

## 8. Testing Strategy

### 8.1 Rust Crates

- **winreg-diff:** Unit tests with TestHiveBuilder. Build two hives with known differences, assert DiffResult matches expectations. Test edge cases: empty hives, identical hives, deeply nested changes, value type changes.
- **winreg-discover:** Unit tests with temp directories containing mock hive files. Test discovery of each SourceOrigin type. Integration tests with real REGF files if available.

### 8.2 Svelte Components

- **@rapidtriage/ui:** Component tests with Svelte Testing Library. Test ForensicTree expand/collapse, SearchBar debounce, DiffHighlight rendering.
- **Plugin views:** Integration tests verifying Tauri IPC mocking + view rendering.

### 8.3 Tauri App

- Build verification: `cargo tauri build` succeeds on macOS, Windows, Linux.
- E2E tests (stretch): Playwright/WebDriver against the Tauri webview.

---

## 9. Dependencies

### 9.1 New Rust Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `tauri` | 2.x | Desktop app framework |
| `tauri-build` | 2.x | Build-time Tauri setup |
| `serde_json` | 1.x | JSON serialization for IPC |

All other Rust dependencies (binrw, bitflags, memmap2, miette, thiserror, chrono, clap) are already in the winreg-forensic workspace.

### 9.2 New JS Dependencies

| Package | Purpose |
|---------|---------|
| `svelte` 5.x | UI framework |
| `@tauri-apps/api` 2.x | Tauri IPC from JS |
| `vite` | Build tool |
| `@sveltejs/vite-plugin-svelte` | Svelte + Vite integration |
| `typescript` | Type safety |
| `pnpm` | Package manager (workspace support) |

---

## 10. Scope Boundaries

### In Scope (This Design)

- `winreg-diff` crate with `diff_hives()` API
- `winreg-discover` crate with `discover_hives()` API
- `rt-reg diff` and `rt-reg discover` CLI subcommands
- `rt-desktop` Tauri app with plugin architecture
- `@rapidtriage/ui` shared Svelte component library
- Registry Diff plugin (DiffView, SideBySide, TimelinePicker)
- MFT Navigator plugin (port of rt-navigator core features)

### Out of Scope (Future Work)

- Dynamic plugin loading (runtime `.so`/`.dylib`)
- Artifact decoder integration (Plan 2 of winreg-forensic)
- Recovery and carving features (Plan 3)
- Python bindings (Plan 4)
- FUSE mount
- Multi-hive timeline view (>2 hives, N-way diff)
- Byte-level diff visualization for binary values (optional enhancement)
