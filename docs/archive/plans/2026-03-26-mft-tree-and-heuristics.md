# MFT Tree Extraction & Forensic Heuristics Engine — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the MFT file tree into a shared crate and build a two-tier forensic heuristics engine inside rt-signatures, integrated into rt-navigator's TUI.

**Architecture:** Arena-style `FileTree` moves from rt-navigator to a new `rt-mft-tree` crate. `rt-signatures` gains a `heuristics` feature flag containing Tier 1 (metadata) and Tier 2 (content-aware) anomaly checks. rt-navigator consumes both crates and surfaces anomalies as red flags in the TUI.

**Tech Stack:** Rust, chrono, ratatui 0.29, crossterm 0.28, indicatif 0.17, mft 0.6

**Spec:** `docs/superpowers/specs/2026-03-25-mft-tree-and-heuristics-design.md`

---

## File Map

### New crate: `crates/rt-mft-tree/`

| File | Responsibility |
|------|---------------|
| `Cargo.toml` | Crate manifest, depends on mft, chrono, anyhow, indicatif |
| `src/lib.rs` | Re-exports: `pub mod node; pub mod tree; pub mod enrich; pub mod parse;` |
| `src/node.rs` | `NtfsTimestamps`, `FileNode` structs |
| `src/tree.rs` | `FileTree` — arena, children, entry_map, cached path index, search, dir_stats |
| `src/enrich.rs` | `enrich_usn()` method |
| `src/parse.rs` | `from_mft()` with indicatif progress bar |

### Modified: `crates/rt-signatures/`

| File | Responsibility |
|------|---------------|
| `Cargo.toml` | Add `heuristics` feature flag, optional dep on rt-mft-tree + rt-parser-usnjrnl |
| `src/lib.rs` | Add conditional `pub mod heuristics;` |
| `src/heuristics/mod.rs` | Public API: `run_tier1()`, `run_tier2()`, re-exports |
| `src/heuristics/anomaly.rs` | `Anomaly`, `AnomalyCategory`, `AnomalyIndex`, `HeuristicsConfig` |
| `src/heuristics/entry_checks.rs` | `check_entry()` — per-node streaming checks (HEUR-TS-*, HEUR-SZ-001, HEUR-AT-001, HEUR-MG-003) |
| `src/heuristics/tree_checks.rs` | `check_tree()` — path-aware checks (HEUR-LOC-*) |
| `src/heuristics/usn_analysis.rs` | `check_usn_stream()` — USN pattern detection (HEUR-USN-*) |
| `src/heuristics/file_reader.rs` | `FileReader` trait, `FsFileReader`, `NoFileReader` |
| `src/heuristics/content_checks.rs` | `run_tier2()` — magic bytes, entropy, crypto containers (HEUR-MG-001/002, HEUR-EN-*) |
| `src/heuristics/magic_table.rs` | Static `MAGIC_TABLE` array (~50 entries) |

### Modified: `crates/rt-navigator/`

| File | Change |
|------|--------|
| `Cargo.toml` | Replace inline tree code with dep on rt-mft-tree + rt-signatures[heuristics] |
| `src/tree.rs` | **Delete** — replaced by rt-mft-tree |
| `src/app.rs` | Import from rt-mft-tree; add `anomaly_index`, `file_reader` fields; `f` and `d` keys |
| `src/ui.rs` | Severity markers on rows, flagged count in footer, detail panel |
| `src/main.rs` | Wire `run_tier1()`, `check_usn_stream()`, and `run_tier2()` after tree construction |

### Modified: workspace root

| File | Change |
|------|--------|
| `Cargo.toml` | Add `rt-mft-tree` to members + workspace deps |

---

## Task 1: Create rt-mft-tree crate — node.rs

**Files:**
- Create: `crates/rt-mft-tree/Cargo.toml`
- Create: `crates/rt-mft-tree/src/lib.rs`
- Create: `crates/rt-mft-tree/src/node.rs`
- Modify: `Cargo.toml` (workspace root)

- [ ] **Step 1: Write failing tests for `NtfsTimestamps` and `FileNode`**

Create `crates/rt-mft-tree/src/node.rs` with the types and tests at the bottom:

```rust
//! NTFS file node and timestamp types for MFT tree construction.

use chrono::{DateTime, Utc};

/// Four NTFS timestamps from a single attribute ($SI or $FN).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsTimestamps {
    pub modified: DateTime<Utc>,
    pub accessed: DateTime<Utc>,
    pub created: DateTime<Utc>,
    pub entry_modified: DateTime<Utc>,
}

/// A single file or directory extracted from the MFT.
#[derive(Debug, Clone)]
pub struct FileNode {
    pub name: String,
    pub mft_entry: u64,
    pub parent_entry: u64,
    pub is_dir: bool,
    pub size: u64,
    /// `$STANDARD_INFORMATION` timestamps (user-visible, modifiable by tools).
    pub si_timestamps: NtfsTimestamps,
    /// `$FILE_NAME` timestamps (kernel-managed, harder to tamper).
    /// `None` if identical to `si_timestamps`.
    pub fn_timestamps: Option<NtfsTimestamps>,
    /// NTFS file attribute flags (from $STANDARD_INFORMATION).
    /// Common: 0x1 = read-only, 0x2 = hidden, 0x4 = system, 0x20 = archive.
    pub file_attributes: u32,
    /// Number of USN journal change records referencing this entry.
    pub usn_change_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn ts(year: i32, month: u32, day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).unwrap()
    }

    fn default_timestamps() -> NtfsTimestamps {
        NtfsTimestamps {
            modified: ts(2024, 1, 1),
            accessed: ts(2024, 1, 1),
            created: ts(2024, 1, 1),
            entry_modified: ts(2024, 1, 1),
        }
    }

    #[test]
    fn ntfs_timestamps_equality() {
        let a = default_timestamps();
        let b = default_timestamps();
        assert_eq!(a, b);
    }

    #[test]
    fn ntfs_timestamps_copy_semantics() {
        let a = default_timestamps();
        let b = a; // Copy
        assert_eq!(a, b);
    }

    #[test]
    fn file_node_with_fn_timestamps() {
        let si = default_timestamps();
        let fn_ts = NtfsTimestamps {
            created: ts(2023, 6, 15),
            ..si
        };
        let node = FileNode {
            name: "test.exe".to_string(),
            mft_entry: 100,
            parent_entry: 5,
            is_dir: false,
            size: 1024,
            si_timestamps: si,
            fn_timestamps: Some(fn_ts),
            file_attributes: 0, usn_change_count: 0,
        };
        assert!(node.fn_timestamps.is_some());
        assert_ne!(node.si_timestamps.created, node.fn_timestamps.unwrap().created);
    }

    #[test]
    fn file_node_without_fn_timestamps() {
        let node = FileNode {
            name: "normal.txt".to_string(),
            mft_entry: 200,
            parent_entry: 5,
            is_dir: false,
            size: 512,
            si_timestamps: default_timestamps(),
            fn_timestamps: None,
            file_attributes: 0, usn_change_count: 0,
        };
        assert!(node.fn_timestamps.is_none());
    }

    #[test]
    fn file_node_directory() {
        let node = FileNode {
            name: "Windows".to_string(),
            mft_entry: 30,
            parent_entry: 5,
            is_dir: true,
            size: 0,
            si_timestamps: default_timestamps(),
            fn_timestamps: None,
            file_attributes: 0, usn_change_count: 0,
        };
        assert!(node.is_dir);
        assert_eq!(node.size, 0);
    }
}
```

- [ ] **Step 2: Create Cargo.toml and lib.rs**

`crates/rt-mft-tree/Cargo.toml`:

```toml
[package]
name = "rt-mft-tree"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license = "Apache-2.0"
description = "Shared MFT file tree for Issen"
repository.workspace = true

[dependencies]
chrono = { workspace = true }
anyhow = { workspace = true }
indicatif = { workspace = true }
mft = { workspace = true }

[dev-dependencies]
tempfile = { workspace = true }

[lints]
workspace = true
```

`crates/rt-mft-tree/src/lib.rs`:

```rust
pub mod node;
```

- [ ] **Step 3: Register crate in workspace**

Add to `Cargo.toml` workspace root:
- In `[workspace] members`: `"crates/rt-mft-tree",`
- In `[workspace.dependencies]`: `rt-mft-tree = { path = "crates/rt-mft-tree" }`

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rt-mft-tree`
Expected: 5 tests pass

- [ ] **Step 5: Commit**

```bash
git add crates/rt-mft-tree/ Cargo.toml
git commit -m "feat(rt-mft-tree): add node.rs with NtfsTimestamps and FileNode"
```

---

## Task 2: Create rt-mft-tree — tree.rs (core data structure)

This migrates `FileTree` from rt-navigator. The struct gains the `NtfsTimestamps`-based `FileNode` but the tree logic (arena, children, path index, search) is identical.

**Files:**
- Create: `crates/rt-mft-tree/src/tree.rs`
- Modify: `crates/rt-mft-tree/src/lib.rs`

- [ ] **Step 1: Write tree.rs with `FileTree` and all tests**

This is a migration from `crates/rt-navigator/src/tree.rs`. Copy the following components, updating `FileNode` imports to use `crate::node::FileNode`:

- `ROOT_MFT_ENTRY` constant
- `FileTree` struct (nodes, children, entry_map, root_idx, paths, total_mft_entries, allocated_entries)
- `from_nodes()` constructor (with BFS path building + orphan fallback)
- Accessors: `root_idx()`, `node()`, `entry_to_idx()`, `children()`, `cached_path()`, `search()`, `dir_stats()`

The test helpers (`ts()`, `dir_node()`, `file_node()`, `sample_nodes()`) must be updated to use `NtfsTimestamps` + `si_timestamps`/`fn_timestamps` fields:

```rust
// In the tests module:
use crate::node::{FileNode, NtfsTimestamps};

fn default_timestamps() -> NtfsTimestamps {
    NtfsTimestamps {
        modified: ts(2024, 1, 1),
        accessed: ts(2024, 1, 1),
        created: ts(2024, 1, 1),
        entry_modified: ts(2024, 1, 1),
    }
}

fn dir_node(name: &str, mft_entry: u64, parent_entry: u64) -> FileNode {
    FileNode {
        name: name.to_string(),
        mft_entry,
        parent_entry,
        is_dir: true,
        size: 0,
        si_timestamps: default_timestamps(),
        fn_timestamps: None,
        file_attributes: 0, usn_change_count: 0,
    }
}

fn file_node(name: &str, mft_entry: u64, parent_entry: u64, size: u64) -> FileNode {
    FileNode {
        name: name.to_string(),
        mft_entry,
        parent_entry,
        is_dir: false,
        size,
        si_timestamps: NtfsTimestamps {
            modified: ts(2024, 6, 15),
            accessed: ts(2024, 6, 15),
            created: ts(2024, 1, 1),
            entry_modified: ts(2024, 6, 15),
        },
        fn_timestamps: None,
        file_attributes: 0, usn_change_count: 0,
    }
}
```

Migrate ALL existing tests from rt-navigator's tree.rs: `from_nodes_builds_tree_with_correct_entry_count`, `from_nodes_finds_root_at_entry_5`, `empty_nodes_produces_no_root`, `root_has_three_children`, `children_sorted_dirs_before_files`, `children_dirs_sorted_case_insensitive`, `system32_has_two_files`, `cached_path_of_root_is_slash`, `cached_path_of_direct_child`, `cached_path_of_deeply_nested_file`, `cached_path_of_system32_exe`, `search_finds_file_by_name`, `search_matches_directory_path`, `search_is_case_insensitive`, `search_anywhere_in_path`, `search_with_no_match_returns_empty`, `search_excludes_root_node`, `dir_stats_for_root`, `dir_stats_for_system32`, `dir_stats_for_empty_dir`, `entry_to_idx_known_entry`, `entry_to_idx_unknown_entry`, `cached_path_all_start_with_slash`, `cached_path_root_is_slash`, `cached_path_deeply_nested`, `cached_path_empty_tree`, `search_uses_cached_paths_same_results`.

Total: 27 tests from tree construction/accessors + 5 from node.rs = 32 tests.

- [ ] **Step 2: Update lib.rs**

```rust
pub mod node;
pub mod tree;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p rt-mft-tree`
Expected: 32 tests pass

- [ ] **Step 4: Commit**

```bash
git add crates/rt-mft-tree/src/
git commit -m "feat(rt-mft-tree): add FileTree with arena, path index, and search"
```

---

## Task 3: Create rt-mft-tree — enrich.rs and parse.rs

**Files:**
- Create: `crates/rt-mft-tree/src/enrich.rs`
- Create: `crates/rt-mft-tree/src/parse.rs`
- Modify: `crates/rt-mft-tree/src/lib.rs`

- [ ] **Step 1: Write enrich.rs with tests**

Migrate `enrich_usn()` from rt-navigator's tree.rs. This is a method on `FileTree`:

```rust
//! USN journal enrichment for FileTree nodes.

use crate::tree::FileTree;

impl FileTree {
    /// Enrich nodes with USN journal change counts.
    ///
    /// Each tuple is `(mft_entry_number, filename)`. Matching is done
    /// solely by MFT entry number.
    pub fn enrich_usn(&mut self, records: &[(u64, String)]) {
        for &(mft_entry, _) in records {
            if let Some(&idx) = self.entry_to_idx(mft_entry) {
                self.node_mut(idx).usn_change_count += 1;
            }
        }
    }
}
```

Note: `node_mut()` is a new accessor needed on `FileTree` — add it in tree.rs:

```rust
/// Mutable reference to a node by arena index.
pub fn node_mut(&mut self, idx: usize) -> &mut FileNode {
    &mut self.nodes[idx]
}
```

Tests (migrate from rt-navigator):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    // Re-use the sample_nodes() and helpers defined in tree.rs tests.
    // Import them via: use crate::tree::tests::{sample_nodes};
    // OR duplicate the helpers here.

    // Tests: enrich_usn_increments_change_count, enrich_usn_ignores_unknown_entries,
    // enrich_usn_multiple_files, enrich_usn_leaves_unenriched_at_zero
}
```

4 enrichment tests.

- [ ] **Step 2: Write parse.rs**

Migrate `from_mft()` from rt-navigator's tree.rs. Update to populate `si_timestamps` and `fn_timestamps` from MFT attributes:

```rust
//! MFT binary parsing into FileTree.

use std::path::Path;

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use mft::attribute::{MftAttributeContent, MftAttributeType};
use mft::MftParser;

use crate::node::{FileNode, NtfsTimestamps};
use crate::tree::FileTree;

impl FileTree {
    /// Parse an `$MFT` file on disk and build the tree.
    #[allow(clippy::cast_possible_truncation)]
    pub fn from_mft(path: &Path) -> Result<Self> {
        let buffer =
            std::fs::read(path).with_context(|| format!("Failed to read: {}", path.display()))?;

        let mut parser =
            MftParser::from_buffer(buffer).context("Failed to initialise MFT parser")?;

        let total = parser.get_entry_count();
        let capacity = (total as usize) / 2;
        let mut nodes = Vec::with_capacity(capacity);

        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::with_template(
                "  Parsing MFT [{bar:40.cyan/dim}] {pos}/{len} entries ({percent}%)",
            )
            .expect("valid template")
            .progress_chars("##-"),
        );

        for i in 0..total {
            pb.set_position(i);

            let Ok(entry) = parser.get_entry(i) else {
                continue;
            };

            if !entry.is_allocated() {
                continue;
            }

            let Some(fname) = entry.find_best_name_attribute() else {
                continue;
            };

            let is_dir = entry.is_dir();
            let entry_id = entry.header.record_number;
            let parent_entry = fname.parent.entry;

            // $FILE_NAME timestamps (kernel-managed).
            let fn_ts = NtfsTimestamps {
                modified: fname.modified,
                accessed: fname.accessed,
                created: fname.created,
                entry_modified: fname.mft_modified,
            };

            // $STANDARD_INFORMATION timestamps (user-visible, preferred).
            let si_ts = entry
                .iter_attributes_matching(Some(vec![MftAttributeType::StandardInformation]))
                .filter_map(std::result::Result::ok)
                .find_map(|attr| {
                    if let MftAttributeContent::AttrX10(si) = attr.data {
                        Some(NtfsTimestamps {
                            modified: si.modified,
                            accessed: si.accessed,
                            created: si.created,
                            entry_modified: si.mft_modified,
                        })
                    } else {
                        None
                    }
                })
                .unwrap_or(fn_ts);

            // Only store fn_timestamps if they differ from si_timestamps.
            let fn_timestamps = if fn_ts != si_ts { Some(fn_ts) } else { None };

            let size = if is_dir { 0 } else { fname.logical_size };

            // Extract file attribute flags from $STANDARD_INFORMATION.
            let file_attributes = entry
                .iter_attributes_matching(Some(vec![MftAttributeType::StandardInformation]))
                .filter_map(std::result::Result::ok)
                .find_map(|attr| {
                    if let MftAttributeContent::AttrX10(si) = attr.data {
                        Some(si.file_flags.bits())
                    } else {
                        None
                    }
                })
                .unwrap_or(0);

            nodes.push(FileNode {
                name: fname.name.clone(),
                mft_entry: entry_id,
                parent_entry,
                is_dir,
                size,
                si_timestamps: si_ts,
                fn_timestamps,
                file_attributes, usn_change_count: 0,
            });
        }

        pb.finish_and_clear();
        let allocated = nodes.len();
        eprintln!("  Parsed {allocated} allocated entries from {total} MFT records.");

        let pb2 = ProgressBar::new_spinner();
        pb2.set_style(
            ProgressStyle::with_template("  {spinner:.cyan} Building directory tree...")
                .expect("valid template"),
        );
        pb2.enable_steady_tick(std::time::Duration::from_millis(80));

        let mut tree = Self::from_nodes(nodes);
        tree.total_mft_entries = total;

        pb2.finish_and_clear();
        Ok(tree)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_mft_rejects_nonexistent_file() {
        let result = FileTree::from_mft(Path::new("/nonexistent/$MFT"));
        assert!(result.is_err());
    }

    #[test]
    fn from_mft_rejects_empty_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let result = FileTree::from_mft(tmp.path());
        assert!(result.is_err());
    }

    #[test]
    fn from_mft_rejects_garbage_data() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"this is not an MFT file at all").unwrap();
        let result = FileTree::from_mft(tmp.path());
        assert!(result.is_err());
    }
}
```

- [ ] **Step 3: Update lib.rs**

```rust
pub mod node;
pub mod tree;
pub mod enrich;
pub mod parse;
```

- [ ] **Step 4: Run all tests**

Run: `cargo test -p rt-mft-tree`
Expected: 39 tests pass (32 tree/node + 4 enrich + 3 parse)

- [ ] **Step 5: Commit**

```bash
git add crates/rt-mft-tree/src/
git commit -m "feat(rt-mft-tree): add USN enrichment and MFT parsing with dual timestamps"
```

---

## Task 4: Migrate rt-navigator to use rt-mft-tree

Replace rt-navigator's inline tree.rs with the shared crate. This is a mechanical replacement — no new features.

**Files:**
- Delete: `crates/rt-navigator/src/tree.rs`
- Modify: `crates/rt-navigator/Cargo.toml`
- Modify: `crates/rt-navigator/src/app.rs`
- Modify: `crates/rt-navigator/src/ui.rs`
- Modify: `crates/rt-navigator/src/main.rs`

- [ ] **Step 1: Update rt-navigator Cargo.toml**

Add `rt-mft-tree` dependency, remove `mft` (now transitive via rt-mft-tree):

```toml
[dependencies]
rt-mft-tree = { workspace = true }
chrono = { workspace = true }
clap = { workspace = true }
anyhow = { workspace = true }
ratatui = { workspace = true }
crossterm = { workspace = true }
indicatif = { workspace = true }
rt-parser-usnjrnl = { workspace = true }
```

- [ ] **Step 2: Delete `crates/rt-navigator/src/tree.rs`**

- [ ] **Step 3: Update imports in app.rs**

Replace:
```rust
use crate::tree::{FileTree, FileNode};
```
With:
```rust
use rt_mft_tree::tree::FileTree;
```

All references to `FileTree` and `FileNode` now come from `rt_mft_tree`. The public API is identical, so `app.rs` logic doesn't change. The only difference is `FileNode` now has `si_timestamps: NtfsTimestamps` instead of bare `modified`/`created`/etc fields.

- [ ] **Step 4: Update imports in ui.rs**

Replace `crate::tree::` imports with `rt_mft_tree::tree::` and `rt_mft_tree::node::`. Update timestamp references from `node.modified` to `node.si_timestamps.modified`, `node.created` to `node.si_timestamps.created`, etc.

- [ ] **Step 5: Update imports in main.rs**

Replace `crate::tree::FileTree` → `rt_mft_tree::tree::FileTree`. The `from_mft()` call is unchanged. The `enrich_usn()` call is unchanged.

- [ ] **Step 6: Run all rt-navigator tests**

Run: `cargo test -p rt-navigator`
Expected: All app.rs tests pass (37 tests). The tree.rs tests no longer exist here — they're in rt-mft-tree now.

- [ ] **Step 7: Run clippy**

Run: `cargo clippy -p rt-navigator -- -W clippy::pedantic`
Expected: No warnings

- [ ] **Step 8: Commit**

```bash
git add crates/rt-navigator/ Cargo.lock
git commit -m "refactor(rt-navigator): migrate to shared rt-mft-tree crate"
```

---

## Task 5: Add heuristics scaffolding to rt-signatures

Set up the feature flag, module structure, and core types (`Anomaly`, `AnomalyCategory`, `AnomalyIndex`, `HeuristicsConfig`).

**Files:**
- Modify: `crates/rt-signatures/Cargo.toml`
- Modify: `crates/rt-signatures/src/lib.rs`
- Create: `crates/rt-signatures/src/heuristics/mod.rs`
- Create: `crates/rt-signatures/src/heuristics/anomaly.rs`

- [ ] **Step 1: Write failing tests for `AnomalyIndex`**

Create `crates/rt-signatures/src/heuristics/anomaly.rs`:

```rust
//! Anomaly data model and index for forensic heuristic findings.

use std::collections::HashMap;

use crate::matching::results::Severity;

/// Category of forensic anomaly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnomalyCategory {
    Timestomping,
    SuspiciousLocation,
    ExtensionMismatch,
    HighEntropy,
    SecureDeletion,
    RansomwarePattern,
    JournalTampering,
    GhostFile,
    SuspiciousSize,
    MftIntegrity,
}

impl AnomalyCategory {
    /// String representation for serialization.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Timestomping => "timestomping",
            Self::SuspiciousLocation => "suspicious_location",
            Self::ExtensionMismatch => "extension_mismatch",
            Self::HighEntropy => "high_entropy",
            Self::SecureDeletion => "secure_deletion",
            Self::RansomwarePattern => "ransomware_pattern",
            Self::JournalTampering => "journal_tampering",
            Self::GhostFile => "ghost_file",
            Self::SuspiciousSize => "suspicious_size",
            Self::MftIntegrity => "mft_integrity",
        }
    }
}

/// A single heuristic finding for a file or directory.
#[derive(Debug, Clone)]
pub struct Anomaly {
    pub severity: Severity,
    pub category: AnomalyCategory,
    /// Stable rule identifier (e.g., "HEUR-TS-001").
    pub rule_id: &'static str,
    pub description: String,
    /// Specific values that triggered detection.
    pub evidence: String,
}

/// Optional configuration for heuristic checks.
pub struct HeuristicsConfig {
    /// If set, HEUR-TS-004 checks for `$SI` timestamps predating this date.
    pub volume_created: Option<chrono::DateTime<chrono::Utc>>,
}

impl Default for HeuristicsConfig {
    fn default() -> Self {
        Self {
            volume_created: None,
        }
    }
}

/// Lookup structure for anomalies by arena index.
#[derive(Debug, Default)]
pub struct AnomalyIndex {
    entries: HashMap<usize, Vec<Anomaly>>,
}

impl AnomalyIndex {
    /// Create an empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an anomaly for a node.
    pub fn add(&mut self, idx: usize, anomaly: Anomaly) {
        self.entries.entry(idx).or_default().push(anomaly);
    }

    /// All anomalies for a node (empty slice if none).
    pub fn for_node(&self, idx: usize) -> &[Anomaly] {
        self.entries.get(&idx).map_or(&[], Vec::as_slice)
    }

    /// Highest severity anomaly for a node.
    pub fn max_severity(&self, idx: usize) -> Option<Severity> {
        self.entries
            .get(&idx)
            .and_then(|anomalies| anomalies.iter().map(|a| a.severity).max())
    }

    /// Total number of flagged nodes.
    pub fn flagged_count(&self) -> usize {
        self.entries.len()
    }

    /// All flagged node indices, sorted by max severity (highest first).
    pub fn flagged_entries(&self) -> Vec<usize> {
        let mut entries: Vec<(usize, Severity)> = self
            .entries
            .iter()
            .filter_map(|(&idx, anomalies)| {
                anomalies.iter().map(|a| a.severity).max().map(|s| (idx, s))
            })
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        entries.into_iter().map(|(idx, _)| idx).collect()
    }

    /// Merge another index into this one.
    pub fn merge(&mut self, other: Self) {
        for (idx, anomalies) in other.entries {
            self.entries.entry(idx).or_default().extend(anomalies);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_anomaly(severity: Severity, rule_id: &'static str) -> Anomaly {
        Anomaly {
            severity,
            category: AnomalyCategory::Timestomping,
            rule_id,
            description: format!("Test: {rule_id}"),
            evidence: String::new(),
        }
    }

    #[test]
    fn empty_index_has_no_flagged() {
        let idx = AnomalyIndex::new();
        assert_eq!(idx.flagged_count(), 0);
        assert!(idx.flagged_entries().is_empty());
    }

    #[test]
    fn for_node_returns_empty_slice_for_unknown() {
        let idx = AnomalyIndex::new();
        assert!(idx.for_node(42).is_empty());
    }

    #[test]
    fn add_and_retrieve_anomaly() {
        let mut idx = AnomalyIndex::new();
        idx.add(10, make_anomaly(Severity::High, "HEUR-TS-001"));
        assert_eq!(idx.for_node(10).len(), 1);
        assert_eq!(idx.for_node(10)[0].rule_id, "HEUR-TS-001");
    }

    #[test]
    fn multiple_anomalies_per_node() {
        let mut idx = AnomalyIndex::new();
        idx.add(10, make_anomaly(Severity::Low, "HEUR-TS-003"));
        idx.add(10, make_anomaly(Severity::High, "HEUR-TS-001"));
        assert_eq!(idx.for_node(10).len(), 2);
    }

    #[test]
    fn max_severity_returns_highest() {
        let mut idx = AnomalyIndex::new();
        idx.add(10, make_anomaly(Severity::Low, "HEUR-TS-003"));
        idx.add(10, make_anomaly(Severity::High, "HEUR-TS-001"));
        assert_eq!(idx.max_severity(10), Some(Severity::High));
    }

    #[test]
    fn max_severity_none_for_unflagged() {
        let idx = AnomalyIndex::new();
        assert!(idx.max_severity(99).is_none());
    }

    #[test]
    fn flagged_count_distinct_nodes() {
        let mut idx = AnomalyIndex::new();
        idx.add(10, make_anomaly(Severity::High, "HEUR-TS-001"));
        idx.add(10, make_anomaly(Severity::Low, "HEUR-TS-003"));
        idx.add(20, make_anomaly(Severity::Medium, "HEUR-LOC-001"));
        assert_eq!(idx.flagged_count(), 2);
    }

    #[test]
    fn flagged_entries_sorted_by_severity() {
        let mut idx = AnomalyIndex::new();
        idx.add(10, make_anomaly(Severity::Low, "r1"));
        idx.add(20, make_anomaly(Severity::Critical, "r2"));
        idx.add(30, make_anomaly(Severity::Medium, "r3"));
        let entries = idx.flagged_entries();
        assert_eq!(entries, vec![20, 30, 10]);
    }

    #[test]
    fn merge_combines_indices() {
        let mut a = AnomalyIndex::new();
        a.add(10, make_anomaly(Severity::High, "r1"));

        let mut b = AnomalyIndex::new();
        b.add(10, make_anomaly(Severity::Low, "r2"));
        b.add(20, make_anomaly(Severity::Medium, "r3"));

        a.merge(b);
        assert_eq!(a.for_node(10).len(), 2);
        assert_eq!(a.for_node(20).len(), 1);
        assert_eq!(a.flagged_count(), 2);
    }

    #[test]
    fn category_as_str() {
        assert_eq!(AnomalyCategory::Timestomping.as_str(), "timestomping");
        assert_eq!(
            AnomalyCategory::SuspiciousLocation.as_str(),
            "suspicious_location"
        );
        assert_eq!(AnomalyCategory::GhostFile.as_str(), "ghost_file");
    }
}
```

- [ ] **Step 2: Update rt-signatures Cargo.toml**

Add feature flags and optional dependency:

```toml
[features]
default = ["heuristics"]
heuristics = ["dep:rt-mft-tree", "dep:rt-parser-usnjrnl"]

[dependencies]
# ... existing deps unchanged ...
chrono = { workspace = true }

# Heuristics (optional)
rt-mft-tree = { workspace = true, optional = true }
rt-parser-usnjrnl = { workspace = true, optional = true }
```

- [ ] **Step 3: Create heuristics/mod.rs and update lib.rs**

`crates/rt-signatures/src/heuristics/mod.rs`:
```rust
pub mod anomaly;
```

`crates/rt-signatures/src/lib.rs`:
```rust
pub mod engines;
pub mod feeds;
pub mod matching;

#[cfg(feature = "heuristics")]
pub mod heuristics;
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p rt-signatures`
Expected: Existing tests + 11 new anomaly tests pass

- [ ] **Step 5: Commit**

```bash
git add crates/rt-signatures/
git commit -m "feat(rt-signatures): add heuristics feature flag with Anomaly and AnomalyIndex"
```

---

## Task 6: Tier 1 entry checks (HEUR-TS-*, HEUR-SZ-001, HEUR-AT-001, HEUR-MG-003)

**Files:**
- Create: `crates/rt-signatures/src/heuristics/entry_checks.rs`
- Modify: `crates/rt-signatures/src/heuristics/mod.rs`

- [ ] **Step 1: Write failing tests**

Create `crates/rt-signatures/src/heuristics/entry_checks.rs` with the `check_entry` function signature and tests. Each HEUR rule gets a positive test (triggers) and a negative test (normal files don't trigger).

```rust
//! Per-entry heuristic checks (Tier 1, streaming-compatible).

use rt_mft_tree::node::{FileNode, NtfsTimestamps};

use crate::matching::results::Severity;
use super::anomaly::{Anomaly, AnomalyCategory, HeuristicsConfig};

/// Run all entry-level heuristic checks on a single node.
pub fn check_entry(node: &FileNode, config: &HeuristicsConfig) -> Vec<Anomaly> {
    let mut results = Vec::new();
    check_ts_001(node, &mut results);
    check_ts_002(node, &mut results);
    check_ts_003(node, &mut results);
    check_ts_004(node, config, &mut results);
    check_sz_001(node, &mut results);
    check_at_001(node, &mut results);
    check_mg_003(node, &mut results);
    results
}

fn check_ts_001(node: &FileNode, results: &mut Vec<Anomaly>) {
    // SI created > SI modified
    if node.si_timestamps.created > node.si_timestamps.modified {
        results.push(Anomaly {
            severity: Severity::High,
            category: AnomalyCategory::Timestomping,
            rule_id: "HEUR-TS-001",
            description: "$SI created timestamp is after modified timestamp".to_string(),
            evidence: format!(
                "created={}, modified={}",
                node.si_timestamps.created, node.si_timestamps.modified
            ),
        });
    }
}

fn check_ts_002(node: &FileNode, results: &mut Vec<Anomaly>) {
    // SI/FN timestamp divergence > 24 hours
    let Some(fn_ts) = &node.fn_timestamps else {
        return;
    };
    let diff = (node.si_timestamps.created - fn_ts.created).num_hours().abs();
    if diff > 24 {
        results.push(Anomaly {
            severity: Severity::Medium,
            category: AnomalyCategory::Timestomping,
            rule_id: "HEUR-TS-002",
            description: "$SI/$FN created timestamps diverge by more than 24 hours".to_string(),
            evidence: format!("si.created={}, fn.created={}, diff={diff}h", node.si_timestamps.created, fn_ts.created),
        });
    }
}

fn check_ts_003(node: &FileNode, results: &mut Vec<Anomaly>) {
    // Zeroed subseconds in SI while FN has subseconds
    let Some(fn_ts) = &node.fn_timestamps else {
        return;
    };
    let si_zeroed = node.si_timestamps.created.timestamp_subsec_nanos() == 0
        && node.si_timestamps.modified.timestamp_subsec_nanos() == 0;
    let fn_has_subsec = fn_ts.created.timestamp_subsec_nanos() != 0
        || fn_ts.modified.timestamp_subsec_nanos() != 0;
    if si_zeroed && fn_has_subsec {
        results.push(Anomaly {
            severity: Severity::Low,
            category: AnomalyCategory::Timestomping,
            rule_id: "HEUR-TS-003",
            description: "$SI timestamps have zeroed subseconds while $FN retains precision".to_string(),
            evidence: format!(
                "si.created_nanos=0, fn.created_nanos={}",
                fn_ts.created.timestamp_subsec_nanos()
            ),
        });
    }
}

fn check_ts_004(node: &FileNode, config: &HeuristicsConfig, results: &mut Vec<Anomaly>) {
    let Some(vol_created) = config.volume_created else {
        return;
    };
    if node.si_timestamps.created < vol_created {
        results.push(Anomaly {
            severity: Severity::Medium,
            category: AnomalyCategory::Timestomping,
            rule_id: "HEUR-TS-004",
            description: "$SI created predates volume creation".to_string(),
            evidence: format!(
                "si.created={}, volume_created={}",
                node.si_timestamps.created, vol_created
            ),
        });
    }
}

fn check_sz_001(node: &FileNode, results: &mut Vec<Anomaly>) {
    if node.is_dir {
        return;
    }
    let name_lower = node.name.to_lowercase();
    let suspicious = if name_lower.ends_with(".txt") || name_lower.ends_with(".log") || name_lower.ends_with(".csv") {
        node.size > 10 * 1024 * 1024 // > 10MB
    } else if name_lower.ends_with(".exe") || name_lower.ends_with(".dll") {
        node.size == 0
    } else if name_lower.ends_with(".jpg") || name_lower.ends_with(".png") {
        node.size < 100 && node.size > 0
    } else {
        false
    };
    if suspicious {
        results.push(Anomaly {
            severity: Severity::Low,
            category: AnomalyCategory::SuspiciousSize,
            rule_id: "HEUR-SZ-001",
            description: "File size is suspicious for its extension".to_string(),
            evidence: format!("name={}, size={}", node.name, node.size),
        });
    }
}

/// NTFS attribute flag constants.
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;

fn check_at_001(node: &FileNode, results: &mut Vec<Anomaly>) {
    if node.is_dir {
        return;
    }
    let both = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
    if node.file_attributes & both == both {
        results.push(Anomaly {
            severity: Severity::Low,
            category: AnomalyCategory::SuspiciousLocation,
            rule_id: "HEUR-AT-001",
            description: "Hidden and system attributes set on non-system file".to_string(),
            evidence: format!("name={}, attributes=0x{:X}", node.name, node.file_attributes),
        });
    }
}

fn check_mg_003(node: &FileNode, results: &mut Vec<Anomaly>) {
    if node.is_dir {
        return;
    }
    let executable_exts = [".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".com", ".pif"];
    let name_lower = node.name.to_lowercase();
    // Find the last extension
    let Some(last_dot) = name_lower.rfind('.') else {
        return;
    };
    let last_ext = &name_lower[last_dot..];
    if !executable_exts.iter().any(|&e| last_ext == e) {
        return;
    }
    // Check if there's a second extension before the last one
    let before_last = &name_lower[..last_dot];
    if before_last.contains('.') {
        results.push(Anomaly {
            severity: Severity::Medium,
            category: AnomalyCategory::ExtensionMismatch,
            rule_id: "HEUR-MG-003",
            description: "Double extension with executable suffix".to_string(),
            evidence: format!("name={}", node.name),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn ts(year: i32, month: u32, day: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).unwrap()
    }

    fn ts_with_nanos(year: i32, month: u32, day: u32, nanos: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, 12, 0, 0)
            .unwrap()
            .with_nanosecond(nanos)
            .unwrap()
    }

    fn default_ts() -> NtfsTimestamps {
        NtfsTimestamps {
            modified: ts(2024, 1, 1),
            accessed: ts(2024, 1, 1),
            created: ts(2024, 1, 1),
            entry_modified: ts(2024, 1, 1),
        }
    }

    fn default_node() -> FileNode {
        FileNode {
            name: "file.txt".to_string(),
            mft_entry: 100,
            parent_entry: 5,
            is_dir: false,
            size: 1024,
            si_timestamps: default_ts(),
            fn_timestamps: None,
            file_attributes: 0, usn_change_count: 0,
        }
    }

    fn default_config() -> HeuristicsConfig {
        HeuristicsConfig::default()
    }

    // --- HEUR-TS-001 ---

    #[test]
    fn ts_001_triggers_when_created_after_modified() {
        let node = FileNode {
            si_timestamps: NtfsTimestamps {
                created: ts(2024, 6, 1),
                modified: ts(2024, 1, 1),
                ..default_ts()
            },
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(anomalies.iter().any(|a| a.rule_id == "HEUR-TS-001"));
    }

    #[test]
    fn ts_001_does_not_trigger_normal_timestamps() {
        let node = FileNode {
            si_timestamps: NtfsTimestamps {
                created: ts(2024, 1, 1),
                modified: ts(2024, 6, 1),
                ..default_ts()
            },
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(!anomalies.iter().any(|a| a.rule_id == "HEUR-TS-001"));
    }

    // --- HEUR-TS-002 ---

    #[test]
    fn ts_002_triggers_on_large_si_fn_divergence() {
        let node = FileNode {
            si_timestamps: NtfsTimestamps {
                created: ts(2024, 6, 1),
                ..default_ts()
            },
            fn_timestamps: Some(NtfsTimestamps {
                created: ts(2023, 1, 1),
                ..default_ts()
            }),
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(anomalies.iter().any(|a| a.rule_id == "HEUR-TS-002"));
    }

    #[test]
    fn ts_002_skipped_when_no_fn_timestamps() {
        let node = FileNode {
            fn_timestamps: None,
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(!anomalies.iter().any(|a| a.rule_id == "HEUR-TS-002"));
    }

    #[test]
    fn ts_002_does_not_trigger_within_24h() {
        let si = NtfsTimestamps {
            created: ts(2024, 1, 2),
            ..default_ts()
        };
        let node = FileNode {
            si_timestamps: si,
            fn_timestamps: Some(NtfsTimestamps {
                created: ts(2024, 1, 1),
                ..default_ts()
            }),
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(!anomalies.iter().any(|a| a.rule_id == "HEUR-TS-002"));
    }

    // --- HEUR-TS-003 ---

    #[test]
    fn ts_003_triggers_zeroed_subseconds() {
        let si = NtfsTimestamps {
            created: ts(2024, 1, 1),    // zero nanos (whole second)
            modified: ts(2024, 1, 1),
            accessed: ts(2024, 1, 1),
            entry_modified: ts(2024, 1, 1),
        };
        let fn_ts = NtfsTimestamps {
            created: ts_with_nanos(2024, 1, 1, 123_456_789),
            modified: ts_with_nanos(2024, 1, 1, 987_654_321),
            accessed: ts(2024, 1, 1),
            entry_modified: ts(2024, 1, 1),
        };
        let node = FileNode {
            si_timestamps: si,
            fn_timestamps: Some(fn_ts),
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(anomalies.iter().any(|a| a.rule_id == "HEUR-TS-003"));
    }

    #[test]
    fn ts_003_does_not_trigger_when_both_have_subseconds() {
        let si = NtfsTimestamps {
            created: ts_with_nanos(2024, 1, 1, 111_111_111),
            modified: ts_with_nanos(2024, 1, 1, 222_222_222),
            accessed: ts(2024, 1, 1),
            entry_modified: ts(2024, 1, 1),
        };
        let fn_ts = NtfsTimestamps {
            created: ts_with_nanos(2024, 1, 1, 123_456_789),
            modified: ts_with_nanos(2024, 1, 1, 987_654_321),
            accessed: ts(2024, 1, 1),
            entry_modified: ts(2024, 1, 1),
        };
        let node = FileNode {
            si_timestamps: si,
            fn_timestamps: Some(fn_ts),
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(!anomalies.iter().any(|a| a.rule_id == "HEUR-TS-003"));
    }

    // --- HEUR-TS-004 ---

    #[test]
    fn ts_004_triggers_when_si_predates_volume() {
        let config = HeuristicsConfig {
            volume_created: Some(ts(2023, 1, 1)),
        };
        let node = FileNode {
            si_timestamps: NtfsTimestamps {
                created: ts(2020, 1, 1),
                ..default_ts()
            },
            ..default_node()
        };
        let anomalies = check_entry(&node, &config);
        assert!(anomalies.iter().any(|a| a.rule_id == "HEUR-TS-004"));
    }

    #[test]
    fn ts_004_skipped_when_no_volume_date() {
        let anomalies = check_entry(&default_node(), &default_config());
        assert!(!anomalies.iter().any(|a| a.rule_id == "HEUR-TS-004"));
    }

    // --- HEUR-SZ-001 ---

    #[test]
    fn sz_001_triggers_large_txt() {
        let node = FileNode {
            name: "data.txt".to_string(),
            size: 20 * 1024 * 1024,
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(anomalies.iter().any(|a| a.rule_id == "HEUR-SZ-001"));
    }

    #[test]
    fn sz_001_triggers_zero_byte_exe() {
        let node = FileNode {
            name: "empty.exe".to_string(),
            size: 0,
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(anomalies.iter().any(|a| a.rule_id == "HEUR-SZ-001"));
    }

    #[test]
    fn sz_001_does_not_trigger_normal_txt() {
        let node = FileNode {
            name: "readme.txt".to_string(),
            size: 4096,
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(!anomalies.iter().any(|a| a.rule_id == "HEUR-SZ-001"));
    }

    // --- HEUR-AT-001 ---

    #[test]
    fn at_001_triggers_hidden_system() {
        let node = FileNode {
            name: "secret.dat".to_string(),
            file_attributes: 0x6, // hidden + system
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(anomalies.iter().any(|a| a.rule_id == "HEUR-AT-001"));
    }

    #[test]
    fn at_001_does_not_trigger_hidden_only() {
        let node = FileNode {
            file_attributes: 0x2, // hidden only
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(!anomalies.iter().any(|a| a.rule_id == "HEUR-AT-001"));
    }

    #[test]
    fn at_001_does_not_trigger_on_directories() {
        let node = FileNode {
            is_dir: true,
            file_attributes: 0x6, // hidden + system
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(!anomalies.iter().any(|a| a.rule_id == "HEUR-AT-001"));
    }

    // --- HEUR-MG-003 ---

    #[test]
    fn mg_003_triggers_double_extension() {
        let node = FileNode {
            name: "report.pdf.exe".to_string(),
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(anomalies.iter().any(|a| a.rule_id == "HEUR-MG-003"));
    }

    #[test]
    fn mg_003_triggers_jpg_scr() {
        let node = FileNode {
            name: "image.jpg.scr".to_string(),
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(anomalies.iter().any(|a| a.rule_id == "HEUR-MG-003"));
    }

    #[test]
    fn mg_003_does_not_trigger_single_extension() {
        let node = FileNode {
            name: "program.exe".to_string(),
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(!anomalies.iter().any(|a| a.rule_id == "HEUR-MG-003"));
    }

    #[test]
    fn mg_003_does_not_trigger_non_executable_double() {
        let node = FileNode {
            name: "archive.tar.gz".to_string(),
            ..default_node()
        };
        let anomalies = check_entry(&node, &default_config());
        assert!(!anomalies.iter().any(|a| a.rule_id == "HEUR-MG-003"));
    }

    // --- Combined false-positive test ---

    #[test]
    fn normal_file_triggers_nothing() {
        let anomalies = check_entry(&default_node(), &default_config());
        assert!(anomalies.is_empty());
    }
}
```

- [ ] **Step 2: Update heuristics/mod.rs**

```rust
pub mod anomaly;
pub mod entry_checks;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p rt-signatures --features heuristics`
Expected: 11 anomaly + 21 entry_checks = 32 new tests pass (+ existing rt-signatures tests)

- [ ] **Step 4: Commit**

```bash
git add crates/rt-signatures/src/heuristics/
git commit -m "feat(heuristics): add Tier 1 entry-level checks for timestomping, size, and double extension"
```

---

## Task 7: Tier 1 tree checks (HEUR-LOC-*)

**Files:**
- Create: `crates/rt-signatures/src/heuristics/tree_checks.rs`
- Modify: `crates/rt-signatures/src/heuristics/mod.rs`

- [ ] **Step 1: Write tree_checks.rs with tests**

```rust
//! Tree-level heuristic checks requiring resolved paths (Tier 1).

use rt_mft_tree::tree::FileTree;

use crate::matching::results::Severity;
use super::anomaly::{Anomaly, AnomalyCategory, AnomalyIndex};

/// Run all tree-level checks. Returns an `AnomalyIndex`.
pub fn check_tree(tree: &FileTree) -> AnomalyIndex {
    let mut index = AnomalyIndex::new();
    let max_entry = tree.allocated_entries as u64;
    let high_entry_threshold = max_entry * 9 / 10; // top 10%

    for idx in 0..tree.allocated_entries {
        let node = tree.node(idx);
        if node.is_dir {
            continue;
        }
        let path_lower = tree.cached_path(idx).to_lowercase();

        check_loc_001(idx, node, &path_lower, &mut index);
        check_loc_002(idx, node, &path_lower, high_entry_threshold, &mut index);
        check_loc_003(idx, node, &mut index);
    }

    index
}

const EXECUTABLE_EXTS: &[&str] = &[".exe", ".dll", ".scr", ".bat", ".ps1", ".vbs", ".cmd", ".com"];

const SUSPICIOUS_PATHS: &[&str] = &[
    "temp", "$recycle.bin", "appdata/local/temp", "appdata/roaming/temp",
    "windows/temp", "tmp",
];

fn has_executable_ext(name: &str) -> bool {
    let lower = name.to_lowercase();
    EXECUTABLE_EXTS.iter().any(|ext| lower.ends_with(ext))
}

fn check_loc_001(
    idx: usize,
    node: &rt_mft_tree::node::FileNode,
    path_lower: &str,
    index: &mut AnomalyIndex,
) {
    if !has_executable_ext(&node.name) {
        return;
    }
    if SUSPICIOUS_PATHS.iter().any(|p| path_lower.contains(p)) {
        index.add(idx, Anomaly {
            severity: Severity::Medium,
            category: AnomalyCategory::SuspiciousLocation,
            rule_id: "HEUR-LOC-001",
            description: "Executable in temporary or recycled path".to_string(),
            evidence: format!("path={}", path_lower),
        });
    }
}

fn check_loc_002(
    idx: usize,
    node: &rt_mft_tree::node::FileNode,
    path_lower: &str,
    high_entry_threshold: u64,
    index: &mut AnomalyIndex,
) {
    if !path_lower.contains("/windows/system32/") && !path_lower.starts_with("/windows/system32") {
        return;
    }
    if node.mft_entry >= high_entry_threshold {
        index.add(idx, Anomaly {
            severity: Severity::Medium,
            category: AnomalyCategory::SuspiciousLocation,
            rule_id: "HEUR-LOC-002",
            description: "High MFT entry number in system directory".to_string(),
            evidence: format!(
                "mft_entry={}, threshold={}, path={}",
                node.mft_entry, high_entry_threshold, path_lower
            ),
        });
    }
}

const SUSPICIOUS_FILENAMES: &[&str] = &[
    "mimikatz", "pwdump", "procdump", "lazagne", "rubeus", "sharphound",
    "psexec", "wce", "gsecdump", "sekurlsa", "lsass_dump", "ntdsutil",
    "covenant", "cobalt", "meterpreter",
];

fn check_loc_003(
    idx: usize,
    node: &rt_mft_tree::node::FileNode,
    index: &mut AnomalyIndex,
) {
    let name_lower = node.name.to_lowercase();
    for &suspicious in SUSPICIOUS_FILENAMES {
        if name_lower.contains(suspicious) {
            index.add(idx, Anomaly {
                severity: Severity::High,
                category: AnomalyCategory::SuspiciousLocation,
                rule_id: "HEUR-LOC-003",
                description: "Known suspicious tool filename".to_string(),
                evidence: format!("name={}, matched={}", node.name, suspicious),
            });
            return; // One match is enough per file
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rt_mft_tree::node::{FileNode, NtfsTimestamps};
    use rt_mft_tree::tree::FileTree;
    use chrono::{TimeZone, Utc};

    fn ts(y: i32, m: u32, d: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
    }

    fn default_ts() -> NtfsTimestamps {
        NtfsTimestamps {
            modified: ts(2024, 1, 1),
            accessed: ts(2024, 1, 1),
            created: ts(2024, 1, 1),
            entry_modified: ts(2024, 1, 1),
        }
    }

    fn dir(name: &str, entry: u64, parent: u64) -> FileNode {
        FileNode {
            name: name.to_string(),
            mft_entry: entry,
            parent_entry: parent,
            is_dir: true,
            size: 0,
            si_timestamps: default_ts(),
            fn_timestamps: None,
            file_attributes: 0, usn_change_count: 0,
        }
    }

    fn file(name: &str, entry: u64, parent: u64, size: u64) -> FileNode {
        FileNode {
            name: name.to_string(),
            mft_entry: entry,
            parent_entry: parent,
            is_dir: false,
            size,
            si_timestamps: default_ts(),
            fn_timestamps: None,
            file_attributes: 0, usn_change_count: 0,
        }
    }

    #[test]
    fn loc_001_exe_in_temp() {
        let nodes = vec![
            dir(".", 5, 5),
            dir("Temp", 10, 5),
            file("malware.exe", 100, 10, 5000),
        ];
        let tree = FileTree::from_nodes(nodes);
        let index = check_tree(&tree);
        assert!(index.for_node(2).iter().any(|a| a.rule_id == "HEUR-LOC-001"));
    }

    #[test]
    fn loc_001_no_flag_for_exe_in_program_files() {
        let nodes = vec![
            dir(".", 5, 5),
            dir("Program Files", 10, 5),
            file("app.exe", 100, 10, 5000),
        ];
        let tree = FileTree::from_nodes(nodes);
        let index = check_tree(&tree);
        assert_eq!(index.flagged_count(), 0);
    }

    #[test]
    fn loc_001_no_flag_for_txt_in_temp() {
        let nodes = vec![
            dir(".", 5, 5),
            dir("Temp", 10, 5),
            file("notes.txt", 100, 10, 512),
        ];
        let tree = FileTree::from_nodes(nodes);
        let index = check_tree(&tree);
        assert_eq!(index.flagged_count(), 0);
    }

    #[test]
    fn loc_002_high_entry_in_system32() {
        // allocated_entries = 5, so threshold = 5 * 9/10 = 4
        // entry 900 >> 4
        let nodes = vec![
            dir(".", 5, 5),
            dir("Windows", 6, 5),
            dir("System32", 7, 6),
            file("suspicious.dll", 900, 7, 1024),
            file("normal.dll", 3, 7, 2048),
        ];
        let tree = FileTree::from_nodes(nodes);
        let index = check_tree(&tree);
        // suspicious.dll (entry 900) should be flagged
        let suspicious_idx = *tree.entry_to_idx(900).unwrap();
        assert!(index.for_node(suspicious_idx).iter().any(|a| a.rule_id == "HEUR-LOC-002"));
        // normal.dll (entry 3) should NOT be flagged
        let normal_idx = *tree.entry_to_idx(3).unwrap();
        assert!(!normal_idx == 0 || index.for_node(normal_idx).is_empty());
    }

    #[test]
    fn loc_003_mimikatz_detected() {
        let nodes = vec![
            dir(".", 5, 5),
            file("mimikatz.exe", 100, 5, 1024),
        ];
        let tree = FileTree::from_nodes(nodes);
        let index = check_tree(&tree);
        assert!(index.for_node(1).iter().any(|a| a.rule_id == "HEUR-LOC-003"));
    }

    #[test]
    fn loc_003_case_insensitive() {
        let nodes = vec![
            dir(".", 5, 5),
            file("MIMIKATZ.EXE", 100, 5, 1024),
        ];
        let tree = FileTree::from_nodes(nodes);
        let index = check_tree(&tree);
        assert!(index.for_node(1).iter().any(|a| a.rule_id == "HEUR-LOC-003"));
    }

    #[test]
    fn loc_003_no_flag_for_normal_file() {
        let nodes = vec![
            dir(".", 5, 5),
            file("notepad.exe", 100, 5, 1024),
        ];
        let tree = FileTree::from_nodes(nodes);
        let index = check_tree(&tree);
        assert_eq!(index.flagged_count(), 0);
    }

    #[test]
    fn clean_tree_no_flags() {
        let nodes = vec![
            dir(".", 5, 5),
            dir("Windows", 6, 5),
            dir("System32", 7, 6),
            file("cmd.exe", 8, 7, 289_000),
            file("notepad.exe", 9, 7, 201_000),
            dir("Users", 10, 5),
            file("readme.txt", 11, 10, 4096),
        ];
        let tree = FileTree::from_nodes(nodes);
        let index = check_tree(&tree);
        assert_eq!(index.flagged_count(), 0);
    }
}
```

- [ ] **Step 2: Update heuristics/mod.rs**

```rust
pub mod anomaly;
pub mod entry_checks;
pub mod tree_checks;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p rt-signatures --features heuristics`
Expected: Previous tests + 8 new tree_checks tests pass

- [ ] **Step 4: Commit**

```bash
git add crates/rt-signatures/src/heuristics/
git commit -m "feat(heuristics): add Tier 1 tree-level checks for suspicious locations and filenames"
```

---

## Task 8: Tier 2 scaffolding — FileReader trait and magic table

**Files:**
- Create: `crates/rt-signatures/src/heuristics/file_reader.rs`
- Create: `crates/rt-signatures/src/heuristics/magic_table.rs`
- Modify: `crates/rt-signatures/src/heuristics/mod.rs`

- [ ] **Step 1: Write file_reader.rs with tests**

```rust
//! File content access abstraction for Tier 2 checks.

use std::path::PathBuf;
use rt_mft_tree::tree::FileTree;

/// Abstract access to file content for Tier 2 heuristic checks.
pub trait FileReader {
    /// Read the first `n` bytes of the file at arena index `idx`.
    fn read_first_bytes(&self, idx: usize, n: usize) -> Option<Vec<u8>>;

    /// Whether this reader can access file content.
    fn is_available(&self) -> bool;
}

/// Reads files from a volume root directory via `std::fs`.
pub struct FsFileReader<'a> {
    volume_root: PathBuf,
    tree: &'a FileTree,
}

impl<'a> FsFileReader<'a> {
    pub fn new(volume_root: PathBuf, tree: &'a FileTree) -> Self {
        Self { volume_root, tree }
    }
}

impl FileReader for FsFileReader<'_> {
    fn read_first_bytes(&self, idx: usize, n: usize) -> Option<Vec<u8>> {
        let cached = self.tree.cached_path(idx);
        // cached_path starts with "/" — strip it for joining
        let rel = cached.strip_prefix('/').unwrap_or(cached);
        let full_path = self.volume_root.join(rel);

        let data = std::fs::read(&full_path).ok()?;
        Some(data[..n.min(data.len())].to_vec())
    }

    fn is_available(&self) -> bool {
        true
    }
}

/// No-op reader for standalone `$MFT` mode (no file access).
pub struct NoFileReader;

impl FileReader for NoFileReader {
    fn read_first_bytes(&self, _idx: usize, _n: usize) -> Option<Vec<u8>> {
        None
    }

    fn is_available(&self) -> bool {
        false
    }
}

/// Test mock: returns pre-loaded byte buffers by arena index.
#[cfg(test)]
pub struct MockFileReader(pub std::collections::HashMap<usize, Vec<u8>>);

#[cfg(test)]
impl FileReader for MockFileReader {
    fn read_first_bytes(&self, idx: usize, n: usize) -> Option<Vec<u8>> {
        self.0.get(&idx).map(|d| d[..n.min(d.len())].to_vec())
    }

    fn is_available(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn no_file_reader_returns_none() {
        let reader = NoFileReader;
        assert!(!reader.is_available());
        assert!(reader.read_first_bytes(0, 16).is_none());
    }

    #[test]
    fn mock_reader_returns_data() {
        let mut data = HashMap::new();
        data.insert(10, b"\x89PNG\r\n\x1a\n rest of png".to_vec());
        let reader = MockFileReader(data);
        assert!(reader.is_available());
        let bytes = reader.read_first_bytes(10, 8).unwrap();
        assert_eq!(&bytes[..4], b"\x89PNG");
    }

    #[test]
    fn mock_reader_clamps_to_data_length() {
        let mut data = HashMap::new();
        data.insert(5, vec![0xFF, 0xD8, 0xFF]);
        let reader = MockFileReader(data);
        let bytes = reader.read_first_bytes(5, 100).unwrap();
        assert_eq!(bytes.len(), 3);
    }

    #[test]
    fn mock_reader_unknown_idx_returns_none() {
        let reader = MockFileReader(HashMap::new());
        assert!(reader.read_first_bytes(99, 16).is_none());
    }
}
```

- [ ] **Step 2: Write magic_table.rs**

```rust
//! Static file signature table for magic byte detection.

/// A file signature entry mapping extensions to magic bytes.
pub struct MagicEntry {
    pub extensions: &'static [&'static str],
    pub magic: &'static [u8],
    pub offset: usize,
    pub description: &'static str,
}

/// Static table of known file signatures (~50 entries).
pub static MAGIC_TABLE: &[MagicEntry] = &[
    // Images
    MagicEntry { extensions: &["jpg", "jpeg"], magic: b"\xFF\xD8\xFF", offset: 0, description: "JPEG" },
    MagicEntry { extensions: &["png"], magic: b"\x89PNG\r\n\x1a\n", offset: 0, description: "PNG" },
    MagicEntry { extensions: &["gif"], magic: b"GIF87a", offset: 0, description: "GIF87a" },
    MagicEntry { extensions: &["gif"], magic: b"GIF89a", offset: 0, description: "GIF89a" },
    MagicEntry { extensions: &["bmp"], magic: b"BM", offset: 0, description: "BMP" },
    MagicEntry { extensions: &["tif", "tiff"], magic: b"II\x2A\x00", offset: 0, description: "TIFF (little-endian)" },
    MagicEntry { extensions: &["tif", "tiff"], magic: b"MM\x00\x2A", offset: 0, description: "TIFF (big-endian)" },
    MagicEntry { extensions: &["ico"], magic: b"\x00\x00\x01\x00", offset: 0, description: "ICO" },
    MagicEntry { extensions: &["webp"], magic: b"RIFF", offset: 0, description: "WebP/RIFF" },
    // Documents
    MagicEntry { extensions: &["pdf"], magic: b"%PDF", offset: 0, description: "PDF" },
    MagicEntry { extensions: &["docx", "xlsx", "pptx", "zip", "jar", "odt", "ods"], magic: b"PK\x03\x04", offset: 0, description: "ZIP/OOXML/ODF" },
    MagicEntry { extensions: &["doc", "xls", "ppt", "msg"], magic: b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", offset: 0, description: "OLE2 Compound" },
    MagicEntry { extensions: &["rtf"], magic: b"{\\rtf", offset: 0, description: "RTF" },
    // Executables
    MagicEntry { extensions: &["exe", "dll", "scr", "sys", "ocx", "drv"], magic: b"MZ", offset: 0, description: "PE executable" },
    MagicEntry { extensions: &["elf", "so", "o"], magic: b"\x7FELF", offset: 0, description: "ELF" },
    MagicEntry { extensions: &["class"], magic: b"\xCA\xFE\xBA\xBE", offset: 0, description: "Java class" },
    MagicEntry { extensions: &["dex"], magic: b"dex\n", offset: 0, description: "Dalvik DEX" },
    // Archives
    MagicEntry { extensions: &["gz", "tgz"], magic: b"\x1F\x8B", offset: 0, description: "gzip" },
    MagicEntry { extensions: &["bz2"], magic: b"BZ", offset: 0, description: "bzip2" },
    MagicEntry { extensions: &["xz"], magic: b"\xFD7zXZ\x00", offset: 0, description: "xz" },
    MagicEntry { extensions: &["7z"], magic: b"7z\xBC\xAF\x27\x1C", offset: 0, description: "7-Zip" },
    MagicEntry { extensions: &["rar"], magic: b"Rar!\x1A\x07", offset: 0, description: "RAR" },
    MagicEntry { extensions: &["cab"], magic: b"MSCF", offset: 0, description: "MS Cabinet" },
    MagicEntry { extensions: &["tar"], magic: b"ustar", offset: 257, description: "tar (POSIX)" },
    // Audio/Video
    MagicEntry { extensions: &["mp3"], magic: b"ID3", offset: 0, description: "MP3 (ID3)" },
    MagicEntry { extensions: &["mp4", "m4a", "m4v"], magic: b"ftyp", offset: 4, description: "MP4/M4A" },
    MagicEntry { extensions: &["avi"], magic: b"RIFF", offset: 0, description: "AVI/RIFF" },
    MagicEntry { extensions: &["flv"], magic: b"FLV", offset: 0, description: "Flash Video" },
    MagicEntry { extensions: &["ogg"], magic: b"OggS", offset: 0, description: "Ogg" },
    MagicEntry { extensions: &["wav"], magic: b"RIFF", offset: 0, description: "WAV/RIFF" },
    // Database
    MagicEntry { extensions: &["sqlite", "db", "sqlite3"], magic: b"SQLite format 3\x00", offset: 0, description: "SQLite" },
    // Disk images & forensic
    MagicEntry { extensions: &["vmdk"], magic: b"KDMV", offset: 0, description: "VMDK" },
    MagicEntry { extensions: &["vhd"], magic: b"conectix", offset: 0, description: "VHD" },
    MagicEntry { extensions: &["iso"], magic: b"CD001", offset: 32769, description: "ISO 9660" },
    MagicEntry { extensions: &["e01", "E01"], magic: b"EVF\x09\x0D\x0A\xFF\x00", offset: 0, description: "EnCase EWF" },
    // Crypto containers (used by HEUR-EN-002)
    MagicEntry { extensions: &["luks"], magic: b"LUKS\xBA\xBE", offset: 0, description: "LUKS" },
    // Scripts
    MagicEntry { extensions: &["ps1", "py", "sh", "bash", "pl", "rb"], magic: b"#!", offset: 0, description: "Shebang script" },
    // XML-based
    MagicEntry { extensions: &["xml", "svg", "html", "xhtml"], magic: b"<?xml", offset: 0, description: "XML" },
];

/// Look up what format a byte buffer actually is, based on magic bytes.
pub fn identify_format(data: &[u8]) -> Option<&'static MagicEntry> {
    MAGIC_TABLE.iter().find(|entry| {
        if data.len() < entry.offset + entry.magic.len() {
            return false;
        }
        data[entry.offset..entry.offset + entry.magic.len()] == *entry.magic
    })
}

/// Check if a file extension matches any entry in the magic table.
pub fn extension_known(ext: &str) -> bool {
    let ext_lower = ext.to_lowercase();
    MAGIC_TABLE
        .iter()
        .any(|entry| entry.extensions.iter().any(|&e| e == ext_lower))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identify_jpeg() {
        let data = b"\xFF\xD8\xFF\xE0rest of jpeg data";
        let entry = identify_format(data).unwrap();
        assert_eq!(entry.description, "JPEG");
    }

    #[test]
    fn identify_pe() {
        let data = b"MZ\x90\x00\x03\x00\x00\x00";
        let entry = identify_format(data).unwrap();
        assert_eq!(entry.description, "PE executable");
    }

    #[test]
    fn identify_pdf() {
        let data = b"%PDF-1.4 blah blah";
        let entry = identify_format(data).unwrap();
        assert_eq!(entry.description, "PDF");
    }

    #[test]
    fn identify_unknown_returns_none() {
        let data = b"\x00\x01\x02\x03unknown data";
        assert!(identify_format(data).is_none());
    }

    #[test]
    fn extension_known_jpg() {
        assert!(extension_known("jpg"));
        assert!(extension_known("JPG"));
    }

    #[test]
    fn extension_unknown() {
        assert!(!extension_known("xyz123"));
    }

    #[test]
    fn magic_table_has_entries() {
        assert!(MAGIC_TABLE.len() >= 30);
    }
}
```

- [ ] **Step 3: Update heuristics/mod.rs**

```rust
pub mod anomaly;
pub mod entry_checks;
pub mod tree_checks;
pub mod file_reader;
pub mod magic_table;
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p rt-signatures --features heuristics`
Expected: All previous + 4 file_reader + 7 magic_table tests pass

- [ ] **Step 5: Commit**

```bash
git add crates/rt-signatures/src/heuristics/
git commit -m "feat(heuristics): add FileReader trait, mock, and static magic table (~40 formats)"
```

---

## Task 9: Tier 2 content checks (HEUR-MG-001/002, HEUR-EN-001/002)

**Files:**
- Create: `crates/rt-signatures/src/heuristics/content_checks.rs`
- Modify: `crates/rt-signatures/src/heuristics/mod.rs`

- [ ] **Step 1: Write content_checks.rs with tests**

```rust
//! Content-aware heuristic checks (Tier 2, conditional on file access).

use rt_mft_tree::tree::FileTree;

use crate::matching::results::Severity;
use super::anomaly::{Anomaly, AnomalyCategory, AnomalyIndex};
use super::file_reader::FileReader;
use super::magic_table::{identify_format, extension_known};

/// Maximum bytes to read per file for content checks.
const MAX_READ_BYTES: usize = 4096;

/// Run Tier 2 checks on specific entries. Results are merged into `index`.
pub fn run_tier2(
    tree: &FileTree,
    entries: &[usize],
    reader: &dyn FileReader,
    index: &mut AnomalyIndex,
) {
    if !reader.is_available() {
        return;
    }
    for &idx in entries {
        let node = tree.node(idx);
        if node.is_dir || node.size == 0 {
            continue;
        }
        let Some(data) = reader.read_first_bytes(idx, MAX_READ_BYTES) else {
            continue;
        };

        check_mg_001(idx, node, &data, index);
        check_mg_002(idx, node, &data, index);
        check_en_001(idx, node, &data, index);
        check_en_002(idx, node, &data, index);
    }
}

/// Shannon entropy of a byte buffer (0.0 = uniform, 8.0 = random).
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&f| f > 0)
        .map(|&f| {
            let p = f as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn file_extension(name: &str) -> Option<String> {
    name.rsplit('.').next().map(|e| e.to_lowercase())
}

fn check_mg_001(
    idx: usize,
    node: &rt_mft_tree::node::FileNode,
    data: &[u8],
    index: &mut AnomalyIndex,
) {
    let Some(ext) = file_extension(&node.name) else {
        return;
    };
    if !extension_known(&ext) {
        return;
    }
    let Some(detected) = identify_format(data) else {
        return; // Unknown format — can't confirm mismatch
    };
    // Check if the file's extension matches the detected format
    if !detected.extensions.iter().any(|&e| e == ext) {
        index.add(idx, Anomaly {
            severity: Severity::Medium,
            category: AnomalyCategory::ExtensionMismatch,
            rule_id: "HEUR-MG-001",
            description: format!(
                "Magic bytes indicate {} but extension is .{}",
                detected.description, ext
            ),
            evidence: format!("detected={}, extension={}", detected.description, ext),
        });
    }
}

const DOCUMENT_EXTS: &[&str] = &[
    "docx", "doc", "xlsx", "xls", "pptx", "ppt", "pdf", "txt",
    "csv", "rtf", "odt", "ods", "jpg", "jpeg", "png", "gif",
    "bmp", "mp3", "mp4", "wav", "avi",
];

fn check_mg_002(
    idx: usize,
    node: &rt_mft_tree::node::FileNode,
    data: &[u8],
    index: &mut AnomalyIndex,
) {
    let Some(ext) = file_extension(&node.name) else {
        return;
    };
    if !DOCUMENT_EXTS.iter().any(|&e| e == ext) {
        return; // Only check document/media extensions
    }
    let is_executable = data.starts_with(b"MZ") || data.starts_with(b"\x7FELF");
    if is_executable {
        index.add(idx, Anomaly {
            severity: Severity::High,
            category: AnomalyCategory::ExtensionMismatch,
            rule_id: "HEUR-MG-002",
            description: format!("Executable disguised as .{ext}"),
            evidence: format!(
                "header={}, extension={}",
                if data.starts_with(b"MZ") { "PE/MZ" } else { "ELF" },
                ext
            ),
        });
    }
}

const LOW_ENTROPY_EXTS: &[&str] = &["txt", "csv", "log", "ini", "xml", "html", "json", "cfg", "conf"];

fn check_en_001(
    idx: usize,
    node: &rt_mft_tree::node::FileNode,
    data: &[u8],
    index: &mut AnomalyIndex,
) {
    let Some(ext) = file_extension(&node.name) else {
        return;
    };
    if !LOW_ENTROPY_EXTS.iter().any(|&e| e == ext) {
        return;
    }
    let entropy = shannon_entropy(data);
    if entropy > 7.5 {
        index.add(idx, Anomaly {
            severity: Severity::Medium,
            category: AnomalyCategory::HighEntropy,
            rule_id: "HEUR-EN-001",
            description: format!("High entropy ({entropy:.2}) in .{ext} file"),
            evidence: format!("entropy={entropy:.4}, extension={ext}"),
        });
    }
}

const LUKS_MAGIC: &[u8] = b"LUKS\xBA\xBE";

fn check_en_002(
    idx: usize,
    node: &rt_mft_tree::node::FileNode,
    data: &[u8],
    index: &mut AnomalyIndex,
) {
    // Check for known crypto container signatures
    if data.len() >= 6 && &data[..6] == LUKS_MAGIC {
        index.add(idx, Anomaly {
            severity: Severity::High,
            category: AnomalyCategory::HighEntropy,
            rule_id: "HEUR-EN-002",
            description: "LUKS encrypted container detected".to_string(),
            evidence: format!("name={}, magic=LUKS", node.name),
        });
        return;
    }

    // Heuristic: file with size multiple of 512, high entropy, no recognized header
    if node.size >= 1024
        && node.size % 512 == 0
        && identify_format(data).is_none()
    {
        let entropy = shannon_entropy(data);
        if entropy > 7.9 {
            index.add(idx, Anomaly {
                severity: Severity::High,
                category: AnomalyCategory::HighEntropy,
                rule_id: "HEUR-EN-002",
                description: "Possible encrypted container (512-byte aligned, high entropy, no header)".to_string(),
                evidence: format!("name={}, size={}, entropy={entropy:.4}", node.name, node.size),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::file_reader::MockFileReader;
    use rt_mft_tree::node::{FileNode, NtfsTimestamps};
    use rt_mft_tree::tree::FileTree;
    use chrono::{TimeZone, Utc};
    use std::collections::HashMap;

    fn ts() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap()
    }

    fn default_ts() -> NtfsTimestamps {
        NtfsTimestamps { modified: ts(), accessed: ts(), created: ts(), entry_modified: ts() }
    }

    fn make_file(name: &str, entry: u64, size: u64) -> FileNode {
        FileNode {
            name: name.to_string(), mft_entry: entry, parent_entry: 5,
            is_dir: false, size, si_timestamps: default_ts(),
            fn_timestamps: None, file_attributes: 0, usn_change_count: 0,
        }
    }

    fn build_tree_and_reader(files: Vec<(FileNode, Vec<u8>)>) -> (FileTree, MockFileReader) {
        let mut nodes = vec![FileNode {
            name: ".".to_string(), mft_entry: 5, parent_entry: 5,
            is_dir: true, size: 0, si_timestamps: default_ts(),
            fn_timestamps: None, file_attributes: 0, usn_change_count: 0,
        }];
        let mut data_map = HashMap::new();
        for (i, (node, data)) in files.into_iter().enumerate() {
            nodes.push(node);
            data_map.insert(i + 1, data); // idx 0 is root, files start at 1
        }
        (FileTree::from_nodes(nodes), MockFileReader(data_map))
    }

    // --- HEUR-MG-001 ---

    #[test]
    fn mg_001_jpg_with_pe_header() {
        let (tree, reader) = build_tree_and_reader(vec![
            (make_file("photo.jpg", 100, 5000), b"MZ\x90\x00\x03\x00\x00\x00rest".to_vec()),
        ]);
        let mut index = AnomalyIndex::new();
        run_tier2(&tree, &[1], &reader, &mut index);
        assert!(index.for_node(1).iter().any(|a| a.rule_id == "HEUR-MG-001"));
    }

    #[test]
    fn mg_001_no_flag_matching_extension() {
        let (tree, reader) = build_tree_and_reader(vec![
            (make_file("photo.jpg", 100, 5000), b"\xFF\xD8\xFF\xE0real jpeg".to_vec()),
        ]);
        let mut index = AnomalyIndex::new();
        run_tier2(&tree, &[1], &reader, &mut index);
        assert!(!index.for_node(1).iter().any(|a| a.rule_id == "HEUR-MG-001"));
    }

    // --- HEUR-MG-002 ---

    #[test]
    fn mg_002_exe_disguised_as_pdf() {
        let (tree, reader) = build_tree_and_reader(vec![
            (make_file("invoice.pdf", 100, 5000), b"MZ\x90\x00pe data".to_vec()),
        ]);
        let mut index = AnomalyIndex::new();
        run_tier2(&tree, &[1], &reader, &mut index);
        assert!(index.for_node(1).iter().any(|a| a.rule_id == "HEUR-MG-002"));
    }

    #[test]
    fn mg_002_no_flag_real_pdf() {
        let (tree, reader) = build_tree_and_reader(vec![
            (make_file("invoice.pdf", 100, 5000), b"%PDF-1.4 real pdf".to_vec()),
        ]);
        let mut index = AnomalyIndex::new();
        run_tier2(&tree, &[1], &reader, &mut index);
        assert!(!index.for_node(1).iter().any(|a| a.rule_id == "HEUR-MG-002"));
    }

    // --- HEUR-EN-001 ---

    #[test]
    fn en_001_high_entropy_txt() {
        // Generate high-entropy data (all 256 byte values equally distributed)
        let mut data = Vec::with_capacity(4096);
        for _ in 0..16 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let (tree, reader) = build_tree_and_reader(vec![
            (make_file("secret.txt", 100, 4096), data),
        ]);
        let mut index = AnomalyIndex::new();
        run_tier2(&tree, &[1], &reader, &mut index);
        assert!(index.for_node(1).iter().any(|a| a.rule_id == "HEUR-EN-001"));
    }

    #[test]
    fn en_001_no_flag_normal_txt() {
        let data = b"Hello world, this is normal text content.\n".to_vec();
        let (tree, reader) = build_tree_and_reader(vec![
            (make_file("readme.txt", 100, data.len() as u64), data.clone()),
        ]);
        let mut index = AnomalyIndex::new();
        run_tier2(&tree, &[1], &reader, &mut index);
        assert!(!index.for_node(1).iter().any(|a| a.rule_id == "HEUR-EN-001"));
    }

    #[test]
    fn en_001_no_flag_high_entropy_zip() {
        // High entropy is expected for zip files
        let mut data = Vec::with_capacity(4096);
        for _ in 0..16 { for b in 0..=255u8 { data.push(b); } }
        let (tree, reader) = build_tree_and_reader(vec![
            (make_file("archive.zip", 100, 4096), data),
        ]);
        let mut index = AnomalyIndex::new();
        run_tier2(&tree, &[1], &reader, &mut index);
        assert!(!index.for_node(1).iter().any(|a| a.rule_id == "HEUR-EN-001"));
    }

    // --- HEUR-EN-002 ---

    #[test]
    fn en_002_luks_header() {
        let mut data = b"LUKS\xBA\xBE\x00\x01".to_vec();
        data.resize(512, 0);
        let (tree, reader) = build_tree_and_reader(vec![
            (make_file("container.img", 100, 1048576), data),
        ]);
        let mut index = AnomalyIndex::new();
        run_tier2(&tree, &[1], &reader, &mut index);
        assert!(index.for_node(1).iter().any(|a| a.rule_id == "HEUR-EN-002"));
    }

    #[test]
    fn en_002_512_aligned_high_entropy_no_header() {
        // Random-like data, 512-byte aligned, no recognized header
        let mut data = Vec::with_capacity(4096);
        for _ in 0..16 { for b in 0..=255u8 { data.push(b); } }
        let (tree, reader) = build_tree_and_reader(vec![
            (make_file("suspicious.dat", 100, 1048576), data),  // 1MB, 512-aligned
        ]);
        let mut index = AnomalyIndex::new();
        run_tier2(&tree, &[1], &reader, &mut index);
        assert!(index.for_node(1).iter().any(|a| a.rule_id == "HEUR-EN-002"));
    }

    // --- Shannon entropy ---

    #[test]
    fn entropy_empty_is_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn entropy_uniform_is_zero() {
        assert!(shannon_entropy(&[42; 1000]) < 0.01);
    }

    #[test]
    fn entropy_random_is_high() {
        let mut data = Vec::new();
        for _ in 0..16 { for b in 0..=255u8 { data.push(b); } }
        assert!(shannon_entropy(&data) > 7.9);
    }

    // --- Tier 2 gate ---

    #[test]
    fn tier2_skipped_when_reader_unavailable() {
        let nodes = vec![FileNode {
            name: ".".to_string(), mft_entry: 5, parent_entry: 5,
            is_dir: true, size: 0, si_timestamps: default_ts(),
            fn_timestamps: None, file_attributes: 0, usn_change_count: 0,
        }];
        let tree = FileTree::from_nodes(nodes);
        let reader = super::super::file_reader::NoFileReader;
        let mut index = AnomalyIndex::new();
        run_tier2(&tree, &[0], &reader, &mut index);
        assert_eq!(index.flagged_count(), 0);
    }
}
```

- [ ] **Step 2: Update heuristics/mod.rs**

```rust
pub mod anomaly;
pub mod entry_checks;
pub mod tree_checks;
pub mod file_reader;
pub mod magic_table;
pub mod content_checks;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p rt-signatures --features heuristics`
Expected: All previous + 13 content_checks tests pass

- [ ] **Step 4: Commit**

```bash
git add crates/rt-signatures/src/heuristics/
git commit -m "feat(heuristics): add Tier 2 content checks — magic bytes, entropy, crypto detection"
```

---

## Task 10: Heuristics public API — `run_tier1()`

Wire entry checks + tree checks together behind the public `run_tier1()` function.

**Files:**
- Modify: `crates/rt-signatures/src/heuristics/mod.rs`

- [ ] **Step 1: Write `run_tier1()` with integration test**

Update `crates/rt-signatures/src/heuristics/mod.rs`:

```rust
pub mod anomaly;
pub mod entry_checks;
pub mod tree_checks;
pub mod usn_analysis;
pub mod file_reader;
pub mod magic_table;
pub mod content_checks;

pub use anomaly::{Anomaly, AnomalyCategory, AnomalyIndex, HeuristicsConfig};
pub use entry_checks::check_entry;
pub use tree_checks::check_tree;
pub use usn_analysis::check_usn_stream;
pub use content_checks::run_tier2;
pub use file_reader::{FileReader, FsFileReader, NoFileReader};

use rt_mft_tree::tree::FileTree;

/// Run all Tier 1 checks (entry-level + tree-level).
///
/// USN stream analysis is not included here — call `check_usn_stream()`
/// separately when USN records are available, then merge with `index.merge()`.
pub fn run_tier1(tree: &FileTree, config: &HeuristicsConfig) -> AnomalyIndex {
    // Tree-level checks
    let mut index = tree_checks::check_tree(tree);

    // Entry-level checks for every node
    for idx in 0..tree.allocated_entries {
        let node = tree.node(idx);
        if node.is_dir {
            continue;
        }
        let anomalies = entry_checks::check_entry(node, config);
        for anomaly in anomalies {
            index.add(idx, anomaly);
        }
    }

    index
}

#[cfg(test)]
mod tests {
    use super::*;
    use rt_mft_tree::node::{FileNode, NtfsTimestamps};
    use rt_mft_tree::tree::FileTree;
    use chrono::{TimeZone, Utc};

    fn ts(y: i32, m: u32, d: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
    }

    fn default_ts() -> NtfsTimestamps {
        NtfsTimestamps { modified: ts(2024,1,1), accessed: ts(2024,1,1), created: ts(2024,1,1), entry_modified: ts(2024,1,1) }
    }

    fn dir(name: &str, entry: u64, parent: u64) -> FileNode {
        FileNode { name: name.to_string(), mft_entry: entry, parent_entry: parent, is_dir: true, size: 0, si_timestamps: default_ts(), fn_timestamps: None, file_attributes: 0, usn_change_count: 0 }
    }

    fn file(name: &str, entry: u64, parent: u64, size: u64) -> FileNode {
        FileNode { name: name.to_string(), mft_entry: entry, parent_entry: parent, is_dir: false, size, si_timestamps: default_ts(), fn_timestamps: None, file_attributes: 0, usn_change_count: 0 }
    }

    #[test]
    fn run_tier1_combines_entry_and_tree_checks() {
        let nodes = vec![
            dir(".", 5, 5),
            dir("Temp", 10, 5),
            // Timestomped exe in temp → triggers HEUR-TS-001 + HEUR-LOC-001
            FileNode {
                name: "payload.exe".to_string(),
                mft_entry: 100, parent_entry: 10, is_dir: false, size: 5000,
                si_timestamps: NtfsTimestamps {
                    created: ts(2024, 6, 1),
                    modified: ts(2024, 1, 1),
                    accessed: ts(2024, 1, 1),
                    entry_modified: ts(2024, 1, 1),
                },
                fn_timestamps: None,
                file_attributes: 0, usn_change_count: 0,
            },
            // Normal file
            file("readme.txt", 200, 5, 1024),
        ];
        let tree = FileTree::from_nodes(nodes);
        let config = HeuristicsConfig::default();
        let index = run_tier1(&tree, &config);

        // payload.exe should have both entry-level and tree-level findings
        let payload_idx = *tree.entry_to_idx(100).unwrap();
        let anomalies = index.for_node(payload_idx);
        let rule_ids: Vec<&str> = anomalies.iter().map(|a| a.rule_id).collect();
        assert!(rule_ids.contains(&"HEUR-TS-001"), "expected timestomping flag");
        assert!(rule_ids.contains(&"HEUR-LOC-001"), "expected suspicious location flag");

        // readme.txt should be clean
        let readme_idx = *tree.entry_to_idx(200).unwrap();
        assert!(index.for_node(readme_idx).is_empty());
    }

    #[test]
    fn run_tier1_clean_tree() {
        let nodes = vec![
            dir(".", 5, 5),
            dir("Users", 10, 5),
            file("document.docx", 100, 10, 52_000),
        ];
        let tree = FileTree::from_nodes(nodes);
        let config = HeuristicsConfig::default();
        let index = run_tier1(&tree, &config);
        assert_eq!(index.flagged_count(), 0);
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p rt-signatures --features heuristics`
Expected: All previous + 2 integration tests pass

- [ ] **Step 3: Commit**

```bash
git add crates/rt-signatures/src/heuristics/mod.rs
git commit -m "feat(heuristics): wire run_tier1() combining entry and tree checks"
```

---

## Task 11: Integrate heuristics into rt-navigator

Wire anomaly detection into the TUI — severity markers, flagged filter (`f`), detail panel (`d`).

**Files:**
- Modify: `crates/rt-navigator/Cargo.toml`
- Modify: `crates/rt-navigator/src/app.rs`
- Modify: `crates/rt-navigator/src/ui.rs`
- Modify: `crates/rt-navigator/src/main.rs`

- [ ] **Step 1: Add rt-signatures dependency to rt-navigator**

In `crates/rt-navigator/Cargo.toml`, add:
```toml
rt-signatures = { workspace = true, features = ["heuristics"] }
```

And add `rt-signatures` to workspace deps in root `Cargo.toml` if not already present (it is — `rt-signatures = { path = "crates/rt-signatures" }`).

- [ ] **Step 2: Write failing tests for App anomaly integration**

In `crates/rt-navigator/src/app.rs`, add to the `App` struct:

```rust
use rt_signatures::heuristics::{AnomalyIndex, FileReader, NoFileReader};

pub struct App {
    pub tree: FileTree,
    pub anomaly_index: AnomalyIndex,
    pub file_reader: Box<dyn FileReader>,
    pub current_dir: usize,
    pub selected: usize,
    pub entries: Vec<usize>,
    path_stack: Vec<(usize, usize)>,
    pub sort_mode: SortMode,
    pub search_query: String,
    pub searching: bool,
    /// Whether to show only flagged entries.
    pub flagged_filter: bool,
}
```

Update `App::new()` to accept `AnomalyIndex` and `Box<dyn FileReader>`:

```rust
pub fn new(tree: FileTree, anomaly_index: AnomalyIndex, file_reader: Box<dyn FileReader>) -> anyhow::Result<Self> { ... }
```

Add keybindings in `handle_normal_key()`:
- `KeyCode::Char('f')` → toggle `flagged_filter`, call `refresh_entries()`
- `KeyCode::Char('d')` → (placeholder for detail panel — sets a `show_detail: bool` field)

Add to `refresh_entries()`: when `flagged_filter` is true and search is empty, filter entries to only those with anomalies.

Tests:

```rust
#[test]
fn f_key_toggles_flagged_filter() {
    let mut app = make_app();
    assert!(!app.flagged_filter);
    app.handle_key(key(KeyCode::Char('f')));
    assert!(app.flagged_filter);
    app.handle_key(key(KeyCode::Char('f')));
    assert!(!app.flagged_filter);
}

#[test]
fn flagged_filter_shows_only_flagged_entries() {
    // Build a tree with one flagged file and one clean file
    // Add an anomaly to the flagged file's index
    // Toggle flagged filter → only flagged file appears
    // ... (exact test code depends on App::new signature)
}
```

- [ ] **Step 3: Update existing tests**

All existing `App::new(tree)` calls in tests must be updated to `App::new(tree, AnomalyIndex::new(), Box::new(NoFileReader))`. This is mechanical.

- [ ] **Step 4: Update ui.rs for severity markers**

In the file list rendering, prepend severity marker to the name column:

```rust
let marker = match app.anomaly_index.max_severity(idx) {
    Some(Severity::Critical | Severity::High) => Span::styled("!! ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
    Some(Severity::Medium) => Span::styled("!  ", Style::default().fg(Color::Yellow)),
    Some(Severity::Low | Severity::Informational) => Span::styled("·  ", Style::default().fg(Color::DarkGray)),
    None => Span::raw("   "),
};
```

Add flagged count to footer: `format!("{} flagged", app.anomaly_index.flagged_count())`

- [ ] **Step 5: Update main.rs to wire heuristics**

After building the tree and enriching with USN:

```rust
use rt_signatures::heuristics::{self, HeuristicsConfig, FsFileReader, NoFileReader};

// After tree construction:
let config = HeuristicsConfig::default();
let mut anomaly_index = heuristics::run_tier1(&tree, &config);

// USN analysis (if USN records were parsed during enrichment).
if !usn_records.is_empty() {
    let usn_index = heuristics::check_usn_stream(&usn_records, Some(&tree));
    anomaly_index.merge(usn_index);
}

eprintln!("  {} anomalies detected.", anomaly_index.flagged_count());

let file_reader: Box<dyn heuristics::FileReader> = if sources.is_volume_root() {
    Box::new(FsFileReader::new(sources.root_path().to_path_buf(), &tree))
} else {
    Box::new(NoFileReader)
};

let app = App::new(tree, anomaly_index, file_reader)?;
```

- [ ] **Step 6: Run all tests**

Run: `cargo test -p rt-navigator`
Run: `cargo clippy -p rt-navigator -- -W clippy::pedantic`
Expected: All tests pass, no clippy warnings

- [ ] **Step 7: Commit**

```bash
git add crates/rt-navigator/
git commit -m "feat(rt-navigator): integrate heuristics with severity markers, flagged filter, and Tier 2 wiring"
```

---

## Task 12: USN stream analysis (HEUR-USN-*)

Implement USN journal pattern detection — secure deletion, rapid mass rename, journal gaps, and ghost files. These checks operate on parsed USN records, optionally cross-referencing the FileTree.

**Files:**
- Create: `crates/rt-signatures/src/heuristics/usn_analysis.rs`
- Modify: `crates/rt-signatures/src/heuristics/mod.rs`

- [ ] **Step 1: Write usn_analysis.rs with implementation and tests**

Create `crates/rt-signatures/src/heuristics/usn_analysis.rs`:

```rust
//! USN journal stream analysis (Tier 1, operates on parsed records).

use std::collections::HashMap;

use rt_mft_tree::tree::FileTree;
use rt_parser_usnjrnl::{UsnRecordV2, UsnReasonFlags};

use crate::matching::results::Severity;
use super::anomaly::{Anomaly, AnomalyCategory, AnomalyIndex};

/// Run all USN stream analysis checks.
///
/// `records` must be sorted by `usn` (ascending). Provide `tree` to enable
/// ghost file detection (HEUR-USN-004) and to attach findings to tree nodes.
/// Findings for entries not in the tree are attached to the root node (idx 0).
pub fn check_usn_stream(records: &[UsnRecordV2], tree: Option<&FileTree>) -> AnomalyIndex {
    let mut index = AnomalyIndex::new();
    check_usn_001(records, tree, &mut index);
    check_usn_002(records, tree, &mut index);
    check_usn_003(records, &mut index);
    if let Some(t) = tree {
        check_usn_004(records, t, &mut index);
    }
    index
}

/// Resolve a file reference number to a tree index, falling back to root (0).
fn resolve_idx(frn: u64, tree: Option<&FileTree>) -> usize {
    tree.and_then(|t| t.entry_to_idx(frn).copied()).unwrap_or(0)
}

/// HEUR-USN-001: Secure deletion pattern (SDelete / CCleaner).
///
/// Looks for rename chains where the new filename is all the same character
/// repeated (e.g. "AAAAAAAAAAAA.AAA"), followed by a delete — all within
/// a 30-second window on the same file reference number.
fn check_usn_001(records: &[UsnRecordV2], tree: Option<&FileTree>, index: &mut AnomalyIndex) {
    // Group records by file_reference_number.
    let mut by_frn: HashMap<u64, Vec<&UsnRecordV2>> = HashMap::new();
    for rec in records {
        by_frn.entry(rec.file_reference_number).or_default().push(rec);
    }

    for (frn, recs) in &by_frn {
        let mut rename_count = 0u32;
        let mut has_delete = false;
        let mut first_ts: Option<i64> = None;
        let mut last_ts: Option<i64> = None;

        for rec in recs {
            let r = rec.reason.0;
            if r & UsnReasonFlags::RENAME_NEW_NAME != 0 && is_wipe_name(&rec.file_name) {
                rename_count += 1;
                if first_ts.is_none() {
                    first_ts = Some(rec.timestamp);
                }
                last_ts = Some(rec.timestamp);
            }
            if r & UsnReasonFlags::FILE_DELETE != 0 {
                has_delete = true;
                last_ts = Some(rec.timestamp);
            }
        }

        // Need at least 2 renames + delete within 30 seconds.
        if rename_count >= 2 && has_delete {
            if let (Some(first), Some(last)) = (first_ts, last_ts) {
                let window_ticks = (last - first).unsigned_abs();
                let thirty_seconds_ticks: u64 = 30 * 10_000_000; // FILETIME is 100ns
                if window_ticks <= thirty_seconds_ticks {
                    let idx = resolve_idx(*frn, tree);
                    index.add(idx, Anomaly {
                        severity: Severity::High,
                        category: AnomalyCategory::SecureDeletion,
                        rule_id: "HEUR-USN-001",
                        description: "Secure deletion pattern: rename chain + delete".to_string(),
                        evidence: format!(
                            "frn={frn}, renames={rename_count}, window_ms={}",
                            window_ticks / 10_000
                        ),
                    });
                }
            }
        }
    }
}

/// Check if a filename looks like a wipe tool rename (all same character).
fn is_wipe_name(name: &str) -> bool {
    let base = name.replace('.', "");
    if base.is_empty() {
        return false;
    }
    let first = base.as_bytes()[0];
    base.bytes().all(|b| b == first)
}

/// HEUR-USN-002: Rapid mass rename (ransomware indicator).
///
/// Flags when >50 distinct files are renamed within a 60-second window.
fn check_usn_002(records: &[UsnRecordV2], tree: Option<&FileTree>, index: &mut AnomalyIndex) {
    // Collect rename records sorted by timestamp.
    let mut renames: Vec<&UsnRecordV2> = records
        .iter()
        .filter(|r| r.reason.0 & UsnReasonFlags::RENAME_NEW_NAME != 0)
        .collect();
    renames.sort_by_key(|r| r.timestamp);

    if renames.len() <= 50 {
        return;
    }

    let sixty_seconds_ticks: i64 = 60 * 10_000_000;
    let mut start = 0usize;

    for end in 0..renames.len() {
        // Shrink window from the left.
        while renames[end].timestamp - renames[start].timestamp > sixty_seconds_ticks {
            start += 1;
        }
        let window = &renames[start..=end];
        // Count distinct file references in window.
        let mut seen = std::collections::HashSet::new();
        for r in window {
            seen.insert(r.file_reference_number);
        }
        if seen.len() > 50 {
            // Flag all files in this window.
            for frn in &seen {
                let idx = resolve_idx(*frn, tree);
                // Avoid duplicate flagging: check if already flagged.
                if index.for_node(idx).iter().any(|a| a.rule_id == "HEUR-USN-002") {
                    continue;
                }
                index.add(idx, Anomaly {
                    severity: Severity::High,
                    category: AnomalyCategory::RansomwarePattern,
                    rule_id: "HEUR-USN-002",
                    description: "Rapid mass rename — possible ransomware activity".to_string(),
                    evidence: format!(
                        "frn={frn}, distinct_renames={}, window_start={}, window_end={}",
                        seen.len(), renames[start].timestamp, renames[end].timestamp
                    ),
                });
            }
            return; // One detection is enough.
        }
    }
}

/// HEUR-USN-003: Journal gap / truncation.
///
/// Checks for discontinuities in USN sequence numbers that are too large
/// to be explained by normal record sizes (gap > 1MB suggests clearing).
fn check_usn_003(records: &[UsnRecordV2], index: &mut AnomalyIndex) {
    const GAP_THRESHOLD: i64 = 1_048_576; // 1MB in bytes

    if records.len() < 2 {
        return;
    }

    for pair in records.windows(2) {
        let gap = pair[1].usn - pair[0].usn;
        if gap > GAP_THRESHOLD {
            // Attach to root node (journal-level finding).
            index.add(0, Anomaly {
                severity: Severity::Medium,
                category: AnomalyCategory::JournalTampering,
                rule_id: "HEUR-USN-003",
                description: "Large gap in USN journal sequence numbers".to_string(),
                evidence: format!(
                    "prev_usn={}, next_usn={}, gap_bytes={}",
                    pair[0].usn, pair[1].usn, gap
                ),
            });
        }
    }
}

/// HEUR-USN-004: Ghost file (USN references non-existent MFT entry).
fn check_usn_004(records: &[UsnRecordV2], tree: &FileTree, index: &mut AnomalyIndex) {
    let mut seen = std::collections::HashSet::new();

    for rec in records {
        let frn = rec.file_reference_number;
        if seen.contains(&frn) {
            continue;
        }
        seen.insert(frn);

        if tree.entry_to_idx(frn).is_none() {
            // File no longer in MFT — attach to parent if possible, else root.
            let parent_idx = tree
                .entry_to_idx(rec.parent_file_reference_number)
                .copied()
                .unwrap_or(0);
            index.add(parent_idx, Anomaly {
                severity: Severity::Medium,
                category: AnomalyCategory::GhostFile,
                rule_id: "HEUR-USN-004",
                description: "USN record references deleted/reallocated MFT entry".to_string(),
                evidence: format!(
                    "ghost_frn={frn}, file_name={}, parent_frn={}",
                    rec.file_name, rec.parent_file_reference_number
                ),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use rt_mft_tree::node::{FileNode, NtfsTimestamps};

    /// Windows FILETIME for 2024-06-01 00:00:00 UTC.
    const BASE_FILETIME: i64 = 133_620_192_000_000_000;
    /// One second in FILETIME ticks (100ns units).
    const ONE_SEC: i64 = 10_000_000;

    fn make_usn_record(
        file_name: &str,
        frn: u64,
        parent_frn: u64,
        reason: u32,
        timestamp: i64,
        usn: i64,
    ) -> UsnRecordV2 {
        UsnRecordV2 {
            record_length: 72 + (file_name.len() as u32 * 2),
            major_version: 2,
            minor_version: 0,
            file_reference_number: frn,
            parent_file_reference_number: parent_frn,
            usn,
            timestamp,
            reason: UsnReasonFlags(reason),
            source_info: 0,
            security_id: 0,
            file_attributes: 0,
            file_name: file_name.to_string(),
        }
    }

    fn default_ts() -> NtfsTimestamps {
        let t = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        NtfsTimestamps { modified: t, accessed: t, created: t, entry_modified: t }
    }

    fn make_tree() -> FileTree {
        let nodes = vec![
            FileNode { name: ".".to_string(), mft_entry: 5, parent_entry: 5, is_dir: true, size: 0, si_timestamps: default_ts(), fn_timestamps: None, file_attributes: 0, usn_change_count: 0 },
            FileNode { name: "Users".to_string(), mft_entry: 10, parent_entry: 5, is_dir: true, size: 0, si_timestamps: default_ts(), fn_timestamps: None, file_attributes: 0, usn_change_count: 0 },
            FileNode { name: "report.docx".to_string(), mft_entry: 100, parent_entry: 10, is_dir: false, size: 50_000, si_timestamps: default_ts(), fn_timestamps: None, file_attributes: 0, usn_change_count: 0 },
        ];
        FileTree::from_nodes(nodes)
    }

    // --- is_wipe_name ---

    #[test]
    fn wipe_name_detects_sdelete_pattern() {
        assert!(is_wipe_name("AAAAAAAAAAAA.AAA"));
        assert!(is_wipe_name("ZZZZZZZZ.ZZZ"));
        assert!(is_wipe_name("BBBB.B"));
    }

    #[test]
    fn wipe_name_rejects_normal_names() {
        assert!(!is_wipe_name("report.docx"));
        assert!(!is_wipe_name("AABBB.AAA"));
        assert!(!is_wipe_name(""));
    }

    // --- HEUR-USN-001 ---

    #[test]
    fn usn_001_triggers_on_sdelete_pattern() {
        let records = vec![
            make_usn_record("AAAAAA.AAA", 100, 10, UsnReasonFlags::RENAME_NEW_NAME, BASE_FILETIME, 1000),
            make_usn_record("BBBBBB.BBB", 100, 10, UsnReasonFlags::RENAME_NEW_NAME, BASE_FILETIME + ONE_SEC, 1100),
            make_usn_record("CCCCCC.CCC", 100, 10, UsnReasonFlags::RENAME_NEW_NAME, BASE_FILETIME + 2 * ONE_SEC, 1200),
            make_usn_record("CCCCCC.CCC", 100, 10, UsnReasonFlags::FILE_DELETE, BASE_FILETIME + 3 * ONE_SEC, 1300),
        ];
        let tree = make_tree();
        let index = check_usn_stream(&records, Some(&tree));
        let entry_idx = *tree.entry_to_idx(100).unwrap();
        assert!(index.for_node(entry_idx).iter().any(|a| a.rule_id == "HEUR-USN-001"));
    }

    #[test]
    fn usn_001_does_not_trigger_normal_rename() {
        let records = vec![
            make_usn_record("old_name.txt", 100, 10, UsnReasonFlags::RENAME_NEW_NAME, BASE_FILETIME, 1000),
            make_usn_record("new_name.txt", 100, 10, UsnReasonFlags::RENAME_NEW_NAME, BASE_FILETIME + ONE_SEC, 1100),
        ];
        let tree = make_tree();
        let index = check_usn_stream(&records, Some(&tree));
        let entry_idx = *tree.entry_to_idx(100).unwrap();
        assert!(!index.for_node(entry_idx).iter().any(|a| a.rule_id == "HEUR-USN-001"));
    }

    #[test]
    fn usn_001_does_not_trigger_without_delete() {
        let records = vec![
            make_usn_record("AAAAAA.AAA", 100, 10, UsnReasonFlags::RENAME_NEW_NAME, BASE_FILETIME, 1000),
            make_usn_record("BBBBBB.BBB", 100, 10, UsnReasonFlags::RENAME_NEW_NAME, BASE_FILETIME + ONE_SEC, 1100),
        ];
        let index = check_usn_stream(&records, None);
        assert_eq!(index.flagged_count(), 0);
    }

    // --- HEUR-USN-002 ---

    #[test]
    fn usn_002_triggers_on_mass_rename() {
        let mut records = Vec::new();
        for i in 0..55u64 {
            records.push(make_usn_record(
                &format!("file{i}.locked"),
                1000 + i,
                10,
                UsnReasonFlags::RENAME_NEW_NAME,
                BASE_FILETIME + (i as i64) * (ONE_SEC / 10), // all within ~5.5 seconds
                (i as i64) * 100,
            ));
        }
        let index = check_usn_stream(&records, None);
        assert!(index.flagged_count() > 0);
        // Check at least one node has HEUR-USN-002
        let has_002 = (0..56).any(|idx| {
            index.for_node(idx).iter().any(|a| a.rule_id == "HEUR-USN-002")
        });
        assert!(has_002);
    }

    #[test]
    fn usn_002_does_not_trigger_below_threshold() {
        let mut records = Vec::new();
        for i in 0..30u64 {
            records.push(make_usn_record(
                &format!("file{i}.locked"),
                1000 + i,
                10,
                UsnReasonFlags::RENAME_NEW_NAME,
                BASE_FILETIME + (i as i64) * ONE_SEC,
                (i as i64) * 100,
            ));
        }
        let index = check_usn_stream(&records, None);
        let has_002 = (0..31).any(|idx| {
            index.for_node(idx).iter().any(|a| a.rule_id == "HEUR-USN-002")
        });
        assert!(!has_002);
    }

    // --- HEUR-USN-003 ---

    #[test]
    fn usn_003_triggers_on_journal_gap() {
        let records = vec![
            make_usn_record("a.txt", 100, 10, UsnReasonFlags::FILE_CREATE, BASE_FILETIME, 1000),
            make_usn_record("b.txt", 200, 10, UsnReasonFlags::FILE_CREATE, BASE_FILETIME + ONE_SEC, 2_000_000), // 2MB gap
        ];
        let index = check_usn_stream(&records, None);
        assert!(index.for_node(0).iter().any(|a| a.rule_id == "HEUR-USN-003"));
    }

    #[test]
    fn usn_003_does_not_trigger_normal_sequence() {
        let records = vec![
            make_usn_record("a.txt", 100, 10, UsnReasonFlags::FILE_CREATE, BASE_FILETIME, 1000),
            make_usn_record("b.txt", 200, 10, UsnReasonFlags::FILE_CREATE, BASE_FILETIME + ONE_SEC, 1200),
        ];
        let index = check_usn_stream(&records, None);
        assert!(!index.for_node(0).iter().any(|a| a.rule_id == "HEUR-USN-003"));
    }

    // --- HEUR-USN-004 ---

    #[test]
    fn usn_004_detects_ghost_file() {
        let tree = make_tree();
        // FRN 999 does not exist in tree — ghost file.
        let records = vec![
            make_usn_record("deleted.exe", 999, 10, UsnReasonFlags::FILE_DELETE, BASE_FILETIME, 1000),
        ];
        let index = check_usn_stream(&records, Some(&tree));
        // Should be attached to parent (FRN 10 → Users dir).
        let parent_idx = *tree.entry_to_idx(10).unwrap();
        assert!(index.for_node(parent_idx).iter().any(|a| a.rule_id == "HEUR-USN-004"));
    }

    #[test]
    fn usn_004_does_not_trigger_for_existing_entries() {
        let tree = make_tree();
        let records = vec![
            make_usn_record("report.docx", 100, 10, UsnReasonFlags::FILE_CREATE, BASE_FILETIME, 1000),
        ];
        let index = check_usn_stream(&records, Some(&tree));
        let has_004 = (0..3).any(|idx| {
            index.for_node(idx).iter().any(|a| a.rule_id == "HEUR-USN-004")
        });
        assert!(!has_004);
    }

    #[test]
    fn usn_004_skipped_when_no_tree() {
        let records = vec![
            make_usn_record("deleted.exe", 999, 10, UsnReasonFlags::FILE_DELETE, BASE_FILETIME, 1000),
        ];
        let index = check_usn_stream(&records, None);
        assert_eq!(index.flagged_count(), 0);
    }
}
```

- [ ] **Step 2: Update heuristics/mod.rs**

Add the module and re-export:

```rust
pub mod anomaly;
pub mod entry_checks;
pub mod tree_checks;
pub mod usn_analysis;
pub mod file_reader;
pub mod magic_table;
pub mod content_checks;

pub use anomaly::{Anomaly, AnomalyCategory, AnomalyIndex, HeuristicsConfig};
pub use entry_checks::check_entry;
pub use tree_checks::check_tree;
pub use usn_analysis::check_usn_stream;
pub use content_checks::run_tier2;
pub use file_reader::{FileReader, FsFileReader, NoFileReader};
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p rt-signatures --features heuristics`
Expected: All previous + 11 usn_analysis tests pass

- [ ] **Step 4: Commit**

```bash
git add crates/rt-signatures/src/heuristics/usn_analysis.rs crates/rt-signatures/src/heuristics/mod.rs
git commit -m "feat(heuristics): add USN stream analysis — secure deletion, mass rename, journal gaps, ghost files"
```

---

## Task 13: Final integration test and cleanup

**Files:**
- Verify: all crates compile together
- Verify: all tests pass across workspace

- [ ] **Step 1: Run full workspace build**

Run: `cargo build -p rt-mft-tree -p rt-signatures -p rt-navigator`
Expected: Clean build, no errors

- [ ] **Step 2: Run all tests**

Run: `cargo test -p rt-mft-tree && cargo test -p rt-signatures && cargo test -p rt-navigator`
Expected: All tests pass across all three crates

- [ ] **Step 3: Run clippy across affected crates**

Run: `cargo clippy -p rt-mft-tree -p rt-signatures -p rt-navigator -- -W clippy::pedantic`
Expected: No warnings

- [ ] **Step 4: Commit any final fixes**

```bash
git commit -m "chore: final cleanup for mft-tree and heuristics integration"
```

---

## Out of Scope

The following items from the spec are intentionally deferred to a separate plan:

- **`Anomaly → FindingRow` conversion** — The `From<Anomaly>` and `From<(Anomaly, &str)>` impls for pipeline/timeline integration belong in Sub-project C (pipeline + timeline integration). This plan focuses on detection only; pipeline consumers will implement the conversion when they wire heuristics into the DuckDB ingest flow.
- **Detail panel (`d` key) rendering** — Task 11 adds the `show_detail` flag and keybinding but the actual panel rendering (showing anomaly list for selected file) is a follow-up UI task after the core detection pipeline is proven.
- **Streaming heuristics for pipeline mode** — The spec mentions streaming entry checks during ingest. This requires a different calling convention (no FileTree available) and belongs in the pipeline integration plan.
