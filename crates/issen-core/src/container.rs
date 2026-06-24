//! Disk-image container first-segment detection.
//!
//! A split image set (EWF `.E01/.E02…`, raw `.001/.002…`) names only its FIRST
//! segment as an ingest root; the disk pipeline follows the remaining segments
//! internally, so nominating a later segment would double-crack the set. This is
//! the single home for that "is this a first segment" rule so the ingest legs
//! (`open_collection` recursion, correlate discovery, source resolution) can't
//! drift on which extensions count.

use std::path::{Path, PathBuf};

/// Disk-image first-segment extensions. Continuations (`.E02`, `.002`, …) are
/// deliberately absent: their extension is not in this list, so they are never
/// nominated as a separate container. Memory dumps (`.mem`/`.raw`) are excluded
/// — they go through the memory leg, not the disk pipeline.
pub const FIRST_SEGMENT_IMAGE_EXTS: &[&str] = &[
    "e01", "ex01", "001", "dd", "img", "vmdk", "vhd", "vhdx", "qcow2", "aff4", "iso",
];

/// True if `path` names a disk-image container first segment.
///
/// Extension-based: this only nominates a *candidate* root. Whether the file is
/// truly a container is confirmed downstream by magic-byte probing
/// (`open_collection`'s provider registry).
#[must_use]
pub fn is_container_first_segment(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .is_some_and(|ext| FIRST_SEGMENT_IMAGE_EXTS.contains(&ext.as_str()))
}

/// Recursively collect disk-image container first-segment files under `dir`,
/// sorted for deterministic ordering. An unreadable directory contributes
/// nothing (never panics).
#[must_use]
pub fn collect_container_first_segments(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk(dir, &mut out);
    out.sort();
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return; // unreadable dir → contributes nothing, never panics
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else if is_container_first_segment(&path) {
            out.push(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_segment_extensions_are_recognized() {
        for name in [
            "img.E01",
            "img.e01",
            "img.Ex01",
            "img.001",
            "img.dd",
            "disk.vmdk",
            "disk.vhd",
            "disk.vhdx",
            "disk.qcow2",
            "disk.aff4",
            "disk.iso",
        ] {
            assert!(
                is_container_first_segment(Path::new(name)),
                "{name} should be a first segment"
            );
        }
    }

    #[test]
    fn continuations_and_non_containers_are_rejected() {
        for name in [
            "img.E02",      // EWF continuation
            "img.E15",      // EWF continuation
            "img.002",      // raw split continuation
            "notes.txt",    // acquisition sidecar
            "img.E01.txt",  // sidecar: real extension is txt
            "mem.raw",      // memory dump
            "dump.mem",     // memory dump
            "no_extension", // bare name
        ] {
            assert!(
                !is_container_first_segment(Path::new(name)),
                "{name} should NOT be a first segment"
            );
        }
    }

    #[test]
    fn collect_picks_only_first_segments_in_a_tree() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sub = dir.path().join("E01-DC01");
        std::fs::create_dir(&sub).expect("subdir");
        // A split EWF set + a sidecar, mirroring the DFIR Madness layout.
        for name in [
            "20200918_0347_CDrive.E01",
            "20200918_0347_CDrive.E01.txt",
            "20200918_0347_CDrive.E02",
        ] {
            std::fs::write(sub.join(name), b"x").expect("write");
        }
        let found = collect_container_first_segments(dir.path());
        assert_eq!(found.len(), 1, "exactly one first segment, got {found:?}");
        assert!(
            found[0].to_string_lossy().ends_with("CDrive.E01"),
            "the .E01 first segment, got {:?}",
            found[0]
        );
    }

    #[test]
    fn collect_on_unreadable_or_empty_is_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(collect_container_first_segments(dir.path()).is_empty());
        assert!(collect_container_first_segments(Path::new("/nonexistent_zzz")).is_empty());
    }
}
