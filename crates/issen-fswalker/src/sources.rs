//! Resolve input evidence paths into attributable sources for a unified timeline.
//!
//! A unified multi-source timeline tags every event with a per-source
//! `evidence_source_id` so two hosts' otherwise-identical events stay distinct
//! and attributable. This module turns the CLI's evidence paths into that set of
//! sources: it expands a directory of disk images into one source per image and
//! derives a **collision-resistant** id, so two `CDrive.E01` files under
//! different host folders never alias onto one id and silently merge.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Disk-image first-segment extensions (mirrors the correlate pipeline). Only the
/// first segment of a split set is nominated; the disk pipeline follows the rest
/// internally, so a later segment would double-crack the set.
const CONTAINER_EXTS: &[&str] = &[
    "e01", "ex01", "001", "dd", "img", "vmdk", "vhd", "vhdx", "qcow2", "aff4", "iso",
];

/// One attributable evidence source: a path to ingest plus its stable id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceSource {
    /// The path the ingest pipeline opens (a container file or a loose-artifact dir).
    pub path: PathBuf,
    /// The collision-resistant per-source id stamped onto every event from `path`.
    pub source_id: String,
}

/// Expand and resolve input paths into attributable evidence sources.
///
/// - A directory containing recognized disk-image containers expands to one
///   source per container; a directory with none is one source (loose artifacts).
/// - A file is one source.
///
/// Each source gets a collision-resistant `source_id`.
#[must_use]
pub fn resolve_evidence_sources(paths: &[PathBuf]) -> Vec<EvidenceSource> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for path in paths {
        for p in expand_path(path) {
            let mut id = source_id_for(&p);
            // Belt-and-suspenders: guarantee uniqueness even if two inputs
            // canonicalize to the same path (the hash would otherwise collide).
            while !seen.insert(id.clone()) {
                id.push('_');
            }
            out.push(EvidenceSource {
                path: p,
                source_id: id,
            });
        }
    }
    out
}

/// Expand one input path: a directory of containers → one path per container;
/// a loose-artifact directory → itself; a file → itself.
fn expand_path(path: &Path) -> Vec<PathBuf> {
    if path.is_dir() {
        let mut imgs = Vec::new();
        collect_containers(path, &mut imgs);
        imgs.sort();
        if imgs.is_empty() {
            vec![path.to_path_buf()]
        } else {
            imgs
        }
    } else {
        vec![path.to_path_buf()]
    }
}

fn collect_containers(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return; // unreadable dir contributes nothing; never panics
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_containers(&p, out);
        } else if is_container(&p) {
            out.push(p);
        }
    }
}

fn is_container(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .is_some_and(|ext| CONTAINER_EXTS.contains(&ext.as_str()))
}

/// Collision-resistant id: sanitized file stem + 8 hex of sha256(canonical path).
/// Two files with the same stem in different directories get distinct ids; the id
/// is stable per-path across runs, so resume keys consistently.
fn source_id_for(path: &Path) -> String {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("source");
    let sanitized: String = stem
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut hasher = Sha256::new();
    hasher.update(canonical.to_string_lossy().as_bytes());
    let digest = hex::encode(hasher.finalize());
    format!("{sanitized}-{}", &digest[..8])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn same_stem_different_dirs_get_distinct_ids() {
        let tmp = tempdir().unwrap();
        let a = tmp.path().join("hostA");
        let b = tmp.path().join("hostB");
        fs::create_dir(&a).unwrap();
        fs::create_dir(&b).unwrap();
        let fa = a.join("CDrive.E01");
        let fb = b.join("CDrive.E01");
        fs::write(&fa, b"x").unwrap();
        fs::write(&fb, b"x").unwrap();

        let srcs = resolve_evidence_sources(&[fa, fb]);
        assert_eq!(srcs.len(), 2);
        assert_ne!(
            srcs[0].source_id, srcs[1].source_id,
            "same stem in different dirs must get distinct source_ids (no silent merge)"
        );
        assert!(srcs.iter().all(|s| s.source_id.starts_with("CDrive")));
    }

    #[test]
    fn directory_of_containers_expands_to_one_source_each() {
        let tmp = tempdir().unwrap();
        fs::write(tmp.path().join("img1.E01"), b"x").unwrap();
        fs::write(tmp.path().join("img2.e01"), b"x").unwrap();
        fs::write(tmp.path().join("notes.txt"), b"x").unwrap();

        let srcs = resolve_evidence_sources(&[tmp.path().to_path_buf()]);
        assert_eq!(
            srcs.len(),
            2,
            "a directory of containers expands to one source per disk image"
        );
    }

    #[test]
    fn loose_artifact_dir_is_single_source() {
        let tmp = tempdir().unwrap();
        fs::write(tmp.path().join("$J"), b"x").unwrap(); // no container extension
        let srcs = resolve_evidence_sources(&[tmp.path().to_path_buf()]);
        assert_eq!(
            srcs.len(),
            1,
            "a directory with no containers is one (loose-artifact) source"
        );
    }
}
