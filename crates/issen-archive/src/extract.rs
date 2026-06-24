//! Safe extraction of generic evidence archives (zip / 7z / tar.gz).
//!
//! The binding security requirement: for EVERY entry of EVERY format the
//! written path MUST stay within the extraction directory. Untrusted evidence
//! archives can carry path-traversal ("zip-slip") entries — `../../../etc/x`,
//! absolute `/etc/x`, or `C:\Windows\x` — and decompression bombs that expand
//! far beyond their on-disk size. This module refuses traversal entries
//! (fail-loud, skip + record the offending name) and bounds total uncompressed
//! bytes so a malicious archive cannot escape the dir or exhaust memory.

use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use issen_core::error::RtError;

/// Floor for the per-archive uncompressed-size cap: any archive may expand to at
/// least this (4 GiB) regardless of its compressed size, so small triage
/// collections are never falsely flagged.
pub const MAX_TOTAL_UNCOMPRESSED: u64 = 4 * 1024 * 1024 * 1024;

/// Maximum tolerated expansion ratio (uncompressed / compressed). A decompression
/// bomb is a *ratio* attack — a tiny archive that explodes to gigabytes
/// (ratios of 1000×–1,000,000×). Legitimate evidence sits far below this: text/log
/// triage zips ~5–20×, and a forensic disk image (E01/raw) barely compresses
/// (~1–2×). Capping the ratio lets a multi-gigabyte disk image through while a
/// bomb still trips almost immediately.
pub const MAX_EXPANSION_RATIO: u64 = 100;

/// The uncompressed-size cap for an archive of `compressed` bytes:
/// `max(floor, ratio × compressed)`. The floor keeps small archives unrestricted;
/// the ratio term scales the allowance to genuinely large inputs (disk images)
/// without ever admitting a high-ratio bomb.
#[must_use]
pub fn cap_for_archive_size(compressed: u64) -> u64 {
    MAX_TOTAL_UNCOMPRESSED.max(compressed.saturating_mul(MAX_EXPANSION_RATIO))
}

/// The bomb cap for a concrete archive file, from its on-disk (compressed) size.
/// An unreadable size falls back to the floor.
fn bomb_cap(archive_path: &Path) -> u64 {
    let compressed = std::fs::metadata(archive_path).map_or(0, |m| m.len());
    cap_for_archive_size(compressed)
}

/// Read chunk size while streaming an entry to disk (also the bomb-check
/// granularity, so the running total is checked before each chunk lands).
const COPY_CHUNK: usize = 64 * 1024;

/// Outcome of extracting one archive: how many entries were written and the
/// names of any traversal entries that were REFUSED (never written).
#[derive(Debug, Default)]
pub struct ExtractReport {
    pub written: usize,
    pub refused: Vec<String>,
}

/// Resolve `dest.join(rel)` and confirm it stays inside `dest`.
///
/// Returns the safe absolute path, or `None` if the entry would escape via a
/// `..` component or an absolute path. Pure lexical check (no symlink follow):
/// any `ParentDir` / `RootDir` / `Prefix` (e.g. `C:\`) component is rejected, so
/// the joined path can never resolve outside `dest`. `CurDir` (`.`) and normal
/// components are allowed.
pub fn safe_join(dest: &Path, rel: &Path) -> Option<PathBuf> {
    let mut out = dest.to_path_buf();
    let mut pushed_any = false;
    for comp in rel.components() {
        match comp {
            Component::Normal(part) => {
                out.push(part);
                pushed_any = true;
            }
            Component::CurDir => {}
            // `..`, an absolute root `/`, or a Windows prefix `C:\` would let the
            // path escape — refuse the whole entry.
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if pushed_any {
        Some(out)
    } else {
        None
    }
}

/// Stream `reader` into `path`, creating parents, charging bytes against the
/// running total, and erroring (no OOM) if the cap is exceeded.
fn write_capped(
    reader: &mut dyn Read,
    path: &Path,
    total: &mut u64,
    cap: u64,
) -> Result<(), RtError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut out = std::fs::File::create(path)?;
    let mut buf = vec![0u8; COPY_CHUNK];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        *total = total.saturating_add(n as u64);
        if *total > cap {
            return Err(bomb_error(cap));
        }
        out.write_all(&buf[..n])?;
    }
    Ok(())
}

fn bomb_error(cap: u64) -> RtError {
    RtError::InvalidData(format!(
        "archive exceeds the {cap}-byte uncompressed size limit (possible \
         decompression bomb); refusing to continue"
    ))
}

/// Safe-extract a zip archive into `dest` (cap via [`cap_for_archive_size`]).
pub fn extract_zip(archive_path: &Path, dest: &Path) -> Result<ExtractReport, RtError> {
    extract_zip_capped(archive_path, dest, bomb_cap(archive_path))
}

/// Safe-extract a zip archive into `dest`, bounding total uncompressed bytes by
/// `cap`. The cap is a parameter so the bomb test can trigger the bound without
/// minting a multi-GiB archive.
pub fn extract_zip_capped(
    archive_path: &Path,
    dest: &Path,
    cap: u64,
) -> Result<ExtractReport, RtError> {
    let file = std::fs::File::open(archive_path)?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| RtError::InvalidData(format!("failed to open zip: {e}")))?;

    let mut report = ExtractReport::default();
    let mut total: u64 = 0;

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| RtError::InvalidData(format!("zip entry {i}: {e}")))?;

        // Refuse symlink entries outright (structural defense, matching extract_tar):
        // a link target can point outside dest, and forensic extraction reconstructs
        // no links. Do not rely on the zip crate materializing symlinks as inert
        // files — make containment a property of this code, not of the dependency.
        if entry.is_symlink() {
            report.refused.push(entry.name().to_string());
            continue;
        }

        // The zip crate's enclosed_name() returns None for any entry whose name
        // would escape via `..` or an absolute / drive-rooted path. REFUSE it.
        let Some(rel) = entry.enclosed_name() else {
            report.refused.push(entry.name().to_string());
            continue;
        };

        if entry.is_dir() {
            if let Some(path) = safe_join(dest, &rel) {
                std::fs::create_dir_all(&path)?;
            }
            continue;
        }

        // Defense in depth: enclosed_name already guarantees containment, but we
        // re-validate against dest so a future change can't silently regress.
        let Some(path) = safe_join(dest, &rel) else {
            report.refused.push(entry.name().to_string());
            continue;
        };

        write_capped(&mut entry, &path, &mut total, cap)?;
        report.written += 1;
    }

    Ok(report)
}

/// Safe-extract a gzip-compressed tar (`.tar.gz`) into `dest`
/// (cap via [`cap_for_archive_size`]).
pub fn extract_tar_gz(archive_path: &Path, dest: &Path) -> Result<ExtractReport, RtError> {
    extract_tar_gz_capped(archive_path, dest, bomb_cap(archive_path))
}

/// Safe-extract a gzip-compressed tar into `dest`, bounding uncompressed bytes.
pub fn extract_tar_gz_capped(
    archive_path: &Path,
    dest: &Path,
    cap: u64,
) -> Result<ExtractReport, RtError> {
    let file = std::fs::File::open(archive_path)?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz);
    // Never follow symlink/hardlink entries or apply unpack()'s own path logic;
    // we resolve and validate every path ourselves.

    let mut report = ExtractReport::default();
    let mut total: u64 = 0;

    let entries = archive
        .entries()
        .map_err(|e| RtError::InvalidData(format!("failed to read tar: {e}")))?;

    for entry in entries {
        let mut entry = entry.map_err(|e| RtError::InvalidData(format!("tar entry: {e}")))?;

        let raw = entry
            .path()
            .map_or_else(|_| PathBuf::from("<non-utf8>"), |p| p.to_path_buf());
        let name = raw.to_string_lossy().to_string();

        let entry_type = entry.header().entry_type();

        // Reject symlinks/hardlinks outright: a link target can point outside the
        // dir, and we don't reconstruct links for forensic extraction anyway.
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            report.refused.push(name);
            continue;
        }

        let Some(path) = safe_join(dest, &raw) else {
            report.refused.push(name);
            continue;
        };

        if entry_type.is_dir() {
            std::fs::create_dir_all(&path)?;
            continue;
        }

        write_capped(&mut entry, &path, &mut total, cap)?;
        report.written += 1;
    }

    Ok(report)
}

/// Safe-extract a 7z archive into `dest` (cap via [`cap_for_archive_size`]).
pub fn extract_7z(archive_path: &Path, dest: &Path) -> Result<ExtractReport, RtError> {
    extract_7z_capped(archive_path, dest, bomb_cap(archive_path))
}

/// Safe-extract a 7z archive into `dest`, bounding uncompressed bytes.
pub fn extract_7z_capped(
    archive_path: &Path,
    dest: &Path,
    cap: u64,
) -> Result<ExtractReport, RtError> {
    let dest = dest.to_path_buf();
    let mut report = ExtractReport::default();
    let mut total: u64 = 0;

    // sevenz-rust hands us each entry's name + a reader; we resolve and validate
    // the path against dest ourselves (its `dest` arg is just dest.join(name)),
    // so a `..`/absolute entry is refused and never written.
    sevenz_rust::decompress_file_with_extract_fn(
        archive_path,
        &dest,
        |entry, reader, _suggested| {
            let name = entry.name().to_string();
            let rel = PathBuf::from(&name);

            if entry.is_directory() {
                if let Some(path) = safe_join(&dest, &rel) {
                    let _ = std::fs::create_dir_all(&path);
                }
                return Ok(true);
            }

            let Some(path) = safe_join(&dest, &rel) else {
                report.refused.push(name);
                return Ok(true); // skip the entry, keep going
            };

            write_capped(reader, &path, &mut total, cap)
                // Funnel our error through 7z's Error so the cap message
                // survives the callback boundary (re-extracted below).
                .map_err(|e| sevenz_rust::Error::Other(e.to_string().into()))?;
            report.written += 1;
            Ok(true)
        },
    )
    .map_err(|e| match e {
        // Surface a triggered bomb-cap as our own InvalidData, not a generic
        // 7z error, so the bound is named.
        sevenz_rust::Error::Other(msg) if msg.contains("decompression bomb") => {
            RtError::InvalidData(msg.to_string())
        }
        other => RtError::InvalidData(format!("failed to extract 7z: {other}")),
    })?;

    Ok(report)
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn safe_join_normal() {
        let d = Path::new("/x/y");
        assert_eq!(
            safe_join(d, Path::new("a/b.txt")),
            Some(PathBuf::from("/x/y/a/b.txt"))
        );
    }

    #[test]
    fn safe_join_curdir_is_skipped() {
        let d = Path::new("/x/y");
        assert_eq!(
            safe_join(d, Path::new("./a/./b")),
            Some(PathBuf::from("/x/y/a/b"))
        );
    }

    #[test]
    fn safe_join_parent_rejected() {
        assert!(safe_join(Path::new("/x"), Path::new("../e")).is_none());
        assert!(safe_join(Path::new("/x"), Path::new("a/../../e")).is_none());
    }

    #[test]
    fn safe_join_absolute_rejected() {
        assert!(safe_join(Path::new("/x"), Path::new("/etc/passwd")).is_none());
    }

    #[test]
    fn safe_join_empty_is_none() {
        assert!(safe_join(Path::new("/x"), Path::new("")).is_none());
        assert!(safe_join(Path::new("/x"), Path::new(".")).is_none());
    }
}
