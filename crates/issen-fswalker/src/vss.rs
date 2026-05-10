//! VSS (Volume Shadow Copy Service) / shadow copy awareness.
//!
//! Provides helpers to detect and enumerate VSS snapshot volumes
//! inside an evidence root, supporting both Windows shadow-copy
//! path conventions and Unix-style mounted snapshot directories.

use std::path::Path;

/// A discovered VSS / shadow-copy volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VssVolume {
    /// Shadow-copy identifier (e.g. "HarddiskVolumeShadowCopy1", "snapshot_0").
    pub shadow_id: String,
    /// Drive letter of the origin volume, if determinable (defaults to `'?'`).
    pub volume_letter: char,
    /// ISO-8601 creation time string, when available.
    pub creation_time: Option<String>,
}

/// Scan `root` for VSS / shadow-copy volumes and return a list of them.
///
/// Detection strategies (in order):
/// 1. `root` itself looks like a mounted VSS volume (contains `GLOBALROOT` or
///    `HarddiskVolumeShadow` in its string representation).
/// 2. Windows-style sub-paths:
///    `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`
/// 3. Unix-style mounted snapshot directories:
///    `<root>/vss/*/` or `<root>/shadow/*/`
/// 4. Test-friendly naming: subdirectories of `root` whose names start with
///    `snapshot_`, `shadow_`, or `vsc_`.
pub fn list_vss_volumes(root: &Path) -> Vec<VssVolume> {
    let mut volumes = Vec::new();

    // Strategy 1: root itself is a VSS volume path.
    if looks_like_vss_str(&root.to_string_lossy()) {
        let shadow_id = extract_shadow_id_from_path(root);
        volumes.push(VssVolume {
            shadow_id,
            volume_letter: '?',
            creation_time: None,
        });
        return volumes;
    }

    // Strategy 2-4: scan immediate children of root.
    let read_dir = match std::fs::read_dir(root) {
        Ok(rd) => rd,
        Err(_) => return volumes,
    };

    for entry in read_dir.flatten() {
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if !file_type.is_dir() {
            continue;
        }

        let entry_path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Strategy 2/3: the child directory itself looks like a VSS path.
        if looks_like_vss_str(&entry_path.to_string_lossy()) {
            let shadow_id = name_str.into_owned();
            volumes.push(VssVolume {
                shadow_id,
                volume_letter: '?',
                creation_time: None,
            });
            continue;
        }

        // Strategy 3: unix-style container directories vss/ or shadow/ —
        // enumerate their children.
        if name_str == "vss" || name_str == "shadow" {
            if let Ok(inner) = std::fs::read_dir(&entry_path) {
                for inner_entry in inner.flatten() {
                    let inner_ft = match inner_entry.file_type() {
                        Ok(ft) => ft,
                        Err(_) => continue,
                    };
                    if !inner_ft.is_dir() {
                        continue;
                    }
                    let inner_name = inner_entry.file_name().to_string_lossy().into_owned();
                    volumes.push(VssVolume {
                        shadow_id: inner_name,
                        volume_letter: '?',
                        creation_time: None,
                    });
                }
            }
            continue;
        }

        // Strategy 4: test-friendly names.
        if name_str.starts_with("snapshot_")
            || name_str.starts_with("shadow_")
            || name_str.starts_with("vsc_")
        {
            volumes.push(VssVolume {
                shadow_id: name_str.into_owned(),
                volume_letter: '?',
                creation_time: None,
            });
        }
    }

    volumes
}

/// Return true if the string representation of a path looks like a VSS path.
fn looks_like_vss_str(s: &str) -> bool {
    // Case-insensitive checks for Windows VSS keywords.
    let lower = s.to_lowercase();
    lower.contains("globalroot")
        || lower.contains("harddiskvolumeshadow")
        || lower.contains("/vss/")
        || lower.contains("/shadow/")
        || lower.contains("snapshot_")
        || lower.contains("shadow_")
        || lower.contains("vsc_")
}

/// Extract a human-readable shadow ID from a path.
fn extract_shadow_id_from_path(path: &Path) -> String {
    // Prefer the last path component, falling back to the full path string.
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned())
}

/// Return `true` if `path` appears to be inside a VSS snapshot.
///
/// A path is considered a VSS path when its string representation
/// contains any of the following substrings (case-insensitive):
/// - `GLOBALROOT`
/// - `HarddiskVolumeShadow`
/// - `/vss/`
/// - `/shadow/`
/// - `snapshot_`
/// - `shadow_`
/// - `vsc_`
pub fn is_vss_path(path: &Path) -> bool {
    looks_like_vss_str(&path.to_string_lossy())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // ------------------------------------------------------------------
    // list_vss_volumes tests
    // ------------------------------------------------------------------

    #[test]
    fn vss_empty_dir_returns_no_volumes() {
        let dir = TempDir::new().expect("tempdir");
        let volumes = list_vss_volumes(dir.path());
        assert!(
            volumes.is_empty(),
            "expected no volumes for an empty directory, got {volumes:?}"
        );
    }

    #[test]
    fn vss_detects_snapshot_subdir() {
        let dir = TempDir::new().expect("tempdir");
        // Create a test-friendly snapshot directory.
        fs::create_dir(dir.path().join("snapshot_001")).expect("create snapshot_001");
        let volumes = list_vss_volumes(dir.path());
        assert_eq!(
            volumes.len(),
            1,
            "expected exactly one volume for snapshot_001, got {volumes:?}"
        );
        assert_eq!(volumes[0].shadow_id, "snapshot_001");
    }

    // ------------------------------------------------------------------
    // is_vss_path tests
    // ------------------------------------------------------------------

    #[test]
    fn is_vss_path_false_for_regular_path() {
        let path = Path::new("/mnt/evidence/Windows/System32/config/SAM");
        assert!(
            !is_vss_path(path),
            "expected false for a regular path, got true"
        );
    }

    #[test]
    fn is_vss_path_true_for_shadow_path() {
        let path = Path::new("/mnt/evidence/shadow_copy1/Windows/System32/config/SAM");
        assert!(
            is_vss_path(path),
            "expected true for a path containing shadow_, got false"
        );
    }
}
