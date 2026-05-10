//! Artifact source resolution — find NTFS metadata files from CLI input.
//!
//! Accepts a file path (direct `$MFT`), a folder path (volume root with
//! NTFS artifacts inside), or explicit `--mft`/`--usnj`/`--logfile`/`--mftmirr`
//! flags. Locates as many artifacts as available.

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

/// Well-known NTFS metadata filenames to look for inside a volume root.
const MFT_NAMES: &[&str] = &["$MFT", "MFT", "$Mft"];
const MFTMIRR_NAMES: &[&str] = &["$MFTMirr", "MFTMirr", "$MftMirr"];
const LOGFILE_NAMES: &[&str] = &["$LogFile", "LogFile", "$Logfile"];
const USNJRNL_NAMES: &[&str] = &[
    "$UsnJrnl:$J",
    "$UsnJrnl_$J",
    "UsnJrnl",
    "$J",
    "$Extend/$UsnJrnl:$J",
    "$Extend/$UsnJrnl_$J",
];

/// Resolved paths to NTFS metadata artifacts.
#[derive(Debug, Clone)]
pub struct ArtifactSources {
    /// Path to the `$MFT` file (required).
    pub mft: PathBuf,
    /// Path to `$MFTMirr` (optional).
    pub mft_mirror: Option<PathBuf>,
    /// Path to `$LogFile` (optional).
    pub logfile: Option<PathBuf>,
    /// Path to `$UsnJrnl:$J` (optional).
    pub usn_journal: Option<PathBuf>,
    /// Volume root directory (set when a folder is scanned, `None` for direct
    /// file paths). Used by Tier 2 content-aware heuristics.
    pub volume_root: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

impl ArtifactSources {
    /// Resolve a single CLI path — either a direct MFT file or a folder
    /// (volume root) containing NTFS metadata files.
    pub fn resolve_path(path: &Path) -> Result<Self> {
        if !path.exists() {
            bail!("Path not found: {}", path.display());
        }

        if path.is_file() {
            return Ok(Self {
                mft: path.to_path_buf(),
                mft_mirror: None,
                logfile: None,
                usn_journal: None,
                volume_root: None,
            });
        }

        if path.is_dir() {
            return Self::scan_folder(path);
        }

        bail!("Not a file or directory: {}", path.display());
    }

    /// Build sources from explicit CLI flags. MFT is required; others are
    /// optional and silently ignored if the path doesn't exist.
    pub fn from_explicit(
        mft: &Path,
        mft_mirror: Option<&Path>,
        logfile: Option<&Path>,
        usn_journal: Option<&Path>,
    ) -> Result<Self> {
        if !mft.exists() {
            bail!("MFT file not found: {}", mft.display());
        }
        Ok(Self {
            mft: mft.to_path_buf(),
            mft_mirror: mft_mirror.filter(|p| p.exists()).map(Path::to_path_buf),
            logfile: logfile.filter(|p| p.exists()).map(Path::to_path_buf),
            usn_journal: usn_journal.filter(|p| p.exists()).map(Path::to_path_buf),
            volume_root: None,
        })
    }

    /// Scan a folder for well-known NTFS metadata filenames.
    fn scan_folder(dir: &Path) -> Result<Self> {
        let Some(mft) = Self::find_first(dir, MFT_NAMES) else {
            bail!(
                "No $MFT found in {}. Looked for: {}",
                dir.display(),
                MFT_NAMES.join(", "),
            );
        };

        Ok(Self {
            mft,
            mft_mirror: Self::find_first(dir, MFTMIRR_NAMES),
            logfile: Self::find_first(dir, LOGFILE_NAMES),
            usn_journal: Self::find_first(dir, USNJRNL_NAMES),
            volume_root: Some(dir.to_path_buf()),
        })
    }

    /// Search for the first matching filename in a directory (including
    /// relative sub-paths like `$Extend/$UsnJrnl_$J`).
    fn find_first(dir: &Path, candidates: &[&str]) -> Option<PathBuf> {
        for name in candidates {
            let path = dir.join(name);
            if path.exists() {
                return Some(path);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Helper: create a file with some content.
    fn touch(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, b"test data").unwrap();
        path
    }

    // -- Direct file path tests ----------------------------------------------

    #[test]
    fn resolve_with_direct_mft_file() {
        let tmp = TempDir::new().unwrap();
        let mft_path = touch(tmp.path(), "my_mft");

        let sources = ArtifactSources::resolve_path(&mft_path).unwrap();
        assert_eq!(sources.mft, mft_path);
        assert!(sources.mft_mirror.is_none());
        assert!(sources.logfile.is_none());
        assert!(sources.usn_journal.is_none());
    }

    #[test]
    fn resolve_with_nonexistent_file_errors() {
        let result = ArtifactSources::resolve_path(Path::new("/nonexistent/path/$MFT"));
        assert!(result.is_err());
    }

    // -- Folder scanning tests -----------------------------------------------

    #[test]
    fn resolve_folder_finds_mft() {
        let tmp = TempDir::new().unwrap();
        touch(tmp.path(), "$MFT");

        let sources = ArtifactSources::resolve_path(tmp.path()).unwrap();
        assert_eq!(sources.mft.file_name().unwrap(), "$MFT");
    }

    #[test]
    fn resolve_folder_finds_all_artifacts() {
        let tmp = TempDir::new().unwrap();
        touch(tmp.path(), "$MFT");
        touch(tmp.path(), "$MFTMirr");
        touch(tmp.path(), "$LogFile");
        touch(tmp.path(), "$UsnJrnl_$J");

        let sources = ArtifactSources::resolve_path(tmp.path()).unwrap();
        assert!(sources.mft_mirror.is_some());
        assert!(sources.logfile.is_some());
        assert!(sources.usn_journal.is_some());
    }

    #[test]
    fn resolve_folder_with_extend_subdir() {
        let tmp = TempDir::new().unwrap();
        touch(tmp.path(), "$MFT");
        touch(tmp.path(), "$Extend/$UsnJrnl_$J");

        let sources = ArtifactSources::resolve_path(tmp.path()).unwrap();
        assert!(sources.usn_journal.is_some());
    }

    #[test]
    fn resolve_folder_without_mft_errors() {
        let tmp = TempDir::new().unwrap();
        // Create some random file, but no $MFT
        touch(tmp.path(), "random.txt");

        let result = ArtifactSources::resolve_path(tmp.path());
        assert!(result.is_err());
    }

    #[test]
    fn resolve_folder_case_variants() {
        let tmp = TempDir::new().unwrap();
        touch(tmp.path(), "MFT"); // alternate name

        let sources = ArtifactSources::resolve_path(tmp.path()).unwrap();
        assert_eq!(sources.mft.file_name().unwrap(), "MFT");
    }

    // -- Explicit override tests ---------------------------------------------

    #[test]
    fn override_mft_with_explicit_path() {
        let tmp = TempDir::new().unwrap();
        let custom_mft = touch(tmp.path(), "custom_mft_file");
        let custom_usnj = touch(tmp.path(), "custom_usnj");

        let sources =
            ArtifactSources::from_explicit(&custom_mft, None, None, Some(&custom_usnj)).unwrap();

        assert_eq!(sources.mft, custom_mft);
        assert_eq!(sources.usn_journal.as_ref().unwrap(), &custom_usnj);
        assert!(sources.mft_mirror.is_none());
        assert!(sources.logfile.is_none());
    }

    #[test]
    fn explicit_with_missing_mft_errors() {
        let result = ArtifactSources::from_explicit(Path::new("/nonexistent"), None, None, None);
        assert!(result.is_err());
    }

    // -- volume_root tests ---------------------------------------------------

    #[test]
    fn scan_folder_sets_volume_root() {
        let tmp = TempDir::new().unwrap();
        touch(tmp.path(), "$MFT");

        let sources = ArtifactSources::resolve_path(tmp.path()).unwrap();
        assert_eq!(
            sources.volume_root.as_deref(),
            Some(tmp.path()),
            "scan_folder should set volume_root to the scanned directory"
        );
    }

    #[test]
    fn direct_file_has_no_volume_root() {
        let tmp = TempDir::new().unwrap();
        let mft_path = touch(tmp.path(), "my_mft");

        let sources = ArtifactSources::resolve_path(&mft_path).unwrap();
        assert!(
            sources.volume_root.is_none(),
            "resolve_path with a direct file should leave volume_root as None"
        );
    }

    #[test]
    fn explicit_flags_have_no_volume_root() {
        let tmp = TempDir::new().unwrap();
        let mft = touch(tmp.path(), "mft");

        let sources = ArtifactSources::from_explicit(&mft, None, None, None).unwrap();
        assert!(
            sources.volume_root.is_none(),
            "from_explicit should leave volume_root as None"
        );
    }

    #[test]
    fn explicit_with_missing_optional_ignores() {
        let tmp = TempDir::new().unwrap();
        let mft = touch(tmp.path(), "mft");

        let sources = ArtifactSources::from_explicit(
            &mft,
            Some(Path::new("/nonexistent/mirror")),
            None,
            None,
        )
        .unwrap();

        // Missing optional should be silently ignored
        assert!(sources.mft_mirror.is_none());
    }
}
