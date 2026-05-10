//! Filesystem-based artifact provider.
//!
//! Checks file existence against a mounted evidence filesystem root using
//! glob patterns. Windows-style paths (drive letters, backslashes) are
//! normalized before building the glob expression.

use std::path::{Path, PathBuf};

use super::{ArtifactProvider, FileEntry, ProviderCapability, ProviderError};

/// A provider that resolves file-existence queries against a local directory
/// tree (typically a mounted forensic disk image).
pub struct FilesystemProvider {
    root: PathBuf,
}

impl FilesystemProvider {
    /// Create a new filesystem provider rooted at the given path.
    #[must_use]
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }

    /// Normalize a Windows-style path for use under the evidence root.
    ///
    /// 1. Strip a leading drive letter (e.g. `C:` or `D:`).
    /// 2. Replace backslashes with forward slashes.
    /// 3. Strip leading `/` so joining with root works correctly.
    fn normalize_pattern(&self, pattern: &str) -> String {
        let mut p = pattern.to_string();

        // Strip leading drive letter (e.g. "C:" or "D:")
        if p.len() >= 2 && p.as_bytes()[1] == b':' && p.as_bytes()[0].is_ascii_alphabetic() {
            p = p[2..].to_string();
        }

        // Replace backslashes with forward slashes
        p = p.replace('\\', "/");

        // Strip leading slash so Path::join works correctly
        p = p.trim_start_matches('/').to_string();

        // Build the full path under root
        let full = self.root.join(&p);
        full.to_string_lossy().to_string()
    }
}

impl ArtifactProvider for FilesystemProvider {
    fn capabilities(&self) -> Vec<ProviderCapability> {
        vec![ProviderCapability::FilePresence]
    }

    fn file_exists(&self, pattern: &str) -> Result<Vec<FileEntry>, ProviderError> {
        let normalized = self.normalize_pattern(pattern);

        let paths = glob::glob(&normalized).map_err(|e| {
            ProviderError::Internal(format!("invalid glob pattern '{normalized}': {e}"))
        })?;

        let mut entries = Vec::new();
        for entry in paths {
            let path =
                entry.map_err(|e| ProviderError::Internal(format!("glob iteration error: {e}")))?;

            // Only include files, not directories
            if path.is_file() {
                let size = path.metadata().ok().map(|m| m.len());
                entries.push(FileEntry {
                    path: path.to_string_lossy().to_string(),
                    size,
                    created: None,
                    modified: None,
                });
            }
        }

        Ok(entries)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_filesystem_provider_finds_files() {
        let tmp = TempDir::new().expect("failed to create tempdir");
        let app_dir = tmp.path().join("TestApp");
        std::fs::create_dir_all(&app_dir).expect("failed to create test dir");
        std::fs::write(app_dir.join("test.exe"), b"PE_HEADER").expect("failed to write test file");

        let provider = FilesystemProvider::new(tmp.path());
        let results = provider
            .file_exists("TestApp/*")
            .expect("file_exists should succeed");

        assert_eq!(results.len(), 1);
        assert!(results[0].path.contains("test.exe"));
        assert!(results[0].size.expect("size should be present") > 0);
    }

    #[test]
    fn test_filesystem_provider_no_match() {
        let tmp = TempDir::new().expect("failed to create tempdir");

        let provider = FilesystemProvider::new(tmp.path());
        let results = provider
            .file_exists("NonExistent/*")
            .expect("file_exists should succeed");

        assert!(results.is_empty());
    }

    #[test]
    fn test_filesystem_provider_normalizes_windows_paths() {
        let tmp = TempDir::new().expect("failed to create tempdir");
        let anydesk_dir = tmp.path().join("Program Files").join("AnyDesk");
        std::fs::create_dir_all(&anydesk_dir).expect("failed to create AnyDesk dir");
        std::fs::write(anydesk_dir.join("AnyDesk.exe"), b"MZ_STUB")
            .expect("failed to write AnyDesk.exe");

        let provider = FilesystemProvider::new(tmp.path());
        let results = provider
            .file_exists(r"C:\Program Files\AnyDesk\*")
            .expect("file_exists should succeed");

        assert_eq!(results.len(), 1);
        assert!(results[0].path.contains("AnyDesk.exe"));
    }

    #[test]
    fn test_capabilities() {
        let provider = FilesystemProvider::new(Path::new("/tmp"));
        let caps = provider.capabilities();

        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0], ProviderCapability::FilePresence);
    }
}
