pub mod registry;
pub mod tempdir;

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use rt_core::artifacts::ArtifactType;

/// How confident a provider is that it can handle a given file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// Cannot handle this format.
    None,
    /// Structure looks plausible but not definitive.
    Low,
    /// Key structural markers found.
    Medium,
    /// Definitive signature identified.
    High,
}

/// Operating system type detected from the collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsType {
    Windows,
    Linux,
    MacOS,
    Unknown,
}

/// Metadata extracted from the collection itself.
#[derive(Debug, Clone)]
pub struct CollectionMetadata {
    pub hostname: Option<String>,
    pub collection_time: Option<DateTime<Utc>>,
    pub os_type: OsType,
    pub tool_version: Option<String>,
}

/// A single entry in the collection manifest.
#[derive(Debug, Clone)]
pub struct ManifestEntry {
    /// Path relative to extracted_root.
    pub path: PathBuf,
    /// Pre-classified artifact type, or None to let the fswalker detect.
    pub artifact_type: Option<ArtifactType>,
}

/// Result of opening a collection — where it was extracted and what's inside.
#[derive(Debug)]
pub struct CollectionManifest {
    pub format_name: String,
    pub extracted_root: PathBuf,
    pub artifacts: Vec<ManifestEntry>,
    pub metadata: CollectionMetadata,
    /// Handle to the temp directory — dropped when manifest is dropped.
    _tempdir: tempfile::TempDir,
}

impl CollectionManifest {
    /// Create a new manifest. The `TempDir` handle keeps the directory alive.
    pub fn new(
        format_name: String,
        tempdir: tempfile::TempDir,
        artifacts: Vec<ManifestEntry>,
        metadata: CollectionMetadata,
    ) -> Self {
        let extracted_root = tempdir.path().to_path_buf();
        Self {
            format_name,
            extracted_root,
            artifacts,
            metadata,
            _tempdir: tempdir,
        }
    }
}

/// Trait implemented by each collection format handler.
///
/// Providers are registered at compile time via `inventory::submit!`.
/// The registry probes all providers and picks the highest-confidence match.
pub trait CollectionProvider: Send + Sync {
    /// Human-readable name of this format (e.g., "Velociraptor", "UAC").
    fn name(&self) -> &str;

    /// Inspect the file and return confidence that this provider can handle it.
    ///
    /// Implementations MUST inspect internal structure (not file extension).
    fn probe(&self, path: &Path) -> Result<Confidence, rt_core::error::RtError>;

    /// Extract the collection to a temp directory and return a manifest.
    fn open(&self, path: &Path) -> Result<CollectionManifest, rt_core::error::RtError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidence_ordering() {
        assert!(Confidence::None < Confidence::Low);
        assert!(Confidence::Low < Confidence::Medium);
        assert!(Confidence::Medium < Confidence::High);
    }

    #[test]
    fn test_confidence_max_selects_highest() {
        let levels = vec![Confidence::Low, Confidence::High, Confidence::Medium];
        assert_eq!(levels.into_iter().max(), Some(Confidence::High));
    }

    #[test]
    fn test_manifest_entry_with_type() {
        let entry = ManifestEntry {
            path: PathBuf::from("$MFT"),
            artifact_type: Some(ArtifactType::Mft),
        };
        assert_eq!(entry.artifact_type, Some(ArtifactType::Mft));
    }

    #[test]
    fn test_manifest_entry_without_type() {
        let entry = ManifestEntry {
            path: PathBuf::from("unknown.dat"),
            artifact_type: None,
        };
        assert!(entry.artifact_type.is_none());
    }

    #[test]
    fn test_collection_metadata_defaults() {
        let meta = CollectionMetadata {
            hostname: None,
            collection_time: None,
            os_type: OsType::Unknown,
            tool_version: None,
        };
        assert_eq!(meta.os_type, OsType::Unknown);
        assert!(meta.hostname.is_none());
    }

    #[test]
    fn test_collection_manifest_holds_tempdir() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let path = tempdir.path().to_path_buf();
        let manifest = CollectionManifest::new(
            "test".into(),
            tempdir,
            vec![],
            CollectionMetadata {
                hostname: None,
                collection_time: None,
                os_type: OsType::Unknown,
                tool_version: None,
            },
        );
        // Temp directory should still exist while manifest is alive
        assert!(path.exists());
        assert_eq!(manifest.extracted_root, path);
        drop(manifest);
        // After drop, temp directory is cleaned up
        assert!(!path.exists());
    }
}
