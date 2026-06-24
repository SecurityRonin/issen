#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::format_push_string,
    clippy::manual_let_else,
    clippy::map_unwrap_or,
    clippy::needless_borrow,
    clippy::redundant_closure_for_method_calls,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::uninlined_format_args,
    clippy::elidable_lifetime_names,
    clippy::match_same_arms,
    clippy::return_self_not_must_use,
    clippy::single_match_else,
    clippy::unnested_or_patterns,
    clippy::field_reassign_with_default,
    clippy::inefficient_to_string,
    clippy::manual_strip,
    clippy::redundant_else,
    clippy::trim_split_whitespace,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::unused_self,
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::missing_fields_in_debug,
    clippy::result_unit_err,
    clippy::unreadable_literal,
    clippy::manual_contains,
    clippy::unnecessary_literal_bound
)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
pub mod registry;
pub mod tempdir;

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use issen_core::artifacts::ArtifactType;

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
    /// Upstream collections kept alive for this manifest's lifetime. Populated
    /// when `open_collection` cracks a disk image out of an archive: callers walk
    /// the cracked filesystem (this manifest), but the archive's extraction dir —
    /// which held the raw image — must outlive parsing. Holding the whole upstream
    /// manifest keeps its `TempDir` alive without reaching into private fields.
    /// Empty for a directly opened collection.
    keepalive: Vec<CollectionManifest>,
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
            keepalive: Vec::new(),
        }
    }

    /// Keep another opened collection's extraction dir(s) alive for as long as
    /// this manifest lives. Used when `open_collection` cracks a disk image out
    /// of an archive: the cracked filesystem (`self`) is what callers walk, but
    /// the archive's extraction dir (which held the raw image) must not be
    /// removed until parsing finishes.
    pub fn keep_alive(&mut self, other: CollectionManifest) {
        self.keepalive.push(other);
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
    fn probe(&self, path: &Path) -> Result<Confidence, issen_core::error::RtError>;

    /// Extract the collection to a temp directory and return a manifest.
    fn open(&self, path: &Path) -> Result<CollectionManifest, issen_core::error::RtError>;
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
    fn test_confidence_none_is_lowest() {
        assert_eq!(
            vec![Confidence::None, Confidence::Low].into_iter().min(),
            Some(Confidence::None)
        );
    }

    #[test]
    fn test_confidence_medium_between_low_and_high() {
        assert!(Confidence::Medium > Confidence::Low);
        assert!(Confidence::Medium < Confidence::High);
    }

    #[test]
    fn test_confidence_equality() {
        assert_eq!(Confidence::None, Confidence::None);
        assert_eq!(Confidence::Low, Confidence::Low);
        assert_eq!(Confidence::Medium, Confidence::Medium);
        assert_eq!(Confidence::High, Confidence::High);
    }

    #[test]
    fn test_confidence_debug() {
        assert_eq!(format!("{:?}", Confidence::None), "None");
        assert_eq!(format!("{:?}", Confidence::Low), "Low");
        assert_eq!(format!("{:?}", Confidence::Medium), "Medium");
        assert_eq!(format!("{:?}", Confidence::High), "High");
    }

    #[test]
    #[allow(clippy::clone_on_copy)] // deliberately exercises the Clone impl on a Copy type
    fn test_confidence_clone_copy() {
        let c = Confidence::High;
        let d = c; // Copy
        let e = c.clone(); // Clone
        assert_eq!(d, e);
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
    fn test_manifest_entry_path_field() {
        let entry = ManifestEntry {
            path: PathBuf::from("C:/Windows/System32/config/SAM"),
            artifact_type: None,
        };
        assert_eq!(entry.path, PathBuf::from("C:/Windows/System32/config/SAM"));
    }

    #[test]
    fn test_manifest_entry_debug() {
        let entry = ManifestEntry {
            path: PathBuf::from("test.dat"),
            artifact_type: None,
        };
        let dbg = format!("{:?}", entry);
        assert!(dbg.contains("test.dat"));
    }

    #[test]
    fn test_manifest_entry_clone() {
        let entry = ManifestEntry {
            path: PathBuf::from("clone.dat"),
            artifact_type: Some(ArtifactType::Mft),
        };
        let cloned = entry.clone();
        assert_eq!(cloned.path, entry.path);
        assert_eq!(cloned.artifact_type, entry.artifact_type);
    }

    #[test]
    fn test_os_type_windows() {
        let os = OsType::Windows;
        assert_eq!(os, OsType::Windows);
    }

    #[test]
    fn test_os_type_linux() {
        let os = OsType::Linux;
        assert_eq!(os, OsType::Linux);
    }

    #[test]
    fn test_os_type_macos() {
        let os = OsType::MacOS;
        assert_eq!(os, OsType::MacOS);
    }

    #[test]
    fn test_os_type_unknown() {
        let os = OsType::Unknown;
        assert_eq!(os, OsType::Unknown);
    }

    #[test]
    fn test_os_type_debug() {
        assert_eq!(format!("{:?}", OsType::Windows), "Windows");
        assert_eq!(format!("{:?}", OsType::Linux), "Linux");
        assert_eq!(format!("{:?}", OsType::MacOS), "MacOS");
        assert_eq!(format!("{:?}", OsType::Unknown), "Unknown");
    }

    #[test]
    fn test_os_type_clone() {
        let os = OsType::Linux;
        let cloned = os.clone();
        assert_eq!(os, cloned);
    }

    #[test]
    fn test_os_type_ne() {
        assert_ne!(OsType::Windows, OsType::Linux);
        assert_ne!(OsType::MacOS, OsType::Unknown);
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
    fn test_collection_metadata_with_some_fields() {
        let now = chrono::Utc::now();
        let meta = CollectionMetadata {
            hostname: Some("DESKTOP-ABC123".to_string()),
            collection_time: Some(now),
            os_type: OsType::Windows,
            tool_version: Some("6.0.0".to_string()),
        };
        assert_eq!(meta.hostname.as_deref(), Some("DESKTOP-ABC123"));
        assert_eq!(meta.os_type, OsType::Windows);
        assert_eq!(meta.tool_version.as_deref(), Some("6.0.0"));
        assert!(meta.collection_time.is_some());
    }

    #[test]
    fn test_collection_metadata_linux() {
        let meta = CollectionMetadata {
            hostname: Some("ubuntu-server".to_string()),
            collection_time: None,
            os_type: OsType::Linux,
            tool_version: None,
        };
        assert_eq!(meta.os_type, OsType::Linux);
        assert_eq!(meta.hostname.as_deref(), Some("ubuntu-server"));
    }

    #[test]
    fn test_collection_metadata_macos() {
        let meta = CollectionMetadata {
            hostname: Some("macbook".to_string()),
            collection_time: None,
            os_type: OsType::MacOS,
            tool_version: Some("2.1.0".to_string()),
        };
        assert_eq!(meta.os_type, OsType::MacOS);
    }

    #[test]
    fn test_collection_metadata_debug() {
        let meta = CollectionMetadata {
            hostname: Some("host1".to_string()),
            collection_time: None,
            os_type: OsType::Windows,
            tool_version: None,
        };
        let dbg = format!("{:?}", meta);
        assert!(dbg.contains("host1"));
        assert!(dbg.contains("Windows"));
    }

    #[test]
    fn test_collection_metadata_clone() {
        let meta = CollectionMetadata {
            hostname: Some("clone-host".to_string()),
            collection_time: None,
            os_type: OsType::Linux,
            tool_version: Some("1.0".to_string()),
        };
        let cloned = meta.clone();
        assert_eq!(cloned.hostname, meta.hostname);
        assert_eq!(cloned.os_type, meta.os_type);
        assert_eq!(cloned.tool_version, meta.tool_version);
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

    #[test]
    fn test_collection_manifest_format_name() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let manifest = CollectionManifest::new(
            "Velociraptor".into(),
            tempdir,
            vec![],
            CollectionMetadata {
                hostname: None,
                collection_time: None,
                os_type: OsType::Unknown,
                tool_version: None,
            },
        );
        assert_eq!(manifest.format_name, "Velociraptor");
    }

    #[test]
    fn test_collection_manifest_artifacts_field() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let entries = vec![
            ManifestEntry {
                path: PathBuf::from("$MFT"),
                artifact_type: Some(ArtifactType::Mft),
            },
            ManifestEntry {
                path: PathBuf::from("unknown.dat"),
                artifact_type: None,
            },
        ];
        let manifest = CollectionManifest::new(
            "UAC".into(),
            tempdir,
            entries,
            CollectionMetadata {
                hostname: None,
                collection_time: None,
                os_type: OsType::Linux,
                tool_version: None,
            },
        );
        assert_eq!(manifest.artifacts.len(), 2);
        assert_eq!(manifest.artifacts[0].path, PathBuf::from("$MFT"));
        assert_eq!(manifest.artifacts[1].artifact_type, None);
    }

    #[test]
    fn test_collection_manifest_metadata_field() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let manifest = CollectionManifest::new(
            "test-format".into(),
            tempdir,
            vec![],
            CollectionMetadata {
                hostname: Some("testhost".to_string()),
                collection_time: None,
                os_type: OsType::Windows,
                tool_version: Some("3.0".to_string()),
            },
        );
        assert_eq!(manifest.metadata.hostname.as_deref(), Some("testhost"));
        assert_eq!(manifest.metadata.os_type, OsType::Windows);
        assert_eq!(manifest.metadata.tool_version.as_deref(), Some("3.0"));
    }

    #[test]
    fn test_collection_manifest_debug() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let manifest = CollectionManifest::new(
            "DebugFormat".into(),
            tempdir,
            vec![],
            CollectionMetadata {
                hostname: None,
                collection_time: None,
                os_type: OsType::Unknown,
                tool_version: None,
            },
        );
        let dbg = format!("{:?}", manifest);
        assert!(dbg.contains("DebugFormat"));
    }

    #[test]
    fn test_collection_manifest_empty_artifacts() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let manifest = CollectionManifest::new(
            "empty".into(),
            tempdir,
            vec![],
            CollectionMetadata {
                hostname: None,
                collection_time: None,
                os_type: OsType::Unknown,
                tool_version: None,
            },
        );
        assert!(manifest.artifacts.is_empty());
    }
}
