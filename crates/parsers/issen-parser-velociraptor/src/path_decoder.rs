use issen_core::artifacts::ArtifactType;

/// Which Velociraptor accessor produced this entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessorType {
    /// Raw NTFS accessor: uploads/ntfs/...
    Ntfs,
    /// Auto accessor: uploads/auto/...
    Auto,
}

/// A decoded Velociraptor zip entry path.
#[derive(Debug, Clone)]
pub struct DecodedPath {
    /// The normalized Windows-style path (e.g., `C:\$MFT`).
    pub windows_path: String,
    /// Which accessor produced this entry.
    pub accessor: AccessorType,
    /// The original zip entry path (needed for extraction).
    pub original_zip_path: String,
    /// Detected artifact type if recognizable.
    pub artifact_type: Option<ArtifactType>,
}

/// Decode a Velociraptor zip entry path into a normalized form.
///
/// Velociraptor encodes paths like:
/// - NTFS: `uploads/ntfs/%5C%5C.%5CC%3A/$MFT` → `C:\$MFT`
/// - Auto: `uploads/auto/C%3A/Windows/System32/config/SYSTEM` → `C:\Windows\System32\config\SYSTEM`
///
/// Returns `None` if the path is not a Velociraptor artifact entry.
#[must_use]
pub fn decode_velociraptor_path(zip_path: &str) -> Option<DecodedPath> {
    let decoded = percent_encoding::percent_decode_str(zip_path)
        .decode_utf8_lossy()
        .to_string();

    if let Some(rest) = decoded.strip_prefix("uploads/ntfs/") {
        // NTFS accessor: \\.\C:\path -> C:\path
        let normalized = rest
            .strip_prefix("\\\\.\\C:\\")
            .or_else(|| rest.strip_prefix("\\\\.\\C:/"))
            .unwrap_or(rest);
        let windows_path = format!("C:\\{}", normalized.replace('/', "\\"));
        let artifact_type = classify_artifact(&windows_path);
        Some(DecodedPath {
            windows_path,
            accessor: AccessorType::Ntfs,
            original_zip_path: zip_path.to_string(),
            artifact_type,
        })
    } else if let Some(rest) = decoded.strip_prefix("uploads/auto/") {
        // Auto accessor: C:/path -> C:\path
        // Some entries use device-path notation \\.\C:/path (e.g., locked files
        // accessed via raw device). Strip it the same way the NTFS decoder does.
        let rest = rest
            .strip_prefix("\\\\.\\C:\\")
            .or_else(|| rest.strip_prefix("\\\\.\\C:/"))
            .unwrap_or(rest);
        let windows_path = if rest.starts_with("C:") || rest.starts_with("c:") {
            rest.replace('/', "\\")
        } else {
            format!("C:\\{}", rest.replace('/', "\\"))
        };
        let artifact_type = classify_artifact(&windows_path);
        Some(DecodedPath {
            windows_path,
            accessor: AccessorType::Auto,
            original_zip_path: zip_path.to_string(),
            artifact_type,
        })
    } else {
        None
    }
}

/// Classify a normalized Windows path into an `ArtifactType`.
///
/// The input `path` is already lowercased by the caller, so extension
/// comparisons are case-insensitive by construction.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn classify_artifact(path: &str) -> Option<ArtifactType> {
    let lower = path.to_lowercase();

    // NTFS core artifacts
    if lower.ends_with("$mft") {
        return Some(ArtifactType::Mft);
    }
    // Only match the $J data stream, not the $Max header or .idx index
    if lower.ends_with("$j") {
        return Some(ArtifactType::UsnJournal);
    }

    // Event logs
    if lower.ends_with(".evtx") {
        return Some(ArtifactType::EventLog);
    }

    // Registry hives
    if (lower.ends_with("\\system")
        || lower.ends_with("\\software")
        || lower.ends_with("\\sam")
        || lower.ends_with("\\security"))
        && lower.contains("config")
    {
        return Some(ArtifactType::Registry);
    }
    if lower.ends_with("ntuser.dat") || lower.ends_with("usrclass.dat") {
        return Some(ArtifactType::Registry);
    }

    // Amcache
    if lower.ends_with("amcache.hve") {
        return Some(ArtifactType::Amcache);
    }

    // Prefetch
    if lower.ends_with(".pf") && lower.contains("prefetch") {
        return Some(ArtifactType::Prefetch);
    }

    // LNK files
    if lower.ends_with(".lnk") {
        return Some(ArtifactType::Lnk);
    }

    // SRUM
    if lower.ends_with("srudb.dat") {
        return Some(ArtifactType::Srum);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_ntfs_mft() {
        let path = "uploads/ntfs/%5C%5C.%5CC%3A/$MFT";
        let decoded = decode_velociraptor_path(path).expect("should decode");
        asseissen_eq!(decoded.accessor, AccessorType::Ntfs);
        asseissen_eq!(decoded.windows_path, "C:\\$MFT");
        asseissen_eq!(decoded.artifact_type, Some(ArtifactType::Mft));
        asseissen_eq!(decoded.original_zip_path, path);
    }

    #[test]
    fn test_decode_ntfs_usnjrnl() {
        let path = "uploads/ntfs/%5C%5C.%5CC%3A/$Extend/$UsnJrnl%3A$J";
        let decoded = decode_velociraptor_path(path).expect("should decode");
        asseissen_eq!(decoded.accessor, AccessorType::Ntfs);
        assert!(decoded.windows_path.contains("$UsnJrnl"));
        asseissen_eq!(decoded.artifact_type, Some(ArtifactType::UsnJournal));
    }

    #[test]
    fn test_decode_auto_evtx() {
        let path = "uploads/auto/C%3A/Windows/System32/winevt/Logs/Security.evtx";
        let decoded = decode_velociraptor_path(path).expect("should decode");
        asseissen_eq!(decoded.accessor, AccessorType::Auto);
        assert!(decoded.windows_path.ends_with("Security.evtx"));
        asseissen_eq!(decoded.artifact_type, Some(ArtifactType::EventLog));
    }

    #[test]
    fn test_decode_auto_registry() {
        let path = "uploads/auto/C%3A/Windows/System32/config/SYSTEM";
        let decoded = decode_velociraptor_path(path).expect("should decode");
        asseissen_eq!(decoded.artifact_type, Some(ArtifactType::Registry));
    }

    #[test]
    fn test_decode_auto_ntuser() {
        let path = "uploads/auto/C%3A/Users/admin/NTUSER.DAT";
        let decoded = decode_velociraptor_path(path).expect("should decode");
        asseissen_eq!(decoded.artifact_type, Some(ArtifactType::Registry));
    }

    #[test]
    fn test_decode_auto_lnk() {
        let path = "uploads/auto/C%3A/Users/admin/AppData/Roaming/Microsoft/Windows/Recent/foo.lnk";
        let decoded = decode_velociraptor_path(path).expect("should decode");
        asseissen_eq!(decoded.artifact_type, Some(ArtifactType::Lnk));
    }

    #[test]
    fn test_decode_non_velociraptor_path_returns_none() {
        assert!(decode_velociraptor_path("some/random/file.txt").is_none());
        assert!(decode_velociraptor_path("").is_none());
    }

    #[test]
    fn test_decode_unknown_artifact() {
        let path = "uploads/auto/C%3A/Windows/Temp/random.tmp";
        let decoded = decode_velociraptor_path(path).expect("should decode");
        assert!(decoded.artifact_type.is_none());
    }

    /// Velociraptor sometimes puts device-path notation `\\.\C:` in auto entries
    /// (e.g., locked files accessed via raw device). The decoder must strip this
    /// prefix to produce a normal `C:\path`, otherwise the relative path starts
    /// with `/` on Unix and causes writes to the root filesystem.
    #[test]
    fn test_decode_auto_device_path_notation() {
        // Real entry from Collection-A380: uploads/auto/%5C%5C.%5CC%3A/Windows/System32/LogFiles/...
        let path =
            "uploads/auto/%5C%5C.%5CC%3A/Windows/System32/LogFiles/WMI/RtBackup/EtwRTDiagLog.etl";
        let decoded = decode_velociraptor_path(path).expect("should decode");
        asseissen_eq!(decoded.accessor, AccessorType::Auto);
        asseissen_eq!(
            decoded.windows_path,
            "C:\\Windows\\System32\\LogFiles\\WMI\\RtBackup\\EtwRTDiagLog.etl",
            "device-path \\\\.\\.\\C: prefix should be stripped, not doubled"
        );
    }

    /// Same test but for Windows.old paths behind device notation.
    #[test]
    fn test_decode_auto_device_path_windows_old() {
        let path = "uploads/auto/%5C%5C.%5CC%3A/Windows.old/WINDOWS/System32/LogFiles/WMI/RtBackup/EtwRTDiagLog.etl";
        let decoded = decode_velociraptor_path(path).expect("should decode");
        asseissen_eq!(decoded.accessor, AccessorType::Auto);
        assert!(
            decoded.windows_path.starts_with("C:\\Windows.old"),
            "should normalize to C:\\ prefix, got: {}",
            decoded.windows_path
        );
    }

    /// The $UsnJrnl:$Max stream is the metadata header (32 bytes), not the
    /// journal data. Only $UsnJrnl:$J should be classified as UsnJournal.
    #[test]
    fn test_classify_usnjrnl_max_is_not_usn_journal() {
        asseissen_eq!(
            classify_artifact("C:\\$Extend\\$UsnJrnl:$Max"),
            None,
            "$Max stream should NOT be classified as UsnJournal"
        );
    }

    /// Velociraptor creates a .idx index file alongside $J — don't classify it.
    #[test]
    fn test_classify_usnjrnl_idx_is_not_usn_journal() {
        asseissen_eq!(
            classify_artifact("C:\\$Extend\\$UsnJrnl:$J.idx"),
            None,
            ".idx index file should NOT be classified as UsnJournal"
        );
    }

    #[test]
    fn test_classify_usnjrnl_j_is_usn_journal() {
        asseissen_eq!(
            classify_artifact("C:\\$Extend\\$UsnJrnl:$J"),
            Some(ArtifactType::UsnJournal)
        );
    }

    #[test]
    fn test_classify_amcache() {
        asseissen_eq!(
            classify_artifact("C:\\Windows\\AppCompat\\Programs\\Amcache.hve"),
            Some(ArtifactType::Amcache)
        );
    }

    #[test]
    fn test_classify_srum() {
        asseissen_eq!(
            classify_artifact("C:\\Windows\\System32\\SRU\\SRUDB.dat"),
            Some(ArtifactType::Srum)
        );
    }
}
