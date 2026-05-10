use issen_core::error::RtError;

/// Create a managed temp directory for collection extraction.
///
/// The returned `TempDir` will be automatically cleaned up when dropped.
/// The caller should store it in the `CollectionManifest` to keep it alive.
pub fn create_extraction_dir() -> Result<tempfile::TempDir, RtError> {
    tempfile::Builder::new()
        .prefix("issen-unpack-")
        .tempdir()
        .map_err(RtError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_extraction_dir() {
        let dir = create_extraction_dir().expect("create dir");
        assert!(dir.path().exists());
        let path = dir.path().to_path_buf();
        drop(dir);
        assert!(!path.exists(), "tempdir should be cleaned up on drop");
    }

    #[test]
    fn test_create_extraction_dir_prefix() {
        let dir = create_extraction_dir().expect("create dir");
        let name = dir
            .path()
            .file_name()
            .and_then(|n| n.to_str())
            .expect("dir name should be valid UTF-8");
        assert!(
            name.starts_with("issen-unpack-"),
            "expected prefix 'rt-unpack-', got: {name}"
        );
    }

    #[test]
    fn test_create_extraction_dir_multiple_calls_return_distinct_paths() {
        let dir1 = create_extraction_dir().expect("create dir1");
        let dir2 = create_extraction_dir().expect("create dir2");
        assert_ne!(
            dir1.path(),
            dir2.path(),
            "each call should produce a unique temp dir"
        );
    }

    #[test]
    fn test_create_extraction_dir_is_a_directory() {
        let dir = create_extraction_dir().expect("create dir");
        assert!(
            dir.path().is_dir(),
            "extracted root should be a directory, not a file"
        );
    }
}
