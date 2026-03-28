use rt_core::error::RtError;

/// Create a managed temp directory for collection extraction.
///
/// The returned `TempDir` will be automatically cleaned up when dropped.
/// The caller should store it in the `CollectionManifest` to keep it alive.
pub fn create_extraction_dir() -> Result<tempfile::TempDir, RtError> {
    tempfile::Builder::new()
        .prefix("rt-unpack-")
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
}
