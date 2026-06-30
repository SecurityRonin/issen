use std::path::Path;

use issen_core::error::RtError;
use issen_unpack::Confidence;

/// Probe a file to check if it's a Velociraptor collection zip.
///
/// Checks for:
/// 1. Valid zip archive
/// 2. Entries starting with `uploads/`
/// 3. URL-encoded path separators (`%5C` or `%3A`)
///
/// # Errors
///
/// Returns `RtError` if an unexpected I/O error occurs. Returns `Ok(Confidence::None)` for
/// files that are not accessible or not a valid zip archive.
pub fn probe_velociraptor(path: &Path) -> Result<Confidence, RtError> {
    let Ok(file) = std::fs::File::open(path) else {
        return Ok(Confidence::None);
    };

    let Ok(mut archive) = zip_core::ZipArchive::new(file) else {
        return Ok(Confidence::None);
    };

    let mut has_uploads = false;
    let mut has_encoded_paths = false;

    let limit = archive.len().min(200);
    for i in 0..limit {
        if let Ok(entry) = archive.by_index(i) {
            let name = entry.name().to_string();
            if name.starts_with("uploads/") {
                has_uploads = true;
                if name.contains("%5C")
                    || name.contains("%5c")
                    || name.contains("%3A")
                    || name.contains("%3a")
                {
                    has_encoded_paths = true;
                    break;
                }
            }
        }
    }

    if has_uploads && has_encoded_paths {
        Ok(Confidence::High)
    } else if has_uploads {
        Ok(Confidence::Medium)
    } else {
        Ok(Confidence::None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_probe_nonexistent_file() {
        let result = probe_velociraptor(Path::new("/nonexistent/file.zip"));
        assert_eq!(result.expect("should not error"), Confidence::None);
    }

    #[test]
    fn test_probe_non_zip_file() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("not_a_zip.txt");
        std::fs::write(&path, b"this is not a zip file").expect("write");
        assert_eq!(probe_velociraptor(&path).expect("probe"), Confidence::None);
    }

    #[test]
    fn test_probe_empty_zip() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("empty.zip");
        let file = std::fs::File::create(&path).expect("create");
        zip::ZipWriter::new(file).finish().expect("zip finish");
        assert_eq!(probe_velociraptor(&path).expect("probe"), Confidence::None);
    }

    #[test]
    fn test_probe_zip_with_uploads_and_encoded() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("velo.zip");
        let file = std::fs::File::create(&path).expect("create");
        let mut zip = zip::ZipWriter::new(file);
        let opts = zip::write::SimpleFileOptions::default();
        zip.start_file("uploads/ntfs/%5C%5C.%5CC%3A/$MFT", opts)
            .expect("entry");
        zip.write_all(b"fake mft data").expect("write");
        zip.finish().expect("finish");
        assert_eq!(probe_velociraptor(&path).expect("probe"), Confidence::High);
    }

    #[test]
    fn test_probe_zip_with_uploads_no_encoding() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("maybe_velo.zip");
        let file = std::fs::File::create(&path).expect("create");
        let mut zip = zip::ZipWriter::new(file);
        let opts = zip::write::SimpleFileOptions::default();
        zip.start_file("uploads/plain/file.txt", opts)
            .expect("entry");
        zip.write_all(b"data").expect("write");
        zip.finish().expect("finish");
        assert_eq!(
            probe_velociraptor(&path).expect("probe"),
            Confidence::Medium
        );
    }
}
