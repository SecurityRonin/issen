use std::io::Read;
use std::path::{Path, PathBuf};

use issen_core::error::RtError;
use issen_unpack::{CollectionMetadata, ManifestEntry, OsType};
use tracing::info;

use crate::path_decoder::{decode_velociraptor_path, DecodedPath};

/// Extract a Velociraptor collection zip to the given destination directory.
///
/// # Errors
///
/// Returns `RtError` if the zip cannot be opened, an entry cannot be read, or a file
/// cannot be written to `dest`.
pub fn extract_velociraptor(
    zip_path: &Path,
    dest: &Path,
) -> Result<(Vec<ManifestEntry>, CollectionMetadata), RtError> {
    let file = std::fs::File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| RtError::InvalidData(format!("Failed to open zip: {e}")))?;

    let mut entries = Vec::new();
    let metadata = extract_metadata_from_filename(zip_path);

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| RtError::InvalidData(format!("Zip entry {i}: {e}")))?;

        if entry.is_dir() {
            continue;
        }

        let zip_entry_name = entry.name().to_string();

        if let Some(decoded) = decode_velociraptor_path(&zip_entry_name) {
            let rel_path = decoded_to_relative_path(&decoded);
            let full_path = dest.join(&rel_path);

            if let Some(parent) = full_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).map_err(RtError::Io)?;
            std::fs::write(&full_path, &buf)?;

            entries.push(ManifestEntry {
                path: rel_path,
                artifact_type: decoded.artifact_type,
            });
        }
    }

    info!(
        artifacts = entries.len(),
        "Extracted Velociraptor collection"
    );
    Ok((entries, metadata))
}

fn decoded_to_relative_path(decoded: &DecodedPath) -> PathBuf {
    let stripped = decoded
        .windows_path
        .strip_prefix("C:\\")
        .or_else(|| decoded.windows_path.strip_prefix("c:\\"))
        .unwrap_or(&decoded.windows_path);
    PathBuf::from(stripped.replace('\\', "/"))
}

fn extract_metadata_from_filename(path: &Path) -> CollectionMetadata {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default();

    let (hostname, collection_time) = if let Some(rest) = stem.strip_prefix("Collection-") {
        if let Some(idx) = rest.find("-20") {
            let host = &rest[..idx];
            let ts_str = &rest[idx + 1..];
            let ts = chrono::NaiveDateTime::parse_from_str(ts_str, "%Y-%m-%dT%H_%M_%SZ")
                .ok()
                .map(|dt| dt.and_utc());
            (Some(host.to_string()), ts)
        } else {
            (Some(rest.to_string()), None)
        }
    } else {
        (None, None)
    };

    CollectionMetadata {
        hostname,
        collection_time,
        os_type: OsType::Windows,
        tool_version: Some("Velociraptor".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use issen_core::artifacts::ArtifactType;
    use std::io::Write;

    #[test]
    fn test_decoded_to_relative_path() {
        let decoded = DecodedPath {
            windows_path: "C:\\$MFT".into(),
            accessor: crate::path_decoder::AccessorType::Ntfs,
            original_zip_path: String::new(),
            artifact_type: Some(ArtifactType::Mft),
        };
        assert_eq!(decoded_to_relative_path(&decoded), PathBuf::from("$MFT"));
    }

    #[test]
    fn test_decoded_to_relative_nested() {
        let decoded = DecodedPath {
            windows_path: "C:\\Windows\\System32\\config\\SYSTEM".into(),
            accessor: crate::path_decoder::AccessorType::Auto,
            original_zip_path: String::new(),
            artifact_type: Some(ArtifactType::Registry),
        };
        assert_eq!(
            decoded_to_relative_path(&decoded),
            PathBuf::from("Windows/System32/config/SYSTEM")
        );
    }

    #[test]
    fn test_extract_metadata_from_filename() {
        let path = Path::new("Collection-A380_localdomain-2025-08-10T03_41_20Z.zip");
        let meta = extract_metadata_from_filename(path);
        assert_eq!(meta.hostname.as_deref(), Some("A380_localdomain"));
        assert!(meta.collection_time.is_some());
        assert_eq!(meta.os_type, OsType::Windows);
    }

    #[test]
    fn test_extract_metadata_non_collection_name() {
        let path = Path::new("random_archive.zip");
        let meta = extract_metadata_from_filename(path);
        assert!(meta.hostname.is_none());
        assert!(meta.collection_time.is_none());
    }

    #[test]
    fn test_extract_velociraptor_basic() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let zip_path = dir.path().join("Collection-TEST-2025-01-01T00_00_00Z.zip");
        let dest = dir.path().join("extracted");
        std::fs::create_dir_all(&dest).expect("mkdir");

        let file = std::fs::File::create(&zip_path).expect("create zip");
        let mut zip = zip::ZipWriter::new(file);
        let opts = zip::write::SimpleFileOptions::default();

        zip.start_file("uploads/ntfs/%5C%5C.%5CC%3A/$MFT", opts)
            .expect("add");
        zip.write_all(b"fake-mft-data").expect("write");

        zip.start_file(
            "uploads/auto/C%3A/Windows/System32/winevt/Logs/Security.evtx",
            opts,
        )
        .expect("add");
        zip.write_all(b"fake-evtx").expect("write");

        zip.finish().expect("finish");

        let (entries, meta) = extract_velociraptor(&zip_path, &dest).expect("extract");

        assert_eq!(entries.len(), 2);
        assert_eq!(meta.hostname.as_deref(), Some("TEST"));

        let mft_entry = entries
            .iter()
            .find(|e| e.artifact_type == Some(ArtifactType::Mft));
        assert!(mft_entry.is_some());
        assert!(dest.join("$MFT").exists());
        assert_eq!(
            std::fs::read(dest.join("$MFT")).expect("read"),
            b"fake-mft-data"
        );

        let evtx_entry = entries
            .iter()
            .find(|e| e.artifact_type == Some(ArtifactType::EventLog));
        assert!(evtx_entry.is_some());
    }
}
