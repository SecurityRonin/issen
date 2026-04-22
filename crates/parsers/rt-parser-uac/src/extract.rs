use std::io::Read;
use std::path::{Path, PathBuf};

use rt_core::error::RtError;
use rt_unpack::{CollectionMetadata, ManifestEntry, OsType};
use tracing::info;

/// Extract a UAC tar.gz to the destination directory.
///
/// Preserves the UAC directory structure. Returns manifest entries
/// and metadata extracted from uac.log.
///
/// # Errors
///
/// Returns `RtError` if archive reading or file extraction fails.
pub fn extract_uac(
    tar_gz_path: &Path,
    dest: &Path,
) -> Result<(Vec<ManifestEntry>, CollectionMetadata), RtError> {
    let file = std::fs::File::open(tar_gz_path)?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz);

    let mut entries = Vec::new();
    let mut uac_log_content = String::new();
    let mut root_prefix: Option<String> = None;

    for entry in archive.entries()? {
        let mut entry = entry?;
        let entry_path = entry.path()?.to_string_lossy().to_string();

        // Detect a root prefix directory that wraps the collection contents
        // (e.g., "uac-vbox-linux-20260324193807/"). Only strip directories
        // that look like UAC output names — never strip real artifact dirs
        // like "bodyfile/" or "live_response/".
        if root_prefix.is_none() {
            if let Some(idx) = entry_path.find('/') {
                let candidate = &entry_path[..idx];
                if candidate.starts_with("uac-") {
                    root_prefix = Some(entry_path[..=idx].to_string());
                }
            }
        }

        // Strip root prefix for relative paths
        let rel_path = if let Some(ref prefix) = root_prefix {
            entry_path.strip_prefix(prefix).unwrap_or(&entry_path)
        } else {
            &entry_path
        };

        if rel_path.is_empty() {
            continue;
        }

        let full_path = dest.join(rel_path);

        if entry.header().entry_type().is_dir() {
            std::fs::create_dir_all(&full_path)?;
            continue;
        }

        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).map_err(RtError::Io)?;
        std::fs::write(&full_path, &buf)?;

        if rel_path == "uac.log" {
            uac_log_content = String::from_utf8_lossy(&buf).to_string();
        }

        entries.push(ManifestEntry {
            path: PathBuf::from(rel_path),
            artifact_type: None, // UAC parsers handle classification
        });
    }

    let metadata = parse_uac_metadata(&uac_log_content, tar_gz_path);

    info!(
        files = entries.len(),
        hostname = ?metadata.hostname,
        "Extracted UAC collection"
    );

    Ok((entries, metadata))
}

/// Parse UAC metadata from the uac.log content and the archive filename.
fn parse_uac_metadata(uac_log: &str, archive_path: &Path) -> CollectionMetadata {
    let hostname = extract_hostname_from_filename(archive_path);

    let collection_time = uac_log.lines().next().and_then(|line| {
        let ts_str = line.trim_start_matches('[').split(']').next()?;
        chrono::NaiveDateTime::parse_from_str(ts_str, "%Y-%m-%d %H:%M:%S")
            .ok()
            .map(|dt| dt.and_utc())
    });

    let os_type = if uac_log.contains("Linux") || uac_log.contains("linux") {
        OsType::Linux
    } else if uac_log.contains("Darwin") || uac_log.contains("macOS") {
        OsType::MacOS
    } else {
        OsType::Unknown
    };

    CollectionMetadata {
        hostname,
        collection_time,
        os_type,
        tool_version: Some("UAC".into()),
    }
}

/// Extract hostname from UAC filename pattern: `uac-<hostname>-<timestamp>.tar.gz`
fn extract_hostname_from_filename(path: &Path) -> Option<String> {
    let stem = path.file_stem()?.to_str()?;
    let stem = stem.strip_suffix(".tar").unwrap_or(stem);

    if let Some(rest) = stem.strip_prefix("uac-") {
        if let Some(idx) = rest.rfind('-') {
            let candidate = &rest[idx + 1..];
            if candidate.len() == 14 && candidate.chars().all(|c| c.is_ascii_digit()) {
                return Some(rest[..idx].to_string());
            }
        }
        Some(rest.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_hostname_from_filename() {
        assert_eq!(
            extract_hostname_from_filename(Path::new("uac-vbox-linux-20260324193807.tar.gz")),
            Some("vbox-linux".into())
        );
    }

    #[test]
    fn test_extract_hostname_non_uac() {
        assert_eq!(
            extract_hostname_from_filename(Path::new("random-archive.tar.gz")),
            None
        );
    }

    #[test]
    fn test_parse_uac_metadata_linux() {
        let log = "[2026-03-24 19:38:07] UAC 2.9.0 started on Linux";
        let meta = parse_uac_metadata(log, Path::new("uac-host-20260324193807.tar.gz"));
        assert_eq!(meta.hostname.as_deref(), Some("host"));
        assert!(meta.collection_time.is_some());
        assert_eq!(meta.os_type, OsType::Linux);
    }

    #[test]
    fn test_parse_uac_metadata_empty_log() {
        let meta = parse_uac_metadata("", Path::new("archive.tar.gz"));
        assert!(meta.hostname.is_none());
        assert!(meta.collection_time.is_none());
    }

    #[test]
    fn test_extract_uac_synthetic() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let tar_gz_path = dir.path().join("uac-testhost-20260101000000.tar.gz");
        let dest = dir.path().join("extracted");
        std::fs::create_dir_all(&dest).expect("mkdir");

        let file = std::fs::File::create(&tar_gz_path).expect("create");
        let gz = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        let mut tar_builder = tar::Builder::new(gz);

        let log_data = b"[2026-01-01 00:00:00] UAC 2.9.0 started on Linux";
        let mut header = tar::Header::new_gnu();
        header.set_size(log_data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder
            .append_data(
                &mut header,
                "uac-testhost-20260101000000/uac.log",
                &log_data[..],
            )
            .expect("log");

        let bf_data = b"0|/bin/ls|1234|100755|0|0|100|1711111111|1711111112|1711111113|0";
        let mut header = tar::Header::new_gnu();
        header.set_size(bf_data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder
            .append_data(
                &mut header,
                "uac-testhost-20260101000000/bodyfile/bodyfile.txt",
                &bf_data[..],
            )
            .expect("bf");

        let gz = tar_builder.into_inner().expect("tar");
        gz.finish().expect("gz");

        let (entries, meta) = extract_uac(&tar_gz_path, &dest).expect("extract");

        assert_eq!(entries.len(), 2);
        assert_eq!(meta.hostname.as_deref(), Some("testhost"));
        assert_eq!(meta.os_type, OsType::Linux);
        assert!(dest.join("uac.log").exists());
        assert!(dest.join("bodyfile/bodyfile.txt").exists());
    }

    /// Tar.gz without a root `uac-*` prefix — entries sit at top level.
    /// This matches real-world UAC output where the archive contains
    /// `uac.log`, `bodyfile/bodyfile.txt`, etc. directly.
    #[test]
    fn test_extract_uac_no_root_prefix() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let tar_gz_path = dir.path().join("uac-noprefix-20260101000000.tar.gz");
        let dest = dir.path().join("extracted");
        std::fs::create_dir_all(&dest).expect("mkdir");

        let file = std::fs::File::create(&tar_gz_path).expect("create");
        let gz = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        let mut tar_builder = tar::Builder::new(gz);

        // uac.log at top level (no prefix dir)
        let log_data = b"[2026-01-01 00:00:00] UAC 2.9.0 started on Linux";
        let mut header = tar::Header::new_gnu();
        header.set_size(log_data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder
            .append_data(&mut header, "uac.log", &log_data[..])
            .expect("log");

        // bodyfile/bodyfile.txt — "bodyfile/" is a real dir, not a prefix
        let bf_data = b"0|/bin/ls|1234|100755|0|0|100|1711111111|1711111112|1711111113|0";
        let mut header = tar::Header::new_gnu();
        header.set_size(bf_data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder
            .append_data(&mut header, "bodyfile/bodyfile.txt", &bf_data[..])
            .expect("bf");

        // live_response/network/ss.txt
        let net_data = b"Netid State Local Address:Port";
        let mut header = tar::Header::new_gnu();
        header.set_size(net_data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder
            .append_data(&mut header, "live_response/network/ss.txt", &net_data[..])
            .expect("net");

        let gz = tar_builder.into_inner().expect("tar");
        gz.finish().expect("gz");

        let (entries, meta) = extract_uac(&tar_gz_path, &dest).expect("extract");

        assert_eq!(entries.len(), 3);
        assert_eq!(meta.hostname.as_deref(), Some("noprefix"));
        assert_eq!(meta.os_type, OsType::Linux);

        // Critical: directory structure must be preserved
        assert!(
            dest.join("uac.log").exists(),
            "uac.log should exist at root"
        );
        assert!(
            dest.join("bodyfile/bodyfile.txt").exists(),
            "bodyfile/bodyfile.txt should keep its directory"
        );
        assert!(
            dest.join("live_response/network/ss.txt").exists(),
            "nested dirs should be preserved"
        );
    }
}
