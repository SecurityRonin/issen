use std::path::Path;

use issen_core::error::RtError;
use issen_unpack::Confidence;

/// Probe a file to check if it's a UAC collection tar.gz.
///
/// Checks for:
/// 1. Valid gzip-compressed tar archive
/// 2. Presence of `uac.log` entry
/// 3. Known UAC directory structure (bodyfile/, `live_response`/)
///
/// # Errors
///
/// Returns `RtError` if archive reading fails unexpectedly.
pub fn probe_uac(path: &Path) -> Result<Confidence, RtError> {
    let Ok(file) = std::fs::File::open(path) else {
        return Ok(Confidence::None);
    };

    let gz = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz);
    let Ok(entries) = archive.entries() else {
        return Ok(Confidence::None);
    };

    let mut has_uac_log = false;
    let mut has_uac_dirs = false;
    let mut count = 0;

    for entry in entries {
        let Ok(entry) = entry else {
            return Ok(Confidence::None);
        };

        let path_str = entry
            .path()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        if path_str.ends_with("uac.log") || path_str.contains("/uac.log") {
            has_uac_log = true;
        }
        if path_str.contains("/bodyfile/")
            || path_str.contains("/live_response/")
            || path_str.contains("/system/")
        {
            has_uac_dirs = true;
        }

        if has_uac_log && has_uac_dirs {
            break;
        }

        count += 1;
        if count > 200 {
            break;
        }
    }

    if has_uac_log {
        Ok(Confidence::High)
    } else if has_uac_dirs {
        Ok(Confidence::Medium)
    } else {
        Ok(Confidence::None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_uac_tar_gz(dir: &Path, include_uac_log: bool) -> std::path::PathBuf {
        use std::io::Write;

        let tar_gz_path = dir.join("uac-test.tar.gz");
        let file = std::fs::File::create(&tar_gz_path).expect("create");
        let gz = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        let mut tar_builder = tar::Builder::new(gz);

        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_mode(0o755);
        header.set_cksum();
        tar_builder
            .append_data(&mut header, "uac-test/bodyfile/", &[] as &[u8])
            .expect("dir");

        if include_uac_log {
            let data = b"[2026-03-24 19:38:07] UAC started";
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar_builder
                .append_data(&mut header, "uac-test/uac.log", &data[..])
                .expect("uac.log");
        }

        let bf_data = b"0|/bin/ls|1234|100755|0|0|100|1711111111|1711111112|1711111113|0";
        let mut header = tar::Header::new_gnu();
        header.set_size(bf_data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder
            .append_data(&mut header, "uac-test/bodyfile/bodyfile.txt", &bf_data[..])
            .expect("bodyfile");

        let gz = tar_builder.into_inner().expect("tar finish");
        gz.finish().expect("gz finish");

        tar_gz_path
    }

    #[test]
    fn test_probe_nonexistent_file() {
        asseissen_eq!(
            probe_uac(Path::new("/nonexistent.tar.gz")).expect("probe"),
            Confidence::None
        );
    }

    #[test]
    fn test_probe_non_gzip_file() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("not_gz.txt");
        std::fs::write(&path, b"not gzip").expect("write");
        asseissen_eq!(probe_uac(&path).expect("probe"), Confidence::None);
    }

    #[test]
    fn test_probe_uac_with_log() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = create_uac_tar_gz(dir.path(), true);
        asseissen_eq!(probe_uac(&path).expect("probe"), Confidence::High);
    }

    #[test]
    fn test_probe_uac_without_log() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = create_uac_tar_gz(dir.path(), false);
        asseissen_eq!(
            probe_uac(&path).expect("probe"),
            Confidence::Medium,
            "Has UAC dirs but no uac.log"
        );
    }
}
