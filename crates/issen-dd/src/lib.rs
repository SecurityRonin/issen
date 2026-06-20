//! Raw (dd) disk image reader for the Issen forensic pipeline.
//!
//! A raw/dd image is a flat byte stream with no container format, so this reads
//! it directly through [`std::fs::File`] (which is `Read + Seek`) to provide a
//! [`DataSource`] for random-access reads over `.dd`, `.img`, `.raw`, `.bin`.

use std::fs::File;
use std::io::Read;
use std::io::{Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;

use issen_core::error::RtError;
use issen_core::plugin::traits::DataSource;

/// Errors specific to raw image operations.
#[derive(Debug, thiserror::Error)]
pub enum DdError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<DdError> for RtError {
    fn from(e: DdError) -> Self {
        match e {
            DdError::Io(io) => Self::Io(io),
        }
    }
}

/// A [`DataSource`] backed by a raw (dd) disk image.
pub struct DdDataSource {
    reader: Mutex<File>,
    size: u64,
}

impl std::fmt::Debug for DdDataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DdDataSource")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl DdDataSource {
    /// Open a raw disk image file. The on-disk file length is the image size.
    pub fn open(path: &Path) -> Result<Self, DdError> {
        let reader = File::open(path).map_err(DdError::Io)?;
        let size = reader.metadata().map_err(DdError::Io)?.len();
        Ok(Self {
            reader: Mutex::new(reader),
            size,
        })
    }
}

impl DataSource for DdDataSource {
    fn len(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
        let mut guard = self.reader.lock().expect("DdDataSource mutex poisoned");
        guard.seek(SeekFrom::Start(offset)).map_err(RtError::Io)?;
        let mut total = 0;
        while total < buf.len() {
            match guard.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(e) => return Err(RtError::Io(e)),
            }
        }
        Ok(total)
    }
}

// ── CollectionProvider ────────────────────────────────────────────────

use issen_unpack::{
    CollectionManifest, CollectionMetadata, CollectionProvider, Confidence, OsType,
};

/// Format-recognition and manifest provider for raw (dd) disk images.
///
/// Raw images have no magic bytes. This provider returns [`Confidence::Low`]
/// for any readable file, making it the last-resort fallback in the registry.
#[derive(Debug, Default)]
pub struct DdProvider;

impl CollectionProvider for DdProvider {
    fn name(&self) -> &'static str {
        "DD"
    }

    fn probe(&self, path: &Path) -> Result<Confidence, RtError> {
        // Any readable file is a potential raw image — lowest confidence so
        // format-specific providers always win.
        std::fs::metadata(path).map_err(RtError::Io)?;
        Ok(Confidence::Low)
    }

    fn open(&self, path: &Path) -> Result<CollectionManifest, RtError> {
        let source = DdDataSource::open(path)?;
        let size = source.len();
        let tempdir = tempfile::tempdir().map_err(RtError::Io)?;
        Ok(CollectionManifest::new(
            self.name().to_string(),
            tempdir,
            vec![],
            CollectionMetadata {
                hostname: None,
                collection_time: None,
                os_type: OsType::Unknown,
                tool_version: Some(format!("{size} bytes")),
            },
        ))
    }
}

inventory::submit!(issen_unpack::registry::ProviderRegistration {
    create: || Box::new(DdProvider),
});

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_image(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tmpfile");
        f.write_all(bytes).expect("write");
        f
    }

    #[test]
    fn open_nonexistent_returns_err() {
        assert!(DdDataSource::open(Path::new("/tmp/nope_dd_99999.dd")).is_err());
    }

    #[test]
    fn len_matches_file_size() {
        let img = make_image(&[0u8; 512]);
        let src = DdDataSource::open(img.path()).expect("open");
        assert_eq!(src.len(), 512);
    }

    #[test]
    fn read_at_returns_correct_bytes() {
        let mut data = vec![0u8; 512];
        data[256] = 0xBE;
        data[257] = 0xEF;
        let img = make_image(&data);
        let src = DdDataSource::open(img.path()).expect("open");
        let mut buf = [0u8; 2];
        let n = src.read_at(256, &mut buf).expect("read_at");
        assert_eq!(n, 2);
        assert_eq!(buf, [0xBE, 0xEF]);
    }

    #[test]
    fn dd_data_source_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DdDataSource>();
    }

    #[test]
    fn dd_error_converts_to_rt_error() {
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let e = DdError::Io(io);
        assert!(matches!(RtError::from(e), RtError::Io(_)));
    }

    // ── DdProvider tests ──────────────────────────────────────────────

    #[test]
    fn dd_provider_name() {
        assert_eq!(DdProvider.name(), "DD");
    }

    #[test]
    fn dd_provider_probe_readable_file_returns_low() {
        let img = make_image(&[0u8; 512]);
        // RED: stub returns None — FAILS (expects Low)
        assert_eq!(
            DdProvider.probe(img.path()).expect("probe"),
            Confidence::Low
        );
    }

    #[test]
    fn dd_provider_probe_nonexistent_returns_err() {
        // RED: stub returns Ok(None) — FAILS
        assert!(DdProvider
            .probe(Path::new("/tmp/nonexistent_99999.dd"))
            .is_err());
    }

    #[test]
    fn dd_provider_open_readable_file_returns_ok() {
        let img = make_image(&[0u8; 512]);
        // RED: stub returns Err — FAILS (expects Ok)
        assert!(DdProvider.open(img.path()).is_ok());
    }

    #[test]
    fn dd_provider_open_nonexistent_returns_err() {
        assert!(DdProvider
            .open(Path::new("/tmp/nonexistent_99999.dd"))
            .is_err());
    }

    #[test]
    fn dd_provider_registered_in_inventory() {
        use issen_unpack::registry::ProviderRegistration;
        let names: Vec<String> = inventory::iter::<ProviderRegistration>
            .into_iter()
            .map(|r| (r.create)().name().to_string())
            .collect();
        assert!(
            names.contains(&"DD".to_string()),
            "DdProvider must be in inventory; got: {names:?}"
        );
    }
}
