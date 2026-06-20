//! AFF4 disk image reader for the Issen forensic pipeline.
//!
//! Wraps [`aff4::Aff4Reader`] and exposes the virtual disk as a [`DataSource`]
//! for downstream forensic parsers.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;

use issen_core::error::RtError;
use issen_core::plugin::traits::DataSource;

/// Errors specific to AFF4 image operations.
#[derive(Debug, thiserror::Error)]
pub enum Aff4Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("AFF4 error: {0}")]
    Aff4(String),
}

impl From<aff4::Aff4Error> for Aff4Error {
    fn from(e: aff4::Aff4Error) -> Self {
        match e {
            aff4::Aff4Error::Io(io) => Self::Io(io),
            other => Self::Aff4(other.to_string()),
        }
    }
}

impl From<Aff4Error> for RtError {
    fn from(e: Aff4Error) -> Self {
        match e {
            Aff4Error::Io(io) => Self::Io(io),
            Aff4Error::Aff4(msg) => Self::Parse { offset: 0, message: format!("aff4: {msg}") },
        }
    }
}

/// A [`DataSource`] backed by an AFF4 disk image.
pub struct Aff4DataSource {
    reader: Mutex<aff4::Aff4Reader>,
    size: u64,
}

impl std::fmt::Debug for Aff4DataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aff4DataSource").field("size", &self.size).finish_non_exhaustive()
    }
}

impl Aff4DataSource {
    /// Open an AFF4 image, parsing metadata from `information.turtle`.
    pub fn open(path: &Path) -> Result<Self, Aff4Error> {
        let reader = aff4::Aff4Reader::open(path)?;
        let size = reader.virtual_disk_size();
        Ok(Self { reader: Mutex::new(reader), size })
    }
}

impl DataSource for Aff4DataSource {
    fn len(&self) -> u64 { self.size }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
        let mut guard = self.reader.lock().expect("mutex poisoned");
        guard.seek(SeekFrom::Start(offset)).map_err(RtError::Io)?;
        let mut total = 0;
        while total < buf.len() {
            match guard.read(&mut buf[total..]).map_err(RtError::Io)? {
                0 => break,
                n => total += n,
            }
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn write_tmp(data: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(data).expect("write");
        f
    }

    #[test]
    fn open_nonexistent_returns_err() {
        assert!(Aff4DataSource::open(Path::new("/tmp/nope.aff4")).is_err());
    }

    #[test]
    fn open_non_aff4_returns_err() {
        let f = write_tmp(&[0u8; 1024]);
        assert!(Aff4DataSource::open(f.path()).is_err());
    }

    #[test]
    fn len_matches_virtual_disk_size() {
        let img = aff4::testutil::test_aff4(&[0u8; 512]);
        let f = write_tmp(&img);
        let src = Aff4DataSource::open(f.path()).expect("open");
        assert_eq!(src.len(), aff4::testutil::CHUNK_SIZE as u64);
    }

    #[test]
    fn read_at_returns_correct_bytes() {
        let mut data = vec![0u8; 512];
        data[10] = 0xCA;
        data[11] = 0xFE;
        let img = aff4::testutil::test_aff4(&data);
        let f = write_tmp(&img);
        let src = Aff4DataSource::open(f.path()).expect("open");
        let mut buf = [0u8; 2];
        src.read_at(10, &mut buf).expect("read_at");
        assert_eq!(buf, [0xCA, 0xFE]);
    }

    #[test]
    fn aff4_data_source_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Aff4DataSource>();
    }

    #[test]
    fn aff4_error_converts_to_rt_error() {
        let e = Aff4Error::Aff4("bad turtle".into());
        assert!(matches!(RtError::from(e), RtError::Parse { .. }));
    }
}
