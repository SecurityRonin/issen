//! Raw (dd) disk image reader for the Issen forensic pipeline.
//!
//! Wraps the [`dd`] crate to provide a [`DataSource`] implementation,
//! enabling random-access reads over flat raw disk images (`.dd`, `.img`,
//! `.raw`, `.bin`).

use std::io::{Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;
use std::io::Read;

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
    reader: Mutex<dd::DdReader>,
    size: u64,
}

impl std::fmt::Debug for DdDataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DdDataSource")
            .field("size", &self.size)
            .finish()
    }
}

impl DdDataSource {
    /// Open a raw disk image file.
    pub fn open(path: &Path) -> Result<Self, DdError> {
        let reader = dd::DdReader::open(path)
            .map_err(|dd::DdError::Io(io)| DdError::Io(io))?;
        let size = reader.virtual_disk_size();
        Ok(Self { reader: Mutex::new(reader), size })
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
}
