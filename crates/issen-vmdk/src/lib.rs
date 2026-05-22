//! VMware VMDK disk image reader for the Issen forensic pipeline.
//!
//! Wraps the [`vmdk`] crate to provide a [`DataSource`] implementation for
//! monolithic sparse VMDK images (VMware Workstation / Fusion).

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;

use issen_core::error::RtError;
use issen_core::plugin::traits::DataSource;

/// Errors specific to VMDK image operations.
#[derive(Debug, thiserror::Error)]
pub enum VmdkError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("VMDK parse error: {0}")]
    Vmdk(String),
}

impl From<vmdk::VmdkError> for VmdkError {
    fn from(e: vmdk::VmdkError) -> Self {
        match e {
            vmdk::VmdkError::Io(io) => Self::Io(io),
            other => Self::Vmdk(other.to_string()),
        }
    }
}

impl From<VmdkError> for RtError {
    fn from(e: VmdkError) -> Self {
        match e {
            VmdkError::Io(io) => Self::Io(io),
            VmdkError::Vmdk(msg) => Self::Parse { offset: 0, message: format!("vmdk: {msg}") },
        }
    }
}

/// A [`DataSource`] backed by a VMware VMDK disk image.
pub struct VmdkDataSource {
    reader: Mutex<vmdk::VmdkReader>,
    size: u64,
}

impl std::fmt::Debug for VmdkDataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmdkDataSource").field("size", &self.size).finish()
    }
}

impl VmdkDataSource {
    /// Open a VMDK disk image (monolithic sparse).
    pub fn open(path: &Path) -> Result<Self, VmdkError> {
        let reader = vmdk::VmdkReader::open(path)?;
        let size = reader.virtual_disk_size();
        Ok(Self { reader: Mutex::new(reader), size })
    }
}

impl DataSource for VmdkDataSource {
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
    use std::io::Write;

    fn sparse_vmdk(sector_data: &[u8]) -> Vec<u8> {
        vmdk::testutil::test_sparse_vmdk(sector_data)
    }

    fn write_tmp(data: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(data).unwrap();
        f
    }

    #[test]
    fn open_nonexistent_returns_err() {
        assert!(VmdkDataSource::open(Path::new("/tmp/nope.vmdk")).is_err());
    }

    #[test]
    fn len_matches_virtual_disk_size() {
        let vmdk = sparse_vmdk(&vec![0u8; 512]);
        let f = write_tmp(&vmdk);
        let src = VmdkDataSource::open(f.path()).expect("open");
        assert_eq!(src.len(), vmdk::testutil::GRAIN_SIZE_BYTES as u64);
    }

    #[test]
    fn read_at_returns_correct_bytes() {
        let mut data = vec![0u8; 512];
        data[10] = 0xCA;
        data[11] = 0xFE;
        let vmdk = sparse_vmdk(&data);
        let f = write_tmp(&vmdk);
        let src = VmdkDataSource::open(f.path()).expect("open");
        let mut buf = [0u8; 2];
        src.read_at(10, &mut buf).expect("read_at");
        assert_eq!(buf, [0xCA, 0xFE]);
    }

    #[test]
    fn vmdk_data_source_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<VmdkDataSource>();
    }

    #[test]
    fn vmdk_error_converts_to_rt_error() {
        let e = VmdkError::Vmdk("bad magic".into());
        assert!(matches!(RtError::from(e), RtError::Parse { .. }));
    }
}
