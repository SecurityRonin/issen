use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rt_core::error::RtError;
use rt_core::plugin::traits::DataSource;

/// File-backed DataSource for reading evidence files from disk.
///
/// Uses a Mutex<File> to satisfy Send+Sync requirements of DataSource.
/// Each read_at call seeks then reads — safe for single-threaded parser use.
pub struct FileDataSource {
    path: PathBuf,
    file: Mutex<File>,
    len: u64,
}

impl FileDataSource {
    /// Open a file as a DataSource.
    pub fn open(path: &Path) -> Result<Self, RtError> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        Ok(Self {
            path: path.to_path_buf(),
            file: Mutex::new(file),
            len,
        })
    }

    /// Get the file path this source was opened from.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl DataSource for FileDataSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
        let mut file = self
            .file
            .lock()
            .map_err(|e| RtError::InvalidData(format!("File mutex poisoned: {e}")))?;
        file.seek(SeekFrom::Start(offset))?;
        let n = file.read(buf)?;
        Ok(n)
    }
}

/// A byte-slice DataSource for testing and in-memory data.
pub struct SliceDataSource {
    data: Vec<u8>,
}

impl SliceDataSource {
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl DataSource for SliceDataSource {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
        let offset = offset as usize;
        if offset >= self.data.len() {
            return Ok(0);
        }
        let available = self.data.len() - offset;
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&self.data[offset..offset + to_read]);
        Ok(to_read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slice_data_source() {
        let source = SliceDataSource::new(vec![1, 2, 3, 4, 5]);
        assert_eq!(source.len(), 5);
        assert!(!source.is_empty());

        let mut buf = [0u8; 3];
        let n = source.read_at(0, &mut buf).expect("read");
        assert_eq!(n, 3);
        assert_eq!(buf, [1, 2, 3]);

        let n = source.read_at(3, &mut buf).expect("read");
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], &[4, 5]);

        let n = source.read_at(10, &mut buf).expect("read past end");
        assert_eq!(n, 0);
    }

    #[test]
    fn test_slice_data_source_empty() {
        let source = SliceDataSource::new(vec![]);
        assert_eq!(source.len(), 0);
        assert!(source.is_empty());
    }

    #[test]
    fn test_file_data_source() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("test.bin");
        std::fs::write(&path, b"hello world").expect("write");

        let source = FileDataSource::open(&path).expect("open");
        assert_eq!(source.len(), 11);
        assert_eq!(source.path(), path);

        let mut buf = [0u8; 5];
        let n = source.read_at(0, &mut buf).expect("read");
        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");

        let n = source.read_at(6, &mut buf).expect("read");
        assert_eq!(n, 5);
        assert_eq!(&buf, b"world");
    }

    #[test]
    fn test_file_data_source_not_found() {
        let result = FileDataSource::open(Path::new("/nonexistent/file.bin"));
        assert!(result.is_err());
    }
}
