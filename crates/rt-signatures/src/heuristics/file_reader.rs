//! File content access abstraction for Tier 2 checks.

use std::io::Read;
use std::path::PathBuf;

use rt_mft_tree::tree::FileTree;

/// Abstract access to file content for Tier 2 heuristic checks.
pub trait FileReader {
    /// Read the first `n` bytes of the file at arena index `idx`.
    fn read_first_bytes(&self, idx: usize, n: usize) -> Option<Vec<u8>>;

    /// Whether this reader can access file content.
    fn is_available(&self) -> bool;
}

/// Reads files from a volume root directory via `std::fs`.
pub struct FsFileReader<'a> {
    volume_root: PathBuf,
    tree: &'a FileTree,
}

impl<'a> FsFileReader<'a> {
    #[must_use]
    pub fn new(volume_root: PathBuf, tree: &'a FileTree) -> Self {
        Self { volume_root, tree }
    }
}

impl FileReader for FsFileReader<'_> {
    fn read_first_bytes(&self, idx: usize, n: usize) -> Option<Vec<u8>> {
        let cached = self.tree.cached_path(idx);
        // cached_path starts with "/" — strip it for joining
        let rel = cached.strip_prefix('/').unwrap_or(cached);
        let full_path = self.volume_root.join(rel);

        let mut file = std::fs::File::open(&full_path).ok()?;
        let mut buf = vec![0u8; n];
        let bytes_read = file.read(&mut buf).ok()?;
        buf.truncate(bytes_read);
        Some(buf)
    }

    fn is_available(&self) -> bool {
        true
    }
}

/// No-op reader for standalone `$MFT` mode (no file access).
pub struct NoFileReader;

impl FileReader for NoFileReader {
    fn read_first_bytes(&self, _idx: usize, _n: usize) -> Option<Vec<u8>> {
        None
    }

    fn is_available(&self) -> bool {
        false
    }
}

/// Test mock: returns pre-loaded byte buffers by arena index.
#[cfg(test)]
pub struct MockFileReader(pub std::collections::HashMap<usize, Vec<u8>>);

#[cfg(test)]
impl FileReader for MockFileReader {
    fn read_first_bytes(&self, idx: usize, n: usize) -> Option<Vec<u8>> {
        self.0.get(&idx).map(|d| d[..n.min(d.len())].to_vec())
    }

    fn is_available(&self) -> bool {
        true
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn no_file_reader_returns_none() {
        let reader = NoFileReader;
        assert!(!reader.is_available());
        assert!(reader.read_first_bytes(0, 16).is_none());
    }

    #[test]
    fn mock_reader_returns_data() {
        let mut data = HashMap::new();
        data.insert(10, b"\x89PNG\r\n\x1a\n rest of png".to_vec());
        let reader = MockFileReader(data);
        assert!(reader.is_available());
        let bytes = reader.read_first_bytes(10, 8).unwrap();
        assert_eq!(&bytes[..4], b"\x89PNG");
    }

    #[test]
    fn mock_reader_clamps_to_data_length() {
        let mut data = HashMap::new();
        data.insert(5, vec![0xFF, 0xD8, 0xFF]);
        let reader = MockFileReader(data);
        let bytes = reader.read_first_bytes(5, 100).unwrap();
        assert_eq!(bytes.len(), 3);
    }

    #[test]
    fn mock_reader_unknown_idx_returns_none() {
        let reader = MockFileReader(HashMap::new());
        assert!(reader.read_first_bytes(99, 16).is_none());
    }
}
