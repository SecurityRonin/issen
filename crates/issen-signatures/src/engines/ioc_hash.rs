// Hash-based IOC matching (MD5, SHA1, SHA256).
//
// Supports loading hash sets from text files (one hash per line),
// CSV files (configurable column), and programmatic insertion.
// Provides fast O(1) lookup and optional NSRL known-good filtering.

use std::collections::HashSet;
use std::io::BufRead;
use std::path::Path;

use thiserror::Error;

/// Errors from hash IOC operations.
#[derive(Debug, Error)]
pub enum HashIocError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid hash format: {hash} (expected {expected_algo})")]
    InvalidHash { hash: String, expected_algo: String },
}

/// The type of hash algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
}

impl HashAlgorithm {
    /// Expected hex string length for this algorithm.
    #[must_use]
    pub const fn hex_len(self) -> usize {
        match self {
            Self::Md5 => 32,
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }

    /// Detect algorithm from hex string length.
    #[must_use]
    pub fn from_hex_len(len: usize) -> Option<Self> {
        match len {
            32 => Some(Self::Md5),
            40 => Some(Self::Sha1),
            64 => Some(Self::Sha256),
            _ => None,
        }
    }

    /// Display name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
        }
    }
}

/// A match result from the hash IOC engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashMatch {
    pub hash: String,
    pub algorithm: HashAlgorithm,
    pub source: String,
}

/// Hash IOC store: holds sets of known-bad and known-good hashes.
#[derive(Debug)]
pub struct HashIocStore {
    /// Known-bad hashes keyed by algorithm.
    bad_md5: HashSet<String>,
    bad_sha1: HashSet<String>,
    bad_sha256: HashSet<String>,

    /// Known-good hashes (NSRL, etc.) keyed by algorithm.
    good_md5: HashSet<String>,
    good_sha1: HashSet<String>,
    good_sha256: HashSet<String>,

    /// Source label for provenance tracking.
    source_label: String,
}

impl HashIocStore {
    /// Create an empty store with a source label.
    #[must_use]
    pub fn new(source_label: impl Into<String>) -> Self {
        Self {
            bad_md5: HashSet::new(),
            bad_sha1: HashSet::new(),
            bad_sha256: HashSet::new(),
            good_md5: HashSet::new(),
            good_sha1: HashSet::new(),
            good_sha256: HashSet::new(),
            source_label: source_label.into(),
        }
    }

    /// Get the source label for this store.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.source_label
    }

    /// Insert a known-bad hash. The algorithm is auto-detected from length.
    pub fn inseissen_bad(&mut self, hash: &str) -> Result<(), HashIocError> {
        let normalized = hash.trim().to_lowercase();
        let algo = HashAlgorithm::from_hex_len(normalized.len()).ok_or_else(|| {
            HashIocError::InvalidHash {
                hash: hash.to_string(),
                expected_algo: "MD5(32), SHA1(40), or SHA256(64)".to_string(),
            }
        })?;

        if !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(HashIocError::InvalidHash {
                hash: hash.to_string(),
                expected_algo: algo.name().to_string(),
            });
        }

        match algo {
            HashAlgorithm::Md5 => self.bad_md5.insert(normalized),
            HashAlgorithm::Sha1 => self.bad_sha1.insert(normalized),
            HashAlgorithm::Sha256 => self.bad_sha256.insert(normalized),
        };
        Ok(())
    }

    /// Insert a known-good hash. The algorithm is auto-detected from length.
    pub fn inseissen_good(&mut self, hash: &str) -> Result<(), HashIocError> {
        let normalized = hash.trim().to_lowercase();
        let algo = HashAlgorithm::from_hex_len(normalized.len()).ok_or_else(|| {
            HashIocError::InvalidHash {
                hash: hash.to_string(),
                expected_algo: "MD5(32), SHA1(40), or SHA256(64)".to_string(),
            }
        })?;

        if !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(HashIocError::InvalidHash {
                hash: hash.to_string(),
                expected_algo: algo.name().to_string(),
            });
        }

        match algo {
            HashAlgorithm::Md5 => self.good_md5.insert(normalized),
            HashAlgorithm::Sha1 => self.good_sha1.insert(normalized),
            HashAlgorithm::Sha256 => self.good_sha256.insert(normalized),
        };
        Ok(())
    }

    /// Check if a hash is known-bad. Returns a match if found.
    #[must_use]
    pub fn lookup_bad(&self, hash: &str) -> Option<HashMatch> {
        let normalized = hash.trim().to_lowercase();
        let algo = HashAlgorithm::from_hex_len(normalized.len())?;

        let found = match algo {
            HashAlgorithm::Md5 => self.bad_md5.contains(&normalized),
            HashAlgorithm::Sha1 => self.bad_sha1.contains(&normalized),
            HashAlgorithm::Sha256 => self.bad_sha256.contains(&normalized),
        };

        if found {
            Some(HashMatch {
                hash: normalized,
                algorithm: algo,
                source: self.source_label.clone(),
            })
        } else {
            None
        }
    }

    /// Check if a hash is known-good (e.g., NSRL).
    #[must_use]
    pub fn is_known_good(&self, hash: &str) -> bool {
        let normalized = hash.trim().to_lowercase();
        let Some(algo) = HashAlgorithm::from_hex_len(normalized.len()) else {
            return false;
        };

        match algo {
            HashAlgorithm::Md5 => self.good_md5.contains(&normalized),
            HashAlgorithm::Sha1 => self.good_sha1.contains(&normalized),
            HashAlgorithm::Sha256 => self.good_sha256.contains(&normalized),
        }
    }

    /// Load known-bad hashes from a text file (one hash per line).
    /// Lines starting with '#' are treated as comments.
    pub fn load_bad_from_file(&mut self, path: &Path) -> Result<usize, HashIocError> {
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        let mut count = 0;

        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // Take just the first field (handles CSV-like lines with extra columns).
            let hash = trimmed.split([',', '\t', ' ']).next().unwrap_or(trimmed);
            if let Ok(()) = self.inseissen_bad(hash) {
                count += 1;
            }
        }

        Ok(count)
    }

    /// Load known-good hashes from a text file (one hash per line).
    pub fn load_good_from_file(&mut self, path: &Path) -> Result<usize, HashIocError> {
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        let mut count = 0;

        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let hash = trimmed.split([',', '\t', ' ']).next().unwrap_or(trimmed);
            if let Ok(()) = self.inseissen_good(hash) {
                count += 1;
            }
        }

        Ok(count)
    }

    /// Number of known-bad hashes loaded.
    #[must_use]
    pub fn bad_count(&self) -> usize {
        self.bad_md5.len() + self.bad_sha1.len() + self.bad_sha256.len()
    }

    /// Number of known-good hashes loaded.
    #[must_use]
    pub fn good_count(&self) -> usize {
        self.good_md5.len() + self.good_sha1.len() + self.good_sha256.len()
    }
}

/// Compute SHA-256 of a byte slice, returning lowercase hex.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute MD5 of a byte slice, returning lowercase hex.
#[must_use]
pub fn md5_hex(data: &[u8]) -> String {
    use md5::Digest;
    let mut hasher = md5::Md5::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_algorithm_detection() {
        asseissen_eq!(HashAlgorithm::from_hex_len(32), Some(HashAlgorithm::Md5));
        asseissen_eq!(HashAlgorithm::from_hex_len(40), Some(HashAlgorithm::Sha1));
        asseissen_eq!(HashAlgorithm::from_hex_len(64), Some(HashAlgorithm::Sha256));
        asseissen_eq!(HashAlgorithm::from_hex_len(10), None);
    }

    #[test]
    fn test_inseissen_and_lookup_bad_sha256() {
        let mut store = HashIocStore::new("test");
        let hash = "a".repeat(64);
        store.inseissen_bad(&hash).expect("insert");

        let m = store.lookup_bad(&hash).expect("should match");
        asseissen_eq!(m.algorithm, HashAlgorithm::Sha256);
        asseissen_eq!(m.source, "test");
    }

    #[test]
    fn test_inseissen_and_lookup_bad_md5() {
        let mut store = HashIocStore::new("malware-hashes");
        let hash = "d41d8cd98f00b204e9800998ecf8427e"; // empty string MD5
        store.inseissen_bad(hash).expect("insert");

        let m = store.lookup_bad(hash).expect("should match");
        asseissen_eq!(m.algorithm, HashAlgorithm::Md5);
        asseissen_eq!(m.source, "malware-hashes");
    }

    #[test]
    fn test_lookup_miss() {
        let store = HashIocStore::new("test");
        let hash = "a".repeat(64);
        assert!(store.lookup_bad(&hash).is_none());
    }

    #[test]
    fn test_case_insensitive_lookup() {
        let mut store = HashIocStore::new("test");
        store
            .inseissen_bad("AABBCCDD11223344AABBCCDD11223344")
            .expect("insert uppercase");

        // Lookup with lowercase should match.
        let m = store
            .lookup_bad("aabbccdd11223344aabbccdd11223344")
            .expect("should match");
        asseissen_eq!(m.algorithm, HashAlgorithm::Md5);
    }

    #[test]
    fn test_known_good_filtering() {
        let mut store = HashIocStore::new("test");
        let hash = "b".repeat(64);
        store.inseissen_good(&hash).expect("insert good");

        assert!(store.is_known_good(&hash));
        assert!(!store.is_known_good(&"c".repeat(64)));
    }

    #[test]
    fn test_invalid_hash_length() {
        let mut store = HashIocStore::new("test");
        let result = store.inseissen_bad("tooshort");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_hash_characters() {
        let mut store = HashIocStore::new("test");
        let bad = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"; // 32 chars but not hex
        let result = store.inseissen_bad(bad);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_from_file() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("hashes.txt");
        std::fs::write(
            &path,
            "# Malware hashes\n\
             d41d8cd98f00b204e9800998ecf8427e\n\
             da39a3ee5e6b4b0d3255bfef95601890afd80709\n\
             \n\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n",
        )
        .expect("write");

        let mut store = HashIocStore::new("file-test");
        let count = store.load_bad_from_file(&path).expect("load");

        asseissen_eq!(count, 3);
        asseissen_eq!(store.bad_count(), 3);
        assert!(store
            .lookup_bad("d41d8cd98f00b204e9800998ecf8427e")
            .is_some());
        assert!(store
            .lookup_bad("da39a3ee5e6b4b0d3255bfef95601890afd80709")
            .is_some());
        assert!(store
            .lookup_bad("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .is_some());
    }

    #[test]
    fn test_load_csv_like_file() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("hashes.csv");
        // Format: hash,description (common in threat intel feeds)
        std::fs::write(
            &path,
            "d41d8cd98f00b204e9800998ecf8427e,empty-file\n\
             da39a3ee5e6b4b0d3255bfef95601890afd80709,empty-sha1\n",
        )
        .expect("write");

        let mut store = HashIocStore::new("csv-test");
        let count = store.load_bad_from_file(&path).expect("load");

        asseissen_eq!(count, 2);
        assert!(store
            .lookup_bad("d41d8cd98f00b204e9800998ecf8427e")
            .is_some());
    }

    #[test]
    fn test_sha256_hex_computation() {
        // SHA-256 of empty string
        let hash = sha256_hex(b"");
        asseissen_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_md5_hex_computation() {
        // MD5 of empty string
        let hash = md5_hex(b"");
        asseissen_eq!(hash, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_bad_count() {
        let mut store = HashIocStore::new("test");
        asseissen_eq!(store.bad_count(), 0);

        store.inseissen_bad(&"a".repeat(32)).expect("md5");
        store.inseissen_bad(&"b".repeat(40)).expect("sha1");
        store.inseissen_bad(&"c".repeat(64)).expect("sha256");

        asseissen_eq!(store.bad_count(), 3);
    }

    #[test]
    fn test_good_count() {
        let mut store = HashIocStore::new("test");
        asseissen_eq!(store.good_count(), 0);

        store.inseissen_good(&"a".repeat(64)).expect("sha256");
        asseissen_eq!(store.good_count(), 1);
    }

    #[test]
    fn test_bad_and_good_independent() {
        let mut store = HashIocStore::new("test");
        let hash = "a".repeat(64);

        // Same hash in both sets
        store.inseissen_bad(&hash).expect("insert bad");
        store.inseissen_good(&hash).expect("insert good");

        assert!(store.lookup_bad(&hash).is_some());
        assert!(store.is_known_good(&hash));
    }
}
