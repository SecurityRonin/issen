use serde::Serialize;

/// A hashed executable from UAC hash_executables output.
#[derive(Debug, Clone, Serialize)]
pub struct HashedExecutable {
    pub hash: String,
    pub path: String,
    pub algorithm: String,
}

/// Parse a UAC hash file (one `hash  path` per line).
///
/// UAC typically produces md5sum/sha1sum/sha256sum output format.
#[must_use]
pub fn parse_hash_file(content: &str, algorithm: &str) -> Vec<HashedExecutable> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (hash, path) = line.split_once(|c: char| c.is_whitespace())?;
            let path = path.trim().trim_start_matches('*');
            if hash.is_empty() || path.is_empty() {
                return None;
            }
            Some(HashedExecutable {
                hash: hash.to_string(),
                path: path.to_string(),
                algorithm: algorithm.to_string(),
            })
        })
        .collect()
}

/// Return hashed executables whose paths appear in the preload list.
///
/// Deduplicates by path, preferring the SHA1 hash (40 hex chars) over MD5 (32)
/// or SHA256 (64) so callers get the most useful hash for VirusTotal lookups.
#[must_use]
pub fn find_preloaded_executables(
    preload_paths: &[String],
    hashes: &[HashedExecutable],
) -> Vec<HashedExecutable> {
    use std::collections::HashMap;
    let preload_set: std::collections::HashSet<&str> =
        preload_paths.iter().map(|s| s.as_str()).collect();

    let mut best: HashMap<String, HashedExecutable> = HashMap::new();
    for h in hashes {
        if !preload_set.contains(h.path.as_str()) {
            continue;
        }
        let entry = best.entry(h.path.clone()).or_insert_with(|| h.clone());
        if h.hash.len() == 40 && entry.hash.len() != 40 {
            *entry = h.clone();
        }
    }
    let mut result: Vec<HashedExecutable> = best.into_values().collect();
    result.sort_by(|a, b| a.path.cmp(&b.path));
    result
}

/// Parse all hash files in a UAC hash_executables directory.
#[must_use]
pub fn parse_hash_dir(dir: &std::path::Path) -> Vec<HashedExecutable> {
    let mut all = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let algo = if name.contains("md5") {
                "md5"
            } else if name.contains("sha256") {
                "sha256"
            } else if name.contains("sha1") {
                "sha1"
            } else {
                "unknown"
            };
            if let Ok(content) = std::fs::read_to_string(&path) {
                all.extend(parse_hash_file(&content, algo));
            }
        }
    }
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Gap 5A RED: find_preloaded_executables ──────────────────────────────

    #[test]
    fn find_preloaded_executables_empty_hashes_returns_empty() {
        let result = find_preloaded_executables(&["/tmp/evil.so".to_string()], &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn find_preloaded_executables_empty_preload_returns_empty() {
        let hashes = vec![HashedExecutable {
            hash: "abc".to_string(),
            path: "/usr/lib/liblegit.so".to_string(),
            algorithm: "sha1".to_string(),
        }];
        let result = find_preloaded_executables(&[], &hashes);
        assert!(result.is_empty());
    }

    #[test]
    fn find_preloaded_executables_match_returns_matching_hash() {
        let hashes = vec![
            HashedExecutable {
                hash: "deadbeef".to_string(),
                path: "/tmp/evil.so".to_string(),
                algorithm: "sha1".to_string(),
            },
            HashedExecutable {
                hash: "cafebabe".to_string(),
                path: "/usr/lib/liblegit.so".to_string(),
                algorithm: "sha1".to_string(),
            },
        ];
        let preload = vec!["/tmp/evil.so".to_string()];
        let result = find_preloaded_executables(&preload, &hashes);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].path, "/tmp/evil.so");
        assert_eq!(result[0].hash, "deadbeef");
    }

    #[test]
    fn find_preloaded_executables_no_match_returns_empty() {
        let hashes = vec![HashedExecutable {
            hash: "cafebabe".to_string(),
            path: "/usr/lib/liblegit.so".to_string(),
            algorithm: "sha1".to_string(),
        }];
        let preload = vec!["/tmp/evil.so".to_string()];
        let result = find_preloaded_executables(&preload, &hashes);
        assert!(result.is_empty());
    }

    #[test]
    fn find_preloaded_executables_deduplicates_by_path() {
        // Same path with different algorithms — only one entry per path (prefer sha1)
        let hashes = vec![
            HashedExecutable {
                hash: "aabbcc".to_string(),
                path: "/tmp/evil.so".to_string(),
                algorithm: "md5".to_string(),
            },
            HashedExecutable {
                hash: "deadbeef1234567890abcdef0123456789abcdef".to_string(),
                path: "/tmp/evil.so".to_string(),
                algorithm: "sha1".to_string(),
            },
        ];
        let preload = vec!["/tmp/evil.so".to_string()];
        let result = find_preloaded_executables(&preload, &hashes);
        // dedup: prefer sha1 (40 chars)
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].algorithm, "sha1");
    }

    // ── existing tests ──────────────────────────────────────────────────────

    #[test]
    fn test_parse_hash_file() {
        let content = "d41d8cd98f00b204e9800998ecf8427e  /usr/bin/ls\n\
                        abc123  /usr/bin/cat\n";
        let hashes = parse_hash_file(content, "md5");
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0].hash, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hashes[0].path, "/usr/bin/ls");
        assert_eq!(hashes[0].algorithm, "md5");
    }

    #[test]
    fn test_parse_hash_file_star_prefix() {
        let content = "abc123 */usr/bin/ls\n";
        let hashes = parse_hash_file(content, "sha256");
        assert_eq!(hashes[0].path, "/usr/bin/ls");
    }
}
