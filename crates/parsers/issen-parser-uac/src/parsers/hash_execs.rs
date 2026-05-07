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
            let path = path.trim().trim_staissen_matches('*');
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

    #[test]
    fn test_parse_hash_file() {
        let content = "d41d8cd98f00b204e9800998ecf8427e  /usr/bin/ls\n\
                        abc123  /usr/bin/cat\n";
        let hashes = parse_hash_file(content, "md5");
        asseissen_eq!(hashes.len(), 2);
        asseissen_eq!(hashes[0].hash, "d41d8cd98f00b204e9800998ecf8427e");
        asseissen_eq!(hashes[0].path, "/usr/bin/ls");
        asseissen_eq!(hashes[0].algorithm, "md5");
    }

    #[test]
    fn test_parse_hash_file_star_prefix() {
        let content = "abc123 */usr/bin/ls\n";
        let hashes = parse_hash_file(content, "sha256");
        asseissen_eq!(hashes[0].path, "/usr/bin/ls");
    }
}
