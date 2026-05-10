use serde::Serialize;

/// A system configuration file captured by UAC.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigFile {
    pub path: String,
    pub content: String,
}

/// Collect all config files from a UAC system directory.
///
/// These are stored as-is for analyst review — the forensic value
/// is in having the configuration snapshot, not in parsing each format.
#[must_use]
pub fn collect_configs(dir: &std::path::Path) -> Vec<ConfigFile> {
    let mut results = Vec::new();
    collect_recursive(dir, dir, &mut results);
    results
}

fn collect_recursive(
    base: &std::path::Path,
    current: &std::path::Path,
    results: &mut Vec<ConfigFile>,
) {
    if let Ok(entries) = std::fs::read_dir(current) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_recursive(base, &path, results);
            } else if path.is_file() {
                let rel = path.strip_prefix(base).unwrap_or(&path);
                if let Ok(content) = std::fs::read_to_string(&path) {
                    results.push(ConfigFile {
                        path: rel.to_string_lossy().to_string(),
                        content,
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_configs() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).expect("mkdir");
        std::fs::write(etc.join("passwd"), "root:x:0:0::/root:/bin/bash\n").expect("write");
        std::fs::write(etc.join("hostname"), "testhost\n").expect("write");

        let configs = collect_configs(dir.path());
        assert_eq!(configs.len(), 2);
    }
}
