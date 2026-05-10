use serde::Serialize;

/// Hardware information parsed from UAC hardware artifacts.
#[derive(Debug, Clone, Serialize)]
pub struct HardwareInfo {
    pub source: String,
    pub content: String,
}

/// Parse all hardware files in a UAC hardware directory.
///
/// Hardware files (dmesg, lspci, lsusb, dmidecode) are stored as-is
/// since their formats are too varied for structured parsing.
#[must_use]
pub fn parse_hardware_dir(dir: &std::path::Path) -> Vec<HardwareInfo> {
    let mut results = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let source = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                if let Ok(content) = std::fs::read_to_string(&path) {
                    results.push(HardwareInfo { source, content });
                }
            }
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hardware_dir() {
        let dir = tempfile::tempdir().expect("tmpdir");
        std::fs::write(dir.path().join("dmesg.txt"), "kernel boot log").expect("write");
        std::fs::write(dir.path().join("lspci.txt"), "00:00.0 Host bridge").expect("write");

        let info = parse_hardware_dir(dir.path());
        assert_eq!(info.len(), 2);
    }
}
