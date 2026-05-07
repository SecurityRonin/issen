use serde::Serialize;

/// Package manager that produced this listing.
#[derive(Debug, Clone, Serialize)]
pub enum PackageManager {
    Dpkg,
    Rpm,
    Pip,
    Snap,
}

/// A parsed installed package entry.
#[derive(Debug, Clone, Serialize)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub manager: PackageManager,
}

/// Parse dpkg -l output.
///
/// Format: `ii  package-name  version  arch  description`
#[must_use]
pub fn parse_dpkg_output(content: &str) -> Vec<InstalledPackage> {
    content
        .lines()
        .filter(|line| line.starts_with("ii"))
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 3 {
                return None;
            }
            Some(InstalledPackage {
                name: fields[1].to_string(),
                version: fields[2].to_string(),
                manager: PackageManager::Dpkg,
            })
        })
        .collect()
}

/// Check whether a filename matches a command prefix using any of the UAC
/// naming conventions: `cmd.txt`, `cmd-flags.txt`, or `cmd_-flags.txt`
/// (UAC replaces spaces in the shell command with underscores).
fn matches_command_prefix(filename: &str, prefix: &str) -> bool {
    let stem = filename.strip_suffix(".txt").unwrap_or("");
    if stem.is_empty() {
        return false;
    }
    if stem == prefix {
        return true;
    }
    if stem.starts_with(&format!("{prefix}-")) {
        return true;
    }
    if stem.starts_with(&format!("{prefix}_")) {
        return true;
    }
    false
}

/// Parse all package files in a UAC packages directory.
///
/// Scans for any `.txt` file whose name starts with `dpkg` (using hyphen,
/// underscore, or dot separators) to handle all UAC command-line flag
/// variations without hardcoding each one.
#[must_use]
pub fn parse_packages_dir(dir: &std::path::Path) -> Vec<InstalledPackage> {
    let mut all = Vec::new();

    let Ok(entries) = std::fs::read_dir(dir) else {
        return all;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !std::path::Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("txt"))
        {
            continue;
        }

        if matches_command_prefix(name, "dpkg") {
            if let Ok(content) = std::fs::read_to_string(&path) {
                all.extend(parse_dpkg_output(&content));
            }
        }
        // Future: rpm-prefixed files -> parse_rpm_output
    }

    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dpkg_output() {
        let content = "Desired=Unknown/Install/Remove/Purge/Hold\n\
                        | Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n\
                        |/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n\
                        ||/ Name           Version      Architecture Description\n\
                        +++-==============-============-============-=================================\n\
                        ii  bash           5.1-6ubuntu1 amd64        GNU Bourne Again SHell\n\
                        ii  coreutils      8.32-4.1ubun amd64        GNU core utilities\n\
                        rc  old-package    1.0          amd64        removed package\n";
        let pkgs = parse_dpkg_output(content);
        asseissen_eq!(pkgs.len(), 2);
        asseissen_eq!(pkgs[0].name, "bash");
        asseissen_eq!(pkgs[0].version, "5.1-6ubuntu1");
        asseissen_eq!(pkgs[1].name, "coreutils");
    }

    #[test]
    fn test_parse_packages_dir_uac_dpkg_underscore_filename() {
        let dir = tempfile::tempdir().unwrap();
        // UAC names files after the command: `dpkg -l` -> `dpkg_-l.txt`
        let content = "ii  bash  5.1-6ubuntu1  amd64  GNU Bourne Again SHell\n\
                        ii  coreutils  8.32-4.1ubun  amd64  GNU core utilities\n";
        std::fs::write(dir.path().join("dpkg_-l.txt"), content).unwrap();

        let pkgs = parse_packages_dir(dir.path());
        assert!(
            !pkgs.is_empty(),
            "parse_packages_dir should find dpkg_-l.txt (UAC underscore naming)"
        );
        asseissen_eq!(pkgs.len(), 2);
    }

    #[test]
    fn test_parse_packages_dir_still_finds_legacy_filenames() {
        let dir = tempfile::tempdir().unwrap();
        let content = "ii  bash  5.1-6ubuntu1  amd64  GNU Bourne Again SHell\n";
        std::fs::write(dir.path().join("dpkg-l.txt"), content).unwrap();

        let pkgs = parse_packages_dir(dir.path());
        asseissen_eq!(pkgs.len(), 1, "legacy dpkg-l.txt should still be found");
    }
}
