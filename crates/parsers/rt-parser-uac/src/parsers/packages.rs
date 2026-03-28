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

/// Parse all package files in a UAC packages directory.
#[must_use]
pub fn parse_packages_dir(dir: &std::path::Path) -> Vec<InstalledPackage> {
    let mut all = Vec::new();

    for name in &["dpkg-l.txt", "dpkg.txt"] {
        let path = dir.join(name);
        if let Ok(content) = std::fs::read_to_string(&path) {
            all.extend(parse_dpkg_output(&content));
        }
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
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "bash");
        assert_eq!(pkgs[0].version, "5.1-6ubuntu1");
        assert_eq!(pkgs[1].name, "coreutils");
    }
}
