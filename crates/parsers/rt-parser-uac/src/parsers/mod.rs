pub mod bodyfile;
pub mod chkrootkit;
pub mod configs;
pub mod hardware;
pub mod hash_execs;
pub mod network;
pub mod packages;
pub mod process;
pub mod rootkit;
pub mod storage;
pub mod system;

use std::path::Path;

use serde::Serialize;
use tracing::info;

/// Aggregated results from parsing all UAC categories.
#[derive(Debug, Default, Serialize)]
pub struct UacParseResult {
    pub bodyfile_entries: usize,
    pub network_connections: usize,
    pub processes: usize,
    pub packages: usize,
    pub login_records: usize,
    pub hashed_executables: usize,
    pub chkrootkit_findings: usize,
    pub config_files: usize,
    pub crontab_entries: usize,
}

/// Parse all UAC categories from an extracted collection directory.
///
/// The `extracted_root` should contain the UAC directory structure
/// (bodyfile/, live_response/, system/, etc.).
#[must_use]
pub fn parse_all_categories(extracted_root: &Path) -> UacParseResult {
    let mut result = UacParseResult::default();

    // Bodyfile
    let bf_path = extracted_root.join("bodyfile/bodyfile.txt");
    if bf_path.exists() {
        if let Ok(entries) = bodyfile::parse_bodyfile_path(&bf_path) {
            result.bodyfile_entries = entries.len();
            info!(entries = entries.len(), "Parsed bodyfile");
        }
    }

    // Network
    let net_dir = extracted_root.join("live_response/network");
    if net_dir.is_dir() {
        let conns = network::parse_network_dir(&net_dir);
        result.network_connections = conns.len();
        info!(connections = conns.len(), "Parsed network state");
    }

    // Process
    for name in &["ps_auxwww.txt", "ps-auxwww.txt", "ps.txt"] {
        let path = extracted_root.join("live_response/process").join(name);
        if let Ok(content) = std::fs::read_to_string(&path) {
            let procs = process::parse_ps_output(&content);
            result.processes += procs.len();
        }
    }

    // Crontab
    let crontab_dir = extracted_root.join("live_response/process");
    for name in &["crontab.txt", "crontab-l.txt"] {
        let path = crontab_dir.join(name);
        if let Ok(content) = std::fs::read_to_string(&path) {
            let entries = process::parse_crontab(&content, "root");
            result.crontab_entries += entries.len();
        }
    }

    // Packages
    let pkg_dir = extracted_root.join("live_response/packages");
    if pkg_dir.is_dir() {
        let pkgs = packages::parse_packages_dir(&pkg_dir);
        result.packages = pkgs.len();
    }

    // System (login history)
    for name in &["last.txt", "last-a.txt"] {
        let path = extracted_root.join("live_response/system").join(name);
        if let Ok(content) = std::fs::read_to_string(&path) {
            let records = system::parse_last_output(&content);
            result.login_records += records.len();
        }
    }

    // Hash executables
    let hash_dir = extracted_root.join("hash_executables");
    if hash_dir.is_dir() {
        let hashes = hash_execs::parse_hash_dir(&hash_dir);
        result.hashed_executables = hashes.len();
    }

    // Chkrootkit
    let chk_path = extracted_root.join("chkrootkit/chkrootkit.log");
    if let Ok(content) = std::fs::read_to_string(&chk_path) {
        let findings = chkrootkit::parse_chkrootkit_log(&content);
        result.chkrootkit_findings = findings.len();
    }

    // Configs
    let sys_dir = extracted_root.join("system");
    if sys_dir.is_dir() {
        let configs = configs::collect_configs(&sys_dir);
        result.config_files = configs.len();
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_all_categories_empty_dir() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let result = parse_all_categories(dir.path());
        assert_eq!(result.bodyfile_entries, 0);
        assert_eq!(result.network_connections, 0);
    }

    #[test]
    fn test_parse_all_categories_with_bodyfile() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let bf_dir = dir.path().join("bodyfile");
        std::fs::create_dir_all(&bf_dir).expect("mkdir");
        std::fs::write(
            bf_dir.join("bodyfile.txt"),
            "0|/bin/ls|1|100755|0|0|100|1000|2000|3000|0\n\
             0|/bin/cat|2|100755|0|0|200|4000|5000|6000|0\n",
        )
        .expect("write");

        let result = parse_all_categories(dir.path());
        assert_eq!(result.bodyfile_entries, 2);
    }
}
