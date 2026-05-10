pub mod auth_log;
pub mod bash_history;
pub mod bodyfile;
pub mod chkrootkit;
pub mod configs;
pub mod hardware;
pub mod hash_execs;
pub mod hidden_pids;
pub mod journal;
pub mod mem_sockstat;
pub mod network;
pub mod packages;
pub mod process;
pub mod rootkit;
pub mod shadow;
pub mod staging_detection;
pub mod storage;
pub mod system;

use std::path::Path;

use serde::Serialize;
use tracing::info;

pub use mem_sockstat::SockstatEntry;

/// A group of hidden processes that share a network endpoint and form a
/// recognizable shell upgrade chain (e.g. `sh → python3 → bash`).
#[derive(Debug, Clone, Serialize)]
pub struct ShellUpgradeChain {
    /// PIDs involved in the chain.
    pub pids: Vec<u32>,
    /// Process names in the chain (e.g. `["sh", "python3", "bash"]`).
    pub process_names: Vec<String>,
    /// `dst_ip:dst_port` shared by all processes in the chain.
    pub shared_endpoint: String,
}

const SHELL_OR_INTERPRETER_NAMES: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "fish",
    "python", "python2", "python3", "perl", "ruby", "node", "nodejs", "php",
];

/// Detect interpreter-upgraded shell chains among hidden processes.
///
/// A chain requires at least two hidden processes sharing the same external
/// `(dst_ip:dst_port)`, where at least one process is a shell or interpreter.
/// Covers both `sh → python3 → bash` (full pty.spawn) and `sh → bash` patterns.
#[must_use]
pub fn detect_shell_upgrade_chain(analysis: &HiddenProcessAnalysis) -> Vec<ShellUpgradeChain> {
    use std::collections::HashMap;

    // Group findings by their first connection's (dst_addr, dst_port).
    let mut by_endpoint: HashMap<String, Vec<&HiddenProcessFinding>> = HashMap::new();
    for finding in &analysis.findings {
        let endpoint = finding.connections.iter().find_map(|c| {
            let port = c.dst_port?;
            let addr = &c.dst_addr;
            if addr.is_empty() || addr == "-" {
                return None;
            }
            Some(format!("{addr}:{port}"))
        });
        if let Some(ep) = endpoint {
            by_endpoint.entry(ep).or_default().push(finding);
        }
    }

    let mut chains = Vec::new();
    for (endpoint, group) in by_endpoint {
        if group.len() < 2 {
            continue;
        }
        let names: Vec<String> = group
            .iter()
            .filter_map(|f| f.process_name.clone())
            .collect();
        let has_shell_or_interp = names.iter().any(|n| {
            let lc = n.to_lowercase();
            SHELL_OR_INTERPRETER_NAMES.iter().any(|s| lc == *s || lc.starts_with(s))
        });
        if has_shell_or_interp {
            let mut pids: Vec<u32> = group.iter().map(|f| f.pid).collect();
            pids.sort_unstable();
            chains.push(ShellUpgradeChain {
                pids,
                process_names: names,
                shared_endpoint: endpoint,
            });
        }
    }
    chains
}

/// A hidden process discovered by correlating `/proc` PID enumeration with
/// `ps` output and (optionally) Volatility memory sockstat.
#[derive(Debug, Clone, Serialize)]
pub struct HiddenProcessFinding {
    /// The PID that was visible in `/proc` but absent from `ps`.
    pub pid: u32,
    /// Process name recovered from memory dump (None if no dump available).
    pub process_name: Option<String>,
    /// Distinct thread names seen for this PID in sockstat (e.g. "libuv-worker").
    pub thread_names: Vec<String>,
    /// All names associated with this process: `[process_name] + thread_names`.
    ///
    /// Useful for display and detection: a process masquerading as "top" but
    /// with "libuv-worker" threads is revealed by inspecting this field.
    /// Empty when no memory dump is available.
    pub all_thread_names: Vec<String>,
    /// Network connections attributed to this PID from memory.
    pub connections: Vec<SockstatEntry>,
}

/// Analysis of hidden processes in a UAC collection.
#[derive(Debug, Default, Serialize)]
pub struct HiddenProcessAnalysis {
    /// PIDs that were in `/proc` but not in `ps` output.
    pub hidden_pids: Vec<u32>,
    /// Correlated findings (one per hidden PID that appeared in sockstat).
    pub findings: Vec<HiddenProcessFinding>,
}

/// Correlate hidden PIDs with Volatility sockstat output.
///
/// For each hidden PID, collects all sockstat entries attributed to that PID,
/// determines the process name, and lists distinct thread names (which can
/// expose masquerade: a process calling itself "top" with "libuv-worker" threads
/// is almost certainly XMRig).
#[must_use]
pub fn analyze_hidden_processes(root: &Path) -> HiddenProcessAnalysis {
    let hidden_pids = hidden_pids::read_hidden_pids(root);
    if hidden_pids.is_empty() {
        return HiddenProcessAnalysis::default();
    }

    let sockstat = mem_sockstat::read_mem_sockstat(root);

    let findings = hidden_pids
        .iter()
        .map(|&pid| {
            let pid_entries: Vec<SockstatEntry> =
                sockstat.iter().filter(|e| e.pid == pid).cloned().collect();

            // Primary process name: the main thread (TID == PID), or any entry.
            let process_name = pid_entries
                .iter()
                .find(|e| e.tid == pid)
                .or_else(|| pid_entries.first())
                .map(|e| e.process_name.clone());

            // Collect distinct thread names (names from entries where TID != PID).
            let mut thread_names: Vec<String> = pid_entries
                .iter()
                .filter(|e| e.tid != pid)
                .map(|e| e.process_name.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();
            thread_names.sort();

            // all_thread_names = [process_name] + thread_names (sorted).
            let mut all_thread_names: Vec<String> = process_name
                .iter()
                .cloned()
                .chain(thread_names.iter().cloned())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();
            all_thread_names.sort();

            HiddenProcessFinding {
                pid,
                process_name,
                thread_names,
                all_thread_names,
                connections: pid_entries,
            }
        })
        .collect();

    HiddenProcessAnalysis {
        hidden_pids,
        findings,
    }
}

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
    /// Hidden process analysis (populated when the collection has the relevant files).
    pub hidden_process_analysis: HiddenProcessAnalysis,
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

    // Hidden process analysis
    result.hidden_process_analysis = analyze_hidden_processes(extracted_root);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> &'static str {
        "NetNS\tProcess Name\tPID\tTID\tFD\tSock Offset\tFamily\tType\tProto\tSource Addr\tSource Port\tDestination Addr\tDestination Port\tState\tFilter\n"
    }

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

    // =========================================================================
    // analyze_hidden_processes — contract:
    //   Given a UAC root with hidden_pids + sockstat, returns correlated findings.
    //
    //   Rules:
    //     - hidden_pids empty + no sockstat → empty analysis
    //     - hidden PIDs with no matching sockstat rows → findings has no connections
    //     - hidden PID with sockstat rows → finding has process_name + connections
    //     - distinct thread_names collected (e.g. "libuv-worker" for miners)
    //     - PIDs not in hidden list but in sockstat are ignored
    // =========================================================================

    #[test]
    fn analyze_empty_collection_returns_empty() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let analysis = analyze_hidden_processes(dir.path());
        assert!(analysis.hidden_pids.is_empty());
        assert!(analysis.findings.is_empty());
    }

    #[test]
    fn analyze_hidden_pid_no_sockstat_still_listed() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let proc_dir = dir.path().join("live_response/process");
        std::fs::create_dir_all(&proc_dir).expect("mkdir");
        std::fs::write(proc_dir.join("hidden_pids_for_ps_command.txt"), "1234\n").expect("write");

        let analysis = analyze_hidden_processes(dir.path());
        assert_eq!(analysis.hidden_pids, vec![1234]);
        // Without sockstat, we still surface the hidden PID
        assert_eq!(analysis.findings.len(), 1);
        assert_eq!(analysis.findings[0].pid, 1234);
        assert!(analysis.findings[0].process_name.is_none());
        assert!(analysis.findings[0].connections.is_empty());
    }

    // ── WS-2 RED: all_thread_names must include both process_name and thread_names ──

    #[test]
    fn all_thread_names_includes_process_name_and_thread_names() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let proc_dir = dir.path().join("live_response/process");
        std::fs::create_dir_all(&proc_dir).expect("mkdir");
        std::fs::write(proc_dir.join("hidden_pids_for_ps_command.txt"), "977\n").expect("write");

        let mem_dir = dir.path().join("memory_dump");
        std::fs::create_dir_all(&mem_dir).expect("mkdir");
        let sockstat = format!(
            "{}\
             4026531840\ttop\t977\t977\t17\t0xABC\tAF_INET\tSTREAM\tTCP\t127.0.0.1\t59182\t127.0.0.1\t3333\tESTABLISHED\t-\n\
             4026531840\tlibuv-worker\t977\t978\t17\t0xABC\tAF_INET\tSTREAM\tTCP\t127.0.0.1\t59182\t127.0.0.1\t3333\tESTABLISHED\t-\n",
            header()
        );
        std::fs::write(mem_dir.join("output-sockstat"), sockstat).expect("write");

        let analysis = analyze_hidden_processes(dir.path());
        let finding = &analysis.findings[0];

        // all_thread_names must contain both "top" (process name) and "libuv-worker" (thread)
        assert!(
            finding.all_thread_names.contains(&"top".to_string()),
            "expected 'top' in all_thread_names: {:?}",
            finding.all_thread_names
        );
        assert!(
            finding
                .all_thread_names
                .contains(&"libuv-worker".to_string()),
            "expected 'libuv-worker' in all_thread_names: {:?}",
            finding.all_thread_names
        );
    }

    #[test]
    fn analyze_correlates_miner_masquerade() {
        // Reproduces the CTF scenario: PID 977 calls itself "top" but
        // libuv-worker threads reveal it is XMRig connecting to :3333.
        let dir = tempfile::tempdir().expect("tmpdir");

        let proc_dir = dir.path().join("live_response/process");
        std::fs::create_dir_all(&proc_dir).expect("mkdir");
        std::fs::write(proc_dir.join("hidden_pids_for_ps_command.txt"), "977\n").expect("write");

        let mem_dir = dir.path().join("memory_dump");
        std::fs::create_dir_all(&mem_dir).expect("mkdir");
        let sockstat = format!(
            "{}\
             4026531840\ttop\t977\t977\t17\t0xABC\tAF_INET\tSTREAM\tTCP\t127.0.0.1\t59182\t127.0.0.1\t3333\tESTABLISHED\t-\n\
             4026531840\tlibuv-worker\t977\t978\t17\t0xABC\tAF_INET\tSTREAM\tTCP\t127.0.0.1\t59182\t127.0.0.1\t3333\tESTABLISHED\t-\n\
             4026531840\tlibuv-worker\t977\t979\t17\t0xABC\tAF_INET\tSTREAM\tTCP\t127.0.0.1\t59182\t127.0.0.1\t3333\tESTABLISHED\t-\n",
            header()
        );
        std::fs::write(mem_dir.join("output-sockstat"), sockstat).expect("write");

        let analysis = analyze_hidden_processes(dir.path());
        assert_eq!(analysis.hidden_pids, vec![977]);
        assert_eq!(analysis.findings.len(), 1);

        let finding = &analysis.findings[0];
        assert_eq!(finding.pid, 977);
        assert_eq!(finding.process_name.as_deref(), Some("top"));
        // Should surface "libuv-worker" as a thread name — the XMRig indicator
        assert!(
            finding.thread_names.contains(&"libuv-worker".to_string()),
            "expected libuv-worker in thread_names: {:?}",
            finding.thread_names
        );
        assert_eq!(finding.connections.len(), 3);
        // All connections are to localhost:3333 (Stratum mining tunnel)
        assert!(finding.connections.iter().all(|c| c.dst_port == Some(3333)));
    }

    // ── Gap 2 RED: detect_shell_upgrade_chain ──────────────────────────────

    #[test]
    fn shell_upgrade_chain_empty_input_returns_empty() {
        let analysis = HiddenProcessAnalysis::default();
        assert!(detect_shell_upgrade_chain(&analysis).is_empty());
    }

    #[test]
    fn shell_upgrade_chain_single_process_no_chain() {
        // One hidden process with connections — not a chain
        let dir = tempfile::tempdir().expect("tmpdir");
        let proc_dir = dir.path().join("live_response/process");
        std::fs::create_dir_all(&proc_dir).expect("mkdir");
        std::fs::write(proc_dir.join("hidden_pids_for_ps_command.txt"), "939\n").expect("write");

        let mem_dir = dir.path().join("memory_dump");
        std::fs::create_dir_all(&mem_dir).expect("mkdir");
        let sockstat = format!(
            "{}\
             4026531840\tsh\t939\t939\t0\t0xABC\tAF_INET\tSTREAM\tTCP\t192.168.4.22\t22\t192.168.4.35\t48411\tESTABLISHED\t-\n",
            header()
        );
        std::fs::write(mem_dir.join("output-sockstat"), sockstat).expect("write");
        let analysis = analyze_hidden_processes(dir.path());
        assert!(detect_shell_upgrade_chain(&analysis).is_empty(), "single process is not a chain");
    }

    #[test]
    fn shell_upgrade_chain_detected_for_sh_python_bash_on_same_endpoint() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let proc_dir = dir.path().join("live_response/process");
        std::fs::create_dir_all(&proc_dir).expect("mkdir");
        std::fs::write(
            proc_dir.join("hidden_pids_for_ps_command.txt"),
            "939\n940\n941\n",
        ).expect("write");

        let mem_dir = dir.path().join("memory_dump");
        std::fs::create_dir_all(&mem_dir).expect("mkdir");
        let sockstat = format!(
            "{}\
             4026531840\tsh\t939\t939\t0\t0xABC\tAF_INET\tSTREAM\tTCP\t192.168.4.22\t22\t192.168.4.35\t48411\tESTABLISHED\t-\n\
             4026531840\tpython3\t940\t940\t0\t0xABC\tAF_INET\tSTREAM\tTCP\t192.168.4.22\t22\t192.168.4.35\t48411\tESTABLISHED\t-\n\
             4026531840\tbash\t941\t941\t8\t0xABC\tAF_INET\tSTREAM\tTCP\t192.168.4.22\t22\t192.168.4.35\t48411\tESTABLISHED\t-\n",
            header()
        );
        std::fs::write(mem_dir.join("output-sockstat"), sockstat).expect("write");
        let analysis = analyze_hidden_processes(dir.path());

        let chains = detect_shell_upgrade_chain(&analysis);
        assert_eq!(chains.len(), 1, "sh→python3→bash on same endpoint is one chain");
        let chain = &chains[0];
        assert!(chain.pids.contains(&939));
        assert!(chain.pids.contains(&940));
        assert!(chain.pids.contains(&941));
        assert!(chain.process_names.iter().any(|n| n == "sh"));
        assert!(chain.process_names.iter().any(|n| n == "python3"));
        assert!(chain.process_names.iter().any(|n| n == "bash"));
        // Shared endpoint should be the attacker IP:port
        assert!(chain.shared_endpoint.contains("192.168.4.35"));
    }

    #[test]
    fn shell_upgrade_chain_miner_processes_not_detected_as_chain() {
        // XMRig processes on port 3333 are NOT a shell upgrade chain
        let dir = tempfile::tempdir().expect("tmpdir");
        let proc_dir = dir.path().join("live_response/process");
        std::fs::create_dir_all(&proc_dir).expect("mkdir");
        std::fs::write(proc_dir.join("hidden_pids_for_ps_command.txt"), "977\n").expect("write");
        let mem_dir = dir.path().join("memory_dump");
        std::fs::create_dir_all(&mem_dir).expect("mkdir");
        let sockstat = format!(
            "{}\
             4026531840\ttop\t977\t977\t17\t0xABC\tAF_INET\tSTREAM\tTCP\t127.0.0.1\t59182\t127.0.0.1\t3333\tESTABLISHED\t-\n\
             4026531840\tlibuv-worker\t977\t978\t17\t0xABC\tAF_INET\tSTREAM\tTCP\t127.0.0.1\t59182\t127.0.0.1\t3333\tESTABLISHED\t-\n",
            header()
        );
        std::fs::write(mem_dir.join("output-sockstat"), sockstat).expect("write");
        let analysis = analyze_hidden_processes(dir.path());
        // libuv-worker is not a shell/interpreter
        assert!(detect_shell_upgrade_chain(&analysis).is_empty(), "miner threads are not a shell upgrade chain");
    }

    #[test]
    fn shell_upgrade_chain_separate_endpoints_separate_chains() {
        // Two independent shell upgrade chains on different endpoints
        let dir = tempfile::tempdir().expect("tmpdir");
        let proc_dir = dir.path().join("live_response/process");
        std::fs::create_dir_all(&proc_dir).expect("mkdir");
        std::fs::write(
            proc_dir.join("hidden_pids_for_ps_command.txt"),
            "100\n101\n200\n201\n",
        ).expect("write");
        let mem_dir = dir.path().join("memory_dump");
        std::fs::create_dir_all(&mem_dir).expect("mkdir");
        let sockstat = format!(
            "{}\
             4026531840\tsh\t100\t100\t0\t0xABC\tAF_INET\tSTREAM\tTCP\t10.0.0.1\t22\t10.0.0.2\t9000\tESTABLISHED\t-\n\
             4026531840\tbash\t101\t101\t0\t0xABC\tAF_INET\tSTREAM\tTCP\t10.0.0.1\t22\t10.0.0.2\t9000\tESTABLISHED\t-\n\
             4026531840\tsh\t200\t200\t0\t0xDEF\tAF_INET\tSTREAM\tTCP\t10.0.0.1\t22\t10.0.0.3\t9001\tESTABLISHED\t-\n\
             4026531840\tbash\t201\t201\t0\t0xDEF\tAF_INET\tSTREAM\tTCP\t10.0.0.1\t22\t10.0.0.3\t9001\tESTABLISHED\t-\n",
            header()
        );
        std::fs::write(mem_dir.join("output-sockstat"), sockstat).expect("write");
        let analysis = analyze_hidden_processes(dir.path());
        let chains = detect_shell_upgrade_chain(&analysis);
        assert_eq!(chains.len(), 2, "two separate endpoints → two chains");
    }

    // ── existing test ───────────────────────────────────────────────────────

    #[test]
    fn analyze_ssh_reverse_shell_chain() {
        // Reproduces the CTF attack chain: sh→python3→bash all on same socket.
        let dir = tempfile::tempdir().expect("tmpdir");

        let proc_dir = dir.path().join("live_response/process");
        std::fs::create_dir_all(&proc_dir).expect("mkdir");
        std::fs::write(
            proc_dir.join("hidden_pids_for_ps_command.txt"),
            "939\n940\n941\n",
        )
        .expect("write");

        let mem_dir = dir.path().join("memory_dump");
        std::fs::create_dir_all(&mem_dir).expect("mkdir");
        let sockstat = format!(
            "{}\
             4026531840\tsh\t939\t939\t0\t0xABC\tAF_INET\tSTREAM\tTCP\t192.168.4.22\t22\t192.168.4.35\t48411\tESTABLISHED\t-\n\
             4026531840\tpython3\t940\t940\t0\t0xABC\tAF_INET\tSTREAM\tTCP\t192.168.4.22\t22\t192.168.4.35\t48411\tESTABLISHED\t-\n\
             4026531840\tbash\t941\t941\t8\t0xABC\tAF_INET\tSTREAM\tTCP\t192.168.4.22\t22\t192.168.4.35\t48411\tESTABLISHED\t-\n",
            header()
        );
        std::fs::write(mem_dir.join("output-sockstat"), sockstat).expect("write");

        let analysis = analyze_hidden_processes(dir.path());
        assert_eq!(analysis.hidden_pids.len(), 3);
        assert_eq!(analysis.findings.len(), 3);

        // python3 is the pty.spawn process
        let py = analysis.findings.iter().find(|f| f.pid == 940).unwrap();
        assert_eq!(py.process_name.as_deref(), Some("python3"));
        assert!(py.connections.iter().all(|c| c.dst_port == Some(48411)));
    }
}
