//! `rt analyse` — rapid triage of a UAC or supported collection.
//!
//! Extracts the collection, runs all parsers, and emits a structured IR
//! summary covering rootkit indicators, hidden processes (correlated with
//! memory), network anomalies, and a plain-English attack narrative.

use std::path::Path;

use colored::Colorize;
use issen_evtx;
use issen_parser_uac::parsers::{
    self,
    rootkit::{RootkitFinding, RootkitSeverity},
    HiddenProcessAnalysis,
};
use issen_unpack::CollectionProvider as _;

/// Triage verdict for a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// No indicators of compromise found.
    Clean,
    /// Low-confidence indicators (e.g. unknown library in ld.so.preload).
    Suspicious,
    /// High-confidence indicators — one strong signal or hidden process.
    LikelyCompromised,
    /// Multiple independent critical signals confirm compromise.
    Confirmed,
}

/// Compute a triage-level verdict from available findings.
///
/// Not a replacement for the forensicnomicon scoring engine — this is
/// a quick "is this host compromised?" call for the analyst banner.
pub fn compute_verdict(
    rootkit_findings: &[RootkitFinding],
    hidden: &HiddenProcessAnalysis,
    _correlation_findings: &[issen_correlation::model::Finding],
) -> Verdict {
    let critical_count = rootkit_findings
        .iter()
        .filter(|f| f.severity == RootkitSeverity::Critical)
        .count();
    let has_hidden = !hidden.hidden_pids.is_empty();

    if critical_count >= 2 || (critical_count >= 1 && has_hidden) {
        Verdict::Confirmed
    } else if critical_count >= 1 || has_hidden {
        Verdict::LikelyCompromised
    } else if !rootkit_findings.is_empty() {
        Verdict::Suspicious
    } else {
        Verdict::Clean
    }
}

/// Run the analyse command against `collection_path`.
///
/// # Errors
///
/// Returns an error string if the collection cannot be opened or parsed.
pub fn run(collection_path: &Path) -> anyhow::Result<()> {
    // ── 1. Open the collection ────────────────────────────────────────────
    let provider = issen_parser_uac::UacProvider;
    let manifest = provider
        .open(collection_path)
        .map_err(|e| anyhow::anyhow!("Failed to open collection: {e}"))?;

    let root = &manifest.extracted_root;
    let hostname = manifest.metadata.hostname.as_deref().unwrap_or("(unknown)");
    let collected_at = manifest.metadata.collection_time.map_or_else(
        || "(unknown)".to_string(),
        |t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
    );

    println!(
        "{}",
        "╔══════════════════════════════════════════════════════════╗"
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "║  Issen — UAC Collection Analysis                   ║"
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════════════╝"
            .bold()
            .cyan()
    );
    println!();
    println!("  Collection : {}", collection_path.display());
    println!("  Host       : {hostname}");
    println!("  Collected  : {collected_at}");
    println!("  Format     : {}", manifest.format_name);
    println!();

    // ── 2. Rootkit indicators + 3. Hidden processes (computed once) ───────
    let rootkit_findings = parsers::rootkit::scan_rootkit_indicators(root);
    let hidden = parsers::analyze_hidden_processes(root);
    let critical_rk: Vec<_> = rootkit_findings
        .iter()
        .filter(|f| f.severity == RootkitSeverity::Critical)
        .collect();
    let warn_rk: Vec<_> = rootkit_findings
        .iter()
        .filter(|f| f.severity == RootkitSeverity::Warning)
        .collect();

    // Verdict banner — shown before section details
    {
        let verdict = compute_verdict(&rootkit_findings, &hidden, &[]);
        let colored_label: colored::ColoredString = match verdict {
            Verdict::Clean => "CLEAN".green().bold(),
            Verdict::Suspicious => "SUSPICIOUS".yellow().bold(),
            Verdict::LikelyCompromised => "LIKELY COMPROMISED".red().bold(),
            Verdict::Confirmed => "CONFIRMED COMPROMISE".red().bold().underline(),
        };
        let banner = match verdict {
            Verdict::Clean => "No indicators of compromise detected.",
            Verdict::Suspicious => "Low-confidence indicators — warrant investigation.",
            Verdict::LikelyCompromised => "High-confidence indicators of active compromise.",
            Verdict::Confirmed => "Multiple independent critical signals confirm compromise.",
        };
        println!(
            "{}",
            "┌─ VERDICT ─────────────────────────────────────────────".bold()
        );
        println!("│  [{colored_label}] {banner}");
        println!();
    }

    println!(
        "{}",
        "┌─ ROOTKIT INDICATORS ──────────────────────────────────".bold()
    );
    if rootkit_findings.is_empty() {
        println!("│  None detected.");
    } else {
        for f in &critical_rk {
            println!(
                "│  [{}] {} — {}",
                "CRITICAL".red().bold(),
                f.check,
                f.evidence
            );
            println!("│             {}", f.description);
        }
        for f in &warn_rk {
            println!(
                "│  [{}]  {} — {}",
                "WARNING".yellow().bold(),
                f.check,
                f.evidence
            );
        }
        for f in rootkit_findings
            .iter()
            .filter(|f| f.severity == RootkitSeverity::Info)
        {
            println!("│  [{}]     {} — {}", "INFO".cyan(), f.check, f.evidence);
        }
    }
    println!();

    println!(
        "{}",
        "┌─ HIDDEN PROCESSES (ps/top blind-spot) ─────────────────".bold()
    );
    if hidden.hidden_pids.is_empty() {
        println!("│  None detected (or collection predates UAC hidden-PID check).");
    } else {
        println!(
            "│  {} PID(s) visible in /proc but absent from ps:",
            hidden.hidden_pids.len().to_string().yellow().bold()
        );
        println!();
        for finding in &hidden.findings {
            let name = finding
                .process_name
                .as_deref()
                .unwrap_or("(name unknown — no memory dump)");
            println!(
                "│  {} {:6}  {}",
                "PID".bold(),
                finding.pid.to_string().bold(),
                name.yellow()
            );

            // Prefer all_thread_names (process + threads) when available, fall
            // back to thread_names for backward compat with old collections.
            let display_names = if finding.all_thread_names.is_empty() {
                finding.thread_names.clone()
            } else {
                finding.all_thread_names.clone()
            };
            if !display_names.is_empty() {
                println!("│           Names: {}", display_names.join(", "));
            }

            // Deduplicate connections for display.
            let mut seen = std::collections::HashSet::new();
            for conn in &finding.connections {
                let key = format!(
                    "{}:{} → {}:{}",
                    conn.src_addr,
                    conn.src_port.map_or("?".to_string(), |p| p.to_string()),
                    conn.dst_addr,
                    conn.dst_port.map_or("?".to_string(), |p| p.to_string()),
                );
                if seen.insert(key.clone()) {
                    println!("│           {} [{}]  ({})", key, conn.state, conn.proto);
                }
            }

            if !finding.unix_socket_paths.is_empty() {
                println!(
                    "│           Unix sockets: {}",
                    finding.unix_socket_paths.join(", ")
                );
            }
            if finding.desktop_masquerade {
                println!("│           {} desktop masquerade — process emulates desktop profile via system-daemon sockets",
                    "[!]".yellow().bold());
            }
            println!("│");
        }

        // Gap 2: shell upgrade chain detection
        let chains = parsers::detect_shell_upgrade_chain(&hidden);
        if !chains.is_empty() {
            println!("│");
            println!(
                "│  {} SHELL UPGRADE CHAIN(S) DETECTED:",
                "[!]".yellow().bold()
            );
            for chain in &chains {
                println!(
                    "│      PIDs {} on {} — {}",
                    chain
                        .pids
                        .iter()
                        .map(std::string::ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("+"),
                    chain.shared_endpoint,
                    chain.process_names.join(" → "),
                );
            }
        }
    }
    println!();

    // ── 4. Network connections ────────────────────────────────────────────
    let net_dir = root.join("live_response/network");
    let net_conns = if net_dir.is_dir() {
        parsers::network::parse_network_dir(&net_dir)
    } else {
        vec![]
    };
    let established: Vec<_> = net_conns
        .iter()
        .filter(|c| {
            c.state.eq_ignore_ascii_case("ESTAB") || c.state.eq_ignore_ascii_case("ESTABLISHED")
        })
        .collect();

    println!(
        "{}",
        "┌─ NETWORK (visible to userspace) ───────────────────────".bold()
    );
    if established.is_empty() {
        println!("│  No established TCP connections found.");
    } else {
        // Deduplicate across numeric (ss -n) and service-name (ss) outputs.
        // Key on normalised addrs so :22 and :ssh collapse to the same entry.
        let mut seen_net: std::collections::HashSet<String> = std::collections::HashSet::new();
        for c in &established {
            let key = format!(
                "{}|{}|{:?}",
                normalize_port_names(&c.local_addr),
                normalize_port_names(&c.remote_addr),
                c.pid,
            );
            if !seen_net.insert(key) {
                continue;
            }
            let pid_prog = match (c.pid, c.program.as_deref()) {
                (Some(p), Some(n)) => format!("  pid={p} ({n})"),
                (Some(p), None) => format!("  pid={p}"),
                _ => String::new(),
            };
            println!("│  {} → {}{}", c.local_addr, c.remote_addr, pid_prog);
        }
    }
    println!();

    // ── 5. CPU anomaly ────────────────────────────────────────────────────
    let top_path = root.join("live_response/process/top_-b_-n1.txt");
    let cpu_user_pct: Option<f32> = std::fs::read_to_string(&top_path).ok().and_then(|c| {
        c.lines()
            .find(|l| l.contains("%Cpu") || l.contains("Cpu(s)"))
            .and_then(|line| {
                // "%Cpu(s): 97.7 us,  2.3 sy, ..."  or  "%Cpu(s):  97.7 us, ..."
                line.split_once(':')
                    .and_then(|(_, rest)| rest.trim().split(',').next())
                    .and_then(|tok| tok.split_whitespace().next())
                    .and_then(|n| n.parse::<f32>().ok())
            })
    });
    if let Some(pct) = cpu_user_pct {
        let top_content = std::fs::read_to_string(&top_path).unwrap_or_default();
        if let Some(cpu_line) = top_content
            .lines()
            .find(|l| l.contains("%Cpu") || l.contains("Cpu(s)"))
        {
            println!(
                "{}",
                "┌─ CPU ───────────────────────────────────────────────────".bold()
            );
            println!("│  {}", cpu_line.trim());
            if pct >= 90.0 {
                println!(
                    "│  {} Near-100% CPU with no visible process — miner likely hidden by rootkit.",
                    "^ WARNING:".yellow().bold()
                );
            }
            println!();
        }
    }

    // ── 6. Pivot rule findings + narrative ────────────────────────────────
    let correlation_findings =
        super::pivot::evaluate_correlation(&rootkit_findings, &hidden, &net_conns, cpu_user_pct)
            .unwrap_or_else(|e| {
                tracing::warn!("Pivot rule evaluation failed: {e}");
                Vec::new()
            });

    if !correlation_findings.is_empty() {
        println!(
            "{}",
            "┌─ CORRELATION FINDINGS ──────────────────────────────────".bold()
        );
        for f in &correlation_findings {
            let sev = f.severity.to_uppercase();
            let severity_label: colored::ColoredString = match sev.as_str() {
                "CRITICAL" => sev.red().bold(),
                "HIGH" => sev.red(),
                "MEDIUM" => sev.yellow().bold(),
                "LOW" => sev.yellow(),
                _ => sev.cyan(),
            };
            println!("│  [{}] {}", severity_label, f.title);
            println!("│         Rule : {}", f.rule_id);
            if f.evidence_rendered.is_empty() {
                println!("│         Evidence : {}", f.evidence_ids.join(", "));
            } else {
                for line in &f.evidence_rendered {
                    println!("│           • {line}");
                }
            }
            println!("│");
        }
        println!();
    }

    // ── 7. Attack narrative ───────────────────────────────────────────────
    build_narrative(&correlation_findings);
    println!();

    // ── 7. Preloaded library provenance check ─────────────────────────────
    // Read ld.so.preload paths and flag any library not in a standard system
    // library directory — provenance-based detection replaces name matching.
    let ld_preload_content_path = root.join("chkrootkit/etc_ld_so_preload.txt");
    let preloaded_paths: Vec<String> = std::fs::read_to_string(&ld_preload_content_path)
        .map(|c| parsers::rootkit::ld_so_preload_paths(&c))
        .unwrap_or_default();

    let hash_dir = root.join("hash_executables");
    if hash_dir.is_dir() || !preloaded_paths.is_empty() {
        let hashes = if hash_dir.is_dir() {
            parsers::hash_execs::parse_hash_dir(&hash_dir)
        } else {
            vec![]
        };
        let preloaded_hashes =
            parsers::hash_execs::find_preloaded_executables(&preloaded_paths, &hashes);
        let unpackaged_paths = parsers::packages::find_unpackaged_paths(&preloaded_paths);

        if !preloaded_hashes.is_empty() || !unpackaged_paths.is_empty() {
            println!(
                "{}",
                "┌─ SUSPICIOUS PRELOADED LIBRARIES ───────────────────────".bold()
            );
            for h in &preloaded_hashes {
                let algo = match h.hash.len() {
                    32 => "MD5",
                    40 => "SHA1",
                    64 => "SHA256",
                    _ => "hash",
                };
                let provenance =
                    if parsers::packages::find_unpackaged_paths(std::slice::from_ref(&h.path))
                        .is_empty()
                    {
                        "system path"
                    } else {
                        "UNPACKAGED"
                    };
                let prov_label: colored::ColoredString = if provenance == "UNPACKAGED" {
                    provenance.red().bold()
                } else {
                    provenance.normal()
                };
                println!("│  [{}] {} — {}: {}", prov_label, h.path, algo, h.hash);
            }
            // Preloaded paths with no hash entry (not in hash_executables)
            for p in &unpackaged_paths {
                if !preloaded_hashes.iter().any(|h| &h.path == p) {
                    println!("│  [UNPACKAGED, no hash] {p}");
                }
            }
            println!();
        }
    }

    // ── EVTX Session Correlation ──────────────────────────────────────────
    let evtx_files = issen_evtx::find_evtx_files(root);
    if !evtx_files.is_empty() {
        println!(
            "{}",
            "┌─ WINDOWS EVENT LOG SESSIONS ───────────────────────────────".bold()
        );
        match issen_evtx::analyse_evtx_sessions(&evtx_files) {
            Ok(summary) => {
                println!("│  EVTX files : {}", evtx_files.len());
                println!("│  Sessions   : {}", summary.session_count);
                if summary.lateral_movement_count > 0 {
                    println!(
                        "│  [!] Lateral movement candidates: {}",
                        summary.lateral_movement_count
                    );
                    for lm in &summary.lateral_movements {
                        println!("│      {} — {}", lm.src_ip.yellow(), lm.reason);
                    }
                }
            }
            Err(e) => println!("│  [WARN] EVTX analysis failed: {e}"),
        }
        println!();
    }

    println!(
        "{}",
        "═══════════════════════════════════════════════════════════"
            .bold()
            .cyan()
    );
    println!("{}", "  Issen analysis complete.".bold());
    println!(
        "{}",
        "═══════════════════════════════════════════════════════════"
            .bold()
            .cyan()
    );

    Ok(())
}

fn build_narrative(findings: &[issen_correlation::model::Finding]) {
    if findings.is_empty() {
        return;
    }
    println!(
        "{}",
        "┌─ NARRATIVE ────────────────────────────────────────────────".bold()
    );
    for (i, f) in findings.iter().enumerate() {
        let num = i + 1;
        if let Some(s) = &f.summary {
            println!("│  {num}. {s}");
        } else {
            println!("│  {num}. {} [{}]", f.title, f.severity);
        }
        if let Some(e) = &f.explanation {
            for line in wrap_text(e, 68) {
                println!("│       {line}");
            }
            println!("│");
        }
    }
}

fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.len() + 1 + word.len() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(current.clone());
            current = word.to_string();
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// Replace well-known service names in an addr string with port numbers
/// so `:ssh` and `:22` produce the same dedup key.
fn normalize_port_names(addr: &str) -> String {
    const MAP: &[(&str, &str)] = &[
        (":ssh", ":22"),
        (":http", ":80"),
        (":https", ":443"),
        (":bootpc", ":68"),
        (":bootps", ":67"),
        (":domain", ":53"),
        (":ftp", ":21"),
        (":smtp", ":25"),
    ];
    let mut s = addr.to_string();
    for (name, num) in MAP {
        if s.ends_with(name) {
            s = format!("{}{}", &s[..s.len() - name.len()], num);
            break;
        }
    }
    s
}

// ── STORAGE MEDIUM BREAKDOWN ──────────────────────────────────────────────────

/// Counts of timeline events grouped by `drive_type:*` tag.
#[allow(dead_code)] // built-but-unwired storage-medium breakdown; kept for future wiring
pub struct DriveBreakdown {
    pub fixed: usize,
    pub removable: usize,
    pub network: usize,
    pub unknown: usize,
}

#[allow(dead_code)] // built-but-unwired storage-medium breakdown methods
impl DriveBreakdown {
    /// Total events across all drive types.
    pub fn total(&self) -> usize {
        self.fixed + self.removable + self.network + self.unknown
    }

    /// Returns `true` if any removable/USB events are present.
    pub fn has_removable(&self) -> bool {
        self.removable > 0
    }

    /// Returns `true` if any network drive events are present.
    pub fn has_network(&self) -> bool {
        self.network > 0
    }

    /// Render the STORAGE MEDIUM BREAKDOWN section for display.
    pub fn render(&self) -> String {
        let removable_suffix = if self.has_removable() {
            "  \u{2190} potential exfiltration"
        } else {
            ""
        };
        format!(
            "\u{250c}\u{2500} STORAGE MEDIUM BREAKDOWN \u{2500}{bar}\n\
             \u{2502}  Fixed disk:    {fixed:>4} events\n\
             \u{2502}  Removable/USB: {removable:>4} events{removable_suffix}\n\
             \u{2502}  Network:       {network:>4} events\n\
             \u{2502}  Unknown:       {unknown:>4} events\n\
             \u{2502}  Total:         {total:>4} LNK events",
            bar = "\u{2500}".repeat(21),
            fixed = self.fixed,
            removable = self.removable,
            removable_suffix = removable_suffix,
            network = self.network,
            unknown = self.unknown,
            total = self.total(),
        )
    }
}

/// Aggregate timeline events by `drive_type:*` tag and return a [`DriveBreakdown`].
#[allow(dead_code)] // built-but-unwired storage-medium breakdown helper
pub fn drive_breakdown(events: &[issen_core::timeline::event::TimelineEvent]) -> DriveBreakdown {
    DriveBreakdown {
        fixed: events
            .iter()
            .filter(|e| e.tags.iter().any(|t| t == "drive_type:fixed"))
            .count(),
        removable: events
            .iter()
            .filter(|e| e.tags.iter().any(|t| t == "drive_type:removable"))
            .count(),
        network: events
            .iter()
            .filter(|e| e.tags.iter().any(|t| t == "drive_type:network"))
            .count(),
        unknown: events
            .iter()
            .filter(|e| !e.tags.iter().any(|t| t.starts_with("drive_type:")))
            .count(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use issen_parser_uac::parsers::{
        rootkit::{RootkitFinding, RootkitSeverity},
        HiddenProcessAnalysis,
    };

    fn critical_rk(check: &str) -> RootkitFinding {
        RootkitFinding {
            severity: RootkitSeverity::Critical,
            check: check.to_string(),
            description: "test".to_string(),
            evidence: "test".to_string(),
        }
    }

    fn warning_rk() -> RootkitFinding {
        RootkitFinding {
            severity: RootkitSeverity::Warning,
            check: "ld_preload".to_string(),
            description: "test".to_string(),
            evidence: "/usr/lib/libunknown.so".to_string(),
        }
    }

    fn hidden_with_pids(pids: &[u32]) -> HiddenProcessAnalysis {
        HiddenProcessAnalysis {
            hidden_pids: pids.to_vec(),
            findings: vec![],
        }
    }

    // ── Gap 4 RED: compute_verdict ──────────────────────────────────────────

    #[test]
    fn verdict_clean_when_no_findings() {
        let v = compute_verdict(&[], &HiddenProcessAnalysis::default(), &[]);
        assert_eq!(v, Verdict::Clean);
    }

    #[test]
    fn verdict_suspicious_with_warning_rootkit_only() {
        let v = compute_verdict(&[warning_rk()], &HiddenProcessAnalysis::default(), &[]);
        assert_eq!(v, Verdict::Suspicious);
    }

    #[test]
    fn verdict_likely_compromised_with_critical_rootkit() {
        let v = compute_verdict(
            &[critical_rk("ld_preload")],
            &HiddenProcessAnalysis::default(),
            &[],
        );
        assert_eq!(v, Verdict::LikelyCompromised);
    }

    #[test]
    fn verdict_confirmed_with_critical_rootkit_and_hidden_processes() {
        let rk = vec![critical_rk("ld_preload")];
        let hidden = hidden_with_pids(&[977]);
        let v = compute_verdict(&rk, &hidden, &[]);
        assert_eq!(v, Verdict::Confirmed);
    }

    #[test]
    fn verdict_confirmed_with_multiple_critical_rootkit_signals() {
        let rk = vec![critical_rk("ld_preload"), critical_rk("kernel_module")];
        let v = compute_verdict(&rk, &HiddenProcessAnalysis::default(), &[]);
        assert_eq!(v, Verdict::Confirmed);
    }

    #[test]
    fn verdict_likely_compromised_with_hidden_pids_only() {
        let hidden = hidden_with_pids(&[939]);
        let v = compute_verdict(&[], &hidden, &[]);
        assert_eq!(v, Verdict::LikelyCompromised);
    }
}
