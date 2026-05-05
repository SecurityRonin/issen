//! `rt analyse` — rapid triage of a UAC or supported collection.
//!
//! Extracts the collection, runs all parsers, and emits a structured IR
//! summary covering rootkit indicators, hidden processes (correlated with
//! memory), network anomalies, and a plain-English attack narrative.

use std::path::Path;

use rt_parser_uac::parsers::{self, rootkit::RootkitSeverity};
use rt_unpack::CollectionProvider as _;
use rt_evtx;

/// Run the analyse command against `collection_path`.
///
/// # Errors
///
/// Returns an error string if the collection cannot be opened or parsed.
pub fn run(collection_path: &Path) -> anyhow::Result<()> {
    // ── 1. Open the collection ────────────────────────────────────────────
    let provider = rt_parser_uac::UacProvider;
    let manifest = provider
        .open(collection_path)
        .map_err(|e| anyhow::anyhow!("Failed to open collection: {e}"))?;

    let root = &manifest.extracted_root;
    let hostname = manifest.metadata.hostname.as_deref().unwrap_or("(unknown)");
    let collected_at = manifest
        .metadata
        .collection_time
        .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "(unknown)".to_string());

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  RapidTriage — UAC Collection Analysis                   ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Collection : {}", collection_path.display());
    println!("  Host       : {hostname}");
    println!("  Collected  : {collected_at}");
    println!("  Format     : {}", manifest.format_name);
    println!();

    // ── 2. Rootkit indicators ─────────────────────────────────────────────
    let rootkit_findings = parsers::rootkit::scan_rootkit_indicators(root);
    let critical_rk: Vec<_> = rootkit_findings
        .iter()
        .filter(|f| f.severity == RootkitSeverity::Critical)
        .collect();
    let warn_rk: Vec<_> = rootkit_findings
        .iter()
        .filter(|f| f.severity == RootkitSeverity::Warning)
        .collect();

    println!("┌─ ROOTKIT INDICATORS ──────────────────────────────────");
    if rootkit_findings.is_empty() {
        println!("│  None detected.                                          │");
    } else {
        for f in &critical_rk {
            println!("│  [CRITICAL] {} — {}", f.check, f.evidence);
            println!("│             {}", f.description);
        }
        for f in &warn_rk {
            println!("│  [WARNING]  {} — {}", f.check, f.evidence);
        }
        for f in rootkit_findings
            .iter()
            .filter(|f| f.severity == RootkitSeverity::Info)
        {
            println!("│  [INFO]     {} — {}", f.check, f.evidence);
        }
    }
    println!();

    // ── 3. Hidden process analysis ────────────────────────────────────────
    let hidden = parsers::analyze_hidden_processes(root);

    println!("┌─ HIDDEN PROCESSES (ps/top blind-spot) ─────────────────");
    if hidden.hidden_pids.is_empty() {
        println!("│  None detected (or collection predates UAC hidden-PID check).");
    } else {
        println!(
            "│  {} PID(s) visible in /proc but absent from ps:",
            hidden.hidden_pids.len()
        );
        println!();
        for finding in &hidden.findings {
            let name = finding
                .process_name
                .as_deref()
                .unwrap_or("(name unknown — no memory dump)");
            println!("│  PID {:6}  {}", finding.pid, name);

            // Prefer all_thread_names (process + threads) when available, fall
            // back to thread_names for backward compat with old collections.
            let display_names = if !finding.all_thread_names.is_empty() {
                finding.all_thread_names.clone()
            } else {
                finding.thread_names.clone()
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
            println!("│");
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

    println!("┌─ NETWORK (visible to userspace) ───────────────────────");
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
                    .and_then(|tok| tok.trim().split_whitespace().next())
                    .and_then(|n| n.parse::<f32>().ok())
            })
    });
    if let Some(pct) = cpu_user_pct {
        let top_content = std::fs::read_to_string(&top_path).unwrap_or_default();
        if let Some(cpu_line) = top_content
            .lines()
            .find(|l| l.contains("%Cpu") || l.contains("Cpu(s)"))
        {
            println!("┌─ CPU ───────────────────────────────────────────────────");
            println!("│  {}", cpu_line.trim());
            if pct >= 90.0 {
                println!("│  ^ WARNING: Near-100% CPU with no visible process — miner likely hidden by rootkit.");
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
        println!("┌─ CORRELATION FINDINGS ──────────────────────────────────");
        for f in &correlation_findings {
            let severity_label = f.severity.to_uppercase();
            println!("│  [{severity_label}] {}", f.title);
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

    // ── 7. Hashed executables suspicious check ────────────────────────────
    let hash_dir = root.join("hash_executables");
    if hash_dir.is_dir() {
        let hashes = parsers::hash_execs::parse_hash_dir(&hash_dir);
        // Flag any library in lib path that is NOT from a known package.
        // Deduplicate by path, preferring SHA1 (40 hex chars) over MD5/SHA256.
        let mut best: std::collections::HashMap<String, &parsers::hash_execs::HashedExecutable> =
            std::collections::HashMap::new();
        for h in &hashes {
            let p = h.path.to_lowercase();
            if p.contains(".so")
                && (p.contains("libymv") || p.contains("libhide") || p.contains("libproc"))
            {
                let entry = best.entry(h.path.clone()).or_insert(h);
                // Prefer SHA1 (40 chars) over MD5 (32) or SHA256 (64).
                if h.hash.len() == 40 && entry.hash.len() != 40 {
                    *entry = h;
                }
            }
        }
        if !best.is_empty() {
            let mut suspicious_libs: Vec<_> = best.values().collect();
            suspicious_libs.sort_by_key(|h| &h.path);
            println!("┌─ SUSPICIOUS EXECUTABLES ───────────────────────────────");
            for h in &suspicious_libs {
                let algo = match h.hash.len() {
                    32 => "MD5",
                    40 => "SHA1",
                    64 => "SHA256",
                    _ => "hash",
                };
                println!("│  {} — {}: {}", h.path, algo, h.hash);
            }
            println!();
        }
    }

    // ── EVTX Session Correlation ──────────────────────────────────────────
    let evtx_files = rt_evtx::find_evtx_files(root);
    if !evtx_files.is_empty() {
        println!("┌─ WINDOWS EVENT LOG SESSIONS ───────────────────────────────");
        match rt_evtx::analyse_evtx_sessions(&evtx_files) {
            Ok(summary) => {
                println!("│  EVTX files : {}", evtx_files.len());
                println!("│  Sessions   : {}", summary.session_count);
                if summary.lateral_movement_count > 0 {
                    println!(
                        "│  [!] Lateral movement candidates: {}",
                        summary.lateral_movement_count
                    );
                    for lm in &summary.lateral_movements {
                        println!("│      {} — {}", lm.src_ip, lm.reason);
                    }
                }
            }
            Err(e) => println!("│  [WARN] EVTX analysis failed: {e}"),
        }
        println!();
    }

    println!("═══════════════════════════════════════════════════════════");
    println!("  RapidTriage analysis complete.");
    println!("═══════════════════════════════════════════════════════════");

    Ok(())
}

fn build_narrative(findings: &[rt_correlation::model::Finding]) {
    if findings.is_empty() {
        return;
    }
    println!("┌─ NARRATIVE ────────────────────────────────────────────────");
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
pub struct DriveBreakdown {
    pub fixed: usize,
    pub removable: usize,
    pub network: usize,
    pub unknown: usize,
}

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
pub fn drive_breakdown(events: &[rt_core::timeline::event::TimelineEvent]) -> DriveBreakdown {
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
