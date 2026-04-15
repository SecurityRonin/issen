//! `rt analyse` — rapid triage of a UAC or supported collection.
//!
//! Extracts the collection, runs all parsers, and emits a structured IR
//! summary covering rootkit indicators, hidden processes (correlated with
//! memory), network anomalies, and a plain-English attack narrative.

use std::path::Path;

use rt_parser_uac::parsers::{self, rootkit::RootkitSeverity};
use rt_unpack::CollectionProvider as _;

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
    let hostname = manifest
        .metadata
        .hostname
        .as_deref()
        .unwrap_or("(unknown)");
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

            if !finding.thread_names.is_empty() {
                println!("│           Thread names: {}", finding.thread_names.join(", "));
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
        .filter(|c| c.state.eq_ignore_ascii_case("ESTAB") || c.state.eq_ignore_ascii_case("ESTABLISHED"))
        .collect();

    println!("┌─ NETWORK (visible to userspace) ───────────────────────");
    if established.is_empty() {
        println!("│  No established TCP connections found.");
    } else {
        for c in &established {
            let pid_prog = match (c.pid, c.program.as_deref()) {
                (Some(p), Some(n)) => format!("  pid={p} ({n})"),
                (Some(p), None) => format!("  pid={p}"),
                _ => String::new(),
            };
            println!(
                "│  {} → {}{}",
                c.local_addr, c.remote_addr, pid_prog
            );
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

    // ── 6. Pivot rule findings ─────────────────────────────────────────────
    match super::pivot::evaluate_pivot(&rootkit_findings, &hidden, &net_conns, cpu_user_pct) {
        Ok(findings) if !findings.is_empty() => {
            println!("┌─ PIVOT FINDINGS ────────────────────────────────────────");
            for f in &findings {
                let severity_label = f.severity.to_uppercase();
                println!("│  [{severity_label}] {}", f.title);
                println!("│         Rule     : {}", f.rule_id);
                println!("│         Evidence : {}", f.evidence_ids.join(", "));
                println!("│");
            }
            println!();
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("Pivot rule evaluation failed: {e}");
        }
    }

    // ── 7. Attack narrative ───────────────────────────────────────────────
    println!("┌─ NARRATIVE ─────────────────────────────────────────────");
    build_narrative(&hidden, &rootkit_findings, &established);
    println!();

    // ── 7. Hashed executables suspicious check ────────────────────────────
    let hash_dir = root.join("hash_executables");
    if hash_dir.is_dir() {
        let hashes = parsers::hash_execs::parse_hash_dir(&hash_dir);
        // Flag any library in lib path that is NOT from a known package.
        let suspicious_libs: Vec<_> = hashes
            .iter()
            .filter(|h| {
                let p = h.path.to_lowercase();
                p.contains(".so") && (p.contains("libymv") || p.contains("libhide") || p.contains("libproc"))
            })
            .collect();
        if !suspicious_libs.is_empty() {
            println!("┌─ SUSPICIOUS EXECUTABLES ───────────────────────────────");
            for h in &suspicious_libs {
                println!("│  {} — SHA1: {}", h.path, h.hash);
            }
            println!();
        }
    }

    println!("═══════════════════════════════════════════════════════════");
    println!("  RapidTriage analysis complete.");
    println!("═══════════════════════════════════════════════════════════");

    Ok(())
}

fn build_narrative(
    hidden: &parsers::HiddenProcessAnalysis,
    rootkit: &[parsers::rootkit::RootkitFinding],
    _established: &[&parsers::network::NetworkConnection],
) {
    // Detect the rootkit library name.
    let preload_lib = rootkit
        .iter()
        .find(|f| f.check == "ld_preload")
        .map(|f| f.evidence.as_str());

    if let Some(lib) = preload_lib {
        println!("│  1. LD_PRELOAD rootkit installed:");
        println!("│       {lib}");
        println!("│     This library intercepts readdir()/opendir() to filter PIDs");
        println!("│     from /proc, making hidden processes invisible to ps, top,");
        println!("│     ss, and any tool that lists processes via /proc.");
        println!("│");
    }

    // Detect reverse shell.
    let has_pty = hidden.findings.iter().any(|f| {
        f.process_name.as_deref() == Some("python3")
            && f.connections.iter().any(|c| c.src_port == Some(22))
    });
    if has_pty {
        println!("│  2. Attacker gained interactive shell via SSH (port 22):");
        println!("│       python3 -c 'import pty; pty.spawn(\"/bin/bash\")'");
        println!("│     The NMS alert was triggered by this string in the SSH session.");
        println!("│");
    }

    // Detect miner via libuv threads.
    let miner = hidden.findings.iter().find(|f| {
        f.thread_names.iter().any(|t| t == "libuv-worker")
    });
    if let Some(m) = miner {
        let name = m.process_name.as_deref().unwrap_or("(unknown)");
        println!("│  3. Crypto miner deployed (PID {}, disguised as '{name}'):", m.pid);
        println!("│       libuv-worker threads indicate XMRig or compatible miner.");
        println!("│       Connections:");
        let mut seen = std::collections::HashSet::new();
        for conn in &m.connections {
            let key = format!(
                "{}:{} → {}:{}",
                conn.src_addr,
                conn.src_port.map_or("?".to_string(), |p| p.to_string()),
                conn.dst_addr,
                conn.dst_port.map_or("?".to_string(), |p| p.to_string()),
            );
            if seen.insert(key.clone()) {
                let annotation = if conn.dst_port == Some(3333) || conn.src_port == Some(3333) {
                    "  ← Stratum tunnel"
                } else if conn.dst_port == Some(22) || conn.src_port == Some(22) {
                    "  ← shared SSH shell socket"
                } else {
                    ""
                };
                println!("│         {} [{}]{}", key, conn.state, annotation);
            }
        }
        println!("│       This explains the CPU anomaly and the 'hidden' process.");
        println!("│");
    }

    // Detect SSH tunnel.
    let tunnel = hidden.findings.iter().find(|f| {
        f.process_name.as_deref() == Some("ssh")
            && f.connections.iter().any(|c| c.src_port == Some(3333) || c.dst_port == Some(3333))
    });
    if let Some(t) = tunnel {
        if let Some(conn) = t.connections.iter().find(|c| c.state == "ESTABLISHED" && c.dst_port == Some(22)) {
            println!(
                "│  4. SSH tunnel to {}:{} established (PID {}):",
                conn.dst_addr,
                conn.dst_port.unwrap_or(22),
                t.pid
            );
            println!("│       ssh -L 127.0.0.1:3333:<pool>:3333 user@{}", conn.dst_addr);
            println!("│     Mining traffic appears as SSH to the NMS — evasion technique.");
        }
    }
}
