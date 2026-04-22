//! Bridge: UAC parser outputs → `rt-correlation` Evidence → Pivot findings.
//!
//! This module converts the structured outputs of `rt-parser-uac` parsers into
//! the neutral [`rt_correlation::model::Evidence`] model, enriches them via
//! `rt_correlation::enrich`, and evaluates the bundled Pivot Rule pack to
//! produce structured [`rt_correlation::model::Finding`]s.
//!
//! The hardcoded narrative strings in `commands/analyse.rs` can then be
//! replaced (or augmented) by these structured findings.

use rt_correlation::engine::CorrelationEngine;
use rt_correlation::enrich::enrich_evidence;
use rt_correlation::model::{Evidence, EvidenceKind, EvidenceSource, Finding, SubjectRef};
use rt_correlation::rules::{bundled_rule_dir, load_rule_pack};
use rt_parser_uac::parsers::{
    network::NetworkConnection, rootkit::RootkitFinding, rootkit::RootkitSeverity,
    HiddenProcessAnalysis,
};

/// Convert UAC parser outputs to Evidence, enrich, and evaluate correlation rules.
///
/// This is the canonical name going forward.  The previous name `evaluate_pivot`
/// is kept as a deprecated alias for backwards compatibility.
///
/// # Errors
///
/// Returns an error if the bundled rule pack cannot be loaded.
pub fn evaluate_correlation(
    rootkit_findings: &[RootkitFinding],
    hidden: &HiddenProcessAnalysis,
    net_conns: &[NetworkConnection],
    cpu_percent_user: Option<f32>,
) -> anyhow::Result<Vec<Finding>> {
    let evidence = build_evidence(rootkit_findings, hidden, net_conns, cpu_percent_user);
    let enriched = enrich_evidence(evidence);
    let rules = load_rule_pack(&bundled_rule_dir())?;
    Ok(CorrelationEngine::default().evaluate(&rules, &enriched))
}

/// Deprecated alias for [`evaluate_correlation`].
///
/// # Errors
///
/// Returns an error if the bundled rule pack cannot be loaded.
#[deprecated(since = "0.1.0", note = "use evaluate_correlation instead")]
#[allow(dead_code)]
pub fn evaluate_pivot(
    rootkit_findings: &[RootkitFinding],
    hidden: &HiddenProcessAnalysis,
    net_conns: &[NetworkConnection],
    cpu_percent_user: Option<f32>,
) -> anyhow::Result<Vec<Finding>> {
    evaluate_correlation(rootkit_findings, hidden, net_conns, cpu_percent_user)
}

/// Build raw (pre-enrichment) Evidence from UAC parser outputs.
#[must_use]
pub fn build_evidence(
    rootkit_findings: &[RootkitFinding],
    hidden: &HiddenProcessAnalysis,
    net_conns: &[NetworkConnection],
    cpu_percent_user: Option<f32>,
) -> Vec<Evidence> {
    let mut out = Vec::new();
    let mut counter = 0u32;
    let mut next_id = move |prefix: &str| -> String {
        counter += 1;
        format!("{prefix}-{counter}")
    };

    // Rootkit indicators → Evidence::Artifact tagged "rootkit_indicator"
    for f in rootkit_findings {
        if f.severity == RootkitSeverity::Critical || f.severity == RootkitSeverity::Warning {
            let ev = Evidence::new(
                next_id("rk"),
                EvidenceSource::Artifact,
                EvidenceKind::Artifact,
                None,
            )
            .with_attr("check", &f.check)
            .with_attr("evidence", &f.evidence)
            .with_tag("rootkit_indicator");
            out.push(ev);
        }
    }

    // Hidden processes → Evidence::Process tagged "hidden_process" per PID
    for finding in &hidden.findings {
        let subject = SubjectRef::Process(finding.pid);
        let name = finding
            .process_name
            .clone()
            .unwrap_or_else(|| "(unknown)".to_string());

        let mut ev = Evidence::new(
            next_id("proc"),
            EvidenceSource::Memory,
            EvidenceKind::Process,
            Some(subject.clone()),
        )
        .with_attr("process_name", &name)
        .with_attr("pid", &finding.pid.to_string())
        .with_tag("hidden_process");

        // If this process has libuv-worker threads → miner indicator
        if finding.thread_names.iter().any(|t| t == "libuv-worker") {
            ev = ev.with_tag("miner_thread");
        }
        out.push(ev);

        // Connections attributed to this hidden process → Network evidence
        let mut seen_ports = std::collections::HashSet::new();
        for conn in &finding.connections {
            let port_key = (conn.src_port, conn.dst_port);
            if !seen_ports.insert(port_key) {
                continue;
            }
            let mut nev = Evidence::new(
                next_id("net"),
                EvidenceSource::Memory,
                EvidenceKind::Network,
                Some(subject.clone()),
            )
            .with_attr("state", &conn.state)
            .with_attr("proto", &conn.proto);

            if let Some(p) = conn.dst_port {
                nev = nev.with_attr("dst_port", &p.to_string());
                // Stratum mining ports
                if matches!(p, 3333 | 4444 | 5555 | 14444 | 45700) {
                    nev = nev.with_tag("mining_pool");
                }
            }
            // SSH tunnel indicator: hidden ssh process listening on 3333
            if let Some(p) = conn.src_port {
                nev = nev.with_attr("src_port", &p.to_string());
                if p == 3333 {
                    nev = nev.with_tag("stratum_listener");
                }
            }
            out.push(nev);
        }
    }

    // Userspace network connections (ss/netstat output) — visible but correlatable
    for conn in net_conns {
        let mut ev = Evidence::new(
            next_id("ss"),
            EvidenceSource::Artifact,
            EvidenceKind::Network,
            conn.pid.map(SubjectRef::Process),
        )
        .with_attr("local", &conn.local_addr)
        .with_attr("remote", &conn.remote_addr)
        .with_attr("state", &conn.state);

        if let Some(p) = conn.pid {
            ev = ev.with_attr("pid", &p.to_string());
        }
        out.push(ev);
    }

    // CPU anomaly
    if let Some(cpu) = cpu_percent_user {
        if cpu >= 90.0 {
            out.push(
                Evidence::new(
                    next_id("cpu"),
                    EvidenceSource::Artifact,
                    EvidenceKind::Artifact,
                    None,
                )
                .with_attr("cpu_user_percent", &format!("{cpu:.1}"))
                .with_tag("cpu_anomaly"),
            );
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rt_parser_uac::parsers::{
        mem_sockstat::SockstatEntry,
        rootkit::{RootkitFinding, RootkitSeverity},
        HiddenProcessAnalysis, HiddenProcessFinding,
    };

    // ── WS-5 RED: evaluate_correlation must exist and behave identically to evaluate_pivot ──

    #[test]
    fn evaluate_correlation_exists_and_returns_findings() {
        let rootkit = vec![RootkitFinding {
            check: "ld_preload".into(),
            evidence: "/lib/x86_64-linux-gnu/libymv.so.3".into(),
            description: "LD_PRELOAD rootkit".into(),
            severity: RootkitSeverity::Warning,
        }];
        let hidden = HiddenProcessAnalysis {
            hidden_pids: vec![977],
            findings: vec![HiddenProcessFinding {
                pid: 977,
                process_name: Some("top".into()),
                thread_names: vec!["libuv-worker".into()],
                all_thread_names: vec!["libuv-worker".into(), "top".into()],
                connections: vec![make_sockstat(977, 3333)],
            }],
        };
        let findings = evaluate_correlation(&rootkit, &hidden, &[], Some(97.7))
            .expect("correlation evaluation");
        assert!(
            !findings.is_empty(),
            "expected correlation findings for CTF scenario"
        );
    }

    fn make_sockstat(pid: u32, dst_port: u16) -> SockstatEntry {
        SockstatEntry {
            process_name: "top".into(),
            pid,
            tid: pid,
            family: "AF_INET".into(),
            proto: "TCP".into(),
            src_addr: "127.0.0.1".into(),
            src_port: Some(59182),
            dst_addr: "127.0.0.1".into(),
            dst_port: Some(dst_port),
            state: "ESTABLISHED".into(),
        }
    }

    // ── RED tests ────────────────────────────────────────────────────────────

    #[test]
    fn rootkit_finding_becomes_evidence_with_rootkit_indicator_tag() {
        let rk = vec![RootkitFinding {
            check: "ld_preload".into(),
            evidence: "/lib/x86_64-linux-gnu/libymv.so.3".into(),
            description: "LD_PRELOAD rootkit".into(),
            severity: RootkitSeverity::Warning,
        }];
        let ev = build_evidence(&rk, &HiddenProcessAnalysis::default(), &[], None);
        assert_eq!(ev.len(), 1);
        assert!(ev[0].tags.contains(&"rootkit_indicator".to_string()));
        assert_eq!(
            ev[0].attrs.get("check").map(String::as_str),
            Some("ld_preload")
        );
    }

    #[test]
    fn hidden_process_becomes_evidence_with_hidden_process_tag() {
        let hidden = HiddenProcessAnalysis {
            hidden_pids: vec![977],
            findings: vec![HiddenProcessFinding {
                pid: 977,
                process_name: Some("top".into()),
                thread_names: vec![],
                all_thread_names: vec!["top".into()],
                connections: vec![],
            }],
        };
        let ev = build_evidence(&[], &hidden, &[], None);
        assert_eq!(ev.len(), 1);
        assert!(ev[0].tags.contains(&"hidden_process".to_string()));
        assert_eq!(
            ev[0].attrs.get("process_name").map(String::as_str),
            Some("top")
        );
    }

    #[test]
    fn libuv_worker_threads_add_miner_thread_tag() {
        let hidden = HiddenProcessAnalysis {
            hidden_pids: vec![977],
            findings: vec![HiddenProcessFinding {
                pid: 977,
                process_name: Some("top".into()),
                thread_names: vec!["libuv-worker".into()],
                all_thread_names: vec!["libuv-worker".into(), "top".into()],
                connections: vec![],
            }],
        };
        let ev = build_evidence(&[], &hidden, &[], None);
        let proc_ev = ev
            .iter()
            .find(|e| e.tags.contains(&"hidden_process".to_string()))
            .unwrap();
        assert!(proc_ev.tags.contains(&"miner_thread".to_string()));
    }

    #[test]
    fn connection_to_stratum_port_gets_mining_pool_tag() {
        let hidden = HiddenProcessAnalysis {
            hidden_pids: vec![977],
            findings: vec![HiddenProcessFinding {
                pid: 977,
                process_name: Some("top".into()),
                thread_names: vec!["libuv-worker".into()],
                all_thread_names: vec!["libuv-worker".into(), "top".into()],
                connections: vec![make_sockstat(977, 3333)],
            }],
        };
        let ev = build_evidence(&[], &hidden, &[], None);
        let net_ev = ev.iter().find(|e| e.kind == EvidenceKind::Network).unwrap();
        assert!(net_ev.tags.contains(&"mining_pool".to_string()));
    }

    #[test]
    fn cpu_above_90_percent_emits_cpu_anomaly_evidence() {
        let ev = build_evidence(&[], &HiddenProcessAnalysis::default(), &[], Some(97.7));
        let cpu_ev = ev
            .iter()
            .find(|e| e.tags.contains(&"cpu_anomaly".to_string()));
        assert!(cpu_ev.is_some(), "expected cpu_anomaly evidence");
        assert_eq!(
            cpu_ev
                .unwrap()
                .attrs
                .get("cpu_user_percent")
                .map(String::as_str),
            Some("97.7")
        );
    }

    #[test]
    fn cpu_below_90_percent_does_not_emit_anomaly() {
        let ev = build_evidence(&[], &HiddenProcessAnalysis::default(), &[], Some(55.0));
        assert!(!ev
            .iter()
            .any(|e| e.tags.contains(&"cpu_anomaly".to_string())));
    }

    #[allow(deprecated)]
    #[test]
    fn ctf_scenario_produces_pivot_findings() {
        // Full CTF scenario: rootkit + hidden XMRig (libuv-worker) + Stratum + CPU
        let rootkit = vec![RootkitFinding {
            check: "ld_preload".into(),
            evidence: "/lib/x86_64-linux-gnu/libymv.so.3".into(),
            description: "LD_PRELOAD rootkit".into(),
            severity: RootkitSeverity::Warning,
        }];
        let hidden = HiddenProcessAnalysis {
            hidden_pids: vec![977],
            findings: vec![HiddenProcessFinding {
                pid: 977,
                process_name: Some("top".into()),
                thread_names: vec!["libuv-worker".into()],
                all_thread_names: vec!["libuv-worker".into(), "top".into()],
                connections: vec![make_sockstat(977, 3333)],
            }],
        };

        let findings =
            evaluate_pivot(&rootkit, &hidden, &[], Some(97.7)).expect("pivot evaluation");

        // Must produce at least one finding from the bundled rules
        assert!(
            !findings.is_empty(),
            "expected pivot findings for CTF scenario"
        );
    }
}
