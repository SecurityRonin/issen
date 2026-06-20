// Post-ingest scanning phase.
//
// Converts TimelineEvents into structured event maps for Sigma evaluation,
// scans artifact files with YARA/hash IOC engines, and produces FindingRows
// for storage in the DuckDB scan_findings table.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use forensicnomicon::attack_events::FAILED_LOGON_BURST;
use forensicnomicon::report::Finding;
use issen_core::timeline::event::TimelineEvent;
use issen_correlation::timestomp::detect_timestomp;
use issen_signatures::attack_classifier::{
    classify_event, failed_logon_burst_finding, NativeEventSignature,
};
use issen_signatures::matching::engine::ScanEngine;
use issen_signatures::matching::results::ScanFinding;
use issen_timeline::findings::FindingRow;

/// Summary of the scanning phase.
#[derive(Debug, Clone, Default)]
pub struct ScanPhaseSummary {
    pub events_evaluated: usize,
    pub files_scanned: usize,
    pub sigma_findings: usize,
    pub file_findings: usize,
    pub network_findings: usize,
    pub native_findings: usize,
    pub timestomp_findings: usize,
    pub total_findings: usize,
}

/// Convert a TimelineEvent into a flat HashMap for Sigma evaluation.
///
/// Sigma rules match on key-value pairs. We map the event's typed fields
/// into string keys and merge in the existing metadata map.
pub fn event_to_map(event: &TimelineEvent) -> HashMap<String, serde_json::Value> {
    let mut map = event.metadata.clone();
    map.insert(
        "EventType".to_string(),
        serde_json::Value::String(event.event_type.to_string()),
    );
    map.insert(
        "Source".to_string(),
        serde_json::Value::String(event.source.to_string()),
    );
    map.insert(
        "ArtifactPath".to_string(),
        serde_json::Value::String(event.artifact_path.clone()),
    );
    map.insert(
        "Description".to_string(),
        serde_json::Value::String(event.description.clone()),
    );
    if let Some(ref user) = event.user {
        map.insert("User".to_string(), serde_json::Value::String(user.clone()));
    }
    if let Some(ref hostname) = event.hostname {
        map.insert(
            "Hostname".to_string(),
            serde_json::Value::String(hostname.clone()),
        );
    }
    map
}

/// Convert a ScanFinding into a FindingRow for DuckDB storage.
fn finding_to_row(
    finding: &ScanFinding,
    evidence_source_id: &str,
    artifact_path: &str,
) -> FindingRow {
    FindingRow {
        evidence_source_id: evidence_source_id.to_string(),
        artifact_path: artifact_path.to_string(),
        engine: format!("{}", finding.source),
        severity: format!("{}", finding.severity).to_lowercase(),
        rule_name: finding.rule_name.clone(),
        description: finding.description.clone(),
        matched_indicator: finding.matched_indicator.clone(),
        tags: serde_json::to_string(&finding.tags).unwrap_or_else(|_| "[]".to_string()),
    }
}

/// `$SI`/`$FN` timestomp tolerance: a one-day slack absorbs benign sub-second /
/// timezone skew, matching the unit `detect_timestomp` is tested against (`DAY_NS`).
const ONE_DAY_NS: i64 = 86_400_000_000_000;

/// Convert a `forensicnomicon::report::Finding` (as emitted by the single-event
/// timestomp detector) into a `FindingRow` for DuckDB storage. MITRE ATT&CK
/// refs become `attack.<technique>` tags, mirroring the native ATT&CK phase.
fn timestomp_finding_to_row(
    finding: &Finding,
    evidence_source_id: &str,
    artifact_path: &str,
) -> FindingRow {
    let severity = finding
        .severity
        .map_or_else(|| "info".to_string(), |s| format!("{s}").to_lowercase());
    let tags: Vec<String> = finding
        .context
        .external_refs
        .iter()
        .filter(|r| r.scheme == "mitre-attack")
        .map(|r| format!("attack.{}", r.id.to_lowercase()))
        .collect();
    FindingRow {
        evidence_source_id: evidence_source_id.to_string(),
        artifact_path: artifact_path.to_string(),
        engine: "Timestomp".to_string(),
        severity,
        rule_name: finding.code.to_string(),
        description: finding.note.clone(),
        matched_indicator: None,
        tags: serde_json::to_string(&tags).unwrap_or_else(|_| "[]".to_string()),
    }
}

/// Build a native ATT&CK signature from a Windows event's metadata. Returns
/// `None` for events that carry no numeric `event_id` (non-EVTX events).
fn native_signature(event: &TimelineEvent) -> Option<NativeEventSignature> {
    let event_id = u32::try_from(event.metadata.get("event_id")?.as_u64()?).ok()?;
    let logon_type = event
        .metadata
        .get("logon_type")
        .and_then(serde_json::Value::as_u64)
        .and_then(|n| u32::try_from(n).ok());
    Some(NativeEventSignature {
        event_id,
        logon_type,
    })
}

/// Classify native Windows events into ATT&CK-tagged `FindingRow`s — no Sigma.
///
/// Per-event techniques (e.g. 4624 type-10 → T1021.001) carry the originating
/// event's provenance; the aggregate 4625 brute-force burst is attributed to the
/// first failed-logon event seen. The resulting tags (`attack.<tactic>`) are what
/// the report's attack-chain reads, so the chain populates without any ruleset.
pub fn run_native_attack_phase(events: &[TimelineEvent]) -> Vec<FindingRow> {
    let mut rows = Vec::new();
    let mut failed_logons = 0usize;
    let mut burst_src: Option<(&str, &str)> = None;

    for event in events {
        let Some(sig) = native_signature(event) else {
            continue;
        };
        if sig.event_id == FAILED_LOGON_BURST.event_id {
            failed_logons += 1;
            burst_src.get_or_insert((
                event.evidence_source_id.as_str(),
                event.artifact_path.as_str(),
            ));
        }
        for finding in &classify_event(&sig) {
            rows.push(finding_to_row(
                finding,
                &event.evidence_source_id,
                &event.artifact_path,
            ));
        }
    }

    if let Some(burst) = failed_logon_burst_finding(failed_logons) {
        let (source_id, path) = burst_src.unwrap_or(("native", "EVTX:Security"));
        rows.push(finding_to_row(&burst, source_id, path));
    }

    rows
}

/// Run the scanning phase: evaluate events with Sigma, scan artifact files.
///
/// Returns a list of FindingRows and a summary. The `evidence_root` path
/// is used to resolve artifact file paths for YARA/hash scanning.
pub fn run_scan_phase(
    events: &[TimelineEvent],
    engine: &ScanEngine,
    evidence_root: &Path,
) -> (Vec<FindingRow>, ScanPhaseSummary) {
    let mut findings = Vec::new();
    let mut summary = ScanPhaseSummary::default();

    // Phase 1: Evaluate events against Sigma rules.
    for event in events {
        summary.events_evaluated += 1;
        let event_map = event_to_map(event);
        let sigma_hits = engine.evaluate_event(&event_map);

        for hit in &sigma_hits {
            findings.push(finding_to_row(
                hit,
                &event.evidence_source_id,
                &event.artifact_path,
            ));
            summary.sigma_findings += 1;
        }
    }

    // Phase 2: Scan unique artifact files with YARA/hash IOC engines.
    let unique_paths: HashSet<&str> = events.iter().map(|e| e.artifact_path.as_str()).collect();

    for artifact_path in unique_paths {
        // Try to resolve the path relative to evidence root.
        let full_path = evidence_root.join(artifact_path);
        if !full_path.is_file() {
            continue;
        }

        match engine.scan_file(&full_path) {
            Ok(report) => {
                summary.files_scanned += 1;
                for finding in &report.findings {
                    // Use the first event's evidence_source_id for this artifact.
                    let source_id = events
                        .iter()
                        .find(|e| e.artifact_path == artifact_path)
                        .map_or("unknown", |e| e.evidence_source_id.as_str());

                    findings.push(finding_to_row(finding, source_id, artifact_path));
                    summary.file_findings += 1;
                }
            }
            Err(e) => {
                tracing::warn!(
                    artifact = artifact_path,
                    error = %e,
                    "failed to scan artifact file"
                );
            }
        }
    }

    // Phase 3: Extract IPs/domains from event metadata and check network IOC stores.
    for event in events {
        let network_hits = extract_network_iocs_from_event(event, engine);
        for hit in &network_hits {
            findings.push(finding_to_row(
                hit,
                &event.evidence_source_id,
                &event.artifact_path,
            ));
            summary.network_findings += 1;
        }
    }

    // Phase 4: native event → ATT&CK classification (no Sigma ruleset).
    let native = run_native_attack_phase(events);
    summary.native_findings += native.len();
    findings.extend(native);

    // Phase 5: single-event $SI/$FN timestomp leads (MITRE T1070.006).
    //
    // Runs the layered, FP-suppressed detector over each FileCreate event,
    // comparing the user-writable $STANDARD_INFORMATION birth time against the
    // system-set $FILE_NAME birth time (`fn_created` metadata) the MFT converter
    // surfaces. These are deliberately Info-graded *leads*, never escalated.
    //
    // This does NOT overlap with the coarser `temporal.timestomping-born-after-modify`
    // TemporalRule: that rule lives in the `supertimeline` command, emits
    // `TemporalFinding`s on a separate output channel, keys on $SI born-after-modify
    // (not $SI-vs-$FN), and never reaches this scan_findings path. Distinct code,
    // distinct severity tier, distinct output — no double-emit.
    for event in events {
        if let Some(finding) = detect_timestomp(event, ONE_DAY_NS) {
            findings.push(timestomp_finding_to_row(
                &finding,
                &event.evidence_source_id,
                &event.artifact_path,
            ));
            summary.timestomp_findings += 1;
        }
    }

    summary.total_findings = findings.len();
    (findings, summary)
}

/// Known metadata field names that may contain IP addresses.
const IP_FIELDS: &[&str] = &[
    "SourceIp",
    "DestinationIp",
    "IpAddress",
    "RemoteAddress",
    "LocalAddress",
    "SourceAddress",
    "DestAddress",
    "ClientIP",
    "ServerIP",
];

/// Known metadata field names that may contain domain names.
const DOMAIN_FIELDS: &[&str] = &[
    "Domain",
    "TargetDomainName",
    "QueryName",
    "DestinationHostname",
    "RemoteHost",
];

/// Extract IPs and domains from event metadata and check against network IOC stores.
fn extract_network_iocs_from_event(event: &TimelineEvent, engine: &ScanEngine) -> Vec<ScanFinding> {
    let mut findings = Vec::new();

    for &field in IP_FIELDS {
        if let Some(val) = event.metadata.get(field) {
            if let Some(ip) = val.as_str() {
                let hits = engine.check_ip(ip);
                findings.extend(hits);
            }
        }
    }

    for &field in DOMAIN_FIELDS {
        if let Some(val) = event.metadata.get(field) {
            if let Some(domain) = val.as_str() {
                let hits = engine.check_domain(domain);
                findings.extend(hits);
            }
        }
    }

    findings
}

/// Enrich timeline events with `sig:` tags based on scan findings.
///
/// For each finding, find events with matching artifact_path and add a tag
/// like `sig:YARA:rule_name` or `sig:Sigma:rule_name`. This allows
/// `rt timeline` to filter events that triggered signature matches.
pub fn enrich_events(events: &mut [TimelineEvent], findings: &[FindingRow]) {
    // Build a map: artifact_path -> Vec<tag_string>
    let mut path_tags: HashMap<String, Vec<String>> = HashMap::new();

    for finding in findings {
        let tag = format!("sig:{}:{}", finding.engine, finding.rule_name);
        path_tags
            .entry(finding.artifact_path.clone())
            .or_default()
            .push(tag);
    }

    // Apply tags to matching events.
    for event in events.iter_mut() {
        if let Some(tags) = path_tags.get(&event.artifact_path) {
            for tag in tags {
                if !event.tags.contains(tag) {
                    event.tags.push(tag.clone());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use issen_core::artifacts::ArtifactType;
    use issen_core::timeline::event::EventType;
    use issen_signatures::engines::ioc_hash::HashIocStore;
    use issen_signatures::engines::ioc_network::NetworkIocStore;
    use issen_signatures::engines::sigma::SigmaEngine;
    use issen_signatures::engines::yara::YaraEngine;

    fn sample_event(event_type: EventType, description: &str) -> TimelineEvent {
        TimelineEvent::new(
            1_700_000_000_000_000_000,
            "2023-11-14T22:13:20Z".to_string(),
            event_type,
            ArtifactType::EventLog,
            "Windows/System32/winevt/Logs/Security.evtx".to_string(),
            description.to_string(),
            "case-001".to_string(),
        )
    }

    #[test]
    fn native_attack_phase_emits_rdp_finding_with_tactic_tags() {
        // event_id 4624 + logon_type 10 → T1021.001 / initial_access (no Sigma).
        let event = sample_event(EventType::LogonSuccess, "RDP logon")
            .with_metadata("event_id", serde_json::json!(4624))
            .with_metadata("logon_type", serde_json::json!(10));
        let rows = run_native_attack_phase(&[event]);
        assert!(
            rows.iter().any(|r| r.engine == "Native"
                && r.tags.contains("attack.t1021.001")
                && r.tags.contains("attack.initial_access")),
            "RDP logon must yield a Native FindingRow tagged T1021.001 / initial_access \
             so the report attack-chain populates without Sigma"
        );
    }

    #[test]
    fn native_attack_phase_emits_brute_force_on_failed_logon_burst() {
        let events: Vec<_> = (0..6)
            .map(|_| {
                sample_event(EventType::LogonFailure, "Failed logon")
                    .with_metadata("event_id", serde_json::json!(4625))
            })
            .collect();
        let rows = run_native_attack_phase(&events);
        assert!(
            rows.iter().any(
                |r| r.tags.contains("attack.t1110") && r.tags.contains("attack.initial_access")
            ),
            "a 4625 burst must yield a brute-force (T1110) FindingRow"
        );
    }

    #[test]
    fn native_attack_phase_ignores_events_without_event_id() {
        let events = vec![sample_event(EventType::FileCreate, "no event id")];
        assert!(run_native_attack_phase(&events).is_empty());
    }

    #[test]
    fn test_event_to_map_basic_fields() {
        let event = sample_event(EventType::LogonFailure, "Failed logon attempt");
        let map = event_to_map(&event);

        assert_eq!(map.get("EventType").unwrap(), "LogonFailure");
        assert_eq!(map.get("Source").unwrap(), "Event Log");
        assert_eq!(map.get("Description").unwrap(), "Failed logon attempt");
        assert!(!map.contains_key("User"));
    }

    #[test]
    fn test_event_to_map_with_user_and_hostname() {
        let event = sample_event(EventType::LogonSuccess, "Logon success")
            .with_user("DOMAIN\\admin")
            .with_hostname("DC01");
        let map = event_to_map(&event);

        assert_eq!(map.get("User").unwrap(), "DOMAIN\\admin");
        assert_eq!(map.get("Hostname").unwrap(), "DC01");
    }

    #[test]
    fn test_event_to_map_preserves_metadata() {
        let event = sample_event(EventType::ProcessExec, "Process started")
            .with_metadata("CommandLine", serde_json::json!("powershell.exe -enc ABC"));
        let map = event_to_map(&event);

        assert_eq!(
            map.get("CommandLine").unwrap(),
            &serde_json::json!("powershell.exe -enc ABC")
        );
        // Standard fields are also present.
        assert_eq!(map.get("EventType").unwrap(), "ProcessExec");
    }

    #[test]
    fn test_finding_to_row_conversion() {
        let finding = ScanFinding {
            source: issen_signatures::matching::results::MatchSource::Sigma,
            severity: issen_signatures::matching::results::Severity::High,
            rule_name: "suspicious_login".to_string(),
            description: "Multiple failed logons".to_string(),
            matched_indicator: Some("rule-001".to_string()),
            tags: vec!["attack.initial_access".to_string()],
        };

        let row = finding_to_row(&finding, "case-001", "/logs/Security.evtx");
        assert_eq!(row.evidence_source_id, "case-001");
        assert_eq!(row.artifact_path, "/logs/Security.evtx");
        assert_eq!(row.engine, "Sigma");
        assert_eq!(row.severity, "high");
        assert_eq!(row.rule_name, "suspicious_login");
        assert_eq!(row.matched_indicator, Some("rule-001".to_string()));
        assert!(row.tags.contains("attack.initial_access"));
    }

    #[test]
    fn test_scan_phase_empty_events() {
        let engine = ScanEngine::new();
        let dir = tempfile::tempdir().unwrap();
        let (findings, summary) = run_scan_phase(&[], &engine, dir.path());

        assert!(findings.is_empty());
        assert_eq!(summary.events_evaluated, 0);
        assert_eq!(summary.files_scanned, 0);
        assert_eq!(summary.total_findings, 0);
    }

    #[test]
    fn test_scan_phase_no_engines() {
        let engine = ScanEngine::new();
        let dir = tempfile::tempdir().unwrap();
        let events = vec![sample_event(EventType::FileCreate, "File created")];

        let (findings, summary) = run_scan_phase(&events, &engine, dir.path());

        assert!(findings.is_empty());
        assert_eq!(summary.events_evaluated, 1);
        assert_eq!(summary.sigma_findings, 0);
    }

    #[test]
    fn test_scan_phase_sigma_match() {
        let mut sigma = SigmaEngine::new();
        sigma
            .load_rule(
                r"
title: Failed Logon Detected
id: test-sigma-001
level: high
detection:
    selection:
        EventType: LogonFailure
    condition: selection
",
            )
            .unwrap();

        let engine = ScanEngine::new().with_sigma(sigma);
        let dir = tempfile::tempdir().unwrap();
        let events = vec![sample_event(EventType::LogonFailure, "Failed logon")];

        let (findings, summary) = run_scan_phase(&events, &engine, dir.path());

        assert_eq!(summary.sigma_findings, 1);
        assert_eq!(summary.total_findings, 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].engine, "Sigma");
        assert_eq!(findings[0].severity, "high");
        assert_eq!(findings[0].rule_name, "Failed Logon Detected");
        assert_eq!(findings[0].evidence_source_id, "case-001");
    }

    #[test]
    fn test_scan_phase_sigma_description_contains_carries_attack_tag() {
        // Mirrors the real triage rule: match the shallow EVTX Description string
        // (the only place the event id reliably appears) and ensure the rule's
        // ATT&CK tactic tag propagates into FindingRow.tags, which the report
        // turns into an attack-chain node. De-risks the full E01 ingest.
        let mut sigma = SigmaEngine::new();
        sigma
            .load_rule(
                r"
title: Failed Logon Attempt (Possible Brute Force)
id: 11111111-0000-0000-0000-000000004625
level: high
detection:
    sel:
        Description|contains: 'EventID:4625 '
    condition: sel
tags:
    - attack.initial_access
    - attack.t1110
",
            )
            .unwrap();

        let engine = ScanEngine::new().with_sigma(sigma);
        let dir = tempfile::tempdir().unwrap();
        // Description shaped exactly like the real parsed EVTX events.
        let events = vec![sample_event(
            EventType::Other("EventID:4625".to_string()),
            "EventID:4625 Provider:Microsoft-Windows-Security-Auditing Channel:Security (Record 5)",
        )];

        let (findings, summary) = run_scan_phase(&events, &engine, dir.path());

        assert_eq!(
            summary.sigma_findings, 1,
            "rule should fire on the description"
        );
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].tags.contains("attack.initial_access"),
            "ATT&CK tactic tag must propagate into the finding: {}",
            findings[0].tags
        );
    }

    #[test]
    fn test_scan_phase_sigma_no_match() {
        let mut sigma = SigmaEngine::new();
        sigma
            .load_rule(
                r"
title: Failed Logon Detected
level: high
detection:
    selection:
        EventType: LogonFailure
    condition: selection
",
            )
            .unwrap();

        let engine = ScanEngine::new().with_sigma(sigma);
        let dir = tempfile::tempdir().unwrap();
        // This event is a LogonSuccess, not LogonFailure.
        let events = vec![sample_event(EventType::LogonSuccess, "Logon success")];

        let (findings, summary) = run_scan_phase(&events, &engine, dir.path());

        assert_eq!(summary.sigma_findings, 0);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_scan_phase_file_yara_match() {
        let yara = YaraEngine::from_source(
            r#"rule detect_payload { strings: $s = "malicious_payload" condition: $s }"#,
        )
        .unwrap();

        let engine = ScanEngine::new().with_yara(yara);
        let dir = tempfile::tempdir().unwrap();

        // Create a file that matches the YARA rule.
        let artifact_name = "suspect.exe";
        std::fs::write(
            dir.path().join(artifact_name),
            b"this contains malicious_payload data",
        )
        .unwrap();

        // Create an event pointing to that artifact.
        let event = TimelineEvent::new(
            1_700_000_000_000_000_000,
            "2023-11-14T22:13:20Z".to_string(),
            EventType::FileCreate,
            ArtifactType::UsnJournal,
            artifact_name.to_string(),
            "File created".to_string(),
            "case-001".to_string(),
        );

        let (findings, summary) = run_scan_phase(&[event], &engine, dir.path());

        assert_eq!(summary.files_scanned, 1);
        assert_eq!(summary.file_findings, 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].engine, "YARA");
        assert_eq!(findings[0].rule_name, "detect_payload");
        assert_eq!(findings[0].artifact_path, artifact_name);
    }

    #[test]
    fn test_scan_phase_file_hash_match() {
        let data = b"known_bad_binary_content";
        let sha256 = issen_signatures::engines::ioc_hash::sha256_hex(data);

        let mut hash_store = HashIocStore::new("malware-hashes");
        hash_store.inseissen_bad(&sha256).unwrap();

        let engine = ScanEngine::new().with_hash_store(hash_store);
        let dir = tempfile::tempdir().unwrap();

        let artifact_name = "malware.bin";
        std::fs::write(dir.path().join(artifact_name), data).unwrap();

        let event = TimelineEvent::new(
            1_700_000_000_000_000_000,
            "2023-11-14T22:13:20Z".to_string(),
            EventType::FileCreate,
            ArtifactType::UsnJournal,
            artifact_name.to_string(),
            "File created".to_string(),
            "case-001".to_string(),
        );

        let (findings, summary) = run_scan_phase(&[event], &engine, dir.path());

        assert_eq!(summary.files_scanned, 1);
        assert!(summary.file_findings >= 1);
        let hash_finding = findings.iter().find(|f| f.engine == "Hash IOC").unwrap();
        assert_eq!(hash_finding.severity, "critical");
    }

    #[test]
    fn test_scan_phase_combined_sigma_and_file() {
        // Sigma rule that matches an event.
        let mut sigma = SigmaEngine::new();
        sigma
            .load_rule(
                r"
title: Suspicious Exec
level: critical
detection:
    selection:
        EventType: ProcessExec
    condition: selection
",
            )
            .unwrap();

        // YARA rule that matches a file.
        let yara =
            YaraEngine::from_source(r#"rule bad_file { strings: $s = "evil" condition: $s }"#)
                .unwrap();

        let engine = ScanEngine::new().with_sigma(sigma).with_yara(yara);
        let dir = tempfile::tempdir().unwrap();

        let artifact_name = "malware.exe";
        std::fs::write(dir.path().join(artifact_name), b"this is evil code").unwrap();

        let event = TimelineEvent::new(
            1_700_000_000_000_000_000,
            "2023-11-14T22:13:20Z".to_string(),
            EventType::ProcessExec,
            ArtifactType::Prefetch,
            artifact_name.to_string(),
            "Process executed".to_string(),
            "case-002".to_string(),
        );

        let (findings, summary) = run_scan_phase(&[event], &engine, dir.path());

        assert_eq!(summary.sigma_findings, 1);
        assert_eq!(summary.file_findings, 1);
        assert_eq!(summary.total_findings, 2);
        assert_eq!(findings.len(), 2);

        // Verify both engines produced findings.
        let engines: Vec<&str> = findings.iter().map(|f| f.engine.as_str()).collect();
        assert!(engines.contains(&"Sigma"));
        assert!(engines.contains(&"YARA"));
    }

    #[test]
    fn test_scan_phase_deduplicates_file_scans() {
        let yara =
            YaraEngine::from_source(r#"rule test { strings: $s = "content" condition: $s }"#)
                .unwrap();

        let engine = ScanEngine::new().with_yara(yara);
        let dir = tempfile::tempdir().unwrap();

        let artifact_name = "data.bin";
        std::fs::write(dir.path().join(artifact_name), b"some content here").unwrap();

        // Two events pointing to the same artifact file.
        let event1 = TimelineEvent::new(
            1_700_000_000_000_000_000,
            "2023-11-14T22:13:20Z".to_string(),
            EventType::FileCreate,
            ArtifactType::UsnJournal,
            artifact_name.to_string(),
            "File created".to_string(),
            "case-001".to_string(),
        );
        let event2 = TimelineEvent::new(
            1_700_000_000_000_000_001,
            "2023-11-14T22:13:21Z".to_string(),
            EventType::FileModify,
            ArtifactType::UsnJournal,
            artifact_name.to_string(),
            "File modified".to_string(),
            "case-001".to_string(),
        );

        let (_findings, summary) = run_scan_phase(&[event1, event2], &engine, dir.path());

        // File should only be scanned once despite two events.
        assert_eq!(summary.files_scanned, 1);
        assert_eq!(summary.file_findings, 1);
    }

    #[test]
    fn test_scan_phase_missing_file_skipped() {
        let yara =
            YaraEngine::from_source(r#"rule test { strings: $s = "x" condition: $s }"#).unwrap();

        let engine = ScanEngine::new().with_yara(yara);
        let dir = tempfile::tempdir().unwrap();

        // Event refers to a file that doesn't exist on disk.
        let event = TimelineEvent::new(
            1_700_000_000_000_000_000,
            "2023-11-14T22:13:20Z".to_string(),
            EventType::FileCreate,
            ArtifactType::UsnJournal,
            "nonexistent_file.exe".to_string(),
            "File created".to_string(),
            "case-001".to_string(),
        );

        let (findings, summary) = run_scan_phase(&[event], &engine, dir.path());

        assert_eq!(summary.files_scanned, 0);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_scan_phase_summary_counts() {
        let summary = ScanPhaseSummary::default();
        assert_eq!(summary.events_evaluated, 0);
        assert_eq!(summary.files_scanned, 0);
        assert_eq!(summary.sigma_findings, 0);
        assert_eq!(summary.file_findings, 0);
        assert_eq!(summary.network_findings, 0);
        assert_eq!(summary.total_findings, 0);
    }

    // ── Event enrichment tests ───────────────────────────────────────

    #[test]
    fn test_enrich_events_adds_sig_tags() {
        let mut events = vec![sample_event(EventType::FileCreate, "File created")];
        let findings = vec![FindingRow {
            evidence_source_id: "case-001".to_string(),
            artifact_path: "Windows/System32/winevt/Logs/Security.evtx".to_string(),
            engine: "YARA".to_string(),
            severity: "high".to_string(),
            rule_name: "detect_malware".to_string(),
            description: "YARA match".to_string(),
            matched_indicator: None,
            tags: "[]".to_string(),
        }];

        enrich_events(&mut events, &findings);

        assert!(events[0]
            .tags
            .contains(&"sig:YARA:detect_malware".to_string()));
    }

    #[test]
    fn test_enrich_events_multiple_findings_same_path() {
        let mut events = vec![sample_event(EventType::FileCreate, "File created")];
        let findings = vec![
            FindingRow {
                evidence_source_id: "case-001".to_string(),
                artifact_path: "Windows/System32/winevt/Logs/Security.evtx".to_string(),
                engine: "YARA".to_string(),
                severity: "high".to_string(),
                rule_name: "rule_a".to_string(),
                description: "YARA match A".to_string(),
                matched_indicator: None,
                tags: "[]".to_string(),
            },
            FindingRow {
                evidence_source_id: "case-001".to_string(),
                artifact_path: "Windows/System32/winevt/Logs/Security.evtx".to_string(),
                engine: "Sigma".to_string(),
                severity: "critical".to_string(),
                rule_name: "rule_b".to_string(),
                description: "Sigma match B".to_string(),
                matched_indicator: None,
                tags: "[]".to_string(),
            },
        ];

        enrich_events(&mut events, &findings);

        assert_eq!(events[0].tags.len(), 2);
        assert!(events[0].tags.contains(&"sig:YARA:rule_a".to_string()));
        assert!(events[0].tags.contains(&"sig:Sigma:rule_b".to_string()));
    }

    #[test]
    fn test_enrich_events_no_findings_leaves_events_unchanged() {
        let mut events =
            vec![sample_event(EventType::FileCreate, "File created").with_tag("existing_tag")];

        enrich_events(&mut events, &[]);

        assert_eq!(events[0].tags, vec!["existing_tag".to_string()]);
    }

    #[test]
    fn test_enrich_events_unmatched_path_not_tagged() {
        let mut events = vec![sample_event(EventType::FileCreate, "File created")];
        let findings = vec![FindingRow {
            evidence_source_id: "case-001".to_string(),
            artifact_path: "totally/different/path.exe".to_string(),
            engine: "YARA".to_string(),
            severity: "high".to_string(),
            rule_name: "detect_malware".to_string(),
            description: "YARA match".to_string(),
            matched_indicator: None,
            tags: "[]".to_string(),
        }];

        enrich_events(&mut events, &findings);

        assert!(events[0].tags.is_empty());
    }

    #[test]
    fn test_enrich_events_deduplicates_tags() {
        let mut events = vec![sample_event(EventType::FileCreate, "File created")];
        // Same finding twice (e.g. from different evidence sources).
        let findings = vec![
            FindingRow {
                evidence_source_id: "case-001".to_string(),
                artifact_path: "Windows/System32/winevt/Logs/Security.evtx".to_string(),
                engine: "YARA".to_string(),
                severity: "high".to_string(),
                rule_name: "detect_malware".to_string(),
                description: "match".to_string(),
                matched_indicator: None,
                tags: "[]".to_string(),
            },
            FindingRow {
                evidence_source_id: "case-002".to_string(),
                artifact_path: "Windows/System32/winevt/Logs/Security.evtx".to_string(),
                engine: "YARA".to_string(),
                severity: "high".to_string(),
                rule_name: "detect_malware".to_string(),
                description: "match".to_string(),
                matched_indicator: None,
                tags: "[]".to_string(),
            },
        ];

        enrich_events(&mut events, &findings);

        // Tag should appear only once.
        let sig_tags: Vec<_> = events[0]
            .tags
            .iter()
            .filter(|t| t.starts_with("sig:"))
            .collect();
        assert_eq!(sig_tags.len(), 1);
    }

    // ── Network IOC extraction tests ─────────────────────────────────

    #[test]
    fn test_network_ioc_extraction_ip_match() {
        let mut net_store = NetworkIocStore::new("c2-tracker");
        net_store.inseissen_ip("10.0.0.99").unwrap();

        let engine = ScanEngine::new().with_network_store(net_store);
        let dir = tempfile::tempdir().unwrap();

        // Event with an IP address in metadata.
        let event = sample_event(EventType::NetworkConnect, "Connection to C2")
            .with_metadata("DestinationIp", serde_json::json!("10.0.0.99"));

        let (findings, summary) = run_scan_phase(&[event], &engine, dir.path());

        assert_eq!(summary.network_findings, 1);
        assert!(summary.total_findings >= 1);
        let net_finding = findings.iter().find(|f| f.engine == "Network IOC").unwrap();
        assert_eq!(net_finding.severity, "high");
    }

    #[test]
    fn test_network_ioc_extraction_domain_match() {
        let mut net_store = NetworkIocStore::new("malware-domains");
        net_store.inseissen_domain("evil.com");

        let engine = ScanEngine::new().with_network_store(net_store);
        let dir = tempfile::tempdir().unwrap();

        let event = sample_event(EventType::NetworkConnect, "DNS query to evil.com")
            .with_metadata("QueryName", serde_json::json!("evil.com"));

        let (findings, summary) = run_scan_phase(&[event], &engine, dir.path());

        assert_eq!(summary.network_findings, 1);
        let net_finding = findings.iter().find(|f| f.engine == "Network IOC").unwrap();
        assert!(net_finding.description.contains("evil.com"));
    }

    #[test]
    fn test_network_ioc_extraction_no_match() {
        let mut net_store = NetworkIocStore::new("c2-tracker");
        net_store.inseissen_ip("10.0.0.99").unwrap();

        let engine = ScanEngine::new().with_network_store(net_store);
        let dir = tempfile::tempdir().unwrap();

        // Event with a different IP that doesn't match.
        let event = sample_event(EventType::NetworkConnect, "Connection to safe host")
            .with_metadata("DestinationIp", serde_json::json!("192.168.1.1"));

        let (findings, summary) = run_scan_phase(&[event], &engine, dir.path());

        assert_eq!(summary.network_findings, 0);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_network_ioc_extraction_multiple_fields() {
        let mut net_store = NetworkIocStore::new("c2-tracker");
        net_store.inseissen_ip("10.0.0.1").unwrap();
        net_store.inseissen_ip("10.0.0.2").unwrap();

        let engine = ScanEngine::new().with_network_store(net_store);
        let dir = tempfile::tempdir().unwrap();

        // Event with both source and destination IPs.
        let event = sample_event(EventType::NetworkConnect, "Connection")
            .with_metadata("SourceIp", serde_json::json!("10.0.0.1"))
            .with_metadata("DestinationIp", serde_json::json!("10.0.0.2"));

        let (_findings, summary) = run_scan_phase(&[event], &engine, dir.path());

        // Both IPs should match.
        assert_eq!(summary.network_findings, 2);
    }

    #[test]
    fn test_network_ioc_extraction_non_string_metadata_ignored() {
        let mut net_store = NetworkIocStore::new("c2-tracker");
        net_store.inseissen_ip("10.0.0.1").unwrap();

        let engine = ScanEngine::new().with_network_store(net_store);
        let dir = tempfile::tempdir().unwrap();

        // Metadata field with a numeric value (not a string).
        let event = sample_event(EventType::NetworkConnect, "Connection")
            .with_metadata("SourceIp", serde_json::json!(12345));

        let (findings, summary) = run_scan_phase(&[event], &engine, dir.path());

        assert_eq!(summary.network_findings, 0);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_combined_sigma_and_network_ioc() {
        let mut sigma = SigmaEngine::new();
        sigma
            .load_rule(
                r"
title: Suspicious Connection
level: high
detection:
    selection:
        EventType: NetworkConnect
    condition: selection
",
            )
            .unwrap();

        let mut net_store = NetworkIocStore::new("c2-list");
        net_store.inseissen_ip("10.0.0.99").unwrap();

        let engine = ScanEngine::new()
            .with_sigma(sigma)
            .with_network_store(net_store);
        let dir = tempfile::tempdir().unwrap();

        let event = sample_event(EventType::NetworkConnect, "C2 connection")
            .with_metadata("DestinationIp", serde_json::json!("10.0.0.99"));

        let (_findings, summary) = run_scan_phase(&[event], &engine, dir.path());

        // Both Sigma and network IOC should fire.
        assert_eq!(summary.sigma_findings, 1);
        assert_eq!(summary.network_findings, 1);
        assert_eq!(summary.total_findings, 2);
    }

    /// Build a `FileCreate` event carrying a timestomped `$SI`<`$FN` signature,
    /// mirroring the metadata keys the MFT converters surface (`fn_created`,
    /// `si_created`, `si_modified`, `si_accessed` in `datetime_to_display`
    /// form). `$SI.created`/`$SI.modified` precede `$FN.created` by years — the
    /// classic single-event timestomp lead that `detect_timestomp` flags.
    fn timestomped_file_create() -> TimelineEvent {
        // $SI birth 2010, $FN birth 2020 — $SI precedes $FN by a decade.
        let si = "2010-01-01T00:00:00.000000000Z";
        let fnc = "2020-01-01T00:00:00.000000000Z";
        TimelineEvent::new(
            1_262_304_000_000_000_000, // 2010-01-01T00:00:00Z ns
            si.to_string(),
            EventType::FileCreate,
            ArtifactType::Mft,
            "Users/victim/Desktop/evil.dll".to_string(),
            "FileCreate: evil.dll".to_string(),
            "case-001".to_string(),
        )
        .with_metadata("si_created", serde_json::json!(si))
        .with_metadata("si_modified", serde_json::json!(si))
        .with_metadata("si_accessed", serde_json::json!(si))
        .with_metadata("fn_created", serde_json::json!(fnc))
    }

    #[test]
    fn scan_phase_emits_single_event_timestomp_lead() {
        // A FileCreate event whose $SI birth precedes its $FN birth must surface
        // the T1070.006 single-event timestomp lead from `detect_timestomp` as a
        // FindingRow — proving the detector is wired into the scan pipeline.
        let engine = ScanEngine::new();
        let dir = tempfile::tempdir().unwrap();

        let (findings, summary) = run_scan_phase(&[timestomped_file_create()], &engine, dir.path());

        let timestomp = findings
            .iter()
            .find(|f| f.engine == "Timestomp")
            .expect("scan phase must emit a Timestomp FindingRow for an $SI<$FN FileCreate");
        assert_eq!(timestomp.rule_name, "NTFS-TIMESTOMP-SI-FN-MISMATCH");
        assert!(
            timestomp.tags.contains("attack.t1070.006"),
            "timestomp finding must carry the MITRE T1070.006 tag: {}",
            timestomp.tags
        );
        // A deliberately low-confidence lead — graded Info/Low/Medium by signal
        // strength, but NEVER escalated to high/critical (that tier needs the
        // USN/$LogFile corroboration the single-event detector lacks).
        assert!(
            ["info", "low", "medium"].contains(&timestomp.severity.as_str()),
            "timestomp lead must stay a low-tier lead, got: {}",
            timestomp.severity
        );
        assert!(
            summary.total_findings >= 1,
            "the timestomp lead must be counted in the phase summary"
        );
    }

    #[test]
    fn scan_phase_no_timestomp_lead_for_normal_ordering() {
        // $SI birth AFTER $FN birth is normal — no timestomp lead.
        let si = "2020-06-01T00:00:00.000000000Z";
        let fnc = "2020-01-01T00:00:00.000000000Z";
        let event = TimelineEvent::new(
            1_590_969_600_000_000_000, // 2020-06-01 ns
            si.to_string(),
            EventType::FileCreate,
            ArtifactType::Mft,
            "Users/victim/x.txt".to_string(),
            "FileCreate: x.txt".to_string(),
            "case-001".to_string(),
        )
        .with_metadata("si_created", serde_json::json!(si))
        .with_metadata("si_modified", serde_json::json!(si))
        .with_metadata("fn_created", serde_json::json!(fnc));

        let engine = ScanEngine::new();
        let dir = tempfile::tempdir().unwrap();
        let (findings, _summary) = run_scan_phase(&[event], &engine, dir.path());

        assert!(
            !findings.iter().any(|f| f.engine == "Timestomp"),
            "normal $SI-after-$FN ordering must not emit a timestomp lead"
        );
    }
}
