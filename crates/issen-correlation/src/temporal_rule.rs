//! Temporal rule evaluation for the supertimeline engine.
//!
//! `TemporalRule` operates on [`TimelineEvent`] slices and detects forensic
//! patterns that require temporal reasoning:
//!
//! - **sequence** — anchor event followed by expected events within a window
//! - **absent**   — anchor event with NO matching event in the window
//! - **discrepancy** — two artifact sources disagree about *when* the same
//!   entity (file, process) was created or first seen

use issen_core::timeline::event::{EntityRef, TimelineEvent};
use serde::{Deserialize, Serialize};

#[cfg(test)]
use issen_core::{
    artifacts::ArtifactType,
    timeline::event::EventType,
};

// ── Public types ──────────────────────────────────────────────────────────────

/// Matches a [`TimelineEvent`] by event type, optional artifact source, and
/// optional description substring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventTypeFilter {
    /// `EventType` display name, e.g. `"ProcessExec"`, `"FileCreate"`.
    pub event_type: String,
    /// Optional `ArtifactType` display name to restrict the source,
    /// e.g. `"Prefetch"`, `"MFT"`, `"Event Log"`.
    #[serde(default)]
    pub source: Option<String>,
    /// Optional substring that must appear in `event.description`.
    #[serde(default)]
    pub description_contains: Option<String>,
}

impl EventTypeFilter {
    /// Convenience constructor: `event_type` only.
    #[must_use]
    pub fn new(event_type: impl Into<String>) -> Self {
        Self {
            event_type: event_type.into(),
            source: None,
            description_contains: None,
        }
    }

    /// Builder: restrict to a specific artifact source.
    #[must_use]
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Builder: require a substring in the event description.
    #[must_use]
    pub fn with_description(mut self, contains: impl Into<String>) -> Self {
        self.description_contains = Some(contains.into());
        self
    }
}

/// Detects a timestamp contradiction between two artifact sources for the same
/// file/process entity.
///
/// The discrepancy fires when the anchor event references entity `E` at time
/// `T_anchor`, and a `compare` event from `compare_source` references the same
/// entity `E` at time `T_compare`, such that the relationship between
/// `T_anchor` and `T_compare` violates the expected temporal order.
///
/// **direction `"before"`** — fires when `T_anchor < T_compare`
///   (the anchor saw the entity before the compare source claims it was created).
///   Example: boot log references `/lib/libymv.so.3` at 23:16, but its
///   `$MFT` born time is 23:24 → anchor predates the MFT creation claim.
///
/// **direction `"after"`** — fires when `T_anchor > T_compare`
///   (the anchor was recorded after the compare source's earlier event).
///   Example: `FileCreate` born time is later than `FileModify` for the same
///   file → classic timestomping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscrepancyClause {
    /// `EntityRef` role to join on: `"path"`, `"process"`, `"user"`, `"ip"`.
    pub entity_role: String,
    /// Event type in the compare source to look for.
    pub compare_event_type: String,
    /// Artifact source of the compare event (e.g. `"MFT"`, `"Prefetch"`).
    pub compare_source: String,
    /// Minimum gap in seconds for the discrepancy to fire. Default 0.
    #[serde(default)]
    pub min_delta_seconds: i64,
    /// `"before"` or `"after"` — see struct docs.
    #[serde(default = "default_direction")]
    pub direction: String,
}

fn default_direction() -> String {
    "before".to_string()
}

fn default_window() -> i64 {
    300
}

/// A temporal rule that operates on [`TimelineEvent`] slices.
///
/// Unlike [`CorrelationRule`](crate::model::CorrelationRule) (which works on
/// enriched [`Evidence`](crate::model::Evidence)), a `TemporalRule` works
/// directly on raw parsed events and detects patterns based on timestamps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporalRule {
    /// Unique rule identifier, e.g. `"temporal.hollow-process"`.
    pub id: String,
    /// Short human title shown in findings.
    pub title: String,
    /// `"critical"`, `"high"`, `"medium"`, or `"low"`.
    pub severity: String,
    /// Optional prose description.
    #[serde(default)]
    pub description: Option<String>,
    /// Time window in seconds (default 300 = 5 minutes).
    #[serde(default = "default_window")]
    pub within_seconds: i64,
    /// The anchor event that triggers rule evaluation.
    pub anchor: EventTypeFilter,
    /// Events that **must** be present in the window for the rule to fire.
    #[serde(default)]
    pub sequence: Vec<EventTypeFilter>,
    /// Event types that **must be absent** from the window for the rule to fire.
    #[serde(default)]
    pub absent: Vec<EventTypeFilter>,
    /// Timestamp contradictions between artifact sources.
    #[serde(default)]
    pub discrepancy: Vec<DiscrepancyClause>,
}

/// Detail about a detected timestamp discrepancy.
#[derive(Debug, Clone)]
pub struct DiscrepancyDetail {
    /// Canonical entity key, e.g. `"path:/lib/libymv.so.3"`.
    pub entity_key: String,
    pub anchor_source: String,
    pub anchor_timestamp_ns: i64,
    pub compare_source: String,
    pub compare_timestamp_ns: i64,
    /// `|compare_timestamp_ns - anchor_timestamp_ns|`
    pub delta_ns: i64,
}

/// A finding produced by [`evaluate_temporal`].
#[derive(Debug, Clone)]
pub struct TemporalFinding {
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    /// `record_hash` of the anchor event that triggered the rule.
    pub anchor_record_hash: String,
    /// `record_hash`es of the matched sequence/absent/discrepancy events.
    pub matched_record_hashes: Vec<String>,
    /// Discrepancy details when the rule fired via a discrepancy clause.
    pub discrepancy: Option<DiscrepancyDetail>,
}

// ── Evaluation ────────────────────────────────────────────────────────────────

/// The bundled set of [`TemporalRule`]s shared across the fleet.
///
/// One registry so every consumer — `correlate`, `timeline --narrative`, and
/// `supertimeline` — evaluates the same rules over its events, instead of each
/// keeping a private copy (issen #110 Phase 2).
#[must_use]
pub fn bundled_temporal_rules() -> Vec<TemporalRule> {
    vec![
        // Hollow process: 4688 event log entry with no Prefetch update within 5s.
        TemporalRule {
            id: "temporal.hollow-process".into(),
            title: "Process created with no Prefetch update — possible hollow process".into(),
            severity: "high".into(),
            description: Some(
                "A process-creation event with no corresponding Prefetch FileModify \
                 within 5 seconds may indicate process hollowing or injection."
                    .into(),
            ),
            within_seconds: 5,
            anchor: EventTypeFilter::new("ProcessExec").with_source("Event Log"),
            sequence: vec![],
            absent: vec![EventTypeFilter::new("FileModify").with_source("Prefetch")],
            discrepancy: vec![],
        },
        // Boot-log predates MFT file creation (rootkit timestomping).
        TemporalRule {
            id: "temporal.boot-log-predates-mft".into(),
            title: "Boot log references file before MFT creation timestamp".into(),
            severity: "critical".into(),
            description: Some(
                "A system boot log entry references a file at a time before the \
                 file's $MFT born time. Consistent with a userspace rootkit that \
                 existed prior to its recorded filesystem creation timestamp."
                    .into(),
            ),
            within_seconds: 3600,
            anchor: EventTypeFilter::new("SystemBoot").with_source("Event Log"),
            sequence: vec![],
            absent: vec![],
            discrepancy: vec![DiscrepancyClause {
                entity_role: "path".into(),
                compare_event_type: "FileCreate".into(),
                compare_source: "MFT".into(),
                min_delta_seconds: 60,
                direction: "before".into(),
            }],
        },
        // Timestomping: MFT born time later than modify time.
        TemporalRule {
            id: "temporal.timestomping-born-after-modify".into(),
            title: "File born time later than modify time — timestomping indicator".into(),
            severity: "high".into(),
            description: None,
            within_seconds: 86400,
            anchor: EventTypeFilter::new("FileCreate").with_source("MFT"),
            sequence: vec![],
            absent: vec![],
            discrepancy: vec![DiscrepancyClause {
                entity_role: "path".into(),
                compare_event_type: "FileModify".into(),
                compare_source: "MFT".into(),
                min_delta_seconds: 1,
                direction: "after".into(),
            }],
        },
        // Ran-then-deleted: Prefetch exec followed by UsnJrnl delete.
        TemporalRule {
            id: "temporal.ran-then-deleted".into(),
            title: "Executable ran then deleted — anti-forensic or dropper".into(),
            severity: "high".into(),
            description: None,
            within_seconds: 3600,
            anchor: EventTypeFilter::new("ProcessExec").with_source("Prefetch"),
            sequence: vec![EventTypeFilter::new("FileDelete").with_source("USN Journal")],
            absent: vec![],
            discrepancy: vec![],
        },
        // PAM hook artifact: /tmp/silly.txt appears after logon.
        TemporalRule {
            id: "temporal.pam-hook-artifact".into(),
            title: "/tmp/silly.txt created on logon — PAM hook indicator".into(),
            severity: "critical".into(),
            description: None,
            within_seconds: 10,
            anchor: EventTypeFilter::new("LogonSuccess"),
            sequence: vec![EventTypeFilter::new("FileCreate").with_description("/tmp/silly.txt")],
            absent: vec![],
            discrepancy: vec![],
        },
    ]
}

/// Evaluate a `TemporalRule` against a slice of timeline events.
///
/// Returns one [`TemporalFinding`] per anchor event that satisfies all clauses.
///
/// - Sequence clauses: all must be present within the time window.
/// - Absent clauses: all must be absent from the window.
/// - Discrepancy clauses: at least one must detect a timestamp contradiction.
///
/// The time window is symmetric (±`within_seconds`) around the anchor timestamp.
#[must_use]
pub fn evaluate_temporal(rule: &TemporalRule, events: &[TimelineEvent]) -> Vec<TemporalFinding> {
    let within_ns = rule.within_seconds.saturating_mul(1_000_000_000);
    let mut findings = Vec::new();

    for anchor in events.iter().filter(|e| filter_matches(e, &rule.anchor)) {
        // Collect events within the time window (excluding anchor itself).
        let window: Vec<&TimelineEvent> = events
            .iter()
            .filter(|e| {
                e.record_hash != anchor.record_hash
                    && (e.timestamp_ns - anchor.timestamp_ns).abs() <= within_ns
            })
            .collect();

        // 1. Sequence clauses: every filter must match at least one window event.
        let mut matched_hashes: Vec<String> = Vec::new();
        let mut sequence_ok = true;
        for seq_filter in &rule.sequence {
            if let Some(ev) = window.iter().find(|e| filter_matches(e, seq_filter)) {
                matched_hashes.push(ev.record_hash.clone());
            } else {
                sequence_ok = false;
                break;
            }
        }
        if !sequence_ok {
            continue;
        }

        // 2. Absent clauses: none of the absent filters may match any window event.
        let all_absent = rule
            .absent
            .iter()
            .all(|abs_filter| !window.iter().any(|e| filter_matches(e, abs_filter)));
        if !all_absent {
            continue;
        }

        // 3. Discrepancy clauses: if any are defined, at least one must fire.
        if rule.discrepancy.is_empty() {
            // No discrepancy clauses — fire based on sequence + absent alone.
            findings.push(TemporalFinding {
                rule_id: rule.id.clone(),
                title: rule.title.clone(),
                severity: rule.severity.clone(),
                anchor_record_hash: anchor.record_hash.clone(),
                matched_record_hashes: matched_hashes,
                discrepancy: None,
            });
        } else {
            let mut found_discrepancy: Option<DiscrepancyDetail> = None;

            'outer: for clause in &rule.discrepancy {
                // Find anchor entity refs matching the entity_role.
                for anchor_ref in anchor.entity_refs.iter().filter(|r| {
                    entity_role_matches(r, &clause.entity_role)
                }) {
                    let anchor_key = entity_key(anchor_ref);

                    // Find a compare event in the FULL events slice (not window-restricted)
                    // that shares the same entity and matches the compare filters.
                    for compare in events.iter().filter(|e| {
                        e.record_hash != anchor.record_hash
                            && event_type_str_matches(e, &clause.compare_event_type)
                            && source_str_matches(e, &clause.compare_source)
                            && e.entity_refs.iter().any(|r| entity_key(r) == anchor_key)
                    }) {
                        let delta_ns =
                            (compare.timestamp_ns - anchor.timestamp_ns).abs();
                        let min_delta_ns =
                            clause.min_delta_seconds.saturating_mul(1_000_000_000);

                        let contradiction = match clause.direction.as_str() {
                            "after" => {
                                // Fires when anchor is AFTER compare by at least min_delta
                                anchor.timestamp_ns > compare.timestamp_ns + min_delta_ns
                            }
                            _ => {
                                // "before" (default): fires when anchor is BEFORE compare
                                // by at least min_delta
                                anchor.timestamp_ns + min_delta_ns < compare.timestamp_ns
                            }
                        };

                        if contradiction {
                            found_discrepancy = Some(DiscrepancyDetail {
                                entity_key: anchor_key.clone(),
                                anchor_source: format!("{:?}", anchor.source),
                                anchor_timestamp_ns: anchor.timestamp_ns,
                                compare_source: clause.compare_source.clone(),
                                compare_timestamp_ns: compare.timestamp_ns,
                                delta_ns,
                            });
                            matched_hashes.push(compare.record_hash.clone());
                            break 'outer;
                        }
                    }
                }
            }

            if found_discrepancy.is_none() {
                continue;
            }

            findings.push(TemporalFinding {
                rule_id: rule.id.clone(),
                title: rule.title.clone(),
                severity: rule.severity.clone(),
                anchor_record_hash: anchor.record_hash.clone(),
                matched_record_hashes: matched_hashes,
                discrepancy: found_discrepancy,
            });
        }
    }

    findings
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Returns true when `event` matches all non-None fields of `filter`.
fn filter_matches(event: &TimelineEvent, filter: &EventTypeFilter) -> bool {
    if !event_type_str_matches(event, &filter.event_type) {
        return false;
    }
    if let Some(ref src) = filter.source {
        if !source_str_matches(event, src) {
            return false;
        }
    }
    if let Some(ref needle) = filter.description_contains {
        if !event.description.contains(needle.as_str()) {
            return false;
        }
    }
    true
}

/// Match `event_type` by display string (e.g. `"ProcessExec"`, `"FileCreate"`).
fn event_type_str_matches(event: &TimelineEvent, type_str: &str) -> bool {
    format!("{:?}", event.event_type) == type_str
}

/// Match artifact source by display string (e.g. `"MFT"`, `"Event Log"`).
fn source_str_matches(event: &TimelineEvent, source_str: &str) -> bool {
    format!("{}", event.source) == source_str
}

/// Check whether an `EntityRef` matches the role string (`"path"`, `"process"`, etc.).
fn entity_role_matches(entity: &EntityRef, role: &str) -> bool {
    matches!(
        (entity, role),
        (EntityRef::FilePath(_), "path")
            | (EntityRef::Process(_), "process")
            | (EntityRef::User(_), "user")
            | (EntityRef::Ip(_), "ip")
            | (EntityRef::Session(_), "session")
    )
}

/// Canonical string key for an entity ref (mirrors `EntityIndex::entity_key`).
fn entity_key(entity: &EntityRef) -> String {
    match entity {
        EntityRef::FilePath(p) => format!("path:{p}"),
        EntityRef::Process(n) => format!("proc:{n}"),
        EntityRef::User(u) => format!("user:{u}"),
        EntityRef::Ip(a) => format!("ip:{a}"),
        EntityRef::Session(id) => format!("session:0x{id:x}"),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const NS: i64 = 1_000_000_000; // 1 second in nanoseconds

    fn ev(
        ts_ns: i64,
        event_type: EventType,
        source: ArtifactType,
        description: &str,
    ) -> TimelineEvent {
        TimelineEvent::new(
            ts_ns,
            format!("{ts_ns}"),
            event_type,
            source,
            "/test/artifact".to_string(),
            description.to_string(),
            "evidence-001".to_string(),
        )
    }

    fn ev_path(
        ts_ns: i64,
        event_type: EventType,
        source: ArtifactType,
        description: &str,
        path: &str,
    ) -> TimelineEvent {
        ev(ts_ns, event_type, source, description)
            .with_entity_ref(EntityRef::FilePath(path.to_string()))
    }

    // ── Phase 2 RED tests ─────────────────────────────────────────────────────

    #[test]
    fn temporal_rule_within_60s_matches_sequence() {
        let rule = TemporalRule {
            id: "test.sequence".into(),
            title: "Process exec followed by file create".into(),
            severity: "medium".into(),
            description: None,
            within_seconds: 60,
            anchor: EventTypeFilter::new("ProcessExec"),
            sequence: vec![EventTypeFilter::new("FileCreate")],
            absent: vec![],
            discrepancy: vec![],
        };

        let anchor = ev(100 * NS, EventType::ProcessExec, ArtifactType::EventLog, "cmd.exe");
        // FileCreate at T+30s — within 60s window
        let create = ev(130 * NS, EventType::FileCreate, ArtifactType::UsnJournal, "output.exe");
        // Far event outside window
        let far = ev(300 * NS, EventType::FileCreate, ArtifactType::UsnJournal, "other.exe");

        let events = vec![anchor, create, far];
        let findings = evaluate_temporal(&rule, &events);

        assert_eq!(findings.len(), 1, "one anchor event should produce one finding");
        assert_eq!(findings[0].rule_id, "test.sequence");
        assert!(!findings[0].matched_record_hashes.is_empty());
    }

    #[test]
    fn temporal_rule_outside_window_no_match() {
        let rule = TemporalRule {
            id: "test.sequence.window".into(),
            title: "Sequence with tight window".into(),
            severity: "low".into(),
            description: None,
            within_seconds: 60,
            anchor: EventTypeFilter::new("ProcessExec"),
            sequence: vec![EventTypeFilter::new("FileCreate")],
            absent: vec![],
            discrepancy: vec![],
        };

        let anchor = ev(100 * NS, EventType::ProcessExec, ArtifactType::EventLog, "cmd.exe");
        // FileCreate at T+200s — OUTSIDE 60s window
        let too_late = ev(300 * NS, EventType::FileCreate, ArtifactType::UsnJournal, "late.exe");

        let events = vec![anchor, too_late];
        let findings = evaluate_temporal(&rule, &events);

        assert!(findings.is_empty(), "event outside window must not produce a finding");
    }

    #[test]
    fn absent_clause_fires_when_prefetch_missing_after_4688() {
        // 4688 process-creation with NO Prefetch update within 5s → hollow process signal
        let rule = TemporalRule {
            id: "temporal.hollow-process".into(),
            title: "Process creation without Prefetch update".into(),
            severity: "high".into(),
            description: Some(
                "A 4688 event with no corresponding Prefetch FileModify within 5s \
                 suggests process hollowing or injection."
                    .into(),
            ),
            within_seconds: 5,
            anchor: EventTypeFilter::new("ProcessExec").with_source("Event Log"),
            sequence: vec![],
            absent: vec![EventTypeFilter::new("FileModify").with_source("Prefetch")],
            discrepancy: vec![],
        };

        let exec = ev(
            100 * NS,
            EventType::ProcessExec,
            ArtifactType::EventLog,
            "4688: svchost.exe",
        );
        // Only a FileCreate in the window, not a FileModify from Prefetch
        let other_create = ev(
            101 * NS,
            EventType::FileCreate,
            ArtifactType::UsnJournal,
            "temp file",
        );

        let events = vec![exec, other_create];
        let findings = evaluate_temporal(&rule, &events);

        assert_eq!(
            findings.len(),
            1,
            "absent Prefetch FileModify should produce a finding"
        );
        assert_eq!(findings[0].rule_id, "temporal.hollow-process");
    }

    #[test]
    fn discrepancy_clause_fires_when_log_timestamp_before_mft_born_time() {
        // An EventLog event references a file at T1.
        // The file's $MFT born time (FileCreate) is T2 > T1.
        // This means the log proves the file existed before MFT claims it was created.
        let rule = TemporalRule {
            id: "temporal.log-predates-mft-create".into(),
            title: "Log references file before MFT creation timestamp".into(),
            severity: "high".into(),
            description: None,
            within_seconds: 3600,
            anchor: EventTypeFilter::new("FileCreate").with_source("Event Log"),
            sequence: vec![],
            absent: vec![],
            discrepancy: vec![DiscrepancyClause {
                entity_role: "path".into(),
                compare_event_type: "FileCreate".into(),
                compare_source: "MFT".into(),
                min_delta_seconds: 60,
                direction: "before".into(),
            }],
        };

        let path = "/lib/x86_64-linux-gnu/libsuspect.so.1";
        // EventLog references the file at T=100s (anchor)
        let log_event = ev_path(
            100 * NS,
            EventType::FileCreate,
            ArtifactType::EventLog,
            "libsuspect.so.1 loaded",
            path,
        );
        // MFT says the file was born at T=300s (200s later)
        let mft_born = ev_path(
            300 * NS,
            EventType::FileCreate,
            ArtifactType::Mft,
            "file created: libsuspect.so.1",
            path,
        );

        let events = vec![log_event, mft_born];
        let findings = evaluate_temporal(&rule, &events);

        assert_eq!(
            findings.len(),
            1,
            "log timestamp before MFT born time should produce a discrepancy finding"
        );
        assert!(findings[0].discrepancy.is_some());
        let detail = findings[0].discrepancy.as_ref().unwrap();
        assert!(detail.delta_ns >= 200 * NS, "delta should be at least 200s");
    }

    #[test]
    fn boot_log_anchor_contradicts_file_mtime() {
        // CTF pattern: boot log at 23:16 mentions libymv.so.3 as "file too short",
        // but $MFT born time for the same file is 23:24 — 8 minutes later.
        // The boot log proves the rootkit existed BEFORE the MFT says it was created.
        let rule = TemporalRule {
            id: "temporal.boot-log-predates-mft".into(),
            title: "Boot log predates MFT file creation — possible timestomping or rootkit".into(),
            severity: "critical".into(),
            description: None,
            within_seconds: 3600,
            anchor: EventTypeFilter::new("SystemBoot").with_source("Event Log"),
            sequence: vec![],
            absent: vec![],
            discrepancy: vec![DiscrepancyClause {
                entity_role: "path".into(),
                compare_event_type: "FileCreate".into(),
                compare_source: "MFT".into(),
                min_delta_seconds: 60,
                direction: "before".into(),
            }],
        };

        let path = "/lib/x86_64-linux-gnu/libymv.so.3";
        let t_boot: i64 = 1_711_228_560 * NS; // 2024-03-24 23:16:00 UTC
        let t_mft: i64 = 1_711_229_040 * NS;  // 2024-03-24 23:24:00 UTC (+8min)

        let boot_log = ev_path(
            t_boot,
            EventType::SystemBoot,
            ArtifactType::EventLog,
            "/lib/x86_64-linux-gnu/libymv.so.3: file too short",
            path,
        );
        let mft_create = ev_path(
            t_mft,
            EventType::FileCreate,
            ArtifactType::Mft,
            "file created: libymv.so.3",
            path,
        );

        let events = vec![boot_log, mft_create];
        let findings = evaluate_temporal(&rule, &events);

        assert_eq!(findings.len(), 1, "boot log predating MFT born time is a critical finding");
        assert_eq!(findings[0].severity, "critical");
        let detail = findings[0].discrepancy.as_ref().expect("discrepancy detail must be set");
        assert!(
            detail.delta_ns >= 8 * 60 * NS,
            "delta must be at least 8 minutes"
        );
    }

    #[test]
    fn father_rootkit_gid_7823_anomaly_detected() {
        // Father rootkit creates files owned by GID 7823 (unusual system GID).
        // Rule: FileCreate within 300s of SystemBoot that mentions gid:7823.
        let rule = TemporalRule {
            id: "temporal.father-rootkit-gid".into(),
            title: "File with unusual GID 7823 created near boot".into(),
            severity: "critical".into(),
            description: None,
            within_seconds: 300,
            anchor: EventTypeFilter::new("SystemBoot"),
            sequence: vec![
                EventTypeFilter::new("FileCreate")
                    .with_description("gid:7823"),
            ],
            absent: vec![],
            discrepancy: vec![],
        };

        let boot = ev(0, EventType::SystemBoot, ArtifactType::EventLog, "system boot");
        let rootkit_file = ev(
            60 * NS,
            EventType::FileCreate,
            ArtifactType::Mft,
            "created /proc/.hidden/entry gid:7823",
        );

        let events = vec![boot, rootkit_file];
        let findings = evaluate_temporal(&rule, &events);

        assert_eq!(
            findings.len(),
            1,
            "FileCreate with gid:7823 near boot should fire Father rootkit rule"
        );
    }

    #[test]
    fn pam_hook_artifact_tmp_silly_txt_detected() {
        // PAM hook persistence: a malicious PAM module creates /tmp/silly.txt
        // on each successful authentication as proof-of-execution.
        let rule = TemporalRule {
            id: "temporal.pam-hook-artifact".into(),
            title: "/tmp/silly.txt created on logon — PAM hook indicator".into(),
            severity: "critical".into(),
            description: None,
            within_seconds: 10,
            anchor: EventTypeFilter::new("LogonSuccess"),
            sequence: vec![
                EventTypeFilter::new("FileCreate").with_description("/tmp/silly.txt"),
            ],
            absent: vec![],
            discrepancy: vec![],
        };

        let logon = ev(100 * NS, EventType::LogonSuccess, ArtifactType::EventLog, "user root");
        let silly = ev(
            103 * NS,
            EventType::FileCreate,
            ArtifactType::UsnJournal,
            "created /tmp/silly.txt",
        );

        let events = vec![logon, silly];
        let findings = evaluate_temporal(&rule, &events);

        assert_eq!(
            findings.len(),
            1,
            "/tmp/silly.txt after LogonSuccess should fire PAM hook rule"
        );
    }

    #[test]
    fn deleted_execution_recovery_usnjrnl_plus_prefetch() {
        // Binary ran (Prefetch entry exists) then was deleted (UsnJrnl CLOSE+DELETE).
        // Pattern: ProcessExec (Prefetch) followed by FileDelete (UsnJrnl) for same entity.
        let rule = TemporalRule {
            id: "temporal.ran-then-deleted".into(),
            title: "Executable ran then deleted — anti-forensic or dropper".into(),
            severity: "high".into(),
            description: None,
            within_seconds: 3600,
            anchor: EventTypeFilter::new("ProcessExec").with_source("Prefetch"),
            sequence: vec![
                EventTypeFilter::new("FileDelete").with_source("USN Journal"),
            ],
            absent: vec![],
            discrepancy: vec![],
        };

        let path = "C:\\Users\\user\\AppData\\Local\\Temp\\payload.exe";
        let exec = ev_path(
            100 * NS,
            EventType::ProcessExec,
            ArtifactType::Prefetch,
            "payload.exe first run",
            path,
        );
        let delete = ev_path(
            500 * NS,
            EventType::FileDelete,
            ArtifactType::UsnJournal,
            "payload.exe deleted",
            path,
        );

        let events = vec![exec, delete];
        let findings = evaluate_temporal(&rule, &events);

        assert_eq!(
            findings.len(),
            1,
            "Prefetch exec followed by UsnJrnl delete on same path is a ran-then-deleted finding"
        );
    }

    #[test]
    fn timestomping_mft_born_after_modify() {
        // Classic timestomping: attacker modified $STANDARD_INFORMATION timestamps,
        // leaving the born time (FileCreate) LATER than the modify time (FileModify).
        // This is logically impossible without timestamp manipulation.
        //
        // Rule anchors on FileCreate (born time) and compares it with FileModify:
        //   direction="after" fires when anchor(born=500s) > compare(modify=100s)
        let rule = TemporalRule {
            id: "temporal.timestomping-born-after-modify".into(),
            title: "File born time later than modify time — timestomping indicator".into(),
            severity: "high".into(),
            description: None,
            within_seconds: 86400, // 24-hour window
            anchor: EventTypeFilter::new("FileCreate").with_source("MFT"),
            sequence: vec![],
            absent: vec![],
            discrepancy: vec![DiscrepancyClause {
                entity_role: "path".into(),
                compare_event_type: "FileModify".into(),
                compare_source: "MFT".into(),
                min_delta_seconds: 1,
                // "after": fires when anchor.timestamp > compare.timestamp
                // i.e. born time (anchor) is AFTER modify time (compare) — contradiction
                direction: "after".into(),
            }],
        };

        let path = "C:\\Windows\\System32\\legit.dll";
        // FileModify at T=100s — the earlier modify timestamp
        let modify = ev_path(
            100 * NS,
            EventType::FileModify,
            ArtifactType::Mft,
            "legit.dll modified",
            path,
        );
        // Born time at T=500s — LATER than modify, which is physically impossible
        let born = ev_path(
            500 * NS,
            EventType::FileCreate,
            ArtifactType::Mft,
            "legit.dll created (born time)",
            path,
        );

        // Anchor is born (FileCreate=500s); compare is modify (FileModify=100s).
        // direction="after" fires because anchor(500s) > compare(100s) + 1s.
        let events = vec![modify, born];
        let findings = evaluate_temporal(&rule, &events);

        assert_eq!(
            findings.len(),
            1,
            "born time (500s) later than modify time (100s) is a timestomping finding"
        );
    }

    #[test]
    fn bundled_temporal_rules_exposes_the_named_rule_set() {
        // issen #110 Phase 2: the five bundled rules live here (shared registry)
        // so `correlate` and `timeline --narrative` evaluate one set, not a
        // CLI-private copy.
        let rules = bundled_temporal_rules();
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        for expected in [
            "temporal.hollow-process",
            "temporal.boot-log-predates-mft",
            "temporal.timestomping-born-after-modify",
            "temporal.ran-then-deleted",
            "temporal.pam-hook-artifact",
        ] {
            assert!(
                ids.contains(&expected),
                "registry missing {expected}; got {ids:?}"
            );
        }
    }

    // ── issen #110/#112 vetted temporal rules (red_scenario-driven) ─────────────

    #[test]
    fn rule_sam_security_hive_copy() {
        let rule = bundled_temporal_rules()
            .into_iter()
            .find(|r| r.id == "temporal.sam-security-hive-copy")
            .expect("rule temporal.sam-security-hive-copy must be registered");

        let mut e0 = ev(3000000000000000, EventType::FileAccess, ArtifactType::EventLog, "handle to C:\\Windows\\System32\\config\\SAM opened");
        e0 = e0.with_entity_ref(EntityRef::FilePath("C:\\Windows\\System32\\config\\SAM".to_string()));
        let mut e1 = ev(3000020000000000, EventType::FileCreate, ArtifactType::UsnJournal, "USN CREATE: C:\\Users\\Public\\sam.save");
        e1 = e1.with_entity_ref(EntityRef::FilePath("C:\\Users\\Public\\sam.save".to_string()));
        let fire_events = vec![e0, e1];
        let fire = evaluate_temporal(&rule, &fire_events);
        assert!(
            fire.iter().any(|f| f.rule_id == "temporal.sam-security-hive-copy"),
            "temporal.sam-security-hive-copy should_fire produced no finding: {fire:?}"
        );

        let mut en0 = ev(4000000000000000, EventType::FileAccess, ArtifactType::EventLog, "handle to C:\\Windows\\System32\\config\\SOFTWARE opened (not SAM)");
        en0 = en0.with_entity_ref(EntityRef::FilePath("C:\\Windows\\System32\\config\\SOFTWARE".to_string()));
        let mut en1 = ev(4000020000000000, EventType::FileCreate, ArtifactType::UsnJournal, "USN CREATE: C:\\Temp\\report.docx");
        en1 = en1.with_entity_ref(EntityRef::FilePath("C:\\Temp\\report.docx".to_string()));
        let quiet_events = vec![en0, en1];
        let quiet = evaluate_temporal(&rule, &quiet_events);
        assert!(
            !quiet.iter().any(|f| f.rule_id == "temporal.sam-security-hive-copy"),
            "temporal.sam-security-hive-copy should_not unexpectedly fired: {quiet:?}"
        );
    }

    #[test]
    fn rule_logon_failure_burst_then_success() {
        let rule = bundled_temporal_rules()
            .into_iter()
            .find(|r| r.id == "temporal.logon-failure-burst-then-success")
            .expect("rule temporal.logon-failure-burst-then-success must be registered");

        let mut e0 = ev(5000000000000000, EventType::LogonFailure, ArtifactType::EventLog, "4625 failed logon: bad password (administrator)");
        e0 = e0.with_entity_ref(EntityRef::User("administrator".to_string()));
        let mut e1 = ev(5000030000000000, EventType::LogonSuccess, ArtifactType::EventLog, "4624 successful logon (administrator)");
        e1 = e1.with_entity_ref(EntityRef::User("administrator".to_string()));
        let fire_events = vec![e0, e1];
        let fire = evaluate_temporal(&rule, &fire_events);
        assert!(
            fire.iter().any(|f| f.rule_id == "temporal.logon-failure-burst-then-success"),
            "temporal.logon-failure-burst-then-success should_fire produced no finding: {fire:?}"
        );

        let mut en0 = ev(6000000000000000, EventType::LogonSuccess, ArtifactType::EventLog, "4624 clean interactive logon, no preceding failures");
        en0 = en0.with_entity_ref(EntityRef::User("alice".to_string()));
        let quiet_events = vec![en0];
        let quiet = evaluate_temporal(&rule, &quiet_events);
        assert!(
            !quiet.iter().any(|f| f.rule_id == "temporal.logon-failure-burst-then-success"),
            "temporal.logon-failure-burst-then-success should_not unexpectedly fired: {quiet:?}"
        );
    }

    #[test]
    fn rule_exec_residue_predates_image_mft_birth() {
        let rule = bundled_temporal_rules()
            .into_iter()
            .find(|r| r.id == "temporal.exec-residue-predates-image-mft-birth")
            .expect("rule temporal.exec-residue-predates-image-mft-birth must be registered");

        let mut e0 = ev(1000000000000000, EventType::ProcessExec, ArtifactType::Prefetch, "Prefetch last-run time for image");
        e0 = e0.with_entity_ref(EntityRef::FilePath("C:\\Windows\\Temp\\svc.exe".to_string()));
        let mut e1 = ev(1000600000000000, EventType::FileCreate, ArtifactType::Mft, "$MFT $SI born time for the same image (600 s later)");
        e1 = e1.with_entity_ref(EntityRef::FilePath("C:\\Windows\\Temp\\svc.exe".to_string()));
        let fire_events = vec![e0, e1];
        let fire = evaluate_temporal(&rule, &fire_events);
        assert!(
            fire.iter().any(|f| f.rule_id == "temporal.exec-residue-predates-image-mft-birth"),
            "temporal.exec-residue-predates-image-mft-birth should_fire produced no finding: {fire:?}"
        );

        let mut en0 = ev(2000000000000000, EventType::ProcessExec, ArtifactType::Prefetch, "Prefetch last-run time for a normally-installed image");
        en0 = en0.with_entity_ref(EntityRef::FilePath("C:\\Program Files\\App\\app.exe".to_string()));
        let mut en1 = ev(1999900000000000, EventType::FileCreate, ArtifactType::Mft, "$MFT born time precedes the run by 100 s (normal: created then run)");
        en1 = en1.with_entity_ref(EntityRef::FilePath("C:\\Program Files\\App\\app.exe".to_string()));
        let quiet_events = vec![en0, en1];
        let quiet = evaluate_temporal(&rule, &quiet_events);
        assert!(
            !quiet.iter().any(|f| f.rule_id == "temporal.exec-residue-predates-image-mft-birth"),
            "temporal.exec-residue-predates-image-mft-birth should_not unexpectedly fired: {quiet:?}"
        );
    }

    #[test]
    fn rule_amcache_exec_predates_mft_born() {
        let rule = bundled_temporal_rules()
            .into_iter()
            .find(|r| r.id == "temporal.amcache-exec-predates-mft-born")
            .expect("rule temporal.amcache-exec-predates-mft-born must be registered");

        let mut e0 = ev(7000000000000000, EventType::ProcessExec, ArtifactType::Amcache, "Amcache first-execution time for image");
        e0 = e0.with_entity_ref(EntityRef::FilePath("C:\\Users\\Public\\runner.exe".to_string()));
        let mut e1 = ev(7000600000000000, EventType::FileCreate, ArtifactType::Mft, "$MFT $SI born time for the same image (600 s later)");
        e1 = e1.with_entity_ref(EntityRef::FilePath("C:\\Users\\Public\\runner.exe".to_string()));
        let fire_events = vec![e0, e1];
        let fire = evaluate_temporal(&rule, &fire_events);
        assert!(
            fire.iter().any(|f| f.rule_id == "temporal.amcache-exec-predates-mft-born"),
            "temporal.amcache-exec-predates-mft-born should_fire produced no finding: {fire:?}"
        );

        let mut en0 = ev(8000000000000000, EventType::ProcessExec, ArtifactType::Amcache, "Amcache first-execution for a normally-installed image");
        en0 = en0.with_entity_ref(EntityRef::FilePath("C:\\Program Files\\Tool\\tool.exe".to_string()));
        let mut en1 = ev(7999900000000000, EventType::FileCreate, ArtifactType::Mft, "$MFT born time precedes the first run by 100 s (normal order)");
        en1 = en1.with_entity_ref(EntityRef::FilePath("C:\\Program Files\\Tool\\tool.exe".to_string()));
        let quiet_events = vec![en0, en1];
        let quiet = evaluate_temporal(&rule, &quiet_events);
        assert!(
            !quiet.iter().any(|f| f.rule_id == "temporal.amcache-exec-predates-mft-born"),
            "temporal.amcache-exec-predates-mft-born should_not unexpectedly fired: {quiet:?}"
        );
    }

    #[test]
    fn rule_persistence_created_then_dropper_deleted() {
        let rule = bundled_temporal_rules()
            .into_iter()
            .find(|r| r.id == "temporal.persistence-created-then-dropper-deleted")
            .expect("rule temporal.persistence-created-then-dropper-deleted must be registered");

        let mut e0 = ev(1000000000000000, EventType::ScheduledTaskCreate, ArtifactType::EventLog, "EID 4698: scheduled task \\Updater registered");
        e0 = e0.with_entity_ref(EntityRef::FilePath("C:/Windows/Tasks/Updater".to_string()));
        let mut e1 = ev(1000090000000000, EventType::FileDelete, ArtifactType::UsnJournal, "USN CLOSE+DELETE: C:/Users/Public/setup_tmp.exe");
        e1 = e1.with_entity_ref(EntityRef::FilePath("C:/Users/Public/setup_tmp.exe".to_string()));
        let fire_events = vec![e0, e1];
        let fire = evaluate_temporal(&rule, &fire_events);
        assert!(
            fire.iter().any(|f| f.rule_id == "temporal.persistence-created-then-dropper-deleted"),
            "temporal.persistence-created-then-dropper-deleted should_fire produced no finding: {fire:?}"
        );

        let mut en0 = ev(1000000000000000, EventType::ScheduledTaskCreate, ArtifactType::EventLog, "EID 4698: GoogleUpdateTaskMachineCore registered");
        en0 = en0.with_entity_ref(EntityRef::FilePath("C:/Windows/Tasks/GoogleUpdateTaskMachineCore".to_string()));
        let mut en1 = ev(2000000000000000, EventType::FileDelete, ArtifactType::UsnJournal, "USN DELETE: C:/Windows/Temp/installer.log");
        en1 = en1.with_entity_ref(EntityRef::FilePath("C:/Windows/Temp/installer.log".to_string()));
        let quiet_events = vec![en0, en1];
        let quiet = evaluate_temporal(&rule, &quiet_events);
        assert!(
            !quiet.iter().any(|f| f.rule_id == "temporal.persistence-created-then-dropper-deleted"),
            "temporal.persistence-created-then-dropper-deleted should_not unexpectedly fired: {quiet:?}"
        );
    }

    #[test]
    fn rule_shadow_copy_deletion_near_mass_delete() {
        let rule = bundled_temporal_rules()
            .into_iter()
            .find(|r| r.id == "temporal.shadow-copy-deletion-near-mass-delete")
            .expect("rule temporal.shadow-copy-deletion-near-mass-delete must be registered");

        let mut e0 = ev(9000000000000000, EventType::ProcessExec, ArtifactType::Prefetch, "VSSADMIN.EXE delete shadows /all /quiet");
        e0 = e0.with_entity_ref(EntityRef::Process("vssadmin.exe".to_string()));
        let mut e1 = ev(9000060000000000, EventType::FileDelete, ArtifactType::UsnJournal, "USN DELETE: C:/Users/Bob/Documents/report.xlsx");
        e1 = e1.with_entity_ref(EntityRef::FilePath("C:/Users/Bob/Documents/report.xlsx".to_string()));
        let fire_events = vec![e0, e1];
        let fire = evaluate_temporal(&rule, &fire_events);
        assert!(
            fire.iter().any(|f| f.rule_id == "temporal.shadow-copy-deletion-near-mass-delete"),
            "temporal.shadow-copy-deletion-near-mass-delete should_fire produced no finding: {fire:?}"
        );

        let mut en0 = ev(10000000000000000, EventType::ProcessExec, ArtifactType::Prefetch, "VSSADMIN.EXE list shadows (read-only enumeration)");
        en0 = en0.with_entity_ref(EntityRef::Process("vssadmin.exe".to_string()));
        let mut en1 = ev(10000060000000000, EventType::FileDelete, ArtifactType::UsnJournal, "USN DELETE: C:/Temp/cache.tmp");
        en1 = en1.with_entity_ref(EntityRef::FilePath("C:/Temp/cache.tmp".to_string()));
        let quiet_events = vec![en0, en1];
        let quiet = evaluate_temporal(&rule, &quiet_events);
        assert!(
            !quiet.iter().any(|f| f.rule_id == "temporal.shadow-copy-deletion-near-mass-delete"),
            "temporal.shadow-copy-deletion-near-mass-delete should_not unexpectedly fired: {quiet:?}"
        );
    }

    #[test]
    fn rule_backup_catalog_deleted_near_archiver() {
        let rule = bundled_temporal_rules()
            .into_iter()
            .find(|r| r.id == "temporal.backup-catalog-deleted-near-archiver")
            .expect("rule temporal.backup-catalog-deleted-near-archiver must be registered");

        let mut e0 = ev(11000000000000000, EventType::ProcessExec, ArtifactType::Prefetch, "WBADMIN.EXE delete catalog -quiet");
        e0 = e0.with_entity_ref(EntityRef::Process("wbadmin.exe".to_string()));
        let mut e1 = ev(11000050000000000, EventType::FileDelete, ArtifactType::UsnJournal, "USN DELETE: C:/WindowsImageBackup/Catalog/BackupGlobalCatalog");
        e1 = e1.with_entity_ref(EntityRef::FilePath("C:/WindowsImageBackup/Catalog/BackupGlobalCatalog".to_string()));
        let fire_events = vec![e0, e1];
        let fire = evaluate_temporal(&rule, &fire_events);
        assert!(
            fire.iter().any(|f| f.rule_id == "temporal.backup-catalog-deleted-near-archiver"),
            "temporal.backup-catalog-deleted-near-archiver should_fire produced no finding: {fire:?}"
        );

        let mut en0 = ev(12000000000000000, EventType::ProcessExec, ArtifactType::Prefetch, "WBADMIN.EXE get versions (read-only)");
        en0 = en0.with_entity_ref(EntityRef::Process("wbadmin.exe".to_string()));
        let mut en1 = ev(12000050000000000, EventType::FileDelete, ArtifactType::UsnJournal, "USN DELETE: C:/Temp/scratch.bin (not the backup catalog)");
        en1 = en1.with_entity_ref(EntityRef::FilePath("C:/Temp/scratch.bin".to_string()));
        let quiet_events = vec![en0, en1];
        let quiet = evaluate_temporal(&rule, &quiet_events);
        assert!(
            !quiet.iter().any(|f| f.rule_id == "temporal.backup-catalog-deleted-near-archiver"),
            "temporal.backup-catalog-deleted-near-archiver should_not unexpectedly fired: {quiet:?}"
        );
    }

    #[test]
    fn rule_mass_file_modify_burst() {
        let rule = bundled_temporal_rules()
            .into_iter()
            .find(|r| r.id == "temporal.mass-file-modify-burst")
            .expect("rule temporal.mass-file-modify-burst must be registered");

        let mut e0 = ev(13000000000000000, EventType::FileModify, ArtifactType::UsnJournal, "USN DATA_OVERWRITE: C:/Users/Bob/a.docx");
        e0 = e0.with_entity_ref(EntityRef::FilePath("C:/Users/Bob/a.docx".to_string()));
        let mut e1 = ev(13000005000000000, EventType::FileModify, ArtifactType::UsnJournal, "USN DATA_OVERWRITE: C:/Users/Bob/b.xlsx");
        e1 = e1.with_entity_ref(EntityRef::FilePath("C:/Users/Bob/b.xlsx".to_string()));
        let mut e2 = ev(13000008000000000, EventType::FileCreate, ArtifactType::UsnJournal, "USN CREATE: C:/Users/Bob/a.docx.locked");
        e2 = e2.with_entity_ref(EntityRef::FilePath("C:/Users/Bob/a.docx.locked".to_string()));
        let mut e3 = ev(13000010000000000, EventType::FileDelete, ArtifactType::UsnJournal, "USN DELETE: C:/Users/Bob/a.docx");
        e3 = e3.with_entity_ref(EntityRef::FilePath("C:/Users/Bob/a.docx".to_string()));
        let fire_events = vec![e0, e1, e2, e3];
        let fire = evaluate_temporal(&rule, &fire_events);
        assert!(
            fire.iter().any(|f| f.rule_id == "temporal.mass-file-modify-burst"),
            "temporal.mass-file-modify-burst should_fire produced no finding: {fire:?}"
        );

        let mut en0 = ev(14000000000000000, EventType::FileModify, ArtifactType::UsnJournal, "USN DATA_OVERWRITE: single document save");
        en0 = en0.with_entity_ref(EntityRef::FilePath("C:/Users/Bob/notes.txt".to_string()));
        let quiet_events = vec![en0];
        let quiet = evaluate_temporal(&rule, &quiet_events);
        assert!(
            !quiet.iter().any(|f| f.rule_id == "temporal.mass-file-modify-burst"),
            "temporal.mass-file-modify-burst should_not unexpectedly fired: {quiet:?}"
        );
    }

    #[test]
    fn rule_service_install_then_start_exec() {
        let rule = bundled_temporal_rules()
            .into_iter()
            .find(|r| r.id == "temporal.service-install-then-start-exec")
            .expect("rule temporal.service-install-then-start-exec must be registered");

        let mut e0 = ev(5000000000000, EventType::ServiceInstall, ArtifactType::EventLog, "7045 A new service was installed in the system");
        e0 = e0.with_entity_ref(EntityRef::Process("msupdate.exe".to_string()));
        let mut e1 = ev(5008000000000, EventType::ServiceStart, ArtifactType::EventLog, "7036 service entered the running state");
        e1 = e1.with_entity_ref(EntityRef::Process("msupdate.exe".to_string()));
        let mut e2 = ev(5012000000000, EventType::ProcessExec, ArtifactType::Prefetch, "MSUPDATE.EXE first execution");
        e2 = e2.with_entity_ref(EntityRef::Process("msupdate.exe".to_string()));
        let fire_events = vec![e0, e1, e2];
        let fire = evaluate_temporal(&rule, &fire_events);
        assert!(
            fire.iter().any(|f| f.rule_id == "temporal.service-install-then-start-exec"),
            "temporal.service-install-then-start-exec should_fire produced no finding: {fire:?}"
        );

        let mut en0 = ev(6000000000000, EventType::SystemBoot, ArtifactType::EventLog, "system boot");
        let mut en1 = ev(6005000000000, EventType::ServiceStart, ArtifactType::EventLog, "7036 spooler entered running state");
        en1 = en1.with_entity_ref(EntityRef::Process("spoolsv.exe".to_string()));
        let mut en2 = ev(6007000000000, EventType::ProcessExec, ArtifactType::Prefetch, "SPOOLSV.EXE execution");
        en2 = en2.with_entity_ref(EntityRef::Process("spoolsv.exe".to_string()));
        let quiet_events = vec![en0, en1, en2];
        let quiet = evaluate_temporal(&rule, &quiet_events);
        assert!(
            !quiet.iter().any(|f| f.rule_id == "temporal.service-install-then-start-exec"),
            "temporal.service-install-then-start-exec should_not unexpectedly fired: {quiet:?}"
        );
    }

    #[test]
    fn rule_scheduled_task_create_run_burst() {
        let rule = bundled_temporal_rules()
            .into_iter()
            .find(|r| r.id == "temporal.scheduled-task-create-run-burst")
            .expect("rule temporal.scheduled-task-create-run-burst must be registered");

        let mut e0 = ev(12000000000000, EventType::ScheduledTaskCreate, ArtifactType::EventLog, "4698 a scheduled task was created");
        e0 = e0.with_entity_ref(EntityRef::Process("updater.exe".to_string()));
        let mut e1 = ev(12010000000000, EventType::ScheduledTaskRun, ArtifactType::EventLog, "200 action started");
        e1 = e1.with_entity_ref(EntityRef::Process("updater.exe".to_string()));
        let mut e2 = ev(12013000000000, EventType::ProcessExec, ArtifactType::Prefetch, "UPDATER.EXE execution");
        e2 = e2.with_entity_ref(EntityRef::Process("updater.exe".to_string()));
        let fire_events = vec![e0, e1, e2];
        let fire = evaluate_temporal(&rule, &fire_events);
        assert!(
            fire.iter().any(|f| f.rule_id == "temporal.scheduled-task-create-run-burst"),
            "temporal.scheduled-task-create-run-burst should_fire produced no finding: {fire:?}"
        );

        let mut en0 = ev(13000000000000, EventType::ScheduledTaskCreate, ArtifactType::EventLog, "4698 daily backup task created");
        en0 = en0.with_entity_ref(EntityRef::Process("backup.exe".to_string()));
        let mut en1 = ev(13003000000000, EventType::FileModify, ArtifactType::Mft, "task XML written under Tasks");
        en1 = en1.with_entity_ref(EntityRef::Process("backup.exe".to_string()));
        let quiet_events = vec![en0, en1];
        let quiet = evaluate_temporal(&rule, &quiet_events);
        assert!(
            !quiet.iter().any(|f| f.rule_id == "temporal.scheduled-task-create-run-burst"),
            "temporal.scheduled-task-create-run-burst should_not unexpectedly fired: {quiet:?}"
        );
    }

    #[test]
    fn rule_crontab_modified_near_process_exec() {
        let rule = bundled_temporal_rules()
            .into_iter()
            .find(|r| r.id == "temporal.crontab-modified-near-process-exec")
            .expect("rule temporal.crontab-modified-near-process-exec must be registered");

        let mut e0 = ev(15000000000000000, EventType::FileModify, ArtifactType::CrontabConfig, "/var/spool/cron/crontabs/root modified");
        e0 = e0.with_entity_ref(EntityRef::FilePath("/var/spool/cron/crontabs/root".to_string()));
        let mut e1 = ev(15000010000000000, EventType::ProcessExec, ArtifactType::Bodyfile, "/tmp/.x execution");
        e1 = e1.with_entity_ref(EntityRef::Process("/tmp/.x".to_string()));
        let fire_events = vec![e0, e1];
        let fire = evaluate_temporal(&rule, &fire_events);
        assert!(
            fire.iter().any(|f| f.rule_id == "temporal.crontab-modified-near-process-exec"),
            "temporal.crontab-modified-near-process-exec should_fire produced no finding: {fire:?}"
        );

        let mut en0 = ev(16000000000000000, EventType::FileModify, ArtifactType::CrontabConfig, "admin edits crontab by hand");
        en0 = en0.with_entity_ref(EntityRef::FilePath("/var/spool/cron/crontabs/admin".to_string()));
        let mut en1 = ev(16000600000000000, EventType::ProcessExec, ArtifactType::Bodyfile, "unrelated process 600s later");
        en1 = en1.with_entity_ref(EntityRef::Process("/usr/bin/vim".to_string()));
        let quiet_events = vec![en0, en1];
        let quiet = evaluate_temporal(&rule, &quiet_events);
        assert!(
            !quiet.iter().any(|f| f.rule_id == "temporal.crontab-modified-near-process-exec"),
            "temporal.crontab-modified-near-process-exec should_not unexpectedly fired: {quiet:?}"
        );
    }

    #[test]
    fn rule_scheduled_task_created_no_logon() {
        let rule = bundled_temporal_rules()
            .into_iter()
            .find(|r| r.id == "temporal.scheduled-task-created-no-logon")
            .expect("rule temporal.scheduled-task-created-no-logon must be registered");

        let mut e0 = ev(20000000000000, EventType::ScheduledTaskCreate, ArtifactType::EventLog, "scheduled task registered (4698) by resident process");
        e0 = e0.with_entity_ref(EntityRef::Process("implant.exe".to_string()));
        let fire_events = vec![e0];
        let fire = evaluate_temporal(&rule, &fire_events);
        assert!(
            fire.iter().any(|f| f.rule_id == "temporal.scheduled-task-created-no-logon"),
            "temporal.scheduled-task-created-no-logon should_fire produced no finding: {fire:?}"
        );

        let mut en0 = ev(21000000000000, EventType::LogonSuccess, ArtifactType::EventLog, "interactive logon: administrator");
        en0 = en0.with_entity_ref(EntityRef::User("administrator".to_string()));
        let mut en1 = ev(21040000000000, EventType::ScheduledTaskCreate, ArtifactType::EventLog, "admin creates nightly backup task");
        en1 = en1.with_entity_ref(EntityRef::Process("taskeng.exe".to_string()));
        let quiet_events = vec![en0, en1];
        let quiet = evaluate_temporal(&rule, &quiet_events);
        assert!(
            !quiet.iter().any(|f| f.rule_id == "temporal.scheduled-task-created-no-logon"),
            "temporal.scheduled-task-created-no-logon should_not unexpectedly fired: {quiet:?}"
        );
    }

    #[test]
    fn rule_new_admin_account_then_logon() {
        let rule = bundled_temporal_rules()
            .into_iter()
            .find(|r| r.id == "temporal.new-admin-account-then-logon")
            .expect("rule temporal.new-admin-account-then-logon must be registered");

        let mut e0 = ev(17000000000000000, EventType::UserAccountChange, ArtifactType::EventLog, "4720 user account created: svc_backup");
        e0 = e0.with_entity_ref(EntityRef::User("svc_backup".to_string()));
        let mut e1 = ev(17000030000000000, EventType::PolicyChange, ArtifactType::EventLog, "4732 member added to Administrators");
        e1 = e1.with_entity_ref(EntityRef::User("svc_backup".to_string()));
        let mut e2 = ev(17000060000000000, EventType::LogonSuccess, ArtifactType::EventLog, "4624 logon: svc_backup");
        e2 = e2.with_entity_ref(EntityRef::User("svc_backup".to_string()));
        let fire_events = vec![e0, e1, e2];
        let fire = evaluate_temporal(&rule, &fire_events);
        assert!(
            fire.iter().any(|f| f.rule_id == "temporal.new-admin-account-then-logon"),
            "temporal.new-admin-account-then-logon should_fire produced no finding: {fire:?}"
        );

        let mut en0 = ev(18000000000000000, EventType::UserAccountChange, ArtifactType::EventLog, "4720 user account created: intern1 (no privilege change, no logon)");
        en0 = en0.with_entity_ref(EntityRef::User("intern1".to_string()));
        let quiet_events = vec![en0];
        let quiet = evaluate_temporal(&rule, &quiet_events);
        assert!(
            !quiet.iter().any(|f| f.rule_id == "temporal.new-admin-account-then-logon"),
            "temporal.new-admin-account-then-logon should_not unexpectedly fired: {quiet:?}"
        );
    }

    #[test]
    fn rule_exec_without_process_creation_log() {
        let rule = bundled_temporal_rules()
            .into_iter()
            .find(|r| r.id == "temporal.exec-without-process-creation-log")
            .expect("rule temporal.exec-without-process-creation-log must be registered");

        let mut e0 = ev(19000000000000000, EventType::ProcessExec, ArtifactType::Prefetch, "EVIL.EXE execution recorded in Prefetch");
        e0 = e0.with_entity_ref(EntityRef::Process("evil.exe".to_string()));
        let fire_events = vec![e0];
        let fire = evaluate_temporal(&rule, &fire_events);
        assert!(
            fire.iter().any(|f| f.rule_id == "temporal.exec-without-process-creation-log"),
            "temporal.exec-without-process-creation-log should_fire produced no finding: {fire:?}"
        );

        let mut en0 = ev(20000000000000000, EventType::ProcessExec, ArtifactType::Prefetch, "APP.EXE execution in Prefetch");
        en0 = en0.with_entity_ref(EntityRef::Process("app.exe".to_string()));
        let mut en1 = ev(20000010000000000, EventType::ProcessExec, ArtifactType::EventLog, "4688 process creation: app.exe");
        en1 = en1.with_entity_ref(EntityRef::Process("app.exe".to_string()));
        let quiet_events = vec![en0, en1];
        let quiet = evaluate_temporal(&rule, &quiet_events);
        assert!(
            !quiet.iter().any(|f| f.rule_id == "temporal.exec-without-process-creation-log"),
            "temporal.exec-without-process-creation-log should_not unexpectedly fired: {quiet:?}"
        );
    }

    #[test]
    fn rule_network_logon_then_service_install() {
        let rule = bundled_temporal_rules()
            .into_iter()
            .find(|r| r.id == "temporal.network-logon-then-service-install")
            .expect("rule temporal.network-logon-then-service-install must be registered");

        let mut e0 = ev(21000000000000000, EventType::LogonSuccess, ArtifactType::EventLog, "4624 successful logon, Logon Type 3 (network)");
        e0 = e0.with_entity_ref(EntityRef::User("admin".to_string()));
        let mut e1 = ev(21000040000000000, EventType::ServiceInstall, ArtifactType::EventLog, "7045 A new service was installed");
        e1 = e1.with_entity_ref(EntityRef::Process("PSEXESVC.exe".to_string()));
        let fire_events = vec![e0, e1];
        let fire = evaluate_temporal(&rule, &fire_events);
        assert!(
            fire.iter().any(|f| f.rule_id == "temporal.network-logon-then-service-install"),
            "temporal.network-logon-then-service-install should_fire produced no finding: {fire:?}"
        );

        let mut en0 = ev(22000000000000000, EventType::LogonSuccess, ArtifactType::EventLog, "4624 successful logon, Logon Type 2 (interactive)");
        en0 = en0.with_entity_ref(EntityRef::User("admin".to_string()));
        let mut en1 = ev(22000040000000000, EventType::ServiceInstall, ArtifactType::EventLog, "7045 vendor agent service installed");
        en1 = en1.with_entity_ref(EntityRef::Process("agent.exe".to_string()));
        let quiet_events = vec![en0, en1];
        let quiet = evaluate_temporal(&rule, &quiet_events);
        assert!(
            !quiet.iter().any(|f| f.rule_id == "temporal.network-logon-then-service-install"),
            "temporal.network-logon-then-service-install should_not unexpectedly fired: {quiet:?}"
        );
    }

    #[test]
    fn rule_remote_scheduled_task_create_run() {
        let rule = bundled_temporal_rules()
            .into_iter()
            .find(|r| r.id == "temporal.remote-scheduled-task-create-run")
            .expect("rule temporal.remote-scheduled-task-create-run must be registered");

        let mut e0 = ev(23000000000000000, EventType::ScheduledTaskCreate, ArtifactType::EventLog, "4698 scheduled task created via RPC");
        e0 = e0.with_entity_ref(EntityRef::Process("taskhost.exe".to_string()));
        let mut e1 = ev(23000120000000000, EventType::ScheduledTaskRun, ArtifactType::EventLog, "4700/200 task action started");
        e1 = e1.with_entity_ref(EntityRef::Process("taskhost.exe".to_string()));
        let fire_events = vec![e0, e1];
        let fire = evaluate_temporal(&rule, &fire_events);
        assert!(
            fire.iter().any(|f| f.rule_id == "temporal.remote-scheduled-task-create-run"),
            "temporal.remote-scheduled-task-create-run should_fire produced no finding: {fire:?}"
        );

        let mut en0 = ev(24000000000000000, EventType::ScheduledTaskCreate, ArtifactType::EventLog, "4698 long-standing daily task created");
        en0 = en0.with_entity_ref(EntityRef::Process("backup.exe".to_string()));
        let mut en1 = ev(24086400000000000, EventType::ScheduledTaskRun, ArtifactType::EventLog, "task runs 24h later on its schedule");
        en1 = en1.with_entity_ref(EntityRef::Process("backup.exe".to_string()));
        let quiet_events = vec![en0, en1];
        let quiet = evaluate_temporal(&rule, &quiet_events);
        assert!(
            !quiet.iter().any(|f| f.rule_id == "temporal.remote-scheduled-task-create-run"),
            "temporal.remote-scheduled-task-create-run should_not unexpectedly fired: {quiet:?}"
        );
    }

    #[test]
    fn rule_service_install_then_start() {
        let rule = bundled_temporal_rules()
            .into_iter()
            .find(|r| r.id == "temporal.service-install-then-start")
            .expect("rule temporal.service-install-then-start must be registered");

        let mut e0 = ev(1718000000000000000, EventType::ServiceInstall, ArtifactType::EventLog, "New service installed via SCM (EID 7045)");
        e0 = e0.with_entity_ref(EntityRef::FilePath("C:/Windows/svc-a1b2.exe".to_string()));
        let mut e1 = ev(1718000012000000000, EventType::ServiceStart, ArtifactType::EventLog, "Service entered the running state (EID 7036)");
        e1 = e1.with_entity_ref(EntityRef::FilePath("C:/Windows/svc-a1b2.exe".to_string()));
        let fire_events = vec![e0, e1];
        let fire = evaluate_temporal(&rule, &fire_events);
        assert!(
            fire.iter().any(|f| f.rule_id == "temporal.service-install-then-start"),
            "temporal.service-install-then-start should_fire produced no finding: {fire:?}"
        );

        let mut en0 = ev(1718000000000000000, EventType::ServiceInstall, ArtifactType::EventLog, "Vendor agent service installed by MSI (EID 7045)");
        en0 = en0.with_entity_ref(EntityRef::FilePath("C:/Program Files/Vendor/agent.exe".to_string()));
        let mut en1 = ev(1718000600000000000, EventType::ServiceStart, ArtifactType::EventLog, "Vendor agent started 10 minutes later (EID 7036)");
        en1 = en1.with_entity_ref(EntityRef::FilePath("C:/Program Files/Vendor/agent.exe".to_string()));
        let quiet_events = vec![en0, en1];
        let quiet = evaluate_temporal(&rule, &quiet_events);
        assert!(
            !quiet.iter().any(|f| f.rule_id == "temporal.service-install-then-start"),
            "temporal.service-install-then-start should_not unexpectedly fired: {quiet:?}"
        );
    }
}
