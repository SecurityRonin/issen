//! Single-event `$SI`/`$FN` timestomp detector (MITRE T1070.006).
//!
//! Task C2. Consumes the `$FILE_NAME` timestamps that the MFT converter
//! surfaces onto each `FileCreate` event's metadata (task C1:
//! `fn_created` / `fn_modified` / `fn_accessed` / `fn_mft_modified`) and
//! compares them against the event's own `$STANDARD_INFORMATION`-driven
//! timestamp.
//!
//! `$STANDARD_INFORMATION` is user-writable (the Win32 `SetFileTime` API, and
//! every timestomping tool, touches it); `$FILE_NAME` is set by the kernel on
//! creation / rename / move and is *not* reachable through that API. So an
//! `$SI` birth time that **predates** the `$FN` birth time *can* indicate a
//! backdated creation timestamp.
//!
//! **But on its own this is the weakest signal in the literature** — a file
//! copy (which preserves the source `$SI`), archive/installer extraction, and
//! NTFS file-system tunnelling all reproduce `$SI < $FN` with no tampering. So
//! this single-event check emits only a low-confidence **`Info` lead**, never a
//! graded finding; it carries T1070.006 as *consistent-with*, and the note
//! states plainly that corroboration is required. The precision-first redesign
//! (copy/tunnelling modifiers, sub-second zeroing, USN/`$LogFile` correlation)
//! is tracked in `docs/research/2026-06-09-timestomp-detection-false-positives.md`.

use forensicnomicon::report::{Category, Finding, Severity, Source};
use issen_core::timeline::event::{EventType, TimelineEvent};
use jiff::Timestamp;

/// Stable, scheme-prefixed finding code (published contract — never change).
/// Matches the Case 001 capability-gaps sub-plan (Workstream C2).
pub const TIMESTOMP_CODE: &str = "NTFS-TIMESTOMP-SI-FN-MISMATCH";

/// Detect `$SI`/`$FN` birth-time inconsistency on a single `FileCreate` event.
///
/// Fires when the `$STANDARD_INFORMATION` birth time (`event.timestamp_ns`)
/// precedes the `$FILE_NAME` birth time (`fn_created` metadata) by more than
/// `tolerance_ns`. Returns `None` when the event is not a `FileCreate`, carries
/// no parseable `fn_created`, or the two times are within tolerance.
#[must_use]
pub fn detect_timestomp(event: &TimelineEvent, tolerance_ns: i64) -> Option<Finding> {
    if !matches!(event.event_type, EventType::FileCreate) {
        return None;
    }

    let fn_created_display = event.metadata.get("fn_created")?.as_str()?.to_string();
    let fn_created = display_to_ns(&fn_created_display)?;
    // $SI.created: prefer the explicit metadata (surfaced by C3); fall back to the
    // event timestamp for events emitted before that field existed.
    let si_created = meta_ns(event, "si_created").unwrap_or(event.timestamp_ns);
    let si_modified = meta_ns(event, "si_modified");
    let si_accessed = meta_ns(event, "si_accessed");

    let threshold = fn_created.saturating_sub(tolerance_ns);

    // ── Corroborator: $SI sub-second (100 ns) zeroing (Velociraptor `USecZeros`,
    //    verified §7.2) — naive whole-second stomp tools zero the sub-second field.
    //    The spec (§5.3 S3) requires the CONTRAST: a zeroed $SI value while the
    //    corresponding $FN value retains true 100 ns precision. A $FN that is
    //    itself whole-second carries no precision to contradict, so it does NOT
    //    corroborate (this keeps genuine whole-second clock skew from tripping it). ──
    let fn_has_precision = !is_whole_second(fn_created);
    let s3 = fn_has_precision
        && (is_whole_second(si_created) || si_modified.is_some_and(is_whole_second));

    // ── Ordering signals — at least one is required to emit anything ──
    // The tolerance suppresses clock-skew noise on the ORDERING-ONLY path. But when
    // the independent sub-second-zeroing corroborator (S3) is present, a *strict*
    // $SI < $FN ordering is enough on its own — a benign clock skew does not also
    // zero the $SI sub-second field against a precise $FN, so the large tolerance
    // would otherwise hide a real same-day back-date (the Szechuan Beth_Secret.txt
    // case: ~4 h stomp, well inside one day). This mirrors the analyzeMFT panel,
    // which fires the $SI/$FN shift on a strict ordering plus the nanosecond tell.
    let s1 = si_created < threshold || (s3 && si_created < fn_created);
    let s2 = si_modified.is_some_and(|m| m < threshold)
        || (s3 && si_modified.is_some_and(|m| m < fn_created));
    if !s1 && !s2 {
        return None;
    }

    // ── Benign-context MODIFIERS (confidence reducers, never hard gates — §6.2) ──
    let copy = si_modified.is_some_and(|m| si_created > m); // born after modified ⇒ copy/restore
    let volume_move = match (si_modified, si_accessed) {
        (Some(m), Some(a)) => a > si_created && a > m,
        _ => false,
    };
    let high_fp_path = is_high_fp_path(&event.artifact_path);

    // ── Base grade from the signals (no benign modifier yet) ──
    let mut severity = if s3 {
        Severity::Medium // ordering + sub-second zeroing
    } else if s2 {
        Severity::Low // a stronger ordering anomaly, but no corroborator
    } else {
        Severity::Info // S1 only — the weakest, copy-dominated lead
    };

    let mut signals: Vec<&str> = Vec::new();
    if s1 {
        signals.push("$SI.created < $FN.created");
    }
    if s2 {
        signals.push("$SI.modified < $FN.created");
    }
    if s3 {
        signals.push("$SI sub-second (100ns) component zeroed");
    }

    // A benign-context modifier caps the lead at Info. The single-event tier has no
    // strong corroborator (the USN/$LogFile High tier is a later step), so a plausible
    // benign explanation dominates — but the hit is NEVER discarded, only downgraded.
    let mut modifiers: Vec<&str> = Vec::new();
    if copy {
        modifiers.push("copy pattern ($SI.created > $SI.modified)");
    }
    if volume_move {
        modifiers.push("volume-move pattern ($SI.accessed newest)");
    }
    if high_fp_path {
        modifiers.push("high-FP path (servicing/installer/recycle/temp)");
    }
    if !modifiers.is_empty() {
        severity = Severity::Info;
    }

    let modifier_clause = if modifiers.is_empty() {
        String::new()
    } else {
        format!(
            "Benign-context modifiers present ({}), so graded as a low-confidence lead. ",
            modifiers.join("; ")
        )
    };
    let note = format!(
        "Possible $SI timestamp manipulation — signals: {}. {}Corroboration \
         ($SI.modified vs $FN, sub-second zeroing, or a USN/$LogFile contradiction keyed \
         on MFT reference + sequence) is required before this is more than a lead; benign \
         causes (file copy, archive/installer extraction, NTFS file-system tunnelling) are \
         not excluded. Consistent with MITRE T1070.006.",
        signals.join("; "),
        modifier_clause,
    );

    Some(
        Finding::observation(severity, Category::Concealment, TIMESTOMP_CODE)
            .source(Source {
                analyzer: "issen-correlation".to_string(),
                scope: "mft.timestomp".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            })
            .note(note)
            .evidence(
                "si_created",
                meta_str(event, "si_created").unwrap_or_else(|| event.timestamp_display.clone()),
            )
            .evidence(
                "si_modified",
                meta_str(event, "si_modified").unwrap_or_default(),
            )
            .evidence("fn_created", fn_created_display)
            .evidence("path", event.artifact_path.clone())
            .mitre("T1070.006")
            .build(),
    )
}

/// Read a metadata value as a string (the `datetime_to_display` form).
fn meta_str(event: &TimelineEvent, key: &str) -> Option<String> {
    Some(event.metadata.get(key)?.as_str()?.to_string())
}

/// Read a metadata timestamp value and parse it to nanoseconds since the epoch.
fn meta_ns(event: &TimelineEvent, key: &str) -> Option<i64> {
    display_to_ns(event.metadata.get(key)?.as_str()?)
}

/// Parse a `datetime_to_display`-formatted string (`%Y-%m-%dT%H:%M:%S%.9fZ`,
/// RFC3339) back to nanoseconds since the Unix epoch.
fn display_to_ns(s: &str) -> Option<i64> {
    i64::try_from(s.parse::<Timestamp>().ok()?.as_nanosecond()).ok()
}

/// `true` when a nanosecond timestamp falls exactly on a whole second — i.e. its
/// sub-second (100 ns) component is zero, the tell of a naive whole-second stomp.
fn is_whole_second(ns: i64) -> bool {
    ns.rem_euclid(1_000_000_000) == 0
}

/// `true` when the path lives under a known high-false-positive location
/// (OS servicing, installers, recycle bin, temp) where benign timestamp
/// divergence is routine. Matches both `\` and `/` separators, case-insensitively.
fn is_high_fp_path(path: &str) -> bool {
    const HIGH_FP: &[&str] = &[
        "/windows/winsxs/",
        "/windows/servicing/",
        "/windows/installer/",
        "/windows/softwaredistribution/",
        "/$recycle.bin/",
        "/windows/temp/",
    ];
    let p = path.replace('\\', "/").to_ascii_lowercase();
    HIGH_FP.iter().any(|seg| p.contains(seg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use issen_core::artifacts::ArtifactType;
    use issen_core::timeline::event::EventType;

    const DAY_NS: i64 = 86_400_000_000_000;
    // 2020-01-01T00:00:00Z in ns since Unix epoch.
    const FN_2020_NS: i64 = 1_577_836_800_000_000_000;
    // 2010-01-01T00:00:00Z in ns since Unix epoch.
    const SI_2010_NS: i64 = 1_262_304_000_000_000_000;
    const FN_2020_DISPLAY: &str = "2020-01-01T00:00:00.000000000Z";

    fn file_create(si_ns: i64) -> TimelineEvent {
        TimelineEvent::new(
            si_ns,
            format!("{si_ns}"),
            EventType::FileCreate,
            ArtifactType::Mft,
            "C:\\Windows\\System32\\evil.dll".to_string(),
            "FileCreate: evil.dll".to_string(),
            "evidence-001".to_string(),
        )
    }

    // ── Layered scorer (Step 3) ────────────────────────────────────────────────
    // Builds a FileCreate event carrying the four $SI MACE + fn_created (as C3
    // surfaces them) so the scorer's signals + modifiers can run from one event.

    const SUB: i64 = 123_456_789; // a non-zero sub-second so a value is NOT whole-second
    const T: i64 = FN_2020_NS; // 2020-01-01T00:00:00Z — a whole second

    fn disp(ns: i64) -> String {
        let ts = Timestamp::from_nanosecond(i128::from(ns)).expect("representable instant");
        jiff::fmt::strtime::format("%Y-%m-%dT%H:%M:%S%.9fZ", ts).expect("valid format")
    }

    fn fc(si_c: i64, si_m: i64, si_a: i64, fn_c: i64, path: &str) -> TimelineEvent {
        TimelineEvent::new(
            si_c,
            disp(si_c),
            EventType::FileCreate,
            ArtifactType::Mft,
            path.to_string(),
            "FileCreate".to_string(),
            "evidence-001".to_string(),
        )
        .with_metadata("si_created", serde_json::json!(disp(si_c)))
        .with_metadata("si_modified", serde_json::json!(disp(si_m)))
        .with_metadata("si_accessed", serde_json::json!(disp(si_a)))
        .with_metadata("fn_created", serde_json::json!(disp(fn_c)))
    }

    #[test]
    fn s1_only_is_info_lead() {
        // si_created<fn (S1), si_modified>fn (no S2), sub-seconds (no S3), no modifier.
        let e = fc(
            T - 10 * DAY_NS + SUB,
            T + DAY_NS + SUB,
            T - 9 * DAY_NS + SUB,
            T,
            "Users/a/x.txt",
        );
        let f = detect_timestomp(&e, DAY_NS).expect("must emit a lead");
        assert_eq!(f.code, TIMESTOMP_CODE);
        assert_eq!(f.severity, Some(Severity::Info));
        assert_eq!(f.category, Category::Concealment);
        assert!(
            f.note.to_lowercase().contains("corroborat")
                && f.note.to_lowercase().contains("not excluded"),
            "note must state corroboration required + benign causes not excluded"
        );
        assert!(f
            .context
            .external_refs
            .iter()
            .any(|r| r.id.contains("T1070.006")));
    }

    #[test]
    fn s1_and_s2_without_subsecond_is_low() {
        // si_created<si_modified<fn (S1+S2), sub-seconds (no S3), no modifier → Low.
        let e = fc(
            T - 10 * DAY_NS + SUB,
            T - 5 * DAY_NS + SUB,
            T - 9 * DAY_NS + SUB,
            T,
            "Users/a/x.txt",
        );
        assert_eq!(
            detect_timestomp(&e, DAY_NS).expect("emit").severity,
            Some(Severity::Low)
        );
    }

    #[test]
    fn ordering_plus_subsecond_zero_is_medium() {
        // si_created on a whole second (S3) and before fn (S1), no modifier → Medium.
        // $FN carries real 100 ns precision (T + SUB) — as kernel-set $FN always
        // does — so the sub-second-zeroing contrast (§5.3 S3: zeroed $SI vs precise
        // $FN) actually holds; a whole-second $FN would carry no precision to
        // contradict and so would not corroborate.
        let e = fc(
            T - 10 * DAY_NS,
            T - 5 * DAY_NS + SUB,
            T - 9 * DAY_NS + SUB,
            T + SUB,
            "Users/a/x.txt",
        );
        assert_eq!(
            detect_timestomp(&e, DAY_NS).expect("emit").severity,
            Some(Severity::Medium)
        );
    }

    #[test]
    fn copy_pattern_caps_at_info_and_is_still_emitted() {
        // si_created>si_modified ⇒ copy/restore. Even with ordering, cap at Info; never drop.
        let e = fc(
            T - 5 * DAY_NS + SUB,
            T - 10 * DAY_NS + SUB,
            T - 9 * DAY_NS + SUB,
            T,
            "Users/a/x.txt",
        );
        let f = detect_timestomp(&e, DAY_NS).expect("must still emit a lead, not discard");
        assert_eq!(f.severity, Some(Severity::Info));
        assert!(f.note.to_lowercase().contains("copy"));
    }

    #[test]
    fn volume_move_pattern_caps_at_info() {
        // si_accessed newest ⇒ volume move. Cap at Info.
        let e = fc(
            T - 10 * DAY_NS + SUB,
            T - 8 * DAY_NS + SUB,
            T + 5 * DAY_NS + SUB,
            T,
            "Users/a/x.txt",
        );
        let f = detect_timestomp(&e, DAY_NS).expect("emit");
        assert_eq!(f.severity, Some(Severity::Info));
        assert!(f.note.to_lowercase().contains("volume"));
    }

    #[test]
    fn high_fp_path_caps_at_info() {
        // Whole-second ordering (would be Medium) but under WinSxS ⇒ cap at Info.
        let e = fc(
            T - 10 * DAY_NS,
            T - 5 * DAY_NS + SUB,
            T - 9 * DAY_NS + SUB,
            T,
            "C:\\Windows\\WinSxS\\amd64_x\\foo.dll",
        );
        let f = detect_timestomp(&e, DAY_NS).expect("emit");
        assert_eq!(f.severity, Some(Severity::Info));
        assert!(f.note.to_lowercase().contains("path"));
    }

    #[test]
    fn no_ordering_anomaly_returns_none() {
        // si_created and si_modified both after fn → nothing to flag.
        let e = fc(
            T + 2 * DAY_NS + SUB,
            T + 3 * DAY_NS + SUB,
            T + 4 * DAY_NS + SUB,
            T,
            "Users/a/x.txt",
        );
        assert!(detect_timestomp(&e, DAY_NS).is_none());
    }

    #[test]
    fn no_finding_when_si_after_fn() {
        // $SI birth later than $FN birth — normal (or a later modify), not timestomp.
        let event = file_create(FN_2020_NS + 30 * DAY_NS)
            .with_metadata("fn_created", serde_json::json!(FN_2020_DISPLAY));
        assert!(detect_timestomp(&event, DAY_NS).is_none());
    }

    #[test]
    fn no_finding_within_tolerance() {
        // $SI one hour before $FN, tolerance one day — clock skew, not timestomp.
        let event = file_create(FN_2020_NS - 3_600_000_000_000)
            .with_metadata("fn_created", serde_json::json!(FN_2020_DISPLAY));
        assert!(detect_timestomp(&event, DAY_NS).is_none());
    }

    #[test]
    fn no_finding_when_not_file_create() {
        // The detector only inspects FileCreate events.
        let mut event =
            file_create(SI_2010_NS).with_metadata("fn_created", serde_json::json!(FN_2020_DISPLAY));
        event.event_type = EventType::FileModify;
        assert!(detect_timestomp(&event, DAY_NS).is_none());
    }

    #[test]
    fn no_finding_when_fn_metadata_absent() {
        // Single-attribute MFT entry: no $FN to compare against.
        let event = file_create(SI_2010_NS);
        assert!(detect_timestomp(&event, DAY_NS).is_none());
    }

    #[test]
    fn no_finding_when_fn_unparseable() {
        let event = file_create(SI_2010_NS)
            .with_metadata("fn_created", serde_json::json!("not-a-timestamp"));
        assert!(detect_timestomp(&event, DAY_NS).is_none());
    }

    // ── Sub-second-zeroing corroborator survives a sub-tolerance back-date ──────
    // Real-data shape from the DFIRMadness "Szechuan Sauce" DC ($MFT entry 87111,
    // \FileShare\Secret\Beth_Secret.txt): $SI.created was stomped to a WHOLE second
    // ~4 h BEFORE the kernel-set $FN.created, which still carries true 100 ns
    // precision. The back-date (≈4 h) is SMALLER than the one-day clock-skew
    // tolerance, yet the zeroed $SI sub-second against a non-zeroed $FN is the
    // classic naive-stomp tell (Velociraptor `USecZeros`; analyzeMFT). The lead
    // must still fire — the tolerance guards only the ordering-ONLY (no-corroborator)
    // path, not an ordering anomaly that an independent corroborator already backs.
    #[test]
    fn subsecond_zeroing_fires_below_tolerance() {
        // $FN.created — non-zeroed, true precision.
        let fn_c = T + 4 * 3_600_000_000_000 + 970_445_000; // +4h, +0.970445000s
                                                            // $SI.created — zeroed sub-second (whole second), only ~4 h before $FN
                                                            // (well inside the one-day tolerance), and $SI.modified after $SI.created
                                                            // (no copy/volume-move modifier).
        let si_c = T; // whole second
        let si_m = T + 90_000_000_000; // +90 s, after created (no copy pattern)
        let si_a = T; // accessed == created (no volume-move)
        let e = fc(si_c, si_m, si_a, fn_c, "FileShare/Secret/Beth_Secret.txt");
        let f = detect_timestomp(&e, DAY_NS)
            .expect("zeroed $SI sub-second vs non-zeroed $FN must fire below tolerance");
        assert_eq!(f.code, TIMESTOMP_CODE);
        // Ordering + sub-second-zeroing corroborator ⇒ Medium, per the spec (§5.3:
        // (S1 or S2) AND S3 → Medium) and the existing `ordering_plus_subsecond_zero_is_medium`
        // test. Grading the sub-tolerance case differently from the identical
        // beyond-tolerance case would be a special case — severity follows the
        // signals, not the back-date margin. Crucially it is NEVER High here: the
        // single-event tier has no cross-artifact (USN/$LogFile) corroborator, so a
        // verdict-grade is structurally out of reach — it remains a graded lead.
        assert_eq!(f.severity, Some(Severity::Medium));
        assert_ne!(
            f.severity,
            Some(Severity::High),
            "single-event $SI/$FN tier must never reach a verdict grade"
        );
        assert!(f
            .context
            .external_refs
            .iter()
            .any(|r| r.id.contains("T1070.006")));
    }

    // Guard the discriminator: a genuine sub-tolerance clock skew where BOTH $SI
    // and $FN carry real (non-zeroed) sub-seconds is NOT a stomp — no corroborator,
    // so the tolerance still suppresses it (no false positive from the fix above).
    #[test]
    fn subsecond_present_below_tolerance_stays_none() {
        let fn_c = T + 4 * 3_600_000_000_000 + 970_445_000; // non-zeroed
        let si_c = T + 3_600_000_000_000 + SUB; // 1 h before fn, NON-zeroed sub-second
        let si_m = T + 5 * 3_600_000_000_000 + SUB;
        let si_a = T + 5 * 3_600_000_000_000 + SUB;
        let e = fc(si_c, si_m, si_a, fn_c, "Users/a/x.txt");
        assert!(
            detect_timestomp(&e, DAY_NS).is_none(),
            "non-zeroed $SI within tolerance is clock-skew noise, not a stomp"
        );
    }
}
