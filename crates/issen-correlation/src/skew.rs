//! Time-skew detection across forensic sources.
//!
//! Groups [`Evidence`] items by their `path` attribute (falls back to `id`),
//! then checks all pairs from *different* sources.  When `|Δt| > threshold`
//! a [`SkewFinding`] is emitted — an anti-forensics signal that timestamps
//! for the same artefact diverge suspiciously between sources.

use chrono::{DateTime, Utc};

use crate::model::{Evidence, EvidenceSource};

// ── Public types ──────────────────────────────────────────────────────────────

/// Options for [`detect_time_skew`].
pub struct SkewOpts {
    /// Emit a finding when `|Δt|` exceeds this many seconds.  Default: 300.
    pub threshold_secs: i64,
}

impl Default for SkewOpts {
    fn default() -> Self {
        Self {
            threshold_secs: 300,
        }
    }
}

/// A suspicious timestamp divergence between two forensic sources for the
/// same artefact path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkewFinding {
    /// The shared artefact path / identifier.
    pub path: String,
    /// Label of the first source (e.g. `"MFT"`).
    pub source_a: String,
    pub timestamp_a: DateTime<Utc>,
    /// Label of the second source (e.g. `"EventLog"`).
    pub source_b: String,
    pub timestamp_b: DateTime<Utc>,
    /// Absolute number of seconds between the two timestamps.
    pub delta_secs: i64,
}

// ── Helper ────────────────────────────────────────────────────────────────────

fn source_label(src: &EvidenceSource) -> String {
    match src {
        EvidenceSource::Sigma => "Sigma".into(),
        EvidenceSource::Yara => "Yara".into(),
        EvidenceSource::Suricata => "Suricata".into(),
        EvidenceSource::Zeek => "Zeek".into(),
        EvidenceSource::Artifact => "Artifact".into(),
        EvidenceSource::Memory => "Memory".into(),
        EvidenceSource::Custom(s) => s.clone(),
    }
}

fn artifact_key(ev: &Evidence) -> String {
    ev.attrs
        .get("path")
        .cloned()
        .unwrap_or_else(|| ev.id.clone())
}

// ── Core algorithm ────────────────────────────────────────────────────────────

/// Detect suspicious timestamp divergences across forensic sources.
///
/// For every group of events that share the same artefact `path` (or `id`),
/// all pairs from *different* sources are compared.  When
/// `|timestamp_a − timestamp_b| > opts.threshold_secs` a [`SkewFinding`] is
/// returned.
#[must_use]
pub fn detect_time_skew(events: &[Evidence], opts: &SkewOpts) -> Vec<SkewFinding> {
    use std::collections::HashMap;

    // Group events by artefact key, keeping only those with a timestamp.
    let mut groups: HashMap<String, Vec<&Evidence>> = HashMap::new();
    for ev in events {
        if ev.timestamp.is_some() {
            groups.entry(artifact_key(ev)).or_default().push(ev);
        }
    }

    let mut findings = Vec::new();

    for (path, members) in &groups {
        let n = members.len();
        for i in 0..n {
            for j in (i + 1)..n {
                let a = members[i];
                let b = members[j];

                // Only compare events from *different* sources.
                if a.source == b.source {
                    continue;
                }

                // Safety: only events with Some(timestamp) are inserted into groups.
                let Some(ts_a) = a.timestamp else { continue };
                let Some(ts_b) = b.timestamp else { continue };
                let delta_secs = (ts_a - ts_b).num_seconds().abs();

                if delta_secs > opts.threshold_secs {
                    findings.push(SkewFinding {
                        path: path.clone(),
                        source_a: source_label(&a.source),
                        timestamp_a: ts_a,
                        source_b: source_label(&b.source),
                        timestamp_b: ts_b,
                        delta_secs,
                    });
                }
            }
        }
    }

    findings
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;

    use super::*;
    use crate::model::{EvidenceKind, EvidenceSource};

    fn make(
        id: &str,
        source: EvidenceSource,
        path: &str,
        ts: DateTime<Utc>,
    ) -> Evidence {
        Evidence::new(id, source, EvidenceKind::Artifact, None)
            .with_attr("path", path)
            .with_timestamp(ts)
    }

    fn ts(h: u32, m: u32, s: u32) -> DateTime<Utc> {
        chrono::Utc
            .with_ymd_and_hms(2026, 4, 19, h, m, s)
            .unwrap()
    }

    // ── RED tests (all expected to FAIL while detect_time_skew is a stub) ─────

    #[test]
    fn test_no_skew_when_single_source() {
        // One event per path — nothing to compare.
        let events = vec![make("e1", EvidenceSource::Artifact, "/bin/bash", ts(0, 0, 0))];
        let findings = detect_time_skew(&events, &SkewOpts::default());
        assert!(findings.is_empty(), "expected no findings, got {findings:?}");
    }

    #[test]
    fn test_no_skew_within_threshold() {
        // Two events for same path, delta = 4 min < 5 min threshold.
        let events = vec![
            make("e1", EvidenceSource::Artifact, "/bin/ls", ts(10, 0, 0)),
            make("e2", EvidenceSource::Memory, "/bin/ls", ts(10, 4, 0)),
        ];
        let findings = detect_time_skew(&events, &SkewOpts::default());
        assert!(
            findings.is_empty(),
            "expected no findings for 4-min delta, got {findings:?}"
        );
    }

    #[test]
    fn test_skew_detected_above_threshold() {
        // Two events for same path from different sources, delta = 10 min.
        let events = vec![
            make("e1", EvidenceSource::Artifact, "/etc/passwd", ts(8, 0, 0)),
            make(
                "e2",
                EvidenceSource::Custom("EventLog".into()),
                "/etc/passwd",
                ts(8, 10, 0),
            ),
        ];
        let findings = detect_time_skew(&events, &SkewOpts::default());
        assert_eq!(findings.len(), 1, "expected exactly one finding");
        assert_eq!(findings[0].path, "/etc/passwd");
        assert_eq!(findings[0].delta_secs, 600);
    }

    #[test]
    fn test_skew_delta_is_absolute() {
        // source_b timestamp is *earlier* than source_a — delta must still be positive.
        let events = vec![
            make(
                "e1",
                EvidenceSource::Custom("MFT".into()),
                "/tmp/evil",
                ts(12, 30, 0),
            ),
            make(
                "e2",
                EvidenceSource::Custom("EventLog".into()),
                "/tmp/evil",
                ts(12, 0, 0), // 30 min earlier
            ),
        ];
        let findings = detect_time_skew(&events, &SkewOpts::default());
        assert_eq!(findings.len(), 1, "expected one finding");
        assert!(
            findings[0].delta_secs > 0,
            "delta_secs must be positive, got {}",
            findings[0].delta_secs
        );
        assert_eq!(findings[0].delta_secs, 1800);
    }

    #[test]
    fn test_multiple_paths_skew() {
        // Path A: 10-min skew → finding.
        // Path B: 2-min skew → no finding.
        let events = vec![
            make("a1", EvidenceSource::Artifact, "/path/A", ts(9, 0, 0)),
            make(
                "a2",
                EvidenceSource::Custom("MFT".into()),
                "/path/A",
                ts(9, 10, 0),
            ),
            make("b1", EvidenceSource::Artifact, "/path/B", ts(9, 0, 0)),
            make("b2", EvidenceSource::Memory, "/path/B", ts(9, 2, 0)),
        ];
        let findings = detect_time_skew(&events, &SkewOpts::default());
        assert_eq!(findings.len(), 1, "expected exactly one finding (for /path/A)");
        assert_eq!(findings[0].path, "/path/A");
    }
}
