//! Pure presentation logic for the live ingest display (Humble Object): map a
//! [`ProgressSnapshot`] to display strings. Everything here is deterministic and
//! unit-tested; the indicatif draw shell that calls it stays thin and untested.

use std::fmt::Write as _;
use std::time::Duration;

use issen_fswalker::progress::{Phase, ProgressSnapshot};

/// Parsed percentage `completed/total`, or `None` while the total is unknown
/// (during extraction/discovery, before a determinate bar is possible).
#[must_use]
pub fn percent(s: &ProgressSnapshot) -> Option<u8> {
    (s.artifacts_total > 0).then(|| {
        let p = s.artifacts_completed.saturating_mul(100) / s.artifacts_total;
        u8::try_from(p.min(100)).unwrap_or(100)
    })
}

/// Events per second, rounded; `0` when no time has elapsed.
#[must_use]
pub fn events_per_sec(events: u64, elapsed: Duration) -> u64 {
    let secs = elapsed.as_secs_f64();
    if secs <= 0.0 {
        return 0;
    }
    (events as f64 / secs).round() as u64
}

/// Estimated time remaining, extrapolating the current completion rate; `None`
/// when there is no rate yet (nothing completed) or the total is unknown.
#[must_use]
pub fn eta(completed: u64, total: u64, elapsed: Duration) -> Option<Duration> {
    if completed == 0 || total == 0 {
        return None;
    }
    let remaining = total.saturating_sub(completed);
    let per_item = elapsed.as_secs_f64() / completed as f64;
    Some(Duration::from_secs_f64(per_item * remaining as f64))
}

/// Compact integer: `950`, `18.4k`, `2.5M`.
#[must_use]
pub fn humanize_count(n: u64) -> String {
    match n {
        0..=999 => n.to_string(),
        1_000..=999_999 => format!("{:.1}k", n as f64 / 1_000.0),
        _ => format!("{:.1}M", n as f64 / 1_000_000.0),
    }
}

/// Byte count in the largest fitting unit: `512 B`, `1.5 KB`, `1.2 GB`.
#[must_use]
pub fn humanize_bytes(n: u64) -> String {
    const KB: f64 = 1024.0;
    let f = n as f64;
    if f < KB {
        format!("{n} B")
    } else if f < KB * KB {
        format!("{:.1} KB", f / KB)
    } else if f < KB * KB * KB {
        format!("{:.1} MB", f / (KB * KB))
    } else {
        format!("{:.1} GB", f / (KB * KB * KB))
    }
}

/// Human label for a pipeline phase.
#[must_use]
pub fn phase_label(phase: Phase) -> &'static str {
    match phase {
        Phase::Queued => "queued",
        Phase::Extracting => "extracting",
        Phase::Discovering => "discovering",
        Phase::Parsing => "parsing",
        Phase::Done => "done",
    }
}

/// A one-line status string: phase, progress (only once the total is known),
/// event count, rate, ETA, and error count.
#[must_use]
pub fn status_line(s: &ProgressSnapshot, elapsed: Duration) -> String {
    let mut line = phase_label(s.phase).to_string();
    if let Some(pct) = percent(s) {
        let _ = write!(
            line,
            "  {}/{}  {pct}%",
            humanize_count(s.artifacts_completed),
            humanize_count(s.artifacts_total)
        );
        if let Some(eta) = eta(s.artifacts_completed, s.artifacts_total, elapsed) {
            let _ = write!(line, "  ETA {}", fmt_duration(eta));
        }
    }
    let _ = write!(
        line,
        "  {} events  {} ev/s",
        humanize_count(s.events_emitted),
        humanize_count(events_per_sec(s.events_emitted, elapsed))
    );
    if s.errors_encountered > 0 {
        let _ = write!(line, "  {} errors", s.errors_encountered);
    }
    line
}

/// `M:SS` (or `H:MM:SS` past an hour).
fn fmt_duration(d: Duration) -> String {
    let secs = d.as_secs();
    let (h, m, sec) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}:{m:02}:{sec:02}")
    } else {
        format!("{m}:{sec:02}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use issen_fswalker::progress::{Phase, ProgressSnapshot};
    use std::time::Duration;

    fn snap(phase: Phase, completed: u64, total: u64) -> ProgressSnapshot {
        ProgressSnapshot {
            phase,
            artifacts_total: total,
            artifacts_completed: completed,
            events_emitted: 0,
            bytes_processed: 0,
            errors_encountered: 0,
        }
    }

    #[test]
    fn percent_is_completed_over_total_or_none_when_unknown() {
        assert_eq!(percent(&snap(Phase::Parsing, 100, 400)), Some(25));
        assert_eq!(percent(&snap(Phase::Parsing, 400, 400)), Some(100));
        assert_eq!(
            percent(&snap(Phase::Discovering, 0, 0)),
            None,
            "total unknown"
        );
    }

    #[test]
    fn events_per_sec_rounds_and_guards_zero_elapsed() {
        assert_eq!(events_per_sec(1000, Duration::from_secs(2)), 500);
        assert_eq!(events_per_sec(100, Duration::ZERO), 0, "no divide-by-zero");
    }

    #[test]
    fn eta_extrapolates_rate_or_none_without_one() {
        assert_eq!(
            eta(100, 400, Duration::from_secs(10)),
            Some(Duration::from_secs(30)),
            "100 of 400 in 10s -> 300 left at 10/s -> 30s"
        );
        assert_eq!(eta(0, 400, Duration::from_secs(10)), None, "no rate yet");
        assert_eq!(eta(400, 400, Duration::from_secs(10)), Some(Duration::ZERO));
        assert_eq!(eta(100, 0, Duration::from_secs(10)), None, "total unknown");
    }

    #[test]
    fn humanize_count_compacts_thousands_and_millions() {
        assert_eq!(humanize_count(950), "950");
        assert_eq!(humanize_count(18_400), "18.4k");
        assert_eq!(humanize_count(2_500_000), "2.5M");
    }

    #[test]
    fn humanize_bytes_scales_units() {
        assert_eq!(humanize_bytes(512), "512 B");
        assert_eq!(humanize_bytes(1536), "1.5 KB");
        assert_eq!(humanize_bytes(1_288_490_189), "1.2 GB");
    }

    #[test]
    fn phase_label_is_human_readable() {
        assert_eq!(phase_label(Phase::Queued), "queued");
        assert_eq!(phase_label(Phase::Extracting), "extracting");
        assert_eq!(phase_label(Phase::Parsing), "parsing");
        assert_eq!(phase_label(Phase::Done), "done");
    }

    #[test]
    fn status_line_carries_progress_events_and_errors() {
        let s = ProgressSnapshot {
            phase: Phase::Parsing,
            artifacts_total: 417,
            artifacts_completed: 312,
            events_emitted: 18_400,
            bytes_processed: 0,
            errors_encountered: 3,
        };
        let line = status_line(&s, Duration::from_secs(36));
        assert!(line.contains("312/417"), "got: {line}");
        assert!(line.contains("74%"), "got: {line}");
        assert!(line.contains("18.4k"), "got: {line}");
        assert!(line.contains("3 error"), "got: {line}");
    }

    #[test]
    fn status_line_during_discovery_shows_no_bogus_percent() {
        let s = snap(Phase::Discovering, 0, 0);
        let line = status_line(&s, Duration::from_secs(2));
        assert!(line.contains("discovering"), "got: {line}");
        assert!(
            !line.contains('%'),
            "no percent before the total is known: {line}"
        );
    }
}
