//! Working-hours classification for timestamp anomaly detection.
//!
//! Timestamps outside Mon–Fri 09:00–17:00 UTC are considered anomalous in
//! corporate environments and may indicate insider threat / after-hours
//! exfiltration activity.
//!
//! Threshold constants are sourced from
//! [`forensicnomicon::heuristics`] so the window definition lives in one place
//! across all crates.

use chrono::{DateTime, Datelike, Timelike, Utc};
use forensicnomicon::heuristics::{WORKING_HOURS_END, WORKING_HOURS_START};

fn ns_to_dt(timestamp_ns: i64) -> DateTime<Utc> {
    let secs = timestamp_ns.div_euclid(1_000_000_000);
    // rem_euclid on i64 with positive divisor always fits in u32 (0..=999_999_999)
    let nanos = u32::try_from(timestamp_ns.rem_euclid(1_000_000_000)).unwrap_or(0);
    DateTime::<Utc>::from_timestamp(secs, nanos)
        .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).expect("epoch is valid"))
}

/// Returns `true` if the Unix nanosecond timestamp falls outside
/// Mon–Fri 09:00–17:00 UTC.
///
/// Weekends are always considered outside working hours.
#[must_use]
pub fn is_outside_working_hours(timestamp_ns: i64) -> bool {
    !matches!(classify_time_anomaly(timestamp_ns), TimeAnomaly::None)
}

/// Returns `true` if the timestamp falls on a weekend (Saturday or Sunday, UTC).
#[must_use]
pub fn is_weekend(timestamp_ns: i64) -> bool {
    matches!(classify_time_anomaly(timestamp_ns), TimeAnomaly::Weekend { .. })
}

/// Returns the hour of day (0–23) for a Unix nanosecond timestamp (UTC).
///
/// # Panics
///
/// Does not panic in practice; the inner timestamp fallback uses epoch 0 on
/// out-of-range input, which is always valid.
#[must_use]
pub fn hour_of_day(timestamp_ns: i64) -> u8 {
    // chrono hour() returns 0–23, which always fits in u8
    u8::try_from(ns_to_dt(timestamp_ns).hour()).unwrap_or(0)
}

/// Returns the weekday (0=Mon … 6=Sun) for a Unix nanosecond timestamp (UTC).
///
/// # Panics
///
/// Does not panic in practice; see [`hour_of_day`].
#[must_use]
pub fn weekday(timestamp_ns: i64) -> u8 {
    // num_days_from_monday returns 0–6, which always fits in u8
    u8::try_from(ns_to_dt(timestamp_ns).weekday().num_days_from_monday()).unwrap_or(0)
}

/// Time-of-day anomaly classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeAnomaly {
    /// Timestamp falls outside 09:00–17:00 on a weekday.
    OutsideWorkingHours { hour: u8, weekday: u8 },
    /// Timestamp falls on a Saturday or Sunday.
    Weekend { weekday: u8 },
    /// Timestamp is within Mon–Fri 09:00–17:00 UTC.
    None,
}

/// Classify a Unix nanosecond timestamp into a [`TimeAnomaly`] variant.
///
/// # Panics
///
/// Does not panic in practice; see [`hour_of_day`].
#[must_use]
pub fn classify_time_anomaly(timestamp_ns: i64) -> TimeAnomaly {
    let dt = ns_to_dt(timestamp_ns);

    // num_days_from_monday: 0=Mon … 6=Sun; hour: 0–23 — both fit in u8
    let wd = u8::try_from(dt.weekday().num_days_from_monday()).unwrap_or(0);
    let hr = u8::try_from(dt.hour()).unwrap_or(0);

    // Saturday = 5, Sunday = 6
    if wd >= 5 {
        return TimeAnomaly::Weekend { weekday: wd };
    }

    // Outside working hours on a weekday (constants from forensicnomicon::heuristics)
    #[allow(clippy::cast_possible_truncation)]
    if !(WORKING_HOURS_START..WORKING_HOURS_END).contains(&u32::from(hr)) {
        return TimeAnomaly::OutsideWorkingHours { hour: hr, weekday: wd };
    }

    TimeAnomaly::None
}
