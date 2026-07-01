//! Temporal correlation primitives for the supertimeline engine.
//!
//! Provides:
//! - [`EntityIndex`] — group events by shared entity (file, process, user, IP)
//! - [`temporal_join`] — find events within a time window around an anchor
//! - [`absence_detection`] — detect when an expected event type is missing
//! - [`deduplicate`] — collapse duplicate events (same record_hash)
//! - [`filetime_to_utc_ns`] — convert Windows FILETIME to Unix nanoseconds

use std::collections::HashMap;

use issen_core::timeline::event::{EntityRef, EventType, TimelineEvent};

/// An index of timeline events grouped by entity reference.
///
/// Built from a slice of `TimelineEvent`s; keys are the string representation
/// of each entity reference (`"path:/etc/ld.so.preload"`, `"proc:xmrig"`, …).
#[derive(Debug, Default)]
pub struct EntityIndex {
    /// Map from canonical entity key → event indices into the source slice.
    inner: HashMap<String, Vec<usize>>,
}

impl EntityIndex {
    /// Build an `EntityIndex` from a slice of events.
    ///
    /// Events with no `entity_refs` are silently skipped.
    #[must_use]
    pub fn build(events: &[TimelineEvent]) -> Self {
        let mut inner: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, event) in events.iter().enumerate() {
            for entity in &event.entity_refs {
                inner.entry(Self::entity_key(entity)).or_default().push(idx);
            }
        }
        Self { inner }
    }

    /// Return all event indices for a given entity key.
    #[must_use]
    pub fn get(&self, key: &str) -> &[usize] {
        self.inner.get(key).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Canonical key for a [`EntityRef`].
    #[must_use]
    pub fn entity_key(entity: &EntityRef) -> String {
        match entity {
            EntityRef::FilePath(p) => format!("path:{p}"),
            EntityRef::Process(n) => format!("proc:{n}"),
            EntityRef::User(u) => format!("user:{u}"),
            EntityRef::Ip(a) => format!("ip:{a}"),
            EntityRef::Session(id) => format!("session:0x{id:x}"),
        }
    }
}

/// Return all events from `events` whose timestamp falls within
/// `±within_ns` nanoseconds of `anchor.timestamp_ns`, excluding the
/// anchor event itself (matched by `record_hash`).
///
/// Use `within_ns = within_seconds * 1_000_000_000`.
#[must_use]
pub fn temporal_join<'a>(
    anchor: &TimelineEvent,
    events: &'a [TimelineEvent],
    within_ns: i64,
) -> Vec<&'a TimelineEvent> {
    events
        .iter()
        .filter(|e| {
            // Exclude the anchor itself
            e.record_hash != anchor.record_hash
                && (e.timestamp_ns - anchor.timestamp_ns).abs() <= within_ns
        })
        .collect()
}

/// Returns `true` when **no** event with `event_type` appears in `events`
/// within `within_ns` nanoseconds of `anchor.timestamp_ns`.
///
/// This is "absence-as-a-finding": e.g. a 4688 process-creation event
/// with no corresponding Prefetch update within 5 seconds signals possible
/// hollow-process injection.
#[must_use]
pub fn absence_detection(
    anchor: &TimelineEvent,
    events: &[TimelineEvent],
    event_type: &EventType,
    within_ns: i64,
) -> bool {
    // Returns true when the event_type is ABSENT in the window
    !events.iter().any(|e| {
        e.record_hash != anchor.record_hash
            && &e.event_type == event_type
            && (e.timestamp_ns - anchor.timestamp_ns).abs() <= within_ns
    })
}

/// Remove duplicate events: if two events share the same `record_hash`,
/// keep only the first occurrence (preserves original ordering).
#[must_use]
pub fn deduplicate(events: Vec<TimelineEvent>) -> Vec<TimelineEvent> {
    let mut seen = std::collections::HashSet::new();
    events
        .into_iter()
        .filter(|e| seen.insert(e.record_hash.clone()))
        .collect()
}

/// Windows FILETIME epoch offset in 100-nanosecond units
/// (number of 100-ns intervals between 1601-01-01 and 1970-01-01).
const FILETIME_EPOCH_OFFSET: u64 = 116_444_736_000_000_000;

/// Convert a Windows FILETIME (100-nanosecond intervals since 1601-01-01)
/// to a Unix nanosecond timestamp (since 1970-01-01).
///
/// Returns `None` for zero values or timestamps before the Unix epoch.
#[must_use]
pub fn filetime_to_utc_ns(filetime: u64) -> Option<i64> {
    if filetime == 0 || filetime < FILETIME_EPOCH_OFFSET {
        return None;
    }
    // Delegate the epoch arithmetic to the spec-cited timeglyph decoder (our own
    // fleet crate); keep the forensic 0/pre-epoch guard above (0 = "no timestamp").
    decode("filetime", i64::try_from(filetime).ok()?)
}

/// Decode a raw integer timestamp in the named format (a [`timeglyph`] format
/// id — e.g. `"filetime"`, `"webkit"`, `"cocoa"`, `"hfsplus"`) to Unix
/// nanoseconds, via the spec-cited timeglyph format registry. `None` if the id
/// is unknown or the value is out of the representable range.
#[must_use]
pub fn decode(format_id: &str, value: i64) -> Option<i64> {
    let fmt = timeglyph::format(format_id).ok()?;
    let posix_ns = fmt.decode_int(value).ok()?;
    i64::try_from(posix_ns.0).ok()
}

/// Calendar system for rendering a `timestamp_ns`.
#[derive(Debug, Clone)]
pub enum Calendar {
    /// Standard civil (Gregorian) instant.
    Civil,
    /// Chinese lunisolar / 干支 four-pillar reading at the render zone's meridian.
    /// The optional value is the observer's longitude (degrees east) for
    /// apparent-solar-time correction (`None` = meridian-only). A reading is a
    /// convention-relative interpretation, not a single verdict.
    Lunisolar(Option<f64>),
}

/// How to render a `timestamp_ns` for human-facing output: the output timezone
/// (via [`timeglyph::RenderZone`] — UTC / fixed offset / DST-correct IANA zone),
/// an optional `jiff` strftime format (RFC 3339 when `None`), and the calendar.
#[derive(Debug, Clone)]
pub struct TimeRenderConfig {
    /// Output timezone.
    pub zone: timeglyph::RenderZone,
    /// Optional `jiff` strftime pattern (e.g. `"%Y-%m-%d %H:%M:%S"`); `None`
    /// renders RFC 3339.
    pub format: Option<String>,
    /// Calendar system.
    pub calendar: Calendar,
}

impl Default for TimeRenderConfig {
    fn default() -> Self {
        Self {
            zone: timeglyph::RenderZone::Utc,
            format: None,
            calendar: Calendar::Civil,
        }
    }
}

/// Render a Unix-nanosecond instant per `cfg`. Never panics; returns the RFC-3339
/// UTC form as a fallback for an out-of-range instant or a bad format.
#[must_use]
pub fn render_at(timestamp_ns: i64, cfg: &TimeRenderConfig) -> String {
    let instant = timeglyph::PosixNs(i128::from(timestamp_ns));
    match &cfg.calendar {
        Calendar::Lunisolar(longitude) => {
            match timeglyph::lunisolar::render(instant, &cfg.zone, *longitude) {
                Ok(r) => format!(
                    "{} 干支 {} {} {} {} · {}",
                    r.civil_local,
                    r.year_pillar,
                    r.month_pillar,
                    r.day_pillar,
                    r.hour_pillar,
                    r.solar_term
                ),
                Err(_) => instant.to_rfc3339().unwrap_or_else(|| "invalid".to_string()),
            }
        }
        Calendar::Civil => match &cfg.format {
            None => instant.render(&cfg.zone).unwrap_or_else(|| "invalid".to_string()),
            Some(fmt) => render_with_format(timestamp_ns, &cfg.zone, fmt),
        },
    }
}

/// Render `ns` in `zone` with a `jiff` strftime `fmt`. Panic-free: a bad format
/// or out-of-range instant yields a diagnostic string, never a panic.
fn render_with_format(ns: i64, zone: &timeglyph::RenderZone, fmt: &str) -> String {
    use timeglyph::RenderZone;
    let tz = match zone {
        RenderZone::Utc => jiff::tz::TimeZone::UTC,
        RenderZone::Fixed(off) => jiff::tz::TimeZone::fixed(*off),
        RenderZone::Named(tz) => tz.clone(),
    };
    let Ok(ts) = jiff::Timestamp::from_nanosecond(i128::from(ns)) else {
        return "invalid".to_string();
    };
    let zoned = ts.to_zoned(tz);
    jiff::fmt::strtime::format(fmt, &zoned).unwrap_or_else(|_| "invalid format".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use issen_core::artifacts::ArtifactType;
    use issen_core::timeline::event::{EntityRef, EventType, TimelineEvent};

    // 1 second = 1_000_000_000 nanoseconds
    const NS: i64 = 1_000_000_000;

    fn make_event(timestamp_ns: i64, event_type: EventType, description: &str) -> TimelineEvent {
        TimelineEvent::new(
            timestamp_ns,
            "2026-01-01T00:00:00Z".to_string(),
            event_type,
            ArtifactType::UsnJournal,
            "/test/artifact".to_string(),
            description.to_string(),
            "test-source".to_string(),
        )
    }

    // ── Phase 1 RED tests ─────────────────────────────────────────────

    #[test]
    fn temporal_join_returns_events_within_window() {
        let anchor = make_event(100 * NS, EventType::ProcessExec, "anchor");
        // Within ±60s window
        let near = make_event(130 * NS, EventType::FileModify, "near event");
        // Outside window
        let far = make_event(200 * NS, EventType::FileModify, "far event");

        let events = vec![anchor.clone(), near.clone(), far.clone()];
        let joined = temporal_join(&anchor, &events, 60 * NS);

        assert_eq!(joined.len(), 1, "only the near event should be returned");
        assert_eq!(joined[0].description, "near event");
    }

    #[test]
    fn temporal_join_excludes_events_outside_window() {
        let anchor = make_event(100 * NS, EventType::ProcessExec, "anchor");
        let too_late = make_event(500 * NS, EventType::FileModify, "too late");

        let events = vec![anchor.clone(), too_late];
        let joined = temporal_join(&anchor, &events, 60 * NS);

        assert!(
            joined.is_empty(),
            "event outside 60s window must be excluded"
        );
    }

    #[test]
    fn entity_index_groups_by_file_path() {
        let path = "/etc/ld.so.preload".to_string();
        let ev1 = make_event(100 * NS, EventType::FileCreate, "create")
            .with_entity_ref(EntityRef::FilePath(path.clone()));
        let ev2 = make_event(200 * NS, EventType::FileModify, "modify")
            .with_entity_ref(EntityRef::FilePath(path.clone()));
        let ev3 = make_event(300 * NS, EventType::FileCreate, "unrelated")
            .with_entity_ref(EntityRef::FilePath("/tmp/other".to_string()));

        let events = vec![ev1, ev2, ev3];
        let idx = EntityIndex::build(&events);
        let key = EntityIndex::entity_key(&EntityRef::FilePath(path));
        let indices = idx.get(&key);

        assert_eq!(indices.len(), 2, "two events share the same file path");
        assert!(indices.contains(&0));
        assert!(indices.contains(&1));
    }

    #[test]
    fn entity_index_groups_by_process_name() {
        let ev1 = make_event(100 * NS, EventType::ProcessExec, "exec xmrig")
            .with_entity_ref(EntityRef::Process("xmrig".to_string()));
        let ev2 = make_event(200 * NS, EventType::FileCreate, "xmrig writes file")
            .with_entity_ref(EntityRef::Process("xmrig".to_string()));
        let ev3 = make_event(300 * NS, EventType::ProcessExec, "exec bash")
            .with_entity_ref(EntityRef::Process("bash".to_string()));

        let events = vec![ev1, ev2, ev3];
        let idx = EntityIndex::build(&events);
        let key = EntityIndex::entity_key(&EntityRef::Process("xmrig".to_string()));
        let indices = idx.get(&key);

        assert_eq!(indices.len(), 2);
    }

    #[test]
    fn entity_index_groups_by_user() {
        let ev1 = make_event(100 * NS, EventType::LogonSuccess, "alice logon")
            .with_entity_ref(EntityRef::User("alice".to_string()));
        let ev2 = make_event(200 * NS, EventType::FileCreate, "alice creates file")
            .with_entity_ref(EntityRef::User("alice".to_string()));
        let ev3 = make_event(300 * NS, EventType::LogonSuccess, "bob logon")
            .with_entity_ref(EntityRef::User("bob".to_string()));

        let events = vec![ev1, ev2, ev3];
        let idx = EntityIndex::build(&events);
        let alice_key = EntityIndex::entity_key(&EntityRef::User("alice".to_string()));
        assert_eq!(idx.get(&alice_key).len(), 2);

        let bob_key = EntityIndex::entity_key(&EntityRef::User("bob".to_string()));
        assert_eq!(idx.get(&bob_key).len(), 1);
    }

    #[test]
    fn deduplication_removes_same_event_from_multiple_sources() {
        // Two events with identical content fields → identical record_hash
        let ev1 = make_event(100 * NS, EventType::FileCreate, "same file created");
        let ev2 = make_event(100 * NS, EventType::FileCreate, "same file created");

        // Verify they have the same hash (test our assumption)
        assert_eq!(
            ev1.record_hash, ev2.record_hash,
            "hashes must match for the test to be valid"
        );

        let events = vec![ev1, ev2];
        let deduped = deduplicate(events);

        assert_eq!(deduped.len(), 1, "duplicate event must be removed");
    }

    #[test]
    fn timestamp_normalization_converts_windows_filetime_to_utc_ns() {
        // FILETIME for 2023-11-14T22:13:20Z = 133444736000000000 (100-ns units)
        // Expected Unix ns = (133444736000000000 - 116444736000000000) * 100
        //                  = 17000000000000000 * 100
        //                  = 1700000000000000000
        let filetime: u64 = 133_444_736_000_000_000;
        let expected_ns: i64 = 1_700_000_000_000_000_000;

        assert_eq!(filetime_to_utc_ns(filetime), Some(expected_ns));
    }

    #[test]
    fn decode_dispatches_multi_format_via_timeglyph() {
        // filetime: must agree with the hand-rolled central helper on a normal value.
        let ft: i64 = 133_444_736_000_000_000;
        assert_eq!(decode("filetime", ft), filetime_to_utc_ns(ft as u64));
        // cocoa: 0 == 2001-01-01T00:00:00Z == 978_307_200 s since the Unix epoch.
        assert_eq!(decode("cocoa", 0), Some(978_307_200_000_000_000));
        // webkit (Chrome, µs since 1601): the Unix epoch is 11_644_473_600_000_000 µs.
        assert_eq!(decode("webkit", 11_644_473_600_000_000), Some(0));
        // unknown format id → None (never a silent wrong answer).
        assert_eq!(decode("not_a_format", 0), None);
    }

    #[test]
    fn render_at_supports_timezone_format_and_lunisolar() {
        use timeglyph::RenderZone;
        // 2020-01-01T00:00:00Z
        let ns: i64 = 1_577_836_800_000_000_000;

        // UTC / RFC 3339 (the default).
        assert_eq!(render_at(ns, &TimeRenderConfig::default()), "2020-01-01T00:00:00Z");

        // A named IANA zone, resolved DST-correct per instant (Tokyo = UTC+9).
        let tokyo = TimeRenderConfig {
            zone: RenderZone::parse("Asia/Tokyo").expect("tz"),
            ..Default::default()
        };
        assert!(
            render_at(ns, &tokyo).starts_with("2020-01-01T09:00:00"),
            "Tokyo render should be UTC+9, got: {}",
            render_at(ns, &tokyo)
        );

        // A custom jiff strftime format.
        let fmt = TimeRenderConfig {
            format: Some("%Y-%m-%d %H:%M".to_string()),
            ..Default::default()
        };
        assert_eq!(render_at(ns, &fmt), "2020-01-01 00:00");

        // Lunisolar / 干支 at the China meridian (UTC+8) with an observer longitude.
        let luni = TimeRenderConfig {
            zone: RenderZone::parse("+08:00").expect("offset"),
            calendar: Calendar::Lunisolar(Some(120.0)),
            ..Default::default()
        };
        let r = render_at(ns, &luni);
        assert!(
            r.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)),
            "a lunisolar reading must contain 干支/CJK pillars, got: {r}"
        );
    }

    #[test]
    fn absence_detection_fires_when_event_type_missing_in_window() {
        // Anchor: 4688-equivalent process exec at T=100s
        let anchor = make_event(100 * NS, EventType::ProcessExec, "cmd.exe launched");
        // Only a FileCreate in the window — no FileModify (which Prefetch would be)
        let file_create = make_event(101 * NS, EventType::FileCreate, "some file created");

        let events = vec![anchor.clone(), file_create];

        // Absence of FileModify within 5s should be detected
        let absent = absence_detection(&anchor, &events, &EventType::FileModify, 5 * NS);
        assert!(
            absent,
            "FileModify is absent — absence_detection should return true"
        );

        // But FileCreate IS present, so absence should return false for it
        let not_absent = absence_detection(&anchor, &events, &EventType::FileCreate, 5 * NS);
        assert!(
            !not_absent,
            "FileCreate is present — absence_detection should return false"
        );
    }
}
