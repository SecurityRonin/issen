//! SRUM (System Resource Usage Monitor) parser for Issen.
//!
//! Parses `SRUDB.dat` ESE database files, converting network usage and
//! application usage records into [`TimelineEvent`]s.
//!
//! Record extraction is performed by the `srum-parser`/`ese-core` ESE B-tree
//! leaf traversal. A valid SRUDB with no rows in a given table yields an empty
//! vector for that table (e.g. Windows Server omits several SRUM extensions),
//! which this parser handles gracefully.

#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]

use chrono::{DateTime, Utc};
use issen_core::artifacts::ArtifactType;
use issen_core::classify;
use issen_core::error::RtError;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::selector as sel;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseOptions, ParseStats, ParserCapabilities,
};
use issen_core::timeline::event::{EventType, TimelineEvent};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

/// SRUM parser — ingests `SRUDB.dat` ESE database files.
pub struct SrumParser;

impl SrumParser {
    /// Returns `true` if `path`'s filename is `SRUDB.dat` (case-insensitive).
    pub fn can_parse(&self, path: &Path) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("SRUDB.dat"))
    }

    /// Parse a SRUDB.dat file and return timeline events (aggregate default).
    ///
    /// Drives `srum-parser`'s real ESE B-tree leaf traversal for the network-
    /// usage and app-resource-usage tables and converts each row into a
    /// [`TimelineEvent`]. A table absent from the catalog yields no events.
    ///
    /// Equivalent to [`parse_path_with_opts`](Self::parse_path_with_opts) with
    /// [`ParseOptions::default()`] — the high-volume PushNotifications/EnergyUsage
    /// tables are aggregated per-app.
    ///
    /// Returns `Err` if the file cannot be read or is not a valid ESE database.
    pub fn parse_path(&self, path: &Path) -> anyhow::Result<Vec<TimelineEvent>> {
        self.parse_path_with_opts(path, &ParseOptions::default())
    }

    /// Parse a SRUDB.dat file under explicit [`ParseOptions`].
    ///
    /// Identical to [`parse_path`](Self::parse_path) for every table EXCEPT the
    /// high-volume PushNotifications and EnergyUsage tables: by default they are
    /// aggregated per-app (one summary event carrying an `occurrences` count), but
    /// when `opts.verbose_rows` is set they emit full per-row events instead — the
    /// full-fidelity view, at the cost of a larger timeline.
    ///
    /// Returns `Err` if the file cannot be read or is not a valid ESE database.
    pub fn parse_path_with_opts(
        &self,
        path: &Path,
        opts: &ParseOptions,
    ) -> anyhow::Result<Vec<TimelineEvent>> {
        let evidence_source = path.to_string_lossy().into_owned();
        let mut events = Vec::new();

        // SruDbIdMapTable: app_id is an index, not a name — resolve it so an
        // analyst sees the application path, not `app_id=285`. Best-effort: a
        // missing/empty id passes through with no `app_name` (the raw id is always
        // retained), so an unresolvable id is valid output, never a failure.
        let id_map: std::collections::HashMap<i32, String> = srum_parser::parse_id_map(path)
            .unwrap_or_default()
            .into_iter()
            .map(|e| (e.id, e.name))
            .collect();
        // Network usage + app resource usage (per-row, enriched).
        events.extend(network_usage_events(
            srum_parser::parse_network_usage(path)?,
            &id_map,
            &evidence_source,
        ));
        events.extend(app_usage_events(
            srum_parser::parse_app_usage(path)?,
            &id_map,
            &evidence_source,
        ));

        // Network connectivity records — when the host was attached to a network
        // and for how long (placement / timeline evidence).
        events.extend(connectivity_events(
            srum_parser::parse_network_connectivity(path)?,
            &id_map,
            &evidence_source,
        ));

        // App timeline records — foreground application usage (focus + user-input
        // time per app), the highest-value SRUM execution signal.
        events.extend(app_timeline_events(
            srum_parser::parse_app_timeline(path)?,
            &id_map,
            &evidence_source,
        ));

        // Push notifications + Energy usage are high-volume / low-signal. By
        // default they are AGGREGATED per app (one summary event with an
        // occurrence count + time range) rather than emitting hundreds of per-row
        // events that would flood the timeline. `opts.verbose_rows` opts into the
        // full per-row view instead — same enrichment and CADET tagging, one event
        // per record.
        let push = srum_parser::parse_push_notifications(path)?;
        let energy = srum_parser::parse_energy_usage(path)?;
        let energy_lt = srum_parser::parse_energy_lt(path)?;
        if opts.verbose_rows {
            events.extend(push_per_row_events(push, &id_map, &evidence_source));
            events.extend(energy_per_row_events(
                energy,
                &id_map,
                &evidence_source,
                "EnergyUsage",
            ));
            events.extend(energy_per_row_events(
                energy_lt,
                &id_map,
                &evidence_source,
                "EnergyUsageLT",
            ));
        } else {
            events.extend(push_aggregate_events(push, &id_map, &evidence_source));
            events.extend(energy_aggregate_events(
                energy,
                &id_map,
                &evidence_source,
                "EnergyUsage",
            ));
            events.extend(energy_aggregate_events(
                energy_lt,
                &id_map,
                &evidence_source,
                "EnergyUsageLT",
            ));
        }

        Ok(events)
    }
}

/// Per-app energy-usage rollup: record count, total energy consumed, the latest
/// charge level, and the time span.
#[derive(Default)]
struct EnergyAgg {
    occurrences: u64,
    total_energy: u64,
    last_charge: u64,
    first: Option<DateTime<Utc>>,
    last: Option<DateTime<Utc>>,
}

/// Aggregate SRUM energy rows per app into one `Execution` event each (an app
/// consuming power is execution evidence), keyed on last-seen. `kind` labels the
/// table — `"EnergyUsage"` or `"EnergyUsageLT"` (same record shape).
fn energy_aggregate_events(
    records: Vec<srum_core::EnergyUsageRecord>,
    id_map: &HashMap<i32, String>,
    evidence_source: &str,
    kind: &str,
) -> Vec<TimelineEvent> {
    let mut by_app: BTreeMap<i32, EnergyAgg> = BTreeMap::new();
    for r in records {
        let a = by_app.entry(r.app_id).or_default();
        a.occurrences += 1;
        a.total_energy += r.energy_consumed;
        if a.last.is_none_or(|l| r.timestamp >= l) {
            a.last_charge = r.charge_level;
        }
        a.first = Some(a.first.map_or(r.timestamp, |f| f.min(r.timestamp)));
        a.last = Some(a.last.map_or(r.timestamp, |l| l.max(r.timestamp)));
    }
    by_app
        .into_iter()
        .filter_map(|(app_id, agg)| {
            let last = agg.last?;
            let app_name = resolve_name(id_map, app_id);
            let app_label = app_name
                .clone()
                .unwrap_or_else(|| format!("app_id={app_id}"));
            let mut event = TimelineEvent::new(
                last.timestamp_nanos_opt().unwrap_or(0),
                last.to_rfc3339(),
                EventType::Other(kind.to_string()),
                ArtifactType::Srum,
                evidence_source.to_string(),
                format!(
                    "SRUM {kind}: {app_label} ({} records, {} energy consumed)",
                    agg.occurrences, agg.total_energy
                ),
                evidence_source.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::Execution)
            .with_metadata("occurrences", serde_json::json!(agg.occurrences))
            .with_metadata("total_energy_consumed", serde_json::json!(agg.total_energy))
            .with_metadata("last_charge_level", serde_json::json!(agg.last_charge))
            .with_metadata("app_id", serde_json::json!(app_id))
            .with_metadata(
                "first_seen",
                serde_json::json!(agg.first.map(|t| t.to_rfc3339())),
            )
            .with_metadata("last_seen", serde_json::json!(last.to_rfc3339()));
            if let Some(name) = &app_name {
                event = event.with_metadata("app_name", serde_json::json!(name));
            }
            Some(event)
        })
        .collect()
}

/// Per-app push-notification rollup: how many records, total notifications, and
/// the time span over which they occurred.
#[derive(Default)]
struct PushAgg {
    occurrences: u64,
    total_count: u64,
    total_fg_cycle: u64,
    first: Option<DateTime<Utc>>,
    last: Option<DateTime<Utc>>,
}

/// Aggregate SRUM PushNotifications per app into one `NetworkActivity` event each,
/// keyed on the app's last-seen time — collapsing a high-volume table into
/// per-app summaries instead of flooding the timeline with per-row events.
fn push_aggregate_events(
    records: Vec<srum_core::PushNotificationRecord>,
    id_map: &HashMap<i32, String>,
    evidence_source: &str,
) -> Vec<TimelineEvent> {
    let mut by_app: BTreeMap<i32, PushAgg> = BTreeMap::new();
    for r in records {
        let a = by_app.entry(r.app_id).or_default();
        a.occurrences += 1;
        a.total_count += u64::from(r.count);
        a.total_fg_cycle += r.foreground_cycle_time;
        a.first = Some(a.first.map_or(r.timestamp, |f| f.min(r.timestamp)));
        a.last = Some(a.last.map_or(r.timestamp, |l| l.max(r.timestamp)));
    }
    by_app
        .into_iter()
        .filter_map(|(app_id, agg)| {
            let last = agg.last?;
            let app_name = resolve_name(id_map, app_id);
            let app_label = app_name
                .clone()
                .unwrap_or_else(|| format!("app_id={app_id}"));
            let mut event = TimelineEvent::new(
                last.timestamp_nanos_opt().unwrap_or(0),
                last.to_rfc3339(),
                EventType::Other("PushNotifications".into()),
                ArtifactType::Srum,
                evidence_source.to_string(),
                format!(
                    "SRUM PushNotifications: {app_label} ({} records, {} notifications)",
                    agg.occurrences, agg.total_count
                ),
                evidence_source.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::NetworkActivity)
            .with_metadata("occurrences", serde_json::json!(agg.occurrences))
            .with_metadata("total_notifications", serde_json::json!(agg.total_count))
            .with_metadata(
                "total_foreground_cycle_time",
                serde_json::json!(agg.total_fg_cycle),
            )
            .with_metadata("app_id", serde_json::json!(app_id))
            .with_metadata(
                "first_seen",
                serde_json::json!(agg.first.map(|t| t.to_rfc3339())),
            )
            .with_metadata("last_seen", serde_json::json!(last.to_rfc3339()));
            if let Some(name) = &app_name {
                event = event.with_metadata("app_name", serde_json::json!(name));
            }
            Some(event)
        })
        .collect()
}

/// Per-row variant of [`energy_aggregate_events`]: one `Execution` event per
/// EnergyUsage record (an app drawing power ⇒ it ran), with the same app-name
/// enrichment and CADET tagging. Emitted only under `ParseOptions::verbose_rows`.
fn energy_per_row_events(
    records: Vec<srum_core::EnergyUsageRecord>,
    id_map: &HashMap<i32, String>,
    evidence_source: &str,
    kind: &str,
) -> Vec<TimelineEvent> {
    records
        .into_iter()
        .map(|record| {
            let app_name = resolve_name(id_map, record.app_id);
            let app_label = app_name
                .clone()
                .unwrap_or_else(|| format!("app_id={}", record.app_id));
            let mut event = TimelineEvent::new(
                record.timestamp.timestamp_nanos_opt().unwrap_or(0),
                record.timestamp.to_rfc3339(),
                EventType::Other(kind.to_string()),
                ArtifactType::Srum,
                evidence_source.to_string(),
                format!(
                    "SRUM {kind}: {app_label} energy_consumed={} charge_level={}",
                    record.energy_consumed, record.charge_level
                ),
                evidence_source.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::Execution)
            .with_metadata("energy_consumed", serde_json::json!(record.energy_consumed))
            .with_metadata("charge_level", serde_json::json!(record.charge_level))
            .with_metadata("app_id", serde_json::json!(record.app_id));
            if let Some(name) = &app_name {
                event = event.with_metadata("app_name", serde_json::json!(name));
            }
            event
        })
        .collect()
}

/// Per-row variant of [`push_aggregate_events`]: one `NetworkActivity` event per
/// PushNotifications record, with the same app-name enrichment and CADET tagging.
/// Emitted only under `ParseOptions::verbose_rows`.
fn push_per_row_events(
    records: Vec<srum_core::PushNotificationRecord>,
    id_map: &HashMap<i32, String>,
    evidence_source: &str,
) -> Vec<TimelineEvent> {
    records
        .into_iter()
        .map(|record| {
            let app_name = resolve_name(id_map, record.app_id);
            let app_label = app_name
                .clone()
                .unwrap_or_else(|| format!("app_id={}", record.app_id));
            let mut event = TimelineEvent::new(
                record.timestamp.timestamp_nanos_opt().unwrap_or(0),
                record.timestamp.to_rfc3339(),
                EventType::Other("PushNotifications".into()),
                ArtifactType::Srum,
                evidence_source.to_string(),
                format!("SRUM PushNotifications: {app_label} count={}", record.count),
                evidence_source.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::NetworkActivity)
            .with_metadata("count", serde_json::json!(record.count))
            .with_metadata(
                "foreground_cycle_time",
                serde_json::json!(record.foreground_cycle_time),
            )
            .with_metadata("app_id", serde_json::json!(record.app_id));
            if let Some(name) = &app_name {
                event = event.with_metadata("app_name", serde_json::json!(name));
            }
            event
        })
        .collect()
}

/// Resolve a `SruDbIdMapTable` index to a non-empty name (best-effort).
fn resolve_name(id_map: &HashMap<i32, String>, id: i32) -> Option<String> {
    id_map.get(&id).filter(|n| !n.is_empty()).cloned()
}

/// Map SRUM NetworkUsage rows (per-app bytes sent/received) to `NetworkActivity`
/// events, app_id resolved to the application name.
fn network_usage_events(
    records: Vec<srum_core::NetworkUsageRecord>,
    id_map: &HashMap<i32, String>,
    evidence_source: &str,
) -> Vec<TimelineEvent> {
    records
        .into_iter()
        .map(|record| {
            let app_name = resolve_name(id_map, record.app_id);
            let app_label = app_name
                .clone()
                .unwrap_or_else(|| format!("app_id={}", record.app_id));
            let mut event = TimelineEvent::new(
                record.timestamp.timestamp_nanos_opt().unwrap_or(0),
                record.timestamp.to_rfc3339(),
                EventType::Other("NetworkBandwidth".into()),
                ArtifactType::Srum,
                evidence_source.to_string(),
                format!(
                    "SRUM NetworkUsage: {app_label} bytes_sent={} bytes_recv={}",
                    record.bytes_sent, record.bytes_recv
                ),
                evidence_source.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::NetworkActivity)
            .with_metadata("bytes_sent", serde_json::json!(record.bytes_sent))
            .with_metadata("bytes_recv", serde_json::json!(record.bytes_recv))
            .with_metadata("app_id", serde_json::json!(record.app_id))
            .with_metadata("user_id", serde_json::json!(record.user_id));
            if let Some(name) = &app_name {
                event = event.with_metadata("app_name", serde_json::json!(name));
            }
            event
        })
        .collect()
}

/// Map SRUM AppUsage rows (per-app CPU cycle time) to `Execution` events,
/// app_id resolved to the application name.
fn app_usage_events(
    records: Vec<srum_core::AppUsageRecord>,
    id_map: &HashMap<i32, String>,
    evidence_source: &str,
) -> Vec<TimelineEvent> {
    records
        .into_iter()
        .map(|record| {
            let app_name = resolve_name(id_map, record.app_id);
            let app_label = app_name
                .clone()
                .unwrap_or_else(|| format!("app_id={}", record.app_id));
            let mut event = TimelineEvent::new(
                record.timestamp.timestamp_nanos_opt().unwrap_or(0),
                record.timestamp.to_rfc3339(),
                EventType::ProcessExec,
                ArtifactType::Srum,
                evidence_source.to_string(),
                format!(
                    "SRUM AppUsage: {app_label} foreground_cycles={} background_cycles={}",
                    record.foreground_cycles, record.background_cycles
                ),
                evidence_source.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::Execution)
            .with_metadata(
                "foreground_cycles",
                serde_json::json!(record.foreground_cycles),
            )
            .with_metadata(
                "background_cycles",
                serde_json::json!(record.background_cycles),
            )
            .with_metadata("app_id", serde_json::json!(record.app_id))
            .with_metadata("user_id", serde_json::json!(record.user_id));
            if let Some(name) = &app_name {
                event = event.with_metadata("app_name", serde_json::json!(name));
            }
            event
        })
        .collect()
}

/// Map SRUM AppTimeline rows (foreground app usage) to `Execution` events.
fn app_timeline_events(
    records: Vec<srum_core::AppTimelineRecord>,
    id_map: &HashMap<i32, String>,
    evidence_source: &str,
) -> Vec<TimelineEvent> {
    records
        .into_iter()
        .map(|record| {
            let ts_ns = record.timestamp.timestamp_nanos_opt().unwrap_or(0);
            let app_name = resolve_name(id_map, record.app_id);
            let app_label = app_name
                .clone()
                .unwrap_or_else(|| format!("app_id={}", record.app_id));
            let mut event = TimelineEvent::new(
                ts_ns,
                record.timestamp.to_rfc3339(),
                EventType::ProcessExec,
                ArtifactType::Srum,
                evidence_source.to_string(),
                format!(
                    "SRUM AppTimeline: {app_label} focus {}ms input {}ms",
                    record.focus_time_ms, record.user_input_time_ms
                ),
                evidence_source.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::Execution)
            .with_metadata("focus_time_ms", serde_json::json!(record.focus_time_ms))
            .with_metadata(
                "user_input_time_ms",
                serde_json::json!(record.user_input_time_ms),
            )
            .with_metadata("app_id", serde_json::json!(record.app_id))
            .with_metadata("user_id", serde_json::json!(record.user_id));
            if let Some(name) = &app_name {
                event = event.with_metadata("app_name", serde_json::json!(name));
            }
            event
        })
        .collect()
}

/// Map SRUM NetworkConnectivity rows (connection intervals) to `NetworkActivity`
/// events. `profile_id` resolves through the same id map (per `enrich_connectivity`).
fn connectivity_events(
    records: Vec<srum_core::NetworkConnectivityRecord>,
    id_map: &HashMap<i32, String>,
    evidence_source: &str,
) -> Vec<TimelineEvent> {
    records
        .into_iter()
        .map(|record| {
            let ts_ns = record.timestamp.timestamp_nanos_opt().unwrap_or(0);
            let app_name = resolve_name(id_map, record.app_id);
            let profile_name = resolve_name(id_map, record.profile_id);
            let app_label = app_name
                .clone()
                .unwrap_or_else(|| format!("app_id={}", record.app_id));
            let mut event = TimelineEvent::new(
                ts_ns,
                record.timestamp.to_rfc3339(),
                EventType::Other("NetworkConnectivity".into()),
                ArtifactType::Srum,
                evidence_source.to_string(),
                format!(
                    "SRUM NetworkConnectivity: {app_label} connected {}s",
                    record.connected_time
                ),
                evidence_source.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::NetworkActivity)
            .with_metadata("connected_time", serde_json::json!(record.connected_time))
            .with_metadata("app_id", serde_json::json!(record.app_id))
            .with_metadata("profile_id", serde_json::json!(record.profile_id))
            .with_metadata("user_id", serde_json::json!(record.user_id));
            if let Some(name) = &app_name {
                event = event.with_metadata("app_name", serde_json::json!(name));
            }
            if let Some(name) = &profile_name {
                event = event.with_metadata("profile_name", serde_json::json!(name));
            }
            event
        })
        .collect()
}

impl ForensicParser for SrumParser {
    fn name(&self) -> &'static str {
        "SRUM Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::Srum]
    }

    fn parse(
        &self,
        input: &dyn DataSource,
        emitter: &dyn EventEmitter,
        opts: &ParseOptions,
    ) -> Result<ParseStats, RtError> {
        // SRUM is an ESE database: the parser seeks across B-tree pages, so it
        // needs random-access *file* semantics, not the streaming byte view.
        // When the source exposes its path (the orchestrator's FileDataSource
        // does), drive the real ESE traversal through it; a byte-only source
        // (no path) yields no events rather than failing.
        let Some(path) = input.source_path() else {
            return Ok(ParseStats::new());
        };

        let events = self
            .parse_path_with_opts(path, opts)
            .map_err(|e| RtError::InvalidData(format!("SRUM parse failed: {e}")))?;
        let mut stats = ParseStats::new();
        stats.events_emitted = events.len() as u64;
        stats.bytes_processed = input.len();
        emitter.emit_batch(events)?;
        Ok(stats)
    }

    fn capabilities(&self) -> ParserCapabilities {
        ParserCapabilities {
            max_memory_bytes: Some(256 * 1024 * 1024), // 256 MiB
            streaming: false,
            deterministic: true,
        }
    }
}

// Compile-time registration with the parser inventory.
inventory::submit! {
    ParserRegistration { create: || Box::new(SrumParser), selector: sel::ArtifactSelector {
            artifact_type: issen_core::artifacts::ArtifactType::Srum,
            matches: classify::srum,
            priority: 90,
            disk_sources: &[
                sel::DiskSource::Ntfs(sel::NtfsLoc::FixedPath(r"\Windows\System32\sru\SRUDB.dat")),
            ],
            cost: sel::CostTier::Default,
        } }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::NamedTempFile;

    #[test]
    fn srum_parser_handles_srudb_dat_name() {
        let parser = SrumParser;
        assert!(parser.can_parse(Path::new("SRUDB.dat")));
    }

    #[test]
    fn srum_parser_handles_srudb_dat_case_insensitive() {
        let parser = SrumParser;
        assert!(parser.can_parse(Path::new("srudb.dat")));
        assert!(parser.can_parse(Path::new("SRUDB.DAT")));
        assert!(parser.can_parse(Path::new("Srudb.Dat")));
    }

    #[test]
    fn srum_parser_rejects_other_files() {
        let parser = SrumParser;
        assert!(!parser.can_parse(Path::new("system.log")));
        assert!(!parser.can_parse(Path::new("$MFT")));
        assert!(!parser.can_parse(Path::new("Security.evtx")));
        assert!(!parser.can_parse(Path::new("SRUDB.dat.bak")));
    }

    #[test]
    fn srum_parser_returns_empty_for_empty_file() {
        let tmp = NamedTempFile::new().expect("tempfile");
        let parser = SrumParser;
        // empty file is not a valid ESE DB — parser must return Ok(vec![]) or Err
        // The srum-parser lib returns Err for invalid ESE; our wrapper must not panic.
        let result = parser.parse_path(tmp.path());
        // Acceptable: Ok(empty) or Err — must not panic.
        if let Ok(events) = result {
            assert!(events.is_empty(), "empty file should yield no events");
        } // Err is also acceptable — file is not a valid ESE DB
    }
}
