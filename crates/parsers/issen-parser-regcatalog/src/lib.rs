//! Catalog-driven registry scanner for Issen.
//!
//! This surfaces the WHOLE forensicnomicon registry catalog: rather than one
//! hardcoded artifact, it walks every catalog descriptor whose hive matches the
//! hive under analysis, opens the descriptor's key, and emits each decoded value
//! — the catalog owns the *meaning* (path, label, MITRE mapping), winreg-core the
//! byte mechanics. One catalog scan replaces dozens of bespoke key-lookups, so a
//! large swath of the registry catalog that was previously dark becomes timeline
//! events.
//!
//! Decoding is delegated to our own `winreg-artifacts::catalog_scan` (over
//! `winreg-core`, knowledge from `forensicnomicon::catalog`) — the registry-
//! artifact home for the fleet — never third-party notatin.
//!
//! Scope note (carried from `winreg-artifacts::catalog_scan`): wildcard (`*`/`**`)
//! and SID-placeholder catalog paths, and per-user (`scan_users`) attribution,
//! are out of scope for this single-hive resolver; they simply produce no hit
//! here. Wiring the multi-user `scan_users` path (which attributes hits to a
//! specific profile/SID) is a follow-up once Issen passes a profile-tagged hive
//! set into the parser layer — TODO(issen#113): thread `scan_users` through the
//! orchestration's per-user hive discovery.

#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    // `fn name(&self) -> &str` must match the `ForensicParser` trait signature.
    clippy::unnecessary_literal_bound,
    // DataSource lengths are bounded well under usize on supported targets.
    clippy::cast_possible_truncation
)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::path::Path;

use issen_core::artifacts::ArtifactType;
use issen_core::classify;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::selector as sel;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseOptions, ParseStats, ParserCapabilities,
};
use issen_core::timeline::event::{EventType, TimelineEvent};

// `activity_category` became a trait method on `ArtifactDescriptorCadetExt` in
// forensicnomicon 1.0 (was an inherent method in 0.11).
use forensicnomicon::cadet::ArtifactDescriptorCadetExt;

/// Standard offline registry hive filenames the catalog scanner engages on.
/// (The actual hive *type* is detected from content; this is only a fast gate.)
const HIVE_FILENAMES: &[&str] = &[
    "software",
    "system",
    "sam",
    "security",
    "default",
    "ntuser.dat",
    "usrclass.dat",
    "amcache.hve",
];

// ---------------------------------------------------------------------------
// Hive-level parsing
// ---------------------------------------------------------------------------

/// Parse any supported registry hive file against the forensicnomicon catalog.
///
/// On any error or missing key, returns `Ok(vec![])`.
pub fn parse_regcatalog(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    let bytes = match std::fs::read(path) {
        Ok(b) if !b.is_empty() => b,
        _ => return Ok(vec![]),
    };
    let hive_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("HIVE");
    Ok(events_from_bytes(&bytes, hive_name, source_id))
}

/// Build catalog-hit [`TimelineEvent`]s from raw hive bytes — shared by
/// [`parse_regcatalog`] (path) and the `ForensicParser::parse` ingest path.
#[must_use]
pub fn events_from_bytes(bytes: &[u8], hive_name: &str, source_id: &str) -> Vec<TimelineEvent> {
    let Ok(hive) = winreg_core::hive::Hive::from_bytes(bytes.to_vec()) else {
        return Vec::new();
    };

    winreg_artifacts::catalog_scan::scan(&hive)
        .into_iter()
        .map(|h| {
            // Catalog hits are value reads; the descriptor carries no structured
            // last-write timestamp (a FILETIME decoder renders into value_data).
            let value_name = h.value_name.clone().unwrap_or_default();
            // Each hit is a different artifact kind, so the CADET category is
            // looked up per-descriptor (forensicnomicon's structural classifier),
            // not one uniform tag for the whole catalog.
            let category = forensicnomicon::catalog::CATALOG
                .by_id(h.catalog_id)
                .map(forensicnomicon::catalog::ArtifactDescriptor::activity_category);
            // The resolved key's LastWriteTime is the hit's forensic timestamp.
            let (ts_ns, ts_display) = h.last_written.map_or_else(
                || (0, "unknown".to_string()),
                |dt| (dt.timestamp_nanos_opt().unwrap_or(0), dt.to_rfc3339()),
            );
            let event = TimelineEvent::new(
                ts_ns,
                ts_display,
                EventType::RegistryModify,
                ArtifactType::Registry,
                format!("{hive_name}\\{}", h.key_path),
                format!(
                    "{} ({}): {} = {}",
                    h.artifact_name, h.meaning, value_name, h.value_data
                ),
                source_id.to_string(),
            )
            .with_metadata("catalog_id", serde_json::json!(h.catalog_id))
            .with_metadata("artifact_name", serde_json::json!(h.artifact_name))
            .with_metadata("meaning", serde_json::json!(h.meaning))
            .with_metadata("key_path", serde_json::json!(h.key_path))
            .with_metadata("value_name", serde_json::json!(h.value_name))
            .with_metadata("value_data", serde_json::json!(h.value_data))
            .with_metadata("mitre_techniques", serde_json::json!(h.mitre_techniques))
            .with_metadata(
                "needs_specialized_decoder",
                serde_json::json!(h.needs_specialized_decoder),
            )
            .with_metadata("user", serde_json::json!(h.user))
            .with_metadata("bindings", serde_json::json!(h.bindings))
            .with_metadata("artifact", serde_json::json!("catalog_scan"));
            match category {
                Some(cat) => event.with_activity_category(cat),
                None => event,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Plugin struct
// ---------------------------------------------------------------------------

/// Catalog-driven registry scanner — engages on any supported offline hive and
/// emits a [`TimelineEvent`] per decoded forensicnomicon-catalog artifact.
pub struct RegCatalogParser;

impl RegCatalogParser {
    /// Return `true` when `path`'s filename is a standard registry hive name
    /// (case-insensitive).
    pub fn can_parse(path: &Path) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .map(str::to_ascii_lowercase)
            .is_some_and(|name| HIVE_FILENAMES.contains(&name.as_str()))
    }
}

impl ForensicParser for RegCatalogParser {
    fn name(&self) -> &str {
        "Registry Catalog Scanner"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::Registry]
    }

    fn parse(
        &self,
        input: &dyn DataSource,
        emitter: &dyn EventEmitter,
        _opts: &ParseOptions,
    ) -> Result<ParseStats, issen_core::error::RtError> {
        let mut stats = ParseStats::new();
        let len = input.len();
        if len == 0 {
            return Ok(stats);
        }
        let mut bytes = vec![0u8; len as usize];
        let mut off = 0u64;
        while off < len {
            let n = input.read_at(off, &mut bytes[off as usize..])?;
            if n == 0 {
                break;
            }
            off += n as u64;
        }
        stats.bytes_processed = off;
        let events = events_from_bytes(&bytes, "HIVE", "regcatalog-evidence");
        stats.events_emitted = events.len() as u64;
        if !events.is_empty() {
            emitter.emit_batch(events)?;
        }
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
    ParserRegistration { create: || Box::new(RegCatalogParser), selector: sel::ArtifactSelector {
            artifact_type: issen_core::artifacts::ArtifactType::Registry,
            matches: classify::registry_hive,
            priority: 96,
            disk_sources: &[],
            cost: sel::CostTier::Default,
        } }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[test]
    fn can_parse_software_hive() {
        assert!(RegCatalogParser::can_parse(&PathBuf::from(
            "/evidence/C/Windows/System32/config/SOFTWARE"
        )));
    }

    #[test]
    fn can_parse_system_hive() {
        assert!(RegCatalogParser::can_parse(&PathBuf::from(
            "/evidence/SYSTEM"
        )));
    }

    #[test]
    fn can_parse_ntuser_hive() {
        assert!(RegCatalogParser::can_parse(&PathBuf::from(
            "/evidence/C/Users/jdoe/NTUSER.DAT"
        )));
    }

    #[test]
    fn can_parse_security_and_sam() {
        assert!(RegCatalogParser::can_parse(&PathBuf::from(
            "/evidence/SECURITY"
        )));
        assert!(RegCatalogParser::can_parse(&PathBuf::from("/evidence/SAM")));
    }

    #[test]
    fn can_parse_usrclass_lowercase() {
        assert!(RegCatalogParser::can_parse(&PathBuf::from(
            "/evidence/UsrClass.dat"
        )));
    }

    #[test]
    fn cannot_parse_random_file() {
        assert!(!RegCatalogParser::can_parse(&PathBuf::from(
            "/evidence/notes.txt"
        )));
    }

    #[test]
    fn parse_nonexistent_returns_empty() {
        let result = parse_regcatalog(Path::new("/nonexistent/SOFTWARE"), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn parse_empty_hive_returns_empty() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let result = parse_regcatalog(tmp.path(), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn events_from_garbage_bytes_is_empty() {
        assert!(events_from_bytes(b"not-a-hive", "SOFTWARE", "test").is_empty());
    }
}
