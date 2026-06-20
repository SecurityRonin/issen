//! Wire the PE parser into the issen ingest pipeline as a **gated** `ForensicParser`.
//!
//! PE deep analysis (full import resolution + per-section entropy) is too
//! expensive to run on every executable on a disk, so the orchestrator routes
//! only *suspicious* executables here (suspicious location today; correlation /
//! IOC next). For each PE this emits one analysis event plus one event per
//! forensic detection (suspicious imports, packing, AV-exclusion strings, IOCs),
//! each carrying the MITRE technique id and evidence.

use issen_core::artifacts::ArtifactType;
use issen_core::classify;
use issen_core::plugin::selector as sel;
use issen_core::error::RtError;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseCompletion, ParseStats, ParserCapabilities,
};
use issen_core::timeline::event::{EventType, TimelineEvent};
use issen_core::ActivityCategory;

use crate::detections::{detect_all, PeDetectionKind};
use crate::parser::{parse_pe, PeInfo};

/// CADET category for a detection kind.
fn category_for(kind: &PeDetectionKind) -> ActivityCategory {
    match kind {
        PeDetectionKind::SuspiciousImport | PeDetectionKind::QWCryptPeIoc => {
            ActivityCategory::Execution
        }
        PeDetectionKind::PackedExecutable | PeDetectionKind::AvExclusionStrings => {
            ActivityCategory::AntiForensics
        }
    }
}

/// Build timeline events from parsed PE info: one analysis summary + one event
/// per forensic detection.
pub fn pe_events_from_info(
    pe: &PeInfo,
    artifact_path: &str,
    source_id: &str,
) -> Vec<TimelineEvent> {
    let ts_ns = i64::from(pe.compile_timestamp) * 1_000_000_000;
    let wx = pe.sections.iter().any(|s| s.is_executable && s.is_writable);
    let kind = if pe.is_dll { "DLL" } else { "EXE" };

    let mut events = Vec::new();
    events.push(
        TimelineEvent::new(
            ts_ns,
            String::new(),
            EventType::Other("pe-analysis".into()),
            ArtifactType::Pe,
            artifact_path.to_string(),
            format!(
                "PE {kind} analyzed: {} imports, {} sections{}",
                pe.imports.len(),
                pe.sections.len(),
                if wx { ", W+X section" } else { "" }
            ),
            source_id.to_string(),
        )
        .with_activity_category(ActivityCategory::Execution)
        .with_metadata("machine", serde_json::json!(pe.machine))
        .with_metadata("is_dll", serde_json::json!(pe.is_dll))
        .with_metadata("import_count", serde_json::json!(pe.imports.len()))
        .with_metadata("section_count", serde_json::json!(pe.sections.len()))
        .with_metadata("compile_timestamp", serde_json::json!(pe.compile_timestamp))
        .with_metadata("has_wx_section", serde_json::json!(wx)),
    );

    for d in detect_all(pe) {
        events.push(
            TimelineEvent::new(
                ts_ns,
                String::new(),
                EventType::Other("pe-detection".into()),
                ArtifactType::Pe,
                artifact_path.to_string(),
                d.description.clone(),
                source_id.to_string(),
            )
            .with_activity_category(category_for(&d.kind))
            .with_tag("suspicious")
            .with_metadata("mitre_technique", serde_json::json!(d.mitre_technique_id))
            .with_metadata("tactic", serde_json::json!(d.tactic))
            .with_metadata("evidence", serde_json::json!(d.evidence)),
        );
    }
    events
}

/// Parse PE bytes and produce events. Empty on parse failure (non-PE input).
#[must_use]
pub fn pe_findings(bytes: &[u8], artifact_path: &str, source_id: &str) -> Vec<TimelineEvent> {
    parse_pe(bytes).map_or_else(
        |_| Vec::new(),
        |pe| pe_events_from_info(&pe, artifact_path, source_id),
    )
}

/// `ForensicParser` wrapper registered into the inventory.
pub struct PeParser;

impl ForensicParser for PeParser {
    fn name(&self) -> &str {
        "PE Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::Pe]
    }

    fn parse(
        &self,
        input: &dyn DataSource,
        emitter: &dyn EventEmitter,
    ) -> Result<ParseStats, RtError> {
        let mut stats = ParseStats::new();
        let len = input.len();
        if len == 0 {
            stats.completion = ParseCompletion::Unsupported;
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

        let artifact_path = input.source_path().map_or_else(
            || "pe-evidence".to_string(),
            |p| p.to_string_lossy().into_owned(),
        );
        let events = pe_findings(&bytes[..off as usize], &artifact_path, "pe-evidence");
        stats.events_emitted = events.len() as u64;
        if !events.is_empty() {
            emitter.emit_batch(events)?;
        }
        stats.completion = ParseCompletion::Complete;
        Ok(stats)
    }

    fn capabilities(&self) -> ParserCapabilities {
        ParserCapabilities {
            max_memory_bytes: Some(256 * 1024 * 1024),
            streaming: false,
            deterministic: true,
        }
    }
}

inventory::submit! {
    ParserRegistration { create: || Box::new(PeParser), selector: sel::ArtifactSelector {
            artifact_type: issen_core::artifacts::ArtifactType::Pe,
            matches: classify::pe_suspicious,
            priority: 10,
            disk_sources: &[],
            cost: sel::CostTier::OptIn,
        } }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::parser::PeSection;

    fn pe_with(imports: Vec<&str>, sections: Vec<PeSection>) -> PeInfo {
        PeInfo {
            machine: 0x8664,
            compile_timestamp: 1_600_000_000,
            is_dll: false,
            imports: imports.into_iter().map(String::from).collect(),
            sections,
            strings: vec![],
        }
    }

    #[test]
    fn suspicious_import_emits_detection_event_with_mitre() {
        let pe = pe_with(vec!["VirtualAllocEx", "WriteProcessMemory"], vec![]);
        let events = pe_events_from_info(&pe, "c:/windows/temp/evil.exe", "test");

        // A summary event is always emitted.
        assert!(events
            .iter()
            .any(|e| matches!(&e.event_type, EventType::Other(s) if s == "pe-analysis")));

        // The injection imports produce at least one detection carrying a MITRE id.
        let det = events
            .iter()
            .find(|e| matches!(&e.event_type, EventType::Other(s) if s == "pe-detection"))
            .expect("a suspicious-import detection event");
        assert_eq!(det.source, ArtifactType::Pe);
        assert!(det.tags.iter().any(|t| t == "suspicious"));
        assert!(det.metadata.contains_key("mitre_technique"));
    }

    #[test]
    fn clean_pe_emits_only_the_summary() {
        let pe = pe_with(vec!["GetTickCount", "lstrlenW"], vec![]);
        let events = pe_events_from_info(&pe, "c:/program files/app/app.exe", "test");
        assert_eq!(events.len(), 1, "clean PE → summary only, no detections");
    }
}
