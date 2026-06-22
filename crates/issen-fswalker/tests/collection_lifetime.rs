//! Regression (issen #115 / collection ingest): `run_auto_units` must keep the
//! collection's extracted tempdir alive across *parsing*, not just discovery.
//!
//! A prior version scoped the `CollectionManifest` to the discovery branch, so
//! its RAII `TempDir` deleted the extracted files before `parse_units` opened
//! them — real Velociraptor collections discovered hundreds of artifacts but
//! parsed zero, every one failing "No such file or directory".
//!
//! This drives a real provider + parser through the global inventories (this is
//! a dedicated test binary, so the registrations do not leak into the lib unit
//! tests, which assert an empty parser registry).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use issen_core::artifacts::ArtifactType;
use issen_core::error::RtError;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseOptions, ParseStats, ParserCapabilities,
};
use issen_core::timeline::event::{EventType, TimelineEvent};
use issen_fswalker::orchestrator::run_auto_units;
use issen_fswalker::progress::ProgressReporter;
use issen_unpack::registry::ProviderRegistration;
use issen_unpack::{
    CollectionManifest, CollectionMetadata, CollectionProvider, Confidence, OsType,
};

/// Magic identifying the file our provider claims, so it never matches anything
/// else linked into this test binary.
const SENTINEL: &[u8] = b"ISSEN-TEST-COLLECTION-V1";

static MFT_KINDS: [ArtifactType; 1] = [ArtifactType::Mft];

/// Provider that probes High only for a SENTINEL file and "extracts" a single
/// `$MFT` artifact into a fresh tempdir owned by the returned manifest.
struct SentinelProvider;

impl CollectionProvider for SentinelProvider {
    fn name(&self) -> &'static str {
        "SentinelTestCollection"
    }

    fn probe(&self, path: &Path) -> Result<Confidence, RtError> {
        let data = std::fs::read(path).map_err(RtError::Io)?;
        if data.starts_with(SENTINEL) {
            Ok(Confidence::High)
        } else {
            Ok(Confidence::None)
        }
    }

    fn open(&self, _path: &Path) -> Result<CollectionManifest, RtError> {
        let tempdir = tempfile::tempdir().map_err(RtError::Io)?;
        // The extracted artifact: a $MFT file → classified as ArtifactType::Mft.
        std::fs::write(tempdir.path().join("$MFT"), b"mft-bytes").map_err(RtError::Io)?;
        Ok(CollectionManifest::new(
            self.name().to_string(),
            tempdir,
            vec![],
            CollectionMetadata {
                hostname: None,
                collection_time: None,
                os_type: OsType::Unknown,
                tool_version: None,
            },
        ))
    }
}

inventory::submit!(ProviderRegistration {
    create: || Box::new(SentinelProvider),
});

/// Parser claiming `ArtifactType::Mft`. `parse_units` opens the file *before*
/// calling this, so if the extracted file was deleted (the bug) the open fails
/// and this never runs.
struct MftTouchParser;

impl ForensicParser for MftTouchParser {
    fn name(&self) -> &'static str {
        "MftTouch"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &MFT_KINDS
    }

    fn parse(
        &self,
        _input: &dyn DataSource,
        emitter: &dyn EventEmitter,
        _opts: &ParseOptions,
    ) -> Result<ParseStats, RtError> {
        emitter.emit(TimelineEvent::new(
            0,
            "ts".into(),
            EventType::FileCreate,
            ArtifactType::Mft,
            "p".into(),
            "mft-event".into(),
            "ev".into(),
        ))?;
        let mut stats = ParseStats::new();
        stats.events_emitted = 1;
        Ok(stats)
    }

    fn capabilities(&self) -> ParserCapabilities {
        ParserCapabilities {
            max_memory_bytes: None,
            streaming: false,
            deterministic: true,
        }
    }
}

inventory::submit!(ParserRegistration {
    create: || Box::new(MftTouchParser),
    selector: issen_core::plugin::selector::ArtifactSelector {
        artifact_type: ArtifactType::Mft,
        matches: issen_core::classify::mft,
        priority: 99,
        disk_sources: &[],
        cost: issen_core::plugin::selector::CostTier::Default,
    },
});

#[test]
fn run_auto_units_keeps_collection_files_alive_through_parse() {
    let dir = tempfile::tempdir().expect("tmp");
    let collection = dir.path().join("collection.bin");
    std::fs::write(&collection, SENTINEL).expect("write sentinel");

    let progress = ProgressReporter::new();
    let no_skip = |_: &ArtifactType, _: &Path, _: &str| false;
    let (units, result, skipped) =
        run_auto_units(&collection, &progress, &no_skip, &ParseOptions::default())
            .expect("run_auto_units");

    assert_eq!(skipped, 0, "nothing is pre-completed");
    assert!(
        result.errors.is_empty(),
        "the extracted $MFT must survive to parse time; errors: {:?}",
        result.errors
    );
    assert_eq!(units.len(), 1, "the extracted $MFT is parsed into one unit");
    assert_eq!(result.total_events, 1, "the parser emitted its event");
}
