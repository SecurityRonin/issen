//! Unallocated-space carving seam (fleet ADR 0001 §1/§4, disk MVP).
//!
//! Adapts an issen [`DataSource`] to the medium-agnostic
//! [`forensic_carve::RegionSource`], runs one
//! [`forensic_carve::sweep`] over the disk's unallocated extents under
//! [`forensic_carve::RecoveryMethod::UnallocatedCarve`], and converts each
//! recovered [`forensic_carve::CarvedItem`] into a [`TimelineEvent`] tagged with
//! the carved format, absolute offset, confidence, and recovery method.
//!
//! The carvers are *injected* (the orchestrator passes
//! [`forensic_carve::registered_carvers`]), so this seam stays free of the carver
//! fleet and is unit-testable with a mock carver over a mock `RegionSource`.
//!
//! Deferred (ADR 0001 follow-ups, out of the disk MVP): the memory leg
//! (`RecoveryMethod::MemoryCarve`), filesystem-tombstone recovery
//! (`RecoveryMethod::Tombstone`), and pipeline **re-entry** of an `ArtifactBytes`
//! payload back through the normal parsers (classification). A carved artifact
//! here carries no container-level timestamp (epoch `0`); a future classify
//! re-entry may enrich it from the decoded records.

use forensic_carve::{
    sweep, CarveOptions, CarvedItem, Carver, RecoveryMethod, Region, RegionSource,
};

use crate::artifacts::ArtifactType;
use crate::plugin::traits::DataSource;
use crate::timeline::event::{EventType, TimelineEvent};

/// Adapt an issen [`DataSource`] (positioned, fallible reads) to the carving
/// engine's [`RegionSource`] (an infallible short-read edge).
///
/// A read error or end-of-source yields `0` bytes — the engine treats a short
/// read as a gap and never fabricates bytes past it, so degrading a failed read
/// to "no data at this offset" is the correct, contract-preserving behavior for a
/// best-effort recovery sweep.
pub struct DataSourceRegionSource<'a>(pub &'a dyn DataSource);

impl RegionSource for DataSourceRegionSource<'_> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> usize {
        self.0.read_at(offset, buf).unwrap_or(0)
    }
}

/// Map a carver `format` token to the timeline [`ArtifactType`].
fn artifact_type_for(format: &str) -> ArtifactType {
    match format {
        "sqlite" => ArtifactType::SqliteCarved,
        "evtx-chunk" => ArtifactType::EventLog,
        "registry-hive" => ArtifactType::Registry,
        _ => ArtifactType::Assessment,
    }
}

/// Convert one recovered item to a timeline event, stamping the carve provenance
/// (format, absolute offset, confidence, recovery method) onto tags + metadata.
fn carved_item_to_event(item: &CarvedItem, evidence_source_id: &str) -> TimelineEvent {
    let format = item.format();
    let offset = item.image_offset();
    let method = item.recovery_method();
    let confidence = item.confidence();
    TimelineEvent::new(
        0,
        "1970-01-01T00:00:00.000000000Z".to_string(),
        EventType::Other(format!("Carved:{format}")),
        artifact_type_for(format),
        format!("unallocated:{format}@{offset}"),
        format!(
            "Carved {format} artifact from unallocated space at offset {offset} \
             (confidence {confidence:.2}, {})",
            method.as_str()
        ),
        evidence_source_id.to_string(),
    )
    .with_tag("carved")
    .with_tag(format!("recovery:{}", method.as_str()))
    .with_tag(format!("format:{format}"))
    .with_metadata("carve_offset", serde_json::json!(offset))
    .with_metadata("carve_format", serde_json::json!(format))
    .with_metadata("carve_confidence", serde_json::json!(confidence))
    .with_metadata("recovery_method", serde_json::json!(method.as_str()))
}

/// Carve the `regions` of a disk `source` into timeline events (disk MVP).
///
/// Runs one [`forensic_carve::sweep`] with the injected `carvers` under
/// [`RecoveryMethod::UnallocatedCarve`], converting each recovered item into a
/// [`TimelineEvent`] stamped with the carve provenance and `evidence_source_id`.
/// The `regions` are the disk's unallocated extents (the caller enumerates them
/// via `forensic-vfs`'s `FileSystem::unallocated()`); the `tag` type `R` is
/// carried through the sweep but not otherwise used here (the item's absolute
/// offset already locates it in the image).
pub fn carve_unallocated<S, R>(
    source: &S,
    regions: impl IntoIterator<Item = Region<R>>,
    carvers: &[&dyn Carver],
    evidence_source_id: &str,
) -> Vec<TimelineEvent>
where
    S: RegionSource,
    R: Clone,
{
    let opts = CarveOptions {
        recovery_method: RecoveryMethod::UnallocatedCarve,
        ..CarveOptions::default()
    };
    sweep(source, regions, carvers, &opts)
        .into_iter()
        .map(|swept| carved_item_to_event(&swept.item, evidence_source_id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::RtError;
    use forensic_carve::{CarveContext, Signature};

    const MOCK_MAGIC: &[u8] = b"CARVEME!";
    static MOCK_SIGS: [Signature; 1] = [Signature::new(MOCK_MAGIC, 0)];

    /// A carver that fires on `MOCK_MAGIC` and emits a single "sqlite" record item
    /// anchored at the hit offset, echoing the sweep's recovery method.
    struct MockCarver;
    impl Carver for MockCarver {
        fn format(&self) -> &'static str {
            "mock"
        }
        fn signatures(&self) -> &[Signature] {
            &MOCK_SIGS
        }
        fn max_window(&self) -> u64 {
            64
        }
        fn carve(&self, _window: &[u8], ctx: &CarveContext) -> Vec<CarvedItem> {
            vec![CarvedItem::records(
                "sqlite",
                ctx.base_offset(),
                1.0,
                ctx.recovery_method(),
            )]
        }
    }

    /// A `RegionSource` backed by an in-memory image.
    struct VecSource(Vec<u8>);
    impl RegionSource for VecSource {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> usize {
            let off = offset as usize;
            if off >= self.0.len() {
                return 0;
            }
            let n = buf.len().min(self.0.len() - off);
            buf[..n].copy_from_slice(&self.0[off..off + n]);
            n
        }
    }

    /// A `DataSource` backed by an in-memory image, to exercise the adapter.
    struct MemSource(Vec<u8>);
    impl DataSource for MemSource {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
            let off = offset as usize;
            if off >= self.0.len() {
                return Ok(0);
            }
            let n = buf.len().min(self.0.len() - off);
            buf[..n].copy_from_slice(&self.0[off..off + n]);
            Ok(n)
        }
    }

    fn image_with_magic_at(offset: usize) -> Vec<u8> {
        let mut data = vec![0u8; offset + 128];
        data[offset..offset + MOCK_MAGIC.len()].copy_from_slice(MOCK_MAGIC);
        data
    }

    #[test]
    fn carves_a_mock_artifact_into_one_tagged_event() {
        let data = image_with_magic_at(100);
        let source = VecSource(data.clone());
        let regions = vec![Region {
            start: 0,
            len: data.len() as u64,
            tag: (),
        }];
        let carver = MockCarver;
        let carvers: Vec<&dyn Carver> = vec![&carver];

        let events = carve_unallocated(&source, regions, &carvers, "evidence-XYZ");

        assert_eq!(events.len(), 1, "one magic hit → one carved event");
        let e = &events[0];
        assert_eq!(
            e.source,
            ArtifactType::SqliteCarved,
            "format \"sqlite\" maps to SqliteCarved"
        );
        assert_eq!(e.event_type, EventType::Other("Carved:sqlite".to_string()));
        assert!(
            e.artifact_path.contains("@100"),
            "artifact_path carries the absolute offset: {}",
            e.artifact_path
        );
        assert!(
            e.tags.iter().any(|t| t == "recovery:unallocated-carve"),
            "recovery method is tagged: {:?}",
            e.tags
        );
        assert_eq!(e.evidence_source_id, "evidence-XYZ");
        assert_eq!(
            e.metadata.get("carve_offset"),
            Some(&serde_json::json!(100u64))
        );
        assert_eq!(
            e.metadata.get("carve_format"),
            Some(&serde_json::json!("sqlite"))
        );
    }

    #[test]
    fn no_magic_yields_no_events() {
        let source = VecSource(vec![0u8; 256]);
        let regions = vec![Region {
            start: 0,
            len: 256,
            tag: (),
        }];
        let carver = MockCarver;
        let carvers: Vec<&dyn Carver> = vec![&carver];
        assert!(carve_unallocated(&source, regions, &carvers, "e").is_empty());
    }

    #[test]
    fn datasource_adapter_bridges_reads_and_carves() {
        // The DataSourceRegionSource adapter is the thin wrapper the disk
        // orchestrator uses over a real image; drive it end-to-end.
        let data = image_with_magic_at(64);
        let ds = MemSource(data.clone());
        let source = DataSourceRegionSource(&ds);
        // Delegation: a mid-image read returns exactly the requested bytes.
        let mut buf = [0u8; 8];
        assert_eq!(source.read_at(64, &mut buf), 8);
        assert_eq!(&buf, MOCK_MAGIC);
        // Past EOF → 0 (gap), never a fabricated byte.
        assert_eq!(source.read_at(data.len() as u64, &mut buf), 0);

        let regions = vec![Region {
            start: 0,
            len: data.len() as u64,
            tag: 7u64,
        }];
        let carver = MockCarver;
        let carvers: Vec<&dyn Carver> = vec![&carver];
        let events = carve_unallocated(&source, regions, &carvers, "img");
        assert_eq!(events.len(), 1);
        assert!(events[0].artifact_path.contains("@64"));
    }

    #[test]
    fn unknown_format_falls_back_to_assessment() {
        assert_eq!(
            artifact_type_for("no-such-format"),
            ArtifactType::Assessment
        );
        assert_eq!(artifact_type_for("evtx-chunk"), ArtifactType::EventLog);
        assert_eq!(artifact_type_for("registry-hive"), ArtifactType::Registry);
    }
}
