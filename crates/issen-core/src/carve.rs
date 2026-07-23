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
use forensic_vfs::{FileSystem, RunAlloc};

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

/// The tag carried on each unallocated [`Region`]: the extent's absolute image
/// byte offset. It is provenance only — the sweep already stamps each carved
/// hit with its own absolute offset — but preserving it lets a future consumer
/// attribute a hit back to the unallocated extent it was recovered from.
pub type RegionTag = u64;

/// Enumerate a filesystem's unallocated extents as carve [`Region`]s.
///
/// Streams [`forensic_vfs::FileSystem::unallocated`] and maps every genuinely
/// [`RunAlloc::Unallocated`] run to a `Region { start: image_offset, len, tag:
/// image_offset }`. Allocated / overwritten / unknown runs — and zero-length
/// runs — are skipped, so only unallocated space is ever handed to a carver
/// (fleet ADR 0001 §4). A per-run stream error is skipped (best-effort), so one
/// bad run never aborts the sweep; if the volume cannot produce an extent stream
/// at all the result is simply empty (a per-source capability miss — the volume
/// was already opened successfully upstream, so this is not a bootstrap failure).
#[must_use]
pub fn unallocated_regions(fs: &dyn FileSystem) -> Vec<Region<RegionTag>> {
    let Ok(stream) = fs.unallocated() else {
        return Vec::new();
    };
    stream
        .filter_map(Result::ok)
        .filter(|ri| ri.alloc == RunAlloc::Unallocated && ri.run.len > 0)
        .map(|ri| Region {
            start: ri.run.image_offset,
            len: ri.run.len,
            tag: ri.run.image_offset,
        })
        .collect()
}

/// Carve a disk source's unallocated space into timeline events (disk MVP).
///
/// The orchestration entry point for the disk leg: enumerates `fs`'s unallocated
/// extents ([`unallocated_regions`]), adapts `datasource` via
/// [`DataSourceRegionSource`], and runs the injected `carvers` over exactly those
/// extents ([`carve_unallocated`]). Allocated space is never swept.
///
/// `carvers` are injected (not read from [`forensic_carve::registered_carvers`]
/// here) for the same reason [`carve_unallocated`] injects them — the seam stays
/// free of the carver fleet and is unit-testable with a mock carver. The
/// orchestrator (`issen-cli`, which force-links the carver crates) passes
/// `&forensic_carve::registered_carvers()`.
///
/// Returns the carved artifacts as [`TimelineEvent`]s stamped with the carve
/// provenance and `evidence_source_id`; an empty vec when the volume exposes no
/// unallocated extents (or no carver fires).
#[must_use]
pub fn carve_disk_source(
    datasource: &dyn DataSource,
    fs: &dyn FileSystem,
    carvers: &[&dyn Carver],
    evidence_source_id: &str,
    base_offset: u64,
) -> Vec<TimelineEvent> {
    let mut regions = unallocated_regions(fs);
    if regions.is_empty() {
        return Vec::new();
    }
    // `fs.unallocated()` reports extents relative to the filesystem's own start.
    // The filesystem sits at `base_offset` within the whole-disk `datasource`
    // (its MBR/GPT partition offset), so translate every extent to an absolute
    // disk offset — otherwise the sweep reads the wrong bytes (and events would
    // carry filesystem-relative, not absolute, offsets). `base_offset` is 0 for a
    // bare, partition-less filesystem image.
    for r in &mut regions {
        r.start = r.start.saturating_add(base_offset);
        r.tag = r.start;
    }
    let source = DataSourceRegionSource(datasource);
    carve_unallocated(&source, regions, carvers, evidence_source_id)
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

    // --- Unallocated-extent enumeration + disk-source carve (fleet ADR 0001 §4) ---

    use forensic_vfs::{
        ByteRun, DirStream, ExtentStream, FileId, FileSystem, FsKind, FsMeta, NodeStream, RunAlloc,
        RunFlags, RunInfo, SectorSizes, StreamId, TimeZonePolicy, VfsResult,
    };

    /// Build one `RunInfo` at an absolute image offset with an allocation status.
    fn run(offset: u64, len: u64, alloc: RunAlloc) -> RunInfo {
        RunInfo {
            run: ByteRun {
                image_offset: offset,
                len,
                flags: RunFlags::default(),
            },
            alloc,
        }
    }

    /// A `forensic_vfs::FileSystem` whose only exercised surface is
    /// `unallocated()` — every other method is unreachable, because the carve
    /// seam navigates a volume solely by its unallocated extents.
    struct MockFs {
        runs: Vec<RunInfo>,
    }

    impl FileSystem for MockFs {
        fn kind(&self) -> FsKind {
            unreachable!("carve reaches only unallocated()")
        }
        fn root(&self) -> FileId {
            unreachable!("carve reaches only unallocated()")
        }
        fn sector_sizes(&self) -> SectorSizes {
            unreachable!("carve reaches only unallocated()")
        }
        fn timestamp_zone(&self) -> TimeZonePolicy {
            unreachable!("carve reaches only unallocated()")
        }
        fn read_dir(&self, _ino: FileId) -> VfsResult<DirStream> {
            unreachable!("carve reaches only unallocated()")
        }
        fn extents(&self, _ino: FileId, _stream: StreamId) -> VfsResult<ExtentStream> {
            unreachable!("carve reaches only unallocated()")
        }
        fn lookup(&self, _parent: FileId, _name: &[u8]) -> VfsResult<Option<FileId>> {
            unreachable!("carve reaches only unallocated()")
        }
        fn meta(&self, _ino: FileId) -> VfsResult<FsMeta> {
            unreachable!("carve reaches only unallocated()")
        }
        fn read_at(
            &self,
            _ino: FileId,
            _stream: StreamId,
            _off: u64,
            _buf: &mut [u8],
        ) -> VfsResult<usize> {
            unreachable!("carve reaches only unallocated()")
        }
        fn read_link(&self, _ino: FileId, _cap: usize) -> VfsResult<Vec<u8>> {
            unreachable!("carve reaches only unallocated()")
        }
        fn deleted(&self) -> VfsResult<NodeStream> {
            unreachable!("carve reaches only unallocated()")
        }
        fn unallocated(&self) -> VfsResult<ExtentStream> {
            let runs = self.runs.clone();
            Ok(ExtentStream::new(runs.into_iter().map(Ok)))
        }
    }

    #[test]
    fn unallocated_regions_maps_only_unallocated_extents() {
        // Two unallocated extents plus an allocated one and a zero-length one:
        // only the two non-empty unallocated runs become carve Regions.
        let fs = MockFs {
            runs: vec![
                run(1_000, 4_096, RunAlloc::Unallocated),
                run(9_000, 512, RunAlloc::Allocated), // allocated → skipped
                run(20_480, 8_192, RunAlloc::Unallocated),
                run(50_000, 0, RunAlloc::Unallocated), // empty → skipped
            ],
        };
        let regions = unallocated_regions(&fs);
        assert_eq!(regions.len(), 2, "two non-empty unallocated extents");
        assert_eq!(regions[0].start, 1_000, "first extent absolute offset");
        assert_eq!(regions[0].len, 4_096);
        assert_eq!(
            regions[0].tag, 1_000,
            "tag carries the source-extent offset"
        );
        assert_eq!(regions[1].start, 20_480, "second extent absolute offset");
        assert_eq!(regions[1].len, 8_192);
    }

    #[test]
    fn carve_disk_source_carves_only_the_unallocated_extent() {
        // A magic-bearing artifact sits in an UNALLOCATED extent (0..128) and an
        // identical one sits in an ALLOCATED extent (256..400). Only the former
        // is swept, so exactly one event is produced, anchored at the
        // unallocated hit — allocated space is never carved.
        let mut image = vec![0u8; 512];
        image[64..64 + MOCK_MAGIC.len()].copy_from_slice(MOCK_MAGIC); // unallocated
        image[300..300 + MOCK_MAGIC.len()].copy_from_slice(MOCK_MAGIC); // allocated
        let ds = MemSource(image);
        let fs = MockFs {
            runs: vec![
                run(0, 128, RunAlloc::Unallocated),
                run(256, 144, RunAlloc::Allocated),
            ],
        };
        let carver = MockCarver;
        let carvers: Vec<&dyn Carver> = vec![&carver];

        let events = carve_disk_source(&ds, &fs, &carvers, "img-1", 0);
        assert_eq!(events.len(), 1, "only the unallocated magic is carved");
        let e = &events[0];
        assert!(
            e.artifact_path.contains("@64"),
            "carved from the unallocated extent: {}",
            e.artifact_path
        );
        assert!(
            !e.artifact_path.contains("@300"),
            "allocated-space magic must never be carved: {}",
            e.artifact_path
        );
        assert!(
            e.tags.iter().any(|t| t == "recovery:unallocated-carve"),
            "recovery method tagged: {:?}",
            e.tags
        );
        assert_eq!(e.evidence_source_id, "img-1");
    }
}
