//! `--unallocated` disk-carve step for the resumable front door (fleet ADR 0001
//! §1/§4, disk MVP).
//!
//! After normal ingest, this step re-opens each disk source as a `DataSource`,
//! re-opens every recognized volume inside it as a `forensic_vfs::FileSystem`
//! (`issen_disk::carve_source_unallocated`), and runs
//! `forensic_carve::registered_carvers()` (sqlite / evtx-chunk / registry-hive)
//! over exactly its *unallocated* extents — never allocated space, so a live
//! artifact is never double-reported. Each recovered item becomes a
//! `TimelineEvent` tagged `recovery:unallocated-carve`, which the caller inserts
//! into the case timeline.
//!
//! Re-opening the source for this opt-in pass (rather than threading a handle
//! through the whole disk-collection path) keeps the change local: the disk leg
//! opens readers transiently during ingest, and the carve pass simply asks for
//! them again.
//!
//! Current source coverage: the retained-`DataSource` opener that exists for an
//! arbitrary path is the raw-file one (`FileDataSource`), so raw/dd images and
//! bare filesystems are swept directly. Container-decoded sources (E01 / VMDK /
//! AFF4) need `issen-unpack` to expose a retained `Box<dyn DataSource>` from its
//! providers (today they open→extract→drop); that seam is the follow-up needed
//! to sweep a zipped/EWF image's unallocated space here.

use std::path::PathBuf;

use issen_core::timeline::event::TimelineEvent;
use issen_fswalker::layers::layer0_storage::FileDataSource;

/// Carve the unallocated space of every disk source into timeline events.
///
/// For each `disk` path: open it as a [`FileDataSource`], then hand it to
/// [`issen_disk::carve_source_unallocated`] with the force-linked
/// [`forensic_carve::registered_carvers`]. A source that cannot be opened is a
/// best-effort skip (stderr note), never a panic — mirroring the per-partition
/// degrade the disk collectors already use. The evidence-source id is the
/// source's file name, tying each carved event back to the image it came from.
#[must_use]
pub fn carve_disk_sources_unallocated(disk: &[PathBuf]) -> Vec<TimelineEvent> {
    let registered = forensic_carve::registered_carvers();
    let carvers: Vec<&dyn forensic_carve::Carver> = registered
        .iter()
        .map(|c| *c as &dyn forensic_carve::Carver)
        .collect();

    let mut events = Vec::new();
    for path in disk {
        let source = match FileDataSource::open(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "Warning: --unallocated could not open {} as a data source: {e}",
                    path.display()
                );
                continue;
            }
        };
        let evidence_id = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("disk")
            .to_string();
        events.extend(issen_disk::carve_source_unallocated(
            &source,
            &evidence_id,
            &carvers,
        ));
    }
    events
}

/// The one-line banner emitted to stderr when `--unallocated` begins its sweep,
/// naming the sources it will carve (stdout carries the analysis stream).
#[must_use]
pub fn unallocated_sweep_banner(disk: &[PathBuf]) -> String {
    let mut out = String::from(
        "issen: --unallocated — sweeping unallocated disk space with the \
         registered carvers (sqlite / evtx-chunk / registry-hive):\n",
    );
    for path in disk {
        out.push_str(&format!("    - {}\n", path.display()));
    }
    out
}

/// Emit [`unallocated_sweep_banner`] to stderr.
pub fn announce_unallocated_sweep(disk: &[PathBuf]) {
    eprintln!("{}", unallocated_sweep_banner(disk));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn banner_names_the_request_and_each_source() {
        let disk = vec![PathBuf::from("DC01.E01"), PathBuf::from("DESKTOP.E01")];
        let banner = unallocated_sweep_banner(&disk);
        assert!(banner.contains("--unallocated"));
        assert!(banner.contains("unallocated"));
        assert!(banner.contains("DC01.E01"));
        assert!(banner.contains("DESKTOP.E01"));
    }

    #[test]
    fn carve_disk_sources_unallocated_degrades_on_unopenable_paths() {
        // A path that cannot be opened as a DataSource is a best-effort skip:
        // an empty result, never a panic or a fabricated extent.
        let events = carve_disk_sources_unallocated(&[PathBuf::from(
            "/nonexistent/issen-no-such-image.E01",
        )]);
        assert!(events.is_empty(), "unopenable source yields no events");
    }

    // ── Real carvers fire through the seam on a synthetic unallocated extent ──
    //
    // Proves the carve seam + the FORCE-LINKED registered carvers recover a real
    // artifact from unallocated space: a minimal SQLite database placed inside a
    // synthetic volume's single unallocated extent yields one carved event. This
    // is the event-production evidence the live pipeline cannot yet supply on a
    // real image, because the published reader crates' `unallocated()` still
    // return an empty extent stream (the bitmap-backed impls are committed but
    // unpublished — pending a ntfs-core 0.9.6 / ext4fs-core 0.2.6 / apfs-core
    // 0.2.6 release). It drives `carve_disk_source` directly with a synthetic
    // `forensic_vfs::FileSystem` so the assertion does not depend on that.

    use forensic_vfs::{
        ByteRun, DirStream, ExtentStream, FileId, FileSystem, FsKind, FsMeta, NodeStream, RunAlloc,
        RunFlags, RunInfo, SectorSizes, StreamId, TimeZonePolicy, VfsResult,
    };
    use issen_core::error::RtError;
    use issen_core::plugin::traits::DataSource;

    /// Build a minimal, structurally valid SQLite image (100-byte header
    /// declaring `page_size` × `page_count`, zero-padded to that length).
    fn build_min_db(page_size: u32, page_count: u32) -> Vec<u8> {
        let total = (page_size as usize) * (page_count as usize);
        let mut db = vec![0u8; total];
        db[..16].copy_from_slice(b"SQLite format 3\0");
        let raw: u16 = if page_size == 65536 {
            1
        } else {
            u16::try_from(page_size).unwrap()
        };
        db[16..18].copy_from_slice(&raw.to_be_bytes());
        db[20] = 0;
        db[28..32].copy_from_slice(&page_count.to_be_bytes());
        db[56..60].copy_from_slice(&1u32.to_be_bytes());
        db
    }

    /// In-memory image `DataSource` with a SQLite DB embedded at `db_offset`.
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

    /// A `forensic_vfs::FileSystem` exposing a single unallocated extent; every
    /// other navigation method is unreachable (the carve seam reaches only
    /// `unallocated()`).
    struct OneExtentFs {
        run: RunInfo,
    }
    impl FileSystem for OneExtentFs {
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
            Ok(ExtentStream::new(std::iter::once(Ok(self.run))))
        }
    }

    #[test]
    fn registered_carvers_recover_a_sqlite_db_from_a_synthetic_unallocated_extent() {
        // The whole 8 KiB image is one unallocated extent; a minimal SQLite DB
        // sits at offset 4096 within it.
        let db = build_min_db(512, 2);
        let db_off = 4096usize;
        let mut image = vec![0u8; db_off];
        image.extend_from_slice(&db);
        image.extend(std::iter::repeat_n(0u8, 256));
        let ds = MemSource(image.clone());
        let fs = OneExtentFs {
            run: RunInfo {
                run: ByteRun {
                    image_offset: 0,
                    len: image.len() as u64,
                    flags: RunFlags::default(),
                },
                alloc: RunAlloc::Unallocated,
            },
        };

        let registered = forensic_carve::registered_carvers();
        assert!(
            registered.iter().any(|c| c.format() == "sqlite"),
            "the sqlite carver must be force-linked: {:?}",
            registered.iter().map(|c| c.format()).collect::<Vec<_>>()
        );
        let carvers: Vec<&dyn forensic_carve::Carver> = registered
            .iter()
            .map(|c| *c as &dyn forensic_carve::Carver)
            .collect();

        let events = issen_core::carve::carve_disk_source(&ds, &fs, &carvers, "synthetic");

        assert!(
            events.iter().any(|e| {
                e.tags.iter().any(|t| t == "recovery:unallocated-carve")
                    && e.tags.iter().any(|t| t == "format:sqlite")
            }),
            "the SQLite DB in the unallocated extent is carved and tagged: {:?}",
            events.iter().map(|e| &e.tags).collect::<Vec<_>>()
        );
        let sqlite = events
            .iter()
            .find(|e| e.tags.iter().any(|t| t == "format:sqlite"))
            .expect("a carved sqlite event");
        assert!(
            sqlite.artifact_path.contains("@4096"),
            "carved at the DB's absolute offset: {}",
            sqlite.artifact_path
        );
        assert_eq!(sqlite.evidence_source_id, "synthetic");
    }
}
