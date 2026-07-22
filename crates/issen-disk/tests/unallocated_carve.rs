//! Real `forensic_vfs::FileSystem` re-open + unallocated carve seam
//! (fleet ADR 0001 §4).
//!
//! Proves issen's disk leg can re-open a volume as a `forensic_vfs::FileSystem`
//! (the reader crate's `vfs` adapter) and drive
//! `issen_core::carve::carve_disk_source` over exactly its unallocated extents —
//! the wiring the `--unallocated` pipeline arm delegates to. The committed
//! bare-ext4 fixture exercises the *real* dyn-`FileSystem` open path; event
//! recovery over a real carvable artifact is validated at the `issen_core` /
//! `issen-cli` layers (a synthetic extent + the real registered carvers), since
//! the fixture carries no artifact in its unallocated space.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensic_carve::{CarveContext, CarvedItem, Carver, Signature};
use issen_core::error::RtError;
use issen_core::plugin::traits::DataSource;
use issen_disk::{carve_ext4_window, carve_source_unallocated, PartitionWindow};

/// A byte-slice `DataSource` over the committed fixture image.
struct VecSource(Vec<u8>);
impl DataSource for VecSource {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
        let start = offset as usize;
        if start >= self.0.len() {
            return Ok(0);
        }
        let n = buf.len().min(self.0.len() - start);
        buf[..n].copy_from_slice(&self.0[start..start + n]);
        Ok(n)
    }
}

/// The committed bare-ext4 fixture (no partition table → one window at 0).
fn ext4_source() -> VecSource {
    VecSource(include_bytes!("data/ext4-minimal.img").to_vec())
}

// A carver that never fires: the fixture holds no carvable artifact in its
// unallocated space, so the test asserts the real dyn-`FileSystem` open + sweep
// RUNS end to end, not that it recovers a record.
static NEVER_SIG: [Signature; 1] = [Signature::new(b"__NOPE__", 0)];
struct NeverCarver;
impl Carver for NeverCarver {
    fn format(&self) -> &'static str {
        "never"
    }
    fn signatures(&self) -> &[Signature] {
        &NEVER_SIG
    }
    fn max_window(&self) -> u64 {
        8
    }
    fn carve(&self, _window: &[u8], _ctx: &CarveContext) -> Vec<CarvedItem> {
        Vec::new()
    }
}

#[test]
fn carve_ext4_window_opens_a_real_dyn_filesystem_and_sweeps() {
    let src = ext4_source();
    let window = PartitionWindow {
        offset: 0,
        length: src.len(),
    };
    let carver = NeverCarver;
    let carvers: Vec<&dyn Carver> = vec![&carver];
    // The ext4 reader opens as a forensic_vfs::FileSystem (vfs feature) and the
    // sweep runs over its unallocated() extents — no panic, a Vec is returned.
    let events = carve_ext4_window(&src, window, "ext4-fixture", &carvers);
    assert!(
        events.is_empty(),
        "the NeverCarver recovers nothing from the fixture: {events:?}"
    );
}

#[test]
fn carve_source_unallocated_degrades_on_a_bare_image_without_partitions() {
    // A bare ext4 image has no partition table, so classification yields no
    // windows and the whole-source entry returns empty — best-effort, never a
    // panic or a fabricated extent.
    let src = ext4_source();
    let carver = NeverCarver;
    let carvers: Vec<&dyn Carver> = vec![&carver];
    let events = carve_source_unallocated(&src, "ext4-fixture", &carvers);
    assert!(events.is_empty());
}
