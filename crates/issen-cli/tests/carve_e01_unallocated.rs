//! End-to-end: `--unallocated` carves a SQLite DB from an E01's unallocated
//! space, routed through the fleet container abstraction (fleet ADR 0001 §4).
//!
//! Fixture `mbr-ext4-sqlite-unalloc.E01` is an EWF/E01 image of an MBR disk with
//! an ext4 partition (at a non-zero partition offset) whose unallocated space
//! holds a `SQLite format 3\0` database. This exercises the whole chain the
//! synthetic tests can't: container decode (E01 → sectors) + partition-offset
//! translation (FS-relative unallocated extents → absolute disk offsets) + the
//! real force-linked carvers.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use issen_core::plugin::traits::DataSource;
use std::io::Write;

const E01: &[u8] = include_bytes!("data/mbr-ext4-sqlite-unalloc.E01");

#[test]
fn e01_unallocated_space_carves_a_sqlite_db_via_container_abstraction() {
    let mut tf = tempfile::Builder::new().suffix(".E01").tempfile().unwrap();
    tf.write_all(E01).unwrap();
    let path = tf.path().to_path_buf();

    // The container adapter decodes the E01 to sectors — not the raw EWF bytes.
    let ds = issen_disk::open_container_source(&path).unwrap();
    let mut magic = [0u8; 3];
    ds.read_at(0, &mut magic).unwrap();
    assert_ne!(
        &magic, b"EVF",
        "decoded bytes must not be the EWF container magic"
    );

    // Carve the decoded image's unallocated space with the registered carvers.
    let registered = forensic_carve::registered_carvers();
    let carvers: Vec<&dyn forensic_carve::Carver> = registered.iter().copied().collect();
    let events = issen_disk::carve_source_unallocated(ds.as_ref(), "e01", &carvers);

    assert!(
        events.iter().any(|e| {
            e.tags.iter().any(|t| t == "format:sqlite")
                && e.tags.iter().any(|t| t == "recovery:unallocated-carve")
        }),
        "the SQLite DB in the ext4 partition's unallocated space must be carved \
         (got {} events: {:?})",
        events.len(),
        events.iter().map(|e| &e.tags).collect::<Vec<_>>()
    );
}
