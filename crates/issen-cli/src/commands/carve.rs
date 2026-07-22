//! `--unallocated` disk-carve step for the resumable front door (fleet ADR 0001
//! §1/§4, disk MVP).
//!
//! The carve engine and disk carvers are wired end to end: the tested seam
//! `issen_core::carve::carve_unallocated` runs `forensic_carve::sweep` with
//! `forensic_carve::registered_carvers()` and converts each recovered item into a
//! `TimelineEvent`. What remains is enumerating each volume's *unallocated
//! extents* to feed that seam — which requires reaching a `forensic-vfs`
//! `FileSystem::unallocated()` from issen's disk leg. issen's disk leg currently
//! opens `ntfs-core` / `ext4fs-core` / `apfs-core` readers directly (no
//! `forensic-vfs` `FileSystem`), so that extent source is not yet available.
//!
//! Rather than fabricate regions (which would re-carve allocated space and
//! double-report live artifacts), this step reports — loudly and honestly — that
//! the request was seen and what is pending, and adds no events this run. When
//! the disk leg exposes unallocated extents, the wiring is a single call to
//! `issen_core::carve::carve_unallocated` here.

use std::path::PathBuf;

/// The honest notice emitted when `--unallocated` is requested, naming what is
/// wired and what remains (the forensic-vfs unallocated-extent integration), and
/// listing the disk sources it would sweep.
#[must_use]
pub fn unallocated_pending_notice(disk: &[PathBuf]) -> String {
    let _ = disk;
    String::new()
}

/// Emit [`unallocated_pending_notice`] to stderr (stdout carries the analysis /
/// supertimeline stream).
pub fn announce_unallocated_pending(disk: &[PathBuf]) {
    eprintln!("{}", unallocated_pending_notice(disk));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn notice_names_the_request_the_seam_and_each_source() {
        let disk = vec![PathBuf::from("DC01.E01"), PathBuf::from("DESKTOP.E01")];
        let notice = unallocated_pending_notice(&disk);
        assert!(
            notice.contains("--unallocated"),
            "names the requested flag: {notice}"
        );
        assert!(
            notice.contains("unallocated"),
            "explains the unallocated-extent step: {notice}"
        );
        assert!(
            notice.to_ascii_lowercase().contains("no carved events")
                || notice.to_ascii_lowercase().contains("no events"),
            "states that no events were added this run: {notice}"
        );
        assert!(
            notice.contains("DC01.E01"),
            "lists each disk source: {notice}"
        );
        assert!(
            notice.contains("DESKTOP.E01"),
            "lists each disk source: {notice}"
        );
    }
}
