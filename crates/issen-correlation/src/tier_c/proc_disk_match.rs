//! `CORR-PROC-DISK-MATCH` (Tier C, plan v4 §5.2 / v5 §7.2).
//!
//! A memory `ProcessExec` row and a **disk** `FileCreate` for the **same image
//! name**: the on-disk artifact is (consistent with) the process now resident in
//! memory. The memory row carries the image as an [`EntityRef::Process`]; the
//! disk row carries the file's `artifact_path`. Both are normalized to the image
//! *stem* (lowercased, extension dropped — exactly as Tier-A's
//! [`stem_entity`](crate::tier_a::stem_entity) does) so a create of
//! `C:\…\coreupdater.exe` joins a resident `coreupdater.exe`.
//!
//! The disk leg is *not* a memory event, so the join is cross-leg: the consequent
//! must come from a non-[`EventSource::Memory`] leg (a disk `FileCreate`),
//! distinguishing this from a same-dump memory↔memory rule. ATT&CK: T1055 /
//! T1105 — consistent with, never a verdict.

use forensicnomicon::report::Severity;

use crate::correlation::{Correlation, CorrelationMember, CorrelationRole, CorrelationScope};
use crate::evaluator::{EventSource, EventView};
use crate::tier_a::{stem, stem_entity};

use issen_core::timeline::event::EntityRef;

use super::{MemEvent, FILE_CREATE_EVENT_TYPE, PROCESS_EXEC_EVENT_TYPE};

/// Examiner-facing note — an observation, never a verdict.
pub const PROC_DISK_MATCH_NOTE: &str =
    "A file created on disk and subsequently found running as a live process in a \
     memory dump is consistent with that on-disk artifact having been executed \
     (T1055 / T1105).";

/// The image stem a memory `ProcessExec` row names, via its
/// [`EntityRef::Process`] subject (lowercased, extension dropped). `None` when
/// the row carries no process subject.
fn process_stem(p: &MemEvent) -> Option<EntityRef> {
    p.entity_refs.iter().find_map(|e| match e {
        EntityRef::Process(name) => Some(EntityRef::FilePath(stem(name).to_ascii_lowercase())),
        _ => None,
    })
}

/// Pair each memory `ProcessExec` with a disk `FileCreate` for the same image
/// stem, emitting a [`Correlation`] per pair.
///
/// The memory process is the anchor and the disk create the consequent. The
/// disk leg must be a non-memory `FileCreate`; the join is on the lowercased,
/// extension-stripped image stem.
#[must_use]
pub fn proc_disk_matches<E>(memory: &[MemEvent], disk: &[E]) -> Vec<Correlation>
where
    E: EventView,
{
    let processes = memory
        .iter()
        .filter(|e| e.event_type == PROCESS_EXEC_EVENT_TYPE);
    let creates: Vec<&E> = disk
        .iter()
        .filter(|e| e.event_type() == FILE_CREATE_EVENT_TYPE && e.source() != EventSource::Memory)
        .collect();

    let mut out = Vec::new();
    for proc in processes {
        let Some(proc_stem) = process_stem(proc) else {
            continue;
        };
        for create in &creates {
            if stem_entity(create.artifact_path()) != proc_stem {
                continue;
            }
            let (first, last) = if proc.timestamp_ns <= create.timestamp_ns() {
                (proc.timestamp_ns, create.timestamp_ns())
            } else {
                (create.timestamp_ns(), proc.timestamp_ns)
            };
            out.push(
                Correlation::new("CORR-PROC-DISK-MATCH", Severity::Medium)
                    .with_attack_technique("T1055")
                    .with_scope(CorrelationScope::SameHost)
                    .with_window(first, last)
                    .with_note(PROC_DISK_MATCH_NOTE)
                    .with_member(CorrelationMember::new(proc.id, CorrelationRole::Anchor))
                    .with_member(CorrelationMember::new(
                        create.id(),
                        CorrelationRole::Consequent,
                    )),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use issen_core::timeline::event::EntityRef;

    use super::super::testkit::DiskEvent;
    use super::super::MemEvent;

    fn resident(id: u64, image: &str) -> MemEvent {
        MemEvent::new(id, 1_000, PROCESS_EXEC_EVENT_TYPE, "DUMP-A")
            .with_entity(EntityRef::Process(image.to_string()))
            .with_pid(3644)
    }

    fn disk_create(id: u64, path: &str) -> DiskEvent {
        DiskEvent::new(id, 500, FILE_CREATE_EVENT_TYPE, "DC01", EventSource::Disk).at(path)
    }

    #[test]
    fn fires_when_resident_process_matches_an_on_disk_create() {
        let memory = vec![resident(1, "coreupdater.exe")];
        let disk = vec![disk_create(2, "C:\\Windows\\System32\\CoreUpdater.exe")];
        let corrs = proc_disk_matches(&memory, &disk);
        assert_eq!(corrs.len(), 1);
        let c = &corrs[0];
        assert_eq!(c.code, "CORR-PROC-DISK-MATCH");
        assert_eq!(c.attack_technique.as_deref(), Some("T1055"));
        assert_eq!(c.severity, Severity::Medium);
        assert_eq!(c.members.len(), 2);
        assert_eq!(c.members[0].timeline_id, 1);
        assert_eq!(c.members[0].role, CorrelationRole::Anchor);
        assert_eq!(c.members[1].timeline_id, 2);
        assert_eq!(c.members[1].role, CorrelationRole::Consequent);
        assert!(c.note.contains("consistent with"));
    }

    // ── Negative control ─────────────────────────────────────────────────────

    #[test]
    fn does_not_fire_when_no_disk_file_matches_the_image() {
        // The resident process has no on-disk create of the same image name.
        let memory = vec![resident(1, "coreupdater.exe")];
        let disk = vec![disk_create(2, "C:\\Windows\\System32\\svchost.exe")];
        assert!(proc_disk_matches(&memory, &disk).is_empty());
    }

    #[test]
    fn does_not_fire_when_the_create_is_itself_a_memory_event() {
        // A FileCreate that is mis-sourced as a memory leg is not a disk artifact;
        // the source!=Memory guard keeps the rule silent (no double-counting the
        // memory leg as its own disk corroboration).
        let memory = vec![resident(1, "coreupdater.exe")];
        let mem_create = DiskEvent::new(
            2,
            500,
            FILE_CREATE_EVENT_TYPE,
            "DUMP-A",
            EventSource::Memory,
        )
        .at("C:\\Windows\\System32\\coreupdater.exe");
        assert!(proc_disk_matches(&memory, &[mem_create]).is_empty());
    }
}
