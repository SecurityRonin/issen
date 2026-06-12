//! ★`CORR-PROC-MIGRATION` (Tier C′, plan v5 §7.2).
//!
//! Process migration: an adversary spawns under one process, injects into a
//! second live process, and lets the first die — the dead husk and the new host
//! both reaching the same C2. The strong form joins three observations from a
//! single dump:
//!
//! 1. a **dead-and-orphaned** process — a `ProcessExec` row with
//!    `thread_count == 0` *and* a `ppid` absent from the dump's process set;
//! 2. a `MemoryInjection` on a **different, live** PID (a `ProcessExec` row for
//!    that PID with `thread_count > 0`);
//! 3. `NetworkConnect` rows tying **both** PIDs to the **same remote endpoint**
//!    (remote-address equality) — the precision guard that the dead process
//!    *itself* held (or held, via a pool-scanned freed socket) a connection to
//!    the shared endpoint, not merely a name link.
//!
//! All rows must come from one dump (`SameDump`). ATT&CK: T1055 — consistent
//! with, never a verdict.
//!
//! ### Degraded form (recorded at lower confidence)
//!
//! When the dump yields no freed-socket row for the dead PID (so clause 3's
//! dead-PID leg is missing), the rule falls back to: the live injected PID holds
//! the shared endpoint *and* the dead PID is name-linked to the same image stem.
//! This weaker shape is emitted as a distinct `code` so a reader never confuses
//! it with the strong form (§7.2 "with the weaker form recorded in the finding's
//! confidence").

use std::collections::BTreeSet;

use forensicnomicon::report::Severity;

use crate::correlation::{Correlation, CorrelationMember, CorrelationRole, CorrelationScope};

use super::{
    MemEvent, MEMORY_INJECTION_EVENT_TYPE, NETWORK_CONNECT_EVENT_TYPE, PROCESS_EXEC_EVENT_TYPE,
};
use crate::tier_a::stem;

/// Examiner-facing note — an observation, never a verdict.
pub const PROC_MIGRATION_NOTE: &str =
    "A dead, orphaned process and an injected live process tied to the same remote \
     endpoint within one dump are consistent with process migration (T1055).";

/// Examiner-facing note for the degraded form (no freed-socket row for the dead
/// PID) — observation, never a verdict; lower confidence is implied by the code.
pub const PROC_MIGRATION_DEGRADED_NOTE: &str =
    "An injected live process holding a remote endpoint while a same-named dead, \
     orphaned process is present (without a recovered socket for the dead process) \
     is consistent with process migration on weaker evidence (T1055).";

/// A `ProcessExec` row's process identity for the dead-orphan / live checks.
#[derive(Debug, Clone, Copy)]
struct ProcRow<'a> {
    ev: &'a MemEvent,
    pid: u32,
    ppid: u32,
    thread_count: u32,
}

/// The remote-IP endpoint a netstat row reaches, if any.
fn remote_endpoint(conn: &MemEvent) -> Option<&str> {
    conn.ip_subjects().next()
}

/// Collect the `ProcessExec` rows that carry pid/ppid/thread_count, scoped to one
/// dump (host label).
fn proc_rows<'a>(events: &'a [MemEvent], host: &Option<String>) -> Vec<ProcRow<'a>> {
    events
        .iter()
        .filter(|e| e.event_type == PROCESS_EXEC_EVENT_TYPE && &e.hostname == host)
        .filter_map(|e| {
            Some(ProcRow {
                ev: e,
                pid: e.pid?,
                ppid: e.ppid?,
                thread_count: e.thread_count?,
            })
        })
        .collect()
}

/// Find a `NetworkConnect` row in `host`'s dump owned by `pid` reaching
/// `endpoint`.
fn conn_for<'a>(
    events: &'a [MemEvent],
    host: &Option<String>,
    pid: u32,
    endpoint: &str,
) -> Option<&'a MemEvent> {
    events.iter().find(|e| {
        e.event_type == NETWORK_CONNECT_EVENT_TYPE
            && &e.hostname == host
            && e.pid == Some(pid)
            && remote_endpoint(e) == Some(endpoint)
    })
}

/// Match process-migration chains. Returns one [`Correlation`] per dead-orphan ↔
/// injected-live ↔ shared-endpoint chain found within a single dump (strong
/// form), or the degraded form when no freed socket ties the dead PID to the
/// endpoint but the dead PID is name-linked to the injected image stem.
#[must_use]
pub fn proc_migration_chains(events: &[MemEvent]) -> Vec<Correlation> {
    // RED stub — replaced by the real matcher in the GREEN commit.
    let _ = events;
    Vec::new()
}

/// `true` when the dead process and the injection name the same image stem
/// (lowercased, extension dropped) — the degraded form's name link.
fn same_image_stem(dead: &MemEvent, inj: &MemEvent) -> bool {
    let dead_stem = dead.process_subjects().next().map(|s| stem(s).to_ascii_lowercase());
    let inj_stem = inj.process_subjects().next().map(|s| stem(s).to_ascii_lowercase());
    matches!((dead_stem, inj_stem), (Some(a), Some(b)) if a == b)
}

/// Build the strong-form correlation (dead anchor, injection consequent, both
/// connections supporting).
fn strong_chain(
    dead: &MemEvent,
    inj: &MemEvent,
    live_conn: &MemEvent,
    dead_conn: &MemEvent,
) -> Correlation {
    let stamps = [
        dead.timestamp_ns,
        inj.timestamp_ns,
        live_conn.timestamp_ns,
        dead_conn.timestamp_ns,
    ];
    let first = stamps.iter().copied().min().unwrap_or(0);
    let last = stamps.iter().copied().max().unwrap_or(0);
    Correlation::new("CORR-PROC-MIGRATION", Severity::Critical)
        .with_attack_technique("T1055")
        .with_scope(CorrelationScope::SameDump)
        .with_window(first, last)
        .with_note(PROC_MIGRATION_NOTE)
        .with_member(CorrelationMember::new(dead.id, CorrelationRole::Anchor))
        .with_member(CorrelationMember::new(inj.id, CorrelationRole::Consequent))
        .with_member(CorrelationMember::new(dead_conn.id, CorrelationRole::Supporting))
        .with_member(CorrelationMember::new(live_conn.id, CorrelationRole::Supporting))
}

/// Build the degraded-form correlation (dead anchor, injection consequent, the
/// live connection supporting; no dead-PID socket).
fn degraded_chain(dead: &MemEvent, inj: &MemEvent, live_conn: &MemEvent) -> Correlation {
    let stamps = [dead.timestamp_ns, inj.timestamp_ns, live_conn.timestamp_ns];
    let first = stamps.iter().copied().min().unwrap_or(0);
    let last = stamps.iter().copied().max().unwrap_or(0);
    Correlation::new("CORR-PROC-MIGRATION-DEGRADED", Severity::High)
        .with_attack_technique("T1055")
        .with_scope(CorrelationScope::SameDump)
        .with_window(first, last)
        .with_note(PROC_MIGRATION_DEGRADED_NOTE)
        .with_member(CorrelationMember::new(dead.id, CorrelationRole::Anchor))
        .with_member(CorrelationMember::new(inj.id, CorrelationRole::Consequent))
        .with_member(CorrelationMember::new(live_conn.id, CorrelationRole::Supporting))
}

#[cfg(test)]
mod tests {
    use super::*;
    use issen_core::timeline::event::EntityRef;

    use super::super::ESTABLISHED_STATE;

    const DUMP: &str = "DUMP-A";
    const C2: &str = "203.78.103.109";

    fn proc(id: u64, image: &str, pid: u32, ppid: u32, threads: u32) -> MemEvent {
        MemEvent::new(id, 1_000, PROCESS_EXEC_EVENT_TYPE, DUMP)
            .with_entity(EntityRef::Process(image.to_string()))
            .with_pid(pid)
            .with_ppid(ppid)
            .with_thread_count(threads)
    }

    fn injection(id: u64, image: &str, pid: u32) -> MemEvent {
        MemEvent::new(id, 1_000, MEMORY_INJECTION_EVENT_TYPE, DUMP)
            .with_entity(EntityRef::Process(image.to_string()))
            .with_pid(pid)
            .with_injection("injected-PE")
    }

    fn conn(id: u64, image: &str, pid: u32, remote: &str) -> MemEvent {
        MemEvent::new(id, 1_000, NETWORK_CONNECT_EVENT_TYPE, DUMP)
            .with_entity(EntityRef::Process(image.to_string()))
            .with_entity(EntityRef::Ip(remote.to_string()))
            .with_pid(pid)
            .with_state(ESTABLISHED_STATE)
    }

    /// The strong-form migration fixture: coreupdater (pid 3644, dead+orphaned,
    /// parent 4 absent from the dump) holds a freed socket to the C2, and
    /// spoolsv (pid 880, live, injected) holds an ESTABLISHED socket to the same
    /// C2.
    fn strong_fixture() -> Vec<MemEvent> {
        vec![
            proc(1, "coreupdater.exe", 3644, 4, 0), // dead orphan (ppid 4 absent)
            proc(2, "spoolsv.exe", 880, 760, 8),    // live host (ppid 760 also absent — fine)
            proc(3, "services.exe", 760, 4, 6),     // makes 760 present so spoolsv is not orphan
            injection(4, "spoolsv.exe", 880),
            conn(5, "spoolsv.exe", 880, C2),         // live PID → C2
            conn(6, "coreupdater.exe", 3644, C2),    // dead PID → same C2 (freed socket)
        ]
    }

    #[test]
    fn fires_for_dead_orphan_injected_live_sharing_an_endpoint() {
        let corrs = proc_migration_chains(&strong_fixture());
        assert_eq!(corrs.len(), 1);
        let c = &corrs[0];
        assert_eq!(c.code, "CORR-PROC-MIGRATION");
        assert_eq!(c.attack_technique.as_deref(), Some("T1055"));
        assert_eq!(c.severity, Severity::Critical);
        assert_eq!(c.scope, CorrelationScope::SameDump);
        // dead anchor, injection consequent, two supporting connections.
        assert_eq!(c.members.len(), 4);
        assert_eq!(c.members[0].timeline_id, 1);
        assert_eq!(c.members[0].role, CorrelationRole::Anchor);
        assert_eq!(c.members[1].timeline_id, 4);
        assert_eq!(c.members[1].role, CorrelationRole::Consequent);
        assert!(c.note.contains("consistent with"));
    }

    // ── The three §7.2 negative controls ─────────────────────────────────────

    #[test]
    fn negative_injected_process_with_no_shared_endpoint() {
        // The live injected spoolsv reaches the C2, but the dead orphan reaches a
        // *different* endpoint — no shared endpoint, and not name-linked.
        let mut events = strong_fixture();
        // Repoint the dead PID's connection to a different endpoint.
        events[5] = conn(6, "coreupdater.exe", 3644, "8.8.8.8");
        assert!(proc_migration_chains(&events).is_empty());
    }

    #[test]
    fn negative_dead_orphan_with_no_injection_elsewhere() {
        // A dead orphan sharing an endpoint with a live process, but that live
        // process is NOT injected — no migration.
        let events = vec![
            proc(1, "coreupdater.exe", 3644, 4, 0), // dead orphan
            proc(2, "spoolsv.exe", 880, 760, 8),    // live, NOT injected
            proc(3, "services.exe", 760, 4, 6),
            conn(5, "spoolsv.exe", 880, C2),
            conn(6, "coreupdater.exe", 3644, C2),
        ];
        assert!(proc_migration_chains(&events).is_empty());
    }

    #[test]
    fn negative_two_healthy_live_processes_sharing_an_endpoint() {
        // Two healthy (thread_count > 0) processes both connected to one server
        // (a connection pool) — neither is dead/orphaned, so no migration even
        // though an injection sits on one of them.
        let events = vec![
            proc(1, "app.exe", 100, 760, 5),  // live
            proc(2, "app2.exe", 200, 760, 5), // live
            proc(3, "services.exe", 760, 4, 6),
            injection(4, "app.exe", 100),
            conn(5, "app.exe", 100, C2),
            conn(6, "app2.exe", 200, C2),
        ];
        assert!(proc_migration_chains(&events).is_empty());
    }

    // ── Degraded form ────────────────────────────────────────────────────────

    #[test]
    fn degraded_form_fires_when_no_freed_socket_but_name_linked() {
        // No connection row exists for the dead PID (freed socket not recovered),
        // but the dead process shares the injected image stem and the live PID
        // holds the endpoint — the degraded form fires under a distinct code.
        let mut events = strong_fixture();
        events.remove(5); // drop the dead-PID connection (freed socket absent)
        // Rename the dead orphan to share the injected stem (coreupdater vs spoolsv
        // -> make the dead one also spoolsv-stemmed for the name link).
        events[0] = proc(1, "spoolsv.exe", 3644, 4, 0);
        let corrs = proc_migration_chains(&events);
        assert_eq!(corrs.len(), 1);
        assert_eq!(corrs[0].code, "CORR-PROC-MIGRATION-DEGRADED");
        assert_eq!(corrs[0].severity, Severity::High);
        assert_eq!(corrs[0].members.len(), 3);
        assert!(corrs[0].note.contains("consistent with"));
    }
}
