//! `CORR-INJECTED-C2` (Tier C, plan v4 §5.2 / v5 §7.2).
//!
//! A `MemoryInjection` (malfind) finding on a PID **and** an ESTABLISHED
//! `NetworkConnect` to an external [`EntityRef::Ip`] from the **same** process,
//! both observed in one dump: an injected process beaconing to C2. The two rows
//! join on their shared [`EntityRef::Process`] subject under the `SameDump`
//! scope; the netstat row must be ESTABLISHED (a half-open/listening socket is
//! not a beacon) and carry a real remote peer.
//!
//! ATT&CK: T1055 (process injection) + T1071 (application-layer C2) — consistent
//! with, never a verdict.

use forensicnomicon::report::Severity;

use crate::correlation::{Correlation, CorrelationMember, CorrelationRole, CorrelationScope};

use super::{
    MemEvent, ESTABLISHED_STATE, MEMORY_INJECTION_EVENT_TYPE, NETWORK_CONNECT_EVENT_TYPE,
};

/// Examiner-facing note — an observation, never a verdict.
pub const INJECTED_C2_NOTE: &str =
    "An injected memory region in a process paired with an established outbound \
     connection to an external address from that same process is consistent with \
     an injected process beaconing to command-and-control (T1055 / T1071).";

/// `true` when a netstat [`MemEvent`] is an ESTABLISHED connection to a real
/// remote peer (a beacon candidate), not a listening or half-open socket.
fn is_established_external(conn: &MemEvent) -> bool {
    conn.event_type == NETWORK_CONNECT_EVENT_TYPE
        && conn.state.as_deref() == Some(ESTABLISHED_STATE)
        && conn.ip_subjects().next().is_some()
}

/// Pair each `MemoryInjection` event with an ESTABLISHED `NetworkConnect` from
/// the *same* process, within one dump, emitting a [`Correlation`] per pair.
///
/// The injection is the anchor and the connection the consequent. Only memory
/// rows from the same dump (host label) pair, mirroring the `SameDump` scope.
#[must_use]
pub fn injected_c2_pairs(events: &[MemEvent]) -> Vec<Correlation> {
    let injections = events
        .iter()
        .filter(|e| e.event_type == MEMORY_INJECTION_EVENT_TYPE);
    let connections: Vec<&MemEvent> = events.iter().filter(|e| is_established_external(e)).collect();

    let mut out = Vec::new();
    for inj in injections {
        for conn in &connections {
            if inj.hostname != conn.hostname {
                continue;
            }
            if !inj.shares_process(conn) {
                continue;
            }
            let (first, last) = if inj.timestamp_ns <= conn.timestamp_ns {
                (inj.timestamp_ns, conn.timestamp_ns)
            } else {
                (conn.timestamp_ns, inj.timestamp_ns)
            };
            out.push(
                Correlation::new("CORR-INJECTED-C2", Severity::Critical)
                    .with_attack_technique("T1055")
                    .with_scope(CorrelationScope::SameDump)
                    .with_window(first, last)
                    .with_note(INJECTED_C2_NOTE)
                    .with_member(CorrelationMember::new(inj.id, CorrelationRole::Anchor))
                    .with_member(CorrelationMember::new(conn.id, CorrelationRole::Consequent)),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use issen_core::timeline::event::EntityRef;

    use super::super::{MemEvent, PROCESS_EXEC_EVENT_TYPE};

    fn injection(id: u64, proc_name: &str, host: &str) -> MemEvent {
        MemEvent::new(id, 1_000, MEMORY_INJECTION_EVENT_TYPE, host)
            .with_entity(EntityRef::Process(proc_name.to_string()))
            .with_pid(3644)
            .with_injection("injected-PE")
    }

    fn established(id: u64, proc_name: &str, remote: &str, host: &str) -> MemEvent {
        MemEvent::new(id, 1_000, NETWORK_CONNECT_EVENT_TYPE, host)
            .with_entity(EntityRef::Process(proc_name.to_string()))
            .with_entity(EntityRef::Ip(remote.to_string()))
            .with_pid(3644)
            .with_state(ESTABLISHED_STATE)
    }

    #[test]
    fn fires_for_injected_process_beaconing_to_c2() {
        let events = vec![
            injection(1, "spoolsv.exe", "DUMP-A"),
            established(2, "spoolsv.exe", "203.78.103.109", "DUMP-A"),
        ];
        let corrs = injected_c2_pairs(&events);
        assert_eq!(corrs.len(), 1);
        let c = &corrs[0];
        assert_eq!(c.code, "CORR-INJECTED-C2");
        assert_eq!(c.attack_technique.as_deref(), Some("T1055"));
        assert_eq!(c.severity, Severity::Critical);
        assert_eq!(c.scope, CorrelationScope::SameDump);
        assert_eq!(c.members.len(), 2);
        assert_eq!(c.members[0].timeline_id, 1);
        assert_eq!(c.members[0].role, CorrelationRole::Anchor);
        assert_eq!(c.members[1].timeline_id, 2);
        assert_eq!(c.members[1].role, CorrelationRole::Consequent);
        assert!(c.note.contains("consistent with"));
    }

    // ── Negative controls ────────────────────────────────────────────────────

    #[test]
    fn does_not_fire_for_injection_with_no_external_connection() {
        // An injected process that holds only a LISTEN socket (no established
        // outbound peer) is not beaconing.
        let mut listen = established(2, "spoolsv.exe", "0.0.0.0", "DUMP-A");
        listen.state = Some("LISTEN".to_string());
        let events = vec![injection(1, "spoolsv.exe", "DUMP-A"), listen];
        assert!(injected_c2_pairs(&events).is_empty());
    }

    #[test]
    fn does_not_fire_for_external_connection_from_a_non_injected_process() {
        // An ESTABLISHED outbound connection from a process with no injection
        // finding is ordinary network activity.
        let events = vec![
            // A benign process row (not an injection) and its connection.
            MemEvent::new(1, 1_000, PROCESS_EXEC_EVENT_TYPE, "DUMP-A")
                .with_entity(EntityRef::Process("chrome.exe".to_string()))
                .with_pid(900),
            established(2, "chrome.exe", "93.184.216.34", "DUMP-A"),
        ];
        assert!(injected_c2_pairs(&events).is_empty());
    }

    #[test]
    fn does_not_fire_across_different_dumps() {
        // The injection and the connection are in different dumps — SameDump must
        // keep the rule silent.
        let events = vec![
            injection(1, "spoolsv.exe", "DUMP-A"),
            established(2, "spoolsv.exe", "203.78.103.109", "DUMP-B"),
        ];
        assert!(injected_c2_pairs(&events).is_empty());
    }

    #[test]
    fn does_not_fire_when_connection_is_from_a_different_process() {
        // Injection on spoolsv but the established C2 is owned by a different
        // process — no shared Process subject, no pairing.
        let events = vec![
            injection(1, "spoolsv.exe", "DUMP-A"),
            established(2, "evil.exe", "203.78.103.109", "DUMP-A"),
        ];
        assert!(injected_c2_pairs(&events).is_empty());
    }
}
