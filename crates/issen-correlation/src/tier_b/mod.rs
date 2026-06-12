//! Tier-B correlation rules (capstone task #37, plan v4 §5.2 / v5 §7.2).
//!
//! Three EVTX/disk-spanning rules that model the adversary's *interactive*
//! phase — brute-force entry, the access that dropped the payload, and the
//! staging of loot for exfiltration. They are built on the Part-A enhanced
//! ordered-window [`evaluate`](crate::evaluator::evaluate) engine:
//!
//! - **`CORR-BRUTEFORCE-LOGON`** — a 4625 failed-logon burst (already
//!   identified upstream and passed as the anchor) followed by a 4624 success
//!   from the *same source IP*, joined on [`EntityRef::Ip`]. Pure ordered-window
//!   shape, no guard needed. ATT&CK T1110.
//! - **`CORR-LOGON-MALWARE-WRITE`** — a remote (external-IP) 4624 success
//!   followed by a `FileCreate` of an executable in a user-writable path,
//!   joined on the account ([`EntityRef::User`]). The "executable in a
//!   user-writable path" precision lives in a Part-A [`guard`] that reads the
//!   consequent's [`artifact_path`]. ATT&CK T1105.
//! - **`CORR-EXFIL-STAGE`** — an archive (`.zip`/`.rar`/`.7z`) `FileCreate` near
//!   `.lnk`/loot artifacts in a user/desktop path, in either temporal order
//!   within the session window, joined per session/host. The staging-context
//!   precision (desktop/user path on both legs, loot-shaped names) lives in a
//!   Part-A guard. Asserted **on both hosts** by the orchestration calling it
//!   per host. ATT&CK T1074.001.
//!
//! Findings are observations: every note says "consistent with", never a
//! verdict. The [`tests::no_tier_b_note_asserts_a_verdict`] test enforces this.
//!
//! [`EntityRef::Ip`]: issen_core::timeline::event::EntityRef::Ip
//! [`EntityRef::User`]: issen_core::timeline::event::EntityRef::User
//! [`guard`]: crate::evaluator::RuleSpec::guard
//! [`artifact_path`]: crate::evaluator::EventView::artifact_path

use crate::evaluator::RuleSpec;

pub mod bruteforce;
pub mod exfil_stage;
pub mod logon_malware;

/// The bundled Tier-B ordered-window rules.
///
/// `CORR-LOGON-MALWARE-WRITE` and `CORR-EXFIL-STAGE` rely on a Part-A guard for
/// their path/staging precision but are still expressed as a [`RuleSpec`] and
/// run through the generic engine; only their `evaluate_*` wrappers attach the
/// real artifact paths the guards read. All three appear here.
#[must_use]
pub fn tier_b_rules() -> Vec<RuleSpec> {
    vec![
        bruteforce::bruteforce_rule(),
        logon_malware::logon_malware_rule(),
        exfil_stage::exfil_stage_rule(),
    ]
}

#[cfg(test)]
pub(crate) mod testkit {
    use issen_core::timeline::event::EntityRef;

    use crate::evaluator::{EventSource, EventView};

    /// A synthetic event for Tier-B rule unit tests. Unlike the Tier-A testkit
    /// it carries a full `artifact_path`, because two Tier-B rules read it from
    /// a Part-A guard.
    #[derive(Debug, Clone)]
    pub struct TestEvent {
        pub id: u64,
        pub ts: i64,
        pub event_type: String,
        pub entity_refs: Vec<EntityRef>,
        pub host: Option<String>,
        pub source: EventSource,
        pub path: String,
    }

    impl TestEvent {
        pub fn new(id: u64, ts: i64, event_type: &str, host: &str, source: EventSource) -> Self {
            Self {
                id,
                ts,
                event_type: event_type.to_string(),
                entity_refs: Vec::new(),
                host: Some(host.to_string()),
                source,
                path: String::new(),
            }
        }

        #[must_use]
        pub fn with_entity(mut self, e: EntityRef) -> Self {
            self.entity_refs.push(e);
            self
        }

        #[must_use]
        pub fn with_path(mut self, p: &str) -> Self {
            self.path = p.to_string();
            self
        }
    }

    impl EventView for TestEvent {
        fn id(&self) -> u64 {
            self.id
        }
        fn timestamp_ns(&self) -> i64 {
            self.ts
        }
        fn event_type(&self) -> &str {
            &self.event_type
        }
        fn entity_refs(&self) -> &[EntityRef] {
            &self.entity_refs
        }
        fn hostname(&self) -> Option<&str> {
            self.host.as_deref()
        }
        fn source(&self) -> EventSource {
            self.source
        }
        fn artifact_path(&self) -> &str {
            &self.path
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_carries_the_tier_b_rules() {
        let codes: Vec<&str> = tier_b_rules().iter().map(|r| r.code).collect();
        assert!(codes.contains(&"CORR-BRUTEFORCE-LOGON"));
        assert!(codes.contains(&"CORR-LOGON-MALWARE-WRITE"));
        assert!(codes.contains(&"CORR-EXFIL-STAGE"));
    }

    /// Epistemics gate (plan v5 §7.5): every Tier-B note is an observation, not
    /// a verdict. It must say "consistent with" and never assert proof.
    #[test]
    fn no_tier_b_note_asserts_a_verdict() {
        let forbidden = ["confirm", "prove", "proof", "exceed", "undoubtedly", "certainly"];
        let notes: Vec<&str> = tier_b_rules().iter().map(|r| r.note).collect();
        for note in notes {
            let lower = note.to_ascii_lowercase();
            assert!(
                lower.contains("consistent with"),
                "note must hedge with 'consistent with': {note:?}"
            );
            for needle in forbidden {
                assert!(
                    !lower.contains(needle),
                    "note must not assert a verdict ({needle:?}): {note:?}"
                );
            }
        }
    }
}
