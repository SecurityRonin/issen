//! `CORR-EXFIL-STAGE` (plan v4 §5.2).
//!
//! An archive (`.zip`/`.rar`/`.7z`) is created next to `.lnk`/loot artifacts in
//! a user/desktop path — collected data staged for exfiltration. The archive
//! `FileCreate` is the anchor; a nearby `.lnk`/loot artifact create is the
//! consequent. The pair may occur in *either* temporal order within the session
//! window (Part-A `ordered: false`), joined per session owner
//! ([`EntityRef::User`]). The staging-context precision — both legs in a
//! user/desktop subtree and the consequent being a loot-shaped artifact — is a
//! Part-A [`guard`](crate::evaluator::RuleSpec::guard) reading both events'
//! [`artifact_path`](crate::evaluator::EventView::artifact_path).
//!
//! The plan requires this rule to fire **on both hosts** (Case 001: the DC's
//! `secret.zip` + `Secret.lnk`, and the Desktop's `loot.zip` + `Loot.lnk`); the
//! rule is `SameHost` and the orchestration invokes it per host, so
//! [`tests::fires_on_both_hosts`] asserts the both-hosts obligation directly.
//! ATT&CK: T1074.001 (local data staging).
//!
//! [`EntityRef::User`]: issen_core::timeline::event::EntityRef::User

use crate::correlation::Correlation;
use crate::evaluator::{evaluate, EventView, RuleSpec, ScopeRule};
use crate::tier_a::copy_delete::same_subtree;
use crate::tier_a::extension;

/// Examiner-facing note — an observation, never a verdict.
pub const EXFIL_STAGE_NOTE: &str =
    "An archive created alongside shortcut/loot artifacts in a user desktop \
     directory is consistent with collected data being staged for exfiltration \
     (T1074.001).";

/// 24 hours in nanoseconds — the session staging window (plan v4 §5.2). The
/// pair is matched in either order within this window.
pub const EXFIL_STAGE_WINDOW_NS: i64 = 24 * 60 * 60 * 1_000_000_000;

/// Lowercased archive extensions a staging bundle typically carries.
const ARCHIVE_EXTENSIONS: &[&str] = &["zip", "rar", "7z", "tar", "gz", "cab"];

/// `true` when `path` lives in a user/desktop location data is staged in
/// (a user profile, Desktop, or Documents tree).
#[must_use]
pub fn is_user_desktop_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase().replace('\\', "/");
    p.contains("/users/") || p.contains("/desktop/") || p.contains("/documents/")
}

/// `true` when `path` is a staging-context artifact: a Windows shortcut
/// (`.lnk`) — the loot-link the plan keys on.
#[must_use]
pub fn is_staging_artifact(path: &str) -> bool {
    extension(path) == "lnk"
}

/// `true` when `path` names an archive (a staging bundle).
#[must_use]
pub fn is_archive(path: &str) -> bool {
    ARCHIVE_EXTENSIONS.contains(&extension(path).as_str())
}

/// The Part-A per-pair guard for staging: the anchor must be an archive, the
/// consequent a staging artifact (`.lnk`), both in a user/desktop location and
/// sharing a directory subtree (the archive sits *next to* the loot link).
fn staging_context(anchor: &dyn EventView, consequent: &dyn EventView) -> bool {
    let archive = anchor.artifact_path();
    let artifact = consequent.artifact_path();
    is_archive(archive)
        && is_staging_artifact(artifact)
        && is_user_desktop_path(archive)
        && is_user_desktop_path(artifact)
        && same_subtree(archive, artifact)
}

/// The either-order-window rule. Anchor and consequent are both `FileCreate`
/// (the archive and the `.lnk`), joined on the session owner
/// ([`EntityRef::User`]); the guard enforces the archive↔loot-link staging
/// context. `SameHost` — the orchestration runs it per host to satisfy the
/// both-hosts obligation.
///
/// [`EntityRef::User`]: issen_core::timeline::event::EntityRef::User
#[must_use]
pub fn exfil_stage_rule() -> RuleSpec {
    RuleSpec {
        code: "CORR-EXFIL-STAGE",
        attack_technique: Some("T1074.001"),
        severity: forensicnomicon::report::Severity::High,
        anchor_event_type: "FileCreate",
        consequent_event_type: "FileCreate",
        window_ns: EXFIL_STAGE_WINDOW_NS,
        scope: ScopeRule::SameHost,
        note: EXFIL_STAGE_NOTE,
        ordered: false,
        guard: Some(staging_context),
    }
}

/// Evaluate the staging rule: an archive `FileCreate` anchor against nearby
/// artifact `FileCreate` candidates carrying their full `artifact_path`. Thin
/// wrapper over the generic engine; both sides carry the session-owner join
/// entity, and the pair may appear in either temporal order.
#[must_use]
pub fn evaluate_exfil_stage<A, C>(_archive: &A, _artifacts: &[C]) -> Option<Correlation>
where
    A: EventView,
    C: EventView,
{
    // RED stub — implemented in the GREEN commit.
    None
}

#[cfg(test)]
mod tests {
    use super::super::testkit::TestEvent;
    use super::*;
    use crate::correlation::{CorrelationRole, CorrelationScope};
    use crate::evaluator::EventSource;
    use forensicnomicon::report::Severity;
    use issen_core::timeline::event::EntityRef;

    fn create(id: u64, ts: i64, user: &str, host: &str, path: &str) -> TestEvent {
        TestEvent::new(id, ts, "FileCreate", host, EventSource::Disk)
            .with_entity(EntityRef::User(user.to_string()))
            .with_path(path)
    }

    #[test]
    fn fires_for_archive_next_to_a_loot_link_on_the_desktop() {
        let archive = create(
            1,
            2_000,
            "beth",
            "WS01",
            "C:\\Users\\beth\\Desktop\\loot.zip",
        );
        // Loot link created earlier in the same dir — either-order match.
        let cands = vec![create(
            2,
            1_000,
            "beth",
            "WS01",
            "C:\\Users\\beth\\Desktop\\Loot.lnk",
        )];

        let corr = evaluate_exfil_stage(&archive, &cands).expect("a correlation");
        assert_eq!(corr.code, "CORR-EXFIL-STAGE");
        assert_eq!(corr.attack_technique.as_deref(), Some("T1074.001"));
        assert_eq!(corr.severity, Severity::High);
        assert_eq!(corr.scope, CorrelationScope::SameHost);
        assert_eq!(corr.members.len(), 2);
        assert_eq!(corr.members[0].timeline_id, 1);
        assert_eq!(corr.members[0].role, CorrelationRole::Anchor);
        assert_eq!(corr.members[1].timeline_id, 2);
        assert_eq!(corr.members[1].role, CorrelationRole::Consequent);
        // Window spans earlier->later regardless of order.
        assert_eq!(corr.first_ts, 1_000);
        assert_eq!(corr.last_ts, 2_000);
        assert!(corr.note.contains("consistent with"));
    }

    #[test]
    fn fires_on_both_hosts() {
        // The plan's both-hosts obligation: DC secret.zip + Secret.lnk, and
        // Desktop loot.zip + Loot.lnk. The SameHost rule fires for each host.
        let dc_archive = create(
            1,
            1_000,
            "Administrator",
            "DC01",
            "C:\\Users\\Administrator\\Desktop\\secret.zip",
        );
        let dc_link = vec![create(
            2,
            1_500,
            "Administrator",
            "DC01",
            "C:\\Users\\Administrator\\Desktop\\Secret.lnk",
        )];
        assert!(
            evaluate_exfil_stage(&dc_archive, &dc_link).is_some(),
            "must fire on the DC (secret.zip)"
        );

        let ws_archive = create(
            3,
            2_000,
            "beth",
            "WS01",
            "C:\\Users\\beth\\Desktop\\loot.zip",
        );
        let ws_link = vec![create(
            4,
            2_500,
            "beth",
            "WS01",
            "C:\\Users\\beth\\Desktop\\Loot.lnk",
        )];
        assert!(
            evaluate_exfil_stage(&ws_archive, &ws_link).is_some(),
            "must fire on the Desktop host (loot.zip)"
        );
    }

    // ── Negative controls ────────────────────────────────────────────────────

    #[test]
    fn does_not_fire_for_an_ordinary_zip_with_no_staging_context() {
        // A zip created with no nearby .lnk/loot artifact — only an unrelated
        // document creation in the dir — must not fire (the canonical negative).
        let archive = create(
            1,
            1_000,
            "beth",
            "WS01",
            "C:\\Users\\beth\\Desktop\\backup.zip",
        );
        let cands = vec![create(
            2,
            1_500,
            "beth",
            "WS01",
            "C:\\Users\\beth\\Desktop\\notes.txt",
        )];
        assert!(evaluate_exfil_stage(&archive, &cands).is_none());
    }

    #[test]
    fn does_not_fire_when_archive_is_outside_user_desktop_space() {
        // Archive staged in a build/temp tree, not a user desktop — guard rejects.
        let archive = create(
            1,
            1_000,
            "beth",
            "WS01",
            "C:\\Build\\artifacts\\loot.zip",
        );
        let cands = vec![create(2, 1_500, "beth", "WS01", "C:\\Build\\artifacts\\Loot.lnk")];
        assert!(evaluate_exfil_stage(&archive, &cands).is_none());
    }

    #[test]
    fn does_not_fire_when_link_is_in_a_different_subtree() {
        // The .lnk lives in an unrelated user dir — the subtree guard keeps it
        // silent even though both are in user space.
        let archive = create(
            1,
            1_000,
            "beth",
            "WS01",
            "C:\\Users\\beth\\Desktop\\loot.zip",
        );
        let cands = vec![create(
            2,
            1_500,
            "beth",
            "WS01",
            "C:\\Users\\beth\\Documents\\Loot.lnk",
        )];
        assert!(evaluate_exfil_stage(&archive, &cands).is_none());
    }

    #[test]
    fn does_not_fire_for_a_different_account() {
        let archive = create(
            1,
            1_000,
            "Administrator",
            "WS01",
            "C:\\Users\\beth\\Desktop\\loot.zip",
        );
        let cands = vec![create(
            2,
            1_500,
            "beth",
            "WS01",
            "C:\\Users\\beth\\Desktop\\Loot.lnk",
        )];
        assert!(evaluate_exfil_stage(&archive, &cands).is_none());
    }

    #[test]
    fn does_not_fire_outside_the_session_window() {
        let archive = create(
            1,
            1_000,
            "beth",
            "WS01",
            "C:\\Users\\beth\\Desktop\\loot.zip",
        );
        let late = 1_000 + EXFIL_STAGE_WINDOW_NS + 1;
        let cands = vec![create(
            2,
            late,
            "beth",
            "WS01",
            "C:\\Users\\beth\\Desktop\\Loot.lnk",
        )];
        assert!(evaluate_exfil_stage(&archive, &cands).is_none());
    }

    #[test]
    fn does_not_fire_across_hosts() {
        let archive = create(
            1,
            1_000,
            "beth",
            "DC01",
            "C:\\Users\\beth\\Desktop\\loot.zip",
        );
        let mut other = create(
            2,
            1_500,
            "beth",
            "WS01",
            "C:\\Users\\beth\\Desktop\\Loot.lnk",
        );
        other.host = Some("WS01".to_string());
        let cands = vec![other];
        assert!(evaluate_exfil_stage(&archive, &cands).is_none());
    }
}
