//! `CORR-COPY-DELETE` (plan v4 §5.2).
//!
//! A file is deleted and a near-identical copy is created within a short
//! window. This is the second-highest false-positive-risk rule, so it carries
//! four precision guards (plan v4 §5.2):
//!
//! 1. **token-set stem match** — the two stems are token *permutations*
//!    (`SECRET_beth` ↔ `Beth_Secret`), compared as sets, never as substrings;
//! 2. **same directory subtree** — the pair lives under a shared directory
//!    subtree (one parent is a prefix of the other);
//! 3. **extension equality** — the two basenames share an extension;
//! 4. **byte-size equality** — enforced only when both MFT sizes are present
//!    (the author's own copy test); absent sizes do not block the pair.
//!
//! The match is symmetric within a ≤ 30 min window: copy-then-delete and
//! delete-then-create both occur in the wild, so the *pair inside one window* is
//! the observation, not a strict order. ATT&CK: T1070 (consistent with).
//!
//! These guards are not an ordered-exact-entity shape, so the rule has no
//! [`RuleSpec`](crate::evaluator::RuleSpec) form. It is matched here by a
//! dedicated, tested function emitting the same [`Correlation`] type — a
//! rule-specific matcher, not a second generic evaluator.

use std::collections::BTreeSet;

use crate::correlation::{Correlation, CorrelationMember, CorrelationRole, CorrelationScope};
use crate::evaluator::EventView;

use super::{extension, parent_dir, stem};

/// Examiner-facing note — an observation, never a verdict.
pub const COPY_DELETE_NOTE: &str =
    "A file delete paired with a near-identical copy within a short window is \
     consistent with covering tracks after duplication (T1070).";

/// 30 minutes in nanoseconds — the copy↔delete pairing window (plan v4 §5.2).
pub const COPY_DELETE_WINDOW_NS: i64 = 30 * 60 * 1_000_000_000;

/// The filesystem facts a copy/delete candidate carries beyond its
/// [`EventView`] identity: its full path and, when MFT metadata is available,
/// its byte size.
#[derive(Debug, Clone)]
pub struct FileFacts {
    /// Full path of the file the event concerns.
    pub path: String,
    /// File byte size, when the MFT `$DATA` size is known.
    pub size: Option<u64>,
}

impl FileFacts {
    /// A fact with a known size.
    #[must_use]
    pub fn sized(path: &str, size: u64) -> Self {
        Self {
            path: path.to_string(),
            size: Some(size),
        }
    }

    /// A fact with no known size (size guard is then not applied).
    #[must_use]
    pub fn without_size(path: &str) -> Self {
        Self {
            path: path.to_string(),
            size: None,
        }
    }
}

/// Split a stem into lowercased tokens on `_`, `-`, space, and dot boundaries.
/// Empty tokens are dropped. Used to compare two stems as token *sets*.
#[must_use]
pub fn tokenize_stem(stem_str: &str) -> BTreeSet<String> {
    stem_str
        .split(['_', '-', ' ', '.'])
        .filter(|t| !t.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

/// `true` when the two paths' stems are token-set permutations of each other —
/// the same multiset-free set of tokens, in any order. A single shared prefix
/// token is not enough (it is set equality, not intersection).
#[must_use]
pub fn stems_are_token_permutations(a: &str, b: &str) -> bool {
    let ta = tokenize_stem(stem(a));
    let tb = tokenize_stem(stem(b));
    !ta.is_empty() && ta == tb
}

/// `true` when the two paths share a directory subtree: their parent dirs are
/// equal, or one parent is a path-prefix of the other.
#[must_use]
pub fn same_subtree(a: &str, b: &str) -> bool {
    let pa = parent_dir(a).to_ascii_lowercase().replace('\\', "/");
    let pb = parent_dir(b).to_ascii_lowercase().replace('\\', "/");
    if pa.is_empty() || pb.is_empty() {
        return false;
    }
    pa == pb || pa.starts_with(&format!("{pb}/")) || pb.starts_with(&format!("{pa}/"))
}

/// `true` when all four precision guards hold for a delete↔create pair: token-
/// set stem permutation, same subtree, extension equality, and — only when both
/// sizes are present — byte-size equality.
#[must_use]
pub fn guards_hold(deleted: &FileFacts, created: &FileFacts) -> bool {
    // Order matters for performance: this runs for every candidate delete↔create
    // pair, so the cheap, selective guards go FIRST and the allocating
    // token-permutation check goes LAST. `stems_are_token_permutations` allocates
    // two `BTreeSet<String>` per call; on a real MFT timeline (millions of
    // FileCreate/Delete events) running it first made it ~100% of correlate's
    // runtime. Extension/size are O(1) slice/Option compares that reject the vast
    // majority of pairs before any allocation; `same_subtree` is next; the
    // tokenization fires only for pairs that already match all three. The result
    // is unchanged (the guards are AND-combined).
    if extension(&deleted.path) != extension(&created.path) {
        return false;
    }
    if matches!((deleted.size, created.size), (Some(x), Some(y)) if x != y) {
        return false;
    }
    if !same_subtree(&deleted.path, &created.path) {
        return false;
    }
    stems_are_token_permutations(&deleted.path, &created.path)
}

/// Pair `FileDelete` events with `FileCreate` events that satisfy all guards,
/// within the ≤ 30 min window, on the same host, in either temporal order.
///
/// Each emitted [`Correlation`] carries the delete as anchor and the create as
/// consequent (member roles), with its window spanning the earlier→later of the
/// pair. A delete pairs with its nearest-in-time qualifying create.
#[must_use]
pub fn copy_delete_pairs<E>(
    deletes: &[(E, FileFacts)],
    creates: &[(E, FileFacts)],
) -> Vec<Correlation>
where
    E: EventView,
{
    // Pre-sort creates by timestamp ONCE so each delete scans only the
    // ±WINDOW slice (binary-searched) instead of every create — O(D log C +
    // matches) instead of O(D × C). Positive timestamps only (the per-candidate
    // `cre_ts <= 0` guard moves up here); the candidate set, window, host filter,
    // and nearest-wins tie-break are otherwise unchanged.
    let mut sorted: Vec<&(E, FileFacts)> = creates
        .iter()
        .filter(|(e, _)| e.timestamp_ns() > 0)
        .collect();
    sorted.sort_by_key(|(e, _)| e.timestamp_ns());
    let sorted_ts: Vec<i64> = sorted.iter().map(|(e, _)| e.timestamp_ns()).collect();

    let mut out = Vec::new();
    for (del_ev, del_facts) in deletes {
        let del_ts = del_ev.timestamp_ns();
        if del_ts <= 0 {
            continue;
        }
        // The window [del_ts - W, del_ts + W] as a contiguous slice of `sorted`.
        let lo = sorted_ts.partition_point(|&t| t < del_ts.saturating_sub(COPY_DELETE_WINDOW_NS));
        let hi = sorted_ts.partition_point(|&t| t <= del_ts.saturating_add(COPY_DELETE_WINDOW_NS));
        let mut best: Option<&(E, FileFacts)> = None;
        for candidate in sorted[lo..hi].iter().copied() {
            let (cre_ev, cre_facts) = candidate;
            let cre_ts = cre_ev.timestamp_ns();
            if del_ev.hostname() != cre_ev.hostname() {
                continue;
            }
            if !guards_hold(del_facts, cre_facts) {
                continue;
            }
            let nearer = match best {
                Some((cur_ev, _)) => {
                    (cre_ts - del_ts).abs() < (cur_ev.timestamp_ns() - del_ts).abs()
                }
                None => true,
            };
            if nearer {
                best = Some(candidate);
            }
        }
        if let Some((cre_ev, _)) = best {
            let cre_ts = cre_ev.timestamp_ns();
            let (first, last) = if del_ts <= cre_ts {
                (del_ts, cre_ts)
            } else {
                (cre_ts, del_ts)
            };
            out.push(
                Correlation::new(
                    "CORR-COPY-DELETE",
                    forensicnomicon::report::Severity::Medium,
                )
                .with_attack_technique("T1070")
                .with_scope(CorrelationScope::SameHost)
                .with_window(first, last)
                .with_note(COPY_DELETE_NOTE)
                .with_member(CorrelationMember::new(del_ev.id(), CorrelationRole::Anchor))
                .with_member(CorrelationMember::new(
                    cre_ev.id(),
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
    use crate::evaluator::EventSource;
    use forensicnomicon::report::Severity;

    use super::super::testkit::TestEvent;

    fn del(id: u64, ts: i64) -> TestEvent {
        TestEvent::new(id, ts, "FileDelete", "DC01", EventSource::Disk)
    }
    fn cre(id: u64, ts: i64) -> TestEvent {
        TestEvent::new(id, ts, "FileCreate", "DC01", EventSource::Disk)
    }

    // ── Guard helpers ────────────────────────────────────────────────────────

    #[test]
    fn token_permutation_matches_reordered_tokens() {
        assert!(stems_are_token_permutations(
            "C:/x/SECRET_beth.zip",
            "C:/x/Beth_Secret.zip"
        ));
    }

    #[test]
    fn token_permutation_rejects_a_mere_shared_prefix() {
        // Shared prefix token only — different token sets, must not match.
        assert!(!stems_are_token_permutations(
            "C:/x/report_2024.docx",
            "C:/x/report_2025.docx"
        ));
    }

    #[test]
    fn same_subtree_detects_shared_and_nested_dirs() {
        assert!(same_subtree("C:/Share/a.zip", "C:/Share/b.zip"));
        assert!(same_subtree("C:/Share/a.zip", "C:/Share/sub/b.zip"));
        assert!(!same_subtree("C:/Share/a.zip", "D:/Other/b.zip"));
    }

    // ── Positive ─────────────────────────────────────────────────────────────

    #[test]
    fn fires_for_a_permuted_copy_then_delete_in_one_dir() {
        let deletes = vec![(
            del(1, 2_000),
            FileFacts::sized("C:/Share/SECRET_beth.zip", 4096),
        )];
        let creates = vec![(
            cre(2, 1_000),
            FileFacts::sized("C:/Share/Beth_Secret.zip", 4096),
        )];
        let corrs = copy_delete_pairs(&deletes, &creates);
        assert_eq!(corrs.len(), 1);
        let c = &corrs[0];
        assert_eq!(c.code, "CORR-COPY-DELETE");
        assert_eq!(c.attack_technique.as_deref(), Some("T1070"));
        assert_eq!(c.severity, Severity::Medium);
        assert_eq!(c.scope, CorrelationScope::SameHost);
        assert_eq!(c.members.len(), 2);
        assert_eq!(c.members[0].timeline_id, 1);
        assert_eq!(c.members[0].role, CorrelationRole::Anchor);
        assert_eq!(c.members[1].timeline_id, 2);
        assert_eq!(c.members[1].role, CorrelationRole::Consequent);
        assert!(c.note.contains("consistent with"));
    }

    #[test]
    fn fires_when_size_is_unknown_on_both_sides() {
        // Size guard is skipped when MFT sizes are absent.
        let deletes = vec![(
            del(1, 1_000),
            FileFacts::without_size("C:/Share/SECRET_beth.zip"),
        )];
        let creates = vec![(
            cre(2, 2_000),
            FileFacts::without_size("C:/Share/Beth_Secret.zip"),
        )];
        assert_eq!(copy_delete_pairs(&deletes, &creates).len(), 1);
    }

    // ── Negative controls ────────────────────────────────────────────────────

    #[test]
    fn does_not_pair_two_files_sharing_only_a_common_prefix() {
        let deletes = vec![(
            del(1, 1_000),
            FileFacts::sized("C:/Share/report_2024.docx", 10),
        )];
        let creates = vec![(
            cre(2, 1_500),
            FileFacts::sized("C:/Share/report_2025.docx", 10),
        )];
        assert!(copy_delete_pairs(&deletes, &creates).is_empty());
    }

    #[test]
    fn does_not_pair_reversed_tokens_in_different_subtrees() {
        // The plan's dictionary-plausible reversal across unrelated dirs: the
        // token sets match but the subtree guard must keep it silent.
        let deletes = vec![(
            del(1, 1_000),
            FileFacts::sized("C:/ProjA/report_final.docx", 10),
        )];
        let creates = vec![(
            cre(2, 1_500),
            FileFacts::sized("D:/ProjB/final_report.docx", 10),
        )];
        assert!(copy_delete_pairs(&deletes, &creates).is_empty());
    }

    #[test]
    fn does_not_pair_unrelated_same_size_files() {
        let deletes = vec![(del(1, 1_000), FileFacts::sized("C:/Share/alpha.bin", 4096))];
        let creates = vec![(cre(2, 1_500), FileFacts::sized("C:/Share/bravo.bin", 4096))];
        assert!(copy_delete_pairs(&deletes, &creates).is_empty());
    }

    #[test]
    fn does_not_pair_when_sizes_differ() {
        let deletes = vec![(
            del(1, 1_000),
            FileFacts::sized("C:/Share/SECRET_beth.zip", 4096),
        )];
        let creates = vec![(
            cre(2, 1_500),
            FileFacts::sized("C:/Share/Beth_Secret.zip", 8192),
        )];
        assert!(copy_delete_pairs(&deletes, &creates).is_empty());
    }

    #[test]
    fn does_not_pair_when_extensions_differ() {
        let deletes = vec![(
            del(1, 1_000),
            FileFacts::sized("C:/Share/SECRET_beth.zip", 10),
        )];
        let creates = vec![(
            cre(2, 1_500),
            FileFacts::sized("C:/Share/Beth_Secret.rar", 10),
        )];
        assert!(copy_delete_pairs(&deletes, &creates).is_empty());
    }

    #[test]
    fn does_not_pair_outside_the_30min_window() {
        let deletes = vec![(
            del(1, 1_000),
            FileFacts::sized("C:/Share/SECRET_beth.zip", 10),
        )];
        let late = 1_000 + COPY_DELETE_WINDOW_NS + 1;
        let creates = vec![(
            cre(2, late),
            FileFacts::sized("C:/Share/Beth_Secret.zip", 10),
        )];
        assert!(copy_delete_pairs(&deletes, &creates).is_empty());
    }

    #[test]
    fn does_not_pair_across_hosts() {
        let deletes = vec![(
            del(1, 1_000),
            FileFacts::sized("C:/Share/SECRET_beth.zip", 10),
        )];
        let mut other = cre(2, 1_500);
        other.host = Some("WS01".to_string());
        let creates = vec![(other, FileFacts::sized("C:/Share/Beth_Secret.zip", 10))];
        assert!(copy_delete_pairs(&deletes, &creates).is_empty());
    }
}
