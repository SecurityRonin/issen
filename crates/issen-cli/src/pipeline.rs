//! Resumable pipeline planning for the unified front door.
//!
//! `issen <evidence…>` is a re-entrant target: re-running it must continue from
//! wherever it stopped and re-run only the stages whose inputs changed. The
//! decision of *which stages to run* is pure logic — given the stage-state
//! persisted in the case DB and the current input fingerprints — and lives here
//! as a Humble Object so it can be unit-tested without any I/O.
//!
//! See `docs/cli-unified-frontdoor-spec.md`.

use std::collections::{HashMap, HashSet};

/// A pipeline stage. `Ingest`/`Correlate`/`Scan` form the disk chain; `Memory`
/// is independent (it consumes memory dumps, not the disk timeline).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
    Ingest,
    Correlate,
    Scan,
    Memory,
}

impl Stage {
    /// Canonical evaluation order. Disk chain first, then the independent memory leg.
    pub const ORDER: [Stage; 4] = [Stage::Ingest, Stage::Correlate, Stage::Scan, Stage::Memory];

    /// Upstream stages whose re-run forces this stage to re-run, because this
    /// stage consumes their output. Re-ingesting the disk timeline invalidates
    /// correlation and scanning; the memory leg depends on neither.
    #[must_use]
    pub fn deps(self) -> &'static [Stage] {
        match self {
            Stage::Ingest | Stage::Memory => &[],
            Stage::Correlate | Stage::Scan => &[Stage::Ingest],
        }
    }
}

/// Persisted completion status of a stage from a prior run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The stage finished cleanly.
    Done,
    /// The stage started but did not finish (e.g. the process was killed).
    Incomplete,
}

/// A stage-state row recovered from the case DB.
#[derive(Debug, Clone)]
pub struct StageRecord {
    pub stage: Stage,
    pub status: Status,
    /// Fingerprint of the stage's inputs at the time it last ran.
    pub fingerprint: String,
}

/// Why a stage needs to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// No prior record — never run for this case.
    Missing,
    /// Prior run did not finish.
    Incomplete,
    /// Inputs changed since the last successful run (fingerprint mismatch).
    Stale,
    /// An upstream dependency is re-running, so this stage's input will change.
    UpstreamRerun,
}

/// What to do with a stage this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Run(Reason),
    Skip,
}

impl Action {
    #[must_use]
    pub fn is_run(self) -> bool {
        matches!(self, Action::Run(_))
    }
}

/// Decide, for each *applicable* stage (one with a current fingerprint — e.g. the
/// memory stage is absent when the case has no dumps), whether to run it and why,
/// or to skip it. Stages are returned in [`Stage::ORDER`].
///
/// Rules, per stage:
/// - no prior record → `Run(Missing)`
/// - prior `Incomplete` → `Run(Incomplete)`
/// - prior `Done` but fingerprint changed → `Run(Stale)`
/// - prior `Done` and fingerprint matches → `Skip` …
/// - …unless an upstream dependency is itself running → `Run(UpstreamRerun)`.
#[must_use]
pub fn plan(prior: &[StageRecord], current_fp: &HashMap<Stage, String>) -> Vec<(Stage, Action)> {
    // STUB (RED): not yet implemented.
    let _ = (prior, current_fp);
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(pairs: &[(Stage, &str)]) -> HashMap<Stage, String> {
        pairs.iter().map(|(s, f)| (*s, (*f).to_string())).collect()
    }

    fn rec(stage: Stage, status: Status, f: &str) -> StageRecord {
        StageRecord {
            stage,
            status,
            fingerprint: f.to_string(),
        }
    }

    fn action_for(plan: &[(Stage, Action)], stage: Stage) -> Option<Action> {
        plan.iter().find(|(s, _)| *s == stage).map(|(_, a)| *a)
    }

    #[test]
    fn cold_run_runs_every_applicable_stage_as_missing() {
        let cur = fp(&[
            (Stage::Ingest, "e1"),
            (Stage::Correlate, "r1"),
            (Stage::Scan, "f1"),
            (Stage::Memory, "m1"),
        ]);
        let p = plan(&[], &cur);
        for s in Stage::ORDER {
            assert_eq!(
                action_for(&p, s),
                Some(Action::Run(Reason::Missing)),
                "{s:?}"
            );
        }
    }

    #[test]
    fn all_done_and_unchanged_skips_everything() {
        let cur = fp(&[
            (Stage::Ingest, "e1"),
            (Stage::Correlate, "r1"),
            (Stage::Scan, "f1"),
        ]);
        let prior = vec![
            rec(Stage::Ingest, Status::Done, "e1"),
            rec(Stage::Correlate, Status::Done, "r1"),
            rec(Stage::Scan, Status::Done, "f1"),
        ];
        let p = plan(&prior, &cur);
        for s in [Stage::Ingest, Stage::Correlate, Stage::Scan] {
            assert_eq!(action_for(&p, s), Some(Action::Skip), "{s:?}");
        }
    }

    #[test]
    fn changed_evidence_reingests_and_cascades_to_disk_chain_only() {
        // Ingest fingerprint changed (new evidence); correlate/scan rule+feed
        // fingerprints unchanged; memory dump unchanged.
        let cur = fp(&[
            (Stage::Ingest, "e2"),
            (Stage::Correlate, "r1"),
            (Stage::Scan, "f1"),
            (Stage::Memory, "m1"),
        ]);
        let prior = vec![
            rec(Stage::Ingest, Status::Done, "e1"),
            rec(Stage::Correlate, Status::Done, "r1"),
            rec(Stage::Scan, Status::Done, "f1"),
            rec(Stage::Memory, Status::Done, "m1"),
        ];
        let p = plan(&prior, &cur);
        assert_eq!(
            action_for(&p, Stage::Ingest),
            Some(Action::Run(Reason::Stale))
        );
        assert_eq!(
            action_for(&p, Stage::Correlate),
            Some(Action::Run(Reason::UpstreamRerun))
        );
        assert_eq!(
            action_for(&p, Stage::Scan),
            Some(Action::Run(Reason::UpstreamRerun))
        );
        // Memory is independent of the disk chain — unchanged, so it skips.
        assert_eq!(action_for(&p, Stage::Memory), Some(Action::Skip));
    }

    #[test]
    fn updated_feeds_rerun_scan_only() {
        let cur = fp(&[
            (Stage::Ingest, "e1"),
            (Stage::Correlate, "r1"),
            (Stage::Scan, "f2"),
        ]);
        let prior = vec![
            rec(Stage::Ingest, Status::Done, "e1"),
            rec(Stage::Correlate, Status::Done, "r1"),
            rec(Stage::Scan, Status::Done, "f1"),
        ];
        let p = plan(&prior, &cur);
        assert_eq!(action_for(&p, Stage::Ingest), Some(Action::Skip));
        assert_eq!(action_for(&p, Stage::Correlate), Some(Action::Skip));
        assert_eq!(
            action_for(&p, Stage::Scan),
            Some(Action::Run(Reason::Stale))
        );
    }

    #[test]
    fn edited_rule_reruns_correlate_only() {
        let cur = fp(&[
            (Stage::Ingest, "e1"),
            (Stage::Correlate, "r2"),
            (Stage::Scan, "f1"),
        ]);
        let prior = vec![
            rec(Stage::Ingest, Status::Done, "e1"),
            rec(Stage::Correlate, Status::Done, "r1"),
            rec(Stage::Scan, Status::Done, "f1"),
        ];
        let p = plan(&prior, &cur);
        assert_eq!(action_for(&p, Stage::Ingest), Some(Action::Skip));
        assert_eq!(
            action_for(&p, Stage::Correlate),
            Some(Action::Run(Reason::Stale))
        );
        // Scan does not depend on correlate's output, so it is unaffected.
        assert_eq!(action_for(&p, Stage::Scan), Some(Action::Skip));
    }

    #[test]
    fn incomplete_stage_resumes_without_rerunning_completed_upstream() {
        // Killed mid-correlate: ingest done, correlate incomplete.
        let cur = fp(&[
            (Stage::Ingest, "e1"),
            (Stage::Correlate, "r1"),
            (Stage::Scan, "f1"),
        ]);
        let prior = vec![
            rec(Stage::Ingest, Status::Done, "e1"),
            rec(Stage::Correlate, Status::Incomplete, "r1"),
        ];
        let p = plan(&prior, &cur);
        assert_eq!(action_for(&p, Stage::Ingest), Some(Action::Skip));
        assert_eq!(
            action_for(&p, Stage::Correlate),
            Some(Action::Run(Reason::Incomplete))
        );
        // Scan was never run (no record) → Missing; ingest (its dep) is not running.
        assert_eq!(
            action_for(&p, Stage::Scan),
            Some(Action::Run(Reason::Missing))
        );
    }

    #[test]
    fn stage_with_no_current_fingerprint_is_not_planned() {
        // No memory dumps in this case → no Memory fingerprint → Memory absent.
        let cur = fp(&[(Stage::Ingest, "e1")]);
        let p = plan(&[], &cur);
        assert_eq!(action_for(&p, Stage::Memory), None);
        assert_eq!(
            action_for(&p, Stage::Ingest),
            Some(Action::Run(Reason::Missing))
        );
    }

    #[test]
    fn plan_is_returned_in_canonical_order() {
        let cur = fp(&[
            (Stage::Memory, "m1"),
            (Stage::Scan, "f1"),
            (Stage::Ingest, "e1"),
            (Stage::Correlate, "r1"),
        ]);
        let p = plan(&[], &cur);
        let order: Vec<Stage> = p.iter().map(|(s, _)| *s).collect();
        assert_eq!(order, Stage::ORDER.to_vec());
    }

    // Silence unused-import warnings in the stub (RED) state.
    #[test]
    fn types_compile() {
        let _: HashSet<Stage> = HashSet::new();
        assert!(Action::Run(Reason::Missing).is_run());
        assert!(!Action::Skip.is_run());
    }
}
