//! The disk-leg correlation runner (capstone task #37, plan v5 §7.1 phase 5).
//!
//! [`run_correlations`] invokes every disk-leg rule over a flat slice of events
//! and collects their [`Correlation`] output. It is deliberately storage-free
//! and generic over [`EventView`], so the core sequencing logic is unit-testable
//! on synthetic events with no `DuckDB` dependency; the store-facing
//! `run_and_persist` wrapper lives in `issen-timeline` (which depends *down* on
//! this crate) and feeds it `StoredEvent`s.
//!
//! ## Which rules run here
//!
//! All disk-leg rules whose anchor/consequent are flat timeline events:
//!
//! - Tier A: `CORR-MALWARE-RELOCATE`, `CORR-MALWARE-PERSIST`, `CORR-COPY-DELETE`
//! - Tier B: `CORR-BRUTEFORCE-LOGON`, `CORR-LOGON-MALWARE-WRITE`,
//!   `CORR-EXFIL-STAGE`
//! - Tier B′: `CORR-PERSIST-REGCONFIRM`
//! - Tier D: `CORR-LATERAL-MOVE`
//!
//! `CORR-BRUTEFORCE-LOGON` anchors on a `LogonFailureBurst` event; the burst is
//! identified upstream (`issen_timeline::burst_windows`) and supplied here as a
//! synthetic anchor event already in the input slice — the runner does not
//! re-derive bursts (that needs the storage type).
//!
//! ## The normalization seam
//!
//! Several rules join on a *normalized* entity that the raw ingest does not
//! attach (the file basename for RELOCATE, the image/service stem for PERSIST /
//! REGCONFIRM). The runner re-projects each candidate into a [`RunEvent`] that
//! carries the right join entity for the rule being evaluated, derived from the
//! event's `artifact_path`. Rules that join on an entity the ingest already
//! attaches (the source IP for BRUTEFORCE, the account for LOGON-MALWARE /
//! EXFIL-STAGE / LATERAL-MOVE) keep the event's own entity refs.
//!
//! ## Tier-C seam
//!
//! Memory-leg (Tier C / C′) rules need the dump's process/netstat/malfind rows —
//! the `thread_count` / `ppid` / `injection` fields that the [`EventView`] trait
//! deliberately does not surface — so they cannot run inside the generic
//! [`run_correlations`] pass. They are matched instead over a projected
//! [`MemEvent`] slice ([`run_memory_rules`]); the store-facing wrapper that owns
//! `StoredEvent` (and its metadata) builds that slice. [`run_correlations_with_memory`]
//! is the wiring point that runs the disk-leg pass and appends the memory-leg
//! firings to the same `Vec<Correlation>` before persistence.

use std::collections::HashMap;

use issen_core::timeline::event::EntityRef;

use crate::correlation::Correlation;
use crate::evaluator::{EventSource, EventView};
use crate::tier_a::copy_delete::{copy_delete_pairs, FileFacts};
use crate::tier_a::persist::evaluate_persist;
use crate::tier_a::relocate::evaluate_relocate;
use crate::tier_a::{basename_entity, stem_entity};
use crate::tier_b::bruteforce::evaluate_bruteforce;
use crate::tier_b::exfil_stage::evaluate_exfil_stage;
use crate::tier_b::logon_malware::evaluate_logon_malware;
use crate::tier_b_prime::regconfirm::evaluate_regconfirm;
use crate::tier_c::{run_memory_rules, MemEvent};
use crate::tier_d::lateral_move::evaluate_lateral_move;

/// An owned projection of an [`EventView`] the runner controls.
///
/// It carries the same `id`/`timestamp_ns`/`event_type`/`hostname`/`source`/
/// `artifact_path` as the source event, plus a *re-derived* set of entity refs
/// (the normalized join key for the rule it feeds). Building it owns its strings
/// so the runner can synthesize join entities without borrowing the source.
#[derive(Debug, Clone)]
pub struct RunEvent {
    id: u64,
    timestamp_ns: i64,
    event_type: String,
    entity_refs: Vec<EntityRef>,
    hostname: Option<String>,
    source: EventSource,
    artifact_path: String,
}

impl RunEvent {
    /// Project a source event, keeping its own entity refs (for rules that join
    /// on an entity the ingest already attaches).
    fn from_view<E: EventView>(ev: &E) -> Self {
        Self {
            id: ev.id(),
            timestamp_ns: ev.timestamp_ns(),
            event_type: ev.event_type().to_string(),
            entity_refs: ev.entity_refs().to_vec(),
            hostname: ev.hostname().map(ToString::to_string),
            source: ev.source(),
            artifact_path: ev.artifact_path().to_string(),
        }
    }

    /// Project a source event, replacing its entity refs with `join` (the
    /// normalized basename/stem the rule joins on).
    fn with_join<E: EventView>(ev: &E, join: EntityRef) -> Self {
        let mut out = Self::from_view(ev);
        out.entity_refs = vec![join];
        out
    }
}

impl EventView for RunEvent {
    fn id(&self) -> u64 {
        self.id
    }
    fn timestamp_ns(&self) -> i64 {
        self.timestamp_ns
    }
    fn event_type(&self) -> &str {
        &self.event_type
    }
    fn entity_refs(&self) -> &[EntityRef] {
        &self.entity_refs
    }
    fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }
    fn source(&self) -> EventSource {
        self.source
    }
    fn artifact_path(&self) -> &str {
        &self.artifact_path
    }
}

/// Run every disk-leg correlation rule over `events`, returning all firings.
///
/// Pure and storage-free: the same logic the store-facing `run_and_persist`
/// drives, exercised here directly on synthetic events. Memory-leg rules are
/// not run (see the module-level Tier-C seam note).
#[must_use]
pub fn run_correlations<E>(events: &[E]) -> Vec<Correlation>
where
    E: EventView,
{
    let mut out = Vec::new();
    out.extend(run_relocate(events));
    out.extend(run_persist(events));
    out.extend(run_copy_delete(events));
    out.extend(run_bruteforce(events));
    out.extend(run_logon_malware(events));
    out.extend(run_exfil_stage(events));
    out.extend(run_regconfirm(events));
    out.extend(run_lateral_move(events));
    out
}

/// Run every disk-leg rule over `events` **and** every memory-leg (Tier C / C′)
/// rule over `memory`, returning all firings in one vector.
///
/// This is the full correlation pass: the disk-leg rules consume the flat
/// timeline events (`events`), the memory-leg rules consume the projected
/// [`MemEvent`] slice (`memory`, carrying the `pid` / `ppid` / `thread_count` /
/// `injection` fields parsed from each memory event's metadata), and the
/// cross-leg `CORR-PROC-DISK-MATCH` reads both. The memory firings are appended
/// to the disk firings on the same `Vec<Correlation>` — the additive Tier-C seam.
#[must_use]
pub fn run_correlations_with_memory<E>(events: &[E], memory: &[MemEvent]) -> Vec<Correlation>
where
    E: EventView + Sync,
{
    // Delegate to the progress-aware path with a no-op start_rule, so the
    // sequencing (and its determinism) lives in exactly one place.
    run_correlations_with_memory_progress(events, memory, &|_| ())
}

/// The disk-leg rules in their canonical evaluation order, each paired with the
/// short name reported to `start_rule`. Collecting their outputs in this fixed
/// order keeps the findings deterministic even though the rules run in parallel.
#[allow(clippy::type_complexity)]
fn disk_rules<E: EventView + Sync>() -> [(&'static str, fn(&[E]) -> Vec<Correlation>); 8] {
    [
        ("relocate", run_relocate::<E>),
        ("persist", run_persist::<E>),
        ("copy-delete", run_copy_delete::<E>),
        ("bruteforce", run_bruteforce::<E>),
        ("logon-malware", run_logon_malware::<E>),
        ("exfil-stage", run_exfil_stage::<E>),
        ("regconfirm", run_regconfirm::<E>),
        ("lateral-move", run_lateral_move::<E>),
    ]
}

/// Run every disk-leg and memory-leg rule, reporting each rule to `start_rule`
/// for the lifetime of its evaluation, and returning all firings in one vector.
///
/// `start_rule(name)` returns an opaque guard held only while that rule runs;
/// dropping it signals the rule is done. The guard type is generic (`G`), so
/// this crate stays UI-free — the CLI passes a closure that claims a progress
/// worker slot, while the library and tests pass a no-op. The rules run in
/// parallel (rayon), but their outputs are reassembled in the fixed
/// [`disk_rules`] order, so the findings set is identical to the sequential
/// [`run_correlations_with_memory`].
#[must_use]
pub fn run_correlations_with_memory_progress<E, F, G>(
    events: &[E],
    memory: &[MemEvent],
    start_rule: &F,
) -> Vec<Correlation>
where
    E: EventView + Sync,
    F: Fn(&str) -> G + Sync,
    G: Send,
{
    use rayon::prelude::*;

    // Disk-leg rules in parallel; carry each rule's fixed index so the firings
    // can be re-laid in canonical order regardless of completion order.
    let rules = disk_rules::<E>();
    let mut indexed: Vec<(usize, Vec<Correlation>)> = rules
        .par_iter()
        .enumerate()
        .map(|(i, (name, rule))| {
            let _guard = start_rule(name);
            (i, rule(events))
        })
        .collect();
    indexed.sort_by_key(|(i, _)| *i);

    let mut out = Vec::new();
    for (_, firings) in indexed {
        out.extend(firings);
    }

    // Memory-leg rules, announced as one "memory" unit (run_memory_rules itself
    // sequences the three Tier-C/C′ matchers; the guard is held for the group).
    {
        let _guard = start_rule("memory");
        out.extend(run_memory_rules(memory, events));
    }
    out
}

/// Events of one type, projected with the given normalized join entity.
fn projected<E, F>(events: &[E], event_type: &str, join: F) -> Vec<RunEvent>
where
    E: EventView,
    F: Fn(&E) -> EntityRef,
{
    events
        .iter()
        .filter(|e| e.event_type() == event_type)
        .map(|e| RunEvent::with_join(e, join(e)))
        .collect()
}

/// Events of one type, projected keeping their own entity refs.
fn of_type<E: EventView>(events: &[E], event_type: &str) -> Vec<RunEvent> {
    events
        .iter()
        .filter(|e| e.event_type() == event_type)
        .map(RunEvent::from_view)
        .collect()
}

/// An inverted index from each candidate's entity refs to the candidate
/// positions that carry them.
///
/// The generic [`evaluate`](crate::evaluator::evaluate) engine mandates
/// `shares_entity(anchor, candidate)` before any pair can fire, so a candidate
/// that shares no entity ref with the anchor can never produce a correlation.
/// Scanning the full candidate slice per anchor is therefore O(anchors ×
/// candidates) of pure rejection. This index lets each anchor visit only the
/// candidates that share one of its own entity refs, collapsing the hot loops to
/// O(matches) without changing which pairs the engine considers — every
/// candidate that *could* match is still reached, so the fired set is identical.
type EntityIndex = HashMap<EntityRef, Vec<usize>>;

/// Build the [`EntityIndex`] over `candidates`, keyed on each candidate's own
/// entity refs (`EntityRef` is `Eq + Hash`, so it keys the map directly).
fn build_entity_index(candidates: &[RunEvent]) -> EntityIndex {
    let mut index: EntityIndex = HashMap::new();
    for (pos, cand) in candidates.iter().enumerate() {
        for entity in cand.entity_refs() {
            index.entry(entity.clone()).or_default().push(pos);
        }
    }
    index
}

/// Candidate positions sharing at least one of `anchor`'s entity refs,
/// de-duplicated (a candidate sharing two of the anchor's entities appears
/// once) and with `exclude` (the anchor's own position in a self-join) removed.
///
/// Positions are returned sorted so the reduced candidate slice preserves the
/// original candidate order — the engine's "nearest consequent wins" tie-break
/// then resolves exactly as it did over the full slice.
fn entity_candidate_positions<A: EventView>(
    anchor: &A,
    index: &EntityIndex,
    exclude: Option<usize>,
) -> Vec<usize> {
    let mut positions: Vec<usize> = Vec::new();
    for entity in anchor.entity_refs() {
        if let Some(bucket) = index.get(entity) {
            positions.extend(bucket.iter().copied());
        }
    }
    positions.sort_unstable();
    positions.dedup();
    if let Some(skip) = exclude {
        positions.retain(|&p| p != skip);
    }
    positions
}

/// The reduced owned candidate slice for `anchor`: the `all` candidates sharing
/// one of the anchor's entity refs (de-duplicated, `exclude` removed), in
/// original order. The owned `Vec<RunEvent>` matches the `&[C]` the `evaluate_*`
/// wrappers take.
fn reduced_candidates<A: EventView>(
    anchor: &A,
    index: &EntityIndex,
    all: &[RunEvent],
    exclude: Option<usize>,
) -> Vec<RunEvent> {
    entity_candidate_positions(anchor, index, exclude)
        .into_iter()
        .map(|p| all[p].clone())
        .collect()
}

// ── Tier A ───────────────────────────────────────────────────────────────────

/// `CORR-MALWARE-RELOCATE`: each `FileCreate` (user-writable drop) against the
/// `FileRename` candidates (system-dir targets), joined on the file basename.
fn run_relocate<E: EventView>(events: &[E]) -> Vec<Correlation> {
    let creates = projected(events, "FileCreate", |e| basename_entity(e.artifact_path()));
    let renames: Vec<(RunEvent, String)> = events
        .iter()
        .filter(|e| e.event_type() == "FileRename")
        .map(|e| {
            let path = e.artifact_path().to_string();
            (RunEvent::with_join(e, basename_entity(&path)), path)
        })
        .collect();

    // Index the rename candidates by their basename join entity; each create
    // anchor only visits renames that share its basename (the engine's
    // shares_entity gate already requires this), not the full rename slice.
    let rename_events: Vec<RunEvent> = renames.iter().map(|(ev, _)| ev.clone()).collect();
    let index = build_entity_index(&rename_events);

    let mut out = Vec::new();
    for anchor in &creates {
        let reduced: Vec<(RunEvent, String)> = entity_candidate_positions(anchor, &index, None)
            .into_iter()
            .map(|p| renames[p].clone())
            .collect();
        if let Some(corr) = evaluate_relocate(anchor, anchor.artifact_path(), &reduced) {
            out.push(corr);
        }
    }
    out
}

/// `CORR-MALWARE-PERSIST`: each executable `FileCreate` against `ServiceInstall`
/// candidates, joined on the image stem.
fn run_persist<E: EventView>(events: &[E]) -> Vec<Correlation> {
    let creates = projected(events, "FileCreate", |e| stem_entity(e.artifact_path()));
    let installs = projected(events, "ServiceInstall", |e| stem_entity(e.artifact_path()));
    let index = build_entity_index(&installs);

    let mut out = Vec::new();
    for anchor in &creates {
        let reduced = reduced_candidates(anchor, &index, &installs, None);
        if let Some(corr) = evaluate_persist(anchor, &reduced) {
            out.push(corr);
        }
    }
    out
}

/// `CORR-COPY-DELETE`: `FileDelete` ↔ `FileCreate` near-identical-copy pairs.
fn run_copy_delete<E: EventView>(events: &[E]) -> Vec<Correlation> {
    let deletes: Vec<(RunEvent, FileFacts)> = events
        .iter()
        .filter(|e| e.event_type() == "FileDelete")
        .map(|e| {
            (
                RunEvent::from_view(e),
                FileFacts::without_size(e.artifact_path()),
            )
        })
        .collect();
    let creates: Vec<(RunEvent, FileFacts)> = events
        .iter()
        .filter(|e| e.event_type() == "FileCreate")
        .map(|e| {
            (
                RunEvent::from_view(e),
                FileFacts::without_size(e.artifact_path()),
            )
        })
        .collect();
    copy_delete_pairs(&deletes, &creates)
}

// ── Tier B ───────────────────────────────────────────────────────────────────

/// `CORR-BRUTEFORCE-LOGON`: a `LogonFailureBurst` anchor (identified upstream)
/// against `LogonSuccess` candidates, joined on the source IP the ingest carries.
fn run_bruteforce<E: EventView>(events: &[E]) -> Vec<Correlation> {
    let bursts = of_type(events, "LogonFailureBurst");
    let successes = of_type(events, "LogonSuccess");

    let mut out = Vec::new();
    for anchor in &bursts {
        if let Some(corr) = evaluate_bruteforce(anchor, &successes) {
            out.push(corr);
        }
    }
    out
}

/// `CORR-LOGON-MALWARE-WRITE`: a `LogonSuccess` anchor against `FileCreate`
/// candidates (the guard reads each candidate's path), joined on the account.
fn run_logon_malware<E: EventView>(events: &[E]) -> Vec<Correlation> {
    let logons = of_type(events, "LogonSuccess");
    let writes = of_type(events, "FileCreate");
    let index = build_entity_index(&writes);

    let mut out = Vec::new();
    for anchor in &logons {
        let reduced = reduced_candidates(anchor, &index, &writes, None);
        if let Some(corr) = evaluate_logon_malware(anchor, &reduced) {
            out.push(corr);
        }
    }
    out
}

/// `CORR-EXFIL-STAGE`: an archive `FileCreate` anchor against nearby
/// `FileCreate` artifacts (the guard reads paths), joined on the session owner.
fn run_exfil_stage<E: EventView>(events: &[E]) -> Vec<Correlation> {
    let creates = of_type(events, "FileCreate");
    let index = build_entity_index(&creates);

    let mut out = Vec::new();
    for (i, anchor) in creates.iter().enumerate() {
        // Every FileCreate is a candidate anchor; the staging guard keeps only
        // the archive↔loot-link pairs. The engine's shares_entity gate means a
        // candidate must share the session-owner join entity, so visit only
        // those candidates; exclude the anchor's own position so a single event
        // never pairs with itself (preserving the prior j != i self-exclusion).
        let candidates = reduced_candidates(anchor, &index, &creates, Some(i));
        if let Some(corr) = evaluate_exfil_stage(anchor, &candidates) {
            out.push(corr);
        }
    }
    out
}

// ── Tier B′ ──────────────────────────────────────────────────────────────────

/// `CORR-PERSIST-REGCONFIRM`: a `ServiceInstall` anchor against `RegistryModify`
/// candidates, joined on the image/service stem.
fn run_regconfirm<E: EventView>(events: &[E]) -> Vec<Correlation> {
    let installs = projected(events, "ServiceInstall", |e| stem_entity(e.artifact_path()));
    let reg_writes = projected(events, "RegistryModify", |e| stem_entity(e.artifact_path()));
    let index = build_entity_index(&reg_writes);

    let mut out = Vec::new();
    for anchor in &installs {
        let reduced = reduced_candidates(anchor, &index, &reg_writes, None);
        if let Some(corr) = evaluate_regconfirm(anchor, &reduced) {
            out.push(corr);
        }
    }
    out
}

// ── Tier D ───────────────────────────────────────────────────────────────────

/// `CORR-LATERAL-MOVE`: an `RdpLogon` into host A against `RdpLogon`s into other
/// hosts, joined on the account; the guard reads the IP entities the ingest
/// carries, so the events keep their own entity refs.
fn run_lateral_move<E: EventView>(events: &[E]) -> Vec<Correlation> {
    let logons = of_type(events, "RdpLogon");
    let index = build_entity_index(&logons);

    let mut out = Vec::new();
    for (i, anchor) in logons.iter().enumerate() {
        // Self-join on the account join entity; exclude the anchor's own
        // position (the prior j != i self-exclusion). RdpLogon slices are tiny,
        // so this is behavior-identical to the full scan — it just shares the
        // same index helper as the hot rules.
        let candidates = reduced_candidates(anchor, &index, &logons, Some(i));
        if let Some(corr) = evaluate_lateral_move(anchor, &candidates) {
            out.push(corr);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use issen_core::timeline::event::EntityRef;

    /// A synthetic source event with everything the runner reads.
    #[derive(Debug, Clone)]
    struct Ev {
        id: u64,
        ts: i64,
        event_type: String,
        entity_refs: Vec<EntityRef>,
        host: Option<String>,
        source: EventSource,
        path: String,
    }

    impl Ev {
        fn new(id: u64, ts: i64, et: &str, host: &str, source: EventSource) -> Self {
            Self {
                id,
                ts,
                event_type: et.to_string(),
                entity_refs: Vec::new(),
                host: Some(host.to_string()),
                source,
                path: String::new(),
            }
        }
        fn ent(mut self, e: EntityRef) -> Self {
            self.entity_refs.push(e);
            self
        }
        fn host_none(mut self) -> Self {
            self.host = None;
            self
        }
        fn at(mut self, p: &str) -> Self {
            self.path = p.to_string();
            self
        }
    }

    impl EventView for Ev {
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

    fn codes(corrs: &[Correlation]) -> Vec<String> {
        corrs.iter().map(|c| c.code.clone()).collect()
    }

    fn has_code(corrs: &[Correlation], code: &str) -> bool {
        corrs.iter().any(|c| c.code == code)
    }

    #[test]
    fn empty_input_fires_nothing() {
        let events: Vec<Ev> = Vec::new();
        assert!(run_correlations(&events).is_empty());
    }

    #[test]
    fn relocate_fires_for_user_drop_then_system_rename() {
        let events = vec![
            Ev::new(1, 1_000, "FileCreate", "DC01", EventSource::Disk)
                .at("C:\\Users\\beth\\Downloads\\coreupdater.exe"),
            Ev::new(2, 2_000, "FileRename", "DC01", EventSource::Disk)
                .at("C:\\Windows\\System32\\coreupdater.exe"),
        ];
        assert!(has_code(
            &run_correlations(&events),
            "CORR-MALWARE-RELOCATE"
        ));
    }

    #[test]
    fn persist_fires_for_create_then_service_install() {
        let events = vec![
            Ev::new(1, 1_000, "FileCreate", "DC01", EventSource::Disk)
                .at("C:\\Windows\\System32\\coreupdater.exe"),
            Ev::new(2, 2_000, "ServiceInstall", "DC01", EventSource::Evtx)
                .at("C:\\Windows\\System32\\coreupdater.exe"),
        ];
        assert!(has_code(&run_correlations(&events), "CORR-MALWARE-PERSIST"));
    }

    #[test]
    fn persist_fires_when_the_disk_create_has_an_unknown_host() {
        // Real-data shape: the FileCreate comes from MFT/USN (no hostname), the
        // 7045 ServiceInstall from EVTX (hostname set). SameHost must not reject a
        // disk artifact whose host is simply unknown — within one image every
        // event is the same host.
        let events = vec![
            Ev::new(1, 1_000, "FileCreate", "", EventSource::Disk)
                .at("coreupdater.exe")
                .host_none(),
            Ev::new(
                2,
                200_000_000_000,
                "ServiceInstall",
                "CITADEL-DC01",
                EventSource::Evtx,
            )
            .at("C:\\Windows\\System32\\coreupdater.exe"),
        ];
        assert!(
            has_code(&run_correlations(&events), "CORR-MALWARE-PERSIST"),
            "persist must fire across a no-host disk create and a hosted service install"
        );
    }

    #[test]
    fn relocate_fires_when_both_disk_events_have_unknown_host() {
        // FileCreate and FileRename both come from MFT/USN with no hostname; the
        // user-drop -> system-dir relocate must still fire (the scope admits the
        // unknown host). (Full-path reconstruction from USN is a separate concern;
        // here both paths carry their directory so the relocate semantics hold.)
        let events = vec![
            Ev::new(1, 1_000, "FileCreate", "", EventSource::Disk)
                .at("C:\\Users\\beth\\Downloads\\coreupdater.exe")
                .host_none(),
            Ev::new(2, 2_000, "FileRename", "", EventSource::Disk)
                .at("C:\\Windows\\System32\\coreupdater.exe")
                .host_none(),
        ];
        assert!(
            has_code(&run_correlations(&events), "CORR-MALWARE-RELOCATE"),
            "relocate must fire across two no-host disk events sharing a basename"
        );
    }

    #[test]
    fn bruteforce_fires_for_burst_then_success_same_ip() {
        let events = vec![
            Ev::new(1, 1_000, "LogonFailureBurst", "DC01", EventSource::Evtx)
                .ent(EntityRef::Ip("194.61.24.102".to_string())),
            Ev::new(2, 2_000, "LogonSuccess", "DC01", EventSource::Evtx)
                .ent(EntityRef::Ip("194.61.24.102".to_string())),
        ];
        assert!(has_code(
            &run_correlations(&events),
            "CORR-BRUTEFORCE-LOGON"
        ));
    }

    #[test]
    fn two_distinct_rules_fire_end_to_end() {
        // A persistence pair AND a brute-force pair in one input — the capstone
        // ">= 2 different rules" gate for the runner.
        let events = vec![
            Ev::new(1, 1_000, "FileCreate", "DC01", EventSource::Disk)
                .at("C:\\Windows\\System32\\coreupdater.exe"),
            Ev::new(2, 2_000, "ServiceInstall", "DC01", EventSource::Evtx)
                .at("C:\\Windows\\System32\\coreupdater.exe"),
            Ev::new(3, 5_000, "LogonFailureBurst", "DC01", EventSource::Evtx)
                .ent(EntityRef::Ip("194.61.24.102".to_string())),
            Ev::new(4, 6_000, "LogonSuccess", "DC01", EventSource::Evtx)
                .ent(EntityRef::Ip("194.61.24.102".to_string())),
        ];
        let corrs = run_correlations(&events);
        let fired = codes(&corrs);
        assert!(
            fired.iter().any(|c| c == "CORR-MALWARE-PERSIST"),
            "persist: {fired:?}"
        );
        assert!(
            fired.iter().any(|c| c == "CORR-BRUTEFORCE-LOGON"),
            "bruteforce: {fired:?}"
        );
        let distinct: std::collections::BTreeSet<&str> = fired.iter().map(String::as_str).collect();
        assert!(
            distinct.len() >= 2,
            "at least two distinct rule codes: {fired:?}"
        );
    }

    #[test]
    fn regconfirm_fires_for_service_install_then_run_key() {
        let events = vec![
            Ev::new(1, 1_000, "ServiceInstall", "DC01", EventSource::Evtx)
                .at("C:\\Windows\\System32\\coreupdater.exe"),
            Ev::new(2, 2_000, "RegistryModify", "DC01", EventSource::Registry)
                .at("C:\\Windows\\System32\\coreupdater.exe"),
        ];
        assert!(has_code(
            &run_correlations(&events),
            "CORR-PERSIST-REGCONFIRM"
        ));
    }

    #[test]
    fn unrelated_events_fire_nothing() {
        // Two FileCreates that share no basename/stem and no staging context.
        let events = vec![
            Ev::new(1, 1_000, "FileCreate", "DC01", EventSource::Disk).at("C:\\a\\report.docx"),
            Ev::new(
                2,
                9_999_999_999_999,
                "FileCreate",
                "DC01",
                EventSource::Disk,
            )
            .at("D:\\b\\photo.jpg"),
        ];
        assert!(
            run_correlations(&events).is_empty(),
            "{:?}",
            run_correlations(&events)
        );
    }

    #[test]
    fn run_with_memory_appends_memory_firings_to_disk_firings() {
        use issen_core::timeline::event::EntityRef;
        // Disk leg: a persistence pair (FileCreate -> ServiceInstall, same stem).
        let events = vec![
            Ev::new(1, 1_000, "FileCreate", "DC01", EventSource::Disk)
                .at("C:\\Windows\\System32\\coreupdater.exe"),
            Ev::new(2, 2_000, "ServiceInstall", "DC01", EventSource::Evtx)
                .at("C:\\Windows\\System32\\coreupdater.exe"),
        ];
        // Memory leg: an injected process beaconing to C2 in one dump.
        let memory = vec![
            MemEvent::new(10, 5_000, "Other(\"MemoryInjection\")", "DUMP-A")
                .with_entity(EntityRef::Process("spoolsv.exe".to_string()))
                .with_pid(880)
                .with_injection("injected-PE"),
            MemEvent::new(11, 5_000, "NetworkConnect", "DUMP-A")
                .with_entity(EntityRef::Process("spoolsv.exe".to_string()))
                .with_entity(EntityRef::Ip("203.78.103.109".to_string()))
                .with_pid(880)
                .with_state("ESTABLISHED"),
        ];
        let corrs = run_correlations_with_memory(&events, &memory);
        // Both a disk-leg and a memory-leg rule fire, in one vector.
        assert!(
            has_code(&corrs, "CORR-MALWARE-PERSIST"),
            "{:?}",
            codes(&corrs)
        );
        assert!(has_code(&corrs, "CORR-INJECTED-C2"), "{:?}", codes(&corrs));
    }

    #[test]
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    fn scales_to_a_large_disjoint_filecreate_slice_without_quadratic_blowup() {
        // Regression guard for the O(n^2) hang: a real DC timeline carries
        // ~111k FileCreate events. The pre-index runner cloned/scanned the ENTIRE
        // candidate slice for every anchor (run_exfil_stage cloned all N others
        // per anchor), so this slice took minutes of CPU. With the entity index,
        // each anchor only visits the candidates that share one of ITS OWN entity
        // refs, so a slice whose events pairwise share nothing is near-instant.
        //
        // The slice below has N FileCreates that share NO entity ref and NO
        // basename/stem with each other (so zero disk-leg correlations among
        // them), plus one genuine FileCreate -> ServiceInstall persistence pair
        // on a shared stem. The ONLY correlation that may fire is that one
        // CORR-MALWARE-PERSIST; we assert exactly that, and that the whole pass
        // completes well under a second.
        const N: u64 = 30_000;
        let mut events: Vec<Ev> = Vec::with_capacity(N as usize + 2);
        for i in 0..N {
            // Each event: unique path (no shared basename/stem) and a unique
            // entity ref (no shared join entity) -> structurally disjoint.
            events.push(
                Ev::new(i, 1_000 + i as i64, "FileCreate", "DC01", EventSource::Disk)
                    .at(&format!("C:\\noise\\u{i}\\f{i}.dat"))
                    .ent(EntityRef::FilePath(format!("noise-entity-{i}"))),
            );
        }
        // One genuine persistence pair (FileCreate -> ServiceInstall, same stem).
        events.push(
            Ev::new(N, 1_000, "FileCreate", "DC01", EventSource::Disk)
                .at("C:\\Windows\\System32\\coreupdater.exe"),
        );
        events.push(
            Ev::new(N + 1, 2_000, "ServiceInstall", "DC01", EventSource::Evtx)
                .at("C:\\Windows\\System32\\coreupdater.exe"),
        );

        let start = std::time::Instant::now();
        let corrs = run_correlations(&events);
        let elapsed = start.elapsed();

        let fired = codes(&corrs);
        assert_eq!(
            fired,
            vec!["CORR-MALWARE-PERSIST".to_string()],
            "only the one genuine persistence pair may fire: {fired:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "a {N}-event disjoint FileCreate slice must not be O(n^2); took {elapsed:?}"
        );
    }

    #[test]
    fn run_with_memory_matches_a_resident_process_to_its_on_disk_create() {
        use issen_core::timeline::event::EntityRef;
        // A disk FileCreate of coreupdater.exe and a memory ProcessExec for the
        // same image -> the cross-leg CORR-PROC-DISK-MATCH fires through the seam.
        let events = vec![Ev::new(1, 500, "FileCreate", "DC01", EventSource::Disk)
            .at("C:\\Windows\\System32\\coreupdater.exe")];
        let memory = vec![MemEvent::new(10, 5_000, "ProcessExec", "DUMP-A")
            .with_entity(EntityRef::Process("coreupdater.exe".to_string()))
            .with_pid(3644)];
        let corrs = run_correlations_with_memory(&events, &memory);
        assert!(
            has_code(&corrs, "CORR-PROC-DISK-MATCH"),
            "{:?}",
            codes(&corrs)
        );
    }

    #[test]
    fn progress_reports_every_rule_and_matches_the_plain_run() {
        use std::collections::BTreeSet;
        use std::sync::{Arc, Mutex};

        use issen_core::timeline::event::EntityRef;

        // A disk-leg persistence pair plus a memory-leg injected-C2 pair, so the
        // progress run drives both legs through the start_rule callback.
        let events = vec![
            Ev::new(1, 1_000, "FileCreate", "DC01", EventSource::Disk)
                .at("C:\\Windows\\System32\\coreupdater.exe"),
            Ev::new(2, 2_000, "ServiceInstall", "DC01", EventSource::Evtx)
                .at("C:\\Windows\\System32\\coreupdater.exe"),
        ];
        let memory = vec![
            MemEvent::new(10, 5_000, "Other(\"MemoryInjection\")", "DUMP-A")
                .with_entity(EntityRef::Process("spoolsv.exe".to_string()))
                .with_pid(880)
                .with_injection("injected-PE"),
            MemEvent::new(11, 5_000, "NetworkConnect", "DUMP-A")
                .with_entity(EntityRef::Process("spoolsv.exe".to_string()))
                .with_entity(EntityRef::Ip("203.78.103.109".to_string()))
                .with_pid(880)
                .with_state("ESTABLISHED"),
        ];

        // Record each rule name the runner starts. The guard returned per rule is
        // a unit value held for the rule's duration; recording happens on claim.
        let started: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let started_for_cb = Arc::clone(&started);
        let start_rule = move |name: &str| {
            started_for_cb
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(name.to_string());
        };

        let progress = run_correlations_with_memory_progress(&events, &memory, &start_rule);
        let plain = run_correlations_with_memory(&events, &memory);

        // Identical findings (same set of codes) as the non-progress path.
        assert_eq!(
            codes(&progress).into_iter().collect::<BTreeSet<_>>(),
            codes(&plain).into_iter().collect::<BTreeSet<_>>(),
            "progress run must produce the identical findings set"
        );

        // Every rule was announced through start_rule (disk + memory legs).
        let reported: BTreeSet<String> = started
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect();
        for rule in [
            "relocate",
            "persist",
            "copy-delete",
            "bruteforce",
            "logon-malware",
            "exfil-stage",
            "regconfirm",
            "lateral-move",
            "memory",
        ] {
            assert!(
                reported.contains(rule),
                "rule {rule:?} must be announced; got {reported:?}"
            );
        }
    }
}
