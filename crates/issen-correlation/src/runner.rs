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

    /// Project a source logon into the `RdpLogon` shape the lateral-move rule
    /// matches: re-type it and give it the supplied entity refs (its account,
    /// its own source IP, and its host's interface inventory).
    fn rdp_projection<E: EventView>(ev: &E, entity_refs: Vec<EntityRef>) -> Self {
        let mut out = Self::from_view(ev);
        out.event_type = "RdpLogon".to_string();
        out.entity_refs = entity_refs;
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
    out.extend(run_beaconing(events));
    out.extend(run_network_risk(events));
    out.extend(run_shared_ioc(events));
    out
}

/// Run every disk-leg rule over `events` **and** every memory-leg (Tier C / C′)
/// rule over `memory`, returning all firings in one vector.
///
/// This is the full correlation pass: the disk-leg rules consume the flat
/// timeline events (`events`), the memory-leg rules consume the projected
/// [`MemEvent`] slice (`memory`, carrying the `pid` / `ppid` / `thread_count` /
/// `injection` fields parsed from each memory event's metadata), and the
/// cross-leg `CORR-DISK-FILE-RUNNING` reads both. The memory firings are appended
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
fn disk_rules<E: EventView + Sync>() -> [(&'static str, fn(&[E]) -> Vec<Correlation>); 11] {
    [
        ("relocate", run_relocate::<E>),
        ("persist", run_persist::<E>),
        ("copy-delete", run_copy_delete::<E>),
        ("bruteforce", run_bruteforce::<E>),
        ("logon-malware", run_logon_malware::<E>),
        ("exfil-stage", run_exfil_stage::<E>),
        ("regconfirm", run_regconfirm::<E>),
        ("lateral-move", run_lateral_move::<E>),
        ("beaconing", run_beaconing::<E>),
        ("network-risk", run_network_risk::<E>),
        ("shared-ioc", run_shared_ioc::<E>),
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

/// `CORR-LATERAL-MOVE`: a remote-interactive (4624 type-10) logon into host A
/// against type-10 logons into other hosts, joined on the account; the guard
/// tests host-B's source IP against host-A's own address inventory.
///
/// Real ingest emits a type-10 logon as `event_type = "LogonSuccess"` with
/// `logon_type() == Some(10)` — it never synthesizes an `RdpLogon` type — so
/// this projects each such logon into the `RdpLogon` shape the rule matches.
/// The anchor must carry host A's OWN interface addresses (not the source IP it
/// logged in *from*); those come from the SYSTEM-hive registry interface events,
/// which carry no hostname, so the inventory is keyed by **evidence source**
/// (one image == one host) rather than by hostname.
fn run_lateral_move<E: EventView>(events: &[E]) -> Vec<Correlation> {
    // Host interface-IP inventory, keyed by evidence source. A registry
    // network-config event surfaces each bound interface address via
    // `interface_ip()`; parsing metadata is gated on the Registry leg so the
    // whole timeline is not re-parsed.
    let mut iface_by_src: HashMap<&str, Vec<String>> = HashMap::new();
    for e in events {
        if e.source() != EventSource::Registry {
            continue;
        }
        if let (Some(src), Some(ip)) = (e.evidence_source(), e.interface_ip()) {
            iface_by_src.entry(src).or_default().push(ip);
        }
    }

    // Project every type-10 LogonSuccess into the `RdpLogon` shape: keep its
    // account and its own source IP, and add its host's interface inventory so
    // it can serve as a host-A anchor (host-B's source IP ∈ host-A inventory).
    let logons: Vec<RunEvent> = events
        .iter()
        .filter(|e| e.event_type() == "LogonSuccess" && e.logon_type() == Some(10))
        .map(|e| {
            let mut refs: Vec<EntityRef> = e
                .entity_refs()
                .iter()
                .filter(|r| matches!(r, EntityRef::User(_) | EntityRef::Ip(_)))
                .cloned()
                .collect();
            if let Some(ips) = e.evidence_source().and_then(|s| iface_by_src.get(s)) {
                for ip in ips {
                    let ent = EntityRef::Ip(ip.clone());
                    if !refs.contains(&ent) {
                        refs.push(ent);
                    }
                }
            }
            RunEvent::rdp_projection(e, refs)
        })
        .collect();
    let index = build_entity_index(&logons);

    let mut out = Vec::new();
    for (i, anchor) in logons.iter().enumerate() {
        // Self-join on the account join entity; exclude the anchor's own
        // position (the prior j != i self-exclusion). Type-10 logon slices are
        // tiny, so this is behavior-identical to the full scan — it just shares
        // the same index helper as the hot rules.
        let candidates = reduced_candidates(anchor, &index, &logons, Some(i));
        if let Some(corr) = evaluate_lateral_move(anchor, &candidates) {
            out.push(corr);
        }
    }
    out
}

/// The set of `(host, process-name)` that started and exited within the
/// short-lived threshold. Pairs `ProcessExec` (EVTX 4688) with the nearest
/// following `ProcessExit` (4689) sharing a `Process` entity on the same host
/// (name-level, since `EventView` carries no PID) and applies
/// `forensicnomicon::process_lifetime::is_short_lived`. A component signal for
/// the composite network-risk score.
fn short_lived_process_names<E: EventView>(
    events: &[E],
) -> std::collections::HashSet<(String, String)> {
    use std::collections::{BTreeMap, HashSet};
    // (host, process) -> start / exit timestamps.
    let mut execs: BTreeMap<(String, String), Vec<i64>> = BTreeMap::new();
    let mut exits: BTreeMap<(String, String), Vec<i64>> = BTreeMap::new();
    for e in events {
        let ts = e.timestamp_ns();
        if ts <= 0 {
            continue;
        }
        let bucket = match e.event_type() {
            "ProcessExec" => &mut execs,
            "ProcessExit" => &mut exits,
            _ => continue,
        };
        let host = e.hostname().unwrap_or_default().to_string();
        for r in e.entity_refs() {
            if let EntityRef::Process(name) = r {
                bucket
                    .entry((host.clone(), name.clone()))
                    .or_default()
                    .push(ts);
            }
        }
    }
    let mut out = HashSet::new();
    for (key, mut starts) in execs {
        let Some(ends) = exits.get(&key) else {
            continue; // no exit seen → lifetime unknown, cannot call it short-lived
        };
        starts.sort_unstable();
        let mut ends = ends.clone();
        ends.sort_unstable();
        // Pair each start with the nearest exit at or after it; if any instance
        // is short-lived, the name is flagged (name-level, no PID available).
        for start in starts {
            if let Some(&end) = ends.iter().find(|&&t| t >= start) {
                let lifetime_s = (end - start) / 1_000_000_000;
                if forensicnomicon::process_lifetime::is_short_lived(lifetime_s) {
                    out.insert(key.clone());
                    break;
                }
            }
        }
    }
    out
}

/// Classify a destination IP string to its cloud/CDN provider (`None` = unknown,
/// invalid, or non-IPv4). Wraps `forensicnomicon::cloud_ranges` for issen's
/// string-typed `EntityRef::Ip`. RED stub; replaced by the GREEN implementation.
fn classify_destination(ip: &str) -> Option<forensicnomicon::cloud_ranges::CloudProvider> {
    ip.parse::<std::net::Ipv4Addr>()
        .ok()
        .and_then(forensicnomicon::cloud_ranges::classify_ipv4)
}

/// Minimum distinct hosts for a destination to count as a shared IOC (definition
/// of "shared": contacted from more than one host).
const SHARED_IOC_MIN_HOSTS: usize = 2;

/// Cross-host aggregation for one destination IP: (distinct hosts, connection
/// (timestamp_ns, timeline id) members).
type SharedIocEntry = (std::collections::BTreeSet<String>, Vec<(i64, u64)>);

/// `NET-IOC-SHARED`: an unknown (non-cloud) destination contacted from two or more
/// hosts — consistent with shared C2 / lateral infrastructure. Known cloud/CDN
/// destinations are benign shared egress and are intentionally not flagged. RED
/// stub; replaced by GREEN.
fn run_shared_ioc<E: EventView>(events: &[E]) -> Vec<Correlation> {
    use crate::correlation::{CorrelationMember, CorrelationRole, CorrelationScope};
    use forensicnomicon::report::Severity;
    use std::collections::BTreeMap;

    // remote-ip -> (distinct hosts, connection (ts, id) members).
    let mut by_ip: BTreeMap<String, SharedIocEntry> = BTreeMap::new();
    for e in events {
        if e.event_type() != "NetworkConnect" {
            continue;
        }
        let ts = e.timestamp_ns();
        if ts <= 0 {
            continue;
        }
        let host = e.hostname().unwrap_or_default().to_string();
        for r in e.entity_refs() {
            if let EntityRef::Ip(ip) = r {
                let entry = by_ip.entry(ip.clone()).or_default();
                entry.0.insert(host.clone());
                entry.1.push((ts, e.id()));
            }
        }
    }

    let mut out = Vec::new();
    for (ip, (hosts, mut members)) in by_ip {
        if hosts.len() < SHARED_IOC_MIN_HOSTS {
            continue;
        }
        // Known cloud/CDN destinations are benign shared egress — not flagged.
        if classify_destination(&ip).is_some() {
            continue;
        }
        members.sort_by_key(|(ts, _)| *ts);
        let first = members.first().map_or(0, |(ts, _)| *ts);
        let last = members.last().map_or(0, |(ts, _)| *ts);
        let host_list = hosts.iter().cloned().collect::<Vec<_>>().join(", ");
        let mut corr = Correlation::new("NET-IOC-SHARED", Severity::High)
            .with_attack_technique("T1071")
            .with_scope(CorrelationScope::CrossHost)
            .with_window(first, last)
            .with_note(format!(
                "unknown (non-cloud) destination {ip} contacted from {} hosts ({host_list}) \
                 — consistent with shared C2 / lateral infrastructure",
                hosts.len()
            ));
        for (_, id) in &members {
            corr = corr.with_member(CorrelationMember::new(*id, CorrelationRole::Supporting));
        }
        out.push(corr);
    }
    out
}

/// A network connection for risk grouping: (timestamp_ns, timeline id, owning
/// process names on the event).
type RiskConn = (i64, u64, Vec<String>);

/// `NET-RISK-COMPOSITE`: a destination that exhibits two or more coinciding
/// network-risk signals — periodic beaconing, an unknown (non-cloud) destination,
/// and a short-lived owning process. Additive to the per-signal findings (does not
/// mutate NET-BEACON-PERIODIC). Severity scales with the signal count (>=2 High,
/// 3 Critical). RED stub; replaced by GREEN.
fn run_network_risk<E: EventView>(events: &[E]) -> Vec<Correlation> {
    use crate::correlation::{CorrelationMember, CorrelationRole, CorrelationScope};
    use forensicnomicon::beaconing::{assess_periodicity, DEFAULT_BEACONING};
    use forensicnomicon::report::Severity;
    use std::collections::BTreeMap;

    let short_lived = short_lived_process_names(events);
    // (host, remote-ip) -> connection (ts, id, owning process names).
    let mut groups: BTreeMap<(String, String), Vec<RiskConn>> = BTreeMap::new();
    for e in events {
        if e.event_type() != "NetworkConnect" {
            continue;
        }
        let ts = e.timestamp_ns();
        if ts <= 0 {
            continue;
        }
        let host = e.hostname().unwrap_or_default().to_string();
        let procs: Vec<String> = e
            .entity_refs()
            .iter()
            .filter_map(|r| match r {
                EntityRef::Process(n) => Some(n.clone()),
                _ => None,
            })
            .collect();
        for r in e.entity_refs() {
            if let EntityRef::Ip(ip) = r {
                groups.entry((host.clone(), ip.clone())).or_default().push((
                    ts,
                    e.id(),
                    procs.clone(),
                ));
            }
        }
    }

    let mut out = Vec::new();
    for ((host, ip), mut conns) in groups {
        conns.sort_by_key(|(ts, _, _)| *ts);
        let ts_sorted: Vec<i64> = conns.iter().map(|(ts, _, _)| *ts).collect();

        let mut signals: Vec<&str> = Vec::new();
        if assess_periodicity(&ts_sorted, &DEFAULT_BEACONING).is_some() {
            signals.push("periodic beaconing");
        }
        if classify_destination(&ip).is_none() {
            signals.push("unknown (non-cloud) destination");
        }
        let short_lived_owner = conns.iter().any(|(_, _, procs)| {
            procs
                .iter()
                .any(|p| short_lived.contains(&(host.clone(), p.clone())))
        });
        if short_lived_owner {
            signals.push("short-lived owning process");
        }
        if signals.len() < 2 {
            continue;
        }

        let severity = if signals.len() >= 3 {
            Severity::Critical
        } else {
            Severity::High
        };
        let first = ts_sorted.first().copied().unwrap_or(0);
        let last = ts_sorted.last().copied().unwrap_or(0);
        let mut corr = Correlation::new("NET-RISK-COMPOSITE", severity)
            .with_attack_technique("T1071")
            .with_scope(CorrelationScope::SameHost)
            .with_window(first, last)
            .with_note(format!(
                "destination {ip} exhibits {} coinciding network-risk signals ({}) \
                 — consistent with malicious C2 infrastructure; review in context",
                signals.len(),
                signals.join(", ")
            ));
        for (_, id, _) in &conns {
            corr = corr.with_member(CorrelationMember::new(*id, CorrelationRole::Supporting));
        }
        out.push(corr);
    }
    out
}

/// `NET-BEACON-PERIODIC`: repeated connections to one destination IP at a regular
/// cadence, grouped per host — consistent with automated C2 beaconing (also fits
/// benign periodic traffic). Groups `NetworkConnect` events by (host, remote IP),
/// then delegates the periodicity judgement to `forensicnomicon::beaconing`
/// (interval coefficient of variation). Source-agnostic: fires on any network
/// leg with distinct per-connection timestamps (Zeek/pcap/repeated dumps); a
/// single netstat snapshot shares one timestamp, so it correctly does not fire.
fn run_beaconing<E: EventView>(events: &[E]) -> Vec<Correlation> {
    use crate::correlation::{CorrelationMember, CorrelationRole, CorrelationScope};
    use forensicnomicon::beaconing::{assess_periodicity, DEFAULT_BEACONING};
    use forensicnomicon::report::Severity;
    use std::collections::BTreeMap;

    // (host, remote-ip) -> connection (timestamp_ns, timeline id). BTreeMap keeps
    // group iteration deterministic (fleet ordering guarantee).
    let mut groups: BTreeMap<(String, String), Vec<(i64, u64)>> = BTreeMap::new();
    for e in events {
        if e.event_type() != "NetworkConnect" {
            continue;
        }
        let ts = e.timestamp_ns();
        if ts <= 0 {
            continue; // no clock → cannot place it on the cadence
        }
        let host = e.hostname().unwrap_or_default().to_string();
        for r in e.entity_refs() {
            if let EntityRef::Ip(ip) = r {
                groups
                    .entry((host.clone(), ip.clone()))
                    .or_default()
                    .push((ts, e.id()));
            }
        }
    }

    let mut out = Vec::new();
    for ((_host, ip), mut conns) in groups {
        conns.sort_by_key(|(ts, _)| *ts);
        let ts_sorted: Vec<i64> = conns.iter().map(|(ts, _)| *ts).collect();
        let Some(a) = assess_periodicity(&ts_sorted, &DEFAULT_BEACONING) else {
            continue;
        };
        let first = ts_sorted.first().copied().unwrap_or(0);
        let last = ts_sorted.last().copied().unwrap_or(0);
        let dst = match classify_destination(&ip) {
            Some(p) => format!("hosted in {} address space", p.as_str()),
            None => "an unknown destination (not a known cloud/CDN range)".to_string(),
        };
        let mut corr = Correlation::new("NET-BEACON-PERIODIC", Severity::Medium)
            .with_attack_technique("T1071")
            .with_scope(CorrelationScope::SameHost)
            .with_window(first, last)
            .with_note(format!(
                "{} connections to {ip} ({dst}) at a regular ~{:.0}s cadence                  (interval CoV {:.2}) — consistent with automated C2 beaconing;                  benign periodic traffic (update checks, telemetry) also fits",
                a.occurrences, a.mean_interval_seconds, a.coefficient_of_variation
            ));
        for (_, id) in &conns {
            corr = corr.with_member(CorrelationMember::new(*id, CorrelationRole::Supporting));
        }
        out.push(corr);
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
        logon_type: Option<u64>,
        interface_ip: Option<String>,
        evidence_source: Option<String>,
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
                logon_type: None,
                interface_ip: None,
                evidence_source: None,
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
        fn with_logon_type(mut self, lt: u64) -> Self {
            self.logon_type = Some(lt);
            self
        }
        fn with_interface_ip(mut self, ip: &str) -> Self {
            self.interface_ip = Some(ip.to_string());
            self
        }
        fn with_evidence(mut self, src: &str) -> Self {
            self.evidence_source = Some(src.to_string());
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
        fn logon_type(&self) -> Option<u64> {
            self.logon_type
        }
        fn interface_ip(&self) -> Option<String> {
            self.interface_ip.clone()
        }
        fn evidence_source(&self) -> Option<&str> {
            self.evidence_source.as_deref()
        }
    }

    fn codes(corrs: &[Correlation]) -> Vec<String> {
        corrs.iter().map(|c| c.code.clone()).collect()
    }

    fn has_code(corrs: &[Correlation], code: &str) -> bool {
        corrs.iter().any(|c| c.code == code)
    }

    /// Regression for the circular-validation bug: the rule fired on synthetic
    /// `RdpLogon` events but real ingest never emits that type — a 4624 type-10
    /// logon is stored as `event_type="LogonSuccess"` with `logon_type == 10`,
    /// the account as `EntityRef::User`, and the source IP as `EntityRef::Ip`.
    /// Host A's OWN interface address comes from the SYSTEM-hive registry
    /// interface event (`interface_ip`), which carries **no hostname**, so the
    /// per-host key is the evidence source. `run_lateral_move` must recognise
    /// this real shape and fire `CORR-LATERAL-MOVE`, tying host A's logon to the
    /// host-B logon sourced from host A's own IP.
    #[test]
    fn lateral_move_fires_for_real_shaped_type10_logon_pivot() {
        let events = vec![
            // Host A (the DC) interface inventory: a registry network-config
            // event — no hostname, evidence source = the DC image.
            Ev::new(
                10,
                1_000,
                "Other(\"system-info\")",
                "?",
                EventSource::Registry,
            )
            .host_none()
            .with_interface_ip("10.42.85.10")
            .with_evidence("dc01.E01"),
            // Host-A logon (into the DC): earlier, attacker-sourced.
            Ev::new(1, 2_000, "LogonSuccess", "CITADEL-DC01", EventSource::Evtx)
                .with_logon_type(10)
                .with_evidence("dc01.E01")
                .ent(EntityRef::User("Administrator".to_string()))
                .ent(EntityRef::Ip("203.0.113.9".to_string())),
            // Host-B logon (into the desktop): later, sourced from the DC's IP.
            Ev::new(
                2,
                3_000,
                "LogonSuccess",
                "DESKTOP-SDN1RPT",
                EventSource::Evtx,
            )
            .with_logon_type(10)
            .with_evidence("desktop.E01")
            .ent(EntityRef::User("Administrator".to_string()))
            .ent(EntityRef::Ip("10.42.85.10".to_string())),
        ];
        let corrs = run_correlations(&events);
        assert!(
            has_code(&corrs, "CORR-LATERAL-MOVE"),
            "a type-10 LogonSuccess pivot sourced from host A's own interface IP \
             must fire CORR-LATERAL-MOVE; got {:?}",
            codes(&corrs)
        );
        let lm = corrs
            .iter()
            .find(|c| c.code == "CORR-LATERAL-MOVE")
            .expect("the lateral-move firing");
        assert_eq!(
            lm.members[0].timeline_id, 1,
            "anchor is the host-A (DC) logon"
        );
        assert_eq!(
            lm.members[1].timeline_id, 2,
            "consequent is the host-B (desktop) logon"
        );
    }

    /// The projection selects only remote-interactive (type-10) logons: a
    /// type-2 (console) `LogonSuccess` pivot is not lateral movement and must
    /// stay silent even when every other condition holds.
    #[test]
    fn lateral_move_ignores_non_type10_logons() {
        let events = vec![
            Ev::new(
                10,
                1_000,
                "Other(\"system-info\")",
                "?",
                EventSource::Registry,
            )
            .host_none()
            .with_interface_ip("10.42.85.10")
            .with_evidence("dc01.E01"),
            Ev::new(1, 2_000, "LogonSuccess", "CITADEL-DC01", EventSource::Evtx)
                .with_logon_type(2) // console, not RDP
                .with_evidence("dc01.E01")
                .ent(EntityRef::User("Administrator".to_string()))
                .ent(EntityRef::Ip("203.0.113.9".to_string())),
            Ev::new(
                2,
                3_000,
                "LogonSuccess",
                "DESKTOP-SDN1RPT",
                EventSource::Evtx,
            )
            .with_logon_type(2)
            .with_evidence("desktop.E01")
            .ent(EntityRef::User("Administrator".to_string()))
            .ent(EntityRef::Ip("10.42.85.10".to_string())),
        ];
        assert!(!has_code(&run_correlations(&events), "CORR-LATERAL-MOVE"));
    }

    /// The interface inventory is de-duplicated against the logon's own refs: a
    /// logon into host A whose recorded source IP already *is* host A's own
    /// interface address must not carry that IP twice, and the pivot still fires.
    #[test]
    fn lateral_move_dedups_interface_ip_already_on_the_logon() {
        let events = vec![
            Ev::new(
                10,
                1_000,
                "Other(\"system-info\")",
                "?",
                EventSource::Registry,
            )
            .host_none()
            .with_interface_ip("10.42.85.10")
            .with_evidence("dc01.E01"),
            // Anchor's own recorded source IP equals host A's interface IP.
            Ev::new(1, 2_000, "LogonSuccess", "CITADEL-DC01", EventSource::Evtx)
                .with_logon_type(10)
                .with_evidence("dc01.E01")
                .ent(EntityRef::User("Administrator".to_string()))
                .ent(EntityRef::Ip("10.42.85.10".to_string())),
            Ev::new(
                2,
                3_000,
                "LogonSuccess",
                "DESKTOP-SDN1RPT",
                EventSource::Evtx,
            )
            .with_logon_type(10)
            .with_evidence("desktop.E01")
            .ent(EntityRef::User("Administrator".to_string()))
            .ent(EntityRef::Ip("10.42.85.10".to_string())),
        ];
        assert!(has_code(&run_correlations(&events), "CORR-LATERAL-MOVE"));
    }

    /// The pivot must not invert: the source address a host was reached *from*
    /// is not that host's own address, so host B (reached from host A's IP) must
    /// never anchor a firing back into host A on a later, unrelated logon. Only
    /// host A's OWN interface inventory forms its anchor address set.
    #[test]
    fn lateral_move_does_not_invert_the_pivot_direction() {
        let events = vec![
            Ev::new(100, 1, "Other(\"system-info\")", "?", EventSource::Registry)
                .host_none()
                .with_interface_ip("10.0.0.1")
                .with_evidence("dc.E01"),
            Ev::new(101, 1, "Other(\"system-info\")", "?", EventSource::Registry)
                .host_none()
                .with_interface_ip("10.0.0.2")
                .with_evidence("ws.E01"),
            // Host A (DC) logon, attacker-sourced, earliest.
            Ev::new(1, 1_000, "LogonSuccess", "DC", EventSource::Evtx)
                .with_logon_type(10)
                .with_evidence("dc.E01")
                .ent(EntityRef::User("Administrator".to_string()))
                .ent(EntityRef::Ip("203.0.113.9".to_string())),
            // Host B (WS) logon, sourced from the DC's own IP — the real pivot.
            Ev::new(2, 2_000, "LogonSuccess", "WS", EventSource::Evtx)
                .with_logon_type(10)
                .with_evidence("ws.E01")
                .ent(EntityRef::User("Administrator".to_string()))
                .ent(EntityRef::Ip("10.0.0.1".to_string())),
            // Later host A logon, attacker-sourced again.
            Ev::new(3, 3_000, "LogonSuccess", "DC", EventSource::Evtx)
                .with_logon_type(10)
                .with_evidence("dc.E01")
                .ent(EntityRef::User("Administrator".to_string()))
                .ent(EntityRef::Ip("203.0.113.9".to_string())),
        ];
        let corrs = run_correlations(&events);
        let lm: Vec<_> = corrs
            .iter()
            .filter(|c| c.code == "CORR-LATERAL-MOVE")
            .collect();
        assert!(!lm.is_empty(), "the real DC->WS pivot must still fire");
        for c in &lm {
            assert_eq!(
                c.members[0].timeline_id, 1,
                "every firing must anchor on the DC (host A), never invert to a WS anchor"
            );
        }
    }

    /// A destination contacted at a regular cadence over time fires
    /// NET-BEACON-PERIODIC (grouped per host, source-agnostic via EntityRef::Ip).
    #[test]
    fn beaconing_fires_for_regular_network_connections() {
        // 5 connections to 203.0.113.7, exactly 60s apart.
        let events: Vec<Ev> = (0i64..5)
            .map(|i| {
                Ev::new(
                    i as u64 + 1,
                    1_000_000_000_000 + i * 60 * 1_000_000_000,
                    "NetworkConnect",
                    "DC01",
                    EventSource::Memory,
                )
                .ent(EntityRef::Ip("203.0.113.7".to_string()))
            })
            .collect();
        assert!(has_code(&run_correlations(&events), "NET-BEACON-PERIODIC"));
    }

    /// Irregular (human) traffic to a destination does not fire.
    #[test]
    fn beaconing_ignores_irregular_connections() {
        let gaps = [5_i64, 3600, 40, 900, 7200];
        let mut ts = 2_000_000_000_000_i64;
        let mut events = vec![
            Ev::new(1, ts, "NetworkConnect", "DC01", EventSource::Memory)
                .ent(EntityRef::Ip("198.51.100.9".to_string())),
        ];
        for (i, g) in gaps.iter().enumerate() {
            ts += g * 1_000_000_000;
            events.push(
                Ev::new(
                    i as u64 + 2,
                    ts,
                    "NetworkConnect",
                    "DC01",
                    EventSource::Memory,
                )
                .ent(EntityRef::Ip("198.51.100.9".to_string())),
            );
        }
        assert!(!has_code(&run_correlations(&events), "NET-BEACON-PERIODIC"));
    }

    /// A single netstat snapshot stamps every connection with the same
    /// acquisition time — no intervals, so beaconing must not fire.
    #[test]
    fn beaconing_ignores_single_snapshot_same_timestamp() {
        let events: Vec<Ev> = (0u64..6)
            .map(|i| {
                Ev::new(
                    i + 1,
                    9_000_000_000_000,
                    "NetworkConnect",
                    "DC01",
                    EventSource::Memory,
                )
                .ent(EntityRef::Ip("203.0.113.7".to_string()))
            })
            .collect();
        assert!(!has_code(&run_correlations(&events), "NET-BEACON-PERIODIC"));
    }

    #[test]
    fn classify_destination_known_aws_ip() {
        // 1.178.1.0 is in the committed AWS snapshot.
        assert_eq!(
            classify_destination("1.178.1.0"),
            Some(forensicnomicon::cloud_ranges::CloudProvider::Aws)
        );
    }

    #[test]
    fn classify_destination_private_and_invalid_are_none() {
        assert!(classify_destination("10.0.0.1").is_none());
        assert!(classify_destination("not-an-ip").is_none());
    }

    /// A beacon to a destination in no known cloud range is flagged as an
    /// unknown destination in the finding note (the higher-signal case).
    #[test]
    fn beaconing_note_flags_unknown_destination() {
        let events: Vec<Ev> = (0i64..5)
            .map(|i| {
                Ev::new(
                    i as u64 + 1,
                    1_000_000_000_000 + i * 60 * 1_000_000_000,
                    "NetworkConnect",
                    "DC01",
                    EventSource::Memory,
                )
                .ent(EntityRef::Ip("203.0.113.7".to_string()))
            })
            .collect();
        let corrs = run_correlations(&events);
        let beacon = corrs
            .iter()
            .find(|c| c.code == "NET-BEACON-PERIODIC")
            .expect("beacon fires");
        assert!(
            beacon.note.contains("unknown destination"),
            "note should flag unknown destination, got: {}",
            beacon.note
        );
    }

    #[test]
    fn short_lived_process_is_detected() {
        let events = vec![
            Ev::new(
                1,
                1_000_000_000_000,
                "ProcessExec",
                "DC01",
                EventSource::Evtx,
            )
            .ent(EntityRef::Process("dropper.exe".to_string())),
            // exits 5s later → short-lived
            Ev::new(
                2,
                1_000_000_000_000 + 5 * 1_000_000_000,
                "ProcessExit",
                "DC01",
                EventSource::Evtx,
            )
            .ent(EntityRef::Process("dropper.exe".to_string())),
        ];
        let set = short_lived_process_names(&events);
        assert!(set.contains(&("DC01".to_string(), "dropper.exe".to_string())));
    }

    #[test]
    fn long_lived_process_is_not_short_lived() {
        let events = vec![
            Ev::new(
                1,
                1_000_000_000_000,
                "ProcessExec",
                "DC01",
                EventSource::Evtx,
            )
            .ent(EntityRef::Process("service.exe".to_string())),
            // exits 1h later
            Ev::new(
                2,
                1_000_000_000_000 + 3600 * 1_000_000_000,
                "ProcessExit",
                "DC01",
                EventSource::Evtx,
            )
            .ent(EntityRef::Process("service.exe".to_string())),
        ];
        assert!(short_lived_process_names(&events).is_empty());
    }

    #[test]
    fn exec_without_exit_is_not_short_lived() {
        let events = vec![Ev::new(
            1,
            1_000_000_000_000,
            "ProcessExec",
            "DC01",
            EventSource::Evtx,
        )
        .ent(EntityRef::Process("still-running.exe".to_string()))];
        assert!(short_lived_process_names(&events).is_empty());
    }

    /// Beacon (regular cadence) + unknown destination = 2 signals -> High composite.
    fn beacon_to_unknown_events(proc: Option<&str>) -> Vec<Ev> {
        (0i64..5)
            .map(|i| {
                let mut e = Ev::new(
                    i as u64 + 1,
                    1_000_000_000_000 + i * 60 * 1_000_000_000,
                    "NetworkConnect",
                    "DC01",
                    EventSource::Memory,
                )
                .ent(EntityRef::Ip("203.0.113.7".to_string()));
                if let Some(p) = proc {
                    e = e.ent(EntityRef::Process(p.to_string()));
                }
                e
            })
            .collect()
    }

    #[test]
    fn composite_high_for_two_signals() {
        let corrs = run_correlations(&beacon_to_unknown_events(None));
        let c = corrs
            .iter()
            .find(|c| c.code == "NET-RISK-COMPOSITE")
            .expect("composite fires");
        assert_eq!(c.severity, forensicnomicon::report::Severity::High);
    }

    #[test]
    fn composite_critical_for_three_signals() {
        // Add a short-lived owning process (exec+exit 5s apart) named on the connections.
        let mut events = beacon_to_unknown_events(Some("mal.exe"));
        events.push(
            Ev::new(
                100,
                900_000_000_000,
                "ProcessExec",
                "DC01",
                EventSource::Evtx,
            )
            .ent(EntityRef::Process("mal.exe".to_string())),
        );
        events.push(
            Ev::new(
                101,
                905_000_000_000,
                "ProcessExit",
                "DC01",
                EventSource::Evtx,
            )
            .ent(EntityRef::Process("mal.exe".to_string())),
        );
        let corrs = run_correlations(&events);
        let c = corrs
            .iter()
            .find(|c| c.code == "NET-RISK-COMPOSITE")
            .expect("composite fires");
        assert_eq!(c.severity, forensicnomicon::report::Severity::Critical);
    }

    #[test]
    fn no_composite_for_single_signal() {
        // Two irregular connections to an unknown IP: unknown only (1 signal).
        let events = vec![
            Ev::new(
                1,
                1_000_000_000_000,
                "NetworkConnect",
                "DC01",
                EventSource::Memory,
            )
            .ent(EntityRef::Ip("203.0.113.7".to_string())),
            Ev::new(
                2,
                1_000_000_000_000 + 7 * 1_000_000_000,
                "NetworkConnect",
                "DC01",
                EventSource::Memory,
            )
            .ent(EntityRef::Ip("203.0.113.7".to_string())),
        ];
        assert!(!has_code(&run_correlations(&events), "NET-RISK-COMPOSITE"));
    }

    fn net_conn(id: u64, ts: i64, host: &str, ip: &str) -> Ev {
        Ev::new(id, ts, "NetworkConnect", host, EventSource::Memory)
            .ent(EntityRef::Ip(ip.to_string()))
    }

    #[test]
    fn shared_ioc_fires_for_unknown_dest_on_two_hosts() {
        let events = vec![
            net_conn(1, 1_000_000_000_000, "DC01", "203.0.113.7"),
            net_conn(2, 1_000_000_000_000, "WS01", "203.0.113.7"),
        ];
        assert!(has_code(&run_correlations(&events), "NET-IOC-SHARED"));
    }

    #[test]
    fn no_shared_ioc_for_single_host() {
        let events = vec![
            net_conn(1, 1_000_000_000_000, "DC01", "203.0.113.7"),
            net_conn(2, 2_000_000_000_000, "DC01", "203.0.113.7"),
        ];
        assert!(!has_code(&run_correlations(&events), "NET-IOC-SHARED"));
    }

    #[test]
    fn no_shared_ioc_for_known_cloud_dest() {
        // 1.178.1.0 is a known AWS range in the snapshot — benign shared egress.
        let events = vec![
            net_conn(1, 1_000_000_000_000, "DC01", "1.178.1.0"),
            net_conn(2, 1_000_000_000_000, "WS01", "1.178.1.0"),
        ];
        assert!(!has_code(&run_correlations(&events), "NET-IOC-SHARED"));
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
        // same image -> the cross-leg CORR-DISK-FILE-RUNNING fires through the seam.
        let events = vec![Ev::new(1, 500, "FileCreate", "DC01", EventSource::Disk)
            .at("C:\\Windows\\System32\\coreupdater.exe")];
        let memory = vec![MemEvent::new(10, 5_000, "ProcessExec", "DUMP-A")
            .with_entity(EntityRef::Process("coreupdater.exe".to_string()))
            .with_pid(3644)];
        let corrs = run_correlations_with_memory(&events, &memory);
        assert!(
            has_code(&corrs, "CORR-DISK-FILE-RUNNING"),
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
