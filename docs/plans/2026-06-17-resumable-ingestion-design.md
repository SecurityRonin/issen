# Resumable Ingestion + Per-Artifact-Type Progress — Design

**Status:** draft for Codex critique (2026-06-17). Author: Claude (Opus 4.8).
**Why:** real ingests run for hours (USN+MFT are the multi-GB backbone; nested volumes are
compressed containers that explode to even larger). An interruption must not throw away hours of
work, and the analyst needs per-artifact-type progress + an ingestion log.

## Executive Summary

Today `run_auto` buffers **every event in RAM** (`CollectingEmitter` = `Mutex<Vec<TimelineEvent>>`)
and the CLI persists once at the end (`inseissen_batch(&events)`). There is no per-artifact
durability, no streaming, and progress is a single global counter. So: (a) huge artifacts risk OOM,
and (b) nothing is resumable. The fix is a **streaming, unit-checkpointed ingestion**:

- The unit of work is **(artifact, parser)** with a stable, reproducible `unit_id`.
- Each unit's events are flushed to DuckDB and the unit is marked complete **in one atomic commit**,
  so "events flushed" and "unit complete" can never disagree across a crash.
- **Resume is the default**: re-run parses only the units not marked complete (idempotently);
  `--refresh` (CLI) / `ingest.refresh` (config) forces a clean re-ingest.
- Progress is **per-artifact-type** with **intra-artifact byte progress for the backbone** (USN/MFT),
  driven by discovery's per-type byte totals.

This subsumes the unified-timeline Phase-4 substrate (per-event provenance, manifest-keyed cache,
partial-ingest honesty) and feeds the #114 CoverageManifest (the ingest log *is* the coverage data).

## Unit of work + stable identity

- **Unit = (artifact_id, parser_name).** All-match dispatch runs N parsers per artifact (registry
  hives ~12); each parser's output is an independent, separately-resumable batch.
- **`unit_id` must be reproducible across runs** (resume matches by it). For a loose file:
  `evidence_relpath + parser`. For a nested-container artifact: `container_identity + inner_relpath +
  parser`, where `container_identity` is a content hash of the container header (stable across
  re-runs; path alone is not, since extraction dirs are temp).
- **`evidence_key`**: canonical evidence path + size/mtime (or content hash). Resume only honors
  completed units whose `evidence_key` matches the current evidence — you cannot resume against a
  different image.

## The ingestion log lives IN the DuckDB (atomic completion — the load-bearing choice)

A file-based log has a crash window: commit DB → (crash) → log not written → resume re-parses → the
committed events duplicate. Eliminate the window by putting the log in the **same transactional
store** as the events:

```sql
CREATE TABLE ingest_log (
  unit_id        VARCHAR PRIMARY KEY,
  evidence_key   VARCHAR NOT NULL,
  artifact_type  VARCHAR NOT NULL,
  parser         VARCHAR NOT NULL,
  bytes          BIGINT,
  event_count    BIGINT,
  status         VARCHAR NOT NULL,   -- 'complete' (only complete is ever written durably)
  started_at     TIMESTAMP,
  completed_at   TIMESTAMP
);
```

Every timeline event carries **`ingest_unit_id`** (provenance — Phase 4). A unit completes by, in one
transaction: insert its events → upsert its `ingest_log` row `status='complete'` → COMMIT. Because the
events and the completion marker commit atomically, the DB is always consistent at the last committed
unit.

## Resume algorithm (idempotent, parallel-safe — generalizes the "next after last complete" model)

```
units      = discover()                       # deterministic, sorted order
done       = SELECT unit_id FROM ingest_log
             WHERE status='complete' AND evidence_key = :ek
for unit in units where unit.id not in done:        # the COMPLEMENT, not "the last"
    BEGIN
      DELETE FROM timeline WHERE ingest_unit_id = unit.id   # clear any partial flush
      events = parse(unit)                                  # only on clean EOF -> proceed
      INSERT events ; UPSERT ingest_log(unit.id, ..., 'complete')
    COMMIT
```

- **Why the complement, not "the last":** the pipeline is rayon-parallel, so completion order ≠
  discovery order and many units are in flight at once — "last complete" is not a single point.
  Re-doing *every unit not marked complete* is the correct generalization. Under sequential
  processing it reduces exactly to the user's model: the not-complete set is {the interrupted unit} ∪
  {not-yet-started}, processed in order, so the interrupted one is redone first.
- **The store already dedups on `record_hash`** (`insert_batch_at_epoch` anti-joins the staged batch
  against existing rows). So for a **deterministic** parser, re-parsing an incomplete unit re-emits
  identical `record_hash`es and the duplicates are dropped *automatically* — resume is idempotent for
  free. The `DELETE … WHERE ingest_unit_id=?` is therefore **not the primary mechanism**; it is a
  backstop for **non-deterministic** parsers (a re-parse that produces different `record_hash`es —
  e.g. a parser folding wall-clock or RNG into a field) and for reclaiming space from a partial unit.
  Reuse the existing dedup-insert primitive per-unit; reach for delete-partial only where determinism
  isn't guaranteed. (Requires `ingest_unit_id` indexed if used.)
- **Reuse, don't rebuild:** the `StoreEmitter` calls the existing `insert_batch_at_epoch` (Appender +
  set-based dedup-insert, file-backed) per unit, wrapped with the `ingest_log` upsert in the same
  transaction. The DB layer already exists; this design changes *when/by whom* it is called (per-unit,
  streaming) and adds the completion log + provenance column.
- **"Verified complete" = parser reached clean EOF** (not an error/truncation) **AND** the commit
  succeeded. A parser that errors or hits truncation mid-stream leaves the unit not-complete → redone.

## Streaming emitter under parallel parse (single-writer reconciliation)

DuckDB is single-writer. Replace `CollectingEmitter` with a **`StoreEmitter`**: rayon parser workers
produce per-unit event batches into a bounded channel; a **single writer thread** drains it and does
the per-unit transaction (delete-partial → insert → mark-complete → commit). This keeps parse parallel
while serializing DB writes, and bounds memory to a few in-flight unit-batches instead of the whole
case. Backbone artifacts may sub-batch within a unit (writer commits sub-batches but only writes the
`complete` marker at EOF; delete-partial-on-resume covers the sub-batched residue).

## Per-artifact-type progress (+ intra-artifact for the backbone)

- Discovery yields, per `ArtifactType`, `{total_units, total_bytes}` up front (for non-nested).
- Extend `ProgressReporter` (today: 4 global atomics) to a **per-type map**:
  `type -> {total_bytes, done_bytes, total_units, done_units, in_flight_unit, in_flight_bytes}`.
- **Intra-artifact byte progress for USN/MFT** (else a multi-GB bar sits at 0% then jumps to 100%):
  the parser API gains a progress hook (a `ProgressSink` passed to `parse`) so the parser reports
  bytes-consumed incrementally. `indicatif::MultiProgress` (already a dep) renders one bar per active
  type + a global ETA.

## Nested volumes (the wildcard — can exceed USN+MFT once decompressed)

- **Recursive discovery**: a container unit, on expansion, *enqueues* inner units; the total
  denominator **grows as containers expand**, so progress shows known + discovered-so-far with an
  honest "expanding…" state and a revised total.
- **Resume at inner-unit granularity**: inner units keyed by `container_identity + inner_relpath +
  parser`. A half-expanded VHD/VSS resumes at its first incomplete inner unit; already-complete inner
  units are skipped (container re-mount/re-extract may repeat, but inner work does not).
- **Bounded + dedup**: depth cap + total-bytes/inode budget (decompression-bomb defense), and VSS
  snapshot dedup (CoW/hash) so near-identical snapshots aren't re-expanded N times. Provenance tags
  every nested artifact with its container/snapshot (so "file as of VSS snapshot 3" ≠ "live file").

## Refresh vs resume

- **Resume = default.** `--refresh` CLI flag + `ingest.refresh` config force a clean re-ingest:
  `DELETE FROM timeline WHERE evidence_key=:ek; DELETE FROM ingest_log WHERE evidence_key=:ek;` then
  ingest from scratch (or write to a fresh DB). Refresh = clean slate for that evidence; never a
  silent append (which would duplicate).

## Crash safety

DuckDB is ACID with its own WAL; an interrupted process leaves the DB at the last committed
transaction. Because each unit's (events + completion) commit atomically, the DB is always consistent
and resume is exact — the only redone work is the unit(s) in flight at crash time.

## Codex critique (folded in — 2026-06-17): the keystone is the parser-completion contract

Codex confirmed the direction but proved every prerequisite is **absent today** and that the
correctness story was overstated. The load-bearing correction reorders the whole plan:

- **`Ok(ParseStats)` does NOT mean "complete" — this is risk #1 (silent data loss).** `parse` returns
  `Result<ParseStats, RtError>` where `Ok` means only "not unrecoverable." MFT returns `Ok` with zero
  events on empty / too-small / init-failed input (`mft.rs:211,217,229` — lenient *skip* paths); USN
  returns `Ok` regardless of recovered errors (`usnjrnl.rs:84,94`). An `ingest_log` built on `Ok`
  would durably mark **partial or skipped units as complete** → resume skips them → permanent silent
  loss. **Fix the contract first:** `parse` must return an explicit terminal status —
  `Complete | CompleteWithRecoveries | Incomplete{offset,reason} | Unsupported | CorruptFatal` — and a
  unit is marked complete ONLY on an explicit `Complete(WithRecoveries)`, never inferred from `Ok`.
  "Zero events" is a valid completion *only* paired with an explicit complete status (distinguishes
  "valid empty" from "skipped invalid" and from "never ran").
- **Completion is tied to the writer's COMMIT ack, not the parser thread.** `emit_batch` today returns
  `Ok` even if the mutex lock fails, silently dropping events (`orchestrator.rs:65-69`). The unit's
  `complete` marker must be written by the single writer only after its transaction commits — never by
  the worker that produced the events.
- **MFT byte-progress is wrong, not just imprecise.** MFT `read_all`s the whole file *before* entry
  iteration (`mft.rs:177,226`), so a byte bar hits 100% then stalls during the real work. Intra-artifact
  progress must be **per-parser-semantic**: MFT = entry index / `entry_count`; USN = byte offset (but
  it skips zero-filled regions). So the progress hook is parser-specific, not a generic byte sink.
- **`deterministic` capability already exists** (`traits.rs:12`) but the orchestrator ignores it. Gate
  the "dedup makes re-parse idempotent for free" reasoning on it; non-deterministic parsers need the
  delete-partial path (and `record_hash` excludes metadata/tags/entity_refs/epoch, so it is not a
  full-content identity).
- **Concurrency is undefined** — `TimelineStore::open` takes no case-level lock; concurrent
  `issen ingest` / resume / `--refresh` against one DuckDB file is unspecified. MVP needs an ingest
  lock/lease + a clear "another ingest owns this case" error.
- **Nested-volume resume isn't honest** unless expansion/enumeration is itself checkpointed: you must
  re-expand (re-pay decompression) just to enumerate inner units. Defer entirely.
- **Schema migration is missing** — no `ingest_log`, no `timeline.ingest_unit_id`, no indexes; the
  initializer is additive-only. Existing case DBs need an explicit migration + a legacy-rows policy
  (treat as immutable; no resume on pre-`ingest_log` DBs).
- **Reuse the appender staging**, don't introduce a per-row writer thread — the existing
  stage-table + set-based dedup-insert is a stronger foundation; on USN/MFT the DB writer + anti-join
  is the throughput ceiling, so a naive writer thread serializes away parallelism. Keep parsing
  parallel but the per-unit commit is the real cost; size transactions accordingly.

### Revised MVP (loose files only; defer nested volumes, VSS dedup, dynamic denominators, intra-artifact progress)

1. **Parser completion contract** (risk #1) — terminal-status enum; fix MFT/USN lenient paths so
   invalid input is not silently equivalent to clean zero-event completion. *Prerequisite for trusting
   any resume.*
2. **Schema + migration** — `timeline.ingest_unit_id`, `ingest_log` table, indexes
   `ingest_log(evidence_key,status)` + `timeline(ingest_unit_id)`; additive migration in the
   initializer; legacy rows = immutable (no resume).
3. **Per-unit transaction in the store** — `begin → DELETE this unit's rows → stage/insert events →
   upsert ingest_log 'complete' → commit`, adapting the existing appender path. Complete marker only
   after commit.
4. **Stable unit IDs for loose artifacts** — root-relative normalized path + parser + evidence_key;
   **deterministic sorted discovery** (also fixes mode 6E ordering).
5. **Unit-level streaming** — MFT/USN already emit in 1000-event batches; route those per-unit to the
   store instead of buffering in `CollectingEmitter`.
6. **Case-level ingest lock** + a clear error when another ingest owns the DB; `--refresh` deletes
   this evidence_key's rows under the lock before re-ingest.

Target: survive kill/restart for loose USN/MFT/EVTX with **no duplicates, no false completion**, and a
clear lock error. Per-type/intra-artifact progress and nested volumes are phase 2+.

## Open questions for Codex

1. DuckDB: can a single unit's transaction hold millions of inserts without OOM, or must we always
   sub-batch + rely on delete-partial? Is `DELETE … WHERE ingest_unit_id=?` cheap with an index at
   100M-row scale?
2. Single-writer-thread + bounded channel vs. one DuckDB connection per worker (DuckDB supports
   concurrent appenders?) — which is simpler and faster without losing the atomic per-unit commit?
3. `container_identity` for resume: is a container-header content hash stable + cheap enough, or is
   there a better reproducible key for VHD/VHDX/E01/VSS?
4. Intra-artifact progress hook: thread a `ProgressSink` through `ForensicParser::parse`, or have the
   `StoreEmitter` infer progress from event byte-offsets? Which is less invasive across 26 parsers?
5. Is per-(artifact,parser) the right unit granularity, or per-artifact (coarser log, re-runs all
   parsers on an interrupted hive)? Trade-off: log-row count vs. resume waste.
6. Determinism: parallel completion order ≠ discovery order; resume is set-based so it's fine, but the
   emitted timeline must still be globally sorted (the existing unsorted-output bug, mode 6E) — does
   streaming-to-DB + final `ORDER BY` fully resolve it, or does narrative/jsonl need an explicit sort?
7. Any failure mode where a unit is marked complete but is actually partial (e.g., a parser that
   returns Ok on truncated input — the zero-event/partial-event stub problem)? How to make "clean EOF"
   trustworthy per parser?
