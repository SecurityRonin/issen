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
- **Why `DELETE … WHERE ingest_unit_id` first:** a huge artifact may have flushed *some* batches before
  the crash (we cannot hold millions of events in one transaction). The delete clears any partial
  residue so the re-parse cannot duplicate. This makes resume correct **regardless of batch
  granularity** — the universal backstop. (Requires `ingest_unit_id` indexed.)
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
