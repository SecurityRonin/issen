# 18. Carving tiers — file-level carving is default-on; whole-disk carving is opt-in behind `--deleted`

Date: 2026-07-21
Status: Accepted (design; governs the sqlite-forensic + winevt-carver wiring)

## Context

The 2026-07-21 fleet-parser audit found deleted-record **carving** largely unwired:
`sqlite-forensic` (deleted-row / free-page / WAL) is entirely dark, `winevt-carver`
(unallocated ElfChnk) is unwired, and `issen-browser` reads only live rows. Wiring
carving into the default triage pipeline raises an obvious objection: **won't carving
be slow?** It depends entirely on *which* carving — and conflating the two kinds is
the mistake this ADR exists to prevent.

## Decision

Recognise **two distinct carving operations** with different cost and different homes:

### Tier 1 — file-level structured carving → DEFAULT-ON, inside the parser

Recovery that operates **within an artifact issen has already located and opened**:
- SQLite: the freelist pages, the WAL/rollback journal, and free space *inside the
  `.db` file*. The freelist is a linked list of pages; the WAL is usually small.
- EVTX: the unallocated `ElfChnk` regions *inside the `.evtx` being parsed*.

Cost is **O(the artifact's own free space)** — bounded by a file the parser is
already reading, so it's marginal incremental work on top of the parse already paid
for (a browser `History.db` carve is milliseconds). This tier runs **by default** in
the relevant parser (`issen-parser-sqlite` / `issen-browser`, `issen-parser-evtx`),
because it recovers the **high-value, recently-deleted rows that live in the file's
own slack** — which is *most* of what matters in triage (deleted history, chat,
credential rows).

### Tier 2 — whole-disk unallocated carving → OPT-IN behind `--deleted`

Magic-byte scanning the **entire image** for *orphaned* SQLite/EVTX/other artifacts
that are no longer referenced by the filesystem at all. This is **O(image size)** —
gigabytes, and it *would* balloon triage time. It is **off by default** and gated
behind the existing **`--deleted`** flag (precedent: ntfs `deleted_nodes()`, the
4n6mount `--deleted` work). It answers the rarer *"the DB/file itself was deleted"*
question.

## Consequences

- **Fast triage stays fast.** The default path gains deleted-row recovery only where
  it is cheap and bounded by the artifact already in hand; the expensive image sweep
  is never implicit.
- **A correctness win, not just a speed one.** The two tiers recover different things:
  Tier 1 gets the high-value slack rows in a live file; Tier 2 gets the edge case of a
  wholly-deleted file. Keeping them separate means the common, valuable case is always
  on, and the rare, expensive case is explicit and auditable.
- **Wiring rule for parsers:** a `*-forensic` carve capability that scopes to a
  *located file's* internal free space is wired into the parser's default path; any
  capability that scans *unallocated disk* is wired behind `--deleted`. When in doubt,
  ask "is the cost bounded by this artifact, or by the image?" — the answer picks the
  tier.
- Applies beyond sqlite/evtx: the same split governs any future carver (registry hive
  free cells, ESE, browser LevelDB tombstones, …).
