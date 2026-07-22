# 0010. disk-forensic as the disk-image access abstraction (collapse issen's per-format wrappers)

- Status: Proposed
- Date: 2026-07
- Deciders: SecurityRonin
- Relationship: see **ADR 0017** (Accepted). This ADR covers the CONTAINER layer
  (`disk_forensic::container::open` → sector stream); 0017 covers the FILESYSTEM layer
  (`forensic-vfs` walking that stream). Complementary per the constitution's "VFS &
  Container" split — not superseded.

## Context

issen's stated architecture (ADR 0001, CLAUDE.md) is that issen is the **thin
orchestration layer** and deep per-artifact knowledge lives in standalone fleet
libraries. The disk path currently violates that.

Adding a disk-image format to issen means adding a **per-format wrapper crate**.
There are eight, each ~300–600 lines and structurally identical — open a container
reader, wrap it as a `DataSource`, handle zip-direct reads, register a
`CollectionProvider`, then call `issen_disk::triage_manifest`:

| crate | lines | crate | lines |
|---|---|---|---|
| issen-ewf | 592 | issen-vmdk | 382 |
| issen-iso | 467 | issen-vhd | 336 |
| issen-vhdx | 420 | issen-qcow2 | 325 |
| issen-dd | 390 | issen-aff4 | 316 |

That is ~3,200 lines of boilerplate whose only real variation is *which container
reader crate* they call. A ninth format is a ninth near-identical crate.

Worse, it **duplicates work disk-forensic already does.** `disk-forensic` (the
`disk4n6` crate) already decodes the wrapper (E01/VMDK/VHDX/VHD/QCOW2/DMG/raw/ISO),
identifies the partition scheme (MBR/GPT/APM), and routes to the right parser
(`container.rs`, `layout.rs`). issen re-opens those same containers in its eight
wrappers instead of reusing that.

## Decision

Make **disk-forensic the disk-image *access* abstraction, not only the *analysis*
one.** Today it emits a structural `DiskReport`; extend it to also expose a
**navigable sector stream** — a container registry `open_image(reader) -> impl
SectorSource` that auto-detects the format and dispatches partition → filesystem.

issen's disk pipeline then collapses to **one** `CollectionProvider` that calls
`disk_forensic::open_image(...)` and triages the result. A new image format,
partition scheme, or filesystem is added **in disk-forensic (and the reader/FS
library)** — never as a new issen crate. The eight per-format wrappers are deleted.

Scope is **disk only.** `CollectionProvider` + inventory registration stay in issen
— they are the orchestration seam that also spans logical collections (AD1 / zip /
UAC / Velociraptor) and memory dumps, which disk-forensic must not subsume.

## Consequences

**Good:** ~3,200 lines of issen boilerplate removed; one home for new formats; the
same abstraction is reusable by `disk4n6` and any future fleet tool; the disk path
finally matches the "issen is thin orchestration" principle; the
container-open duplication between disk-forensic and issen is eliminated.

**Cost / trade-offs:**
- disk-forensic today *analyzes* (returns a report); serving a *navigable* image is
  real work — expose the readers' sector streams and own filesystem dispatch. It is
  an extension (container detection already exists), not a rewrite.
- This is a deliberate cross-repo refactor, not a quick change; it must not regress
  the current disk triage (gate on the Case-001 end-to-end ingest).
- Two datetime/util concerns are unaffected; the migration is orthogonal to the
  chrono→jiff work.

## The load-bearing seam

`DataSource` / `ReadSeekSend` live in `issen-core` / `issen-unpack` today, so
disk-forensic cannot return one without depending *up* into issen. **Move the
sector-source trait down** into a low shared crate (the way `state-history-forensic`
holds shared traits), so both disk-forensic and issen depend *down* on it. That one
relocation is what makes the whole consolidation clean.

zip-direct stays split cleanly: issen-unpack owns the backing (the
`open_reader(Box<dyn ReadSeekSend>)` + zran/spill work already done, ADR 0006), and
disk-forensic opens the container *over* that backing — issen supplies bytes,
disk-forensic supplies structure.

## Migration outline (scoped project, gate each step on the Case-001 ingest)

1. **Extract the trait.** Move `DataSource` / `ReadSeekSend` (the sector-source
   surface) to a low shared crate both repos depend on. Non-breaking re-export from
   the old paths during transition.
2. **Grow disk-forensic.** Add `open_image(reader) -> impl SectorSource` — a
   container registry over the reader crates (ewf/vmdk/vhdx/vhd/qcow2/aff4/dd/iso),
   returning a navigable stream; own partition → filesystem dispatch (or keep FS in
   `issen-disk` and have disk-forensic hand back the per-partition sector windows).
3. **One issen disk provider.** Replace the eight wrappers with a single
   `CollectionProvider` that calls `disk_forensic::open_image` + triage; keep the
   zip-direct backing supplied from issen-unpack.
4. **Delete the eight per-format wrapper crates**; update `issen-providers`.
5. **Validate** end-to-end on the four Case-001 archives (disk legs) — identical
   event counts and artifacts to the pre-refactor baseline.

## References

- ADR 0001 (issen as thin orchestration), ADR 0004 (`CollectionProvider`), ADR 0006 (zip-direct/zran backing)
- `disk-forensic` (`disk4n6`): `src/container.rs`, `src/layout.rs`, `analyse_disk`
- issen per-format wrappers: `crates/issen-{ewf,vmdk,vhd,vhdx,qcow2,aff4,dd,iso}`
- Trait homes today: `crates/issen-core/src/plugin/traits.rs`, `crates/issen-unpack/src/{lib,backing}.rs`
