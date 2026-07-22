# 0016. Multi-profile browser discovery rides the fswalk, not `discover_profiles`

Status: accepted
Date: 2026-07-14

## Context

A proposal asked to wire `browser_forensic_discovery::discover_profiles(home)`
into ingestion so that *all* browser profiles — not just `Default` — are
discovered and parsed across Chromium/Firefox/Safari, on the assumption that the
directory, UAC-collection, and disk-image legs each catch only the `Default`
profile.

Investigation of the actual ingest paths showed the assumption holds for exactly
one of those legs.

### How each leg reaches the browser parser

- **Directory / loose-file input** (`issen <dir>`): a plain directory classifies
  as `None`, then routes to the disk leg (`None if p.is_dir() => disk.push(..)`
  in `pipeline_run.rs`). The disk leg calls `commands::ingest::run`, which runs
  `run_auto_parse_jobs(&dir, ..)` — a **recursive `std::fs` walk** that
  classifies every file with the registry-derived classifier
  (`issen_core::plugin::registry::detect_from_registry` →
  `issen_core::classify::browser_history`).
- **UAC collection**: `ingest_collection_into_db` runs the *same*
  `run_auto_parse_jobs` over the collection's extracted root.
- **NTFS disk image**: the disk leg extracts artifacts by the parser's
  `disk_sources` — for browser history, two `PerSubdirSweep` entries hard-coded
  to `…\User Data\Default`.

### What the classifier matches

`classify::browser_history` keys off the **filename and full path**, not a
`Default` subdirectory:

- Chromium `History` when the path contains a vendor token
  (`chrome`/`chromium`/`edge`/`brave`/`opera`/`vivaldi`/`arc`);
- Firefox `places.sqlite` (any path);
- Safari `History.db` under a path containing `safari`.

So the recursive walk already discovers **every** profile under a real home tree
— `Default`, `Profile 1`, `Profile 2`, Firefox, Safari — because a genuine
Chromium layout (`…/Google/Chrome/User Data/<Profile>/History`) always carries
the vendor token. This is exercised end-to-end by
`crates/issen-cli/tests/browser_profile_discovery.rs`: a non-`Default`
`Profile 2` History lands in the timeline, and a single file is not
double-counted.

`discover_profiles` walks the *same* known base directories
(`AppData/Local/Google/Chrome/User Data`, `.config/google-chrome`, …), all of
which contain those vendor tokens. On a structure-preserved home tree the two
mechanisms therefore find the identical set of files.

## Decision

**Do not wire `discover_profiles` into the directory or collection legs.** The
recursive fswalk + registry classifier already discovers all profiles there.
Adding `discover_profiles` would re-enumerate the same `History` / `places.sqlite`
/ `History.db` files the walk already parses, producing duplicate timeline events
that would then need dedup to suppress — churn that adds a dependency and a code
path to cancel out its own output. It would violate "enrich, don't duplicate".

The `Default`-only limitation is real for **one** leg only: the **NTFS
disk-image** `disk_sources`.

## The genuinely deferred work — all-profile NTFS `disk_sources`

`issen-browser`'s two `PerSubdirSweep { parent: \Users, rel:
…\User Data\Default, name: Suffix("History") }` sources cover only the `Default`
profile of an NTFS image. Covering every profile needs **two** variable path
levels — the user folder *and* the profile folder
(`\Users\<user>\…\User Data\<profile>\History`) — but `PerSubdirSweep` expresses
only **one** variable level (`<sub>`) followed by a fixed `rel`.

`discover_profiles` cannot close this gap directly: NTFS extraction
(`issen_disk::extract_*`) returns a **flat `Vec<ExtractedFile>`** of in-memory
bytes keyed by NTFS path strings, while `discover_profiles` needs a **walkable
`std::fs` path**. Bridging them would mean writing the extracted subtree back to
a tempdir with its directory structure preserved — a larger seam than this
change warrants.

The in-architecture fix is instead a **two-level sweep primitive** for
`disk_sources` (a `PerSubdirSweep` variant that sweeps `<sub>` then, inside it,
sweeps a second `<profile>` level before the fixed suffix), or a
structure-preserving `extract` that yields a walkable tree. Both are separable
follow-ups; neither is a browser-specific hack.

### Also deferred

- **ext4 / APFS disk images**: no file extraction until the Linux/macOS
  disk-image path lands (see ADR 0015). Browser discovery on those images waits
  on that.

## Consequences

- No new dependency (`browser-forensic-discovery`) and no new code path in the
  legs that already work; behaviour of the disk/memory/collection legs is
  otherwise unchanged.
- Multi-profile discovery for directory + collection input is now pinned by a
  regression test, so a future refactor of the walk or classifier cannot
  silently regress it.
- The NTFS all-profile gap and its two candidate fixes are recorded for a later
  focused change.
