# Fleet Capability Inventory — *wire, don't reinvent*

Which fleet forensic parsers are wired into issen's auto-ingest pipeline, at what
depth, and what remains dark. **Current state verified 2026-07-21** (full 3-layer
audit); this supersedes the June-2026 snapshot, whose §1/§2 tables were substantially
stale (they called many now-wired parsers "dark").

## How wiring works (so the status column is interpretable)

A parser is **live in auto-ingest** only if three layers align, all verified per row:

1. **Force-linked** — the crate is a dep of `crates/issen-parsers/` (`build.rs` emits
   `extern crate <dep> as _;`; anchored at `issen-cli/src/lib.rs:61`). Without this the
   crate's `inventory::submit!` is dead-code-eliminated.
2. **Registered** — it `inventory::submit!`s one or more `ArtifactType`s
   (`issen-core/src/plugin/selector.rs` dispatches on them).
3. **Discovered** — `issen-core/src/classify.rs` has a filename/magic predicate that
   tags a found file with that `ArtifactType`.

Container / filesystem / partition / crypto crates (ewf, vhd(x), vmdk, qcow2, aff4,
dd, dmg, iso, ntfs, ext4fs, apfs, hfsplus, mbr/gpt/apm, bitlocker/luks/veracrypt/
filevault) are **not** artifact parsers — they're wired through `issen-providers` /
`issen-disk` / `issen-decrypt`, out of scope for this parser inventory.

## 🟢 Wired-deep — live in the pipeline, surfacing most of the upstream capability

| Artifact / source | Fleet crate | issen wrapper |
|---|---|---|
| Registry (all hives) | `winreg-core` + `winreg-artifacts` | `issen-parser-registry` **+ 11 dedicated**: sam, runkeys, userassist, typedurls, shimcache, lsasecrets, svcdiff, comhijack, dcc2, lxss, regcatalog |
| SRUM (8 tables) | `srum-parser` + `srum-core` | `issen-parser-srum` |
| Prefetch (8 run-times + audit) | `prefetch-core` + `prefetch-forensic` | `issen-parser-prefetch` |
| Amcache | `winreg-artifacts` | `issen-parser-amcache` |
| MFT | `ntfs-core` | `issen-parser-mft` + `issen-disk` |
| $LogFile | `ntfs-core` | `issen-parser-logfile` |
| USN journal | ntfs USN | `issen-parser-usnjrnl` |
| LNK / JumpLists | `lnk-core` + `cfb-forensic` | `issen-parser-lnk` |
| Recycle Bin ($I/$R) | `trash-core` | `issen-parser-trash` |
| Biome (SEGB) | `segb` + `segb-forensic` + `useract-forensic` | `issen-parser-biome` |
| Shellbags | `winreg-artifacts` | `issen-parser-shellbags` |
| SetupAPI (device install) | inline | `issen-parser-setupapi` |
| EVTX (extract + detect + carve) | `winevt-extract` + `winevt-analysis` + `winevt-carver` | `issen-parser-evtx` — ATT&CK enrichment + ElfChnk-slack carving (ADR 0018 tier 1) |
| SQLite deleted rows | `sqlite-forensic` + `sqlite-core` | `issen-parser-sqlite` — freelist/dropped-page/free-block carving, schema-agnostic (ADR 0018 tier 1) |

## 🟡 Wired-shallow — live, but surfacing a fraction of the fleet capability

| Artifact | Wrapper | Missing (upstream has it) |
|---|---|---|
| EVTX | `issen-parser-evtx` | `winevt-integrity`, `winevt-memory` still unwired. `winevt-analysis` (EventID→ATT&CK) + `winevt-carver` (ElfChnk slack) are now wired (tier 1). |
| Browser | `issen-browser` | Live rows only. No `browser-forensic-carve` (deleted rows), no history-clearing / AutoIncrementGap findings. *(Loose-file SQLite deleted rows are now caught by `issen-parser-sqlite`; browser-DB-specific carving still pending.)* |
| Linux | `issen-parser-linux` | Hand-rolled (auth.log/syslog/cron/bash_history); doesn't use `shellhist-forensic` or `journald-forensic` (binary journal unhandled). |
| macOS | `issen-parser-macos` | system.log / .logarchive / fseventsd only. |
| PE | `issen-parser-pe` | `goblin` inline; doesn't use the fleet `exec-pe-forensic` analyzer. |

## 🔴 Dark — fleet crate (or enum variant) exists, nothing wired

Priority order (`sqlite-forensic` + EVTX-depth **cleared 2026-07-21** — see Wired-deep):

1. **Browser depth** — add `browser-forensic-carve` + clearing findings to `issen-browser`
   (browser-DB-specific carving; loose-file SQLite deleted rows already covered by
   `issen-parser-sqlite`).
2. **`bam-forensic`** — `ArtifactType::Bam` is in the enum but no parser produces it and
   `classify.rs` has no `bam()` predicate → the variant is dark.
3. **No wrapper at all:** `usb-forensic` / `peripheral-forensic`, `leveldb-forensic`
   (browser IndexedDB), `journald-forensic`, `dpapi-forensic` (offline DPAPI).
4. **EVTX residual:** `winevt-integrity` (tamper) + `winevt-memory` still unwired.

Niche / lower-priority: `git-forensic`, `web3-forensic`, `bluetooth-forensic`,
`ese-forensic` (ESE reached only via `srum-parser`).

**Superseded-by-`winreg-artifacts` (not gaps):** `amcache-forensic`,
`userassist-forensic`, `shimcache-forensic` — issen deliberately uses the consolidated
`winreg-artifacts` decoders per the dependency-preference policy.

**Memory-leg dark walkers** (SAM hashdump / LSA / cachedump via `issen-mem` →
`memory-forensic`) are a separate subsystem from `crates/parsers/` and are **not
covered by this inventory** — see the memf audit notes.

## Carving — cost tiers

Wiring `sqlite-forensic` / `winevt-carver` follows **ADR
[0018](decisions/0018-carving-tiers-file-level-default-whole-disk-opt-in.md)**:
**file-level** carving (a located file's own freelist/WAL/unallocated) is cheap and
**default-on** in the parser; **whole-disk** unallocated carving is O(image) and gated
behind **`--unallocated`** (alias `--unalloc`).
