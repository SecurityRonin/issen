# Issen Dependency-Graph Reachability Audit

**Question:** which fleet component crates are actually wired into issen (reachable in its
dependency graph), and which are orphaned (built/published but the orchestrator never reaches them)?

**Method (verified, not assumed):** `cargo tree -e normal` **resolved cleanly** from
`components/orchestration/issen` (EXIT=0), so this uses the *real resolved graph* (870 reachable
crate names incl. third-party), not a static guess. Fleet crate names were enumerated by reading
every `[package].name` across all 84 component repos (283 distinct crates; 66 are issen's own
`issen-*` workspace members, 217 are non-issen fleet crates). DIRECT vs TRANSITIVE was split by
parsing every issen member's `[dependencies]`. Reverse edges confirmed with `cargo tree -i <crate>`.

## Executive Summary

- **83 non-issen component repos.** Of these: **37 DIRECT**, **16 TRANSITIVE**, **30 ORPHANED**.
- **shellitem IS wired** (TRANSITIVE) — contrary to the belief it is orphaned. It is pulled in
  through **four** intermediaries: `lnk-core`, `winreg-artifacts`, `memf-windows`, and
  `useract-forensic`. No action needed to wire it.
- The 30 orphaned repos fall into two buckets: **(a) superseded in-tree** — issen reimplements the
  artifact itself (amcache/shimcache/userassist/BAM decoded via `winreg-artifacts`, PE via
  `issen-parser-pe`), and **(b) genuinely unreached** — filesystems issen's disk layer does not yet
  mount (btrfs/xfs/zfs/udf/hfsplus/refs/ufs/fat), plus git/journald/usb/leveldb/protobuf/dpapi/
  bluetooth/vsc/snapshot/archive/cfb and the standalone VFS mount/engine crates.

## Repo-level classification

### DIRECT — an issen member depends on the crate (37 repos)

| Repo | Wired crate(s) |
|---|---|
| archive/zip-forensic | zip-forensic-core |
| container/ad1-forensic | ad1-core |
| container/aff4-forensic | aff4 |
| container/dmg-forensic | dmg-core |
| container/ewf-forensic | ewf |
| container/qcow2-forensic | qcow2-core |
| container/vhd-forensic | vhd-core |
| container/vhdx-forensic | vhdx-core |
| container/vmdk-forensic | vmdk-core, vmdk-forensic |
| encryption/bitlocker-forensic | bitlocker-core |
| encryption/filevault-forensic | filevault-core |
| encryption/luks-forensic | luks-core |
| encryption/veracrypt-forensic | veracrypt-core |
| filesystem/apfs-forensic | apfs-core |
| filesystem/ext4fs-forensic | ext4fs-core |
| filesystem/forensic-vfs | forensic-vfs |
| filesystem/iso9660-forensic | iso9660-forensic |
| filesystem/ntfs-forensic | ntfs-core, ntfs-forensic |
| knowledge/forensic-hashdb | forensic-hashdb |
| knowledge/forensicnomicon | forensicnomicon, -core, -data |
| log/winevt-forensic | winevt-analysis, -carver, -core, -extract, -integrity |
| memory/memory-forensic | memf-core, -correlate, -format, -linux, -strings, -symbols, -windows |
| orchestration/disk-forensic | disk-forensic |
| orchestration/useract-forensic | useract-forensic |
| parser/browser-forensic | browser-forensic-chrome, -core, -firefox, -safari |
| parser/lnk-forensic | lnk-core |
| parser/prefetch-forensic | prefetch-core, prefetch-forensic |
| parser/segb-forensic | segb-core, segb-forensic |
| parser/snss-forensic | snss-core |
| parser/sqlite-forensic | sqlite-core, sqlite-forensic |
| parser/srum-forensic | srum-core, srum-parser |
| parser/trash-forensic | trash-core |
| parser/winreg-forensic | winreg-artifacts, -carve, -core, -discover, -format |
| utility/forensic-carve | forensic-carve |
| utility/jsonguard | jsonguard |
| utility/shrinkpath | shrinkpath |
| utility/timeglyph | timeglyph |

### TRANSITIVE — reachable only via another fleet crate (16 repos)

| Repo | Wired crate | Reached via (intermediary → issen member) |
|---|---|---|
| acquisition/livedisk-forensic | livedisk-core, livedisk-forensic | disk-forensic → issen-disk |
| archive/dar-forensic | dar-core | disk-forensic → issen-disk |
| codec/lzo | lzo | dar-core & memf-core |
| codec/lzvn | lzvn-core | apfs-core → issen-disk |
| codec/xpress-huffman | xpress-huffman | prefetch-core, memf-windows |
| encryption/elephant-diffuser | elephant-diffuser | bitlocker-core → issen-decrypt |
| history/state-history-forensic | state-history-forensic | forensic-vfs, ext4fs-core, issen-core |
| parser/ese-forensic | ese-core | srum-parser, useract-forensic |
| parser/peripheral-forensic | peripheral-core | useract-forensic → issen-parser-biome |
| parser/shellhist-forensic | shellhist-core | useract-forensic → issen-parser-biome |
| **parser/shellitem** | **shellitem** | **lnk-core, winreg-artifacts, memf-windows, useract-forensic** |
| partition/apm-partition-forensic | apm-partition-core, -forensic | disk-forensic → issen-disk |
| partition/gpt-partition-forensic | gpt-partition-core, -forensic | disk-forensic → issen-disk |
| partition/mbr-partition-forensic | mbr-partition-core, -forensic | disk-forensic → issen-disk |
| utility/blazehash | blazehash-core | ext4fs-core (and others) |
| utility/safe-read | safe-read | ext4fs-core, ntfs-core (fleet-wide reader primitive) |

### ORPHANED — no issen member can reach any of the repo's crates (30 repos)

Confirmed: `cargo tree -i` returns **0 reverse-edge lines** for every crate below.

| Repo | Crates | Likely reason |
|---|---|---|
| archive/archive-forensic | archive-core, archive-forensic | issen unpacks via issen-unpack/issen-archive, not this |
| encryption/dpapi-forensic | dpapi-core, dpapi-forensic | DPAPI not wired into issen-decrypt |
| filesystem/4n6mount | forensic-mount | mount tool, not orchestrated |
| filesystem/btrfs-forensic | btrfs-core, btrfs-forensic | FS not mounted by issen-disk |
| filesystem/fat-forensic | fat-core, fat-forensic, -cli | FS not mounted by issen-disk |
| filesystem/forensic-vfs-engine | forensic-vfs-engine | issen uses forensic-vfs, not the engine crate |
| filesystem/forensic-vfs-mount | forensic-vfs-mount | mount front-end, not orchestrated |
| filesystem/hfsplus-forensic | hfsplus-forensic | FS not mounted by issen-disk |
| filesystem/refs-forensic | refs-core, refs-forensic | FS not mounted by issen-disk |
| filesystem/udf-forensic | udf-forensic | FS not mounted by issen-disk |
| filesystem/ufs-forensic | ufs-core, ufs-forensic | FS not mounted by issen-disk |
| filesystem/xfs-forensic | xfs-core, xfs-forensic | FS not mounted by issen-disk |
| filesystem/zfs-forensic | zfs-forensic, -core | FS not mounted by issen-disk |
| graph/git-forensic | git-core, git-forensic | git artifact parser not wired |
| history/snapshot-forensic | snapshot-core, snapshot-forensic | not wired |
| history/vsc-forensic | vsc-core, vsc-forensic | VSS not wired (issen has no issen-parser-vsc) |
| log/journald-forensic | journald-binary/carver/cli/core/integrity | Linux logs not wired (issen-parser-linux covers other Linux) |
| parser/amcache-forensic | amcache-core, amcache-forensic | **superseded**: issen-parser-amcache decodes via winreg-artifacts |
| parser/atx-forensic | atx-core | not wired |
| parser/bam-forensic | bam-core, bam-forensic | **superseded**: BAM is a registry artifact → winreg path |
| parser/blob-decoder | blob-decoder | not wired (issen decodes blobs elsewhere) |
| parser/bluetooth-forensic | bluetooth-forensic, -core | not wired |
| parser/cfb-forensic | cfb-forensic | OLE/CFB not wired |
| parser/exec-pe-forensic | exec-pe-analysis, exec-pe-core | **superseded**: issen-parser-pe uses goblin/pdb directly |
| parser/leveldb-forensic | leveldb-core, leveldb-forensic, leveldb4n6 | LevelDB not wired (browser IndexedDB path differs) |
| parser/protobuf-forensic | protobuf-forensic, -core, protobuf4n6 | not wired |
| parser/shimcache-forensic | shimcache-core, shimcache-forensic | **superseded**: issen-parser-shimcache via winreg-artifacts |
| parser/usb-forensic | usb-forensic | **superseded/gap**: issen-parser-setupapi + peripheral cover USB differently |
| parser/userassist-forensic | userassist-core, userassist-forensic | **superseded**: issen-parser-userassist via winreg-artifacts |
| utility/name-variants | name-variants, name-variants-py | not wired |

## shellitem — specific status

**WIRED (transitive).** shellitem is reachable through four independent intermediaries, all already
wired into issen:

```
shellitem
├─ lnk-core          → issen-parser-lnk   → issen-parsers → issen-cli
├─ winreg-artifacts  → issen-parser-amcache/-comhijack/-registry/... & useract-forensic
├─ memf-windows      → issen-mem          → issen-cli
└─ useract-forensic  → issen-parser-biome → issen-cli
```

Intended consumers (lnk shell-item ID lists, registry shellbags, memory) all consume it already.
**No wiring action is required for shellitem** — the belief that it is orphaned is incorrect per the
resolved `cargo tree`. If the concern is a *specific* shellbags path, note issen decodes shellbags
in `issen-parser-shellbags` via `winreg-artifacts`/`winreg-core` (which in turn pulls shellitem),
not via a standalone shellitem-based parser.

## The parser-wiring pattern (mechanical — how issen pulls a parser in)

issen uses a **compile-time `inventory` registry**, not runtime discovery. Concrete files:

1. **Trait** — `crates/issen-core/src/plugin/traits.rs:147` defines `pub trait ForensicParser`.
2. **Registry** — `crates/issen-core/src/plugin/registry.rs:22` `inventory::collect!(ParserRegistration)`;
   `all_parsers()`, `detect_from_registry()`, `triage_ntfs_sources()` iterate the inventory. Each
   `ParserRegistration { create, selector }` carries an `ArtifactSelector` (the compiler forces every
   parser to declare what artifact it consumes — "registered but unclassified" is impossible).
3. **Wrapper crate** — one per artifact under `crates/parsers/issen-parser-<x>/`. It depends on the
   fleet reader crate (e.g. `crates/parsers/issen-parser-prefetch/Cargo.toml` → `prefetch-core = "0.1"`),
   impls `ForensicParser`, and calls `inventory::submit! { ParserRegistration { … } }`
   (`crates/parsers/issen-parser-prefetch/src/lib.rs:108`). Decode is delegated to the fleet crate.
4. **Aggregator** — `crates/issen-parsers/Cargo.toml` lists every `issen-parser-*` as a dependency;
   its `build.rs` generates `anchors.rs` (`extern crate <dep> as _;`) so each `inventory::submit!`
   survives dead-code elimination. A drift-gate test enforces manifest⇄anchor parity
   (`crates/issen-parsers/src/lib.rs`).
5. **Root anchor** — `issen-cli`'s `lib.rs` has `extern crate issen_parsers as _;` pulling the whole set.

**To wire an orphaned parser** (e.g. usb-forensic, git-forensic, a new filesystem): create
`crates/parsers/issen-parser-<x>/` depending on the fleet crate, impl `ForensicParser` +
`inventory::submit!`, then add **one dependency line** to `crates/issen-parsers/Cargo.toml`. For a
filesystem, the seam is different — it wires into the disk/VFS layer (`issen-disk` / `forensic-vfs`),
not the parser inventory.

## Honesty caveats

- `cargo tree` **resolved successfully** (EXIT=0), so WIRED/ORPHANED classification is from the true
  resolved graph — high confidence. Third-party crates were excluded by intersecting against the
  enumerated fleet crate-name set.
- DIRECT vs TRANSITIVE was computed by static parsing of issen members' `[dependencies]`
  (incl. `[workspace.dependencies]` inheritance and `package=` renames). A crate marked TRANSITIVE
  that is *also* a direct dep under an unusual target-specific table could in principle be
  mis-split, but spot-checks via `cargo tree -i` confirmed the intermediaries shown.
- "Likely reason" in the orphaned table is inferred from issen's in-tree parser deps
  (e.g. issen-parser-amcache/shimcache/userassist all dep `winreg-artifacts`, confirmed by reading
  their Cargo.tomls); treat those as consistent-with, not proven-intent.
