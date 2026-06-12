# Fleet Format-Coverage Audit — *implement the whole spec, not the first variant*

*Verified 2026-06-12 by a 7-cluster read-only audit fan-out. Trigger: the
Case-001 DC01 shimcache bug — a parser built around the one header we'd seen
(Win10 `0x34`) silently sentineled the documented Win8.1/Server-2012-R2 header on
real evidence. This document is the fleet-wide coverage matrix that resulted.*

## Executive summary

The fleet is **strong at the container/format layer** (fail-loud is already the
norm: vhd, vmdk, qcow2, dmg, kdump, winevt, winreg-core, apm) and **weak at two
specific layers** — *compression/encoding within a recognised format*, and
*OS-structure/schema variants across builds*. The audit's single most important
result is that **two different failure species hide under "we only implemented
one variant," and they need opposite treatment:**

- **Honest-incomplete (fail loud):** the reader meets a documented variant it
  can't decode and **says so** with an explicit error. Annoying, not dangerous.
  *Examples: prefetch v17/v23/v26 (`UnsupportedVersion`), qcow2 zstd/LUKS, dmg
  bzip2/LZFSE, kdump LZO.* → **backlog item.**
- **Silent wrong output (bug):** the code path runs to completion and emits
  **confident garbage** — no error, no sentinel. *Examples: hfsplus decmpfs,
  ntfs LZNT1, sqlite UTF-16, memf EPROCESS offsets.* → **bug to fix.**

Making **F (fail-loud) a first-class axis** is what separates these. The shimcache
gap and the prefetch gap are *identical* at the D−I level (one variant
implemented); prefetch is safe because it fails loud, shimcache was dangerous
because it sentineled. **The remediation that matters is not "decode everything" —
it is "never emit silent wrong output," then decode by prevalence.**

A third, systemic finding cuts across every cluster: **the V axis is near-empty.**
Almost all validation is synthetic fixtures — the exact trap that hid the Win8.1
bug. Real-artifact validation exists for only a handful (winevt, prefetch v30/v31,
xpress-huffman, apm, dar, ntfs boot sector, shimcache-DC01). Sourcing a real
corpus per format is the actual gate for every fix below.

## The rubric (four axes per reader)

| Axis | Question |
|---|---|
| **D — Documented set** | what variants/versions does the authoritative spec define? |
| **I — Implemented** | which of D does the reader decode? |
| **V — Validated** | which of I are confirmed against a *real* artifact (not a synthetic fixture)? |
| **F — Fail-loud** | on a `D − I` variant, does the reader error explicitly, or silently sentinel/garble? |

Complete = `I=D` · honest = `F=loud` on the gap · trustworthy = `V=I`.

## Verified coverage matrix

`✓` clean · `⚠` gap, fails loud (honest-incomplete) · `🔴` gap, **silent wrong output** · `—` not implemented (stub)

### Clean passers — complete, fail-loud, *and* real-artifact-validated
| Reader | Note |
|---|---|
| **winevt-forensic** ✓ | all 24 BinXML value-types + arrays + embedded BinXML; loud `UnknownType`; real EVTX corpus |
| **winreg-core** ✓ | all 5 REGF versions, 8 cell types, all value types, big-data; loud `UnsupportedVersion` |
| **apm-partition-forensic** ✓ | complete, real hdiutil artifact, *and* honors variable sector size (reads block size from DDM) |

### Honest-incomplete — fail loud, real validation debt only (backlog, low risk)
| Reader | `D − I` (fails loud ✓) | Validation |
|---|---|---|
| prefetch-forensic ⚠ | SCCA v17/v23/v26 (`UnsupportedVersion`) | v30/v31 REAL ✓ |
| vmdk-forensic ⚠ | SEsparse, vmfs (`UnsupportedVersion`/`Compressed`) | v1–v3 ~real |
| qcow2-forensic ⚠ | zstd, LUKS, backing, snapshots (explicit rejects) | v2/v3 zlib ~real |
| dmg ⚠ | bzip2, LZFSE block types (loud `Unsupported`) | zlib REAL ✓ |
| kdump (memf-format) ⚠ | LZO (explicit "not yet supported") | synthetic |
| dar-forensic ⚠ | formats 2–6 (deprecated band) | 1+7–11 REAL ✓ |

### 🔴 Silent wrong output — the bug class (ranked by prevalence × undetectability)
| Reader | Silent gap | Why it's dangerous | Cheapest honest fix |
|---|---|---|---|
| **memf-windows / memf-linux** 🔴 | EPROCESS/VAD/task_struct via **hardcoded offsets, no build/kernel dispatch** | a Win7/8/11 or non-matching-kernel dump yields a *plausible* wrong PID/PPID — **undetectable** | guard: unknown struct-profile → error, never walk with wrong offsets |
| **ntfs-core** 🔴 | **LZNT1** `decompress()` exists but is **never wired** into the reader; WofCompressed reparse skipped | compressed `$DATA` / Compact-OS files (ubiquitous Win10+) return garbage/empty | wire `is_compressed()`→`decompress()`; the decoder already exists (≈30 min fail-loud, ≈2 d full) |
| **hfsplus-forensic** ✅ FIXED | ~~**decmpfs** (zlib/LZVN/LZFSE) entirely absent~~ → **full decoder shipped**: all types (1/3/4/7/8/9/10/11/12), inline + resource fork, via `flate2`+`lzfse_rust`; fail-loud on LZBitmap/dedup/unknown; wired into `read_file` (attributes B-tree + resource fork). Validated against **real `ditto --hfsCompression` LZVN** end-to-end. Knowledge in `forensicnomicon::decmpfs`. | (was: ~70% of macOS system files compressed → garbage as success) | DONE |
| **sqlite-forensic** 🔴 | **text encoding** (header byte 56) never read; `from_utf8_lossy` unconditional | UTF-16 SQLite DBs (Windows/legacy) → U+FFFD mojibake, no error (`core/src/lib.rs:2702`) | read byte 56, route to `from_utf16` (≈0.5 d) |
| **journald-forensic** 🔴 | **LZ4/XZ/ZSTD** flags recognised, **no decompressor deps at all** | modern journals (ZSTD default on 2023+ distros) → objects silently skipped | add lz4-flex/xz2/zstd + decompress |
| **browser-forensic** 🔴~ | schema-version drift unhandled (single fixed column map) | Chrome v70 vs v100 History → NULL columns silently | read `schema_version`, version-routed column maps |
| **git-forensic** 🔴 | only loose objects; **packfiles** unimplemented | every post-`gc` repo → misleading "object not found" (not "unsupported") | fail-loud guard on `pack/*.idx`; or pack v2 reader |
| **vhdx-forensic** 🔴 | **differencing** disks — no parent-locator guard | Hyper-V checkpoint → corrupt/missing data, no error | detect parent-locator → `DifferencingNotSupported` |
| **xpress-huffman** 🔴 | only [MS-XCA] §2.2 Huffman; **§2.1 plain LZ77 absent** | format-3 input mis-reported as "Huffman table truncated" (corruption) | format-byte dispatch + decode or loud `Unsupported(XPRESS)` |
| **shimcache** 🔴 | genuinely-unrecognised header → **empty-path sentinel** (not error) | XP/2003/Vista/7 cache reads as "no entries" — the original exemplar, residual | replace sentinel with `UnsupportedFormat`; implement Win7 next |

### Mixed / lookup-miss (NOT the bug class — see severity note)
| Reader | Finding | My grade |
|---|---|---|
| mbr / gpt partition | unknown type-code / type-GUID → "Unknown" | **informational, not a bug** — an open-registry lookup miss; the partition is fully readable. Surface as an *observation*, not a parse error. (Audit G over-graded this CRITICAL; I'm down-grading it.) |
| mbr / gpt partition | **no hybrid MBR/GPT cross-validation; 4Kn sector assumed 512** | ⚠ genuine — the MBR/GPT inconsistency *is* forensic evidence; 4Kn geometry off by 8× |
| usnjrnl v4 | recognised, silently skipped (no timeline value) | ⚠ minor — should log/observe the skip, not drop silently |
| ntfs $REPARSE/$EA | returned as opaque blob | ⚠ honest-ish — present but uninterpreted (not garbage) |
| ext4fs HTree, unwritten extents | flag detected, passed through | ⚠ minor |

### Stubs (no code → no silent-failure surface; defer until artifact-driven)
vsc-forensic (VSS — research only), snapshot-forensic (format catalog only).

## Ranked remediation backlog

**Tier 0 — silent wrong output on COMMON modern evidence (do first; cheap fail-loud guard buys safety even before full decode):**
1. **memf-windows/linux** build/kernel-profile guard — highest undetectability.
2. **ntfs-core** wire LZNT1 (decoder already exists) + WofCompressed.
3. **hfsplus** decmpfs (fail-loud guard in 1 h; full decode after).
4. **sqlite** UTF-16 text encoding.

**Tier 1 — silent skip / misleading error on common evidence:**
5. journald LZ4/XZ/ZSTD · 6. git-forensic packfiles (or guard) · 7. vhdx differencing guard · 8. xpress-huffman plain-LZ77 + dispatch · 9. browser schema-version routing.

**Tier 2 — honest-incomplete, implement as a real artifact is sourced:**
shimcache 7/XP/2003 (+ make its fallback fail loud) · prefetch v17/v23/v26 · amcache Win8 `File` schema · usnjrnl v4 decode · ntfs $REPARSE/$EA · ext4 HTree.

**Tier 3 — validation debt (the V axis, fleet-wide):** every reader gets a
`docs/validation.md` naming the **real** artifact behind each validated variant;
sourcing the real corpus is the gate for Tiers 0–2.

## Cross-cutting fleet actions
- **Fail-loud convention (lint/standard):** a reader's format dispatch must end in
  an explicit `Unsupported(<recognised-variant>)` error — never a silent empty,
  sentinel, or garbled result. Violators found: shimcache (sentinel), usnjrnl v4
  (skip), memf offsets (garbage), ntfs LZNT1 (garbage), hfsplus decmpfs (garbage),
  sqlite UTF-16 (mojibake), journald/git (silent skip / misleading error).
- **The "misleading error" sub-species is worse than silence** — git's "object not
  found" and xpress's "table truncated" send the analyst chasing the wrong cause.
  An `Unsupported` error must *name the format*, not masquerade as corruption.
- **Triage by species, not by D−I:** honest-incomplete = backlog; silent-wrong =
  bug. Don't let the larger honest-incomplete list bury the smaller bug list.

## The shimcache precedent (worked example, fixed 2026-06-12)
`forensicnomicon::appcompatcache` (0.4.2) holds the full documented header/entry
table (XP→11) with citations; `winreg-artifacts::shimcache` decodes Win10 + Win8.x,
validated on the real DC01 hive (140/140 timestamps). Residual is in Tier 2:
implement 7/XP/2003 and replace the sentinel fallback with a loud `UnsupportedFormat`.

---
*Methodology: 7 parallel read-only audit agents (CONTAINER, FILESYSTEM, REGISTRY,
LOG/APP, MEMORY, CODEC, PARTITION), each enumerating each reader's documented
variant set from the authoritative spec (libyal `*-kb`, [MS-*], UEFI, kernel.org,
TN1150, sqlite.org, systemd.io, Zimmerman), reading the dispatch site for `I`,
classifying test provenance for `V`, and quoting the fallback arm for `F`.
Severity re-graded by the orchestrator where an agent conflated a lookup-table
miss with an undecodable structural variant.*
