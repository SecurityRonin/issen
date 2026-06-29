# Selective Decompression for Triage — Block-Indexed Reads over the Filesystem Spine

Status: **bzip2 selective reader implemented** (`issen-unpack::bzseek::Bzip2SeekReader`,
validated against `bzip2-rs`). The spine/extent-map orchestration and the
coverage fallback gate are the remaining integration. Pairs with
[`writing-disk-image-crates.md`](writing-disk-image-crates.md) and the adaptive
spill in `issen-unpack/src/backing.rs`.

## Summary

A timeline ingest needs a **small, scattered** fraction of an image's bytes —
filesystem metadata plus a curated set of small artifacts (registry hives, EVTX,
prefetch, SRUM, browser SQLite, LNK, $MFT/$LogFile/$UsnJrnl, amcache, Biome). The
question is never "how big is the image" but "can I reach those scattered bytes
without inflating everything between them." That depends entirely on the
**random-access unit** of the outer container, and on the image format's own
sparse map — not on the byte size of the working set.

Two things ship here:

1. **The optimized ingestion algorithm** (spine-first, extent-mapped, read in
   physical order, decode only covering units).
2. **`Bzip2SeekReader`** — the one outer format that previously had *no* random
   access and now does: it indexes bzip2's independent blocks and decodes only
   the ~900 KB blocks a read touches.

The matrix below states which **compression formats** and which **image formats**
support a fast path, and which **combinations are fastest** — the headline being
that the *size of the random-access unit* decides efficiency (EWF's 64 KB chunk
beats bzip2's 900 KB block for scattered small artifacts), and that the standard
forensic container (E01) is already the practical winner.

## The optimized ingestion algorithm

Given a backing that supports cheap random access, issen already reads only the
working set — the parsers request an artifact's clusters, never the whole disk.
The algorithm that minimizes decompression is therefore:

1. **Read the spine first.** Boot sector / superblock / FAT → locate the bulk
   metadata. The *pointers* are front-loaded; the bulk is not — $MFT fragments,
   ext4 inode tables are distributed one-per-block-group, $UsnJrnl sits wherever
   it was allocated.
2. **Decode the metadata, build the file→extent map** (NTFS data runs / ext4
   extents). This is the only unavoidable "decode a region you didn't ask for"
   step, and it is small.
3. **Translate the selected artifact set to random-access units** (EWF chunks /
   bzip2 blocks / qcow2 clusters / vmdk grains), and **deduplicate** — many small
   artifacts share a unit.
4. **Read units in physical-offset order.** Once reads are coalesced and ordered,
   full traveling-salesman optimality buys little; offset order captures ~all of
   it and is what minimizes both seeks and unit re-decoding.
5. **Cache decoded units** (bounded LRU) and **gate on coverage**: if the covered
   fraction of units is high (most of the image is touched anyway), fall back to
   decode-once-and-spill — selective decode only pays when coverage is sparse.

`Bzip2SeekReader` implements steps 3–5 for bzip2 (`partition_point` over the
block offset map → decode only covering blocks → 8-block move-to-front LRU). EWF
implements them already inside `ewf` (`read_at` inflates only covering chunks).

## Fast-path support — by outer (compression/container) format

The fast path = the outer format exposes a **bounded random-access unit**, so a
scattered read inflates only the units it overlaps.

| Outer format | Random-access unit | Fast path | Notes |
|---|---|---|---|
| raw / `.dd` | byte (none to decode) | ✅ | direct seek |
| zip-`Stored` | byte (in-place window) | ✅ | `SubRangeReader` over the entry |
| E01 / EWF | ~32–64 KB zlib chunk | ✅ | already selective in `ewf` |
| AFF4 | image-stream chunk | ✅ | chunked like EWF |
| bzip2 (`.bz2`) | ~900 KB block | ✅ | `Bzip2SeekReader` (this work) |
| zip-`Deflated` | — (one DEFLATE stream/entry) | — | materialize (spill) |
| tar.gz | — (one gzip stream) | — | materialize (spill) |
| tar.bz2 | ~900 KB block, per member | ✅ | `tar_members` + `RangeView` over a shared `Bzip2SeekReader` (this work) |
| 7z solid | — (one LZMA stream) | — | materialize (spill) |
| 7z non-solid | per-file LZMA stream | ✅ | `read_file` decodes only matching files (this work) |

A single-stream codec (gzip, solid 7z) has no random-access unit short of a
prebuilt sync-point index, so it stays on the spill floor.

## Fast-path support — by image (inner container) format

This is the *other* axis: given a random-access byte backing, does the image
format let you read only the clusters you need? **All of them do** — each carries
a sparse map, and each already decodes only the clusters requested:

| Image format | Sparse map | Selective read |
|---|---|---|
| raw / `.dd` | identity (offset == LBA) | ✅ |
| E01 / EWF | chunk offset table | ✅ |
| VMDK (sparse) | grain directory / grain tables | ✅ |
| VHD (dynamic) | Block Allocation Table | ✅ |
| VHDX | BAT + region table | ✅ |
| QCOW2 | L1/L2 cluster tables | ✅ |
| AFF4 | image-stream index | ✅ |

So the image format is **not** the bottleneck — the outer compression is. A
sparse VMDK inside a `tar.gz` loses all of its selectivity, because the gzip layer
has no random-access unit; the same VMDK loose, or in a zip-`Stored`, keeps it.

## Which combinations are fastest

Fast path requires **both** axes: a random-access outer unit **and** a sparse
image format. Since every image format is sparse, the ranking is driven by the
outer unit — specifically its **size**, because a scattered small artifact forces
decoding the *whole* unit it lands in (over-decode = unit_size − artifact_size).

Ranked for a sparse triage workload (fastest first):

1. **raw / zip-`Stored` + any image format** — zero decompression, pure seeks.
   The ceiling; e.g. a `.dd`, or an uncompressed image in a zip-`Stored`.
2. **E01 / EWF** — ~32–64 KB chunks. Small unit → little over-decode per
   artifact, and the chunk index is built into the format (no separate index
   pass). For real evidence this is the **practical winner**: near-raw speed on
   the working set with the storage savings of compression. (AFF4 sits here too.)
3. **bzip2 `.bz2` / `.tar.bz2` via `Bzip2SeekReader`** — selective, but two costs
   make it slower than EWF: the ~900 KB block is ~14–28× larger than an EWF chunk
   (more wasted decompression per scattered 64 KB artifact), and bzip2 stores no
   output length, so the offset map costs **one full decode** up front
   (parallelizable, no temp writes). A `.tar.bz2` member is a `RangeView` over the
   shared reader, so it inherits the same block-granular selectivity. Beats
   decode-once-and-spill only when the working set is sparse *and* temp is
   slow/absent (e.g. a read-only or tmpfs-only host).
4. **non-solid 7z via `read_file`** — per-file LZMA. Selective at *file*
   granularity (decodes only the matching files, never the others), but each
   matching file is one LZMA stream with no *intra*-file random access, so a
   member is decoded whole. Best when extracting a small subset of small files
   from a many-file archive; a single large member just falls back to spill.

Not on the fast path (materialize once, then free seeks off the spill):
**zip-`Deflated`, tar.gz, solid 7z, single-stream gzip.**

The one-line rule: **prefer a format whose random-access unit is small and
indexed.** EWF wins because 64 KB ≪ 900 KB and its index is free; bzip2 is the
fallback that rescues an otherwise-unseekable `.bz2`; gzip/solid-7z can't be
rescued without a full index pass and stay on spill.

## Nested wrappers seen in the wild: `e01.zip`, `e01.7z`

E01 is itself a compressed, chunk-indexed format, so it is common to find one
re-wrapped for transport or archival — `case.E01.zip`, `case.E01.7z`. These are
**nested**: an outer container around an already-selective image. The rule for
whether the inner E01's chunk-selectivity *survives* is the same single axis —
**the outer format's random-access unit must be fine-grained enough not to force
materializing the whole E01.**

| Wrapper of an E01 | Outer unit | E01 chunk-selectivity | Net |
|---|---|---|---|
| loose / raw | byte | ✅ | fast (native EWF chunks) |
| **zip-`Stored`** | byte (in-place window) | ✅ | **fast** — and this is the *usual* `e01.zip` |
| **`.E01.bz2`** | ~900 KB block | ✅ | **fast** — *double* selective: bz2 block → EWF chunk |
| zip-`Deflated` | one DEFLATE stream | ✗ | materialize the whole E01 first |
| 7z (solid **or** non-solid) | one LZMA stream per file | ✗ | materialize the whole E01 first |

Two practical points the table encodes:

- **`e01.zip` is normally the fast case.** E01 is already zlib-compressed, so
  deflating it again buys almost nothing — tools overwhelmingly store an E01 into
  a zip with **`Stored`** (no compression). That keeps the byte-granular in-place
  window, so the EWF chunk index still serves selective reads straight through the
  zip. (issen reaches this via the EWF-in-zip path: `EwfDataSource::open_zip` →
  `archive_backing(.., &["E01"])` → in-place window for `Stored`.)
- **`e01.7z` always materializes the E01.** 7z re-compresses the E01 with LZMA for
  a smaller archive (its reason to exist), but the E01 becomes **one LZMA stream**
  — and LZMA has no intra-stream random access. Non-solid 7z only lets you skip
  *other* files; the E01 file itself must be decoded whole before its chunk index
  is usable again. So treat `e01.7z` as transport packaging: spill the E01 once
  (or extract it to loose), then enjoy native EWF selectivity — do not expect
  selective reads *through* the 7z layer.

The same logic generalizes to any `image.<wrapper>`: a sparse VMDK/QCOW2/VHD keeps
its selectivity inside zip-`Stored` or bzip2, and loses it inside zip-`Deflated`,
gzip, or 7z. The inner format is never the bottleneck — the outer unit is.

## `Bzip2SeekReader` — how it works

bzip2's blocks each carry their own CRC and share **no** inter-block dictionary,
so a single block can be rebuilt into a standalone one-block stream and decoded in
isolation — the `bzip2recover` technique, no decoder-state injection. (gzip's
DEFLATE and solid 7z's LZMA both carry cross-unit state, which is why neither can
do this.)

1. **Index:** one streaming, rolling 48-bit bit-scan records every block magic
   (`0x314159265359`) and the EOS magic (`0x177245385090`).
2. **Lengths:** bzip2 stores no per-block output length, so each block is decoded
   once to learn its decompressed span and build the offset map (one full decode,
   no temp).
3. **Extract:** for block *k*, emit `BZh<level>` + the block's bits verbatim + the
   EOS magic + the block's stored CRC (a one-block stream's combined CRC *is* that
   block's CRC), and hand the synthetic stream to `bzip2-rs`.
4. **Serve:** `read_at` finds covering blocks via `partition_point` on the offset
   map and decodes only those, behind an 8-block LRU.

Limitation: block boundaries are found by a 48-bit magic, so a payload that
happens to contain the magic is a ~2⁻⁴⁸ false-positive per bit position — a bogus
boundary makes a block fail to decode, which surfaces **loudly** at index build
(never a silent wrong read). Multi-stream `.bz2` (concatenated `BZh` headers, e.g.
`pbzip2`) is untested.

## Integration status & next steps

- **Done — `Bzip2SeekReader`** (random-access bzip2), TDD against `bzip2-rs`.
- **Done — bzip2 backings are selective** (`backing::bzip2_entries`): a bare
  `.bz2` image is a `RangeView` over the seek reader, and each `.tar.bz2` member
  is a `RangeView` over a *shared* reader, so it inflates only the covering
  blocks. This replaced the bzip2 spill path.
- **Done — non-solid 7z is selective** (`backing::sevenz_entries`): a non-solid
  archive whose matching members each fit RAM decodes only those files via
  `read_file`; solid archives or oversized members fall back to stream-once +
  spill (`sevenz_entries_streaming`).
- **Caveat (the spill floor still matters):** the bzip2 seek reader builds its
  offset map with one full decode and re-decodes blocks on LRU eviction, so a
  *full sequential* read of a `.bz2` backing (whole-image hash/carve) is slower
  than decode-once-and-spill. issen ingest is targeted (artifact-scoped reads),
  which is the favorable pattern; an access-pattern/coverage gate (below) is the
  general mitigation.
- **Next:** a triage entry point that (a) builds the spine + extent map, (b)
  engages the selective backing (bzip2 / non-solid-7z, or the EWF/qcow2/vmdk
  native sparse path) for the selected artifact set, and (c) applies the coverage
  gate — fall back to spill when most units are touched or the access pattern is
  sequential.

## Measured — real-evidence benchmark (the spill floor, not the selective path)

The four DFIR Madness **"Szechuan Sauce"** evidence files were ingested **straight
from their `.zip` form** (no pre-extraction), at commit `4ad0ce4` on a 48 GB macOS
host. Wall-clock via `/usr/bin/time -l`; peak temp via `df` sampling of the spill
volume (approximate).

| Leg | Source(s) | Wall | Peak RSS | issen temp | Output |
|---|---|---|---|---|---|
| Disk ingest | `DC01-E01.zip` + `DESKTOP-E01.zip` (multi-segment E01–E04) | 67.0 s | 10.7 GB | **0** | 2,337,495 events |
| Memory — DC01 | `DC01-memory.zip` (2 GB dump) | 8.0 s | 4.1 GB | **0** | ok |
| Memory — Desktop | `DESKTOP-SDN1RPT-memory.zip` (2 GB dump) | 11.1 s | 4.1 GB | **0** | ok |

**Tier-2** (real third-party corpus, checked against an oracle): the
2,337,495-event timeline reconciles exactly with the prior extract-then-ingest
run of the same corpus — the event count is the correctness oracle, so the
zip-direct path produces an identical timeline, not just a fast one.

The `0` temp is an **attributable** measurement, not a `df` guess: pointing
`ISSEN_SPILL_DIR` at an empty directory and sampling its size during the run gave
a peak of 0 MB. (A naive `df` of `/var/tmp` showed ~1.6 GB "used" — pure noise
from other processes on that volume; the empty-dir measurement is what isolates
*issen's* footprint. Look at the right thing.)

**What this does and does not measure — the load-bearing caveat.** Every entry in
these four archives is **zip-`Deflated`**, so the run exercises the **inflate-to-RAM
path** (ewf reads a Deflated zip entry through a RAM `Cursor`, not a spill), *not*
the selective bzip2 reader. The selective fast-path engages only for `.bz2` /
`.tar.bz2` / non-solid `.7z`, none of which appear in this corpus. So these numbers
measure the **materialize floor on real evidence**: zero temp, with the 10.7 GB RSS
dominated by the ingest pipeline (DuckDB + the NTFS/registry/EVTX parsers) and the
inflated image segments riding on top of it. A `.bz2`-wrapped image is what would
exercise the selective reader; that measurement is the integration's job (below).

## The "just recompress everything to bz2" experiment

A natural question: bz2 is the one stream codec we made selective — so if the
evidence arrived as `.bz2` instead of `.zip`, is it the better "best case"? The
four files were recompressed at **max bzip2 (-9)** (E01 segments → `.tar.bz2`,
memory dumps → `.bz2`) and compared. The answer is **no, twice over.**

**Size — no win on *this* evidence (which is the exception, not the rule).**
In general bzip2 compresses **~10–15% smaller** than zip/gzip on text-like data
(at a 3–6× speed cost) — that is the documented norm. This forensic corpus is an
atypical case where that advantage evaporates:

| Source | zip | bz2 (-9) | bz2 / zip |
|---|---|---|---|
| DC01 memory | 535 MiB | 544 MiB | 101.7% |
| Desktop memory | 766 MiB | 832 MiB | 108.6% |
| DC01 E01 (2 segments) | 4.50 GiB | 4.45 GiB | 98.8% |
| Desktop E01 (4 segments) | 6.37 GiB | 6.41 GiB | 100.5% |

Two distinct reasons, both verified:

- **E01 is already zlib-compressed internally**, so neither codec can squeeze it
  further — both land within ~1% of the raw E01. This is not a bzip2 weakness;
  nothing re-compresses already-compressed data.
- **The raw memory dumps genuinely favor DEFLATE** here by ~1–8%. Re-running with
  single-threaded `bzip2 -9` (ruling out any `pbzip2` multi-stream overhead, which
  measured at only ~0.4–0.8%) still left zip the smaller of the two — these
  zero-heavy, structurally-repetitive dumps are exactly the binary shape where
  LZ77's window/run-handling edges bzip2's Burrows–Wheeler block-sort.

So "max-compression bz2" buys nothing on **this** evidence — but don't generalize
that to "bz2 is bigger than zip"; on ordinary text/log corpora bzip2 is the
smaller of the two.

**Speed — bz2 is ~3× slower to decompress (single-stream):**

| Decompressing a 2 GB memory dump | Wall | vs deflate |
|---|---|---|
| zip DEFLATE (1 core) | 10.0 s | 1.0× |
| bz2 single-stream (1 core — what `bzip2-rs` does) | 32.2 s | **3.2× slower** |
| bz2 parallel (`pbzip2`, 14 cores, multi-stream) | 2.95 s | 0.3× |

bzip2's decode is intrinsically heavier than DEFLATE, and issen's `bzip2-rs`
reader is single-threaded single-stream — the 32 s row. A whole-image read
(memory, or a full-disk pass) pays that 3× in full.

**Why this is consistent with the thesis, not a contradiction.** bz2's *only*
advantage is block-seekable **selective** reads — and that helps **scattered
triage reads**, never a whole-image ingest. These four legs read whole images
(memory needs the entire dump in RAM; the disk leg streams every segment), so the
selective reader cannot engage and bz2 is left as just a slower, no-smaller codec.
The win bz2 offers is real but narrow: pulling a few scattered artifacts from a
*single large* `.bz2` image on a host where the alternative is materializing the
whole thing.

**Caveat — bz2 ingest is not wired end-to-end.** issen's disk (`EwfProvider`) and
memory (`dump_source`) entry points detect **zip only** (by `PK\x03\x04` magic);
neither routes a `.bz2` / `.tar.bz2` through the selective backing yet. So the
speed figures above are the **codec-throughput proxy**, not a measured `issen`
ingest of the bz2 files — wiring the providers to the centralized
`archive_backing` (so a bz2-wrapped image is recognized) is the integration step
that would make an apples-to-apples ingest comparison possible. Given the size and
whole-image-speed results, the expected outcome of that wiring is clear: **no win
for full ingest**; value only on the gated triage path.

## Validation plan (for the integration)

Tier-2 against an independent oracle: decode the selected artifact set via the
selective path and via full decompression + parse, asserting byte-identical
extents. Measure **unit coverage** and wall-clock against `spill_from` on a real
bzip2-wrapped image (not a synthetic round-trip) before claiming a speedup, and
report the coverage number alongside any timing — the win is coverage-bound.
