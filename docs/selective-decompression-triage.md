# Selective Decompression for Triage — a Block-Indexed Reader over the Filesystem Spine

Status: **backlog / design note** (not implemented). Owner layer: `issen-unpack`
backing + the container readers. Pairs with
[`writing-disk-image-crates.md`](writing-disk-image-crates.md) and the adaptive
spill in `issen-unpack/src/backing.rs`.

## Summary

A timeline ingest needs a **small, scattered** fraction of an image's bytes —
filesystem metadata plus a curated set of small artifacts (registry hives, EVTX,
prefetch, SRUM, browser SQLite, LNK, $MFT/$LogFile/$UsnJrnl, amcache, Biome).
For **random-access backings** (raw `.dd`, zip-`Stored`, and **EWF/E01**) issen
already reads only that working set, decompressing nothing it doesn't need — EWF
is chunk-indexed, so `read_at` inflates only the chunks overlapping the requested
clusters. That is already the "parse the spine, map the loose files, touch the
fewest compressed units" pattern, in production.

The gap is the **whole-image stream codecs** added alongside the multi-format
backing (`.img.gz`, `.img.bz2`, solid `.7z`): these have no cheap random access,
so the current path materializes the entire decompressed image once (the
`spill_from` RAM/temp spill) and then serves free seeks off the spill. For
single-stream codecs that floor is unavoidable. For **block-seekable** codecs it
is not — and that is the optimization this note scopes.

**Recommendation:** keep `spill_from` as the universal floor; add a **block-indexed
selective reader** for bzip2 and non-solid 7z that parses the filesystem spine,
maps the artifact extent set to compressed blocks, and decodes only those blocks.
Engage it on the triage path; leave full-image operations (hashing, carving,
imaging) on the spill path.

## What forces a full read is the codec, not the need

The working set is low-single-digit-percent of image bytes, but whether you can
*reach* it without decompressing everything depends entirely on the container's
random-access unit:

| Backing | Cluster random access | Selective decode |
|---|---|---|
| EWF / E01 | per-~32–64 KB zlib chunk + offset table | **already selective** ✅ |
| raw `.dd`, zip-`Stored` | direct seek | nothing to decompress |
| **bzip2** | independent ~900 KB blocks (`seek-bzip`/`pbzip2` model) | **possible — the win** |
| **non-solid 7z** | per-file LZMA stream | possible (per target file) |
| gzip stream, **solid 7z** | none without a prebuilt sync-point index | streamed to the last-needed byte → spill-once is the floor |

EWF is the case that matters most in practice (the standard forensic container),
and it is already selective. The new stream-codec paths are non-forensic
packagings; bzip2 and non-solid 7z among them are the ones worth making selective.

## The decisive metric: block coverage, not byte coverage

A 64 KB artifact pins a whole 900 KB bzip2 block, so a scattered extent set can
light up many blocks even at a few percent of bytes. The selective reader wins to
the extent that the artifact extents **cluster** rather than spread uniformly —
and filesystem allocation locality is on its side: the $MFT zone, `System32`, the
registry `config\` directory, and the user profile each concentrate artifacts into
regions, keeping block coverage well below 100%. The win is real where locality
holds and shrinks toward the spill cost where it does not; the reader should fall
back to spill when measured block coverage is high.

## Sketch

1. **Build the block index** for the codec:
   - bzip2 — scan for block-start magic (`0x314159265359`), record bit-offsets +
     output byte ranges (one decode pass, or lazily as blocks are first touched).
   - non-solid 7z — the archive header already lists per-file streams; no scan.
2. **Parse the spine** from the front: boot sector / superblock → locate $MFT (or
   inode tables / FAT), decode the blocks holding the metadata, build the
   file→extent map (NTFS data runs / ext4 extents).
3. **Map artifacts to blocks:** for the selected artifact set, translate each
   file's extents to the set of compressed blocks that cover them; deduplicate.
4. **Read blocks in physical-offset order** (the practical 80 % of the "traveling
   salesman" framing — once reads are coalesced and offset-ordered, full TSP
   optimality buys little) and cache decoded blocks (LRU bounded by the same RAM
   threshold the spill path uses).
5. **Fallback gate:** if the covered-block fraction exceeds a threshold (most of
   the image is touched anyway), fall through to `spill_from` — selective decode
   only pays when coverage is sparse.

## Scope / non-goals

- Single-stream gzip and solid 7z stay on `spill_from` (no cheap random access).
- Full-image operations (whole-image hash, carving unallocated, re-imaging) read
  everything by definition and stay on the spill path.
- This is a **triage** fast lane (pull a named artifact set), not a replacement
  for the universal backing.

## Validation plan (when built)

Tier-2 against an independent oracle: decode the same artifact set via the
selective reader and via full decompression + parse, and assert byte-identical
extents. Measure block coverage and wall-clock against `spill_from` on a real
bzip2-wrapped image (not a synthetic round-trip) before claiming a speedup —
report the coverage number alongside any timing, since the win is coverage-bound.
