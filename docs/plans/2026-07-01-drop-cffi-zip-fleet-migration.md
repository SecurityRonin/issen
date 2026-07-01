# Drop the C-FFI `zip` crate across the fleet

Status: **unblocked, not yet started** (2026-07-01). The precondition —
`zip-forensic-core` / `zip-forensic` published to crates.io — is met as of 0.2.0.

Move the fleet off the third-party `zip` crate (zip-rs) and its three C-FFI
libraries (`bzip2-sys`, `zstd-sys`, `lzma-sys`). Executed as **one wave** across
`issen` + `aff4`; the container crates `qcow2-forensic` / `vhd` / `vmdk-forensic`
/ `vhdx-forensic` pull no `zip` dep and need no change.

## Why a split, not a wholesale replacement

The fleet **writes** zips (zip-rs `ZipWriter`), so it cannot move wholesale to the
read/decompress-only `zip-forensic-core`. Verified writer usages:

- `issen-archive/src/extract.rs` (re-packaging)
- `issen-parser-velociraptor/src/{lib,extract,probe}.rs`
- `issen-qcow2/src/lib.rs`, `issen-aff4/src/lib.rs`
- `aff4/aff4/src/{lib,testutil}.rs`
- and write/round-trip paths in several other `issen-*` crates.

## The wave (one pass)

1. Repoint every **read** consumer from `zip` to `zip-forensic-core`
   (`use zip_core::…`). The whole read surface is covered — `ZipArchive::new`,
   `len`/`by_index`/`by_name`, `ZipFile::{name,size,compressed_size,crc32,
   compression,is_dir,data_start}`, `impl Read`, the `CompressionMethod` enum.
   `issen-unpack/backing.rs` (the most demanding consumer — in-place Stored
   window via `data_start()` + `compressed_size()`) migrates with no logic change.
2. Change every remaining **write** `zip` dependency to
   `zip = { version = "2", default-features = false, features = ["deflate"] }`.
   Cargo unifies features across the whole build, so a single full-featured `zip`
   anywhere re-enables the C libs for everyone — every zip-rs dep in the unified
   graph must be slim.
3. Close the one read-API gap: `by_index_raw`
   (`issen-parser-velociraptor/src/probe.rs`) — satisfy via `structural_view()`
   or a thin `by_index_raw`-style accessor added to `zip-forensic-core` when
   velociraptor is migrated (mirror the zip-rs name for a mechanical port).

## Acceptance

From the issen workspace root, after the wave — the single success criterion:

```
cargo tree -e features --workspace | grep -E 'bzip2-sys|zstd-sys|lzma-sys'   # must be EMPTY
```

## Reference

Rationale for the read-only crate design and the recognize-and-refuse scope:
zip-forensic ADRs 0001/0002 (<https://securityronin.github.io/zip-forensic/decisions/>).
