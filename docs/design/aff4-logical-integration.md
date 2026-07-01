# AFF4 v0.2.0 integration — handoff

**Status: dep bumped, disk path already wired; AFF4-Logical is the remaining work.**

`aff4` is bumped to **0.2.0** (`Cargo.toml`). Two things come with 0.2.0:

1. A **correctness fix** — the reader now decodes the 12-byte bevy index (the ≤0.1.1
   reader mis-read every real image, returning zeros/garbage). `issen-aff4`'s
   `Aff4DataSource` (disk-image `DataSource` over `aff4::Aff4Reader`) is unchanged
   API-wise and now reads correctly. It compiles clean against 0.2.0
   (`cargo check -p issen-aff4`).
2. **New capabilities** to wire up: AFF4-Logical (AFF4-L) file containers and
   encrypted-container decryption.

## What's already done

- `Aff4DataSource` (disk images: `aff4:ImageStream` / `aff4:Map`) — a `DataSource`
  consumed by the disk/partition pipeline. No change needed.
- The `From<aff4::Aff4Error>` conversion already has a wildcard arm, so 0.2.0's
  `#[non_exhaustive]` error enum (new `Encrypted` variant) does not break it.

## Remaining work — AFF4-L as a `CollectionProvider`

AFF4-L is a **collection of logical files**, not a disk — it belongs in
`issen-unpack` as a `CollectionProvider`, not the disk pipeline (mirror the AD1
plan; AFF4-L is the analogue of an AD1 logical image).

### The aff4 0.2.0 logical API (accurate — the crate's public surface)

```rust
use aff4::{LogicalContainer, LogicalEntry};

let mut c = LogicalContainer::open(path)?;               // AFF4-L container
// encrypted: LogicalContainer::open_encrypted(path, password)?
for entry in c.files().to_vec() {                        // files() -> &[LogicalEntry]
    // LogicalEntry { original_file_name: String, size: u64,
    //                hashes: Vec<aff4::StoredHash>, last_written: Option<String> }
    let bytes = c.read_file(&entry)?;                     // -> Result<Vec<u8>, Aff4Error>
}
```

There is **no `is_dir` on a `LogicalEntry`** — entries are files with slash-separated
paths; synthesize the directory tree from `original_file_name`.

### Steps

1. In `crates/issen-aff4/src/lib.rs`, add `Aff4LogicalProvider` implementing
   `issen_unpack::CollectionProvider` (template: `crates/issen-archive`). Its
   `open()` calls `LogicalContainer::open`, enumerates `files()`, and returns a
   `CollectionManifest` (extracted tree or synthetic tree with `read_file` payloads).
2. Register it with `inventory::submit!` (as `issen-archive` does).
3. **Container-type detection is the one gap.** AFF4 is a **ZIP with an
   `information.turtle`** — there is **no `AFF4\x00` magic**. Disk vs logical is
   decided by the turtle (`aff4:ImageStream`/`aff4:Map` → disk; `aff4:FileImage` →
   logical). Today the only way to tell is to *try* an opener: `LogicalContainer::open`
   returns a `BadFormat("no aff4:FileImage…")` for a disk image, and `Aff4Reader::open`
   errors for a pure logical container. Recommended: add a small
   `aff4::container_kind(&Path) -> Result<ContainerKind>` to the `aff4` crate (reads
   the turtle once) so `probe()` can return `Confidence::High` without exception
   control-flow. Until then, `probe()` can `LogicalContainer::open(path).is_ok()`.
4. Test: mirror `crates/issen-archive/src/tests.rs`; validate against a real AFF4-L
   image (pyaff4 `dream.aff4`, provenance in `aff4-forensic/core/tests/data/README.md`).

### Encryption

`LogicalContainer::open_encrypted(path, password)` decrypts an
`aff4:EncryptedStream` (AES-XTS). If issen surfaces password-protected collections,
route a supplied password here; a wrong password returns `Aff4Error::Encrypted`
(never garbage).
