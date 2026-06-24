# Validation

`issen` orchestrates forensic parsing of untrusted memory and disk evidence:
it dispatches a dump to the right reader, then drives the per-format walkers
(NTFS, registry, the memory `memf` stack, DPAPI, …) over bytes a compromised
host wrote. Correctness is therefore established the way forensic tooling must
be: against **independent oracles** (a different tool, or a different code path,
that already decodes the same bytes correctly) on **real third-party corpora**
with known ground truth — never against fixtures we hand-encoded and then graded
ourselves.

This page records the oracle and the corpus behind each capability `issen`'s
orchestration adds on top of the format crates — the in-memory `memf-windows`
stack (registry-from-memory, shellbags, lsadump, netscan, DPAPI) and the
ingest/dispatch layer. The standalone format crates `issen` reuses
(`ntfs-forensic`, `forensicnomicon`, the container readers, …) each carry their
**own** `docs/validation.md`; this page cross-references them rather than
duplicating them. Per-file provenance (source, download URL, hashes, license)
lives in
[`tests/data/README.md`](https://github.com/SecurityRonin/issen/blob/main/tests/data/README.md);
the fleet-wide machine index is
[`docs/corpus-catalog.md`](corpus-catalog.md). This page cross-references both.

## How to read the evidence tiers

Each validation below is tagged with the trustworthiness of its check, not
whether the data is "synthetic":

- **Tier 1** — an independent third party authored the artifact *and* the answer
  key, or it is real-world data decoded by an independent tool. The strongest claim.
- **Tier 2** — real engine output whose ground truth is derivable from the
  documented construction, or confirmed by an *independent code path* on real
  data. Genuinely checked, but we chose the scenario.
- **Tier 3** — fixture and expected answer both authored here, nothing
  independent vouching. Used only for per-branch coverage, never as a
  correctness claim: a self-consistent round trip proves internal consistency,
  not correctness against real-world bytes.

## Independent oracles

| Oracle | Independent of us? | Validates | Tier |
|---|---|---|---|
| **impacket** (`dpapi.py` — `DPAPI_BLOB.decrypt`) | Yes — separate Python codebase | DPAPI blob decrypt (SHA-512/AES-256-CBC, 3DES) of a real Windows-minted blob | 1 |
| **impacket** (published `tests/misc/test_dpapi.py`, `deriveKeysFromUser`) | Yes — third-party-authored test vectors | DPAPI master-key derivation + per-user pre-key (SHA-1 path) | 2 |
| **winreg-core** flat-file `CellReader` backend | Yes — independent *code path* (the audited disk-hive decoder) | In-memory hive walk: `memf`'s HMAP cell-index→VA translation, dual-backend equivalence | 2 |
| **regipy 6.2.1** (MIT) | Yes — no shared dependency with `memf` | Shellbags BagMRU folder tree recovered from a resident hive in memory | 2 |
| **Volatility 3** (`windows.registry.lsadump`) | Yes — separate Python tool | LSA-secret decryption chain (boot key → PolEKList → per-secret AES) | 2 |
| **Volatility 3** (`windows.netscan`) / DFIR Madness + SecurityNik answer keys | Yes — separate tool + third-party write-ups | Network endpoint recovery (TCP/UDP/listeners, IPv4+IPv6) | 1/2 |
| **the real `issen` binary** (end-to-end ingest) | Independent *code path* (format detection + dispatch) | Memory-vs-disk format recognition and redirect | 2 |
| **MemProcFS v5.17.8** (`m_sys_netdns`) | Yes — separate C tool | DNS resolver cache — oracle *identified*, walker **not yet validated** (see below) | — |

## Independent test corpora

Both memory corpora are third-party, publicly distributed, and carry
independently established ground truth. The large dumps are gitignored and
fetched/extracted manually (extracted copies live under `/tmp`, never `~/src`);
the DPAPI vectors are small and committed in-crate. Hashes and full provenance
are in
[`tests/data/README.md`](https://github.com/SecurityRonin/issen/blob/main/tests/data/README.md)
and [`docs/corpus-catalog.md`](corpus-catalog.md).

| Corpus | Source | Used for | License / redistribution |
|---|---|---|---|
| **DFIR Madness "Stolen Szechuan Sauce" Case 001** — `citadeldc01.mem` (≈2 GB, CitadelDC01, Server 2012 R2 / NT 6.3.9600); DC01 + DESKTOP-SDN1RPT disk E01s; pcap; and the ingested DuckDB timelines `g1-rerun/{dc01,desktop}.duckdb` | [dfirmadness.com](https://dfirmadness.com/the-stolen-szechuan-sauce/) — James Smith | memf shellbags / lsadump / netstat real-dump tests; the ingested timelines | Educational/research use ([catalog §A3](corpus-catalog.md)) |
| **SecurityNik TOTAL RECALL 2024** — `SECURITYNIK-WIN-20231116-235706.dmp` (≈1.3 GB zip, Windows) | [Nik Alleyne write-up](https://www.securitynik.com/2024/03/total-recall-2024-memory-forensics-self.html) | memf `netscan` ESTABLISHED-C2 + `malfind` injected-region tests | SecurityNik & Volatility public ([catalog](corpus-catalog.md)) |
| **impacket DPAPI test vectors** (`test_dpapi.py`) + a real Windows-minted DPAPI blob (MK recovered via mimikatz) | [fortra/impacket](https://github.com/fortra/impacket/blob/master/tests/misc/test_dpapi.py) | DPAPI blob-decrypt and master-key-derivation unit tests | Apache-2.0 (vectors); committed in-crate |

Crate-relative paths: the memory tests live in `crates/issen-mem/tests/`
(`issen` repo); the DPAPI tests live in `~/src/memory-forensic`
(`crates/memf-windows/src/dpapi/`) and `~/src/dpapi-forensic`
(`core/src/masterkey.rs`); the dual-backend equivalence test lives in
`~/src/memory-forensic/crates/memf-windows/tests/`.

## Per-capability validation

### DPAPI blob decrypt (SHA-512/AES-256-CBC + 3DES) — Tier 1

The DPAPI blob decryptor mirrors impacket's `DPAPI_BLOB.decrypt`: derive the
session key, run AES-256-CBC (or 3DES), then verify the trailing `Sign` HMAC
before returning plaintext. Validation is against **impacket as the independent
oracle on a real Windows-minted blob** whose master key was recovered with
mimikatz. In
`~/src/memory-forensic/crates/memf-windows/src/dpapi/decrypt.rs`:

- `decrypt_sha512_aes256_blob_no_entropy` and
  `decrypt_sha512_aes256_blob_with_entropy` both decrypt to the impacket-confirmed
  plaintext `b"Some test string"` (V1 no-entropy; V2 with entropy `b"Some entropy"`).
- `decrypt_sha512_blob_wrong_entropy_fails_integrity` confirms the V2 blob
  decrypted **without** the entropy fails the `Sign` HMAC (`is_err()`) rather than
  silently returning garbage — the fail-loud property a forensic decryptor needs.
- `parse_real_blob_matches_impacket_fields`
  (`crates/memf-windows/src/dpapi/dpapi_blob.rs`) asserts the parsed blob fields
  against impacket's parse of the same real blob.

Tier 1: the artifact is a real Windows blob and the answer key is impacket's
own output. (The source comments in `decrypt.rs` cite impacket 0.12.0; the
master-key crate cites 0.13.1. The load-bearing fact is the byte-for-byte
agreement with impacket on real bytes; the exact impacket patch version is not
re-confirmed here and is not load-bearing.)

### DPAPI master-key derivation — Tier 2

`~/src/dpapi-forensic/core/src/masterkey.rs` derives the 64-byte DPAPI master
key from a per-user/LSA pre-key and the per-user pre-key from a password, against
**impacket's published `tests/misc/test_dpapi.py` vectors** plus a real Windows
master-key file:

- `derive_system_master_key_matches_impacket` — parses the real master-key file
  (GUID `ea95eba8-ba00-4e1a-b43f-51ea30171d11`, SHA-512 / AES-256-CBC, 17400
  rounds) and asserts the derived key equals impacket's
  `682a9b8923ff4ca7…2c2a59` (the value in impacket's published test).
- `prekey_from_password_matches_impacket` and `prekey_from_sha1_matches_impacket`
  — `deriveKeysFromUser(SID, "Admin456")` → `742ab02b5f80ea56…3c536a`, with
  `SHA1(UTF16LE("Admin456")) = 7ca54db25c28c72a…7c8b5fc6` as the intermediate
  (SID `S-1-5-21-1455520393-…-500`).
- `wrong_prekey_fails_hmac` — a wrong pre-key surfaces `DpapiError::HmacMismatch`,
  never a fabricated key.

Tier 2: the test vectors are impacket-authored (independent) and the master-key
file is a real artifact, but the scenario (which vectors, which file) is one we
selected, and the derivation is checked against impacket's *vectors* rather than
an end-to-end re-run on this host. The crate is `dpapi-core` (source at version
`0.1.0`; the `masterkey` module is present in the source tree — its published
availability on crates.io was not re-confirmed offline at write time).

### In-memory registry hive parsing (`MemfHiveReader`) — Tier 2

`memf`'s `MemfHiveReader` resolves a hive's cells through the in-memory HMAP cell
map (cell index → block VA), then hands the *bytes* to `winreg-core`'s shared
`Key` navigation. Correctness of that translation is established by **dual-backend
equivalence**: `winreg-core`'s own flat-file `Hive<Cursor<Vec<u8>>>` `CellReader`
(the audited third-party disk-hive decoder) and the HMAP-backed `MemfHiveReader`
walk the **same** hive bytes and must agree on keys, subkeys, and values.

`~/src/memory-forensic/crates/memf-windows/tests/hive_reader_dual_backend.rs` ::
`both_backends_agree_on_walked_keys_and_values` builds a hive whose bin base is
offset so the resolution exercises the **real** `block_va` math — the flag-mask
`(PermanentBinAddress & !0xF) + BlockOffset + N` — rather than the trivial
identity case, and asserts root + child key snapshots match across both backends.
The test was mutation-verified: neutralising the `& !0xF` mask (or dropping
`BlockOffset`) lands on the wrong block and fails.

Tier 2: the ground truth is derivable from the hive construction *and* corroborated
by an independent code path (`winreg-core`), genuinely checked, but the hive is
one we constructed.

### Shellbags BagMRU (registry-from-memory) — Tier 2 — **OWED: e2e re-run**

`memf`'s `shellbags::walk_shellbags` navigates the in-memory HMAP cell map to
`Shell\BagMRU` (through `winreg-core`'s `Key` over `MemfHiveReader`) and rebuilds
the folder tree from the shell items.
`~/src/issen/crates/issen-mem/tests/szechuan_shellbags.rs` ::
`szechuan_shellbags_recovers_bagmru_from_resident_usrclass` (env-gated
`SZECHUAN_DC_MEM`, `#[ignore]`) runs it on `citadeldc01.mem`: the Administrator
`UsrClass.dat` is fully resident at VA `0xc001f1e94000` (≈107 BagMRU rows / 27
shell items), and the recovered tree must contain `FileShare`, `Secret`,
`FTK Imager`, and `Administrator` — folders that independently match the
documented Szechuan Sauce attack narrative. The oracle is **regipy 6.2.1** (MIT,
no shared dependency with `memf`) run on the extracted resident hive.

Tier 2: regipy is an independent oracle on a real dump, but the answer key is the
regipy run we performed.

> **CONFIRMED post-migration (2026-06-24).** `shellbags` was migrated onto
> `MemfHiveReader` / `winreg-core`, and the regipy 27-folder e2e was **re-run
> against the migrated walker** on `citadeldc01.mem`: it recovered the **identical
> 27 folders** (incl. `FileShare\Secret`, `E:\FTK Imager`,
> `Users\Administrator\…`), so the backend swap is behavior-preserving on real
> data, not only in-repo. Reproduce:
> ```bash
> SZECHUAN_DC_MEM=/tmp/szechuan-extracted/citadeldc01.mem \
>   cargo test -p issen-mem --test szechuan_shellbags -- --ignored
> ```

### Network connections (netscan: TCP/UDP/listeners, IPv4+IPv6) — Tier 1/2 — **partial; census OWED**

`memf`'s `network` module (`scan_tcp_endpoints` / `scan_udp_endpoints` /
`scan_tcp_listeners`) pool-tag-scans for `_TCP_ENDPOINT` / `_UDP_ENDPOINT` /
`_TCP_LISTENER`, with per-NT-build struct layouts taken from **Volatility 3's
maintained netscan overlays**, and emits dual-stack (IPv4 + IPv6) rows. Two
committed real-dump tests validate it against independent answer keys:

- `~/src/issen/crates/issen-mem/tests/szechuan_netstat.rs` ::
  `szechuan_netstat_recovers_coreupdater_c2` (env-gated `SZECHUAN_DC_MEM`,
  `#[ignore]`) — on `citadeldc01.mem`, the walk must surface
  `coreupdater.exe → 203.78.103.109:443`, the published DFIR Madness answer-key C2.
- `~/src/issen/crates/issen-mem/tests/securitynik_netscan_malfind.rs` ::
  `securitynik_netstat_surfaces_verified_c2` and
  `securitynik_malfind_flags_injected_processes` (env-gated `MEMF_TEST_DATA`,
  `#[ignore]`) — on the SecurityNik Total Recall dump, the walk must surface the
  write-up's verified ESTABLISHED sessions to `10.0.0.110`/`10.0.0.101`
  (4444/443/22) and **not** the DFIR Madness IP; malfind must flag the verified
  RWX-private injected regions in `vmtoolsd.exe` (7164) and `powershell.exe` (4852).

Tier 1 where the answer key is a third-party write-up on real data
(coreupdater C2; SecurityNik sessions); Tier 2 for the layout-overlay derivation
from Volatility 3.

> **OWED — full netscan census vs Volatility 3.** A vol3 `windows.netscan`
> census of `citadeldc01.mem` (TCP 51 / UDP 19511 / listeners 123, dual-stack) was
> observed during development, but it lives only in an **uncommitted scratch
> harness** (`zz_scratch_netscan.rs`, which must not be committed). There is **no
> committed test** asserting those counts, so the census is *not* a corroborated
> claim here — only the per-connection C2 / malfind assertions above are. Promote
> the census to a committed, env-gated differential before relying on the counts.

### LSA secrets (lsadump) — Tier 2

`memf`'s `lsadump` walks the SYSTEM boot key → Vista+ LSA key (PolEKList) →
per-secret AES decrypt chain over a hive resolved from memory.
`~/src/issen/crates/issen-mem/tests/szechuan_lsadump.rs` (env-gated
`SZECHUAN_DC_MEM`, `#[ignore]`) validates it against **Volatility 3's
`windows.registry.lsadump`**, which decrypts 5 secrets on `citadeldc01.mem` —
notably `DefaultPassword` → UTF-16LE `ROOT#123` (a recovered auto-logon
password). The test asserts the secret is decrypted and equals `ROOT#123`.

Tier 2: Volatility is an independent oracle on a real dump; the scenario (this
dump, this secret) is the one we checked.

### issen ingest format detection (memory vs disk) — Tier 2

The ingest dispatcher must recognise a memory dump and redirect it to the
`memory` subcommand rather than mis-treating it as a raw disk image. The
`MemoryProvider` claims memory dumps ahead of the `DdProvider` last-resort
fallback. Validated by the real dispatch code path
(`~/src/issen/crates/issen-mem/src/provider.rs` and
`~/src/issen/crates/issen-dd/src/lib.rs`):

- `provider.rs` — `probe_lime_magic_returns_high` / `probe_crashdump_magic_returns_high`
  (LiME `EMiL` / crashdump magic recognised regardless of extension),
  `probe_mem_extension_raw_bytes_returns_medium` (headerless `.mem` recognised by
  extension as the tiebreak over the DD fallback),
  `probe_unrelated_extension_raw_bytes_returns_none`, `probe_nonexistent_returns_err`.
- `issen-dd/src/lib.rs` — `dd_provider_open_pcap_names_pcap_and_shows_hex`: a pcap
  is named as a pcap and its leading magic (`0xA1B2C3D4` either byte order, or the
  pcapng SHB `0x0A0D0D0A`) is surfaced in the message, turning a dead-end
  "unsupported" into an actionable redirect.

Tier 2: real binary/code-path output, with scenarios we constructed.

### Generic archive ingest (zip / 7z / tar.gz) — Tier 1/2 + security

`issen-archive`'s `ArchiveProvider` extracts a generic zip / 7z / `.tar.gz`
evidence collection to a tempdir (Confidence `Medium`, so a UAC/Velociraptor-shaped
archive still routes to its specific `High` provider) and returns a
`CollectionManifest` the orchestrator walks. The archive is untrusted evidence, so
**safe extraction is the load-bearing property** — extraction can never write
outside the tempdir. Tests in `~/src/issen/crates/issen-archive/`:

- **Real archive — Tier 1.** The real DFIR Madness `DC01-autorunsc.zip` extracts
  **byte-identical to the system `7z x`** (`autorunsc-citadel-dc01.csv`, SHA-256
  `2a2ea036…78482`, 1 068 150 bytes) — a third-party artifact decoded the same way by
  an independent tool.
- **Archive-wrapped disk image — Tier 2 (real data).** A disk-image container found
  inside an extracted archive is recursed through the disk pipeline (`open_collection`
  re-dispatches the first-segment container, cracking the NTFS volume), so
  `issen ingest DC01-E01.zip` works directly on the *downloaded* evidence archive — no
  manual unzip. Validated end-to-end on the real DFIR Madness `DC01-E01.zip` (4.5 GB zip
  wrapping the split `…CDrive.E01/.E02`): **139 artifacts → 727 393 events**, and the
  documented marker `--ip 10.42.85.115` returns **197** — *the same value measured on the
  bare-E01 ingest* — confirming the archive-wrapped image cracks to identical forensic
  content. The recursion itself is also covered hermetically by
  `crates/issen-unpack/tests/nested_container.rs` (mock providers, no fixture).
- **7z — Tier 2.** `extract_7z_matches_system_oracle` builds a `.7z` with the system
  `7z` (p7zip 17.05) and asserts `sevenz-rust`'s extracted tree matches `7z x`
  byte-for-byte (independent oracle).
- **Zip-slip / path-traversal — security.** `zip_slip_*` / `tar_slip_*` and the
  adversarial `adversarial_zipslip.rs` (hostile `../`, absolute, mixed-normalize, and
  symlink entries; the parent dir snapshotted byte-for-byte) assert **nothing is written
  outside the tempdir** — traversal entries are refused + recorded fail-loud. Containment
  is *structural*: `safe_join` rejects any `..`/absolute/drive component on every entry of
  every format; zip uses `enclosed_name()` **and** explicitly refuses symlink entries
  (matching tar), so a future zip-crate change cannot reintroduce an escaping symlink.
- **Decompression bomb — security.** The cap is **ratio-based** —
  `cap_for_archive_size = max(4 GiB floor, 100× compressed size)` (`cap_*` unit tests) —
  because a bomb is a *ratio* attack (1000×+), while a forensic disk image barely
  compresses (~1.1×) and so must be admitted. `zip_bomb_errors_with_bound_no_oom`:
  `write_capped` still errors at the (now per-archive) bound, never OOMs.

The slip/bomb fixtures are Tier-3 (hand-authored hostile archives, emitted via raw `ustar`
headers / `add_symlink` the way real malicious archives are built); the 7z and real-zip
checks are Tier-1/2 against the independent system `7z`.

### DNS resolver cache — **PENDING (not validated)**

Oracle **identified but the capability is not yet validated** — this is not a
correctness claim. **MemProcFS v5.17.8** (`m_sys_netdns`) recovers an 18-entry
DNS cache from `citadeldc01.mem` (a tier-2 answer key; full recipe in
`~/src/memory-forensic/docs/plans/2026-06-24-dns-cache-walker.md`). A de-risk
found `memf`'s current `dns_cache.rs` hardcodes a `DNS_CACHE_ENTRY` layout that
is **wrong for 2012 R2** (`Ttl@20` where the real record has `dwTTL@24`; `Data`
treated as inline where the real entry stores `pbData` as a pointer), and the
walker increments (the `.data` pointer-array scan, increments 2–4 in the plan)
are **unbuilt**. So: the oracle exists; the walker does not work on real 2012 R2
data yet. No tier is assigned until the walker is built and differenced against
MemProcFS.

### Timeline query (Phase 1) — **IN-PROGRESS (not landed)**

The intended oracle is **raw SQL on the real ingested `g1-rerun/dc01.duckdb`**:
the typed-flag query layer must reproduce the raw-SQL numbers the deck quotes
(e.g. the `event_type` histogram `RegistryModify` 195 485 / `FileCreate`
111 240). The DuckDB timelines are present
(`tests/data/dfirmadness-szechuan-sauce/g1-rerun/{dc01,desktop}.duckdb`), but a
search of the committed test tree found **no test referencing those counts or
the DuckDB timelines**. The Phase-1 work was in progress at write time, so this
is recorded as **not yet landed** — promote to a tiered entry once the test
exists and passes.

## Cross-referenced format-crate validation

The standalone forensic crates `issen` orchestrates carry their own validation
pages and corpora; this page does not restate them:

- **NTFS** — `ntfs-forensic/docs/validation.md` (TSK `fsstat`/`icat`, the `mft`
  crate, LogFileParser; CITADEL-DC01 + DEF CON `MaxPowers`).
- **Service/driver baselines** — `forensicnomicon/docs/validation.md` (DC01
  `SYSTEM` hive via `winreg-core`; LOLDrivers BYOVD; the `coreupdater.exe`
  masquerade isolation).
- Container readers, APFS/ext4, registry-on-disk, etc. — each crate's own
  `docs/validation.md`.

The fleet-wide machine index of every corpus (real-vs-synthetic, license,
ground-truth status) is [`docs/corpus-catalog.md`](corpus-catalog.md).

## Reproducing the validation

```bash
# DPAPI blob decrypt + master-key derivation (committed vectors, always run)
cargo test -p memf-windows dpapi::          # ~/src/memory-forensic
cargo test -p dpapi-core masterkey          # ~/src/dpapi-forensic

# In-memory hive dual-backend equivalence (committed, always run)
cargo test -p memf-windows --test hive_reader_dual_backend  # ~/src/memory-forensic

# Ingest format detection (committed, always run)
cargo test -p issen-mem provider
cargo test -p issen-dd

# Real-dump memf tests (need the gitignored 2 GB DC dump, extracted to /tmp)
SZECHUAN_DC_MEM=/tmp/szechuan-extracted/citadeldc01.mem \
  cargo test -p issen-mem --test szechuan_shellbags --test szechuan_lsadump \
                          --test szechuan_netstat -- --ignored --nocapture

# SecurityNik netscan/malfind (needs the 1.3 GB Total Recall zip)
MEMF_TEST_DATA=/path/to/SecurityNik \
  cargo test -p issen-mem --test securitynik_netscan_malfind -- --ignored --nocapture
```
