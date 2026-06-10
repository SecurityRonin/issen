## Strategic Context

This project was planned using North Star Advisor.
Before implementing features, read:

- `north-star-advisor/ai-context.yml` - Strategic context (start here)
- `north-star-advisor/docs/INDEX.md` - Documentation hub

## Multi-Repo Architecture

Issen orchestrates a family of standalone forensic libraries. Each
library is a deep, self-contained expert in one artifact family; Issen
is the thin wrapping and correlation layer on top.

### The Layer Hierarchy

Layers are architectural concepts; a single repo may contribute crates to
multiple layers. Repos are noted in brackets.

```
KNOWLEDGE
  forensicnomicon          zero-dep, compile-time artifact specs, format constants
  [repo: forensicnomicon]
  state-history-forensic   zero-dep, [H] functor traits: HistoricalSource,
                           TemporalCohort<H>, ClockProvenance, ArtifactRef, …
  [repo: state-history-forensic]

CONTAINER                  decode a raw source format → addressable data stream
  ewf                      E01/EWF/Ex01 → raw sector stream     [repo: ewf, issen-ewf]
  vhdx                     VHDX → raw sector stream             [repo: vhdx, issen-vhdx]
  dd                       raw/dd/img → flat sector stream      [repo: dd, issen-dd]
  [vmdk, qcow2, vhd, iso, aff4, dmg, apfs-container]          [planned]
  memf-format              memory dumps (WinPMEM, raw,          [repo: memory-forensic]
                           hiberfil.sys, ELF core) → raw page stream
  [log containers: EVTX binary, journal binary, tracev3, PCAP, cloud API stream]

  Each path has its own address space and navigation primitive. All five are
  parallel and independent; none feeds another; all converge at PARSER.

  [P] Persistent Storage        [M] Memory              [L] Log
    navigate by: path             navigate by: PID        navigate by: timestamp
    name → inode → block          PID → EPROCESS          or record number
                                  → VA → PA               seek → boundary → field

    FILESYSTEM                    PAGING                  LOG FORMAT
      ext4fs-forensic               memf-hw  VA→PA          winevt-forensic  EVTX
      ntfs-forensic  [planned]      PML4/PAE/AArch64        [repo: winevt-forensic]
      apfs-forensic  [planned]      [repo: memory-forensic] journal-forensic [plan]
      4n6mount  FUSE bridge         OS STRUCTURE            tracev3-forensic [plan]
      [repo: ext4fs-forensic,         memf-windows            zeek-forensic  [plan]
       4n6mount]                       EPROCESS, VAD           cloudtrail-src [plan]
                                       DPAPI, DKOM
                                       memf-linux [planned]

  [Q] Live Query                [C] Content-Addressed
    navigate by: query            navigate by: hash
    (endpoint, query, cursor)     hash → blob → content graph
    → result rows

    QUERY ENGINE                  GRAPH NAVIGATION
      issen-remote-access           cas-forensic        [planned]
      velociraptor-parser           git-forensic        [planned]
      WQL / OSQuery [planned]       sigstore-forensic   [planned]

  Note: a disk path can feed a log or memory path — hiberfil.sys and EVTX files
  live on disk and are accessed via ext4/NTFS first. Cloud/streaming logs have
  no disk or memory path upstream — the log path stands alone.
  [Q] and [C] have no container in the traditional sense: the endpoint or hash
  store IS the entry point.

  [H] State-History (cross-cutting functor — NOT a vertical tier)
    [H] lifts each base primitive to a time-indexed variant:
    [P^H] disk-history     VSS, APFS snapshots, Time Machine, btrfs
                           [vss-history, apfs-snapshot-history — planned]
    [M^H] mem-history      hiberfil chain, VMware memory snapshots [planned]
    [L^H] log-history      journald sealed epochs, rotated logs [planned]
    [Q^H] query-history    point-in-time osquery exports [planned]
    [C^H] ≅ [C]            CAS is the fixed point: git already encodes history
    Shared traits:         state-history-forensic [repo: state-history-forensic]

PARSER                     interpret artifact records → forensic meaning
  browser-forensic         browser artifact files / SQLite pages → BrowserEvent
  winevt-forensic          EVTX records → EventRecord  (also in LOG FORMAT above)
  srum-forensic            ESE page bytes → SrumRecord
  [registry-forensic, prefetch-forensic, ...]
  [repo: browser-forensic, winevt-forensic, srum-forensic, ...]

ORCHESTRATION
  Issen              wires all five paths, cross-artifact correlation,
                           TimelineEvent/Evidence, user-facing CLI
```

**Dependency rules:**
- CONTAINER depends on KNOWLEDGE only
- FILESYSTEM / PAGING / OS STRUCTURE / LOG FORMAT depend on their container + KNOWLEDGE
- OS STRUCTURE (memf-windows) MAY call PARSER repos when it locates artifact bytes
  in a VA region (e.g., SQLite page in hiberfil.sys → browser-carve)
- PARSER depends on KNOWLEDGE only; accepts `Path` or `&[u8]` — never imports
  CONTAINER, FILESYSTEM, PAGING, OS STRUCTURE, or LOG FORMAT crates
- QUERY ENGINE crates (issen-remote-access, velociraptor-parser) depend on KNOWLEDGE
  and produce result-row types that feed into PARSER or directly into ORCHESTRATION
- GRAPH NAVIGATION crates (cas-forensic, git-forensic) depend on KNOWLEDGE and
  produce CAS event types that feed into PARSER or directly into ORCHESTRATION
- `[H]` crates depend on state-history-forensic (KNOWLEDGE) plus whichever layer they
  observe (FILESYSTEM for vss-history, PARSER for wal-history, etc.) — they may depend
  on any layer below ORCHESTRATION as needed, and export `TemporalCohort<H>` upward
- ORCHESTRATION is the primary wiring point between all layers

**The five navigation primitives:**
- [P] Disk: `name → inode → block address` (filesystem tree traversal)
- [M] Memory: `PID → EPROCESS → virtual address → physical address` (page table walk)
- [L] Log: `timestamp / record-number → record boundary → field decode` (stream seek)
- [Q] Live Query: `(endpoint, query, cursor) → result_set → field` (ephemeral; data is produced, not retrieved)
- [C] Content-Addressed: `hash → blob → content_graph` (Merkle DAG traversal; identity = hash)

**Why PARSER repos have no layer dependency below them:**

```
Live system      → OS opens Path normally            → browser-forensic(path)
4n6mount         → FUSE exposes path transparently   → browser-forensic(path)
ewf + ext4fs     → Issen extracts file bytes         → browser-forensic(bytes)
memf-windows     → extracts SQLite page from VA      → browser-carve(bytes)
winevt-forensic  → decodes EVTX record               → EventRecord
cloudtrail-src   → streams CloudTrail events          → (future parser)(record)
velociraptor     → executes VQL query                 → (parser)(result_rows)
cas-forensic     → resolves hash to blob content      → (parser)(bytes)
```

PARSER repos are medium-agnostic by design. The wiring to a source happens in
ORCHESTRATION or inside the OS STRUCTURE / LOG FORMAT / QUERY ENGINE layer that
located the artifact.

### Layer Responsibilities

**forensicnomicon:**
- Magic bytes, record markers, format header offsets (ESE page, EVTX chunk, etc.)
- Field schemas and invariants for application-level formats
- NO parsing algorithms, NO file I/O, NO binary deserialization

**state-history-forensic:**
- `HistoricalSource` trait, `TemporalCohort<H>`, `TemporalState<H>` generics
- `ArtifactRef` + `IdentityClaim` multi-facet identity; `IdentityDiscipline` selector
- `ClockProvenance` with 4 orthogonal axes (source / trust_grade / tamper_resistance / ordering_only)
- `EpochTag`, `LsnKind`, `CohortTopology`, `MaterializationSafety`
- `AcquisitionProtocol` and `StateMaterializer` trait boundaries
- NO parsing, NO file I/O; zero external deps; pure type/trait definitions

**CONTAINER crates** (ewf, memf-format):
- Decode the outer container/dump format to expose a raw addressable stream
- ewf: sector stream from E01 segments, hash verification
- memf-format: physical page stream from WinPMEM/raw/hiberfil.sys/ELF core
- Log containers (EVTX binary, journal, tracev3, PCAP) are handled within the
  LOG FORMAT layer itself — they have no separate "outer container" wrapper

**FILESYSTEM crates** (ext4fs-forensic, ntfs-forensic, apfs-forensic, 4n6mount):
- Navigate a sector stream by path: name → inode → block addresses → file bytes
- 4n6mount: FUSE bridge — makes any CONTAINER+FILESYSTEM pair look like a
  normal OS path, so PARSER repos need no image-format knowledge

**PAGING crate** (memf-hw / currently memf-core):
- Navigate a page stream by virtual address: PID → EPROCESS → VA → PA
- OS-agnostic: x86_64 PML4/5-level, PAE, AArch64 page-table walking
- ObjectReader: symbol-based kernel struct field access
- Knows nothing about Windows or Linux — pure hardware abstraction

**OS STRUCTURE crates** (memf-windows, memf-linux):
- Navigate a VA space by OS object: EPROCESS list, VAD tree, DPAPI cache, ETW
- Calls PARSER repos when known artifact bytes are located; passes `&[u8]`

**LOG FORMAT crates** (winevt-forensic, journal-forensic [planned],
tracev3-forensic [planned], zeek-forensic [planned], cloudtrail-src [planned]):
- Navigate a log stream by timestamp or record number: seek → boundary → fields
- Address space: sequence numbers, timestamps, cursor tokens
- winevt-forensic: EVTX chunk seek by record ID + BinXML field decode
- journal-forensic: journal cursor (seqnum + boot-id) → structured entry fields
- cloudtrail-src: time-range + pagination cursor → JSON event stream
- Note: winevt-forensic is both a LOG FORMAT layer (navigation) and a PARSER
  (semantic interpretation of Windows event IDs) — the boundary is internal to
  the repo: `binary.rs` / chunk walking = LOG FORMAT; `EventRecord` extraction = PARSER

**QUERY ENGINE crates** (issen-remote-access, velociraptor-parser):
- Execute a query against a live endpoint and stream result rows
- Navigation primitive: `(endpoint, query, cursor) → result_set → field`
- The query itself is part of the evidence chain; results are attacker-durable
- issen-remote-access: dispatches VQL/WQL/SQL to a remote agent
- velociraptor-parser: decodes Velociraptor collection output into typed rows

**GRAPH NAVIGATION crates** (cas-forensic, git-forensic, sigstore-forensic):
- Navigate a content-addressed store by hash: hash → blob → content graph
- Navigation primitive: Merkle DAG traversal — following object references by hash
- Identity equals hash: globally addressable, immutability guaranteed by construction
- cas-forensic: abstract CAS interface over git/OCI/IPFS
- git-forensic: commit/blob/tree graph + provenance chain
- sigstore-forensic: transparency log entries → artifact signing chain

**PARSER crates** (browser-forensic, winevt-forensic, srum-forensic, …):
- Accept `Path`, `&[u8]`, or structured log/query records; medium-agnostic
- `<format>-core`: domain types + format constants
- `<format>-carve`: free-page/WAL/record recovery, magic-byte scanning
- `<format>-integrity`: tampering and deletion detection (NOT "antiforensic")
- `<format>-memory`: pure byte-pattern scanner — no layer dependencies below PARSER

**Issen** (ORCHESTRATION):
- Thin `issen-<artifact>` wrapping crates
- Converts parser output into `TimelineEvent` / `Evidence`
- Wires all five paths into the correlation engine
- Cross-artifact correlation via `issen-correlation` and `forensic-pivot`
- User-facing CLI via `issen-cli`

### Practical Decision Rule

1. **"Is this a fact about a format?"** → `forensicnomicon`
2. **"Does this decode an image/dump container?"** → CONTAINER (`ewf`, `memf-format`)
3. **"Does this navigate sectors by path (name→inode→block)?"** → FILESYSTEM (`ext4fs-forensic`, `4n6mount`, …)
4. **"Does this navigate pages by virtual address (PID→EPROCESS→VA→PA)?"** → PAGING (`memf-hw`)
5. **"Does this walk Windows/Linux kernel objects?"** → OS STRUCTURE (`memf-windows`, `memf-linux`)
6. **"Does this navigate a log stream by timestamp or record number?"** → LOG FORMAT (`winevt-forensic`, `journal-forensic`, …)
7. **"Does this interpret artifact records as forensic evidence?"** → PARSER (`browser-forensic`, `winevt-forensic`, `srum-forensic`, …)
8. **"Does this correlate findings or drive the UX?"** → `Issen`
9. **"Does this execute a live query against an endpoint and capture the result?"** → QUERY ENGINE (`issen-remote-access`, `velociraptor-parser`)
10. **"Does this navigate a content-addressed store by hash (Merkle DAG)?"** → GRAPH NAVIGATION (`cas-forensic`, `git-forensic`, `sigstore-forensic`)
11. **"Does this enumerate the temporal cohort of states for an artifact?"** → `[H]` state-history layer (`vss-history`, `wal-history`, `git-history`, etc.) sharing types from `state-history-forensic`

## The Reporting Model — `forensicnomicon::report`

Format specs are one role of the KNOWLEDGE leaf; the **normalized reporting
vocabulary** is the other. Every analyzer in the fleet emits its findings as this
single model so ORCHESTRATION (Issen, disk4n6) and a future GUI render them
uniformly instead of N bespoke `XxxAnalysis` types. It is the **union (superset)
of the analyzers' data, not a flattening**.

### Core types (`forensicnomicon::report`)

- `Severity` — `Info < Low < Medium < High < Critical`. A finding carries
  `Option<Severity>`: `None` ("not scored") is forensically distinct from
  `Some(Info)` ("scored, benign"). Emit `None` only when the analyzer genuinely
  cannot grade in isolation (e.g. a PE writable+executable section); otherwise grade.
- `Category` — the analytical lens: `Integrity, Structure, Residue, Provenance,
  History, Concealment, Threat`. Coarse by design; fine taxonomy lives in `code` + MITRE.
- `Finding { severity, category, code, note, source, subjects, evidence, context }`
  — constructed **only** via `Finding::observation(sev, cat, code)` /
  `Finding::unrated(cat, code)` + the returned builder, never a struct literal.
- `FindingContext { confidence, occurrences, timestamps, external_refs, tags }`
  — the behavioral superset; disk findings leave it empty, memory/winevt/srum populate it.
- `Location` — `ByteOffset/Lba/Sector/Rva/RecordId/Path/Field/Key/Other{space,value}`.
- `SubjectRef { scheme, kind, id, label }` — non-disk subjects (process/module/registry/…).
- `ExternalRef` (e.g. `ExternalRef::mitre_attack("T1055.012")`) — **"consistent with", never a verdict.**
- `Report { findings, provenance, timeline, metadata }` — the aggregate Issen renders;
  `Report::{max_severity, findings_at_least, unrated_findings}`.

### The producer pattern

Each analyzer KEEPS its typed `AnomalyKind`/event type (domain knowledge) and
converts to canonical Findings — `forensicnomicon` never enumerates every anomaly kind:

- **Static codes** → `impl forensicnomicon::report::Observation` for the kind
  (`severity/category/code/note` required; `subjects/evidence/mitre/confidence` optional).
  `Observation::to_finding(Source)` assembles the `Finding` in one place.
- **Dynamic codes** (usnjrnl rule names, memory `Finding::Other(String)`, srum filter
  flags) → an inherent `fn to_finding(&self, Source) -> Finding` using the builder directly,
  because `Observation::code()` returns `&'static str`.

### Conventions (binding across the fleet)

- **`code` is a published contract**: scheme-prefixed SCREAMING-KEBAB
  (`VMDK-RGD-MISMATCH`, `MBR-PART-OVERLAP`, `MEM-PROCESS-HOLLOWING`,
  `WINEVT-PROVIDER-GUID-SPOOFING`). Never change a shipped code; new variants get new codes.
- **Category** defaults to `Category::from_code(code)`; override per-variant only where the
  keyword classifier is wrong (e.g. overloaded `BOOT-` prefixes).
- **Findings are observations, never legal conclusions** — the analyst/tribunal concludes.
  Use "consistent with" for MITRE/threat narration.
- **`#[non_exhaustive]` + builders** keep the model additively evolvable: a new field,
  `Location`, or `Category` variant is a non-breaking `forensicnomicon` minor bump, not a
  fleet-wide break. Consumers must use a `_` arm when matching the shared enums.

### Severity normalization (the canonical mapping every analyzer applies)

| Native scale | → canonical |
|---|---|
| 5-level (mbr, gpt, apm, iso9660, usnjrnl, memory) | identity |
| 4-level (vhdx, ewf, winevt, ese-integrity) | `Info→Info, Warning→Medium, Error→High, Critical→Critical` |
| 3-level (vmdk: `Info/Warning/Error`) | per-variant re-grade (a forensic judgment, not a blanket rename) |
| triage (srum-analysis: `Clean/Informational/Suspicious/Critical`) | `Clean→Info, Informational→Low, Suspicious→High, Critical→Critical` |
| unrated (exec-pe `PeAnomaly`) | graded per-variant on migration, or `severity: None` |

### Dependency direction

`forensicnomicon` is the leaf — every analyzer depends **down** onto it; it depends on
no one. Adding `report` did not change that. disk-forensic / Issen depend down onto both
the migrated analyzers and `forensicnomicon::report` to aggregate findings into one `Report`.

## Crate-structure standard — reader/analyzer split (core/ + forensic/)

**Standard layout for every format** (adopted 2026-06-08; reference impl: `ntfs-forensic`):

- **One workspace repo, named `<x>-forensic`** (the analyzer is the headline; keep this name even though the repo also holds the core crate).
- Two members:
  - **`core/`** → crate **`<x>-core`** — the raw reader/parser, exposes `Read + Seek` (containers) or `NtfsFs`-style navigation (filesystems). No findings.
  - **`forensic/`** → crate **`<x>-forensic`** — the anomaly auditor: `AnomalyKind`/`Anomaly` + `audit()`/`audit_record()` emitting `forensicnomicon::report::Finding` via `impl Observation`, **depending on `<x>-core`** (path within the workspace, registry version for publish).
- Optional `cli/` member for a debug CLI (the end-user CLI is still `disk4n6`/Issen).

**Naming / imports:**
- If the bare `<x>` crate name is taken on crates.io by a third party we can co-exist with safely (obscure/ours), publish `<x>-core` with `[lib] name = "<x>"` so consumers write `use <x>::…`. If the bare name is a *popular* crate (e.g. `ntfs` = Colin Finck's), do **not** hijack the import — keep `<x>_core` (ntfs-core imports as `ntfs_core`).
- Reader = `<x>-core`, analyzer = `<x>-forensic`. Always.

**Coverage gate:** each crate keeps 100% line coverage (`cargo llvm-cov --lib`, fail on any `DA:n,0`) **except lines annotated `// cov:unreachable`**. The analyzer's `audit_record`-style entry points are tested end-to-end (build a valid record, drive parse→extract→audit), not just the component helpers.

**Coverage is a backstop, not a 100%-for-its-own-sake target.** The number exists to prove behavior is exercised and to catch regressions — never pursue it by deleting defensive code or contriving meaningless tests (see the `// cov:unreachable` standard below, and the global "Coverage — A Backstop, Not a Target" discipline). **Pure-library crates** (the reference: vmdk/vhdx/ntfs/qcow2) gate on `--lib` at 100%. **Binary-shipping repos** (CLI/TUI/server — e.g. browser-forensic with `br4n6`/`bw`/MCP) gate on **`--workspace`** instead, because `--lib` neither counts integration-test coverage nor measures `main()`/render-loop bins, so it *understates* a binary repo. For those, keep the bin glue thin via the **Humble Object** pattern (decisions in testable libs, only an irreducible draw/read/transport shell in `main()`/the loop), ratchet the `--workspace` threshold to the actual achieved level (no slack), and document the residual untestable shell — do not exempt the glue silently nor drop the bar to hide it.

**`// cov:unreachable` — defence-in-depth over coverage purism (binding standard).** Panic-free parsers keep defensive guard arms (`let Some(x) = … else { continue }`, bounds-checked `.get()` fallbacks, length checks) that are *provably unreachable* under a dominating invariant but are kept so the code degrades gracefully if that invariant is ever broken by a future change. Such an arm cannot be exercised by any test. **Never delete or restructure a defensive guard solely to satisfy the coverage gate** — that trades robustness for a number, the exact opposite of the Paranoid Gatekeeper standard. Instead append `// cov:unreachable: <the dominating invariant>` to the uncovered line (the `continue;`/`return …;`/guard expression). The CI gate exempts only annotated lines; every other zero-hit line still fails. Prefer restructuring to *infallible-by-construction* (e.g. `split_at_mut` so there is no `Option` to guard) where it loses no defence; reach for a crafted-input test before annotating (only annotate genuinely-unreachable arms); the `code-coverage` CI job reads each `DA:n,0` line's source and fails unless it carries the marker.

**Realignment status:** `vmdk`, `vhdx`, `ntfs`, and `qcow2` are all migrated to the workspace standard (vmdk-forensic, vhdx-forensic, ntfs-forensic, qcow2-forensic — each `core/` + `forensic/`).

## Security & Robustness Standard — Paranoid Gatekeeper (MANDATORY for every `*-core` / `*-forensic` crate)

These crates parse **untrusted, attacker-controllable disk images**. The bar is: *never panic, never read out of bounds, never trust a length field.* The standard below is the **superset** of the strongest settings found across vmdk/vhdx/ewf/ntfs/qcow2 — every forensic crate must meet all of it.

**Lints (in `[workspace.lints]`, every member inherits via `[lints] workspace = true`):**
- `[workspace.lints.rust]`: `unsafe_code = "forbid"` — **except** crates that legitimately need one bounded `unsafe` (e.g. an mmap-backed reader calling `memmap2::Mmap::map`): use `unsafe_code = "deny"` and put a justified `#[allow(unsafe_code)]` on each genuine site (`forbid` can't be locally overridden). ewf-forensic does this for its 4 mmap sites; every other `unsafe` stays a hard error.
- `[workspace.lints.clippy]`: `all = warn`, `pedantic = warn`, `correctness = deny`, `suspicious = deny`, **`unwrap_used = deny`**, **`expect_used = deny`**. Pragmatic allows (priority 1): `module_name_repetitions`, `must_use_candidate`, `missing_errors_doc`, `missing_panics_doc`, `cast_possible_truncation/wrap/sign_loss/precision_loss`.
- Tests opt out of the panic lints: `#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]` in each lib; integration-test files (separate crates) need their own top-level `#![allow(clippy::unwrap_used, clippy::expect_used)]`.

**Panic-free production code:** no `.unwrap()`, `.expect()`, `panic!`, or unchecked slice indexing in non-test code. Read integers through bounds-checked helpers (`fn be_u32(data, off) -> u32 { let mut b=[0;4]; if let Some(s)=data.get(off..off+4){b.copy_from_slice(s);} u32::from_be_bytes(b) }`) — out-of-range yields 0, never a panic. Range-check every length/offset/count field from the image *before* using it; cap allocations (reject absurd table sizes) to defend against allocation bombs.

**Required tooling files (copy/keep in sync, repo root):** `deny.toml` (cargo-deny: licenses + advisories + bans), `.gitleaks.toml`, `clippy.toml`, `rustfmt.toml`, `.pre-commit-config.yaml`, `renovate.json`, `LICENSE`.

**Fuzzing:** a `fuzz/` cargo-fuzz workspace with **one target per parsed structure** (ntfs is the model: `boot`, `record`, `attributes`, `attribute_list`, `runlist`, `index_buffer`, `compress`, …) **plus** a `fuzz_forensic` target driving the full inspect/audit pipeline. Each target's invariant is "must not panic." A `fuzz.yml` CI workflow builds + smoke-runs every target.

**CI gates (every PR):** build, test, `cargo clippy --workspace --all-targets` (the paranoid set, warnings = errors), `cargo fmt --check`, `cargo deny check`, gitleaks, and **100% line coverage** (`cargo llvm-cov --lib`, fail on any `DA:n,0` not annotated `// cov:unreachable` — see the coverage-gate standard above). Validate against **real artifacts** (e.g. qcow2 validates `inspect()` against qemu-img-produced images with backing-file/snapshot/encryption + a real CirrOS corpus), not only synthetic fixtures.

**Compliance (2026-06-08):** qcow2, vmdk, vhdx, ewf, ntfs-forensic all enforce the `unwrap_used`/`expect_used = deny` panic lints with panic-free bounds-checked readers, and all have `fuzz.yml`. Panic-free remediation counts: vhdx 80 reads, ewf 47, ntfs 44+2, qcow2 clean by construction. Residual debt to clear in a *separate* pass (not security — pre-existing pedantic/fmt style): vhdx ~30 pedantic warnings, ewf broad stylistic allow-list + fmt diffs. The safety lints are hard denies everywhere.

## README Standard (every forensic repo)

Full rules live in the global `~/.claude/CLAUDE.personal.md` ("SecurityRonin Repository README Standard"); the load-bearing points for these crates:

- **Goal:** convert the target reader (forensic analyst *or* Rust dev) into an active user in **30 seconds** — `cargo add` to a result they care about, above the fold.
- **Badges (badge the guarantees we already enforce; plan for TWO rows — 9 badges wrap on GitHub, and accidental wrapping destroys the information architecture):**
  - *Row 1 — identity + adoption decision:* **Crates.io** version (both `<x>-core` and `<x>-forensic`) · **Docs.rs** (libraries) · **Rust MSRV** (e.g. `Rust 1.80+` — a build-compat go/no-go, so it pairs with identity, NOT buried in a meta tail) · **License: Apache-2.0** · **Sponsor** (`h4x0r`).
  - *Row 2 — trust proof:* **CI** (Actions passing) · **Coverage** (Codecov — the 100% line-coverage gate) · **`unsafe forbidden`** — only for crates that are genuinely `unsafe_code = forbid` (winreg/vhdx/ntfs/qcow2/sqlite-core…); the mmap crates (`ewf`, `memory-forensic`) are `unsafe_code = deny` + bounded-allow, so they **skip** this badge rather than misrepresent · **Security advisories clean** (RustSec / cargo-deny).
  - *Single-row order (when it doesn't wrap):* Crates.io · Docs.rs · Rust 1.80+ · CI · Coverage · unsafe-forbidden · security-audit · License · Sponsor.
  - *Optional / later:* Crates.io **Downloads** · **deps.rs** · a **fuzzing** badge ONLY with a real fuzz-CI story behind it (an unearned fuzz badge damages trust).
  - *Never badge:* a **Stars** badge — GitHub already renders the star count natively in the repo header; a README copy is pure redundancy.
  - Rationale (Codex-reviewed): lead with identity/installability (crates.io → docs → MSRV) so both audiences orient *before* the proof claims; **Coverage** bridges CI→security (read as a natural escalation of rigor); **unsafe-forbidden before security-audit** because memory-safety is the sharper differentiator for evidence parsers than dependency hygiene. Coverage/unsafe-forbidden/security-audit turn standards we *already meet* into visible proof — the "trust but verify" pitch.
- **GitHub repo metadata (the "About" panel — standardize across the fleet):**
  - **Description** (one line): `<Domain> forensic <library|reader|analyzer> — <what it parses/does>, <headline capabilities>. <differentiator>.` Mirror the README tagline (one concept, one name); lead with the artifact family, then capabilities (parse/detect/carve/recover), then the differentiator (panic-free · single static binary · no runtime deps · deleted-record carving). e.g. browser-forensic: *"Browser forensic library suite — parse Chrome/Firefox/Safari artifacts, detect history clearing, carve deleted records. Single static binary, no runtime deps."*
  - **Topics** (GitHub topics, ≤ 20, most-specific first): always `rust` + the DFIR set `forensics · dfir · digital-forensics · incident-response`; plus the **artifact-family** topic (`browser-forensics` / `memory-forensics` / `registry` / `ntfs` …) and the **specific formats/tools** it handles (`chrome · firefox · safari · sqlite`; `registry · windows`; etc.); add `cli` if it ships one.
  - **Homepage** (the "About" website field): set to `https://securityronin.github.io/<repo>/` (the Pages docs). The README links to docs via the **docs badge** — do **NOT** add a separate "Full documentation →" prose link (redundant with the badge + the homepage field).
- **Above the fold:** a bold one-line tagline (never copied between repos), then the single fastest path — for a `*-forensic` workspace lead with the *analyzer* hook (`audit_path(...)` → graded findings), since that is the differentiator, then show the reader.
- **Body:** the two-crate split (`<x>-core` reader / `<x>-forensic` analyzer), the anomaly-code table, and a "trust but verify" paragraph (panic-free, fuzzed, validated against real artifacts).
- **Comparison / capability tables** (the "What's Different" vs-competitors matrix, the artifact-coverage matrix): mark a supported cell with **`✅`** (U+2705), not a plain `✓` — the emoji reads at a glance and renders consistently. Use `—` (em dash) for "not supported" and the literal word `partial` for partial support; reserve `❌` only when an *explicit* negative is the point being made.
- **Footer (mandatory, exact):** `[Privacy Policy](https://securityronin.github.io/<repo>/privacy/) · [Terms of Service](https://securityronin.github.io/<repo>/terms/) · © 2026 Security Ronin Ltd` — and `docs/privacy.md` + `docs/terms.md` **must exist** to back the links.
- **No `## License` section** (the Apache-2.0 badge → `LICENSE` is the single source of truth; the fleet standardized on **Apache-2.0** for its explicit patent grant — migrate any residual MIT repos).
- A `docs/validation.md` documents the differential/real-artifact validation (Doer-Checker evidence). **Carving/recovery analyzers must validate against an *independent* reference tool, not only against records we deleted ourselves** — the established oracle per domain (e.g. SQLite deleted-record carving → **fqlite**; NTFS → analyzeMFT/the Sleuth Kit; registry → RegRipper/yarp) is the yardstick: run it on the same artifact and reconcile counts + contents, explaining any divergence.
- After a `*-core`→`*-core`/`*-forensic` restructure, **rewrite the README**: badges/links/repo-name/`cargo add` lines all point at the new crate names, not the pre-split single crate.

## Test Corpus Catalog — keep it current (MANDATORY)

`issen/docs/corpus-catalog.md` is the **single fleet-wide catalog** of all forensic test data —
real datasets (what + source + hotlinked download URL + MD5) and synthetic fixtures (the **exact
command line(s)** that produce them). Because `tests/data/` is gitignored, this catalog is the only
committed record others can use to reproduce the corpus.

**Whenever you download or build test data anywhere in the fleet, update the catalog in the same
change:**
- **Downloaded a real dataset?** Add an entry with: what it is, authoritative source, **hotlinked
  download URL**, `md5` of the file, and a redistribution note. Confirm provenance by inspecting the
  artifact, not just the filename (Doer-Checker).
- **Built a synthetic fixture?** Record the **verbatim command(s)** that generate it (the
  `qemu-img` / `mkfs` / `xorriso` / `ewfacquire` / `dar` / `hdiutil` line, or the in-code Rust
  builder fn + `file:line`). Never write "generated for coverage" without the command — if there is
  no generator, say "NO GENERATOR IN REPO" rather than guessing.
- Classify each entry (`REAL-ext` / `REAL-self` / `SYNTHETIC` / `VENDORED` / `FUZZ`) and mark
  confidence (`✓` confirmed / `~` inferred / `?` undetermined).
- Keep the **§H MD5 manifest** in sync (hash new files; `tests/data/` is gitignored so hashes must
  live in the catalog).

**One repo-root `tests/data/` (MANDATORY layout — workspaces included).** Every repo keeps a *single*
`tests/data/` at the repo root, never per-member `<member>/tests/data/` directories. In a Cargo
workspace each member's integration tests reach the shared fixtures with a **relative `include_bytes!`
path** — from `<member>/tests/<file>.rs` the repo root is two levels up, so it is symmetric across
members: `include_bytes!("../../tests/data/<file>")`. This keeps one home, one README, and no
duplication, and it is conceptually neutral (a carving fixture used only by `<x>-forensic` need not
live "inside" `<x>-core`).

- **Never symlink fixtures** to fake a shared location. `include_bytes!` follows symlinks on Unix, but
  **git on Windows materializes a symlink as a text file containing the link target** — `include_bytes!`
  would then embed that path *string* instead of the file bytes, silently breaking the Windows CI
  runner. Use the relative path, not a symlink.
- **Verification gate:** after moving/adding fixtures, `cargo test` for every member must still compile
  (the `include_bytes!` paths must resolve) — a wrong path is a build error, not a silent miss.

**`tests/data/README.md` (one per repo, MANDATORY).** Modeled on
[`issen/tests/data/README.md`](../tests/data/README.md): a per-file `#### <filename>` entry giving
**Source / Identity / writeup URL(s) / original download URL (hotlinked) / MD5 (or sha256) / notable
contents** for real datasets, and the **verbatim generator command** (or builder `fn` at `file:line`)
for synthetic fixtures — never a download URL for something we generate. The README is the co-located
human-facing detail; `docs/corpus-catalog.md` stays the single machine-index — **cross-reference, never
duplicate** (the README links up to the catalog). Document large untracked/gitignored artifacts here
too (provenance even when the bytes aren't committed — e.g. a vendored oracle's test corpus). Use
straight ASCII in paths/commands.
