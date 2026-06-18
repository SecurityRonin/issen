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
  jsonguard                output-sanitization utility leaf: RFC-4180 CSV /
                           formula-injection guard, bidi/control stripping,
                           serde JsonSafe<'_>; cross-cutting (memf uses it for
                           safe CLI output) — not a forensic format reader
  [repo: jsonguard]

CONTAINER                  decode a raw source format → addressable data stream
  ewf                      E01/EWF/Ex01 → raw sector stream     [repo: ewf, issen-ewf]
  vhdx                     VHDX → raw sector stream             [repo: vhdx, issen-vhdx]
  dd                       raw/dd/img → flat sector stream      [repo: dd, issen-dd]
  segb-core                Apple SEGB (Biome) container → v1/v2 record stream
                           (state, timestamps, CRC, protobuf payload);
                           App.MenuItem field walker  [repo: segb-forensic]
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
  segb-forensic            SEGB (Biome) records → anomaly Findings
                           (CRC-mismatch / timestamp-order); over segb-core
  [registry-forensic, prefetch-forensic, ...]
  [repo: browser-forensic, winevt-forensic, srum-forensic, segb-forensic, ...]

ORCHESTRATION
  useract-forensic         user-activity correlation: merges shell-history +
                           peripheral-device + Biome App.MenuItem events into
                           one per-user timeline (consumes segb-core)
  [repo: useract-forensic]
  Issen              wires all five paths, cross-artifact correlation,
                           TimelineEvent/Evidence, user-facing CLI
```

**Dependency rules:**
- CONTAINER depends on KNOWLEDGE only
- FILESYSTEM / PAGING / OS STRUCTURE / LOG FORMAT depend on their container + KNOWLEDGE
- OS STRUCTURE (memf-windows) MAY call PARSER repos when it locates artifact bytes
  in a VA region (e.g., SQLite page in hiberfil.sys → browser-forensic-carve)
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
memf-windows     → extracts SQLite page from VA      → browser-forensic-carve(bytes)
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

## Crate naming grammar (binding — applies to every fleet repo)

Two repo shapes, two naming patterns. Decide which shape a repo is *before* naming its crates.

**Pattern A — single-format repo** (containers/filesystems: vmdk, vhdx, ntfs, qcow2, segb).
Exactly two crates: `<x>-core` (reader) + `<x>-forensic` (analyzer). The `<x>-forensic` *crate*
name is reserved for this one-reader/one-analyzer shape (see the Crate-structure standard above).

**Pattern B — multi-crate PARSER/domain suite** (browser, winevt, memf). Decompose *by concern*
with role suffixes. The repo name is the **umbrella and is NOT itself a crate** — `memory-forensic`
→ `memf-*`, `winevt-forensic` → `winevt-*`, `browser-forensic` → `browser-forensic-*` (its short form `browser-*` is a generic word → keep the full prefix; see the self-describing rule below); there is no
`memory-forensic` / `winevt-forensic` / `browser-forensic` *crate*. Never rename a suite's analyzer
to `<repo>-forensic` (it over-claims, collides with the repo name, and breaks Pattern B). Suffixes:

| suffix | role | examples |
|---|---|---|
| `-core` | shared/domain types + format constants | browser-forensic-core, winevt-core |
| *family name* | a reader (one format/source) | browser-forensic-chrome / -firefox / -safari |
| `-carve` | recovery (free-page / WAL / record / unallocated) | browser-forensic-carve, winevt-carver |
| `-memory` | pure byte-pattern scanner, **medium-agnostic** | browser-forensic-memory, winevt-memory |
| `-integrity` | tamper / clearing / corruption detection (analyzer slot) | browser-forensic-integrity |
| `-analysis` | semantic analysis (e.g. event-ID → ATT&CK) | winevt-analysis |
| `-triage` | one-click **orchestrated report** (NOT `-rt`, NOT `-orchestrator`) | winevt-triage, browser-forensic-triage |
| `-cli` | front-end: CLI tool (may carry an interactive TUI *mode*) | browser-forensic-cli (`br4n6`), winevt-cli (`ev4n6`) |
| `-tui` | front-end: interactive TUI, no scriptable surface | *(pure-TUI only)* |
| `-mcp` | front-end: MCP server (agent-facing) | browser-forensic-mcp |

**Binding rules:**

- **The suite prefix must be self-describing on crates.io.** A crate name is read *bare* — in search,
  `cargo add`, and transitive dependency lists — with all repo/GitHub context stripped; the name alone
  must claim a namespace. A *distinctive* short prefix (`memf-`, `winevt-`, `snss-`) stands alone and is
  preferred for import brevity. A *generic-word* prefix does **not** stand alone, so that suite takes the
  full `<repo>-*` form: `browser-forensic-*`, never `browser-*` (which reads as a generic browser lib).
  The `repository` link is GitHub-only and never travels into the name.

- **Name by the role the analyst recognizes (the outcome), not by internal mechanism.** The
  orchestrated-report crate is `-triage` (what the user gets), never `-orchestrator` (how it is
  built) — and "orchestration" is reserved for issen's fleet-wiring layer. *One concept, one name*
  across the fleet: do not use `-rt` in one repo and `-triage` in another.
- **Name by the knowledge the crate owns; the dependency arrow then follows.** A format's
  byte-scanner is `<format>-memory` and lives **with the format parser**, depending DOWN on
  `<format>-core` — never `memf-<format>`. `memf-*` owns *memory navigation* (VA→PA, EPROCESS,
  VADs) and hands `&[u8]` across the boundary; the artifact-pattern knowledge is parser-side.
  PARSER crates must never import PAGING/OS-STRUCTURE, so a `memf-browser` would invert the
  dependency. (A memf-side *locator* that walks a process's VADs to find a region is a legitimately
  separate crate that *feeds* `<format>-memory` its bytes — complementary, not a rename.)
- **Front-end binaries follow the `<x>4n6` convention:** br4n6 (browser-forensic-cli), ev4n6 (winevt-cli),
  sqlite4n6, mem4n6, disk4n6. The *binary* is `<x>4n6`; the *crate* is `<artifact>-cli` (a CLI tool,
  which may carry an interactive TUI *mode*), `-tui` (pure-TUI only), or `-mcp` (agent-facing server).
  A **dual-mode** tool is `-cli` for fleet consistency (the CLI is the primary surface; the TUI is a
  mode), never `-tui` (that hides the CLI). **`-cli` is intentionally overloaded to cover dual-mode** —
  one consistent suffix fleet-wide is worth more than the precision of a separate `-term` (deliberate,
  non-purist; e.g. browser-forensic-cli is CLI + TUI yet stays `-cli`).
- **A reconstructor/`-writer` is read-only-safe** only when it emits derived artifacts to NEW paths
  (carved/repaired output), never the source. Prefer `-reconstruct` / `-rebuild` over `-writer` in
  a read-only suite to avoid the "evidence editor" misread.

**crates.io rename window:** a crate can be *deleted* (name freed, not merely yanked) within **72h
of first publish**, or later only if single-owner + <500 downloads + no dependents. Settle names
*before* publishing; if a rename is needed, do it inside the 72h window (delete + republish = clean,
no orphan). After 72h, a yank leaves the old name as a permanent reserved orphan.

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

## Batteries-Included — Compile Everything In (binding fleet default)

A forensic tool in the field must do the whole job from one artifact — the analyst
cannot `cargo build --features gpu,cloud` on an evidence workstation, and a capability
that isn't compiled in is a capability that isn't there when it matters. So:

- **`default-features = false` is BANNED as a way to slim a fleet dependency.** Depend on
  fleet crates (and capability deps like `blazehash`) with their full default feature set;
  the analyst gets a single static binary that can hash, carve, decompress, query, and
  report without a rebuild. Slimming to "keep the dep tree small" or to dodge a gate is the
  wrong instinct — it ships a tool that silently can't do the thing.
- **When full features trip a gate, fix the GATE, not the feature set.** The canonical case:
  `blazehash` pulls `xxhash-rust` (BSL-1.0), which fails a downstream `cargo deny` license
  allowlist. The fix is to **allow BSL-1.0 in the fleet `deny.toml`** (xxhash is a legitimate
  forensic hash), NOT to `default-features = false` blazehash and lose every other algorithm.
  Same for a heavy transitive: address it in `deny.toml`/`Cargo.lock`, never by amputating
  capability. (A genuine pre-release in the graph — e.g. `ml-dsa 0.1.0-rc.8` — is publish
  hygiene: pin it, don't slim around it.)
- **Commit `Cargo.lock` in every binary/app repo** so CI resolves the same batteries-included
  graph the analyst ships, instead of a fresh resolution that can pull a broken or
  license-tainted version. (This is what actually bit 4n6mount: no committed lock → fresh
  resolution → CI red, mis-diagnosed as a blazehash compile bug — blazehash compiles fine.)
- **Lean library core, full binary (the preferred mechanism — binding).** When a capability
  crate is both a heavy end-user tool AND something other fleet *libraries* link for one
  primitive, split it the way the fleet splits readers: a lean `<x>-core` library carrying just
  the primitives (e.g. `blazehash-core` = the hash algorithms, no GPU/cloud/DuckDB/yara), and the
  full `<x>` app/binary crate (every feature compiled in) depending on `<x>-core`. Fleet
  *libraries* that need only the primitive depend on `<x>-core` (lean, so no `default-features =
  false` is ever needed); fleet *binaries* and the `<x>` tool itself stay batteries-included. One
  `default` cannot be both lean-for-libraries and full-for-the-binary — the **split**, not
  feature-juggling, is the answer. Reference: `blazehash` → `blazehash-core` (lean lib) +
  `blazehash` (full binary); `ext4fs-core`/`ewf-forensic` depend on `blazehash-core` for
  `algorithm::hash_bytes`, never the GPU+cloud app stack.
- **Exception (the only one):** a genuinely optional, *rarely-wanted* heavy subsystem MAY be a
  named non-default feature **as long as the shipping binary turns it on**. The library's
  `default` may stay lean for third-party reuse, but every fleet binary that links it builds
  with the full feature set. The slim path is for outside consumers, never for our own tools.

## Fleet GUI Standard — egui (single binary, crates.io-publishable)

A fleet GUI follows the same shippability rule as a CLI: it must be a **pure-Rust,
single static binary** that `cargo install`s into a working app and **publishes to
crates.io** like the `<x>4n6` tools — never a webview app crates.io cannot deliver.

- **Framework: `egui` (`eframe`) is the default.** Immediate-mode, pure Rust, single
  static binary, no runtime deps, cross-platform, and the *same* code compiles to
  WASM for a browser build. It fits data-dense analyst UIs (super-timeline, event
  tables, MFT/registry trees, hex). The `-gui` crate then publishes exactly like
  `-cli`. (`iced`/`slint` are acceptable for a more polished retained-mode app, but
  egui is the default; the TUI→GUI progression `ratatui`→`egui` keeps the
  single-binary / `cargo install` / crates.io properties at every rung.)
- **Banned for fleet GUIs: Tauri / `dioxus-desktop` / any `wry`/webview bundle.**
  They ship a JS/HTML bundle + a bundler step, so crates.io cannot deliver a working
  artifact — they are release-installer-distributed, not `cargo install`. If one is
  *genuinely* required (rich web tech), it carries a documented reason AND
  `publish = false`, so it never reads as a missing publish (e.g. `srum-gui`).
- **Icons: `egui-phosphor`** — the ~6000-glyph Phosphor set (egui's built-ins are far
  too few). Pin it to the egui-matching version (egui 0.29 ↔ egui-phosphor 0.7). Wire
  once at startup: `egui_phosphor::add_to_fonts(&mut fonts, egui_phosphor::Variant::Regular);`
  then use glyph constants inline: `use egui_phosphor::regular;` →
  `ui.button(format!("{} Refresh", regular::ARROW_CLOCKWISE))`. **Reference
  implementation: `~/src/nameback` (`nameback-gui`).**

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
  - **Homepage** (the "About" website field): **leave EMPTY by default.** It is reserved for a genuine product/landing page if one ever exists — it is **not** the docs site. Docs are reached from the README's **docs badge** only; pointing Homepage at the Pages docs mis-slots documentation into the landing-page spot (and never add a separate "Full documentation →" prose link in the README — the docs badge covers that). Same destination may appear once per *surface* (About sidebar vs README body), never twice within the README.
- **Above the fold:** a bold one-line tagline (never copied between repos), then the single fastest path — for a `*-forensic` workspace lead with the *analyzer* hook (`audit_path(...)` → graded findings), since that is the differentiator, then show the reader.
- **Body:** the two-crate split (`<x>-core` reader / `<x>-forensic` analyzer), the anomaly-code table, and a "trust but verify" paragraph (panic-free, fuzzed, validated against real artifacts).
- **Comparison / capability tables** (the "What's Different" vs-competitors matrix, the artifact-coverage matrix): mark a supported cell with **`✅`** (U+2705), not a plain `✓` — the emoji reads at a glance and renders consistently. Use `—` (em dash) for "not supported" and the literal word `partial` for partial support; reserve `❌` only when an *explicit* negative is the point being made.
- **Footer (mandatory, exact):** `[Privacy Policy](https://securityronin.github.io/<repo>/privacy/) · [Terms of Service](https://securityronin.github.io/<repo>/terms/) · © 2026 Security Ronin Ltd` — and `docs/privacy.md` + `docs/terms.md` **must exist** to back the links.
- **Docs site must be LIVE at publish — no dangling links (publish gate).** A repo that carries a docs badge or the Pages footer links MUST ship a `.github/workflows/docs.yml` that builds mkdocs and deploys to GitHub Pages (reference: `browser-forensic/.github/workflows/docs.yml` — `mkdocs build --strict` → `configure-pages`/`upload-pages-artifact`/`deploy-pages`, pinned SHAs, `pages: write` + `id-token: write`), **and** Pages must be enabled (source = GitHub Actions). At publish, **verify the docs badge URL and the footer Privacy/Terms URLs actually resolve** (HTTP 200 *and* real content — beware fake-200s), exactly as the global "no dangling footer links" rule requires. A 404 docs badge on a published repo is the canonical dangling-link failure (it happened to sqlite-forensic — shipped with mkdocs.yml + docs/ but no deploy workflow, so the Pages URL 404'd). Never publish the badge before the site builds.
- **Documentation site = MkDocs, never rustdoc-only (fleet standard). Reference implementation: `sqlite-forensic`.** Every fleet repo's docs site is a **curated MkDocs site** — `docs.yml` runs `mkdocs build --strict` and deploys the rendered site to Pages. A `cargo doc` / rustdoc deploy does **NOT** satisfy this: rustdoc serves an auto-generated API reference, not the curated pages that back the README **docs badge** and the **Privacy/Terms footer links** — so on a rustdoc-only repo those footer URLs 404 (the dangling-link failure above). Copy the three pieces from `sqlite-forensic` and adapt names:
  1. **`mkdocs.yml`** — `site_name: <repo>`, `site_url: https://securityronin.github.io/<repo>/`, `repo_url`, `theme: { name: material }`, a `nav:` listing `index.md` + the repo's analysis docs (e.g. `validation.md`, `recovery-comparison.md`, `corpus-catalog.md`) + `privacy.md` + `terms.md`, `markdown_extensions` (`admonition`, `attr_list`, `md_in_html`, `pymdownx.superfences`, `tables`), `plugins: [search]`.
  2. **`docs/`** — at minimum `index.md` + `privacy.md` + `terms.md` (the footer-link targets) + `validation.md` (the Doer-Checker evidence); add per-domain pages as warranted.
  3. **`.github/workflows/docs.yml`** — `pip install mkdocs mkdocs-material` → `mkdocs build --strict --site-dir site` → `actions/upload-pages-artifact` / `actions/configure-pages` / `actions/deploy-pages` (pinned SHAs), `permissions: pages: write` + `id-token: write`, triggered on push to `docs/**` + `mkdocs.yml` (+ `workflow_dispatch`).
  **Migration debt (as of 2026-06-15):** `memory-forensic`, `winevt-forensic`, `forensicnomicon`, and `srum-forensic` still ship a rustdoc-only `docs.yml` (`cargo doc`) with no `mkdocs.yml` — convert each to the MkDocs standard above (their README footer Privacy/Terms links currently 404).
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

## Release & Distribution Standard — binaries + Homebrew/apt/winget (every app/CLI repo)

Reference implementations (both verified end-to-end): **`blazehash`** and **`disk-forensic`** —
`.github/workflows/release.yml` is byte-identical between them except for the binary/crate name and
the Homebrew dispatch `event-type`. Copy from one of those, then apply the rules below. This applies
to **apps/CLIs** (the `*4n6` binaries, `blazehash`, GUI tools) — published *libraries* only need the
`crate` job, not the binary/Homebrew/apt/winget channels.

### What one `v*` tag delivers

A single annotated, signed tag (`git tag -s vX.Y.Z && git push origin vX.Y.Z`) triggers
`release.yml`, which produces **all** of:
- **Standalone executables for macOS (aarch64 + x86_64), Linux (aarch64 + x86_64, musl-static), and Windows (x86_64 MSI)** — attached to a GitHub Release with a `checksums.txt`.
- **crates.io** publish (`crate` job).
- **Homebrew** formula bump (dispatch → shared tap).
- **apt/.deb** for amd64 + arm64, uploaded to the Release **and** pushed to Cloudsmith (`apt` repo).
- **winget** auto-PR (after the one-time manual bootstrap — see below).

Build matrix targets: `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-musl`,
`aarch64-unknown-linux-musl`, `x86_64-pc-windows-msvc` (binaries); `x86_64-unknown-linux-gnu` +
`aarch64-unknown-linux-gnu` (the `deb` job only).

### Secrets — ORG-level, single source of truth

All four release secrets live as **SecurityRonin organization** secrets (visibility = all repos), so
every fleet repo inherits them and rotation is one update:

| Secret | Purpose | Notes |
|---|---|---|
| `CARGO_REGISTRY_TOKEN` | crates.io publish | crate-scoped tokens are *more* secure than one broad token, but org-wide is the chosen trade-off for fleet convenience |
| `TAP_GITHUB_TOKEN` | dispatch to `SecurityRonin/homebrew-tap` | owned by `securityronin-bot`; the bot must have **write** (push) on the tap (see Homebrew) |
| `WINGET_TOKEN` | PR to `microsoft/winget-pkgs` | `securityronin-bot` PAT, `public_repo`; the fork lives at `securityronin-bot/winget-pkgs`; `release.yml` sets `fork-user: securityronin-bot` |
| `CLOUDSMITH_API_KEY` | push `.deb` to Cloudsmith | account-wide; works for any repo |

- **Shadowing rule (the trap):** a **repo-level** secret *overrides* an org secret of the same name.
  After adding an org secret, **delete the repo-level copies** or the repo keeps using its stale local
  value and silently ignores the org one. (`gh secret delete <NAME> -R SecurityRonin/<repo>`.)
- **Secret values are write-only** — they cannot be read back via API or copied between repos; they
  live only in GitHub's vault (and your password manager). "We have it in <repo>" means it's set on
  that repo's GitHub, not recoverable from the checkout.
- **Org secrets need `admin:org`** to manage via CLI (`gh auth refresh -h github.com -s admin:org`),
  or use the web UI (org owner can always do it there).
- **Binaries + GitHub Release need only the built-in `GITHUB_TOKEN`** — the four secrets are only for
  crates.io / Homebrew / winget / Cloudsmith. A release with *just* the executables works with zero
  external secrets.

### Two gotchas that fail the build/deb green-looking (both bit disk-forensic)

1. **`rust-toolchain.toml` pin overrides the cross-build → `error[E0463]: can't find crate for core`.**
   If the repo pins `rust-toolchain.toml` (apps pin to the dev toolchain, e.g. `1.96.0`), that pin
   overrides whatever toolchain the `dtolnay/rust-toolchain` action installs. The action adds the
   cross-*target* to its default `stable`, but cargo actually builds with the pinned version — which
   lacks the target → every cross build fails. **Fix:** pin the action to the *same* version, so the
   target lands on the toolchain cargo uses:
   ```yaml
   - uses: dtolnay/rust-toolchain@<sha> # stable
     with:
       toolchain: 1.96.0          # MUST match rust-toolchain.toml
       targets: ${{ matrix.target }}
   ```
   Apply to **both** the `build` job and the `deb` job (native `crate`/publish is unaffected).
   Symptom is platform-independent and fails in ~20s (before real compilation). A *native* `cargo
   publish --dry-run` will NOT catch it — only a `--target` build does.
2. **`cargo-deb` (v3.x) errors `The package must have a copyright or authors property`.** Add
   `authors = ["Albert Hui <albert@securityronin.com>"]` to `[package]` in `Cargo.toml`. (blazehash
   had it; disk-forensic didn't — that's the whole difference.) Verify locally before tagging:
   `cargo install cargo-deb && cargo deb` must package past the copyright check (the macOS-only
   `strip: unrecognized option --strip-unneeded` warning is harmless — GNU strip on the Linux runner
   is fine).

### crates.io versioning rule

A crate version can be published **once**. **Bump `version` in `Cargo.toml` before every release tag**
— a tag whose `crate` job re-publishes an existing version fails "already exists." Re-tagging the
*same* `vX.Y.Z` is only safe if the prior run never reached the `crate`/`release` jobs (e.g. it died
in `build`); once published, you must bump (e.g. `0.8.2` → `0.8.3`). To move a not-yet-published tag:
`git tag -d v… ; git push origin :refs/tags/v… ; git tag -s v… ; git push origin v…`.

### App requirement: conventional `--version`

The CLI must support `-V`/`--version` printing `<bin> X.Y.Z` to stdout and exiting **0** (use
`env!("CARGO_PKG_VERSION")`). The Homebrew formula `test do` block asserts on it
(`assert_match "<bin> #{version}", shell_output("#{bin}/<bin> --version")`). disk4n6 originally lacked
it and treated `--version` as a path — add it (TDD: RED parse test → GREEN).

### Homebrew — shared tap, per-project dispatch + handler

- One tap for the whole fleet: **`SecurityRonin/homebrew-tap`** (`brew install SecurityRonin/tap/<bin>`).
- **Each project dispatches its OWN `event-type`** (`update-<bin>`, e.g. `update-blazehash`,
  `update-disk4n6`) and the tap has a **matching per-project handler workflow** `update-<bin>.yml`
  listening on that type. **Never share a generic `update-formula` event** — two projects on the same
  event collide (the second project's release fires the first project's updater). Each handler downloads
  the release `checksums.txt`, fills the SHA256s, and writes `Formula/<bin>.rb`.
- **`securityronin-bot` must have `write` (push) on `homebrew-tap`** — `repository_dispatch` requires
  write access; a read collaborator gets 403. (Granting it creates an *invitation* the bot must accept:
  `gh api -X PUT repos/SecurityRonin/homebrew-tap/collaborators/securityronin-bot -f permission=push`
  then accept as the bot via `gh api -X PATCH user/repository_invitations/<id>`.)
- Formula class name is the bin name capitalized, digits kept (`disk4n6` → `class Disk4n6 < Formula`).
- The tap handler commits via the GitHub API / `github-actions[bot]` (GitHub-verified) — consistent
  with the tap's existing bot-commit style.

### winget — action does UPDATES only; first version is a MANUAL bootstrap

`vedantmgoyal9/winget-releaser` **cannot create a new package** — it only bumps an existing one. So
the `winget` job is `continue-on-error: true` and **fails harmlessly until the first version is
submitted by hand**. After the first PR merges, every future release auto-PRs the update. The PR
title tells which is which: a manual first submission says **"New package: …"** / "Add …"; the
action's auto-PRs say **"New version: …"**. (blazehash's 0.2.0 was a manual PR by `h4x0r`; 0.2.1+ were
auto by the bot.)

**Bootstrapping the first version from a Mac (no Windows, no `wingetcreate` — it's Windows-only):**
1. `brew install msitools` and extract the MSI GUIDs:
   `msiinfo export <bin>-X.Y.Z-x86_64-pc-windows-msvc.msi Property | grep -iE 'ProductCode|UpgradeCode|ProductVersion'`.
2. Get the installer SHA256 from the release `checksums.txt` (winget wants it **uppercase**).
3. Hand-author the **3 manifests** (model them on an existing fleet package already in winget-pkgs,
   e.g. `manifests/s/SecurityRonin/blazehash/<v>/`): `<Id>.yaml` (version), `<Id>.installer.yaml`
   (InstallerType `wix`, Scope `machine`, `ProductCode`, `AppsAndFeaturesEntries` with Product+Upgrade
   codes, the installer URL + SHA256), `<Id>.locale.en-US.yaml` (publisher/license/description/tags).
4. Submit via the bot, API-only (don't clone the huge winget-pkgs repo): `gh auth switch --user
   securityronin-bot` → `gh repo sync securityronin-bot/winget-pkgs --source microsoft/winget-pkgs` →
   create a branch ref at master → `PUT` the 3 files under
   `manifests/s/SecurityRonin/<bin>/X.Y.Z/` → `POST` a PR `head: securityronin-bot:<branch>`,
   `base: master` → `gh auth switch --user h4x0r`.
- **`PackageIdentifier` must be identical** between the manual first PR and the action's `identifier:`
  input (`SecurityRonin.<bin>`), or future auto-updates orphan.
- **Keep the MSI `UpgradeCode` stable across versions** (it's fixed in `wix/main.wxs`) — winget keys
  upgrades off it; a changing UpgradeCode makes each release look like an unrelated package.

### Cloudsmith (apt)

- One account-wide `CLOUDSMITH_API_KEY`. **The destination repo must exist first** —
  `securityronin/<repo>` at cloudsmith.io (the push 404s otherwise). Public install path:
  `curl -1sLf https://dl.cloudsmith.io/public/securityronin/<repo>/setup.deb.sh | sudo bash`.

### Pre-tag checklist

1. `version` bumped in `Cargo.toml` (not already on crates.io).
2. `[package] authors` present (cargo-deb).
3. `release.yml` toolchain pinned to `rust-toolchain.toml`'s version (if pinned).
4. CLI has `--version`.
5. Org secrets present; repo-level shadows deleted.
6. Homebrew: per-project `update-<bin>.yml` exists in the tap; dispatch `event-type` matches; bot has
   write on the tap.
7. Cloudsmith repo created.
8. First winget version bootstrapped (or accept `continue-on-error` until you do).
9. Tag is **signed** (`git tag -s`).
