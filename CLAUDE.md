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
  ewf                      E01/EWF → raw sector stream          [repo: ewf]
  [aff4, vmdk, raw, ...]   other disk image formats             [planned]
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
