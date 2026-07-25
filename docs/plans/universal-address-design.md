# Persistent Evidential Address — Design (minimal [P] cut)

**Status:** Proposed (design only; no production code changes). Revised after adversarial review (agy + codex panel); the broader five-primitive/universal-URI vision is **deferred, not deleted** — see Appendix A.
**Date:** 2026-07-18
**Prior art this extends:** `state-history-forensic/src/identity.rs` (`ArtifactRef`, `IdentityClaim`, `IdentityDiscipline`, `VolumeId`), `forensic-vfs` (`FileId`, the resolved layer stack), `forensicnomicon-core` (the `FsKind` keystone precedent for relocated identity types), the `[P]` navigation primitive (`issen/CLAUDE.md`).

## Executive Summary

One new claim variant — `IdentityClaim::PersistentAddress` — in the **existing** `state-history-forensic/src/identity.rs` gives every filesystem object a subject-world identity: `{ volume, file_id, path, allocation, stream }`. The strict key is the claim's deterministic canonical-byte serialization; derived `Eq`/`Hash` **is** the identity. Three things are deliberately **excluded from the key**: labels (display-only, never identity), the host (context — cloned VMs share a MachineGuid and would over-merge; a USB drive moved between hosts would under-merge), and the epoch (a temporal-state dimension the crate's existing `EpochTag`/cohort machinery already owns; where epochs are needed they derive from **subject state** — boot session, snapshot id — never from the acquisition event, so E01 vs live-mount vs VSS-of-the-same-state cannot split one object into several). `file_id` **reuses the fleet's `FileId` verbatim** rather than a partial mirror — relocated to `forensicnomicon-core` beside `FsKind` (the same keystone precedent), re-exported unchanged by `forensic-vfs`, so `state-history-forensic` depends only on the knowledge leaf. Correlation is an exact-key batch join; merging is a deterministic whole-set operation with known-vs-known conflicts rejecting the merge as a Finding — there is no similarity-driven clustering, because pairwise compatibility is not transitive. **Phase-1 success: the same file reached via E01, live mount, and VSS on Case-001 yields byte-identical `PersistentAddress` claims — one join key.** Access routes (the `forensic-vfs` `PathSpec`) are case-file provenance records referencing the address, never part of it.

---

## 1. The Problem and the Decision

A resolved artifact today carries only its mechanical access locator — the `forensic-vfs` `PathSpec` (`7z://case.E01 → gpt[0] → bitlocker → ntfs:/Users/beth/notes.txt`). That records HOW the examiner reached the bytes; nothing records WHAT the object is in the subject world. Consequence: the same file reached through two routes (disk image vs live mount; disk file vs its VSS copy) produces artifacts issen cannot join except by ad-hoc heuristics.

**Decision:** add exactly one identity facet for the `[P]` (persistent-storage) primitive: `IdentityClaim::PersistentAddress`, the tuple `(volume, file_id, path, allocation, stream)`. Nothing else — no address URI language, no anchor chains, no host/epoch links, no new crate, no new module. The address belongs to the **subject world** (a claim about the evidence); the access `PathSpec` belongs to the **examiner world** (custody — a record of an action) and stays in the case file's provenance store, which references the address:

| | `PersistentAddress` claim | Access `PathSpec` (case-file provenance) |
|---|---|---|
| Question | What is this, in the subject world? | How did I reach these bytes, in the examiner world? |
| Lives in | `ArtifactRef.claims` | The case file's provenance store |
| Cardinality | One per filesystem object | Many per object (each access route is its own record) |
| Use | Correlation/DB join key | Re-resolution, verification, custody audit |
| Mutation | Immutable once emitted | Immutable once recorded |

One object reached three ways = one `PersistentAddress` claim + three provenance records pointing at it. "One object, many routes" is expressed by the join; no provenance is discarded; the identity type never learns what a resolution chain is.

---

## 2. The Claim

### 2.1 Type sketch (extends the existing enum — signatures only)

```rust
// state-history-forensic/src/identity.rs

#[non_exhaustive]        // ← added in this cut; see §5 (this addition IS a breaking change,
pub enum IdentityClaim { //   and #[non_exhaustive] makes it the last one of its kind)
    // ... all existing variants unchanged ...

    /// [P] persistent-storage evidential address: the subject-world identity of a
    /// filesystem object. Derived Eq/Hash over every field IS the strict identity;
    /// the canonical-byte serialization (§2.4) is the correlation/DB key.
    /// Deliberately contains NO labels, NO host, NO epoch — §3.2.
    PersistentAddress {
        /// Existing `VolumeId` (String), restricted to the stable-discriminator
        /// conventions of §2.2. Never a drive letter, never a volume label.
        volume: VolumeId,
        /// The fleet's `FileId`, reused verbatim (NtfsRef / ExtInode / ApfsOid /
        /// FatDirEntry / IsoExtent / Opaque) — NOT a partial mirror. Lives in
        /// `forensicnomicon-core` (relocated beside `FsKind`); forensic-vfs
        /// re-exports it unchanged (§4.2).
        file_id: forensicnomicon_core::FileId,
        /// Byte-verbatim path as recovered: '/'-separated components, raw bytes,
        /// no case folding, no Unicode normalization (§3.4). Empty for an orphan
        /// with no recoverable name (allocation distinguishes that case).
        path: Vec<u8>,
        allocation: Allocation,
        stream: StreamSel,
    },
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Allocation { Allocated, Deleted, Orphan }

/// Tri-state stream selector. `Unknown` (stream presence undetermined, e.g. a
/// producer that never inspected ADS) is a distinct concrete value — it is not
/// "matches anything", and it is not `Default`.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StreamSel { Default, Named(Vec<u8>), Unknown }
```

### 2.2 `VolumeId` conventions (reusing the existing type, tightening its use)

`VolumeId` is already an opaque `String` in `identity.rs`. For `PersistentAddress` its value is **restricted to scheme-prefixed stable discriminators**:

| Form | Meaning |
|---|---|
| `gpt:<guid>` | GPT partition GUID (lowercase hyphenated hex) |
| `uuid:<hex>` | Filesystem UUID (ext4 superblock, APFS volume UUID) |
| `vsn:<hex16>` | NTFS boot-sector volume serial (16 lowercase hex digits) |
| `mbr:<disksig-hex8>.<start-lba>` | MBR disk signature + partition start LBA |

Drive letters (`C:`) and volume labels (`WINDOWS`) are **banned** as `PersistentAddress` volume values: drive letters are per-boot mappings, labels are display strings. A producer that cannot determine a stable discriminator does not emit a `PersistentAddress` claim for that object (the other claims — `CanonicalPath`, `ContentHash`, … — still apply); it never substitutes an unstable value.

A `_partitionN`-style human name, when needed in a report, is a **rendering** derived from the case file — the ordinal is never identity (partition-table reordering is a real anti-forensic trick).

### 2.3 Display

Human rendering for reports/UI/logs joins the *display metadata* the case file holds (host name, volume label) around the claim's path: `[P]CITADEL-DC01:WINDOWS:/Users/beth/notes.txt`. This rendering is lossy, is **not** stored in the claim, and has no parser. The claim itself is the only machine form.

### 2.4 Canonical bytes — the DB key

The correlation/DB key is `PersistentAddress::canonical_bytes()`: a versioned, deterministic, length-prefixed binary encoding defined in-crate (one leading version byte; enum discriminant bytes; `u32`-LE length prefixes for the variable fields; field order fixed as declared). No serde dependency is required in the crate itself (a `serde` derive behind an optional feature may ride along for consumers, but the **key** is the in-crate encoding, so key stability never depends on an external codec's map-ordering rules).

Invariants (test- and fuzz-enforced):
1. `decode(canonical_bytes(a)) == a` (round-trip).
2. `canonical_bytes(a) == canonical_bytes(b) ⟺ a == b` (injective; the key equals strict identity).
3. `decode(arbitrary bytes)` never panics (fuzz target; typed error).

---

## 3. Semantics

### 3.1 Strict identity

Derived structural `Eq`/`Hash` over every field of `PersistentAddress` is the identity — a genuine equivalence relation, safe as a map/DB key. `StreamSel::Unknown` is a concrete distinct value (`Unknown ≠ Default ≠ Named`). There is **no** wildcard matching in equality, anywhere.

### 3.2 What is excluded from the key, and why (the three exclusions are load-bearing)

- **Labels.** Hostnames, volume labels, image names are display metadata: they collide, change, and are trivially spoofable. They live in the case file's context tables and in renderings (§2.3) — never in the claim, never in `Eq`/`Hash`. (An earlier draft carried labels inside the identity-bearing type while asserting "labels are never identity" — a contradiction the review caught; the label concept is now entirely outside the claim.)
- **Host.** The host is **context, not part of the `[P]` key**. Including it fails in both directions: cloned VMs and golden-image deployments share a Windows `MachineGuid`, so a host-bearing key **over-merges** distinct machines' files; a USB volume moved between two hosts would get two keys for one object and **under-merge**. The volume discriminator is the correct outermost `[P]` identity: it travels with the medium. Host association (which machine mounted this volume, when) is a case-file relation derived from registry `MountedDevices`/event evidence — queryable context beside the key, never inside it.
- **Epoch.** Temporal state is the crate's existing business: `TemporalCohort`/`EpochTag` already model "the same artifact across states", and `ArtifactRef` + `IdentityDiscipline` already group states into cohorts. Baking an epoch into the address key would duplicate that machinery — and the reviewed draft's binding ("epoch = the acquisition-baseline tag") was **wrong on its own terms**: the same subject state acquired twice (E01 vs live mount; a Velociraptor collection vs a KAPE collection) would get two epochs and two addresses, failing the headline "one address" promise. The correct rule, recorded here for every future use of epochs with addresses: **an epoch identity derives from the SUBJECT's state — boot-session id, VSS shadow-set id, APFS snapshot xid — never from the examiner's acquisition event.** Two acquisitions of one subject state are one epoch. In this cut, the address has no epoch field at all; a VSS copy of an unchanged file carries the same address as the live file (that is the correlation payoff), and if the object *differs* between the live volume and the snapshot, the claims legitimately differ in `file_id.seq`/content — different temporal states, grouped into a cohort by the existing discipline machinery.

### 3.3 Matching, merging — deterministic, batch, conflict-loud

- **Correlation is an exact-key join.** Two artifacts correlate under `PersistentAddress` iff their claims are strictly equal (equivalently: identical canonical bytes). Deterministic, order-independent, transitive by construction.
- **Matching disciplines.** `claims_match_under` gains arms so `PersistentAddress` participates in the **existing** disciplines — `PathStable` (equal `volume` + `path` + `stream`) and `ObjectStable` (equal `volume` + `file_id`) — no new `IdentityDiscipline` variant in this cut. Cross-form matching (`PersistentAddress` vs a legacy `CanonicalPath`/`NtfsFileRef` claim) is deferred (Appendix A).
- **No similarity clustering.** The reviewed draft's pairwise `compatible()` unification is **rejected**: partial-information compatibility is not transitive (A with unknown host is "compatible" with B on PC1 and with C on PC2, but B and C conflict), so any clustering driven by it is order-dependent and unsound. In its place, the only merge operation is a **deterministic batch merge** over immutable keys: given the full set *S* of observations that some evidence asserts co-refer, check every field across all of *S* — if the Known values of any field are not a singleton, the entire merge is rejected and a Finding is emitted (known-vs-known conflict, e.g. proposed code `SHF-ADDR-CONFLICT`, `Category::Provenance`); otherwise emit **one** merge event recording every input key and the merged result. The outcome depends on *S* as a set, never on arrival order. Keys are immutable: a merge event is a new case-file fact linking keys, not a rewrite of stored rows.

### 3.4 Path policy

- **Storage is byte-verbatim**: components as recovered, separator-normalized to `/` only. No case folding, no Unicode normalization at construction — an NFC/NFD pair or a deliberate case-twin is evidence, and normalizing would destroy it.
- **Strict identity is byte equality** of the stored form. Filesystem-aware, case/normalization-insensitive comparison (NTFS case-insensitivity, HFS+ NFD) is a *query-time* concern for analysts, layered in issen — it never changes the key. The robust facet is `file_id` (which is why `ObjectStable` matching exists); the path is corroborating.
- Deleted/orphan objects keep their `file_id` with `allocation = Deleted | Orphan` and an empty or partial `path`.

### 3.5 Enrichment of context — priority ledger, immutable keys

Enrichment fills **contextual metadata** (host name for a volume, volume display label, mount history) in the case file — it never rewrites a stored key. Rules:

- Monotonic Unknown→Known filling stands, but conflict handling is **not** first-writer-wins: freezing the first Known value can strand a stale one (a backup-hive hostname beating the active OS's). Instead, every fill carries a **priority class** on its source, and the retained value is the highest-priority one, with the full ledger kept:
  1. active/current OS state (the running `ControlSet`'s `ComputerName`, live `/etc/hostname`)
  2. snapshot/backup state (VSS-copy hives, backup hives, `RegBack`)
  3. examiner assertion (case metadata)
- A disagreement **within the same priority class** is a Finding (surfaced, both values kept in the ledger, no winner chosen). A lower-priority value never displaces a higher-priority one; a higher-priority arrival supersedes with the supersession recorded.
- Each ledger entry records: field, value, source (registry hive + key path / `/etc` file / examiner note), priority class, and a reference into the case file's provenance store for the artifact that justified it — enrichment has chain-of-custody without the identity type ever embedding an access route.

---

## 4. Interop

### 4.1 Deriving the claim from a resolved `forensic-vfs` stack

When resolution reaches an `FsNode`, every field of the claim is already in hand:

| Source in the resolved stack | Claim field |
|---|---|
| Filesystem layer (volume serial / fs UUID) or volume-system layer (GPT GUID, MBR sig+LBA) | `volume` (per §2.2 convention; prefer the fs-level discriminator, fall back to the partition-level one) |
| `FsNode`'s `FileId` | `file_id` (verbatim) |
| Resolved path components | `path` (byte-verbatim) |
| `FsMeta` allocation split (`Allocated`/`Deleted`/`Orphan`) | `allocation` |
| ADS/stream info in `FsMeta` | `stream` (`Default`/`Named`; `Unknown` only for producers that don't inspect streams) |

The derivation is total for `[P]`: no field needs enrichment to exist. Live-mount ingestion (4n6mount or the OS path) derives the same fields from the same on-disk structures — which is precisely what makes the E01/live-mount/VSS triple converge on one key.

The **derivation code lives in issen** (ORCHESTRATION — the layer that already sees both `forensic-vfs` types and `ArtifactRef`). If a second consumer needs it later, extract an adapter then, not before.

### 4.2 `FileId` reuse — relocated to `forensicnomicon-core` (the `FsKind` precedent)

`file_id` is the fleet's `FileId`, **reused verbatim**. The reviewed draft redefined a partial mirror (`FileIdent`) that silently dropped `FatDirEntry`, `IsoExtent`, and `Opaque` — a partial re-declaration that would have made FAT/ISO objects unaddressable and drifted from the source of truth. But reuse is NOT wired as a `state-history-forensic → forensic-vfs` edge; the type moves down instead:

- **`FileId` relocates into `forensicnomicon-core`, beside `FsKind`.** This follows the established keystone precedent exactly: `forensic-vfs` already depends on `forensicnomicon-core` and already re-exports `FsKind` from it (`forensic-vfs/Cargo.toml:21`, the fn-core 1.2 `FsKind` move). `FileId` is the same category of thing — a pure, format-defined identity structure (`NtfsRef{entry,seq}` / `ExtInode{ino,gen}` / `ApfsOid{oid,xid}` / `FatDirEntry` / `IsoExtent` / `Opaque`), a zero-dep enum that already derives `Eq + Hash` (verified, `fs.rs:18`) — knowledge, not vfs machinery.
- **`forensic-vfs` keeps `pub use forensicnomicon_core::FileId`** — zero breakage for every current `forensic_vfs::FileId` consumer; the import path they use today keeps working.
- **`state-history-forensic` depends on `forensicnomicon-core`** — a first-party KNOWLEDGE leaf that itself depends on nobody. The crate's "pure types, no I/O, no parsing" charter holds intact; there is no wrong-direction coupling to the vfs layer, no new crate, and no cycle.
- **Cost, stated:** one `forensicnomicon-core` minor bump (additive: the relocated type + the vfs re-export) and the usual fleet dependency reconvergence at implementation time. Both are routine (the `FsKind` move already walked this path).

### 4.3 Provenance stays in the case file

Nothing here serializes, stores, or references a `PathSpec` inside `state-history-forensic`. The case file's provenance store records each access route (keeping the PathSpec's own lossless canonical URI) and points at the artifact/address. "Resolvable" is a property of the case file (does a provenance record with an access route exist for this key?), never of the address.

---

## 5. Compatibility and Semver — the honest statement

- `IdentityClaim` and `IdentityDiscipline` are **not** `#[non_exhaustive]` today (`identity.rs:29`, `identity.rs:64`). Adding the `PersistentAddress` variant **is a breaking change** for downstream exhaustive matches. This cut adds `#[non_exhaustive]` to both enums in the same release, so this is the **last** break of its kind; the release is called out as breaking in the CHANGELOG (0.x: a minor bump with breaking semantics, stated plainly — not smuggled).
- `HashAlgo` already derives `Hash` (`identity.rs:13`) — no change needed there (a prior draft claimed otherwise; wrong).
- Exactly **one** new claim variant ships. No new disciplines, no new modules, no new crates.
- The `FileId` relocation is **additive** in `forensicnomicon-core` (minor bump) and **invisible** to `forensic-vfs` consumers (the `pub use` re-export keeps `forensic_vfs::FileId` working verbatim) — no break rides that move.
- The `cohort_key` fingerprint fold gains a `PersistentAddress` arm (its existing non-collision-resistant design is unchanged and its existing caveat stands; DB join keys use `canonical_bytes`, not `cohort_key`).

---

## 6. Phase 1 — Frozen Scope and Success Criterion

**In scope:**
1. `forensicnomicon-core`: relocate `FileId` beside `FsKind` (§4.2); `forensic-vfs` re-exports it (`pub use`) — zero consumer breakage; fn-core minor bump + dependent reconvergence.
2. `identity.rs`: the `PersistentAddress` variant (using `forensicnomicon_core::FileId`), `Allocation`, `StreamSel`, `canonical_bytes()`/`decode()`, `#[non_exhaustive]` on the two enums, `claims_match_under` arms for `PathStable`/`ObjectStable`, `claim_fingerprint` arm. Round-trip/injectivity/no-panic tests + fuzz target per the fleet gate.
3. issen: derivation at ingest (§4.1) for the disk pipeline, 4n6mount/live path, and the VSS view; the key stored as a column; provenance records referencing it; the batch-merge event + conflict Finding plumbing (§3.3); the priority-ledger context enrichment (§3.5) for host name/volume label display.

**Out of scope (deferred — Appendix A):** any URI text form, `[M]`/`[L]`/`[Q]`/`[C]` addresses, epoch anchors, cross-form matching against legacy claims, new disciplines, making the key issen's primary correlation key fleet-wide.

**Success criterion (Case-001, Doer-Checker):** the **same file** reached via (a) the DC01 E01 through the vfs stack, (b) a live mount of the same image via 4n6mount, and (c) the VSS snapshot view (for a file unchanged between live and snapshot) yields **byte-identical `PersistentAddress` claims** — one join key, three provenance records. Negative controls: a file *modified* between live and snapshot yields keys differing in `file_id.seq` (two temporal states, cohort-grouped under `PathStable`, not falsely merged); two different hosts' `C:\Windows\System32\ntdll.dll` yield different keys (different volume discriminators) while still correlating by `ContentHash` where contents match.

---

## 7. Residual Risks / Open Questions

1. **Volume-discriminator collisions are claims, not proofs.** NTFS volume serials are 64-bit and clonable; imaging tools duplicate GPT GUIDs. A duplicated discriminator over-merges two volumes' files. Mitigation is the standard one for every `IdentityClaim`: corroborate across facets (`ContentHash`, `file_id` patterns) and surface disagreement as a Finding; the claim set model already treats identity as evidence, not truth.
2. **Dual-discriminator drift.** §4.1 prefers the fs-level discriminator with partition-level fallback; two producers observing the same volume through different layers could emit different `volume` values (e.g. `uuid:` vs `gpt:`) and under-merge. Phase 1 must pin ONE deterministic preference order and both pipelines must apply it; the batch-merge path (§3.3) is the recovery mechanism when mixed-form data meets.
3. **Path byte-equality under-merges across encodings.** Two producers recovering the same name via different decode layers (raw bytes vs UTF-8-normalized) yield different `path` bytes and distinct keys; `ObjectStable` matching on `file_id` is the backstop. Producer discipline (emit as-recovered bytes, no normalization) must be stated in the derivation code's contract and tested.
4. **`StreamSel::Unknown` fragmentation.** A producer that doesn't inspect ADS emits `Unknown` where another emits `Default`, giving two keys for one object. The Phase-1 issen producers must all inspect streams (emit `Default`/`Named`); `Unknown` exists for legacy/degraded data only, and the batch merge handles reconciliation when it appears.

(The two dependency residuals of the prior revision — "`FileId` prerequisites unverified" and "the `state-history-forensic → forensic-vfs` edge" — are resolved by the §4.2 relocation: `FileId` already derives `Eq + Hash` in the source (`fs.rs:18`), and the knowledge leaf now depends only on `forensicnomicon-core`.)

---

## Appendix A — Future Work (deferred, not deleted): the Universal Evidential Address

The reviewed broader design — a five-primitive address `primitive → host → scope → epoch → locator` spanning `[P]/[M]/[L]/[Q]/[C]`, with a lossless canonical `evd:` URI and a lossy Display — remains the long-term direction: one addressing vocabulary across disk, memory, logs, live query, and content-addressed stores, so cross-media correlation (a disk EVTX record ≡ the memory-carved copy) becomes an address join. It is deferred until the `[P]` cut proves itself on real corpora, and any revival **must carry the corrections from this review**:

1. **Labels are display metadata everywhere** — outside every identity-bearing type, outside `Eq`/`Hash`, outside any key. No `(id, label)` pair may sit inside an equality-derived struct.
2. **Host is context for `[P]`** (and must be re-argued per primitive, not assumed): machine identity is meaningful scope for `[M]`/`[Q]`, but never inside a medium-portable `[P]` key.
3. **Epochs derive from subject state** (boot session, snapshot id, transaction id) — never from the examiner's acquisition event; two acquisitions of one subject state are one epoch. `EpochTag`/`ClockProvenance` remain the identity/trust vocabulary to reuse.
4. **No pairwise-compatibility clustering.** Partial-information matching is non-transitive; any future unification is the deterministic whole-set batch merge of §3.3, over immutable keys, conflicts rejecting loudly.
5. **Any text form is serialization-of-record only if it preserves key⟺bytes injectivity**; the Phase-1 canonical-bytes encoding is the precedent, and a URI form is a rendering of it, not a second source of truth.
6. Per-primitive scope/locator typing (a tagged `Body` union so invalid combinations are unrepresentable) and `#[non_exhaustive]`-everywhere remain the right shape when the extension happens.

`[M]`/`[L]`/`[Q]`/`[C]` extensions land one at a time, each with a concrete producer wired the release it ships, per the fleet's YAGNI discipline.
