# Split Plan: winevt-forensic → Issen

**Date:** 2026-05-04  
**Last revised:** 2026-05-04 (post-codebase audit, reflects actual repo state)

---

## Current State (as of last audit)

### winevt-forensic workspace — ACTUAL

```
winevt-forensic/
└── crates/
    ├── winevt-core          ← EvtxEvent + LogonSession + ProcessEvent types
    │   ├── src/lib.rs       ← domain types, logon_type_name(), substatus_description()
    │   └── src/binary.rs    ← EVTX binary format: EvtxFileHeader, EvtxChunkHeader,
    │                           EvtxRecordHeader, ELFFILE_MAGIC, ELFCHNK_MAGIC,
    │                           RECORD_MAGIC, IntegrityIndicator enum
    ├── winevt-integrity  ← detect_record_id_gaps(), verify_chunk_header_checksum(),
    │                           check_timestamp_monotonicity(), check_file_header_consistency()
    └── winevt-carver        ← carve_from_bytes(), recover_records_from_slice()
                                CarvedChunk, RecoveredRecord, CarveResult, Integrity enum
```

**No CLI binary. No `wt-evtx`. No `winevt-session`, `winevt-handlers`, `winevt-analyze`.**  
Those crates have been removed. The repo is a pure forensic library.

Pending (not yet added to workspace):
- `winevt-memory` — ETW/EVTX types for memory forensics (see `PLAN.md` §7)

---

### Issen — BROKEN PATH DEPS (fix immediately)

`Issen/Cargo.toml` still references four crates that no longer exist in winevt-forensic:

```toml
# THESE ARE BROKEN — delete them:
winevt-session  = { path = "../winevt-forensic/crates/winevt-session" }
winevt-handlers = { path = "../winevt-forensic/crates/winevt-handlers" }
winevt-analyze  = { path = "../winevt-forensic/crates/winevt-analyze" }
```

And `winevt-core` path dep should remain for now (until crates.io publish):
```toml
# KEEP (temporarily):
winevt-core = { path = "../winevt-forensic/crates/winevt-core" }
```

`rt-evtx/src/lib.rs` calls `winevt_session::correlate_sessions()` and `winevt_analyze::frequency_analysis()` directly — this code is now broken and must be rewritten to own the logic internally.

---

## Migration Status

| Task | Status |
|------|--------|
| Remove `winevt-session` from winevt-forensic | ✅ DONE |
| Remove `winevt-handlers` from winevt-forensic | ✅ DONE |
| Remove `winevt-analyze` from winevt-forensic | ✅ DONE |
| Remove `wt-evtx` CLI binary from winevt-forensic | ✅ DONE |
| Add `winevt-core/src/binary.rs` | ✅ DONE |
| Add `winevt-integrity` crate | ✅ DONE |
| Add `winevt-carver` crate (chunk discovery + record recovery) | ✅ DONE |
| Wire anti-forensic gap detection into `carve_from_bytes` post-carve | ⏳ Pending (user story 01) |
| Add `carve_from_file` and `verify_integrity` to winevt-carver | ⏳ Pending (user story 02) |
| Add `winevt-memory` crate | ⏳ Pending (user stories 04-05) |
| Remove broken path deps from Issen (`winevt-session` etc.) | 🔴 URGENT |
| Rewrite `rt-evtx/src/session.rs` to own session correlation | 🔴 URGENT |
| Rewrite `rt-evtx/src/analyze.rs` to own frequency analysis | 🔴 URGENT |
| Add `winevt-carver` + `winevt-integrity` deps to `rt-evtx` | ⏳ After crates stabilize |
| Publish `winevt-core` to crates.io | ⏳ After API stabilizes |

---

## Immediate Fixes Required in Issen

### Fix 1 — Remove broken path deps

In `Issen/Cargo.toml`, delete:
```toml
winevt-session  = { path = "../winevt-forensic/crates/winevt-session" }
winevt-handlers = { path = "../winevt-forensic/crates/winevt-handlers" }
winevt-analyze  = { path = "../winevt-forensic/crates/winevt-analyze" }
```

### Fix 2 — Rewrite `rt-evtx/src/session.rs`

Currently calls `winevt_session::correlate_sessions()` etc. Those crates are gone.  
Move the implementation directly into `rt-evtx`:

| Function | Was in | Now in |
|----------|--------|--------|
| `correlate_sessions()` | `winevt-session` | `rt-evtx/src/session.rs` |
| `extract_process_events()` | `winevt-session` | `rt-evtx/src/session.rs` |
| `link_processes_to_sessions()` | `winevt-session` | `rt-evtx/src/session.rs` |
| `find_lateral_movement()` | `winevt-session` | `rt-evtx/src/session.rs` |
| `find_orphaned_sessions()` | `winevt-session` | `rt-evtx/src/session.rs` |
| `LateralMovementFinding` | `winevt-session` | `rt-evtx/src/session.rs` |

Source material: the original implementations are in git history of winevt-forensic.

### Fix 3 — Rewrite `rt-evtx/src/analyze.rs`

| Function | Was in | Now in |
|----------|--------|--------|
| `frequency_analysis()` | `winevt-analyze` | `rt-evtx/src/analyze.rs` |
| `pivot_sessions_by_src_ip()` | `winevt-analyze` | `rt-evtx/src/analyze.rs` |
| `FrequencyKey` enum | `winevt-analyze` | `rt-evtx/src/analyze.rs` |
| `FrequencyAnomaly` struct | `winevt-analyze` | `rt-evtx/src/analyze.rs` |

### Fix 4 — Add `winevt-handlers` logic to `rt-evtx/src/handlers.rs`

| Item | Was in | Now in |
|------|--------|--------|
| `EventHandler` trait | `winevt-handlers` | `rt-evtx/src/handlers.rs` (new file) |
| 12 handler impls | `winevt-handlers` | `rt-evtx/src/handlers.rs` |
| `all_handlers()` | `winevt-handlers` | `rt-evtx/src/handlers.rs` |

**TDD for Fixes 2-4:**
Each fix requires: RED commit (failing tests) → GREEN commit (implementation).  
Recover the source code from `git log --all` in winevt-forensic:
```bash
git -C ../winevt-forensic log --all --oneline | grep GREEN
git -C ../winevt-forensic show <hash>:crates/winevt-session/src/lib.rs
```

---

## Target State (post all fixes)

### winevt-forensic (stable library suite)

```
winevt-forensic/
└── crates/
    ├── winevt-core          ← types + binary format constants     (publish to crates.io v0.1)
    ├── winevt-integrity  ← detection algorithms                (publish to crates.io v0.1)
    ├── winevt-carver        ← disk carving + integrity check      (publish to crates.io v0.1)
    └── winevt-memory        ← ETW/EVTX memory forensic types      (publish to crates.io v0.1)
```

NO CLI. Issen is the only CLI consumer.

### Issen (post-fix)

```
rt-evtx/
├── src/session.rs      ← owns session correlation (moved from winevt-session)
├── src/analyze.rs      ← owns frequency analysis (moved from winevt-analyze)
├── src/handlers.rs     ← owns event handlers (moved from winevt-handlers)
└── Cargo.toml          ← deps: winevt-core, winevt-carver, winevt-integrity
                           (path deps until crates.io publish, then versioned)
```

---

## Expanded Issen Capabilities (post winevt-carver/winevt-integrity)

Per `PLAN.md` §9, once `winevt-carver` and `winevt-integrity` are stable:

```toml
# rt-evtx/Cargo.toml additions
winevt-carver       = { path = "../../winevt-forensic/crates/winevt-carver" }
winevt-integrity = { path = "../../winevt-forensic/crates/winevt-integrity" }
```

New `rt analyse` capabilities:
1. **Corrupt file fallback**: when `EvtxParser::from_path` fails → fall back to `winevt_carver::carve_from_file` to recover available records
2. **Anti-forensic report section**: after parsing, run `winevt_integrity` checks → include indicators in triage output
3. **Log-cleared enrichment**: `LogClearedHandler` (EID 1102/104) enhanced with carver-based pre-clear record count

---

## Dependency Graph (final)

```
winevt-core  (crates.io)
    ^
    |
winevt-integrity  (crates.io)
    ^         ^
    |         |
winevt-carver  winevt-memory  (crates.io)

Issen/rt-evtx
    ├── winevt-core
    ├── winevt-carver
    └── winevt-integrity

memory-forensic/memf-windows
    └── winevt-core  (for binary format constants only)
```

---

## LateralMovementFinding → Evidence Bridge

(Unchanged from previous revision — still valid once session.rs is moved to rt-evtx)

```rust
impl From<&LateralMovementFinding> for Evidence {
    fn from(f: &LateralMovementFinding) -> Self {
        Evidence::new(
            EvidenceSource::Custom("winevt-session".into()),
            EvidenceKind::Network,
        )
        .with_subject(Some(SubjectRef::Session(
            format!("0x{:x}", f.sessions.first().copied().unwrap_or(0))
        )))
        .with_attr("src_ip", &f.src_ip)
        .with_attr("reason", &f.reason)
        .with_attr("session_count", &f.sessions.len().to_string())
        .with_tag("lateral-movement")
        .with_tag("windows-event-log")
    }
}
```

---

## Risk Register (updated)

| Risk | Status | Mitigation |
|------|--------|-----------|
| Broken path deps in Issen break `cargo build` | 🔴 ACTIVE | Fix 1 above — delete 3 lines from Cargo.toml |
| `rt-evtx/src/lib.rs` calls deleted crates | 🔴 ACTIVE | Fixes 2-4 — move code into rt-evtx |
| `winevt-core` API changes before crates.io publish | 🟡 | Mark public types `#[non_exhaustive]` |
| BinXml parsing in carved records | 🟡 | carver returns raw bytes; parsing delegated to `evtx` crate where possible |
| CRC32 variant mismatch | 🟢 MITIGATED | Verified: EVTX uses standard CRC32 (ISO 3309 = `crc32fast`) |
