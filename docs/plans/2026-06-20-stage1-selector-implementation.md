# Stage 1 — Additive ArtifactSelector: Implementation Plan

**Parent design:** `2026-06-20-registry-driven-artifact-selector-design.md`
**Goal:** every parser declares an `ArtifactSelector` on its `ParserRegistration`. **Additive — nothing reads selectors yet; `detect_artifact_type` and `extract_triage` are unchanged, so runtime behavior is identical.** This stages the inputs for Stage 2 (differential classifier) and Stage 3 (derived collection).

## Key decisions

- **Shared matcher predicates live in `issen-core::classify`**, one `fn(&Path) -> bool` per `detect_artifact_type` arm, **copied verbatim from the classifier** so Stage 2's differential is exact by construction. Parsers that share an input (the 13 registry-hive parsers) reference the same predicate — a hive *is* a shared input, so this is honest, not duplication. The parser still *declares* (in its selector) which predicate is its input.
- **`disk_sources` are assigned to the parser that owns the file**, not duplicated across consumers. The base `RegistryHiveParser` owns the hive sources; the sub-parsers (shimcache, runkeys, …) declare empty `disk_sources` and consume what the base collects (collection dedups by path anyway). Linux/macOS and PE declare empty `disk_sources` (no ext4/APFS extractor; PE is `cost: OptIn`).
- **`priority`** mirrors the classifier's if-ladder order (earlier arm ⇒ higher priority), so Stage 2 first-match-wins reproduces today's precedence. Same-type overlaps (all registry parsers) need no priority distinction — they agree on the type.
- **Field is `Option<ArtifactSelector>` during population (incremental, workspace always builds), then hardened to required** in the final step so the compiler enforces presence forever.

## Types (issen-core)

```rust
pub struct ArtifactSelector {
    pub artifact_type: ArtifactType,
    pub matches: fn(&Path) -> bool,        // issen_core::classify::*
    pub priority: u8,
    pub disk_sources: &'static [DiskSource],
    pub cost: CostTier,
}
pub enum CostTier { Default, OptIn }       // OptIn = not collected by default (PE)
pub enum DiskSource { Ntfs(NtfsLoc) }      // Ext4/Apfs added when those extractors exist
pub enum NtfsLoc {
    FixedPath(&'static str),                              // extract_files
    DirSuffix { dir: &'static str, suffix: &'static str },// extract_dir_suffix
    PerUserFile(&'static str),                            // extract_per_subdir(\Users)
    PerSubdirSweep { parent: &'static str, rel: &'static str, name: NameMatch }, // extract_subdir_sweep
    NamedStream { path: &'static str, stream: &'static str },                    // extract_named_streams
}
pub enum NameMatch { Suffix(&'static str), Prefix(&'static str) }
```

## TDD task sequence

1. **RED — infra + gate.** Add `classify` predicates (verbatim from `detect_artifact_type`) + selector types to issen-core, unit-tested against the same inputs the classifier uses. Add `selector: Option<ArtifactSelector>` to `ParserRegistration`; sweep all ~30 `inventory::submit!` sites to `selector: None` (scripted). Add `crates/issen-cli/tests/selector_gate.rs`: every registration has `Some` selector whose `artifact_type` is in the parser's `supported_artifacts()`. Compiles, **fails** (all `None`).
2. **GREEN — populate.** Each parser sets its selector per the manifest below. Gate passes.
3. **Harden.** `Option<ArtifactSelector>` → required `ArtifactSelector`; remove `None`. Compiler now enforces presence.
4. **Verify.** Full workspace build + clippy `-D warnings` + every gate green. Confirm `detect_artifact_type` and `extract_triage` are byte-for-byte unchanged (Stage 1 adds no behavior). Re-run the real-data tests (`extract_user_artifacts`) — unchanged.

## Work manifest (parser → selector)

`pred` = `issen_core::classify::`. Registry family shares `registry_hive`. Priority: higher = checked first.

| Parser | artifact_type | matches (pred) | priority | disk_sources | cost |
|---|---|---|---|---|---|
| UsnJrnlParser | UsnJournal | `usn` | 100 | `NamedStream(\$Extend\$UsnJrnl, $J)` | Default |
| MftFileParser | Mft | `mft` | 99 | `FixedPath(\$MFT)` | Default |
| EvtxFileParser | EventLog | `evtx` | 98 | `DirSuffix(\Windows\System32\winevt\Logs, .evtx)` | Default |
| PrefetchParser | Prefetch | `prefetch` | 97 | `DirSuffix(\Windows\Prefetch, .pf)` | Default |
| RegistryHiveParser | Registry | `registry_hive` | 96 | `FixedPath`×{SYSTEM,SOFTWARE,SAM,SECURITY,DEFAULT}, `PerUserFile`×{NTUSER.DAT, AppData\Local\Microsoft\Windows\UsrClass.dat} | Default |
| RegCatalogParser | Registry | `registry_hive` | 96 | — | Default |
| ShimcacheParser | Registry | `registry_hive` | 96 | — | Default |
| RunKeysParser | Registry | `registry_hive` | 96 | — | Default |
| Dcc2Parser | Registry | `registry_hive` | 96 | — | Default |
| LsaSecretsParser | Registry | `registry_hive` | 96 | — | Default |
| ComHijackParser | Registry | `registry_hive` | 96 | — | Default |
| ShellbagsParser | Registry | `registry_hive` | 96 | — | Default |
| UserAssistParser | Registry | `registry_hive` | 96 | — | Default |
| LxssParser | Registry | `registry_hive` | 96 | — | Default |
| SvcDiffParser | Registry | `registry_hive` | 96 | — | Default |
| SamParser | Registry | `registry_hive` | 96 | — | Default |
| TypedUrlsParser | Registry | `registry_hive` | 96 | — | Default |
| AmcacheParser | Amcache | `amcache` | 90 | `FixedPath(\Windows\AppCompat\Programs\Amcache.hve)` | Default |
| SrumParser | Srum | `srum` | 90 | `FixedPath(\Windows\System32\sru\SRUDB.dat)` | Default |
| LnkParser | Lnk | `lnk` | 80 | `PerSubdirSweep(\Users, AppData\Roaming\Microsoft\Windows\Recent, Suffix .lnk)`, `PerSubdirSweep(\Users, Desktop, Suffix .lnk)` | Default |
| RecycleBinParser | RecycleBin | `recycle_i` | 80 | `PerSubdirSweep(\$Recycle.Bin, "", Prefix $i)` | Default |
| SetupApiParser | DeviceInstall | `setupapi` | 70 | `FixedPath(\Windows\INF\setupapi.dev.log)`, `FixedPath(\Windows\INF\setupapi.setup.log)` | Default |
| LinuxAuthLogParser | LoginHistory | `auth_log` | 60 | — (ext4, dormant) | Default |
| LinuxBashHistoryParser | LoginHistory | `bash_history` | 60 | — | Default |
| LinuxSyslogParser | SystemInfo | `syslog` | 55 | — | Default |
| LinuxCronParser | CrontabConfig | `cron` | 55 | — | Default |
| MacosUnifiedLogParser | SystemInfo | `macos_log` | 50 | — (apfs, dormant) | Default |
| MacosFsEventsParser | SystemInfo | `fsevents` | 50 | — | Default |
| PeParser | Pe | `pe_suspicious` | 10 | — | **OptIn** |
| BiomeParser | BiomeMenuItem | `segb` (new) | 40 | — | Default |

Notes:
- **Biome** is command-routed today; giving it a `segb` matcher makes it discovery-reachable — a deliberate *improvement* Stage 2's differential will flag as an intentional new classification (annotate it).
- `$LogFile` (in today's `WINDOWS_TRIAGE_PATHS`) has no parser; under derived collection it stops being collected — a clean drop (it was never parsed). Note for Stage 3.
- The classifier's `is_regf` magic-byte fallback inside `registry_hive` reads the file; the predicate keeps it for parity (path-only callers get `false`, same as today).
