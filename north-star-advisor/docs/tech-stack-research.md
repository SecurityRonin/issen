# Issen Technology Stack Research

> Research date: 2026-03-20
> Scope: Rust ecosystem evaluation for an integrated forensic triage platform

---

## 1. Binary Parsing & Forensic Crates

### Recommendation: **binrw** (primary) + **nom** (complex/streaming parsers)

| Crate | Approach | Best For |
|-------|----------|----------|
| **binrw** | Derive macros on structs | Fixed-layout binary structures (MFT records, USN entries, registry cells) |
| **nom** | Functional parser combinators | Complex/variable-length parsing, streaming input, protocol-level parsing |
| **deku** | Bit-level proc-macros | Bit-field-heavy formats (network packets, bitflags) |

**Rationale**: binrw provides the most ergonomic declarative approach for forensic struct parsing -- define the struct, derive `BinRead`/`BinWrite`, and get endian-aware parsing with validation. nom remains essential for streaming parsers and complex conditional logic. The existing `usnjrnl-forensic` and `tl` crates likely already use one of these; binrw is recommended for new parsers.

### Forensic-Specific Libraries

| Crate | Purpose | Status |
|-------|---------|--------|
| **forensic-rs** | Framework for reusable forensic artifact parsers | Active (Feb 2025), trait-based abstraction |
| **ntfs** (Colin Finck) | Low-level NTFS filesystem parsing | Stable, Apache 2.0/MIT |
| **nt_hive2** | Windows registry hive parsing | Active |
| **memprocfs** | Physical memory analysis (PCILeech/WinPMEM) | Active |
| **artemis** | Cross-platform DFIR parser (JS scripting via Boa) | Active, Windows/macOS/Linux/FreeBSD |
| **zff** | Forensic file format (alternative to E01/AFF) | Active, pure Rust |
| **fat** | FAT filesystem forensic parsing | Available |

**Key gap**: No pure-Rust E01/EWF reader exists. The user's `ewf v0.1` crate fills a genuine ecosystem void. The only alternative is FFI bindings to C-based `libewf`. This is a significant differentiator for the project.

**Sources**:
- [binrw on crates.io](https://crates.io/crates/binrw) | [GitHub](https://github.com/jam1garner/binrw)
- [deku on crates.io](https://crates.io/crates/deku)
- [forensic-rs on lib.rs](https://lib.rs/crates/forensic-rs) | [GitHub](https://github.com/ForensicRS/forensic-rs)
- [ntfs crate by Colin Finck](https://github.com/ColinFinck/ntfs) | [Blog post](https://colinfinck.de/posts/an-implementation-of-the-ntfs-filesystem-in-a-rust-crate/)
- [artemis on GitHub](https://github.com/puffyCid/artemis) | [Architecture](https://github.com/puffyCid/artemis/blob/main/ARCHITECTURE.md)
- [lib.rs parser implementations](https://lib.rs/parser-implementations)

---

## 2. Plugin Architecture

### Recommendation: **Dual-layer** -- abi_stable for performance-critical first-party plugins, WASM (Wasmtime + WIT) for sandboxed third-party plugins

### Native Plugins (First-Party / Trusted)

| Crate | Approach | Trade-off |
|-------|----------|-----------|
| **abi_stable** | FFI-safe trait objects, layout checking at load time | Mature (0.11.3), ~2yr since last update, Rust-to-Rust only |
| **stabby** | Stable ABI with niche optimization, sum-type support | Newer alternative, actively developed |
| **cglue** | Minimal FFI-safe trait objects, C/C++ binding generation | Subset of abi_stable, multi-language |

**Performance**: Native dynamic loading benchmarks at ~140K ns/iter vs ~970K ns/iter for WASM runtimes (roughly 7x faster).

### Sandboxed Plugins (Third-Party / Community)

| Runtime | Focus | Key Feature |
|---------|-------|-------------|
| **Wasmtime** | Standalone WASM execution, WASIp2 | Component Model support, official Bytecode Alliance |
| **Wasmer** | Embedded WASM, multiple compilers | WASIX (threads, sockets, tokio), Singlepass for fast compilation |
| **Extism** | Cross-language WASM plugin framework | Unified host/guest API, uses Wasmtime under the hood |

**2025-2026 consensus**: The WASM Component Model with WIT (WebAssembly Interface Types) is the recommended path for portable, sandboxed plugin systems. WASIp2 is now targetable from Rust (`wasm32-wasip2`).

**Recommended architecture for Issen**:
1. Core parsers: Static Rust crates in the workspace (no plugin overhead)
2. First-party extensions: `abi_stable` or `stabby` for native-speed dynamic loading
3. Community plugins: Wasmtime + WIT for sandboxed execution with defined capabilities
4. Scripting layer: Consider embedded JavaScript (Boa, as artemis does) or Lua (mlua) for quick custom parsers

**Sources**:
- [NullDeref: Plugins in Rust series](https://nullderef.com/blog/plugin-start/) | [Technologies](https://nullderef.com/blog/plugin-tech/) | [Dynamic Loading](https://nullderef.com/blog/plugin-dynload/)
- [abi_stable on crates.io](https://crates.io/crates/abi_stable) | [GitHub](https://github.com/rodrimati1992/abi_stable_crates)
- [stabby on GitHub](https://github.com/ZettaScaleLabs/stabby)
- [WASI Preview 2 plugins in Rust](https://benw.is/posts/plugins-with-rust-and-wasi)
- [Moonrepo WASM plugins (Extism)](https://moonrepo.dev/docs/guides/wasm-plugins)
- [WebAssembly in Rust 2025 Edition](https://medium.com/@mtolmacs/a-gentle-introduction-to-webassembly-in-rust-2025-edition-c1b676515c2d)

---

## 3. Report Generation

### Recommendation: **Askama** (HTML templating) + **Headless Chrome/Chromium** (PDF) + **docx-rs** (Word) + subprocess to python-docx for complex DOCX

### HTML Templating

| Crate | Type | Best For |
|-------|------|----------|
| **Askama** | Compile-time (Jinja syntax) | Production templates -- type-safe, fast, catches errors at compile time |
| **Tera** | Runtime (Jinja2 syntax) | User-customizable templates -- hot-reload, dynamic loading |
| **Maud** | Macro-based (Rust DSL) | Small HTML fragments, component-based UI |

**Recommendation**: Use **Askama** for built-in report templates (compile-time safety, zero-cost) and **Tera** for user-customizable templates (attorneys may need to adjust report layouts).

### PDF Generation

| Approach | Quality | Complexity | Dependencies |
|----------|---------|------------|--------------|
| **Headless Chrome** (via chromiumoxide/html2pdf) | Excellent -- full CSS3, JS, fonts | Medium | Chrome/Chromium binary |
| **WeasyPrint** (Python subprocess) | Very good -- CSS Paged Media | Low | Python + WeasyPrint |
| **printpdf** | Basic -- manual positioning | High for complex layouts | Pure Rust |
| **genpdf** | Basic -- high-level API over printpdf | Medium | Pure Rust (unmaintained ~3yr) |

**Recommendation**: Askama/Tera generates HTML reports, then headless Chrome converts to PDF. This produces attorney-ready quality with full CSS control. For environments without Chrome, fall back to WeasyPrint subprocess.

### Word/DOCX Generation

| Crate | Read | Write | Maturity |
|-------|------|-------|----------|
| **docx-rs** (bokuweb) | Yes | Yes | Most popular (1M+ downloads), WASM-compatible |
| **rdocx** | Yes | Yes | Newer, includes layout engine + PDF/HTML/Markdown export |
| **docx-rust** | Yes | Yes | Alternative, supports modification |

**Recommendation**: Use **docx-rs** for programmatic DOCX generation from Rust. For complex expert witness reports requiring advanced Word features (multilevel numbering, TOC, cross-references), use **python-docx via subprocess** -- this aligns with the CLAUDE.md directives about Word document heading numbering via `w:abstractNum` + `w:numPr`.

### Visualization

| Crate | Output | Best For |
|-------|--------|----------|
| **Plotters** | SVG, PNG, WASM, native backends | Pure-Rust high-performance charts, embedded in reports |
| **Charming** | HTML (ECharts), SVG, PNG, many image formats | Interactive charts in HTML reports, rich themes |

**Recommendation**: **Charming** for interactive HTML reports (leverages Apache ECharts), **Plotters** for static charts embedded in PDF/DOCX reports.

**Sources**:
- [Askama docs](https://askama.rs/en/stable/) | [GitHub](https://github.com/askama-rs/askama)
- [Tera + Askama comparison](https://leapcell.io/blog/seamless-server-side-templating-in-rust-web-applications-with-askama-and-tera)
- [Rust HTML to PDF comparison](https://docraptor.com/rust-html-to-pdf)
- [Production HTML-to-PDF service in Rust](https://lpfy.medium.com/building-a-production-ready-html-to-pdf-service-why-browser-pooling-matters-8d26ede62252)
- [INNOQ Report Generator in Rust](https://www.innoq.com/en/blog/rust-repoissen-generator/)
- [docx-rs by bokuweb](https://github.com/bokuweb/docx-rs)
- [rdocx on lib.rs](https://lib.rs/crates/rdocx)
- [Charming on GitHub](https://github.com/yuankunzhang/charming)
- [Plotters docs](https://docs.rs/plotters)
- [genpdf on crates.io](https://crates.io/crates/genpdf)
- [printpdf on GitHub](https://github.com/fschutt/printpdf)

---

## 4. Timeline & Database Backend

### Recommendation: **rusqlite** (SQLite) with WAL mode, prepared statements, and composite indexes

### Why SQLite

- **Battle-tested at scale**: The Matrix Rust SDK achieved **4.2 million events/second** throughput with rusqlite after query optimization (from an initial 19k/sec). This proves SQLite can handle forensic timeline volumes.
- **Single-file portability**: A forensic case's timeline can be a single `.db` file -- easy to share, archive, and reproduce.
- **Forensic integrity**: SQLite databases can be hashed for chain-of-custody verification.
- **Rusqlite maturity**: 40M+ downloads, bundled SQLite 3.51.3, production-proven.

### Performance Optimization Strategy

| Technique | Impact |
|-----------|--------|
| WAL mode (`PRAGMA journal_mode=WAL`) | Concurrent reads during writes |
| Prepared/cached statements | Eliminate repeated SQL parsing |
| Batch inserts in transactions | 15K+ inserts/sec (vs ~1.6K without) |
| Composite indexes on (timestamp, artifact_type, source) | Fast timeline range queries |
| `PRAGMA synchronous=NORMAL` | 2-3x faster writes (acceptable for non-financial data) |
| Memory-mapped I/O (`PRAGMA mmap_size`) | Faster reads for large databases |
| FTS5 full-text search | Fast keyword search across event descriptions |
| R*Tree index | Geospatial or range-based timeline queries |

### Schema Design for Forensic Timelines

```sql
CREATE TABLE events (
    id INTEGER PRIMARY KEY,
    timestamp_utc INTEGER NOT NULL,  -- Unix epoch nanoseconds
    timestamp_src TEXT,               -- Original timezone/format
    artifact_type TEXT NOT NULL,      -- 'usn_journal', 'mft', 'prefetch', etc.
    source_file TEXT,                 -- Path within evidence
    short_desc TEXT,                  -- Human-readable summary
    detail_json TEXT,                 -- Full parsed artifact as JSON
    evidence_hash TEXT,               -- SHA-256 of source for integrity
    tags TEXT                         -- Comma-separated analyst tags
);
CREATE INDEX idx_timeline ON events(timestamp_utc, artifact_type);
CREATE INDEX idx_artifact ON events(artifact_type, timestamp_utc);
```

### Alternatives Considered

| Database | Pros | Cons |
|----------|------|------|
| **DuckDB** (duckdb-rs) | Columnar, excellent analytics queries | Heavier, less portable |
| **Redb** | Pure Rust embedded KV store | No SQL, less query flexibility |
| **Sled** | Pure Rust embedded DB | Uncertain maintenance, no SQL |
| **Polars** | DataFrame library, fast analytics | In-memory focus, not a database |

**Verdict**: SQLite via rusqlite is the clear winner for forensic timelines -- portable, fast enough at scale, SQL-queryable, and chain-of-custody friendly. Use Polars for in-memory analytical transformations before writing to SQLite.

**Sources**:
- [Matrix Rust SDK: 19k to 4.2M events/sec](https://mnt.io/articles/from-19k-to-4-2m-events-per-sec-story-of-a-sqlite-query-optimisation/)
- [15k inserts/s with Rust and SQLite](https://kerkour.com/high-performance-rust-with-sqlite)
- [rusqlite on GitHub](https://github.com/rusqlite/rusqlite)
- [SQLite for time series in Rust](https://medium.com/rustaceans/harnessing-the-power-of-sqlite-for-time-series-data-storage-in-rust-a-comprehensive-guide-321612470836)
- [Rusqlite crate guide 2025](https://generalistprogrammer.com/tutorials/rusqlite-rust-crate-guide)
- [Investigating Rust with SQLite](https://tedspence.com/investigating-rust-with-sqlite-53d1f9a41112)

---

## 5. UI Layer

### Recommendation: **Ratatui** (TUI, immediate) + **Tauri v2** (desktop/web GUI, future) + **Axum** (API/dashboard backend)

### TUI (Current -- Phase 1)

**Ratatui** is the standard for Rust terminal UIs. It is the maintained successor to `tui-rs` and is widely used for forensic/security CLI tools. The existing `tl v0.1` timeline tool likely uses ratatui already.

### Desktop/Web GUI (Future -- Phase 2+)

| Framework | Paradigm | Verdict |
|-----------|----------|---------|
| **Tauri v2** | Web frontend + Rust backend | **Recommended** -- leverages existing web skills, smallest bundle size vs Electron, rich plugin ecosystem, auto-updater |
| **egui** | Immediate mode, pure Rust | Good for quick prototypes and debug UIs, limited layout customization |
| **Iced** | Elm-like retained mode | Pre-1.0, incomplete accessibility, steeper learning curve |
| **Slint** | Declarative DSL | Commercial license required for closed-source |

**Rationale for Tauri**: Issen's interactive HTML reports already require web rendering. Tauri reuses that investment -- the same Askama/Tera templates and Charming charts render in both standalone reports and the Tauri desktop app. The Rust backend handles parsing, and the frontend uses a lightweight framework (Svelte or Leptos).

### Web API (Backend for dashboards and remote access)

**Axum** (by the Tokio team) is the recommended web framework:
- Built on Tokio + Hyper + Tower middleware ecosystem
- Native SSE support for streaming timeline events to dashboards
- WebSocket support for real-time analysis collaboration
- ~10K concurrent connections with <5ms latency demonstrated
- Axum 0.8.x stable, 0.9 in development

### Real-Time Dashboard Pattern

```
[Forensic Engine (Rust)] --SSE--> [Axum Server] --WebSocket/SSE--> [Browser Dashboard]
                                       |
                                  [REST API for case management]
```

**Sources**:
- [2025 Survey of Rust GUI Libraries](https://www.boringcactus.com/2025/04/13/2025-survey-of-rust-gui-libraries.html)
- [Tauri vs Iced vs egui performance](http://lukaskalbertodt.github.io/2023/02/03/tauri-iced-egui-performance-comparison.html)
- [State of Rust GUI](https://weeklyrust.substack.com/p/the-state-of-rust-gui-the-good-and)
- [Rust GUI benchmark (2026)](https://medium.com/@build_break_learn/i-benchmarked-every-rust-gui-framework-they-all-failed-heres-why-i-m-going-back-to-electron-d88596c042fb)
- [Axum docs](https://docs.rs/axum/latest/axum/) | [GitHub](https://github.com/tokio-rs/axum)
- [Real-time WebSockets with Axum 2025](https://medium.com/rustaceans/beyond-rest-building-real-time-websockets-with-rust-and-axum-in-2025-91af7c45b5df)
- [Building real-time apps with Rust (2026)](https://oneuptime.com/blog/post/2026-02-01-rust-realtime-applications/view)
- [Rust HTMX and SSE](https://blog.nashtechglobal.com/rust-htmx-and-sse/)

---

## 6. Cross-Platform Considerations

### Recommendation: Native compilation per platform via CI matrix, static linking for IR deployment

| Concern | Strategy |
|---------|----------|
| **Build targets** | `x86_64-unknown-linux-musl` (static), `x86_64-pc-windows-msvc`, `x86_64-apple-darwin`, `aarch64-apple-darwin` |
| **Platform-specific artifacts** | `#[cfg(target_os = "windows")]` for Registry, Prefetch, NTFS-specific; `#[cfg(target_os = "macos")]` for plist, Unified Log |
| **Static linking** | `musl` on Linux, `+cissen-static` on Windows -- critical for IR deployment on target systems |
| **CI** | GitHub Actions matrix across OS runners; use `cross` tool for Linux ARM targets |
| **Filesystem abstraction** | Trait-based I/O layer (as forensic-rs does) so parsers work on live FS, disk images, or ZIP triage packages |

### Cross-Compilation Challenges
- macOS cross-compilation from Linux requires Apple SDK (licensing restrictions)
- Best practice: compile natively on each platform via CI matrix runners
- Windows: Use MSVC toolchain (not MinGW) for compatibility with forensic tool ecosystem
- Consider `cargo-dist` for automated release artifact building

**Sources**:
- [Cross compilation in Rust (2025)](https://fpira.com/blog/2025/01/cross-compilation-in-rust)
- [Building cross-platform tools in Rust](https://codezup.com/building-cross-platform-tools-rust-guide-windows-macos-linux/)
- [Effortless cross-compilation for Rust](https://medium.com/rust-rock/effortless-cross-compilation-for-rust-building-for-any-platform-6cce81558123)
- [artemis cross-platform forensic parser](https://github.com/puffyCid/artemis)

---

## 7. Cargo Workspace & Monorepo Strategy

### Recommendation: Single workspace, directory-based separation, feature flags for tier gating

### Proposed Workspace Layout

```
Issen/
├── Cargo.toml                    # Workspace root (resolver = "2")
├── crates/
│   ├── oss/                      # Apache 2.0 / MIT -- published to crates.io
│   │   ├── ewf/                  # E01 image reader (existing v0.1)
│   │   ├── usnjrnl/              # USN Journal parser (existing v0.6)
│   │   ├── mft-parser/           # MFT parser
│   │   ├── ntfs-artifacts/       # NTFS forensic artifacts
│   │   ├── tl-core/              # Timeline core data structures
│   │   ├── shrinkpath/           # Path shortening (existing v0.1)
│   │   ├── forensic-types/       # Shared types, traits, error types
│   │   └── prefetch/             # Prefetch parser
│   │
│   ├── proprietary/              # Closed source -- NOT published
│   │   ├── issen-engine/            # Pipeline engine, orchestration
│   │   ├── issen-reports/           # Report generation (HTML, PDF, DOCX)
│   │   ├── issen-timeline/          # Timeline aggregation, deduplication, scoring
│   │   ├── issen-ui/                # TUI/GUI application
│   │   └── issen-enterprise/        # Enterprise features (RBAC, API, etc.)
│   │
│   └── shared/                   # MIT -- internal shared utilities
│       ├── issen-common/            # Logging, config, CLI framework
│       └── issen-plugin-api/        # Plugin trait definitions (published for plugin authors)
│
├── plugins/                      # WASM plugin examples and templates
├── xtask/                        # Build automation (xtask pattern)
└── tests/                        # Integration tests, test fixtures
```

### Feature Flag Strategy

```toml
# In forensic-types/Cargo.toml
[features]
default = []
proprietary = []  # Gates proprietary trait implementations
enterprise = ["proprietary"]  # Superset

# In issen-engine/Cargo.toml
[features]
default = ["community"]
community = []           # Free tier: 5 artifact types, HTML reports
professional = []        # Paid: All artifacts, PDF/DOCX, timeline scoring
enterprise = ["professional"]  # Team features, API, RBAC
```

### Key Practices

1. **Use `resolver = "2"`** -- prevents unintended feature unification
2. **Path + version dual dependencies** for publishable crates
3. **`cargo-workspaces`** for batch version bumps and publishing
4. **`cargo-deny`** for license compliance (critical for mixed licensing)
5. **`cargo-nextest`** for faster test execution across the workspace
6. **`xtask` pattern** for build automation (generate test fixtures, run benchmarks, build releases)
7. **Feature matrix CI** -- test `community`, `professional`, and `enterprise` feature combinations

**Sources**:
- [7 Advanced Cargo Workspace Patterns](https://medium.techkoalainsights.com/7-advanced-cargo-workspace-patterns-for-scalable-rust-monorepo-management-and-build-orchestration-66b7913c1acb)
- [Monorepos with Cargo Workspace](https://earthly.dev/blog/cargo-workspace-crates/)
- [Cargo Features reference](https://doc.rust-lang.org/cargo/reference/features.html)
- [Publish all crates everywhere (Tweag, 2025)](https://www.tweag.io/blog/2025-07-10-cargo-package-workspace/)
- [Cargo Workspace Best Practices](https://reintech.io/blog/cargo-workspace-best-practices-large-rust-projects)

---

## 8. Performance & Processing

### Recommendation: **rayon** (CPU parallelism) + **memmap2** (memory-mapped I/O) + **tokio** (async I/O) + streaming parsers

### Parallel Processing

| Crate | Use Case |
|-------|----------|
| **rayon** | CPU-bound parallel parsing (MFT records, USN entries, hashing) |
| **tokio** | Async I/O for network, file streaming, concurrent evidence processing |
| **crossbeam** | Lock-free data structures, scoped threads for fine-grained control |

### Memory-Mapped I/O for Large Images

```rust
use memmap2::MmapOptions;
use rayon::prelude::*;

// Memory-map a forensic image
let file = File::open("evidence.E01")?;
let mmap = unsafe { MmapOptions::new().map(&file)? };

// Parallel processing with rayon's par_chunks
mmap.par_chunks(1_048_576) // 1MB chunks
    .for_each(|chunk| {
        // Process chunk (hash, scan, parse)
    });
```

### Streaming Parser Architecture

For multi-gigabyte evidence files:
1. **Memory-map** the E01/raw image via `memmap2`
2. **Stream** filesystem structures (MFT, USN Journal) using iterators
3. **Parallelize** independent record parsing via `rayon::par_bridge()`
4. **Batch-insert** parsed events into SQLite within transactions
5. **Report progress** via channels (`tokio::sync::watch` or `crossbeam::channel`)

### Benchmarks to Target

| Operation | Target | Reference |
|-----------|--------|-----------|
| MFT record parsing | >100K records/sec | Single-threaded baseline |
| USN Journal parsing | >500K entries/sec | With rayon parallelism |
| Timeline SQLite inserts | >15K events/sec | Batched transactions |
| Timeline SQLite queries | >4M events/sec | Optimized indexes (Matrix SDK benchmark) |
| E01 decompression + read | >200 MB/sec | Memory-mapped, parallel decompression |

**Sources**:
- [Accelerating file hashing with Rayon](https://transloadit.com/devtips/accelerating-file-hashing-in-rust-with-parallel-processing/)
- [Efficient File I/O in Rust (2026)](https://oneuptime.com/blog/post/2026-01-07-rust-file-io-efficient/view)
- [memmap2 on crates.io](https://crates.io/crates/memmap2)
- [Matrix SDK SQLite optimization](https://mnt.io/articles/from-19k-to-4-2m-events-per-sec-story-of-a-sqlite-query-optimisation/)

---

## Summary: Recommended Stack

| Layer | Choice | License |
|-------|--------|---------|
| **Binary Parsing** | binrw + nom | MIT |
| **NTFS** | ntfs crate (Colin Finck) | Apache 2.0/MIT |
| **E01 Images** | ewf (existing, proprietary advantage) | User-controlled |
| **Forensic Framework** | forensic-rs (traits) or custom traits | Apache 2.0 |
| **Plugin System** | abi_stable (native) + Wasmtime/WIT (sandboxed) | Apache 2.0/MIT |
| **Database** | rusqlite (SQLite) | MIT |
| **HTML Templating** | Askama (built-in) + Tera (customizable) | MIT/Apache 2.0 |
| **PDF Generation** | Headless Chrome via HTML | N/A |
| **DOCX Generation** | docx-rs + python-docx subprocess (complex reports) | MIT |
| **Charts** | Charming (interactive HTML) + Plotters (static) | MIT/Apache 2.0 |
| **TUI** | ratatui | MIT |
| **Web Backend** | Axum + Tokio | MIT |
| **Desktop GUI** | Tauri v2 (future) | MIT/Apache 2.0 |
| **Parallelism** | rayon + tokio | MIT/Apache 2.0 |
| **Memory-Mapped I/O** | memmap2 | MIT/Apache 2.0 |
| **Workspace Tooling** | cargo-workspaces, cargo-deny, cargo-nextest, xtask | Various |

---

## Ecosystem Peers & Inspiration

| Tool | Language | Relevance |
|------|----------|-----------|
| **Plaso/log2timeline** | Python | Super timeline creation -- Issen's `tl` competes here with Rust performance |
| **Eric Zimmerman's tools** | C# | Windows forensic artifact parsers -- gold standard for accuracy |
| **Autopsy/Sleuth Kit** | Java/C | Full forensic suite -- Issen is lighter, faster, attorney-focused |
| **Velociraptor** | Go | Collection + hunting -- Issen ingests its output |
| **artemis** | Rust | Cross-platform DFIR parser -- closest Rust ecosystem peer |
| **forensic-rs** | Rust | Reusable forensic framework -- potential collaboration or trait alignment |

**Sources**:
- [ForensicRS GitHub](https://github.com/ForensicRS/forensic-rs)
- [Artemis GitHub](https://github.com/puffyCid/artemis)
- [DFRWS: Transitioning from Python to Rust](https://dfrws.org/presentation/transitioning-from-python-to-rust-for-forensic-tool-creation/)
- [Forensic Tool Development with Rust](https://blog.getreu.net/projects/forensic-tool-development-with-rust/)
- [Plaso/log2timeline GitHub](https://github.com/log2timeline/plaso)
