# Memory Forensics Tools and Libraries: Comprehensive Research

**Date:** 2026-03-30
**Purpose:** Inventory of memory forensics frameworks, Rust ecosystem, extractable artifacts, commercial tools, and modern approaches.

---

## 1. Major Memory Forensics Frameworks

### 1.1 Volatility 3

**Status:** Active, gold standard. v2.27.0 (Jan 2026), v2.26.0 "Feature Parity" (May 2025).
**Architecture:** Python 3, modular object-oriented design with layered memory model (memory layers, symbol tables, object templates). Symbol-based analysis replaces heuristic profiling.
**Platforms:** Windows, Linux, macOS.

**Plugin System:**
- Modular architecture; community contributes via annual plugin contest
- VolShell interactive shell for plugin development
- 40+ Linux plugins, extensive Windows plugins

**Linux Plugin Categories:**
| Category | Key Plugins | What They Extract |
|----------|-------------|-------------------|
| Process Analysis | pslist, psscan, pstree, psaux, kthreads, pidhashtable, ptrace | Running/hidden/terminated processes, parent-child trees, command lines, kernel threads |
| Files | lsof, proc.Maps, pagecache (RecoverFs), mountinfo | Open file descriptors, memory-mapped regions, cached file recovery, mount points |
| Network | sockstat, sockscan, netfilter, ip.Addr, ip.Link | Sockets, active connections, firewall rules, interface config |
| Security | capabilities, check_creds, envars | Process caps, credential discrepancies, environment variables |
| Rootkit Detection | malfind, check_idt, check_syscall, check_afinfo, check_modules, hidden_modules, modxview, tty_check, keyboard_notifiers, ebpf | Code injection, IDT/syscall/network hooks, hidden modules, eBPF rootkits, keyloggers |
| Kernel | lsmod, module_extract, kallsyms, kmsg | Loaded modules, kernel symbols, kernel log buffer |
| Tracing | ftrace, perf_events, tracepoints | Kernel tracing framework state |
| User Activity | bash, elfs, library_list | Command history, ELF binaries, shared libraries |
| Scanning | vmaregexscan, vmayarascan | Regex and YARA scanning of process memory |

**Notable Community Plugins:**
- Docker container forensics
- OpenVPN credential extraction
- OpenSSH session key recovery
- HollowFind (process hollowing detection)
- eBPF rootkit detection

**References:**
- [Volatility Foundation](https://volatilityfoundation.org/the-volatility-framework/)
- [Volatility 3 Linux Plugins Docs](https://volatility3.readthedocs.io/en/develop/volatility3.plugins.linux.html)
- [Developing Volatility3 Plugins](https://jakeperalta7.github.io/2025/11/02/developing-a-volatility3-plugin.html)

---

### 1.2 Rekall (Discontinued)

**Status:** Archived. No active maintainers. GRR migrated to YARA.
**Historical significance:** Pioneered profile-free Linux analysis via /proc/kallsyms. Forked from Volatility "scudette" branch in 2011.
**Legacy:** WinPmem continues at [Velocidex/WinPmem](https://github.com/Velocidex/WinPmem).

**Capabilities (historical):**
- Cross-platform: Windows, macOS, Linux (32/64-bit)
- Live and offline analysis
- LMAP: inject pmem into existing kernel modules (no per-kernel compilation)
- YARA + Capstone disassembler integration
- Enterprise agent for remote forensics

**References:**
- [Rekall GitHub (Archived)](https://github.com/google/rekall)
- [Rekall Cheat Sheet - SANS](https://www.sans.org/posters/rekall-cheat-sheet/)

---

### 1.3 MemProcFS

**Status:** Active, v5.16.4 (Oct 2025). Rust crate v5.17.0.
**Architecture:** C/C++ core, FUSE-based virtual filesystem, multi-language APIs (Rust, Python, C#, Java).
**Paradigm:** Mount memory dumps as filesystems — browse artifacts as files/directories.

**Core Capabilities:**
- Process, thread, module, handle, network, registry as files/directories
- Forensic mode: sequential full-dump analysis, SQLite output, timelines, NTFS MFT
- Integrated YARA scanning with Elastic Security FindEvil rules
- Windows Defender AV detection integration
- Live memory via DumpIt, WinPMEM, PCILeech FPGA, VMware
- Remote IR via LeechAgent over SMB

**2025 Highlights:**
- ARM64 Windows support
- Hibernation file support
- Proxmox dump support
- Windows 11 24H2 support
- FindEvil: YARA scans of file objects, UM APC detection

**MemProcFS-Analyzer (Companion):**
- Automated analysis: OS fingerprinting, process tree, masquerading detection
- Artifact extraction: registry, EVTX, browser history, Amcache, ShimCache, Prefetch, LNK

**References:**
- [MemProcFS GitHub](https://github.com/ufrisk/MemProcFS)
- [MemProcFS-Analyzer GitHub](https://github.com/LETHAL-FORENSICS/MemProcFS-Analyzer)
- [MemProcFS Forensic Wiki](https://github.com/ufrisk/MemProcFS/wiki/FS_Forensic)

---

### 1.4 mquire (Trail of Bits, February 2026)

**Status:** New, proof-of-concept. Written in Rust.
**Innovation:** Zero-dependency Linux memory forensics — no external debug symbols needed.
**Architecture:** Leverages kernel-embedded BTF (type info) + kallsyms (symbol addresses).

**Capabilities:**
- SQL-based query interface (osquery-inspired)
- Queryable tables: processes, open files, memory mappings, network connections, interfaces, kernel modules, kernel ring buffer, system logs, kernel symbols
- Hidden process detection via multiple enumeration strategies
- File recovery from page cache (.dump command)
- Raw memory carving (.carve command)
- Library crate for building custom analysis tools

**Requirements:** Kernel 4.18+ (BTF), 6.4+ (kallsyms)

**References:**
- [mquire GitHub](https://github.com/trailofbits/mquire)
- [Trail of Bits Blog](https://blog.trailofbits.com/2026/02/25/mquire-linux-memory-forensics-without-external-dependencies/)
- [Help Net Security](https://www.helpnetsecurity.com/2026/03/04/mquire-open-source-linux-memory-forensics-tool/)

---

## 2. Rust-Based Memory Forensics Ecosystem

### 2.1 Acquisition Tools

| Tool/Crate | Purpose | Downloads | Notes |
|------------|---------|-----------|-------|
| **avml** (Microsoft) | Linux volatile memory acquisition | 67,574 | Static binary, LiME format, Snappy compression, Azure Blob upload |
| **freta** | Project Freta cloud analysis client | 21,369 | 4,000+ kernel versions, agentless VM analysis, rootkit detection |

### 2.2 Analysis Frameworks

| Tool/Crate | Purpose | Downloads | Notes |
|------------|---------|-----------|-------|
| **memprocfs** | MemProcFS Rust API wrapper | 35,233 | Full VMM access, plugin development in Rust |
| **mquire** | Zero-dep Linux memory forensics | New (2026) | BTF+kallsyms, SQL interface, file recovery |
| **dmalibrary** | DMA card memory forensics | — | PID discovery, sig scanning, scatter read/write |

### 2.3 Support Tools

| Tool/Crate | Purpose | Downloads | Notes |
|------------|---------|-----------|-------|
| **yara-x** | Pure Rust YARA implementation | 81,574 | Drop-in YARA replacement |
| **btf2json** | Volatility3 profile generation from BTF | GitHub only | 12x faster than dwarf2json |
| **stringsext** | Multi-encoding forensic string search | GitHub only | Memory-safe string extraction |
| **ntdsextract2** | Active Directory ntds.dit parser | crates.io | |
| **zff** | Forensic image format library | crates.io | |
| **read-process-memory** | Cross-process memory reading | crates.io | |

### 2.4 Gap Analysis: What's Missing in Rust

- **No pure-Rust Volatility equivalent**: No framework for full cross-platform memory analysis
- **No Rust-native Windows memory parsing**: Relies on MemProcFS C/C++ core via FFI
- **No Rust crypto key extraction library**: No equivalent to bulk_extractor or CryKeX
- **No Rust memory visualization for ML**: No tools for converting dumps to images for ML
- **Limited Linux kernel structure parsing**: mquire is PoC-stage; no production-grade library

**References:**
- [crates.io memory-forensics keyword](https://crates.io/keywords/memory-forensics)
- [crates.io forensics keyword](https://crates.io/keywords/forensics)
- [GitHub memory-forensics+Rust](https://github.com/topics/memory-forensics?l=rust)
- [AVML GitHub](https://github.com/microsoft/avml)
- [MemProcFS Rust API Docs](https://docs.rs/memprocfs/latest/memprocfs/)
- [MemProcFS Rust Plugin Dev](https://github.com/ufrisk/MemProcFS/wiki/Dev_Rust)

---

## 3. Linux Memory Dump: Extractable Artifacts

### 3.1 Process Artifacts
- Running/terminated processes (task_struct traversal)
- Process trees (parent-child relationships)
- Command-line arguments, environment variables
- Process capabilities and credentials
- Kernel threads, PID hash table entries
- Ptrace relationships, per-process call stacks
- Memory maps (VMAs), ELF binaries, shared libraries

### 3.2 Network Artifacts
- Open sockets (AF_UNIX, AF_INET) with namespace, family, type, protocol
- Active TCP/UDP connections with endpoints
- Network interfaces (IP, MAC, scope, status, MTU)
- Netfilter hooks and firewall rules
- Reverse shells and backdoor connections

### 3.3 Kernel Artifacts
- Loaded/hidden kernel modules
- Kernel symbol addresses (kallsyms)
- IDT, syscall table integrity
- eBPF programs
- Ftrace, perf events, tracepoints
- Kernel log buffer (dmesg equivalent)
- TTY hooks, keyboard notifiers

### 3.4 File System Artifacts
- Open files per process (file descriptors)
- Mounted filesystems
- Page cache contents (file recovery without disk)
- Memory-mapped files
- Deleted files still in page cache

### 3.5 Cryptographic Material
- **AES keys**: Key-schedule validation scanning, metadata-based discovery, entropy analysis
- **RSA private keys**: ASN.1/PKCS#8 signature scanning (7-byte signature)
- **TLS/SSH session keys**: Extractable from process memory
- **FDE keys**: TrueCrypt DEVICE_EXTENSION, BitLocker key material
- **Ransomware keys**: 90%+ Salsa20 key recovery rate from live memory
- **Tools**: Interrogate, Volatility dumpcerts, bulk_extractor/aes_keyfind, CryKeX

### 3.6 Malware/Rootkit Indicators
- RWX memory regions not backed by files (code injection)
- Module discrepancies between enumeration sources
- Task list manipulation (process hiding)
- eBPF-based rootkits
- Syscall/IDT/network operation hooks
- Process hollowing indicators (PAGE_EXECUTE_READWRITE vs WRITECOPY, VAD tags)

### 3.7 Forensic Value Assessment

| Artifact Category | Forensic Value | Disk Alternative? |
|-------------------|---------------|-------------------|
| Running processes | **Critical** — shows live system state | Partial (prefetch, recent apps) |
| Network connections | **Critical** — C2, lateral movement | Partial (firewall logs, pcap) |
| Encryption keys | **Unique** — only source for software keys | None |
| Injected code/malware | **Critical** — fileless malware detection | None |
| Kernel rootkits | **Critical** — hidden from userspace | Very limited |
| Bash history | **High** — may differ from .bash_history | Yes (.bash_history file) |
| Page cache files | **High** — includes deleted files | Partial (disk carving) |
| eBPF programs | **Unique** — new attack vector | None |
| Credentials | **Critical** — plaintext in memory | Hashed on disk only |

**References:**
- [LiME Memory Acquisition](https://levelblue.com/blogs/security-essentials/memory-dump-analysis-using-lime-for-acquisition-and-volatility-for-initial-setup)
- [Linux Memory Forensics with Volatility](https://blog.ivanov.ninja/forensics-with-volatility-3-2025-edition/)
- [Crypto Key Extraction](https://www.sciencedirect.com/science/article/pii/S1742287609000486)
- [CryKeX](https://github.com/cryptolok/CryKeX)

---

## 4. Commercial Tools

### 4.1 Comparison Matrix

| Feature | Belkasoft X | Magnet AXIOM | X-Ways Forensics |
|---------|-------------|--------------|-------------------|
| RAM Acquisition | Built-in (kernel-mode) | External tools | X-Ways Capture / F-Response |
| RAM Analysis OS | Modern Windows, macOS, Linux | Broad (via imports) | Windows 2000-7 only |
| AI Integration | BelkaGPT (offline NLP) | Magnet.AI (triage) | None |
| Artifact Types | 1,500+ | Larger library | Focused hex/structure |
| Cross-Source | Yes | Industry-leading | Limited |
| Price | More affordable | Enterprise | Very cost-effective |
| Best For | Dedicated RAM forensics | Unified multi-source | Expert low-level analysis |

### 4.2 What Commercial Offers Over Open Source
1. Integrated acquisition-to-reporting workflows
2. AI/ML automated triage and classification
3. Cross-source correlation (mobile + desktop + cloud + RAM)
4. Enterprise features (compliance, multi-user, audit trails)
5. Vendor support, training, court testimony
6. Larger artifact parsers for application-specific data
7. GUI-driven lower barrier to entry

### 4.3 What Open Source Offers Over Commercial
1. Deeper low-level analysis capabilities
2. Plugin development and scripting
3. Auditable code for court admissibility
4. Free (critical for academic, small agencies)
5. Faster community response to new threats
6. Better Linux/macOS support
7. Purpose-built specialized tools

**References:**
- [Belkasoft RAM Forensics](https://belkasoft.com/ram-forensics-tools-techniques)
- [Magnet AXIOM](https://www.magnetforensics.com/)
- [X-Ways Forensics](https://www.x-ways.net/forensics/)
- [Top 10 Paid DFIR Tools 2025](https://hawkeyeforensic.com/top-10-paid-digital-forensic-tools-in-2025-features-pros-cons/)

---

## 5. Modern Approaches (2024-2026)

### 5.1 Profile-less Analysis
- **mquire**: BTF + kallsyms embedded in kernel, no external symbols
- **btf2json**: 12x faster profile generation from BTF data
- **Volatility 3**: Symbol-based analysis (improvement but still needs symbol tables)
- **Trend**: Moving away from external profile dependencies

### 5.2 Machine Learning Integration

| Approach | Accuracy | Method |
|----------|----------|--------|
| CNN on memory features | 97.8% | Memory pages, threads, files, syscalls via Volatility/Rekall |
| Ensemble soft voting (fileless) | 99.9% binary, 88.86% multiclass | Memory forensics + ML |
| CNN on memory dumps | 97.48% | Convolutional analysis of raw dumps |
| Texture-based image analysis | Varies | Memory visualized as images, LIME-guided DL |

### 5.3 Key Research Papers
- ACM Computing Surveys 2025: "Memory Analysis for Malware Detection" — OSCAR methodology survey
- MDPI Electronics July 2024: "Comprehensive Literature Review on Volatile Memory Forensics"
- DFRWS 2025: 3D printing forensics via memory analysis of slicing software
- July 2024: Steam Deck memory forensics (stripped symbols on novel devices)
- ICCWS Feb 2026: Cross-platform forensic acquisition challenges

### 5.4 Novel Application Domains
- 3D printer forensics (Ultimaker Cura slicing software analysis)
- Gaming console forensics (Steam Deck)
- IoT device memory analysis
- Automotive infotainment systems
- eBPF program forensics (new attack surface)

### 5.5 Key Trends
1. **File-system paradigm** (MemProcFS) complementing/replacing CLI plugins
2. **Zero-dependency analysis** (mquire) eliminating profile management
3. **Deep learning automation** reducing manual analysis burden
4. **Fileless malware** as primary research driver
5. **Multi-source data fusion** (memory + network + disk)
6. **Rust adoption** for performance and memory safety (AVML, mquire, yara-x, btf2json)
7. **SQL-based interfaces** making forensics more accessible (mquire/osquery pattern)

**References:**
- [ACM Survey: Memory Analysis for Malware Detection](https://dl.acm.org/doi/10.1145/3764580)
- [MDPI: Volatile Memory Forensics Literature Review](https://www.mdpi.com/2079-9292/13/15/3026)
- [DFRWS 2025: 3D Printing Memory Forensics](https://dfrws.org/wp-content/uploads/2025/05/Leveraging-memory-forensics-to-investigate-and-detect-illegal-3D-printing-activities.pdf)
- [mquire Blog Post](https://blog.trailofbits.com/2026/02/25/mquire-linux-memory-forensics-without-external-dependencies/)
- [btf2json Blog](https://lolcads.github.io/posts/2024/11/btf2json/)

---

## 6. Framework Comparison Summary

| Framework | Language | Status | Linux Support | Profile-Free | File Recovery | Plugin System | Rust API |
|-----------|----------|--------|---------------|-------------|---------------|---------------|----------|
| Volatility 3 | Python 3 | Active | 40+ plugins | No (needs symbols) | Via pagecache | Extensive | No |
| Rekall | Python 2/3 | Discontinued | Yes | Partial (kallsyms) | Limited | Yes | No |
| MemProcFS | C/C++ | Active | Limited | N/A | Via VFS | Yes (C, Rust, Python) | Yes (FFI wrapper) |
| mquire | Rust | PoC (2026) | Primary focus | Yes (BTF+kallsyms) | Yes (page cache) | No (SQL queries) | Yes (native) |
| Project Freta | Rust | Active (cloud) | Primary focus | Yes (4000+ kernels) | In-memory files | API-based | Client crate |
