# memory-forensic: Pure-Rust Memory Forensics Framework

## Overview

A standalone Rust workspace at `~/src/memory-forensic` providing a pure-Rust memory forensics framework. Inspired by Volatility 3, mquire, and MemProcFS but written from scratch with zero C dependencies. Supports 13+ dump formats (LiME, AVML, ELF core, kdump, Windows DMP, hiberfil.sys, VMware, VirtualBox, etc.), OS kernel structure walking (processes, sockets, modules) for Linux/macOS/Windows, string-based IoC classification with YARA-X, and detection engines for rootkits, crypto keys, and credential recovery.

## Goals

- **Format-agnostic physical memory access** -- a `PhysicalMemoryProvider` trait with confidence-based probing so dump formats are detected by magic bytes, never file extension
- **Multi-OS kernel walking** -- extract processes, network connections, loaded modules, and mount points from Linux, macOS, and Windows memory dumps via pluggable `WalkerPlugin` implementations
- **Symbol resolution without external tools** -- BTF (Linux 5.2+), Mach-O DWARF (macOS), and ISF JSON (Volatility 3-compatible, all OS) backends for resolving kernel struct offsets at runtime
- **String-based IoC classification** -- YARA-X rule matching plus regex-based classifiers for URLs, IPs, file paths, credentials, and crypto material in extracted strings
- **Detection engines** -- cross-view rootkit detection, crypto key recovery (FDE, blockchain, SSH, browser), and credential extraction (DPAPI, LSASS, Kerberos, OAuth, session tokens)
- **Strict TDD** -- every feature developed red-green-refactor with synthetic test fixtures

## Non-Goals

- Live memory acquisition (use AVML, LiME, WinPmem for capture -- this tool reads dumps only)
- TUI or GUI (CLI only; Issen rt-navigator may integrate later)
- Network-based analysis (no packet capture parsing)
- Disk image mounting or filesystem analysis (that's Issen's domain)
- Android/iOS mobile memory analysis (future work)

---

## 1. Workspace Structure & Crate Responsibilities

```
~/src/memory-forensic/
├── Cargo.toml                  # workspace root
├── LICENSE                     # Apache-2.0
├── crates/
│   ├── memf-format/            # physical memory providers (dump format parsers)
│   ├── memf-symbols/           # symbol resolution backends (BTF, Mach-O, ISF)
│   ├── memf-core/              # virtual address translation, ObjectReader, page table walking
│   ├── memf-linux/             # Linux kernel structure walkers
│   ├── memf-mac/               # macOS XNU kernel structure walkers
│   ├── memf-windows/           # Windows kernel structure walkers
│   ├── memf-strings/           # string extraction + IoC classification + YARA-X
│   └── memf-detect/            # detection engines (rootkits, crypto keys, credentials)
└── src/
    └── main.rs                 # memf CLI binary
```

### Crate Dependency DAG

```
memf (CLI)
├── memf-detect
│   ├── memf-linux
│   │   ├── memf-core
│   │   │   ├── memf-format
│   │   │   └── memf-symbols
│   │   └── memf-core
│   ├── memf-mac
│   │   └── memf-core
│   ├── memf-windows
│   │   └── memf-core
│   └── memf-strings
│       └── memf-format
└── memf-strings
```

### Shared Conventions (all crates)

- `edition = "2021"`, MSRV 1.75+
- `#![deny(unsafe_code)]` -- no unsafe Rust
- `thiserror = "2"` for library errors, `anyhow = "1"` for CLI only
- `inventory = "0.3"` for compile-time plugin registration
- `memmap2 = "0.9"` for memory-mapped file I/O
- Clippy pedantic + `#![warn(missing_docs)]`

---

## 2. Physical Memory Provider Layer (`memf-format`)

### Core Trait

```rust
/// A provider of physical memory from a dump file.
pub trait PhysicalMemoryProvider: Send + Sync {
    /// Read `buf.len()` bytes from physical address `addr`.
    /// Returns number of bytes actually read (may be less if crossing a gap).
    fn read_phys(&self, addr: u64, buf: &mut [u8]) -> Result<usize>;

    /// Return all valid physical address ranges in the dump.
    fn ranges(&self) -> &[PhysicalRange];

    /// Total physical memory size (sum of all ranges).
    fn total_size(&self) -> u64;

    /// Human-readable format name (e.g., "LiME", "AVML v2").
    fn format_name(&self) -> &str;
}

pub struct PhysicalRange {
    pub start: u64,
    pub end: u64,   // exclusive
}
```

### Plugin Registration

```rust
pub trait FormatPlugin: Send + Sync {
    /// Human-readable name for this format.
    fn name(&self) -> &str;

    /// Probe the first `header` bytes of a file. Return confidence 0-100.
    fn probe(&self, header: &[u8]) -> u8;

    /// Open the file and return a PhysicalMemoryProvider.
    fn open(&self, path: &Path) -> Result<Box<dyn PhysicalMemoryProvider>>;
}

// Registration via inventory crate
inventory::collect!(Box<dyn FormatPlugin>);
```

### Supported Formats (3 tiers)

**Tier 1 -- Phase 1 (high priority, test data available):**

| Format | Magic / Signature | Notes |
|--------|------------------|-------|
| LiME | `0x4C694D45` (LE) at offset 0 | Linux memory, version field at +4, address range records |
| AVML v2 | `0x4C4D5641` + Snappy-compressed blocks | Azure AVML, each block: header + snappy payload |
| Raw/padded | No magic (fallback, confidence 5) | Contiguous physical dump, size must be power-of-2 aligned |

**Tier 2 -- Phase 2 (common formats):**

| Format | Magic / Signature | Notes |
|--------|------------------|-------|
| ELF core | `0x7F454C46` + `PT_LOAD` segments | Linux kdump, QEMU, libvirt; parse program headers for ranges |
| Windows DMP 32 | `"PAGEDUMP"` at offset 0 | 32-bit crash dump; `DUMP_HEADER` struct |
| Windows DMP 64 | `"PAGEDU64"` at offset 0 | 64-bit crash dump; `DUMP_HEADER64` struct |
| VMware `.vmem` | Paired with `.vmss`/`.vmsn` for metadata | Raw memory + snapshot metadata |

**Tier 3 -- Phase 3 (extended support):**

| Format | Magic / Signature | Notes |
|--------|------------------|-------|
| kdump (makedumpfile) | `0x8757D0E0` (LE) or `0xE0D05787` (BE) | Flattened or ELF-based, optional LZO/zstd/snappy compression |
| hiberfil.sys | `"HIBR"` / `"RSTR"` / `"WAKE"` at offset 0 | Windows hibernation; Xpress Huffman decompression |
| VirtualBox `.sav` | VBox core dump in ELF wrapper | Parse VBox-specific ELF notes |
| Hyper-V `.vsv` | Hyper-V saved state | Binary paging file format |
| HPAK | `0x4850414B` ("HPAK") | Comae (now Magnet) format, zlib compressed |
| Mach-O core | `0xFEEDFACF` + `LC_SEGMENT_64` | macOS kernel core dumps |

### Probing Strategy

```
read first 4096 bytes
for each FormatPlugin (sorted by Tier):
    score = plugin.probe(header)
    if score >= 80: return plugin.open(path)   # high confidence
collect all scores >= 20
if exactly one >= 50: return that plugin
if multiple >= 50: return error (ambiguous)
if none >= 20: return error (unknown format)
```

---

## 3. String Analysis Layer (`memf-strings`)

### Architecture

```
PhysicalMemoryProvider
    -> StringExtractor (configurable min_len, encoding)
        -> ClassifierPipeline
            -> RegexClassifier (URLs, IPs, emails, paths, credentials)
            -> YaraClassifier (YARA-X rule matching)
            -> Custom StringClassifier plugins
        -> ClassifiedString { value, offset, categories, confidence }
```

### Core Types

```rust
pub struct ClassifiedString {
    pub value: String,
    pub physical_offset: u64,
    pub encoding: StringEncoding,
    pub categories: Vec<StringCategory>,
    pub confidence: f32,  // 0.0 - 1.0
}

pub enum StringEncoding {
    Ascii,
    Utf8,
    Utf16Le,
    Utf16Be,
}

pub enum StringCategory {
    Url(UrlType),           // http/https/ftp/file/data URIs
    IpAddress(IpVersion),   // IPv4, IPv6
    Email,
    FilePath(OsType),       // Windows backslash, Unix forward-slash
    DomainName,
    RegistryKey,            // Windows registry paths
    Credential(CredentialType),
    CryptoMaterial(CryptoType),
    Command(CommandType),   // shell commands, PowerShell
    Ioc(IocType),           // known malware indicators
    Uncategorized,
}

pub enum UrlType { Http, Https, Ftp, File, Data }
pub enum IpVersion { V4, V6 }
pub enum OsType { Windows, Linux, MacOs }
pub enum CredentialType { Password, Hash, Token, Cookie, ApiKey }
pub enum CryptoType { PrivateKey, SeedPhrase, Wallet, Certificate, EncryptionKey }
pub enum CommandType { Shell, PowerShell, Cmd, Python }
pub enum IocType { C2Domain, MalwareSignature, SuspiciousPath }

pub trait StringClassifier: Send + Sync {
    fn name(&self) -> &str;
    fn classify(&self, input: &str) -> Vec<(StringCategory, f32)>;
}

inventory::collect!(Box<dyn StringClassifier>);
```

### String Extraction

- Scan physical memory ranges sequentially
- Extract ASCII (printable 0x20-0x7E), UTF-8, and UTF-16LE strings
- Configurable minimum length (default: 4 characters)
- Deduplication by value (keep first occurrence offset)
- Streaming output to avoid holding all strings in memory

### YARA-X Integration

```rust
pub struct YaraClassifier {
    scanner: yara_x::Scanner,
}
```

- Load YARA rules from a configurable rules directory
- Ship default rules for common IoCs (C2 URLs, malware strings, tool signatures)
- Users can add custom `.yar` files
- YARA-X version: `0.12` (pure Rust, stable since June 2025)

### Pre-existing String File Support

For Issen UAC collections that already contain `memory-strings.ascii`:

```rust
pub fn from_strings_file(path: &Path) -> Result<impl Iterator<Item = ClassifiedString>>
```

- Parse one-string-per-line format (as produced by `strings` command)
- Skip classification pipeline's extraction step, feed directly to classifiers
- Supports both raw strings files and offset-prefixed format (`offset: string`)

---

## 4. Symbol Resolution Layer (`memf-symbols`)

### Three-Backend Architecture

```rust
pub trait SymbolResolver: Send + Sync {
    /// Resolve a struct field offset: e.g., ("task_struct", "comm") -> Some(2776)
    fn field_offset(&self, struct_name: &str, field_name: &str) -> Option<u64>;

    /// Resolve a struct's total size: e.g., "task_struct" -> Some(9792)
    fn struct_size(&self, struct_name: &str) -> Option<u64>;

    /// Resolve a kernel symbol address: e.g., "init_task" -> Some(0xffffffff82a13780)
    fn symbol_address(&self, symbol_name: &str) -> Option<u64>;

    /// Human-readable backend name.
    fn backend_name(&self) -> &str;
}
```

### Backend 1: BTF (Linux 5.2+)

- Parse `.BTF` section from vmlinux or extract from the dump itself (some distros embed BTF in the kernel image mapped in memory)
- BTF type format: header (magic `0xEB9F`) + type section + string section
- Resolves struct layouts, field offsets, and sizes without external files
- Cannot resolve symbol addresses (pair with kallsyms for that)

**kallsyms integration:** Parse `/proc/kallsyms` equivalent from memory (the `kallsyms_names`, `kallsyms_token_table`, `kallsyms_token_index` arrays in kernel `.rodata`) to resolve symbol virtual addresses. Combined with BTF for full resolution.

### Backend 2: Mach-O Symbols (macOS)

- Parse the kernel's Mach-O headers from memory (the XNU kernel is a Mach-O executable loaded at a known VA range)
- Extract DWARF debug info from `__DWARF` segment (if present) for struct layouts
- Extract symbol table (`LC_SYMTAB` load command) for symbol addresses
- macOS kernels often have DWARF info available in kernel debug kits (KDKs)
- Resolution chain: in-memory Mach-O symbols -> user-supplied KDK DWARF -> ISF fallback

### Backend 3: ISF JSON (All platforms, fallback)

- Volatility 3-compatible Intermediate Symbol Format
- JSON files containing: `base_types`, `user_types` (structs), `enums`, `symbols`
- User provides ISF files for their target kernel version
- Lookup path: `$MEMF_SYMBOLS_PATH` env var, `~/.memf/symbols/`, or `--symbols` CLI flag
- Can download from Volatility's symbol server (optional, requires network)

### Resolution Chain

```
Linux:   BTF (from dump) + kallsyms (from dump) -> ISF JSON (user-supplied)
macOS:   Mach-O (from dump) + DWARF (from KDK) -> ISF JSON (user-supplied)
Windows: ISF JSON (required, from PDB conversion)
```

Each OS walker requests symbols through the `SymbolResolver` trait. The implementation tries backends in priority order and returns the first successful resolution.

### KASLR Shift Detection

All modern kernels randomize their load address. Before symbol resolution works, we must find the actual kernel base:

**Linux:** Scan physical memory for `"Linux version "` banner string. The banner's physical address, combined with the known virtual address of `linux_banner` from symbols, yields the KASLR offset.

**macOS:** Scan for the Mach-O `MH_MAGIC_64` (`0xFEEDFACF`) header in the expected kernel VA range (`0xFFFFFF8000000000`+). The `__TEXT` segment's `vmaddr` vs its physical location gives the slide.

**Windows:** Scan for `"MZ"` + `"PE\0\0"` at aligned addresses in physical memory. Match against `ntoskrnl.exe` PE header characteristics. Compare to expected base from ISF.

---

## 5. Core Memory Model (`memf-core`)

### Virtual Address Space

```rust
/// Translates virtual addresses to physical addresses via page table walking.
pub struct VirtualAddressSpace {
    physical: Box<dyn PhysicalMemoryProvider>,
    page_table_root: u64,  // CR3 / TTBR0 / PML4 base
    mode: TranslationMode,
}

pub enum TranslationMode {
    X86_64FourLevel,     // PML4 -> PDPT -> PD -> PT (standard)
    X86_64FiveLevel,     // PML5 (LA57, rare)
    Aarch64,             // ARM 4-level (macOS Apple Silicon)
    X86Pae,              // 32-bit PAE (legacy Windows)
    X86NonPae,           // 32-bit non-PAE (very legacy)
}

impl VirtualAddressSpace {
    /// Read bytes from a virtual address (translates page-by-page).
    pub fn read_virt(&self, vaddr: u64, buf: &mut [u8]) -> Result<usize>;

    /// Translate a single virtual address to physical.
    pub fn virt_to_phys(&self, vaddr: u64) -> Result<u64>;
}
```

### Page Table Walking (x86_64)

```
Virtual Address (48-bit):
[PML4 index : 9 bits] [PDPT index : 9 bits] [PD index : 9 bits] [PT index : 9 bits] [Offset : 12 bits]

Walk:
1. PML4E = read_phys(cr3 + pml4_idx * 8)
2. PDPTE = read_phys((PML4E & ADDR_MASK) + pdpt_idx * 8)
   - If PS bit set: 1GB huge page -> return physical + offset
3. PDE = read_phys((PDPTE & ADDR_MASK) + pd_idx * 8)
   - If PS bit set: 2MB large page -> return physical + offset
4. PTE = read_phys((PDE & ADDR_MASK) + pt_idx * 8)
5. Physical = (PTE & ADDR_MASK) + page_offset

ADDR_MASK = 0x000F_FFFF_FFFF_F000  (bits 51:12)
Present bit = bit 0; must be set or page is not mapped.
```

### ObjectReader

```rust
/// High-level typed reader combining virtual memory + symbol resolution.
pub struct ObjectReader {
    vas: VirtualAddressSpace,
    symbols: Box<dyn SymbolResolver>,
}

impl ObjectReader {
    /// Read a field from a kernel struct at a virtual address.
    pub fn read_field<T: Pod>(&self, base_vaddr: u64, struct_name: &str, field_name: &str) -> Result<T>;

    /// Read a null-terminated string from a virtual address.
    pub fn read_string(&self, vaddr: u64, max_len: usize) -> Result<String>;

    /// Walk a Linux `list_head` doubly-linked list, yielding container struct addresses.
    pub fn walk_list(&self, head_vaddr: u64, struct_name: &str, list_field: &str) -> Result<Vec<u64>>;
}
```

The `Pod` trait bound (from `bytemuck`) ensures only plain-old-data types can be read, maintaining `#![deny(unsafe_code)]` by using `bytemuck::from_bytes` for safe transmutation.

---

## 6. OS Walker Plugins

### Plugin Trait

```rust
pub trait WalkerPlugin: Send + Sync {
    fn name(&self) -> &str;

    /// Probe whether this walker can handle the given memory dump.
    /// Returns confidence 0-100 (check for OS-specific kernel signatures).
    fn probe(&self, reader: &ObjectReader) -> u8;

    /// List processes.
    fn processes(&self, reader: &ObjectReader) -> Result<Vec<ProcessInfo>>;

    /// List network connections.
    fn connections(&self, reader: &ObjectReader) -> Result<Vec<ConnectionInfo>>;

    /// List loaded kernel modules.
    fn modules(&self, reader: &ObjectReader) -> Result<Vec<ModuleInfo>>;
}

inventory::collect!(Box<dyn WalkerPlugin>);
```

### Common Output Types

```rust
pub enum ProcessState { Running, Sleeping, Stopped, Zombie, Dead, Unknown }
pub enum Protocol { Tcp, Udp, Tcp6, Udp6, Unix, Raw }
pub enum ConnectionState { Established, Listen, TimeWait, CloseWait, SynSent, SynRecv, FinWait1, FinWait2, Closing, LastAck, Close, Unknown }
pub enum ModuleState { Live, Loading, Unloading, Unknown }

pub struct ProcessInfo {
    pub pid: u64,
    pub ppid: u64,
    pub name: String,
    pub comm: String,          // short name (Linux: 16 chars)
    pub cmdline: Option<String>,
    pub uid: Option<u64>,
    pub gid: Option<u64>,
    pub state: ProcessState,
    pub start_time: Option<u64>,  // kernel ticks or ns since boot
    pub vaddr: u64,               // virtual address of task struct
    pub cr3: Option<u64>,         // page table root for this process
}

pub struct ConnectionInfo {
    pub protocol: Protocol,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: ConnectionState,
    pub pid: Option<u64>,
    pub inode: Option<u64>,
}

pub struct ModuleInfo {
    pub name: String,
    pub base_addr: u64,
    pub size: u64,
    pub path: Option<String>,
    pub state: ModuleState,
    pub taint_flags: u32,
}
```

### `memf-linux` -- Linux Kernel Walkers

**Process enumeration:**
- Walk `init_task.tasks` list (`task_struct` linked list via `list_head`)
- For each `task_struct`: read `pid`, `comm`, `mm->pgd` (CR3), `real_parent->pid` (PPID)
- Thread group: walk `thread_group` list for threads
- Cmdline: read `mm->arg_start` to `mm->arg_end` from process address space

**Network connections:**
- Walk `tcp_hashinfo.listening_hash` and `tcp_hashinfo.ehash` for TCP sockets
- Walk `udp_table.hash` / `udp_table.hash2` for UDP sockets
- For each `inet_sock`: extract `sk_common.skc_daddr`, `skc_rcv_saddr`, ports, state
- Map socket to process via `sock->sk_socket->file` -> scan process fd tables

**Kernel modules:**
- Walk `modules` list (`struct module` linked via `list`)
- For each module: read `name`, `core_layout.base`, `core_layout.size`
- Taint flags from `taints` field

**Kernel version handling:**
- VMA iteration: `mm->mmap` linked list (pre-6.1) vs `mm->mm_mt` maple tree (6.1+)
- Detection: check for `maple_tree` struct in BTF/symbols; if present, use maple tree walker

### `memf-mac` -- macOS XNU Kernel Walkers

**Process enumeration:**
- Walk `allproc` list (`proc` structures linked via `p_list`)
- For each `proc`: read `p_pid`, `p_comm`, `p_ppid`, `task->map->pmap->cr3`
- Mach tasks: `proc->task` for thread/port information

**Network connections:**
- Walk `tcbinfo.ipi_listhead` (TCP) and `udbinfo.ipi_listhead` (UDP) inpcb lists
- Extract `inp_laddr`, `inp_faddr`, `inp_lport`, `inp_fport`

**Kernel extensions:**
- Walk `kmod_info` linked list for loaded kexts
- Extract name, version, base address, size
- Note: kexts deprecated since macOS 11; newer systems use System Extensions (dext) -- these don't appear in kernel memory

**Zone allocator:**
- Parse XNU zone allocator metadata for heap forensics
- Useful for finding freed-but-not-zeroed allocations

### `memf-windows` -- Windows Kernel Walkers

**Process enumeration:**
- Walk `PsActiveProcessHead` doubly-linked list of `_EPROCESS` structures
- For each `_EPROCESS`: read `UniqueProcessId`, `ImageFileName`, `InheritedFromUniqueProcessId`, `ActiveThreads`, `Pcb.DirectoryTableBase` (CR3)
- PEB traversal for command line and loaded DLLs

**Network connections:**
- Scan pool allocations for `_TCP_ENDPOINT`, `_UDP_ENDPOINT` tagged blocks
- Pool tag scanning: `TcpE`, `UdpA` tags
- Extract local/remote addresses and ports from connection objects

**Kernel modules:**
- Walk `PsLoadedModuleList` (`_LDR_DATA_TABLE_ENTRY` list)
- Each entry: `BaseDllName`, `DllBase`, `SizeOfImage`, `FullDllName`

**Registry hives (bonus):**
- Walk `CmpHiveListHead` for in-memory registry hives
- Extract hive paths and base addresses for offline analysis

---

## 7. Detection Engines (`memf-detect`)

### Engine Trait

```rust
pub trait DetectionEngine: Send + Sync {
    fn name(&self) -> &str;

    /// Run detection on the given memory dump, returning findings.
    fn detect(&self, ctx: &DetectionContext) -> Result<Vec<Finding>>;
}

pub struct DetectionContext {
    pub reader: ObjectReader,
    pub processes: Vec<ProcessInfo>,
    pub modules: Vec<ModuleInfo>,
    pub connections: Vec<ConnectionInfo>,
    pub strings: Vec<ClassifiedString>,
}

pub struct Finding {
    pub engine: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub evidence: Vec<Evidence>,
}

pub enum Severity {
    Critical,   // confirmed compromise indicator
    High,       // strong suspicion
    Medium,     // anomaly worth investigating
    Low,        // informational
}

pub enum Evidence {
    Process(ProcessInfo),
    Module(ModuleInfo),
    Connection(ConnectionInfo),
    MemoryRegion { offset: u64, size: u64, data: Vec<u8> },
    String(ClassifiedString),
}

inventory::collect!(Box<dyn DetectionEngine>);
```

### Engine 1: Cross-View Rootkit Detection (Linux)

Detects hidden processes and modules by comparing multiple kernel data structures that should agree:

**Process cross-view (4 sources):**
1. `init_task.tasks` linked list (standard enumeration)
2. PID hash table (`pid_hash` or `idr` depending on kernel version)
3. `/proc` directory entries (reconstruct from `proc_dir_entry` tree)
4. Brute-force: scan all physical memory for `task_struct` signatures (magic fields: `stack_canary` alignment, valid `mm` pointer, valid `pid` range)

**Module cross-view (4 sources):**
1. `modules` linked list (standard enumeration)
2. `module_kset` kobject set (sysfs view)
3. Memory section tree (`mod_tree` in modern kernels)
4. `kallsyms` entries referencing module text ranges

A process or module appearing in some views but not others is flagged as potentially hidden.

**Syscall table integrity:**
- Read `sys_call_table` entries
- Verify each entry points into kernel text or a known module
- Entries pointing to unknown memory regions indicate hooking
- Note: Linux 6.9+ removed syscall table patching as an attack vector; check kernel version

**eBPF program detection:**
- Walk `bpf_prog_array` and `bpf_map` structures
- Flag unexpected BPF programs attached to tracepoints, kprobes, or XDP hooks
- Modern rootkits increasingly use eBPF instead of kernel module loading

### Engine 2: Crypto Key Recovery

Recovers encryption keys, wallet credentials, and key material from memory using pattern matching and structural analysis.

#### 2a. Full Disk Encryption Keys

**BitLocker (Windows):**
- Scan for FVEK pool tags and key structures in kernel memory
- FVEK is always 512 bits (64 bytes) total: encryption key + tweak key
- Encryption mode identifiers: `0x0480` (XTS-AES-128), `0x8001` (AES-256+Diffuser)
- VMK: 256-bit, header identified by `0x2C 0x00 0x00 0x00`
- Recovery key format: 8 groups of 6 digits, each divisible by 11
- Pool tag scanning varies by Windows version

**FileVault 2 (macOS):**
- Volume Encryption Key (VEK) in IOKit registry `AppleKeyStore` service
- VEK typically at offset +0x430 from service object base
- Alternatively scan for AES key schedules in `kernel_task` memory
- Key wrapped with user password-derived KEK via PBKDF2

**LUKS (Linux):**
- Scan for `crypt_config` struct instances (dm-crypt)
- The `key` field contains the unwrapped master key
- `crypt_config` identifiable by `cipher_string` field containing algo name (e.g., `"aes-xts-plain64"`)
- Key length at known offset from struct base

**VeraCrypt/TrueCrypt:**
- Volume header: 512 bytes, starts at offset 0 (standard) or 65536 (hidden)
- In memory: scan for decrypted header structure with `"TRUE"` magic (TrueCrypt) or `"VERA"` (VeraCrypt)
- Master key immediately follows header in memory when volume is mounted

#### 2b. AES Key Schedule Detection

Generic detection for any AES key material in memory:
- AES key expansion produces round keys with mathematical relationships between consecutive rounds
- Scan for 176-byte (AES-128), 208-byte (AES-192), or 240-byte (AES-256) blocks where each 16-byte segment satisfies the AES key schedule recurrence relation
- Validate by checking inter-round-key relationships (XOR + S-box + Rcon)
- High confidence when combined with nearby context (crypto library structures)

#### 2c. SSH Keys

- **OpenSSH private keys:** Scan for `"openssh-key-v1\0"` magic (AUTH_MAGIC)
- **Shielded private keys (OpenSSH 8.0+):** Key material XORed with prekey derived from `ssh-keygen -Y find-principals`; look for prekey in `ssh-agent` process memory
- **PEM format:** `"-----BEGIN RSA PRIVATE KEY-----"`, `"-----BEGIN EC PRIVATE KEY-----"`, `"-----BEGIN OPENSSH PRIVATE KEY-----"`
- **PuTTY `.ppk`:** `"PuTTY-User-Key-File-"` header

#### 2d. Blockchain Keys and Seed Phrases

**Bitcoin private keys:**
- WIF format: Base58Check, starts with `5` (uncompressed) or `K`/`L` (compressed), 51-52 chars
- Raw 32-byte secp256k1 private keys: validate by checking if value < group order `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`
- Mini private keys: 22-30 chars starting with `S`, validate via SHA-256 checksum

**BIP-39 mnemonic seed phrases:**
- 12/15/18/21/24 words from standardized 2048-word wordlists (10 languages)
- Each word has a unique 4-character prefix -- scan for sequences of 12+ known prefixes separated by spaces
- English wordlist most common; also scan Japanese (UTF-8 Hiragana), Korean (UTF-8 Hangul), Chinese
- Regex approach: build prefix automaton from all 10 wordlists

**BIP-32 extended keys (HD wallets):**
- Base58Check encoded, 111 chars: `xprv...` (mainnet private), `xpub...` (mainnet public)
- Also `yprv`/`ypub` (P2WPKH-nested), `zprv`/`zpub` (native SegWit)
- 78-byte serialization: 4 version + 1 depth + 4 fingerprint + 4 index + 32 chain code + 33 key

**Ethereum:**
- Raw 32-byte private keys (often hex-encoded with `0x` prefix, 66 chars total)
- Keystore JSON v3: `{"crypto":{"cipher":"aes-128-ctr"...}}` structure in browser/node process memory
- MetaMask vault: encrypted JSON blob, scan for `"data":"` + `"iv":"` + `"salt":"` pattern

**Other chains:**
- Monero: 64-char hex spend key + view key
- Solana: Base58-encoded 64-byte keypair
- Substrate/Polkadot: Sr25519 keypairs

#### 2e. OAuth Tokens, API Keys, and Session Credentials

**JWT detection:**
- Universal prefix: `eyJ` (Base64URL of `{"`) -- scan for `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`
- Decode payload for `exp`, `iss`, `sub` fields to classify token type
- Azure AD tokens: `eyJ0eX` prefix (from `{"typ"`)

**API key patterns (50+ providers):**

| Provider | Pattern | Regex |
|----------|---------|-------|
| AWS Access Key | `AKIA...` (20 chars) | `AKIA[0-9A-Z]{16}` |
| AWS Session | `ASIA...` (20 chars) | `ASIA[0-9A-Z]{16}` |
| GitHub PAT | `ghp_...` (40 chars) | `ghp_[0-9a-zA-Z]{36}` |
| GitHub OAuth | `gho_...` | `gho_[0-9a-zA-Z]{36}` |
| Slack Bot | `xoxb-...` | `xoxb-[0-9]{10,13}-[0-9a-zA-Z-]+` |
| Slack User | `xoxp-...` | `xoxp-[0-9]{10,13}-[0-9a-zA-Z-]+` |
| Stripe Live | `sk_live_...` | `sk_live_[0-9a-zA-Z]{24,}` |
| Google API | `AIza...` | `AIza[0-9A-Za-z_-]{35}` |
| Google OAuth | `ya29.` | `ya29\.[A-Za-z0-9_-]{50,}` |
| SendGrid | `SG.` | `SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}` |
| Twilio | `SK` (34 chars) | `SK[0-9a-fA-F]{32}` |

**Kerberos tickets:**
- TGT/TGS: ASN.1 DER-encoded, scan for Kerberos application tags
- Windows: in LSASS process memory, near `kerberos.dll` allocations
- Linux: ccache files, KEYRING entries, or KCM socket data
- kirbi format detection for offline ticket extraction

**Session cookies:**
- Framework-specific patterns: `PHPSESSID=`, `ASP.NET_SessionId=`, `JSESSIONID=`, `connect.sid=`
- Browser cookie stores: Chrome (DPAPI/App-Bound Encryption), Firefox (NSS), Safari (Keychain)

**Password manager vaults:**
- 1Password: encrypted vault, memory-resident master key
- LastPass: `"lastpass rocks"` sentinel string near vault blob
- KeePass: KDBX header `0x03D9A29A67FB4BB5`, CVE-2023-32784 master password recovery from .NET strings
- Bitwarden: CVE-2023-38840 plaintext master password in process memory

**TOTP/HOTP secrets:**
- Base32-encoded shared secrets (16-32 uppercase chars A-Z, 2-7)
- `otpauth://totp/` and `otpauth://hotp/` URI patterns
- Google Authenticator migration format (protobuf)

**Certificate private keys:**
- PEM markers: `-----BEGIN RSA PRIVATE KEY-----`, `-----BEGIN EC PRIVATE KEY-----`, `-----BEGIN PRIVATE KEY-----` (PKCS#8)
- DER binary: ASN.1 SEQUENCE tag `0x30` followed by OID for RSA (`2a 86 48 86 f7 0d 01 01 01`) or EC (`2a 86 48 ce 3d 02 01`)
- PKCS#12 containers: `0x30 0x82` followed by content type OID

### Engine 3: DKOM / Data Structure Manipulation (Windows)

- Detect DKOM (Direct Kernel Object Manipulation) by walking `_EPROCESS` list and comparing with pool tag scans
- Check `ObjectTable` handles for consistency
- Validate `_OBJECT_HEADER` type index for each kernel object
- Detect process hollowing: `_EPROCESS.ImageFileName` vs actual PEB `ImagePathName`

---

## 8. CLI (`memf`)

### Command Structure

```
memf <COMMAND> [OPTIONS] <dump_file>

Commands:
  info        Show dump format, OS detection, and basic metadata
  strings     Extract and classify strings from memory dump
  ps          List processes
  netstat     List network connections
  modules     List loaded kernel modules
  detect      Run detection engines (rootkit, crypto, credentials)
  symbols     Manage symbol resolution (list backends, download ISF)
  yara        Run YARA-X rules against memory

Global Options:
  --format <fmt>       Force dump format (skip probing)
  --symbols <path>     Path to ISF JSON or BTF file
  --output <fmt>       Output format: table (default), json, csv
  -v, --verbose        Increase verbosity
  -q, --quiet          Suppress non-essential output
```

### Example Usage

```bash
# Basic info about a dump
memf info memory.lime

# Extract and classify strings
memf strings memory.lime --min-length 8 --encoding utf8,utf16le

# Classify pre-extracted strings file (from UAC collection)
memf strings --from-file memory-strings.ascii

# List processes
memf ps memory.lime --output json

# Run all detection engines
memf detect memory.lime --engines all

# Run only crypto key recovery
memf detect memory.lime --engines crypto

# Run YARA rules
memf yara memory.lime --rules ./my-rules/
```

### Output Formats

- **Table** (default): Human-readable aligned columns via `comfy-table` crate
- **JSON**: Machine-parseable, one JSON object per line (JSONL) or pretty-printed
- **CSV**: For spreadsheet import

### Dependencies

```toml
[dependencies]
clap = { version = "4", features = ["derive"] }
anyhow = "1"
comfy-table = "7"
serde_json = "1"
```

---

## 9. Testing Strategy

### Synthetic Test Fixtures

All unit tests use builder-pattern synthetic fixtures -- no real memory dumps in the test suite (they're too large for git):

```rust
/// Builder for creating test LiME dumps in memory.
pub struct LimeBuilder {
    ranges: Vec<(u64, Vec<u8>)>,
    version: u32,
}

impl LimeBuilder {
    pub fn new() -> Self { ... }
    pub fn add_range(mut self, start: u64, data: &[u8]) -> Self { ... }
    pub fn build(self) -> Vec<u8> { ... }
}

#[test]
fn test_lime_two_ranges() {
    let dump = LimeBuilder::new()
        .add_range(0x0000_0000, &[0xAA; 4096])
        .add_range(0x0010_0000, &[0xBB; 4096])
        .build();
    let provider = LimeProvider::from_bytes(&dump).unwrap();
    assert_eq!(provider.ranges().len(), 2);

    let mut buf = [0u8; 4];
    provider.read_phys(0x0000_0000, &mut buf).unwrap();
    assert_eq!(buf, [0xAA; 4]);
}
```

Similar builders for:
- `AvmlBuilder` -- AVML v2 dumps with Snappy compression
- `ElfCoreBuilder` -- ELF core dumps with `PT_LOAD` segments
- `DmpBuilder` -- Windows DMP headers + physical memory pages
- `PageTableBuilder` -- synthetic 4-level page tables for address translation tests
- `TaskStructBuilder` -- synthetic `task_struct` chains for process walking tests

### Integration Tests with Real Data

Tests requiring real dumps use `#[ignore]` and a `MEMF_TEST_DATA` env var:

```rust
#[test]
#[ignore = "requires real dump: set MEMF_TEST_DATA=/path/to/dumps"]
fn test_avml_real_dump() {
    let path = std::env::var("MEMF_TEST_DATA").unwrap();
    let dump_path = PathBuf::from(path).join("avml.lime");
    if !dump_path.exists() { return; }
    let provider = open_dump(&dump_path).unwrap();
    assert!(provider.total_size() > 1_000_000_000); // > 1GB
}
```

Real test data source: `~/src/Issen/tests/data/uac-vbox-linux-20260324234043.tar.gz` contains an 8GB `avml.lime` dump + 2.2GB `memory-strings.ascii`.

### Test Coverage Targets

| Crate | Unit Tests | Integration |
|-------|-----------|-------------|
| memf-format | Each format: probe, open, read, boundary conditions, corrupt headers | Real dumps per format |
| memf-symbols | BTF parsing, ISF loading, field resolution, missing fields | Real kernel BTF sections |
| memf-core | Page table walk (all modes), ObjectReader, list traversal | Real dump + symbols |
| memf-linux | Process list, connections, modules (synthetic chains) | Real Linux dump |
| memf-mac | Process list, connections, kexts (synthetic) | Real macOS dump |
| memf-windows | Process list, connections, modules (synthetic) | Real Windows dump |
| memf-strings | Extraction, classification, YARA rules, pre-existing file | Real strings files |
| memf-detect | Each engine with planted indicators (synthetic) | Real dumps with known artifacts |

### TDD Discipline

Every feature follows strict red-green-refactor:
1. Write failing test first
2. Run test, verify it fails for the right reason
3. Write minimal implementation to pass
4. Run test, verify it passes
5. Refactor if needed (tests still pass)
6. Commit

---

## 10. Phasing & External Dependencies

### Phase 1: Format Detection + String Analysis

**Crates built:** `memf-format` (Tier 1 formats), `memf-strings`, `memf` (CLI: `info`, `strings`)

**Deliverables:**
- Open LiME, AVML v2, and raw dumps
- Extract strings with configurable encoding and min-length
- Classify strings via regex classifiers (URLs, IPs, paths, credentials, crypto)
- YARA-X rule scanning
- `--from-file` mode for pre-extracted string files

**Key dependency:** `yara-x = "0.12"`

**Value:** Immediate utility for Issen UAC collections containing `memory-strings.ascii`. The `memf strings --from-file` command provides IoC classification without needing to parse the actual dump.

### Phase 2: Linux + macOS Process/Network Extraction

**Crates built:** `memf-symbols` (BTF + ISF), `memf-core`, `memf-linux`, `memf-mac`, `memf-format` (Tier 2 formats)

**Deliverables:**
- Symbol resolution via BTF (Linux) and ISF JSON (all)
- KASLR shift detection for Linux and macOS
- Virtual address translation (x86_64 4-level, AArch64)
- Linux process/connection/module walking
- macOS process/connection/kext walking
- CLI: `ps`, `netstat`, `modules` commands
- ELF core dump support, VMware `.vmem` support

**Key dependencies:** `bytemuck = "1"` (safe transmutation), `scroll = "0.12"` (binary parsing)

### Phase 3: Detection Engines + Windows

**Crates built:** `memf-detect`, `memf-windows`, `memf-format` (Tier 3 formats), `memf-symbols` (Mach-O backend)

**Deliverables:**
- Cross-view rootkit detection (Linux + Windows)
- Crypto key recovery (FDE keys, blockchain wallets, SSH keys)
- Credential extraction (DPAPI, LSASS concepts, OAuth tokens, session cookies)
- Windows process/connection/module walking
- Windows DMP, hiberfil.sys, Hyper-V format support
- DKOM detection
- CLI: `detect` command with engine selection

**Key dependencies:** `yara-x = "0.12"` (already from Phase 1), no new major deps

### External Dependencies Summary

| Dependency | Version | Used By | Purpose |
|-----------|---------|---------|---------|
| `thiserror` | 2 | all crates | Error types |
| `anyhow` | 1 | CLI only | Error context |
| `inventory` | 0.3 | all plugin crates | Compile-time registration |
| `memmap2` | 0.9 | memf-format | Memory-mapped I/O |
| `yara-x` | 0.12 | memf-strings | YARA rule engine |
| `bytemuck` | 1 | memf-core | Safe byte-to-type casting |
| `scroll` | 0.12 | memf-format, memf-symbols | Binary struct parsing |
| `clap` | 4 | CLI | Argument parsing |
| `comfy-table` | 7 | CLI | Table output formatting |
| `serde` / `serde_json` | 1 | memf-symbols (ISF), CLI | JSON parsing + output |
| `snap` | 1 | memf-format (AVML) | Snappy decompression |
| `flate2` | 1 | memf-format (kdump) | zlib/gzip decompression |
| `regex` | 1 | memf-strings, memf-detect | Pattern matching |
| `aho-corasick` | 1 | memf-strings, memf-detect | Multi-pattern scanning |

---

## References

### Research Corpus

All research files located at `~/src/Issen/research/`:

- `memory-forensics-landscape.md` -- Tool comparison (Volatility 3, Rekall, MemProcFS, mquire), Rust ecosystem gaps
- `memory-dump-file-formats-specification.md` -- All 13+ format specs with magic bytes, header layouts, compression
- `linux-kernel-memory-forensics-data-structures.md` -- task_struct, sockets, modules, rootkit detection, key recovery
- `volatility3-architecture-deep-dive.md` -- ISF format, layer system, Linux plugin internals
- `memory-strings-analysis-techniques.md` -- IoC patterns, YARA rules, sockstat analysis
- `fde-keys-credential-stores-memory-forensics.md` -- BitLocker, FileVault, LUKS, DPAPI, LSASS, SSH, browser creds
- `oauth-cookies-tokens-memory-forensics.md` -- JWT, OAuth, SAML, Kerberos, API keys, session cookies, TOTP, cert keys
- `blockchain-key-formats-memory-forensics.md` -- Bitcoin WIF, BIP-39, BIP-32, Ethereum, Monero, Solana

### Inspirations

- [Volatility 3](https://github.com/volatilityfoundation/volatility3) -- Python, ISF symbol format, plugin architecture
- [mquire](https://github.com/mtth-bfft/mquire) -- Rust, Windows memory forensics
- [MemProcFS](https://github.com/ufrisk/MemProcFS) -- C, FUSE-based memory filesystem
- [AVML](https://github.com/microsoft/avml) -- Rust, Azure memory acquisition
- [YARA-X](https://github.com/VirusTotal/yara-x) -- Rust, pattern matching engine
