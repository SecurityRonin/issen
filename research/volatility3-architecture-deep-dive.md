# Volatility 3 Architecture & Linux Plugin System — Deep Research

> Research date: 2026-03-30
> Sources: Vol3 official docs, GitHub source code (develop branch), DeepWiki analysis

---

## 1. Architecture: Vol3 vs Vol2

### Fundamental Design Shift

| Aspect | Volatility 2 | Volatility 3 |
|---|---|---|
| Symbol info | Monolithic profiles (vtypes + overlays) | ISF JSON symbol tables per kernel build |
| Memory model | Linear address space stack | Directed graph of layers (DAG) |
| Object model | Proxy objects (ordering-sensitive ops) | Native Python subclasses (int is int) |
| State management | Global/implicit | Context object (self-contained) |
| Auto-setup | Implicit, not modular | Automagic system (enable/disable per run) |
| Data reads | Live re-reads (designed for live memory) | Single read at construction (static) |
| Library design | Script-oriented | Library-first (embeddable) |

### Core Components

1. **Context** (`ContextInterface`): Central container holding all layers, symbol tables, and modules. All state needed to run a plugin is self-contained here. Plugins receive it as a dependency.

2. **Memory Layers**: A directed graph. Terminal nodes are `DataLayerInterface` (raw bytes from files). Internal nodes are `TranslationLayerInterface` (address translation). A single virtual layer can depend on multiple physical layers (e.g., RAM + swap file).

3. **Symbol Tables (ISF)**: JSON-based Intermediate Symbol Format containing type definitions, symbol addresses, enumerations, and metadata. Validated against JSON schemas in `volatility3/schemas/`.

4. **Automagic System**: Modular setup phase before plugin execution. Identifies OS, locates symbol tables, builds layer stack, determines KASLR/ASLR shifts. Each automagic has a `stack_order` priority.

5. **Plugin System**: Plugins inherit `PluginInterface`, declare requirements via `get_requirements()`, implement `_generator()` yielding data tuples, and return `TreeGrid` output from `run()`.

### Object Model

Vol3 objects inherit directly from their Python counterparts. An integer recovered from memory is a real `int` with all standard methods. Vol2's proxy approach caused subtle bugs where `x + y` might work but `y + x` might not if one operand was a proxy.

Data is read once at object construction and cached. This eliminated redundant page table walks that Vol2 performed on each property access.

---

## 2. ISF — Intermediate Symbol Format

### JSON Structure

An ISF file contains five groups:

```json
{
  "metadata": {
    "producer": { "name": "dwarf2json", "version": "0.9.0" },
    "format": "6.2.0",
    "linux": { ... }
  },
  "base_types": {
    "int": { "size": 4, "signed": true, "kind": "int", "endian": "little" },
    "pointer": { "size": 8, "signed": false, "kind": "int", "endian": "little" }
  },
  "user_types": {
    "task_struct": {
      "size": 9792,
      "fields": {
        "pid": { "type": { "kind": "base", "name": "int" }, "offset": 1256 },
        "comm": { "type": { "kind": "array", "count": 16, "subtype": { "kind": "base", "name": "char" } }, "offset": 1400 },
        "tasks": { "type": { "kind": "struct", "name": "list_head" }, "offset": 1080 }
      }
    }
  },
  "enums": {
    "module_state": {
      "size": 4,
      "base": "unsigned int",
      "constants": { "MODULE_STATE_LIVE": 0, "MODULE_STATE_COMING": 1 }
    }
  },
  "symbols": {
    "init_task": { "address": 18446744071596400640 },
    "sys_call_table": { "address": 18446744071594680320 },
    "linux_banner": { "address": 18446744071594164224, "constant_data": "TGludXgg..." }
  }
}
```

### Symbol Table Generation Pipeline

| OS | Tool | Input | Output |
|---|---|---|---|
| **Linux** | `dwarf2json` (Go binary) | ELF with DWARF debug info + optional System.map | ISF JSON |
| **macOS** | `dwarf2json` | Mach-O from Kernel Debug Kit (KDK) | ISF JSON |
| **Windows** | `pdbconv.py` (Python) | PDB files from Microsoft Symbol Server | ISF JSON |

#### Linux ISF Generation Steps

1. Identify exact kernel version (from `linux_banner` in memory via `banners` plugin)
2. Obtain debug kernel package:
   - Debian/Ubuntu: `linux-image-$(uname -r)-dbgsym` (`.ddeb`)
   - RHEL/CentOS: `kernel-debuginfo-$(uname -r)`
   - Contains `/usr/lib/debug/boot/vmlinux-<version>` with DWARF info
3. Generate ISF:
   ```bash
   dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-5.15.0-91-generic \
     --system-map /boot/System.map-5.15.0-91-generic > linux-5.15.0-91-generic.json
   ```
4. Place under `volatility3/symbols/linux/` (or any subdirectory, organization doesn't matter)
5. Requires 8GB+ RAM for processing large DWARF files

**Critical**: Exact banner match required. Not just kernel version — includes build timestamp, GCC version, kernel config hash. A generic "close enough" table will produce inaccurate results.

#### Windows ISF Generation

Windows is simpler — Volatility auto-downloads PDB from Microsoft's symbol server based on GUID+age from the memory image. `pdbconv.py` converts PDB → ISF JSON automatically. No manual intervention needed for most cases.

### Caching System

- SQLite database at `~/.cache/volatility3/` stores `identifier → ISF file path` mappings
- Identifier for Linux = `linux_banner` constant_data (base64-encoded banner string)
- Identifier for Windows = `PDB_name|GUID|age`
- Cache updated automatically by `SymbolCacheMaintenance` automagic on each run
- First run with many new ISF files may take time; can be safely interrupted

### Emerging: BTF-Based ISF

BPF Type Format (BTF) data in kernel binaries contains compact type information. Research projects aim to generate ISF from BTF + System.map without needing the full debug kernel. Potentially enables ISF creation from the memory dump itself. Still early-stage.

---

## 3. Layer System — Address Translation

### Layer Hierarchy (Directed Graph)

```
Plugin reads virtual address 0xffff888012345678
  │
  ▼
LinuxIntel32e (TranslationLayer)
  ├── page_map_offset = DTB from init_top_pgt symbol
  ├── walks 4-level page table: PML4 → PDPT → PD → PT
  ├── translates to physical address 0x12345678
  │
  ├─→ FileLayer "memory_layer" (DataLayer)
  │     reads offset 0x12345678 from memory dump file
  │
  └─→ SwapLayer (optional, for paged-out memory)
        reads from swap file
```

### Layer Interface Hierarchy

```
DataLayerInterface (abstract)
├── FileLayer — reads from file on disk
├── QemuLayer — handles QEMU memory snapshots
├── LiMELayer — Linux Memory Extractor format
└── ELFLayer — ELF core dumps

TranslationLayerInterface (abstract)
└── LinearlyMappedLayer
    └── Intel (IA32, 32-bit, 2-level page tables)
        ├── IntelPAE (32-bit PAE, 3-level page tables)
        └── Intel32e (64-bit, 4-level page tables)
            ├── Intel32e5Levels (64-bit LA57, 5-level)
            ├── LinuxIntel32e (Linux-specific canonical handling)
            ├── LinuxIntel (Linux 32-bit specific)
            └── WindowsIntel32e (Windows-specific)
```

### Intel Translation Implementation (`intel.py`)

The `Intel` class implements IA32 page table walk:

```python
class Intel(linear.LinearlyMappedLayer):
    _PAGE_BIT_PRESENT = 0
    _PAGE_BIT_PSE = 7  # Page Size Extension (2MB/4MB pages)
    _page_size_in_bits = 12  # 4096 byte pages
    _bits_per_register = 32
    _maxvirtaddr = 32

    # Page table structure: (bit position, entry width, large_page?)
    _structure = [(12, 10, False), (22, 10, True)]
    # Level 1: bits 12-21 (1024 entries per table)
    # Level 2: bits 22-31 (1024 entries, can be 4MB large page)
```

For 64-bit (`Intel32e`):
```python
class Intel32e(Intel):
    _bits_per_register = 64
    _maxvirtaddr = 48
    _structure = [
        (12, 9, False),   # PT:   bits 12-20 (512 entries)
        (21, 9, True),    # PD:   bits 21-29 (512 entries, 2MB large pages)
        (30, 9, True),    # PDPT: bits 30-38 (512 entries, 1GB large pages)
        (39, 9, False),   # PML4: bits 39-47 (512 entries)
    ]
```

#### Translation Algorithm (`_translate` method)

1. Start with initial entry = `page_map_offset | 0x1` (DTB with present bit set)
2. For each level in `_structure` (from highest to lowest):
   a. Extract index from virtual address using bit position and width
   b. Compute entry address: `(entry & page_mask) + (index * entry_size)`
   c. Read entry from lower layer
   d. Check present bit — if not present, check swap layers
   e. If PSE bit set and level supports large pages → direct mapping
3. Final physical address = `(last_entry & page_mask) | (virtual_addr & page_offset_mask)`

#### Linux-Specific Layer Handling

`LinuxIntel32e` overrides canonical address handling. Linux uses "high half" canonical addresses for kernel space (addresses with bit 47 set get sign-extended to have bits 48-63 all set = `0xffff...`).

### Automagic Layer Stacking (`LinuxIntelStacker`)

The stacker is the bridge between a raw memory dump and a usable analysis environment:

1. **Banner scanning**: Scans physical memory for `linux_banner` strings using `MultiStringScanner`
2. **ISF matching**: Looks up scanned banner in SQLite cache to find corresponding ISF file
3. **Symbol table creation**: Loads ISF as `LinuxKernelIntermedSymbols` table
4. **KASLR detection**: Scans for `init_task.comm == "swapper\0"` pattern in memory, compares found address vs ISF-declared address to compute `kaslr_shift`
5. **DTB discovery**: Reads DTB (Directory Table Base/CR3) from `init_top_pgt` or `init_level4_pgt` or `swapper_pg_dir` symbol (adjusted by KASLR shift)
6. **Layer creation**: Instantiates `LinuxIntel32e` (or appropriate variant) with DTB as `page_map_offset`
7. **Verification**: Reads `init_task` through the new virtual layer to confirm translation works

```python
# Simplified flow in LinuxIntelStacker.stack()
banner_match → load ISF → find_aslr() → get DTB symbol →
  create Intel layer → verify → return layer
```

---

## 4. Linux Plugin Internals

### 4.1 linux.pslist — Process Listing

**Purpose**: Lists all processes visible in the kernel's task list.

**Kernel Structures Walked**:
- `init_task` (symbol): The idle/swapper process (PID 0), always present
- `task_struct.tasks` (`list_head`): Doubly-linked list connecting all `task_struct` instances
- `task_struct.thread_group` (`list_head`): Links threads within a thread group

**Algorithm**:
1. Resolve `init_task` symbol → get kernel `task_struct` for PID 0
2. Follow `init_task.tasks.next` → traverse linked list
3. For each `task_struct`: extract PID, TGID, PPID, comm, UID/GID, creation_time
4. If `--threads`: also walk `thread_group` list per task
5. If `--dump`: use `elfs.Elfs` to extract process binary

**Key code**:
```python
@classmethod
def list_tasks(cls, context, vmlinux_module_name, filter_func=None):
    vmlinux = context.modules[vmlinux_module_name]
    init_task = vmlinux.object_from_symbol(symbol_name="init_task")
    # Walk the tasks linked list
    for task in init_task.tasks.to_list(
        vmlinux.symbol_table_name + "!task_struct", "tasks"
    ):
        if filter_func and not filter_func(task):
            continue
        yield task
```

**`TaskFields` dataclass** (returned per process):
- `offset`: Physical offset of `task_struct` in memory
- `user_pid` / `user_tid` / `user_ppid`: PID namespace-aware values
- `name`: Process command name (16 chars max)
- `uid`, `gid`, `euid`, `egid`: Credential IDs
- `creation_time`: Process birth timestamp (if available)

**Limitations**: Only finds processes in the active task list. Hidden/unlinked processes (rootkit technique) won't appear. Use `psscan` for those.

### 4.2 linux.pstree — Process Tree

**Purpose**: Displays process hierarchy (parent → child relationships).

**Algorithm**:
1. Call `PsList.list_tasks()` to enumerate all processes
2. Build `_tasks` dict: `{pid: task_struct}`
3. Build `_children` dict: `{parent_pid: set(child_pids)}`
4. For each task, `find_level()` walks up parent chain to compute depth
5. Detect anomalies: smeared processes (ppid=0, pid>2), circular references

**Smear detection**: If `parent_pid == 0` and `pid > 2`, the process is likely from a smeared (corrupted/terminated) memory region. Only PID 1 (init/systemd) and PID 2 (kthreadd) legitimately have swapper (PID 0) as parent.

### 4.3 linux.bash — Bash History from Memory

**Purpose**: Recovers bash command history even after `history -c` or `.bash_history` deletion.

**How it works** (two-phase approach):

**Phase 1 — Process identification**:
1. Use `PsList.list_tasks()` to find bash/sh/dash processes
2. Create process memory layer via `task.add_process_layer()`

**Phase 2 — Heap scanning**:
1. Load bash-specific ISF (`bash32` or `bash64` JSON) defining `hist_entry` structure
2. `hist_entry` structure: `{ char *line; char *timestamp; char *data; }`
3. Scan process heap for timestamp markers (`#` followed by 10+ digits = Unix epoch)
4. For each timestamp hit, compute offset to `hist_entry` start using `ts_offset`
5. Read `hist_entry.line` pointer → dereference to get command string
6. Parse `hist_entry.timestamp` → convert Unix epoch to human-readable datetime

**Key detail**: The `hist_entry` struct is from bash source code, not the kernel. Vol3 ships its own ISF for bash structures (`volatility3/framework/symbols/linux/bash.py`).

**Forensic value**: Recovers commands that were:
- Cleared with `history -c`
- From sessions where `.bash_history` was never written (crash, kill)
- From `HISTFILE=/dev/null` configurations (commands still in heap)

### 4.4 linux.check_syscall — Syscall Table Integrity

**Purpose**: Detect rootkits that hook system calls by replacing `sys_call_table` entries.

**Kernel Structure**: `sys_call_table` — a kernel-global array of function pointers. Index = syscall number, value = handler address. Example: `sys_call_table[1]` = address of `sys_write`.

**Algorithm**:
1. Locate `sys_call_table` symbol address
2. Determine table size (number of syscalls) via three methods:
   - **Disassembly** (requires `capstone`): Find `system_call_fastpath` function, disassemble to find `cmp reg, NR_syscalls` instruction
   - **Meta symbols**: Count symbols starting with `__syscall_meta__`
   - **Next symbol**: Calculate `(next_symbol_address - table_address) / pointer_size`
3. Take minimum of available sizes for safety
4. For each entry `i` in `[0, table_size)`:
   - Read function pointer from `sys_call_table + i * ptr_size`
   - Resolve address → symbol name using `lookup_module_address()`
   - Categorize: kernel function (normal), module function (suspicious), unknown (HOOKED)
5. Also checks 32-bit compatibility table (`ia32_sys_call_table`) on 64-bit systems

**Detection heuristic**: Any syscall handler pointing outside kernel text section or known legitimate modules is flagged. Rootkits commonly hook: `sys_getdents` (hide files), `sys_read` (hide data), `sys_kill` (trigger backdoor), `sys_write` (filter output).

### 4.5 linux.hidden_modules — Find Hidden Kernel Modules

**Purpose**: Detect kernel modules that have been deliberately unlinked from the `modules` list (rootkit technique).

**Two detection techniques**:

#### Technique 1: Memory-Aligned Scanning (kernels >= 4.2)
From kernel 4.2+, `struct module` allocations are aligned to L1 cache line size (typically 64 bytes on x86/x86_64/arm64).

1. Determine module memory region boundaries from known modules
2. Scan the region at 64-byte alignment boundaries
3. At each candidate offset, overlay `struct module` template
4. Validate via `module.is_valid()`:
   - Entire struct readable in memory
   - `core_size >= MODULE_MINIMUM_SIZE` (4096 bytes)
   - `core_text_size <= core_size` (text can't exceed total)
   - `init_size` is reasonable (0 to 10MB cap)
   - **Self-referential check**: `mkobj.mod == module_address` (module's kobject points back to itself)
5. Compare against `lsmod` list — modules found by scan but not in list = **HIDDEN**

#### Technique 2: Legacy Scanning (older kernels)
Falls back to broader scanning without alignment constraints. Less efficient but works on pre-4.2 kernels.

**Why self-referential check works**: `struct module` contains `module_kobject mkobj`, which has a `struct module *mod` member pointing back to the module itself. This circular reference is set during module initialization and is extremely unlikely to occur by coincidence in random memory.

### 4.6 linux.lsmod — Loaded Kernel Modules

**Purpose**: List modules from the kernel's official module list.

**Kernel Structure**:
- `modules` symbol → `list_head` pointing to `struct module` chain
- Each `struct module` linked via `module.list` member

**Implementation**:
- Delegates to `linux_utilities_modules.Modules.list_modules()`
- Walks linked list from `modules` head
- Extracts: module name, core layout size, taint flags, dependencies
- Supports `--dump` to extract module binary to disk

**Taint flags decoded**: Proprietary (P), GPL (G), out-of-tree (O), unsigned (E), staging (S), etc.

### 4.7 linux.sockstat — Socket Statistics (replaces netstat)

**Purpose**: Enumerate all network sockets per process with full connection details.

**Kernel Structures**:
- `task_struct.files.fdt.fd[]` → file descriptor array
- Socket FDs identified by `struct file.f_op` matching socket operations
- `struct socket` → `struct sock *sk` → socket family-specific structs

**Socket Family Handlers**:

| Family | Handler | Key Fields Extracted |
|---|---|---|
| `AF_UNIX` | `_unix_sock()` | Path, peer, state |
| `AF_INET` | `_inet_sock()` | Source/dest IP + port, TCP state, protocol |
| `AF_INET6` | `_inet_sock()` | IPv6 addresses + port, TCP state |
| `AF_NETLINK` | `_netlink_sock()` | Port ID, groups, protocol |
| `AF_VSOCK` | `_vsock_sock()` | CID, port |
| `AF_PACKET` | `_packet_sock()` | Interface, protocol |
| `AF_XDP` | `_xdp_sock()` | Interface, queue ID |
| `AF_BLUETOOTH` | `_bluetooth_sock()` | BT-specific |

**Implementation details**:
1. Build network device map from `net_namespace_list` → maps `ifindex` to interface name
2. For each process (via `pslist`), iterate FDs (via `lsof`)
3. Identify socket FDs by `f_op` check
4. Cast `struct file` → `struct socket` → `struct sock`
5. Dispatch to family-specific handler based on `sk.__sk_common.skc_family`
6. Each handler casts to protocol-specific struct (e.g., `inet_sock`, `unix_sock`)
7. Extract addresses, ports, states using kernel structure offsets

**Note**: Vol3 does NOT have a separate `linux.netstat` plugin. `sockstat` is the modern equivalent with far more capability.

### 4.8 linux.proc.Maps — Process Memory Maps

**Purpose**: Lists all VMAs (Virtual Memory Areas) for processes, equivalent to `/proc/<pid>/maps`.

**Kernel Structures**:
- `task_struct.mm` → `mm_struct` → VMA list/tree
- `vm_area_struct`: `vm_start`, `vm_end`, `vm_flags`, `vm_file`, `vm_pgoff`
- Newer kernels (6.1+): maple tree instead of linked list for VMAs

**Implementation**:
```python
@classmethod
def list_vmas(cls, task, filter_func=...):
    mm_pointer = task.mm
    if mm_pointer:
        for vma in mm_pointer.get_vma_iter():
            if filter_func(vma):
                yield vma
```

Each VMA reports: start address, end address, flags (rwxp), page offset, major:minor device, inode, file path.

### 4.9 linux.malfind — Detect Injected/Suspicious Memory

**Purpose**: Find process memory regions that likely contain injected code.

**Detection Heuristics** (`vma.is_suspicious()`):
1. **Executable**: VMA has `VM_EXEC` flag set
2. **Anonymous**: No backing file (`vm_file` is NULL) — legitimate code comes from mapped files
3. **Dirty pages**: At least one page in the region has soft-dirty bit set (recently written)
4. The combination means: someone wrote executable code to anonymous memory at runtime

**What it catches**:
- Shellcode injection via `mmap(RWX)` + write
- `mprotect()` escalation (allocate RW, write code, change to RX)
- LD_PRELOAD-style injections that create anonymous executable mappings
- Process hollowing remnants

**What it reports per finding**:
- PID, process name
- VMA start/end address
- VMA protection flags (e.g., `r-xp`)
- VMA name (usually blank for anonymous)
- First N bytes (hex dump) of the suspicious region
- Optionally all dirty pages via `--dump-page`

**False positive sources**: JIT compilers (Java, .NET, V8), legitimate `mmap(PROT_EXEC)` usage. Context is key.

### 4.10 linux.check_idt — Interrupt Descriptor Table Verification

**Purpose**: Detect IDT hooking where interrupt handlers are replaced.

**Kernel Structure**: `idt_table` — 256-entry array of gate descriptors.

**Gate descriptor fields** (64-bit / `gate_struct64`):
- `offset_low` (bits 0-15 of handler address)
- `offset_middle` (bits 16-31)
- `offset_high` (bits 32-63)
- Reconstructed: `handler = offset_low | (offset_middle << 16) | (offset_high << 32)`

**Algorithm**:
1. Determine gate type from available symbols (arch-dependent)
2. Read all 256 IDT entries from `idt_table` symbol
3. For each entry:
   - Reconstruct full handler address from offset fields
   - Resolve to symbol + module via `lookup_module_address()`
   - Report: vector number, handler address, symbol, module
4. Entries pointing outside kernel text or known modules = potential hook

**Forensic significance**: IDT hooks are used by rootkits to intercept hardware interrupts, page faults, and software traps. Less common than syscall hooks but harder to detect without memory analysis.

### 4.11 linux.tty_check — TTY Hook Detection (Reverse Shell Detection!)

**Purpose**: Detect hooks in TTY line discipline operations — a strong indicator of reverse shells and keystroke loggers.

**Kernel Structures**:
- `tty_drivers` → linked list of `tty_driver` structs
- `tty_driver.ttys[]` → array of `tty_struct` pointers
- `tty_struct.ldisc` → `tty_ldisc` → `tty_ldisc_ops`
- `tty_ldisc_ops` function pointers: `open`, `close`, `read`, `write`, `receive_buf`, `write_wakeup`

**Algorithm**:
1. Walk `tty_drivers` linked list
2. For each driver, iterate `ttys[0..num]` array
3. For each active TTY:
   - Read `ldisc.ops` function pointers
   - Resolve each function pointer to kernel symbol/module
   - Compare against known modules list (from `run_modules_scanners`)
4. Any function pointer pointing to unknown/unexpected address = potential hook

**Why this matters for reverse shells**:
- Attackers using `socat`, `script`, or PTY-based reverse shells manipulate TTY line disciplines
- Custom `receive_buf` handler can intercept all terminal input (keystroke logger)
- Custom `write` handler can intercept all terminal output (exfiltration)
- Modified ldisc ops are invisible from userspace tools like `ps` or `strace`

---

## 5. Additional Notable Plugins

### Malware Detection Suite (`linux/malware/`)
As of 2025, Vol3 reorganized malware-focused plugins under `linux/malware/`:
- `check_syscall.py` — Syscall table hook detection
- `check_idt.py` — IDT hook detection
- `malfind.py` — Suspicious memory detection
- `tty_check.py` — TTY hook detection
- `hidden_modules.py` — Hidden module detection
- `check_afinfo.py` — Network protocol handler verification
- `check_creds.py` — Credential anomaly detection
- `keyboard_notifiers.py` — Keylogger detection
- `modxview.py` — Multi-source module cross-reference
- `netfilter.py` — Network filter hook analysis
- `process_spoofing.py` — Process name/PID spoofing detection

### Process Analysis
- `pslist` — Task list walk (primary)
- `pstree` — Hierarchical view
- `psscan` — Physical memory scan for task_struct (finds hidden/dead processes)
- `pidhashtable` — PID hash table enumeration (alternative, cross-reference with pslist)
- `psaux` — Command line arguments (from `/proc/*/cmdline` equivalent)
- `pscallstack` — Process call stacks

### Network
- `sockstat` — Full socket enumeration (TCP/UDP/Unix/Netlink/XDP/Bluetooth/VSOCK/Packet)
- `sockscan` — Physical memory scan for socket structures
- `ip.Addr` — Network interface configuration (IPs, MACs, promiscuous mode)

### Kernel Integrity
- `check_modules` — Cross-reference modules visible in different kernel structures
- `kallsyms` — Recover kernel symbol table from memory
- `ebpf` — List loaded eBPF programs (eBPF rootkit detection)
- `ftrace` / `tracepoints` / `perf_events` — Kernel tracing hook detection

### Filesystem & Data
- `lsof` — Open files per process
- `proc.Maps` — Process memory maps
- `mountinfo` — Mount points
- `pagecache` — Cached file pages in memory
- `envars` — Process environment variables

---

## 6. Plugin Architecture Pattern

Every Vol3 Linux plugin follows this structural pattern:

```python
class MyPlugin(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(name="kernel", ...),
            # Optional: version requirements, filters, booleans
        ]

    def _generator(self):
        vmlinux = self.context.modules[self.config["kernel"]]
        # Walk kernel structures using vmlinux symbols
        for item in self._walk_structures(vmlinux):
            yield (0, (field1, field2, field3))

    def run(self):
        return renderers.TreeGrid(
            [("Field1", str), ("Field2", int), ("Field3", format_hints.Hex)],
            self._generator()
        )
```

**Key patterns**:
- `self.context.modules[self.config["kernel"]]` — get kernel module with symbols
- `vmlinux.object_from_symbol("name")` — create typed object at symbol address
- `vmlinux.get_symbol("name").address` — get raw symbol address
- `obj.member.to_list("type!struct_name", "list_member")` — walk kernel linked lists
- `LinuxUtilities.lookup_module_address()` — resolve address → symbol + module
- `task.add_process_layer()` — create virtual memory layer for a process
- `context.layers[name].scan()` — scan layer for patterns

---

## References

- Volatility 3 Official Documentation: https://volatility3.readthedocs.io/en/latest/
- Volatility 3 GitHub (develop): https://github.com/volatilityfoundation/volatility3
- dwarf2json: https://github.com/volatilityfoundation/dwarf2json
- Pre-built ISF Collection: https://github.com/Abyss-W4tcher/volatility3-symbols
- DeepWiki Analysis: https://deepwiki.com/volatilityfoundation/volatility3/
- HackTheBox ISF Guide: https://www.hackthebox.com/blog/how-to-create-linux-symbol-tables-volatility
