# Linux Kernel Data Structures for Memory Forensics

> Deep research compilation covering process structures, network sockets, kernel modules,
> file descriptors, filesystem structures, symbol resolution, rootkit detection, and
> cryptographic key recovery from Linux memory dumps.
>
> Date: 2026-03-30

---

## Table of Contents

1. [Process Structures](#1-process-structures)
2. [Network Structures](#2-network-structures)
3. [Kernel Module List](#3-kernel-module-list)
4. [File Descriptors](#4-file-descriptors)
5. [Mount/Filesystem Structures](#5-mountfilesystem-structures)
6. [Symbol Resolution](#6-symbol-resolution)
7. [Rootkit Detection](#7-rootkit-detection)
8. [Cryptographic Key Recovery](#8-cryptographic-key-recovery)

---

## 1. Process Structures

### 1.1 `task_struct` — The Process Descriptor

Every process and thread in Linux is represented by a `struct task_struct`, defined in
`include/linux/sched.h`. On modern kernels (6.x), this structure is approximately 8KB
with ~155 fields. It is the central nexus for all process-related data.

**Key fields for forensics:**

| Field | Type | Forensic Significance |
|-------|------|----------------------|
| `pid` | `pid_t` | Thread ID (the kernel-level identifier; misleading name) |
| `tgid` | `pid_t` | Thread Group ID — this is the user-visible PID |
| `comm` | `char[16]` | Executable basename, truncated to 16 characters |
| `mm` | `struct mm_struct *` | Memory management descriptor (NULL for kernel threads) |
| `files` | `struct files_struct *` | Open file descriptor table |
| `fs` | `struct fs_struct *` | Filesystem info: current working directory, root |
| `nsproxy` | `struct nsproxy *` | Namespace proxy (IPC, net, PID, mount, cgroup, time) |
| `cred` | `const struct cred *` | Process credentials: uid, gid, euid, egid, capabilities |
| `tasks` | `struct list_head` | Circular doubly-linked process list linkage |
| `parent` | `struct task_struct *` | Parent process pointer |
| `children` | `struct list_head` | Child process list head |
| `sibling` | `struct list_head` | Links siblings under the same parent |
| `thread_info` | `struct thread_info` | Low-level CPU/thread state, preemption count |
| `state` / `__state` | `unsigned int` | Process state (TASK_RUNNING, TASK_INTERRUPTIBLE, etc.) |
| `start_time` | `u64` | Process start time (monotonic) |
| `real_start_time` | `u64` | Process start time (boot-based) |

**Important notes on offsets:** Exact field offsets depend on kernel version, architecture
(x86, x86_64, ARM64), and kernel configuration (`CONFIG_SMP`, `CONFIG_CGROUPS`, etc.).
Tools like `pahole`, `gdb` with debug symbols, or the `offsetof()` macro determine
offsets at runtime. BTF (BPF Type Format) embedded in modern kernels also provides this
information.

### 1.2 Walking the Process List

The kernel maintains a circular doubly-linked list of all `task_struct` instances. The
anchor is `init_task` — the statically-allocated idle process (PID 0, "swapper").

**How it works:**

```
init_task.tasks <---> process_A.tasks <---> process_B.tasks <---> ... <---> init_task.tasks
```

The `for_each_process()` macro iterates the entire list:

```c
#define for_each_process(p) \
    for (p = &init_task; (p = next_task(p)) != &init_task; )
```

**Forensic tool approach:**

1. Locate the `init_task` symbol via `System.map`, kallsyms, or by scanning for the
   known `init_task` structure signature.
2. Follow the `tasks.next` pointer to get the next `task_struct` (using `list_entry()`
   to convert from `list_head` to the containing `task_struct`).
3. Continue traversing until `tasks.next` points back to `init_task`.
4. For each `task_struct`, extract `pid`, `tgid`, `comm`, `mm`, `cred`, etc.

**Alternative enumeration methods (for rootkit detection):**
- **PID namespace hash table**: Walk the PID hash table (`pid_hash[]` or radix tree in
  modern kernels) to find tasks by PID rather than the task list.
- **For threads**: Use `for_each_process_thread(p, t)` which iterates the thread group
  list via `thread_group` linked list within each process.

### 1.3 `mm_struct` — Memory Descriptor

Each process's virtual address space is described by `struct mm_struct`, pointed to by
`task_struct->mm`. Kernel threads have `mm = NULL`.

**Key fields:**

| Field | Type | Description |
|-------|------|-------------|
| `pgd` | `pgd_t *` | Page Global Directory — root of the page table tree |
| `mmap` | `struct vm_area_struct *` | (Legacy) Head of the VMA linked list |
| `mm_mt` | `struct maple_tree` | (Modern, 6.1+) Maple tree containing all VMAs |
| `map_count` | `int` | Number of VMAs |
| `total_vm` | `unsigned long` | Total number of pages mapped |
| `start_code` / `end_code` | `unsigned long` | Code segment boundaries |
| `start_data` / `end_data` | `unsigned long` | Data segment boundaries |
| `start_brk` / `brk` | `unsigned long` | Heap boundaries |
| `start_stack` | `unsigned long` | Stack start |
| `arg_start` / `arg_end` | `unsigned long` | argv location |
| `env_start` / `env_end` | `unsigned long` | Environment variables location |
| `exe_file` | `struct file *` | The executable file struct |

**Forensic use:** `pgd` gives you the page table root (equivalent to the CR3 register
value on x86_64), enabling virtual-to-physical address translation for the process's
entire address space.

### 1.4 `vm_area_struct` — Virtual Memory Areas

Each VMA describes a contiguous range of virtual addresses with identical attributes.

**Key fields:**

| Field | Type | Description |
|-------|------|-------------|
| `vm_start` | `unsigned long` | Start address (inclusive) |
| `vm_end` | `unsigned long` | End address (exclusive) |
| `vm_flags` | `unsigned long` | Access permissions + behavior flags (VM_READ, VM_WRITE, VM_EXEC, VM_SHARED) |
| `vm_page_prot` | `pgprot_t` | Page-level protection |
| `vm_file` | `struct file *` | Backing file (NULL for anonymous mappings) |
| `vm_pgoff` | `unsigned long` | Offset within the file (in pages) |
| `vm_mm` | `struct mm_struct *` | Back-pointer to the owning mm_struct |

**Forensic use:** Walking VMAs reveals every mapped region — executable code, shared
libraries, heap, stack, memory-mapped files, and anonymous mappings. The `vm_file`
pointer links to the backing file (via dentry and inode), enabling identification of
which shared libraries are loaded.

**Walking VMAs:** In kernels before 6.1, VMAs were in a linked list via `vm_next`. In
6.1+, VMAs live in a maple tree (`mm_struct->mm_mt`), requiring maple tree traversal
(the `VMA_ITERATOR` or `vma_iter_*` APIs in kernel, or the forensic tool must implement
maple tree walking).

### 1.5 Page Table Walking

Given `mm_struct->pgd`, a forensic tool walks the page tables to translate virtual
addresses to physical addresses:

```
PGD (Page Global Directory)
 -> PUD (Page Upper Directory)      [4-level paging on x86_64]
   -> PMD (Page Middle Directory)
     -> PTE (Page Table Entry)
       -> Physical Page Frame
```

On x86_64 with 4-level paging, a 48-bit virtual address is split:
- Bits 47-39: PGD index (9 bits, 512 entries)
- Bits 38-30: PUD index (9 bits)
- Bits 29-21: PMD index (9 bits)
- Bits 20-12: PTE index (9 bits)
- Bits 11-0: Page offset (12 bits, 4KB page)

5-level paging (with PGD -> P4D -> PUD -> PMD -> PTE) is used on newer kernels with
`CONFIG_X86_5LEVEL`.

---

## 2. Network Structures

### 2.1 Socket Structure Hierarchy

Linux uses a layered hierarchy of socket structures, each adding protocol-specific fields:

```
struct socket        (BSD socket abstraction — user-space facing)
  -> struct sock     (network-layer socket — INET socket in kernel terminology)
    -> struct inet_sock          (IPv4/IPv6 specific: addresses, ports)
      -> struct inet_connection_sock  (connection-oriented: TCP timers, congestion)
        -> struct tcp_sock       (TCP specific: sequence numbers, windows, etc.)
```

**Critical design pattern:** Each struct embeds the previous one as its first member.
This enables safe C-style "inheritance" through pointer casting:

```c
// All of these point to the same memory location:
struct sock *sk;
struct inet_sock *inet = inet_sk(sk);
struct inet_connection_sock *icsk = inet_csk(sk);
struct tcp_sock *tp = tcp_sk(sk);
```

The casting works because when a TCP socket is allocated, `prot->obj_size` equals
`sizeof(struct tcp_sock)`, so the full structure is allocated and the `struct sock`
sits at offset 0.

### 2.2 `struct sock` (and `sock_common`)

The generic network socket. The most forensically relevant fields are in `__sk_common`
(type `struct sock_common`), shared with `inet_timewait_sock`:

| Field | Type | Description |
|-------|------|-------------|
| `skc_daddr` | `__be32` | Foreign (destination) IPv4 address |
| `skc_rcv_saddr` | `__be32` | Bound local IPv4 address |
| `skc_dport` | `__be16` | Destination port |
| `skc_num` | `unsigned short` | Local port (host byte order) |
| `skc_family` | `unsigned short` | Address family (AF_INET, AF_INET6) |
| `skc_state` | `volatile unsigned char` | Connection state (TCP_ESTABLISHED, etc.) |
| `skc_prot` | `struct proto *` | Protocol operations |
| `sk_socket` | `struct socket *` | Back-pointer to the BSD socket |

For IPv6, the `skc_v6_daddr` and `skc_v6_rcv_saddr` fields (type `struct in6_addr`)
hold the 128-bit addresses.

### 2.3 `struct inet_sock`

Extends `struct sock` with IP-layer fields:

| Field | Type | Description |
|-------|------|-------------|
| `inet_saddr` | `__be32` | Source address (may duplicate `skc_rcv_saddr`) |
| `inet_dport` | `__be16` | Destination port (may duplicate `skc_dport`) |
| `inet_sport` | `__be16` | Source port |
| `inet_id` | `__u16` | IP ID field counter |
| `uc_ttl` | `__s16` | Unicast TTL |

Note: In modern kernels (4.x+), many of these fields have been consolidated into
`sock_common` and are accessed via macros/inline functions. The exact field layout
depends on the kernel version.

### 2.4 `struct tcp_sock`

The full TCP state. Its fields are organized into cacheline groups for fast-path
performance. Key fields for forensics:

**Sequence Number Fields (maps to RFC 793 TCB variables):**

| Linux Field | RFC 793 | Type | Description |
|------------|---------|------|-------------|
| `rcv_nxt` | RCV.NXT | `u32` | Next expected receive sequence number |
| `snd_nxt` | SND.NXT | `u32` | Next sequence number to send |
| `snd_una` | SND.UNA | `u32` | First unacknowledged byte |
| `rcv_wnd` | RCV.WND | `u32` | Current receive window |
| `snd_wnd` | SND.WND | `u32` | Peer's advertised window |
| `snd_wl1` | SND.WL1 | `u32` | Sequence for window update |
| `copied_seq` | — | `u32` | Head of unread data (user hasn't read yet) |
| `write_seq` | — | `u32` | Tail(+1) of data in TCP send buffer |
| `snd_sml` | — | `u32` | Last byte in most recently transmitted small packet |

**Other forensically useful TCP fields:**

| Field | Description |
|-------|-------------|
| `srtt_us` | Smoothed round-trip time (microseconds) |
| `mdev_us` | Mean deviation of RTT |
| `snd_cwnd` | Congestion window size |
| `snd_ssthresh` | Slow-start threshold |
| `rcv_tstamp` | Timestamp of last received ACK |
| `lsndtime` | Last time data was sent |
| `mss_cache` | Cached effective MSS |

### 2.5 How Forensic Tools Recover Network Connections

**Method 1: Walk the task list and follow file descriptors**

```
task_struct -> files_struct -> fdtable -> fd[] -> struct file
  -> f_private_data (for sockets, this is struct socket)
    -> socket->sk (struct sock / tcp_sock)
      -> Extract: skc_daddr, skc_rcv_saddr, skc_dport, skc_num, skc_state
```

**Method 2: Walk kernel hash tables directly**

The kernel maintains hash tables for TCP connections:
- `tcp_hashinfo.ehash` — established connections
- `tcp_hashinfo.bhash` — bound ports
- `tcp_hashinfo.listening_hash` — listening sockets

Volatility's `linux.sockstat` plugin traverses these structures. The plugin uses
network namespace awareness (via `task->nsproxy->net_ns`) to correctly attribute
connections to network namespaces.

**Method 3: Reconstruct `/proc/net/tcp`**

The kernel computes queue sizes as:
- TX queue: `tp->write_seq - tp->snd_una`
- RX queue: `max(tp->rcv_nxt - tp->copied_seq, 0)`

### 2.6 `struct sk_buff` — Packet Buffers

Packets in flight are represented by `sk_buff`. Forensically interesting because
buffered data (not yet read by application or not yet sent) can be recovered:

- `sk->sk_receive_queue` — received packets not yet read
- `sk->sk_write_queue` — data queued for transmission
- Protocol headers are accessible via `transport_header`, `network_header`, `mac_header` offsets

---

## 3. Kernel Module List

### 3.1 `struct module`

Every loaded kernel module is described by a `struct module` (defined in
`include/linux/module.h`). When a module is loaded, memory is allocated for this
structure and it is linked into the kernel's module list.

**Key fields:**

| Field | Type | Description |
|-------|------|-------------|
| `state` | `enum module_state` | MODULE_STATE_LIVE, MODULE_STATE_COMING, MODULE_STATE_GOING |
| `list` | `struct list_head` | Links into the global module list |
| `name` | `char[MODULE_NAME_LEN]` | Module name (typically 56 bytes max) |
| `mkobj` | `struct module_kobject` | Contains embedded `kobject` for sysfs |
| `init` | `int (*)(void)` | Initialization function pointer |
| `core_layout` / `mem[]` | `struct module_layout` / `struct module_memory` | Memory region info (base address, size) |
| `syms` | `const struct kernel_symbol *` | Exported symbols |
| `num_syms` | `unsigned int` | Number of exported symbols |
| `srcversion` | `char[]` | Source version string |
| `taints` | `unsigned long` | Taint flags (out-of-tree, proprietary, etc.) |

### 3.2 Walking the Module List

All modules are linked in a circular doubly-linked list. The list head is the kernel
symbol `modules` (a `struct list_head`).

**Forensic traversal:**

```
modules (list_head)
  -> module_A.list -> module_B.list -> ... -> modules
```

Use `list_entry()` to convert from `list_head` to the containing `struct module`.
This is equivalent to what `lsmod` displays.

### 3.3 How Rootkits Hide Modules

Since the first publication about Linux kernel rootkits in Phrack (April 1997), the
standard hiding technique is **unlinking from the module list**:

```c
// Typical rootkit hideme() function:
static struct list_head *prev_module;

void hideme(void) {
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);  // Remove from module list
}

void showme(void) {
    list_add(&THIS_MODULE->list, prev_module);  // Re-link
}
```

After `list_del()`, since kernel 2.5.71, Linux "poisons" the stale list pointers by
setting them to `LIST_POISON1` (0x00100100) and `LIST_POISON2` (0x00200200). This
is itself a forensic indicator.

**More advanced hiding:**
- Remove from `module_kset` (sysfs) as well
- Zero out or overwrite the `name` field
- Remove from the module memory tree (added in kernel 4.2)
- Filter `/proc/modules`, `/proc/kallsyms`, `/proc/kcore`, and `/proc/vmallocinfo`
  (as done by the Singularity rootkit)

### 3.4 Cross-View Detection of Hidden Modules

The forensic countermeasure is to enumerate modules from multiple independent kernel
data sources and compare them:

| Source | Data Structure | What It Reveals |
|--------|---------------|-----------------|
| **Module list** | `modules` linked list | Standard enumeration (what `lsmod` shows) |
| **module_kset / sysfs** | `module_kset->list` kobject chain | Modules registered in sysfs (`/sys/module/`) |
| **Module memory tree** | Red-black tree of `module_layout` / `module_memory` (kernel 4.2+) | Memory regions allocated for modules |
| **Kallsyms** | Kernel symbol table | Symbols tagged with module names |
| **Memory scanning** | Sequential scan of kernel memory | Look for `struct module` signatures in memory |

**Volatility plugins:**
- `linux.lsmod` — Walk the standard module list
- `linux.hidden_modules` — Detect modules hidden from the module list
- `linux.check_modules` — Compare modules visible in different kernel structures
- `linux.modxview` — Centralized cross-view comparison

A module that appears in the memory tree or sysfs but NOT in the module list is a
strong indicator of a hidden rootkit module.

**DFRWS 2025 research** (Roland Nagy et al.) extended cross-view detection and
tested it on 55 rootkit-infected memory dumps covering 27 kernel versions. Their
Volatility plugin implements all known enumeration sources.

---

## 4. File Descriptors

### 4.1 `files_struct` — Per-Process File Descriptor Table

Each process has a `files_struct` (pointed to by `task_struct->files`) that manages
its open file descriptors.

**Key fields:**

| Field | Type | Description |
|-------|------|-------------|
| `count` | `atomic_t` | Reference count (shared among CLONE_FILES threads) |
| `fdt` | `struct fdtable *` | Pointer to the current file descriptor table |
| `fdtab` | `struct fdtable` | Embedded initial fdtable (used before expansion) |

### 4.2 `struct fdtable`

The actual file descriptor table, kept separate for atomic RCU-based updates:

| Field | Type | Description |
|-------|------|-------------|
| `max_fds` | `unsigned int` | Current capacity of the fd array |
| `fd` | `struct file __rcu **` | Array of pointers to `struct file` (indexed by fd number) |
| `close_on_exec` | `unsigned long *` | Bitmap of close-on-exec flags |
| `open_fds` | `unsigned long *` | Bitmap of allocated file descriptors |
| `full_fds_bits` | `unsigned long *` | Bitmap indicating fully allocated words |

**Design note:** Initially, the fdtable is embedded within `files_struct` itself
(`fdtab` field). When the process opens more files than the initial capacity, a new
`fdtable` is allocated and `files->fdt` is updated via `rcu_assign_pointer()`. The
old fdtable is freed after an RCU grace period.

### 4.3 `struct file` — Open File Description

Each open file descriptor points to a `struct file`:

| Field | Type | Description |
|-------|------|-------------|
| `f_path` | `struct path` | Contains `dentry` and `vfsmount` |
| `f_inode` | `struct inode *` | Cached inode pointer |
| `f_op` | `const struct file_operations *` | File operation function pointers |
| `f_mode` | `fmode_t` | File access mode (FMODE_READ, FMODE_WRITE) |
| `f_flags` | `unsigned int` | Open flags (O_RDONLY, O_NONBLOCK, etc.) |
| `f_pos` | `loff_t` | Current file position (seek offset) |
| `f_count` | `atomic_long_t` | Reference count |
| `private_data` | `void *` | Protocol-specific data (e.g., socket struct for AF_INET) |

### 4.4 Forensic File Descriptor Recovery

The traversal chain from process to open file paths:

```
task_struct
  -> files (struct files_struct *)
    -> fdt (struct fdtable *)
      -> fd[i] (struct file *)
        -> f_path.dentry (struct dentry *)
          -> d_name (struct qstr) — filename component
          -> d_parent — parent directory dentry
            -> d_name — parent directory name
              -> ... (walk up to root)
        -> f_path.mnt (struct vfsmount *) — mount point
        -> f_inode (struct inode *)
          -> i_ino — inode number
          -> i_mode — file type and permissions
          -> i_size — file size
          -> i_atime, i_mtime, i_ctime — timestamps
```

**Path reconstruction:** The full path is built by walking the dentry chain from the
file's dentry up through `d_parent` pointers to the root, then prepending the mount
point path. This is what the kernel's `d_path()` function does.

**Deleted file recovery:** Files that have been deleted from disk but are still open
(or cached in the page cache) remain recoverable from memory. The dentry will have
`d_flags` indicating deletion, but the inode and cached pages persist. The mquire tool
(2026) can extract such files via its `.dump` command.

### 4.5 Lock-Free Access (RCU)

Modern kernels (2.6.12+) use RCU (Read-Copy-Update) for lock-free file descriptor
access. The `lookup_fdget_rcu()` and `files_lookup_fdget_rcu()` APIs look up file
structures without taking a lock. On newer kernels, RCU-based lookup uses
`SLAB_TYPESAFE_BY_RCU` for the file slab cache, requiring pointer validation before
and after incrementing the reference count.

For forensics, this means the fdtable can be read consistently from a memory snapshot
without concern about locks (the snapshot is a point-in-time freeze).

---

## 5. Mount/Filesystem Structures

### 5.1 VFS Core Data Structures

The Linux Virtual Filesystem (VFS) provides a unified abstraction layer. Four core
structures describe the filesystem state:

**`struct super_block`** — Per-filesystem instance:

| Field | Type | Description |
|-------|------|-------------|
| `s_type` | `struct file_system_type *` | Filesystem type (ext4, xfs, tmpfs, etc.) |
| `s_dev` | `dev_t` | Device identifier |
| `s_bdev` | `struct block_device *` | Underlying block device |
| `s_root` | `struct dentry *` | Root dentry of this filesystem |
| `s_dirty` | `struct list_head` | List of dirty inodes |
| `s_files` | `struct list_head` | List of all open files on this superblock |
| `s_mounts` | `struct list_head` | List of mount instances |
| `s_inodes` | `struct list_head` | All inodes for this filesystem |

**`struct vfsmount` / `struct mount`** — Mount instance:

| Field | Type | Description |
|-------|------|-------------|
| `mnt_root` | `struct dentry *` | Root dentry of the mounted filesystem |
| `mnt_sb` | `struct super_block *` | Superblock of the mounted filesystem |
| `mnt_parent` | `struct mount *` | Parent mount |
| `mnt_mountpoint` | `struct dentry *` | Dentry of the mount point in the parent |
| `mnt_list` | `struct list_head` | System-wide mount list |
| `mnt_instances` | `struct list_head` | Per-superblock mount list |
| `mnt_devname` | `const char *` | Device name (e.g., "/dev/sda1") |

**`struct dentry`** — Directory entry cache:

| Field | Type | Description |
|-------|------|-------------|
| `d_name` | `struct qstr` | Name of this directory entry |
| `d_inode` | `struct inode *` | Associated inode |
| `d_parent` | `struct dentry *` | Parent directory's dentry |
| `d_subdirs` | `struct list_head` | Child dentries |
| `d_sb` | `struct super_block *` | Superblock |
| `d_op` | `const struct dentry_operations *` | Dentry operations |
| `d_flags` | `unsigned int` | Dentry flags (DCACHE_DISCONNECTED, etc.) |

**`struct inode`** — In-core filesystem object:

| Field | Type | Description |
|-------|------|-------------|
| `i_ino` | `unsigned long` | Inode number |
| `i_mode` | `umode_t` | File type + permissions |
| `i_uid` / `i_gid` | `kuid_t` / `kgid_t` | Owner/group |
| `i_size` | `loff_t` | File size |
| `i_atime` | `struct timespec64` | Last access time |
| `i_mtime` | `struct timespec64` | Last modification time |
| `i_ctime` | `struct timespec64` | Last status change time |
| `i_sb` | `struct super_block *` | Superblock |
| `i_mapping` | `struct address_space *` | Page cache for this inode |
| `i_op` | `const struct inode_operations *` | Inode operations |
| `i_fop` | `const struct file_operations *` | Default file operations |

### 5.2 Enumerating Mounted Filesystems

**Method 1:** Walk the global mount list (rooted at the init process's mount namespace).

```
init_task -> nsproxy -> mnt_ns -> root (struct mount)
  -> mnt_list traversal gives all mounts in the namespace
```

**Method 2:** Walk per-superblock mount lists via `super_block->s_mounts`.

**Method 3:** Walk the `file_system_type` list (each registered filesystem type has
an `fs_supers` list linking all its superblocks).

### 5.3 Recovering Recent File Access

The **dentry cache (dcache)** is a kernel-memory cache of filename-to-inode mappings.
It persists in memory even after files are closed, providing a window into recent
filesystem activity. Walking the dcache hash table or inode hash table reveals recently
accessed files.

The **inode lists** on each superblock (`s_dirty`, `s_io`) reveal files with pending
writes, indicating very recent activity.

The **page cache** (accessed via `inode->i_mapping`) contains cached file data pages.
Even after a file is closed, its pages may remain in the page cache until memory
pressure causes eviction.

---

## 6. Symbol Resolution

### 6.1 The Symbol Problem

Memory forensics tools must know the exact layout (field names, offsets, sizes) of
kernel data structures to parse a memory dump. This information varies by:
- Kernel version (2.6, 4.x, 5.x, 6.x — structures evolve)
- Architecture (x86, x86_64, ARM64 — different sizes, alignment)
- Kernel configuration (CONFIG options change struct layouts)
- Compiler version and optimization level

### 6.2 Volatility 2: Profiles

A Volatility 2 Linux profile consists of:

1. **System.map** — A text file mapping kernel symbol names to virtual addresses.
   Found at `/boot/System.map-<version>` on the target system.
2. **DWARF debug info** — Contains complete type information (struct layouts, field
   offsets, sizes, types). Extracted from a kernel compiled with `CONFIG_DEBUG_INFO`
   or from the `linux-image-*-dbg` / `kernel-debuginfo` package.

These are combined with `dwarfdump` into a profile ZIP file. Volatility matches profiles
to memory dumps using the **kernel banner string** (e.g.,
`Linux version 5.10.0-20-amd64 (gcc-10 (Debian 10.2.1-6) ...)`).

### 6.3 Volatility 3: ISF (Intermediate Symbol Format)

Volatility 3 uses JSON-based ISF files generated by:

- **dwarf2json** — Converts DWARF debug info + System.map into ISF JSON
- **btf2json** — Converts BTF + System.map into ISF JSON (no debug kernel needed!)

The ISF file contains:
- All kernel type definitions (structs, unions, enums, typedefs)
- All kernel symbol addresses
- An identifying banner string

**Banner matching:** Volatility 3 automagic compares the banner found in the memory
dump with banners in available ISF files. The banner must match exactly (including
compiler version and build timestamp).

### 6.4 BTF — The Modern Alternative to DWARF

BPF Type Format (BTF) is a compact type description format designed for eBPF. Key
advantages for forensics:

- **Embedded in production kernels** — Most major distros ship kernels with
  `CONFIG_DEBUG_INFO_BTF=y` since kernel 4.18+
- **Much smaller than DWARF** — Typically a few MB vs. hundreds of MB
- **Contains complete struct layouts** — Field names, offsets, sizes, type relationships
- **No debug package needed** — Available on the running system itself

**btf2json** can generate Volatility 3 profiles from BTF, enabling forensics on:
- Custom-compiled kernels without debug symbols
- Distributions that don't provide kernel debug packages (e.g., Arch Linux)
- Any kernel with `CONFIG_DEBUG_INFO_BTF` enabled

### 6.5 KASLR (Kernel Address Space Layout Randomization)

KASLR randomizes kernel virtual (and physical) addresses at boot, breaking the static
addresses in System.map.

**Pre-4.8 KASLR:**
- Only virtual address randomization
- A single random offset `r` is added to all kernel virtual addresses
- Volatility uses **kernel identity paging** to determine `r`: for kernel code/data,
  `physical_address + known_offset = virtual_address`. By checking if the identity
  mapping holds with various offsets, Volatility brute-forces `r`.

**Post-4.8 KASLR:**
- Both physical and virtual randomization
- Two independent random values: physical shift `p` and virtual shift `v`
- Volatility must determine both shifts
- The approach involves scanning page tables for the kernel DTB (`swapper_pg_dir`),
  then verifying identity mappings at candidate offsets

**Volatility 3 automagic implementation:**
1. Scan for the Linux banner string in physical memory
2. Use the banner to select the correct ISF file
3. Call `find_aslr()` which determines `kaslr_shift` and `aslr_shift`
4. Compute DTB: `virtual_to_physical_address(swapper_pg_dir + kaslr_shift)`
5. Build the Intel address translation layer with the discovered DTB

### 6.6 Kallsyms — In-Memory Symbol Table

`/proc/kallsyms` exposes the kernel's internal symbol table. This same data exists in
the memory dump and can be extracted:

- **mquire (2026)** scans for kallsyms data structures in the dump
- The kallsyms data is stored in a compressed format in kernel memory
  (`kallsyms_names`, `kallsyms_offsets`, `kallsyms_num_syms`, `kallsyms_token_table`,
  `kallsyms_token_index`)
- Extraction provides symbol addresses adjusted for the actual KASLR shift

**Requirements:** mquire's kallsyms scanner requires kernel 6.4+ due to format changes
in `scripts/kallsyms.c`.

### 6.7 mquire — Zero-Dependency Linux Forensics (2026)

Trail of Bits' mquire combines BTF + Kallsyms to perform Linux memory forensics
without any external dependencies:

1. Scans the memory dump for embedded BTF data (type information)
2. Scans for embedded Kallsyms data (symbol addresses)
3. Combines both to locate and parse kernel data structures
4. Provides an SQL interface (osquery-inspired) for interactive analysis

**Supported tables:** `tasks`, `task_open_files`, `memory_mappings`, `kernel_modules`,
`network_connections`, `network_interfaces`, `syslog_file`

**Requirements:** BTF support requires kernel 4.18+ with BTF enabled. Kallsyms support
requires kernel 6.4+. Written in Rust, Apache 2.0 licensed.

---

## 7. Rootkit Detection

### 7.1 Rootkit Taxonomy and Evolution

Linux rootkits have evolved through several generations:

| Era | Technique | Characteristics |
|-----|-----------|-----------------|
| **1997-2000s** | Userland binary replacement | Replace `ps`, `ls`, `netstat` binaries |
| **2000s** | Loadable Kernel Module (LKM) | Hook syscall table, DKOM |
| **2010s** | `LD_PRELOAD` / library injection | Intercept libc functions in user space |
| **Late 2010s** | eBPF-based | Kernel-space hooks via BPF programs; bypass LKM scanners |
| **2025+** | io_uring-based (emerging) | Batch syscall-like operations; evade syscall-based EDRs |

### 7.2 Syscall Table Hooking

The `sys_call_table` is an array of function pointers, one per system call number.
Rootkits like **Diamorphine** modify entries to point to malicious handlers:

**Diamorphine's hooks:**
- **`sys_getdents` / `sys_getdents64`** (syscalls 78, 217): Filters directory entries
  to hide files and `/proc/<pid>` entries of hidden processes
- **`sys_kill`** (syscall 62): Intercepts `kill -63 <pid>` as a control signal to
  toggle process visibility or module visibility

**Detection by Volatility (`linux_check_syscall`):**
1. Read each entry in `sys_call_table[]`
2. Compare each function pointer against the expected address from the kernel symbol table
3. If the pointer falls outside the kernel's core text region, it's hooked
4. Report the hooked syscall number and the address it points to

**Kernel 6.9 mitigation:** The x86-64 syscall dispatch mechanism was fundamentally
changed, rendering traditional syscall table patching obsolete for newer kernels.

### 7.3 Inline Function Hooking

Instead of modifying syscall table pointers, the rootkit patches the target function's
machine code directly:

```
// Overwrite first 5 bytes of target function with JMP to hook:
unsigned char jmp[5] = {0xE9, offset_bytes...};
memcpy(target_function_address, jmp, 5);
```

The rootkit must handle:
- Disabling write protection on kernel text (`CR0.WP` bit, or using `set_memory_rw()`)
- Saving original bytes for the trampoline (to call the original function)
- Architecture-specific encoding (relative jumps on x86, different on ARM64)

**Detection:** Compare in-memory function prologues against known-good copies
(from the vmlinux with debug symbols or from a clean reference).

### 7.4 ftrace-Based Hooking

ftrace is a legitimate kernel tracing framework. Rootkits abuse it because:
- It provides a clean API for function interception
- Hooks installed via ftrace look like normal tracing activity
- No need to patch kernel text directly (ftrace manages the patching)

Examples: **PUMAKIT** uses ftrace hooks alongside direct syscall table hooks.

**Detection:** Enumerate active `ftrace_ops` structures and check if the callback
functions reside in known modules or kernel text.

### 7.5 kprobe-Based Hooking

Kprobes allow setting "breakpoints" on any kernel instruction. Modern rootkits use
them to:
- Steal unexported symbol addresses (e.g., register a kprobe on `kallsyms_lookup_name`
  and read the address when the probe fires)
- Hook functions by attaching pre/post handlers that modify behavior

**Diamorphine** uses a kprobe to resolve `kallsyms_lookup_name` since it was
de-exported in kernel 5.7.

### 7.6 eBPF-Based Rootkits

eBPF programs run in kernel space but are NOT loaded as kernel modules:
- Do not appear in `/proc/modules` or `lsmod`
- Can attach to tracepoints, kprobes, LSM hooks, XDP, cgroup hooks
- Bypass traditional LKM scanners, Secure Boot, `rkhunter`, `chkrootkit`
- Require `CAP_BPF` or `CAP_SYS_ADMIN`

Examples:
- **Triple Cross (2022)** — hooks `execve` via eBPF
- **Boopkit (2022)** — covert C2 channel entirely via eBPF

### 7.7 io_uring Rootkits (Emerging, 2025+)

io_uring allows batching file, network, and process operations via shared memory rings:
- Operations happen in kernel context via SQPOLL kernel workers
- Produces far fewer observable syscall events
- Evades syscall-based EDR/monitoring
- **RingReaper (2025)** — replaces `read`, `write`, `connect`, `unlink` via io_uring

### 7.8 Direct Kernel Object Manipulation (DKOM)

Beyond syscall hooking, rootkits manipulate kernel data structures directly:

- **Process hiding:** Unlink `task_struct` from the `tasks` list (but leave in PID
  namespace structures, or vice versa)
- **Module hiding:** Unlink `struct module` from the `modules` list
- **Network hiding:** Filter socket structures from enumeration paths
- **File hiding:** Manipulate VFS structures or hook `iterate_dir` (the modern
  replacement for `getdents`)

**Detection via cross-view analysis:**
- Enumerate processes via task list AND PID namespace AND /proc AND cgroup lists
- Any process visible in one source but not another indicates manipulation
- mquire (2026) explicitly supports multiple task enumeration strategies for this purpose

### 7.9 VFS Operation Table Hooking

Instead of hooking syscalls, rootkits can replace function pointers in VFS operation
tables:
- `struct file_operations` — `iterate_shared` (directory listing), `read`, `write`
- `struct inode_operations` — `lookup`, `create`, `unlink`
- These are per-filesystem, making detection harder (need to check every mounted
  filesystem's operation tables)

### 7.10 Memory Forensics Detection Summary

| Technique | Detection Method |
|-----------|-----------------|
| Syscall table hook | Compare `sys_call_table[]` entries against symbol table |
| Inline function hook | Compare function prologues against known-good vmlinux |
| ftrace hook | Enumerate `ftrace_ops` list, check callback addresses |
| kprobe hook | Enumerate registered kprobes |
| eBPF hook | Enumerate loaded BPF programs and their attachment points |
| Hidden process (DKOM) | Cross-view: task list vs. PID hash vs. scheduler runqueue |
| Hidden module (DKOM) | Cross-view: module list vs. sysfs vs. memory tree vs. kallsyms |
| VFS op hook | Compare VFS operation pointers against expected values |
| io_uring | Monitor io_uring SQ/CQ ring contents and SQPOLL workers |

---

## 8. Cryptographic Key Recovery

### 8.1 AES Key Schedule Detection

AES key schedules have a distinctive mathematical structure that makes them detectable
in memory dumps without knowing where keys are stored.

**How AES key schedules work:**
- AES-128: 10 rounds, each requiring a 16-byte round key. The full key schedule is
  176 bytes (11 round keys x 16 bytes).
- AES-256: 14 rounds, key schedule is 240 bytes (15 round keys x 16 bytes).
- Each round key is derived from the previous one via XOR, SubBytes (S-box), and
  rotation operations.
- The **inter-round-key relationships** are deterministic: given any round key, you
  can verify whether the adjacent bytes follow the AES key schedule pattern.

**Detection algorithm (aeskeyfind):**
1. Scan memory byte-by-byte
2. At each position, check if the next 176 bytes (AES-128) or 240 bytes (AES-256)
   satisfy the AES key schedule recurrence relations
3. If relations hold for two consecutive rounds, there is very high probability that
   a valid AES key schedule exists at that location
4. Extract the first round key (which IS the original AES key)

**Tools:**
- **aeskeyfind** — Locates AES-128 and AES-256 keys in memory dumps. Part of Kali Linux.
- **AESFix** — Recovers AES keys from corrupted/partially overwritten memory images.
  Handles "decayed" memory (cold boot attack scenario).

**Cold boot attack research (Halderman et al.):**
The improved recovery algorithm can reliably recover AES-128 key schedules at 70% memory
decay, more than twice the decay capacity of previous methods. Performance is tens of
millions of times faster than the original proof-of-concept.

**Practical application — Ransomware forensics:**
Memory captures from ransomware-infected systems have been used to extract AES keys.
NotPetya, Bad Rabbit, and Phobos hybrid ransomware samples were successfully targeted
during investigations by extracting symmetric encryption keys from RAM.

### 8.2 SSH Private Key Extraction

SSH keys in memory take several forms depending on the SSH implementation and version:

**Pre-2019 OpenSSH (before "Shielded Private Keys"):**
- ssh-agent stored unencrypted RSA/EC private keys in the heap
- Tools like **sshkey-grab** (NetSPI) could dump ssh-agent's stack/heap and parse
  the key structures directly
- RSA keys were detectable by their ASN.1 DER encoding signature

**Post-2019 OpenSSH (Shielded Private Keys, OpenSSH 8.0+):**
Introduced to defend against Spectre/Meltdown side-channel attacks:
- When `ssh-add` loads a key, ssh-agent encrypts ("shields") it with a symmetric key
  derived from a random 16KB `pre_key`
- The key is stored as `shielded_private` (encrypted) + `shield_prekey` (16384 bytes)
- Both are referenced from the `sshkey` struct in the heap
- `shield_prekey_len` is always `0x4000` (16KB), useful as a search signature

**Extraction procedure (HN Security technique):**
1. Find the key comment string in the ssh-agent heap
2. Search for cross-references (pointers) to that comment address
3. This reveals the `sshkey` struct location
4. Extract `shielded_private` and `shield_prekey` from the struct
5. Use `sshkey_unshield_private()` + `sshkey_save_private()` from OpenSSH source
   to decrypt ("unshield") the key

This technique works **even if ssh-agent is locked** (`ssh-add -x`).

**Machine learning approaches:**
The SmartVMI project trains ML models to detect SSH key patterns in OpenSSH heap dumps,
using entropy and structural analysis to identify key material.

**General tool: CryKeX**
Linux memory cryptographic keys extractor that dumps live process memory and uses
entropy analysis + C data type structure matching to identify probable cryptographic
keys.

### 8.3 TLS Session Key Extraction

TLS key material in memory enables decryption of captured network traffic.

**Key types and lifetimes:**
- **Pre-Master Secret (PMS)**: Short-lived, exists only during the TLS handshake
- **Master Secret**: Derived from PMS, persists for the session duration (up to 24h
  per RFC 5246 for session resumption)
- **Session Keys**: Derived from master secret, used for actual encryption/decryption
  of application data, persist for the connection lifetime
- **TLS 1.3**: Uses handshake traffic secrets and application traffic secrets instead
  of a single master secret

**Extraction methods:**

| Method | Approach | Requirements |
|--------|----------|-------------|
| **SSLKEYLOGFILE** | OpenSSL/NSS write key material to a file | Must be enabled before TLS handshake |
| **TLSkex** | Virtual machine introspection | Hypervisor access to guest memory |
| **X-Ray-TLS** | eBPF + dirty page tracking (Linux 3.9+) | Root access on live system |
| **TLSKeyHunter (2025)** | Memory forensics, brute-force search | Memory dump |
| **DroidKex** | Data structure semantics reconstruction | Android app memory |
| **Volatility plugin (Kambic)** | Parse LSASS/Schannel artifacts | Windows memory dump |

**X-Ray-TLS technique:**
1. Monitor TLS connections via eBPF
2. Take memory snapshots between ClientHello and first ApplicationData
3. Track dirty pages between snapshots
4. Search dirty page differences for key-like material
5. Brute-force verify against known handshake transcript

**Key survival in memory:**
TLS session keys remain in memory for the duration of the connection. Master secrets
may persist longer if session resumption is enabled. Even after the connection closes,
freed memory may not be immediately overwritten, leaving key material recoverable.

### 8.4 GPG/PGP Key Recovery

Volatility plugins have been developed for GPG key extraction from memory dumps:
- Kudelski Security developed two Volatility3 plugins
- Similar to AES detection, GPG keys can be found via their mathematical structure
- RSA private key components (p, q, d) may exist in decrypted form in gpg-agent memory

### 8.5 Full-Disk Encryption Key Recovery

Tools like Volatility can recover BitLocker volume encryption keys from Windows
memory dumps. On Linux, LUKS/dm-crypt master keys reside in kernel memory:
- The dm-crypt module holds the decrypted volume key in kernel space
- It can be extracted from a memory dump if the kernel structures are parsed correctly
- **Aeskeyfind** can also locate these keys via their AES key schedule signature

---

## References and Sources

### Process Structures
- [Process Address Space — kernel.org](https://www.kernel.org/doc/gorman/html/understand/understand021.html)
- [Processes Lecture — Linux Kernel Labs](https://linux-kernel-labs.github.io/refs/heads/master/lectures/processes.html)
- [task_struct Definition — FSU](https://www.cs.fsu.edu/~baker/opsys/examples/task_struct.html)
- [task_struct — torvalds/linux on GitHub](https://github.com/torvalds/linux/blob/master/include/linux/sched.h)
- [Linux Kernel Threads and Processes Management — cylab.be](https://cylab.be/blog/347/linux-kernel-threads-and-processes-management-task-struct)
- [Process Addresses — kernel.org](https://docs.kernel.org/mm/process_addrs.html)
- [Linternals: Exploring the MM Subsystem Part 1](https://sam4k.com/linternals-exploring-the-mm-subsystem-part-1/)
- [How the Kernel Manages Your Memory](https://manybutfinite.com/post/how-the-kernel-manages-your-memory/)

### Network Structures
- [Networking Lab — Linux Kernel Labs](https://linux-kernel-labs.github.io/refs/heads/master/labs/networking.html)
- [sock.h — torvalds/linux](https://github.com/torvalds/linux/blob/master/include/net/sock.h)
- [tcp_sock Struct Reference](https://docs.huihoo.com/doxygen/linux/kernel/3.7/structtcp__sock.html)
- [tcp_sock fast path cacheline layout — kernel.org](https://docs.kernel.org/networking/net_cachelines/tcp_sock.html)
- [inet_sock.h — torvalds/linux](https://github.com/torvalds/linux/blob/master/include/net/inet_sock.h)
- [TCP Handling in Linux](https://medium.com/@dipakkrdas/tcp-handling-in-linux-cc864f35818b)
- [Inspecting Internal TCP State on Linux — Jane Street](https://blog.janestreet.com/inspecting-internal-tcp-state-on-linux/)

### Kernel Module List / Hidden Modules
- [Detecting Hidden Kernel Modules in Memory Snapshots — ScienceDirect (2025)](https://www.sciencedirect.com/science/article/pii/S2666281725000678)
- [Finding Hidden Kernel Modules (Extreme Way Reborn) — Phrack Issue 71](https://phrack.org/issues/71/12)
- [Linux Rootkits Part 5: Hiding Kernel Modules — TheXcellerator](https://xcellerator.github.io/posts/linux_rootkits_05/)
- [Volatility Labs: KBeast Rootkit, Detecting Hidden Modules](https://volatility-labs.blogspot.com/2012/09/movp-15-kbeast-rootkit-detecting-hidden.html)
- [Singularity Rootkit — GitHub](https://github.com/MatheuZSecurity/Singularity)

### File Descriptors
- [File Management in the Linux Kernel — kernel.org](https://docs.kernel.org/filesystems/files.html)
- [File Descriptor Table Notes — Shuo Chen](https://www.chenshuo.com/notes/kernel/file-descriptor-table/)
- [fdtable Struct Reference (Linux 3.7)](https://docs.huihoo.com/doxygen/linux/kernel/3.7/structfdtable.html)
- [mquire — Trail of Bits Blog](https://blog.trailofbits.com/2026/02/25/mquire-linux-memory-forensics-without-external-dependencies/)

### Mount/Filesystem Structures
- [Overview of the Linux Virtual File System — kernel.org](https://www.kernel.org/doc/html/v5.7/filesystems/vfs.html)
- [Linux Kernel 2.4 Internals: VFS](https://tldp.org/LDP/lki/lki-3.html)
- [File System Drivers Part 1 — Linux Kernel Labs](https://linux-kernel-labs.github.io/refs/heads/master/labs/filesystems_part1.html)
- [Introduction to Linux VFS — Star Lab](https://www.starlab.io/blog/introduction-to-the-linux-virtual-filesystem-vfs-part-i-a-high-level-tour)

### Symbol Resolution / KASLR
- [KASLR in Linux / Volatility Brute-Force Page Tables](https://bneuburg.github.io/volatility/kaslr/2017/04/26/KASLR1.html)
- [KASLR Part 2: Finding the Needle](https://bneuburg.github.io/volatility/kaslr/2017/05/05/KASLR2.html)
- [Creating Linux Symbol Tables for Volatility — HackTheBox](https://www.hackthebox.com/blog/how-to-create-linux-symbol-tables-volatility)
- [BTF Information in Linux Memory Forensics — btf2json](https://lolcads.github.io/posts/2024/11/btf2json/)
- [Creating New Symbol Tables — Volatility 3 Docs](https://volatility3.readthedocs.io/en/latest/symbol-tables.html)
- [dwarf2json — Volatility Foundation](https://github.com/volatilityfoundation/dwarf2json)
- [mquire — GitHub](https://github.com/trailofbits/mquire)

### Rootkit Detection
- [Hooked on Linux: Rootkit Taxonomy — Elastic Security Labs (2026)](https://www.elastic.co/security-labs/linux-rootkits-1-hooked-on-linux)
- [FlipSwitch: Novel Syscall Hooking — Elastic Security Labs](https://www.elastic.co/security-labs/flipswitch-linux-rootkit)
- [Hunting Rootkits with eBPF — Aqua Security](https://www.aquasec.com/blog/linux-syscall-hooking-using-tracee/)
- [New Diamorphine Variant in the Wild — Gen Digital](https://www.gendigital.com/blog/insights/research/new-diamorphine-rootkit-variant-seen-undetected-in-the-wild)
- [Diamorphine Rootkit — GitHub](https://github.com/m0nad/Diamorphine)
- [RingReaper (io_uring rootkit) — GitHub](https://github.com/MatheuZSecurity/RingReaper)
- [Hidden Threat: Linux Rootkit Limitations — ACM](https://dl.acm.org/doi/10.1145/3688808)
- [Kernel-level Rootkit Detection Survey — arXiv](https://arxiv.org/pdf/2304.00473)

### Cryptographic Key Recovery
- [AESKeyFind — Kali Linux Tools](https://www.kali.org/tools/aeskeyfind/)
- [Improved Recovery Algorithm for Decayed AES Key Schedules — Springer](https://link.springer.com/chapter/10.1007/978-3-642-05445-7_14)
- [The Persistence of Memory: Forensic Identification and Extraction of Cryptographic Keys — ScienceDirect](https://www.sciencedirect.com/science/article/pii/S1742287609000486)
- [GPG Memory Forensics — Kudelski Security](https://research.kudelskisecurity.com/2022/06/16/gpg-memory-forensics/)
- [OpenSSH ssh-agent Shielded Key Extraction — HN Security](https://security.humanativaspa.it/openssh-ssh-agent-shielded-private-key-extraction-x86_64-linux/)
- [sshkey-grab — NetSPI GitHub](https://github.com/NetSPI/sshkey-grab)
- [Predicting SSH Keys in OpenSSH Memory Dumps — arXiv](https://arxiv.org/html/2404.16838v1)
- [CryKeX — GitHub](https://github.com/cryptolok/CryKeX)
- [TLS Key Material Identification and Extraction — ScienceDirect (2024)](https://www.sciencedirect.com/science/article/pii/S2666281724000854)
- [All Your TLS Keys Are Belong to Us — DFRWS (2025)](https://dfrws.org/presentation/all-your-tls-keys-are-belong-to-us-a-novel-approach-to-live-memory-forensic-key-extraction/)
- [DroidKex — ScienceDirect](https://www.sciencedirect.com/science/article/pii/S1742287618301890)
- [Tales from the Crypt(o) — Leaking AES Keys](https://parsiya.net/blog/2015-01-06-tales-from-the-crypto-leaking-aes-keys/)
