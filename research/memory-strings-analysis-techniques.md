# Memory String Analysis Techniques for Forensics

> Context: 2.2GB `memory-strings.ascii` file from a compromised Linux CI/CD worker (rootkit + cryptominer + reverse shell)

## 1. String-Based Indicators

### 1.1 Mining Pool / Cryptominer Patterns

**Protocol prefixes (grep -E):**
```
stratum\+tcp://
stratum\+ssl://
stratum\+udp://
daemon\+http://
daemon\+https://
```

**Known mining pool domains:**
```
pool.minexmr.com
monerohash.com
pool.supportxmr.com
xmrpool.eu
pool.hashvault.pro
gulf.moneroocean.stream
mine.xmrpool.net
nanopool.org
2miners.com
f2pool.com
```

**XMRig-specific strings:**
```
xmrig
config.json
"algo": "cryptonight"
"algo": "rx/0"
RandomX
"nicehash"
--nicehash
'h' hashrate, 'p' pause, 'r' resume
* CPU: %s (%d) %sx64 %sAES-NI
-t, --threads=N
-r, --retries=N
-B, --background
pkill -f cryptonight
pkill -f xmrig
pkill -f xmr-stak
```

**Competitor-killing patterns (attackers kill other miners):**
```
pkill -f cryptonight
pkill -f xmrig
pkill -f xmr-stak
pkill -f minerd
kill -9
```

### 1.2 Cryptocurrency Wallet Address Regex

| Currency | Regex Pattern | Length |
|----------|--------------|-------|
| **Monero (XMR)** | `[48][1-9A-HJ-NP-Za-km-z]{94}` | 95 chars |
| **Bitcoin Legacy** | `1[a-km-zA-HJ-NP-Z1-9]{25,34}` | 26-35 chars |
| **Bitcoin P2SH** | `3[a-km-zA-HJ-NP-Z1-9]{25,34}` | 26-35 chars |
| **Bitcoin SegWit** | `bc1[a-zA-HJ-NP-Z0-9]{25,39}` | 28-42 chars |
| **Ethereum** | `0x[0-9a-fA-F]{40}` | 42 chars |

### 1.3 Rootkit String Indicators

**Diamorphine:**
- `diamorphine` (module name)
- Hooks: `sys_call_table`, `kill`, `getdents`, `getdents64`
- Visible in `/sys/module/diamorphine` even when hidden from lsmod
- Used by TeamTNT for cryptomining since Aug 2020
- Not functional since kernel 6.9 (system call table removed)

**Reptile:**
- `reptile`, `reptile_hidden`, `reptile_shell`
- Install directory: `/reptile`
- Uses khook for binary patching of `filldir`
- Associated with Chinese-attributed threat groups

**Other rootkits:**
- `r77`, `$77` (r77 rootkit)
- `Singularity` (modern 6.x kernel rootkit)
- `BPFDoor` (BPF-based, no listening ports)
- `Symbiote` (redefines libpcap, filters /proc/net/tcp)
- `Adore` (hooks tcp4_seq_show)
- `list_del` (kernel function for hiding modules)
- `LD_PRELOAD` (userspace rootkit injection)

**Volatility plugins for rootkit detection:**
- `linux_check_modules` -- finds hidden kernel modules still in memory
- `linux_check_syscall` -- detects sys_call_table modifications
- `linux_check_kernel_inline` -- detects inline hooking (JMP/CALL/RET in prologues)

### 1.4 Reverse Shell Indicators

**Bash:**
```
bash -i >& /dev/tcp/
exec 5<>/dev/tcp/
/dev/tcp/
/dev/udp/
0>&1
2>&1
```

**Python:**
```
pty.spawn
import socket,subprocess,os
os.dup2(s.fileno()
subprocess.call(["/bin/sh","-i"])
__import__('pty').spawn
```

**Perl:**
```
use Socket;
exec("/bin/sh")
IO::Socket::INET
perl -MIO
```

**Netcat:**
```
nc -e /bin/sh
nc -c bash
mkfifo /tmp/f
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f
```

**Other:**
```
socat exec:'bash
openssl s_client -connect
ruby -rsocket
child_process
fsockopen
/inet/tcp/
```

**Obfuscation:**
```
base64 -d | bash
echo ... | base64 -d | sh
eval(base64_decode(
-EncodedCommand
Invoke-Expression
```

### 1.5 C2 Communication

**HTTP beacons:**
- Unusual User-Agent strings (Cobalt Strike, Metasploit, Sliver)
- URI patterns: `/api/`, `/gate.php`, `/panel/`, `/c2/`, `/beacon/`
- `Content-Type: application/octet-stream` with suspicious hosts

**Base64 commands:** `[A-Za-z0-9+/]{20,}={0,2}`

**Common C2 ports:** 4444 (Metasploit), 8443, 8080, 443, 53 (DNS tunnel), 999 (XMRig API)

**Download-and-execute:** `curl .../x.sh | sh & disown`

**Process indicators:**
- `/proc/[pid]/exe` -> `(deleted)` (binary deleted but process running)
- Processes executing from `/tmp`, `/dev/shm`, `/var/tmp`
- Process names masquerading as kernel threads: `[kworker/0:0]`, `[migration/0]`

### 1.6 SSH Keys and Credentials

**SSH:**
```
ssh-rsa, ssh-ed25519, ssh-dss, ecdsa-sha2-nistp256
authorized_keys
id_rsa, id_ed25519
-----BEGIN RSA PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
```

**Credentials:**
```
password=, passwd=, pass=, pwd=
username=, user=, login=
token=, api_key=, secret=, bearer
AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
GITHUB_TOKEN, GITLAB_TOKEN, CI_JOB_TOKEN
DOCKER_AUTH_CONFIG
NPM_TOKEN, PYPI_TOKEN
mysql://, postgres://, mongodb://
Basic <base64>
.kube/config
```

---

## 2. YARA Rules for Memory Artifacts

### 2.1 Key Repositories

| Repository | Focus | URL |
|-----------|-------|-----|
| Neo23x0/signature-base | XMRig, generic miners | https://github.com/Neo23x0/signature-base |
| advanced-threat-research/Yara-Rules | Monero miners | https://github.com/advanced-threat-research/Yara-Rules |
| Yara-Rules/rules | Community rules (anti-debug, malware, packers) | https://github.com/Yara-Rules/rules |
| mikesxrs/Open-Source-YARA-rules | Aggregated (incl. Umbreon rootkit) | https://github.com/mikesxrs/Open-Source-YARA-rules |
| nsacyber/Mitigating-Web-Shells | Web shells, SUNBURST | https://github.com/nsacyber/Mitigating-Web-Shells |
| elastic/protections-artifacts | Elastic endpoint rules | https://github.com/elastic/protections-artifacts |
| InQuest/awesome-yara | Meta-list of rule repositories | https://github.com/InQuest/awesome-yara |
| Xumeiquer/yara-forensics | File magic headers for raw/dump files | https://github.com/Xumeiquer/yara-forensics |

### 2.2 YARA-X (Rust Rewrite)

YARA-X: first stable release June 2025, written in Rust. Original YARA now in maintenance mode.

### 2.3 Example Rule for Memory Scanning

```yara
rule XMRIG_Monero_Miner {
    meta:
        author = "Florian Roth"
        reference = "https://github.com/xmrig/xmrig/releases"
    strings:
        $s1 = "stratum+tcp://"
        $s2 = "stratum+ssl://"
        $s3 = "cryptonight"
        $s4 = "xmrig"
        $s5 = "--nicehash"
        $s6 = "'h' hashrate"
        $wallet = /[48][1-9A-HJ-NP-Za-km-z]{94}/
    condition:
        3 of ($s*) or $wallet
}
```

### 2.4 Google Cloud VMTD

Combines YARA rules + memory hash signatures via CRYPTOMINING_HASH and CRYPTOMINING_YARA modules. Matches binary family hashes like `linux-x86-64_xmrig_6.12.2`.

---

## 3. MemProcFS vs. Volatility

| Aspect | MemProcFS | Volatility |
|--------|-----------|------------|
| **Interface** | Virtual filesystem + GUI | CLI plugins |
| **Model** | Mount memory as filesystem, browse process memory as files | Run plugins, dump output |
| **Speed** | Fast triage | Plugin-dependent |
| **String analysis** | Browse per-process memory regions, run external `strings`/`bstrings` | `memdump`/`procdump` plugins, then external strings |
| **Plugins** | Growing | Extensive (Vol2 especially) |
| **Timeline** | Built-in timelines | Plugin-based |
| **OS support** | Primarily Windows | Windows, Linux, Mac |
| **Registry** | Built-in browser | Plugin-based |
| **Best for** | Rapid triage, visual exploration | Deep analysis, scripting, Linux dumps |
| **Limitation** | No behavioral analysis | Steeper learning curve |

**Key difference for string analysis:** MemProcFS lets you navigate to individual process memory regions as files and run strings on targeted areas. Volatility requires dumping process memory first via plugins, then running external string tools.

**Recommended combined workflow:** MemProcFS for rapid triage + Volatility for deep analysis + `bstrings` for classified string extraction.

---

## 4. Automated String Classification

### 4.1 Tools

| Tool | Capability |
|------|-----------|
| **bstrings** (Eric Zimmerman) | Built-in regex for IPs, URLs, paths, emails, Bitlocker keys. Custom regex via `--fr` flag. Cross-platform (.NET6). |
| **FLOSS** (Mandiant/FireEye) | Automatically decodes obfuscated strings from malware using emulation. |
| **memory-dumper** (ivan-sincek) | Dumps process memory, extracts data via regex patterns. https://github.com/ivan-sincek/memory-dumper |
| **CyberChef** | Web-based decode/classify: base64, hex, URL, XOR. Recipe chains. |
| **strings + grep** | Classic approach: `strings file | grep -oP 'regex'` |

### 4.2 Classification Regex Patterns

```bash
# IP addresses
grep -oP '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'

# URLs
grep -oP 'https?://[^\s<>"'"'"'{}\|\\^`\[\]]+'

# Linux file paths
grep -oP '/(?:usr|etc|var|tmp|home|opt|dev|proc|sys|root|bin|sbin|lib)[/][^\s:*?"<>|]+'

# Base64 strings (20+ chars)
grep -oP '[A-Za-z0-9+/]{20,}={0,2}'

# Email addresses
grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

# Monero wallets
grep -oP '[48][1-9A-HJ-NP-Za-km-z]{94}'

# Bitcoin wallets
grep -oP '[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,39}'

# Ethereum wallets
grep -oP '0x[0-9a-fA-F]{40}'

# SSH private keys
grep -c 'BEGIN.*PRIVATE KEY'

# Stratum mining
grep -c 'stratum+tcp\|stratum+ssl'
```

### 4.3 Recommended Workflow for 2.2GB memory-strings.ascii

1. **Quick triage** -- grep for high-value indicators first (stratum, wallet patterns, /dev/tcp)
2. **Classify all strings** -- run bstrings with built-in regex or use grep pipeline
3. **Decode obfuscated** -- extract base64 candidates, decode with CyberChef or `base64 -d`
4. **YARA scan** -- run YARA rules against the strings file (or original memory dump)
5. **Cross-reference** -- check IPs/domains against VirusTotal, AbuseIPDB, Shodan
6. **Enrich** -- use Akamai's Monero network map (~30K nodes) to identify pool connections

---

## 5. /proc/net/sockstat Analysis

### 5.1 Format

```
sockets: used 3037
TCP: inuse 1365 orphan 17 tw 2030 alloc 2788 mem 4109
UDP: inuse 6 mem 3
UDPLITE: inuse 0
RAW: inuse 0
FRAG: inuse 0 memory 0
```

### 5.2 What sockstat Reveals That ss/netstat Miss

**The alloc-inuse gap:**
- `alloc` = ALL TCP sockets (including TCP_CLOSE)
- `inuse` = all EXCEPT TCP_CLOSE
- **Gap = sockets allocated but not actively connected**
- Large gap indicates: socket leaking, hidden backdoor sockets, covert channels

**Bound-but-not-listening ports (critical finding):**
- TCP ports can be BOUND without LISTENING
- netstat, ss, lsof, fuser will NOT show these
- The port IS allocated and blocked for other use
- Only sockstat `alloc` count reflects these phantom allocations
- Attackers can reserve ports invisibly

**Orphan sockets:**
- `orphan` = TCP connections with no user file handle
- High count indicates: killed process residue, deliberate detachment for evasion, exfiltration artifacts

### 5.3 Why ss/netstat Can Be Evaded

| Tool | Mechanism | Rootkit evasion |
|------|-----------|----------------|
| **netstat** | Reads `/proc/net/tcp` files | Adore hooks `tcp4_seq_show()` to filter output |
| **ss** | Uses netlink/SOCK_DIAG kernel API | Harder to hook, but Singularity rootkit manages it |
| **lsof** | Scans process table for open FDs | Hidden processes = hidden sockets |
| **sockstat** | Aggregate kernel counters | Much harder to tamper individually |

### 5.4 Cross-Validation Method

```bash
# Capture simultaneously for comparison:
cat /proc/net/sockstat
cat /proc/net/sockstat6
wc -l /proc/net/tcp    # minus header
wc -l /proc/net/tcp6
ss -s
netstat -an | wc -l

# Formula for detecting hidden connections:
# closed_tcp = alloc - (inuse + inuse6 - tw)
```

### 5.5 In Memory Dumps (Volatility)

```bash
vol3 -f dump.mem linux.sockstat.Sockstat
```
Extracts: process name, PID, source address, state, ports. Reveals backdoors/reverse shells via unusual sockets.

### 5.6 Modern Rootkit Evasion (Singularity)

The Singularity rootkit (kernel 6.x) hides:
- TCP/UDP connections and ports
- conntrack entries
- Filters `/proc/kcore`, `/proc/kallsyms`, `/proc/vmallocinfo`
- Memory forensics evasion capabilities

---

## 6. Additional Tools

| Tool | Purpose |
|------|---------|
| LiME | Linux memory acquisition |
| AVML | Microsoft's Linux memory acquisition |
| Memoryze | Memory capture + analysis |
| WinPmem/PMEM | Fast acquisition |
| MASHKA | Anti-forensic resilient memory analysis |
| Tracee | eBPF-based rootkit detection |
| sandfly-processdecloak | Rootkit process decloaking (Diamorphine, Reptile) |
| rkspotter | Kernel-level rootkit signatures |
| rkhunter | String-based rootkit detection (easily bypassed) |
| ProcWatch | Linux process security scanner |
| Falco | Runtime container security (XMRig detection) |

---

## Sources

- [Elastic Security Labs: Linux Rootkits](https://www.elastic.co/security-labs/linux-rootkits-1-hooked-on-linux)
- [Diamorphine GitHub](https://github.com/m0nad/Diamorphine)
- [Sandfly Process Decloaking](https://sandflysecurity.com/blog/linux-stealth-rootkit-process-decloaking-tool-sandfly-processdecloak)
- [Akamai Cryptominers Anatomy](https://www.akamai.com/blog/security-research/cryptominer-analyzing-samples-active-campaigns)
- [Neo23x0 YARA XMRig Rules](https://github.com/Neo23x0/signature-base/blob/master/yara/pua_xmrig_monero_miner.yar)
- [McAfee YARA Monero Rules](https://github.com/advanced-threat-research/Yara-Rules/blob/master/miners/MINER_Monero.yar)
- [MemProcFS vs Volatility Part 1](https://medium.com/@cyberengage.org/moving-forward-with-memory-analysis-from-volatility-to-memprocfs-part-1-a28df61de30b)
- [MemProcFS Practical Guide](https://www.cyberengage.org/post/extracting-memory-objects-with-memprocfs-volatility3-bstrings-a-practical-guide)
- [bstrings SANS](https://www.sans.org/tools/bstrings)
- [Eric Zimmerman bstrings](https://github.com/EricZimmerman/bstrings)
- [FLOSS Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/automatically-extracting-obfuscated-strings/)
- [Crypto Address Regex](https://gist.github.com/MBrassey/623f7b8d02766fa2d826bf9eca3fe005)
- [CyberCop Labs Regex](https://cybercoplabs.net/article/regex-searching-of-addresses/)
- [Sandfly Reverse Shell Detection](https://sandflysecurity.com/blog/linux-reverse-shell-detection-and-forensics)
- [Pentestmonkey Reverse Shell Cheat Sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [SANS sockstat Analysis](https://www.sans.org/blog/when-redundant-yields-different-results/)
- [Proc Filesystem Forensics](https://andreafortuna.org/2026/01/19/proc-filesystem)
- [Linux Rootkits Port Hiding](https://xcellerator.github.io/posts/linux_rootkits_08/)
- [Singularity Rootkit](https://github.com/MatheuZSecurity/Singularity)
- [Falco Cryptomining Detection](https://falco.org/blog/falco-detect-cryptomining/)
- [Wiz Linux Rootkits LKM](https://www.wiz.io/blog/linux-rootkits-explained-part-2-loadable-kernel-modules)
- [InQuest awesome-yara](https://github.com/InQuest/awesome-yara)
- [YARA-X (Rust rewrite)](https://virustotal.github.io/yara/)
