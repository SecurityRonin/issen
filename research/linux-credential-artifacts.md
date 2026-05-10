# Linux Credential Artifacts — Comprehensive Forensic Catalog

**Compiled:** 2026-04-13  
**Scope:** Linux systems (all major distributions)  
**Purpose:** Forensic enumeration of credential storage locations, authentication material, and session tokens  
**Classification:** Research / DFIR Reference

---

## Table of Contents

1. [Local Account Databases](#local-account-databases)
2. [SSH Credentials](#ssh-credentials)
3. [Keyring and Secret Storage](#keyring-and-secret-storage)
4. [GPG / PGP Keys](#gpg--pgp-keys)
5. [Browser Credentials](#browser-credentials)
6. [System Authentication Logs](#system-authentication-logs)
7. [Cloud and Container Credentials](#cloud-and-container-credentials)
8. [Network Credentials](#network-credentials)
9. [Application Credentials](#application-credentials)
10. [Memory-Resident Credentials](#memory-resident-credentials)

---

## Local Account Databases

### 1. `/etc/passwd` — User Account Database

| Field | Value |
|-------|-------|
| **Location** | `/etc/passwd` |
| **Format** | Plaintext, colon-delimited, world-readable |
| **Key Fields** | `username:x:UID:GID:GECOS:home:shell` — seven colon-separated fields; the `x` in field 2 indicates the real hash is in `/etc/shadow` |
| **Forensic Value** | Reveals all accounts including service accounts; UID=0 duplicates indicate backdoor root accounts; service accounts with `/bin/bash` shell (rather than `/usr/sbin/nologin` or `/bin/false`) indicate possible tampering; unknown usernames indicate attacker-created accounts |
| **OS Scope** | All Linux distributions |
| **Data Scope** | System |
| **Decoder Approach** | Plain `cat`; `awk -F: '$3==0'` to find UID 0 accounts; `grep '/bin/bash'` to find interactive-shell accounts; `pwck` for integrity verification; sort by UID with `sort -nk3 -t:` to detect anomalies |
| **MITRE ATT&CK** | T1003.008 (OS Credential Dumping: /etc/passwd and /etc/shadow), T1136.001 (Create Account: Local Account) |
| **References** | [MCSI Linux Forensics: Enumerating Users](https://library.mosse-institute.com/articles/2022/07/linux-forensics-enumerating-users-and-groups/linux-forensics-enumerating-users-and-groups.html); [nixCraft: /etc/passwd Format](https://www.cyberciti.biz/faq/understanding-etcpasswd-file-format/); [Embrace The Red: UID 0 Backdoor](https://embracethered.com/blog/posts/2021/linux-user-uid-zero-backdoor/); [MITRE T1003.008](https://attack.mitre.org/techniques/T1003/008/) |

---

### 2. `/etc/shadow` — Shadow Password File

| Field | Value |
|-------|-------|
| **Location** | `/etc/shadow` |
| **Format** | Plaintext, colon-delimited; readable only by root (mode 000 or 640 depending on distro) |
| **Key Fields** | Nine colon-separated fields: `username:$hash_type$salt$hash:lastchg:min:max:warn:inactive:expire:reserved`. Hash field encodes algorithm as `$id$`: `$1$`=MD5 (obsolete), `$2a$`/`$2y$`=Blowfish, `$5$`=SHA-256, `$6$`=SHA-512, `$y$`=yescrypt (modern default on Debian 11+, Ubuntu 22.04+, Fedora 35+). Special values: `!` or `!!` = locked/no password; `*` = system account with no password auth |
| **Forensic Value** | Primary source of password hashes for offline cracking; weak algorithms (`$1$` MD5) are trivially crackable with modern hardware (billions of guesses/second); `lastchg` field (days since Jan 1 1970) reveals when passwords were last changed; empty hash fields indicate passwordless accounts; accounts locked post-compromise may show altered `expire` fields |
| **OS Scope** | All Linux distributions |
| **Data Scope** | System |
| **Decoder Approach** | `sudo cat /etc/shadow`; `unshadow /etc/passwd /etc/shadow > crackable.txt` then John the Ripper or Hashcat; inspect `$id$` prefix for algorithm; parse `lastchg` as Unix epoch days; `pwck` for file integrity |
| **MITRE ATT&CK** | T1003.008 (OS Credential Dumping: /etc/passwd and /etc/shadow), T1110.002 (Brute Force: Password Cracking) |
| **References** | [Linuxize: /etc/shadow File](https://linuxize.com/post/etc-shadow-file/); [Baeldung: Shadow Passwords and yescrypt](https://www.baeldung.com/linux/shadow-passwords); [Sandfly Security: Obsolete Hash Threats](https://sandflysecurity.com/blog/obsolete-linux-password-hash-threats); [linux.die.net shadow(5)](https://linux.die.net/man/5/shadow); [MITRE T1003.008](https://attack.mitre.org/techniques/T1003/008/) |

---

### 3. `/etc/group` — Group Account Database

| Field | Value |
|-------|-------|
| **Location** | `/etc/group` |
| **Format** | Plaintext, colon-delimited, world-readable |
| **Key Fields** | `groupname:password:GID:members` — four colon-separated fields; GID=0 is the root group; `sudo` and `wheel` groups grant administrative access |
| **Forensic Value** | Unauthorized additions to `sudo`, `wheel`, `adm`, or `docker` groups grant privilege escalation; non-root users in GID 0 are a critical IoC; `docker` group membership provides effective root-equivalent access via container escapes |
| **OS Scope** | All Linux distributions |
| **Data Scope** | System |
| **Decoder Approach** | `cat /etc/group`; `grep -E '^sudo:|^wheel:|^docker:' /etc/group` to identify privileged group members; `grpck` for integrity validation; compare against change management baselines |
| **MITRE ATT&CK** | T1136.001 (Create Account: Local Account), T1548.003 (Sudo and Sudo Caching) |
| **References** | [MCSI Linux Forensics: Enumerating Users and Groups](https://library.mosse-institute.com/articles/2022/07/linux-forensics-enumerating-users-and-groups/linux-forensics-enumerating-users-and-groups.html); [man7.org gshadow(5)](https://www.man7.org/linux/man-pages/man5/gshadow.5.html) |

---

### 4. `/etc/gshadow` — Group Shadow Password File

| Field | Value |
|-------|-------|
| **Location** | `/etc/gshadow` |
| **Format** | Plaintext, colon-delimited; readable only by root |
| **Key Fields** | `groupname:encrypted_password:group_admins:group_members`; `!` = password locked; `!!` = password never set; empty password = members only can use `newgrp` |
| **Forensic Value** | Group passwords allow non-members to gain group permissions via `newgrp`; encrypted group passwords can be cracked offline; group admin fields reveal who can manage group membership without root |
| **OS Scope** | All Linux distributions |
| **Data Scope** | System |
| **Decoder Approach** | `sudo cat /etc/gshadow`; `grpck` for integrity; cross-reference with `/etc/group` for membership discrepancies |
| **MITRE ATT&CK** | T1003.008, T1136.001 |
| **References** | [man7.org gshadow(5)](https://www.man7.org/linux/man-pages/man5/gshadow.5.html); [Red Hat: /etc/gshadow](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/4/html/introduction_to_system_administration/s3-acctsgrps-gshadow); [Medium: passwd, shadow, group, gshadow](https://atharvvvsharma.medium.com/information-about-passwd-group-shadow-and-gshadow-file-f2aee1b38a4f) |

---

### 5. `/etc/sudoers` and `/etc/sudoers.d/*` — Sudo Privilege Configuration

| Field | Value |
|-------|-------|
| **Location** | `/etc/sudoers`, `/etc/sudoers.d/*.conf` (or files without extension, distro-dependent) |
| **Format** | Plaintext; readable only by root; edited via `visudo` (applies syntax checking) |
| **Key Fields** | `user/group ALL=(runas) NOPASSWD: commands`; `Defaults timestamp_timeout=N` (sudo credential cache window); `Defaults !tty_tickets` (disables per-terminal session isolation, used by Proton macOS malware on Linux) |
| **Forensic Value** | `NOPASSWD: ALL` grants passwordless root access; `sudoers.d/` drop-in files are a common persistence mechanism; dangerous binary grants (vi, nano, less, find, cp, tee) enable shell escapes to root; modified `tty_tickets` setting allows cross-terminal credential reuse; sudo timestamp cache at `/var/db/sudo` or `/var/run/sudo/ts/` reveals 15-minute session windows that can be hijacked |
| **OS Scope** | All Linux distributions |
| **Data Scope** | System |
| **Decoder Approach** | `sudo cat /etc/sudoers`; `sudo cat /etc/sudoers.d/*`; check `sudo -l` output; monitor with auditd for write events; compare file mtime against change management records; CVE-2025-32462 and CVE-2025-32463 affect sudo < 1.9.17p1 |
| **MITRE ATT&CK** | T1548.003 (Abuse Elevation Control Mechanism: Sudo and Sudo Caching), T1078.003 (Valid Accounts: Local Accounts) |
| **References** | [MITRE T1548.003](https://attack.mitre.org/techniques/T1548/003/); [Splunk: Persistence and Privilege Escalation Detection](https://www.splunk.com/en_us/blog/security/deep-dive-on-persistence-privilege-escalation-technique-and-detection-in-linux-platform.html); [Elastic: Privilege Escalation via Sudoers](https://www.elastic.co/guide/en/security/current/potential-privilege-escalation-via-sudoers-file-modification.html); [Juggernaut-Sec: Sudo LPE](https://juggernaut-sec.com/sudo-part-1-lpe/) |

---

## SSH Credentials

### 6. `~/.ssh/authorized_keys` — SSH Public Key Authorization

| Field | Value |
|-------|-------|
| **Location** | `~/.ssh/authorized_keys`, `~/.ssh/authorized_keys2` (legacy); `/root/.ssh/authorized_keys` for root |
| **Format** | Plaintext; one key per line: `key-type base64-encoded-key comment`; key types include `ssh-rsa`, `ssh-ed25519`, `ecdsa-sha2-nistp256`, `sk-ssh-ed25519@openssh.com` (FIDO2) |
| **Forensic Value** | Attacker-injected public keys provide persistent passwordless backdoor access; key fingerprints and comments can identify the source system or actor; authorized keys survive password resets; cross-reference with `id_*.pub` files across the network to trace key origin; modification timestamps indicate when backdoor was planted; Splunk and Elastic provide prebuilt detection rules for unauthorized modification |
| **OS Scope** | All Linux distributions |
| **Data Scope** | User |
| **Decoder Approach** | `cat ~/.ssh/authorized_keys`; `ssh-keygen -l -f ~/.ssh/authorized_keys` to display fingerprints; compare mtime against expected change windows; correlate with `/var/log/auth.log` SSH login events; FIM alerting on this file |
| **MITRE ATT&CK** | T1098.004 (Account Manipulation: SSH Authorized Keys), T1078.003 |
| **References** | [MCSI: Linux Forensics SSH Artifacts](https://library.mosse-institute.com/articles/2022/07/linux-forensics-ssh-artifacts/linux-forensics-ssh-artifacts.html); [SANS: SSH Keys in Cloud](https://www.sans.org/blog/securing-ssh-keys-cloud-environments-practical-guidance-security-forensics-legal-accountability); [Elastic: SSH Authorized Keys Detection](https://www.elastic.co/guide/en/security/current/ssh-authorized-keys-file-modification.html); [Splunk: Authorized Keys Modification](https://research.splunk.com/endpoint/f5ab595e-28e5-4327-8077-5008ba97c850/) |

---

### 7. SSH Private Keys — `~/.ssh/id_rsa`, `id_ed25519`, `id_ecdsa`

| Field | Value |
|-------|-------|
| **Location** | `~/.ssh/id_rsa`, `~/.ssh/id_ed25519`, `~/.ssh/id_ecdsa`, `~/.ssh/id_dsa` (deprecated); `/root/.ssh/id_*`; `/etc/ssh/ssh_host_*_key` (host keys) |
| **Format** | PEM (Base64-encoded with `-----BEGIN [OPENSSH/RSA] PRIVATE KEY-----` header) or OpenSSH native binary format; optionally passphrase-encrypted |
| **Key Fields** | Header line identifies format: `-----BEGIN OPENSSH PRIVATE KEY-----` = modern OpenSSH format (may be encrypted with `aes256-cbc`/`aes256-ctr` + `bcrypt` KDF); `-----BEGIN RSA PRIVATE KEY-----` = legacy PEM; `-----BEGIN PRIVATE KEY-----` = PKCS#8 unencrypted; `-----BEGIN ENCRYPTED PRIVATE KEY-----` = PKCS#8 encrypted. Ed25519 keys always use OpenSSH format. Unencrypted keys contain `cipher=none` and `kdfname=none` in the binary header. |
| **Forensic Value** | Unencrypted private keys provide immediate authentication capability to any host with the matching public key in `authorized_keys`; stolen private keys survive password resets; passphrase-encrypted keys can be subjected to offline brute-force; presence in unexpected locations (tmp, world-readable paths) indicates exfiltration or poor hygiene |
| **OS Scope** | All Linux distributions |
| **Data Scope** | User |
| **Decoder Approach** | `ssh-keygen -l -f <keyfile>` (displays fingerprint without exposing key material); `ssh-keygen -y -f <keyfile>` (derives public key — confirms key is valid/unencrypted); file header inspection identifies encryption status; `grep -r "BEGIN.*PRIVATE KEY" /home /root /tmp` for broad discovery; check permissions — should be mode 600 |
| **MITRE ATT&CK** | T1552.004 (Unsecured Credentials: Private Keys), T1078.003 |
| **References** | [ArchWiki: SSH Keys](https://wiki.archlinux.org/title/SSH_keys); [The Digital Cat: OpenSSH Private Keys](https://www.thedigitalcatonline.com/blog/2021/06/03/public-key-cryptography-openssh-private-keys/); [Peter Lyons: OpenSSH Ed25519 Format](https://peterlyons.com/problog/2017/12/openssh-ed25519-private-key-file-format/); [MITRE T1552.004](https://attack.mitre.org/techniques/T1552/004/) |

---

### 8. `~/.ssh/known_hosts` — User SSH Known Hosts

| Field | Value |
|-------|-------|
| **Location** | `~/.ssh/known_hosts` |
| **Format** | Plaintext; one entry per line; modern systems hash hostnames by default (`HashKnownHosts yes`): `|1|<base64-salt>|<base64-hash> key-type base64-pubkey`; unhashed format: `hostname key-type base64-pubkey` |
| **Forensic Value** | Records all hosts to which the user has ever initiated an SSH connection (key exchange, not necessarily login); reveals lateral movement targets; hashed entries can be reverse-searched with `ssh-keygen -F <hostname>`; alterations by an attacker (e.g., replacing legitimate host keys with attacker keys) enable MITM attacks; presence of internal hostnames or IP ranges maps network topology |
| **OS Scope** | All Linux distributions |
| **Data Scope** | User |
| **Decoder Approach** | `cat ~/.ssh/known_hosts`; `ssh-keygen -F <hostname>` to query for specific host; `ssh-keygen -H` to hash entries; cross-reference with `/var/log/auth.log` to confirm actual logins vs. mere key exchanges |
| **MITRE ATT&CK** | T1021.004 (Remote Services: SSH), T1552.004 |
| **References** | [MCSI: Linux Forensics SSH Artifacts](https://library.mosse-institute.com/articles/2022/07/linux-forensics-ssh-artifacts/linux-forensics-ssh-artifacts.html); [Sandfly: SSH Lateral Movement](https://sandflysecurity.com/blog/ssh-lateral-movement-risks-on-linux-webinar-and-white-paper); [Binalyze AIR: SSH Known Hosts](https://kb.binalyze.com/air/features/acquisition/acquisition-profiles/linux-collections/ssh-known-hosts) |

---

### 9. `/etc/ssh/ssh_known_hosts` — System-Wide SSH Known Hosts

| Field | Value |
|-------|-------|
| **Location** | `/etc/ssh/ssh_known_hosts` |
| **Format** | Same as `~/.ssh/known_hosts` but applies to all users system-wide; plaintext; root-writable, world-readable |
| **Forensic Value** | Reveals hosts that any system process or user can connect to without prompting; pre-populated entries may indicate administrative trust relationships; attacker modification of this file enables system-wide MITM attacks against all users; cross-reference with network topology to identify trust relationships and lateral movement paths |
| **OS Scope** | All Linux distributions |
| **Data Scope** | System |
| **Decoder Approach** | `cat /etc/ssh/ssh_known_hosts`; `ssh-keygen -F <hostname> -f /etc/ssh/ssh_known_hosts`; compare mtime against `~/.ssh/known_hosts` modification times |
| **MITRE ATT&CK** | T1021.004, T1565.001 (Data Manipulation: Stored Data Manipulation) |
| **References** | [LinuxHint: known_hosts File](https://linuxhint.com/known-hosts-file-ssh-linux/); [LinuxHandbook: known_hosts](https://linuxhandbook.com/known-hosts-file/); [OpenSSH/Client Config — Wikibooks](https://en.wikibooks.org/wiki/OpenSSH/Client_Configuration_Files) |

---

### 10. `~/.ssh/config` — SSH Client Configuration

| Field | Value |
|-------|-------|
| **Location** | `~/.ssh/config`, `/etc/ssh/ssh_config` (system-wide) |
| **Format** | Plaintext; `Host` stanza blocks with keyword-value pairs |
| **Key Fields** | `Host` (alias), `HostName` (actual target), `User` (remote username), `IdentityFile` (path to private key), `ProxyJump` (pivot host chain), `ProxyCommand` (arbitrary command for tunneling), `ForwardAgent yes` (enables SSH agent forwarding — major lateral movement risk) |
| **Forensic Value** | `ProxyJump` and `ProxyCommand` stanzas document planned or historical lateral movement paths; `ForwardAgent yes` enables agent hijacking on jump hosts; `IdentityFile` reveals which keys are used for which hosts; custom `Host` aliases may obscure destination hostnames; `StrictHostKeyChecking no` weakens MITM protection |
| **OS Scope** | All Linux distributions |
| **Data Scope** | User |
| **Decoder Approach** | `cat ~/.ssh/config`; `grep -i 'proxycommand\|proxyjump\|forwardagent\|identityfile' ~/.ssh/config`; `ssh -G <host>` to display effective options for a given host |
| **MITRE ATT&CK** | T1021.004, T1552.004, T1090 (Proxy) |
| **References** | [SANS: SSH Keys in Cloud Environments](https://www.sans.org/blog/securing-ssh-keys-cloud-environments-practical-guidance-security-forensics-legal-accountability); [HighOn.Coffee: SSH Lateral Movement Cheat Sheet](https://highon.coffee/blog/ssh-lateral-movement-cheat-sheet/) |

---

## Keyring and Secret Storage

### 11. GNOME Keyring — `~/.local/share/keyrings/`

| Field | Value |
|-------|-------|
| **Location** | `~/.local/share/keyrings/*.keyring` (legacy format); `~/.local/share/keyrings/login.keyring` (login keyring); `/run/user/<UID>/keyring/control` (runtime control socket) |
| **Format** | Encrypted binary (GnuTLS/libsecret format); `login.keyring` is encrypted with the user's login password and auto-unlocked on session start; accessible via D-Bus `org.freedesktop.secrets` API |
| **Key Fields** | Collections (keyrings) contain items; each item has a `label`, `secret`, and lookup `attributes` (key-value pairs); the login collection unlocks automatically when the user logs in |
| **Forensic Value** | Stores WiFi passwords, browser credentials, SSH passphrases, application passwords, and GPG passphrases; CVE-2018-19358: any application can read any secret from an unlocked keyring via D-Bus without authentication; if session is locked but not logged out, keyring remains unlocked in memory (DMA attack surface); `secret-tool` CLI can enumerate contents when keyring is unlocked |
| **OS Scope** | GNOME desktop environments (Debian, Ubuntu, Fedora with GNOME) |
| **Data Scope** | User |
| **Decoder Approach** | `secret-tool search --all ''` (lists all items if keyring is unlocked); `dbus-send` to `org.freedesktop.secrets` interface; offline: requires user's login password to decrypt `login.keyring`; `seahorse` GUI tool for live session inspection |
| **MITRE ATT&CK** | T1555 (Credentials from Password Stores), T1555.003 |
| **References** | [ArchWiki: GNOME Keyring](https://wiki.archlinux.org/title/GNOME/Keyring); [GNOME Keyring Wikipedia](https://en.wikipedia.org/wiki/GNOME_Keyring); [RTFM: Linux Keyring, gnome-keyring, Secret Service, D-Bus](https://rtfm.co.ua/en/what-is-linux-keyring-gnome-keyring-secret-service-and-d-bus/); [Baeldung on Linux: /run/user/$UID](https://www.baeldung.com/linux/run-user-uid-directory) |

---

### 12. KDE KWallet — `~/.local/share/kwalletd/`

| Field | Value |
|-------|-------|
| **Location** | `~/.local/share/kwalletd/kdewallet.kwl` (wallet file); `~/.local/share/kwalletd/kdewallet.salt`; `~/.config/kwalletrc` (configuration) |
| **Format** | Binary `.kwl` format; encrypted with Blowfish (CBC mode, modern) or GnuPG; key derived from user password via SHA-1 (pre-2018 versions: no salt, 56-bit effective key — brute-forceable) |
| **Key Fields** | Wallet contains folders (categories) containing entries; each entry has a key name and secret value; integrated with applications via D-Bus `org.kde.kwalletd` or `org.freedesktop.secrets` (ksecretd) |
| **Forensic Value** | Stores WiFi passwords, SSH keys, Git credentials, browser passwords, and arbitrary application secrets; pre-2018 implementations used SHA-1 without salting — making older `.kwl` files highly susceptible to brute-force; PAM integration (`kwallet-pam`) auto-unlocks wallet on login using the login password (Blowfish wallets only); migrating between KWallet and Secret Service API introduced transition risks in early 2025 |
| **OS Scope** | KDE Plasma desktop environments |
| **Data Scope** | User |
| **Decoder Approach** | `KWalletManager` GUI for live session inspection; offline brute-force of `.kwl` using Blowfish with known salt from `kdewallet.salt`; check `kwalletrc` for auto-open wallet settings |
| **MITRE ATT&CK** | T1555 (Credentials from Password Stores) |
| **References** | [ArchWiki: KDE Wallet](https://wiki.archlinux.org/title/KDE_Wallet); [KWallet Wikipedia](https://en.wikipedia.org/wiki/KWallet); [GitHub: KDE/kwallet](https://github.com/KDE/kwallet) |

---

### 13. Linux Kernel Keyring — In-Memory Key Storage

| Field | Value |
|-------|-------|
| **Location** | Kernel-managed, not on disk; inspected via `/proc/keys`, `/proc/key-users`; keyrings identified by type and name: `_uid.<UID>` (user keyring), `_uid_ses.<UID>` (user session keyring) |
| **Format** | In-memory kernel data structures; key types include `user` (arbitrary blobs), `logon` (kernel-only, never readable from userspace), `keyring`, `asymmetric`, `dns_resolver` |
| **Key Fields** | Each key has a serial number, type, description, and payload; user keyrings shared across all processes of same UID; session keyrings per-login session; process keyrings private to a process |
| **Forensic Value** | Applications and PAM modules store credentials (passwords, tokens, Kerberos tickets) in the kernel keyring; `logon` type keys cannot be read back to userspace (write-only from a forensic perspective); user keyring persists across processes for the same UID — compromise of one process can reveal keys used by others; `keyctl show @s` displays the session keyring tree |
| **OS Scope** | Linux kernel 2.6.10+ (all modern distributions) |
| **Data Scope** | User / System |
| **Decoder Approach** | `keyctl show @s` (session keyring); `keyctl show @u` (user keyring); `cat /proc/keys` (all keys); `cat /proc/key-users` (per-user statistics); `keyctl read <serial>` (read key payload if permitted); `keyctl list @s` (list session keyring entries) |
| **MITRE ATT&CK** | T1003.007 (OS Credential Dumping: Proc Filesystem), T1555 |
| **References** | [Cloudflare: Linux Kernel Key Retention Service](https://blog.cloudflare.com/the-linux-kernel-key-retention-service-and-why-you-should-use-it-in-your-next-application/); [Linux Kernel: Credentials](https://docs.kernel.org/security/credentials.html); [man7: user-keyring(7)](https://man7.org/linux/man-pages/man7/user-keyring.7.html); [man7: user-session-keyring(7)](https://man7.org/linux/man-pages/man7/user-session-keyring.7.html) |

---

## GPG / PGP Keys

### 14. GnuPG Private Key Store — `~/.gnupg/`

| Field | Value |
|-------|-------|
| **Location** | `~/.gnupg/private-keys-v1.d/*.key` (GnuPG 2.1+, one file per key, named by keygrip); `~/.gnupg/secring.gpg` (GnuPG 1.x legacy, all secret keys in one file); `~/.gnupg/pubring.kbx` (public keyring, keybox format); `~/.gnupg/trustdb.gpg` (trust database); `~/.gnupg/openpgp-revocs.d/` (revocation certificates) |
| **Format** | `private-keys-v1.d/*.key`: binary, S-expression format, encrypted with user passphrase via `gpg-agent`; `secring.gpg`: OpenPGP binary format (RFC 4880); `pubring.kbx`: keybox binary format |
| **Key Fields** | Each `.key` file identified by 40-character keygrip (SHA-1 of key parameters); passphrase protection via `gpg-agent`; `trustdb.gpg` records web-of-trust relationships |
| **Forensic Value** | Private keys enable decryption of any data encrypted to that key and signature forgery; passphrases can be brute-forced offline once key file is obtained; `gpg-agent` caches passphrases in memory during session; presence of revocation certificates (`openpgp-revocs.d/`) indicates key owner had concerns about compromise; key metadata (creation date, expiry, UIDs) reveals identity and operational history |
| **OS Scope** | All Linux distributions |
| **Data Scope** | User |
| **Decoder Approach** | `gpg --list-secret-keys` (enumerate keys); `gpg --export-secret-key -a <keyid>` (export — requires passphrase or agent); `gpg --fingerprint` (display fingerprints); file permissions should be mode 600; `gpgconf --list-dirs` to confirm key store location |
| **MITRE ATT&CK** | T1552.004 (Unsecured Credentials: Private Keys), T1552.001 |
| **References** | [HowToGeek: Back Up and Restore GPG Keys](https://www.howtogeek.com/816878/how-to-back-up-and-restore-gpg-keys-on-linux/); [GnuPG: GPG Configuration Options](https://www.gnupg.org/documentation/manuals/gnupg/GPG-Configuration-Options.html); [Ubuntu manpage: gpg-agent](https://manpages.ubuntu.com/manpages/noble/man1/gpg-agent.1.html) |

---

## Browser Credentials

### 15. Chrome / Chromium — Login Data (SQLite)

| Field | Value |
|-------|-------|
| **Location** | `~/.config/google-chrome/Default/Login Data` (Google Chrome); `~/.config/chromium/Default/Login Data` (Chromium); `~/.config/microsoft-edge/Default/Login Data` (Edge); `~/.config/brave-browser/Default/Login Data` (Brave); `~/.config/google-chrome/Local State` (contains encryption key) |
| **Format** | SQLite 3 database; `Login Data` contains `logins` table; password field encrypted with user keyring key (on Linux, via `libsecret`/GNOME Keyring or KWallet) |
| **Key Fields** | `logins` table columns: `origin_url`, `username_value`, `password_value` (encrypted blob), `date_created`, `date_last_used`, `times_used`, `blacklisted_by_user` (1 = user chose "never save" — still records the site visited) |
| **Forensic Value** | Stores credentials for all websites where user saved passwords; `blacklisted_by_user=1` entries reveal sites visited even when user declined to save password; `date_last_used` and `times_used` reveal active credentials vs. stale ones; on Linux, password decryption requires access to the user's keyring or may fall back to an empty password (older Chrome versions); credential sync means credentials from other devices may appear locally; used by 85+ known threat actor groups and malware families (MITRE T1555.003) |
| **OS Scope** | All Linux distributions with Chromium-based browsers |
| **Data Scope** | User |
| **Decoder Approach** | `sqlite3 "Login Data" "SELECT origin_url, username_value, password_value FROM logins"` (raw); decrypt `password_value` using the key from `Local State` + GNOME Keyring; tools: LaZagne, HarvestBrowserPasswords; copy DB before opening to avoid lock conflicts |
| **MITRE ATT&CK** | T1555.003 (Credentials from Password Stores: Credentials from Web Browsers) |
| **References** | [Medium: Chrome Browser Credential Recovery](https://palmenas.medium.com/forensic-recovery-of-chrome-based-browser-passwords-e8df90d4a3cd); [Atropos4n6: Chrome Login Data Forensics](https://atropos4n6.com/windows/chrome-login-data-forensics/); [MITRE T1555.003](https://attack.mitre.org/techniques/T1555/003/) |

---

### 16. Firefox — `logins.json` and `key4.db`

| Field | Value |
|-------|-------|
| **Location** | `~/.mozilla/firefox/*.default*/logins.json` (encrypted credential entries); `~/.mozilla/firefox/*.default*/key4.db` (SQLite, master key); `~/.mozilla/firefox/*.default*/cookies.sqlite` (session cookies); legacy: `key3.db` (Berkeley DB), `signons.sqlite` (pre-Firefox 58) |
| **Format** | `logins.json`: JSON array of login objects; `key4.db`: SQLite database containing master encryption key material |
| **Key Fields** | `logins.json` fields: `hostname`, `encryptedUsername`, `encryptedPassword` (both 3DES-CBC encrypted, ASN.1 encoded, Base64 encoded); `key4.db` tables: `metadata` (contains `globalSalt`), `nssPrivate` (contains `entrySalt` and encrypted key material); decryption key derived from `globalSalt` + `entrySalt` + master password (default: empty string) |
| **Forensic Value** | Default master password is empty — credentials are decryptable without user interaction using only `key4.db` and `logins.json`; if user set a master password, offline brute-force is required; both username and password are encrypted (unlike Chrome where only the password is encrypted); session cookies in `cookies.sqlite` may allow direct session hijacking without credential decryption |
| **OS Scope** | All Linux distributions with Firefox |
| **Data Scope** | User |
| **Decoder Approach** | `firepwd` Python tool (lclevy/firepwd on GitHub) decrypts using `key4.db` + `logins.json`; `sqlite3 key4.db` to inspect key material; `sqlite3 cookies.sqlite "SELECT host, name, value, expiry FROM moz_cookies"` for session cookies |
| **MITRE ATT&CK** | T1555.003 (Credentials from Password Stores: Credentials from Web Browsers) |
| **References** | [GitHub: lclevy/firepwd](https://github.com/lclevy/firepwd); [CyberEngage: Browser Credential Storage](https://www.cyberengage.org/post/browser-credential-storage-and-forensic-password-recovery); [Medium: Browser Credential Forensics](https://medium.com/@cyberengage.org/browser-credential-storage-and-forensic-password-recovery-0f2ead617fa1); [MITRE T1555.003](https://attack.mitre.org/techniques/T1555/003/) |

---

## System Authentication Logs

### 17. `/var/log/auth.log` and `/var/log/secure` — PAM Authentication Log

| Field | Value |
|-------|-------|
| **Location** | `/var/log/auth.log` (Debian/Ubuntu); `/var/log/secure` (RHEL/CentOS/Fedora/SUSE) |
| **Format** | Plaintext syslog format: `Month Day HH:MM:SS hostname process[PID]: message` |
| **Key Fields** | SSH login events (`sshd: Accepted publickey/password from`), sudo events (`sudo: USER : TTY=...; USER=root ; COMMAND=...`), PAM events, `su` usage, failed login attempts (`Failed password for`), and session open/close events |
| **Forensic Value** | Primary source for authentication timeline reconstruction; correlate with `wtmp`/`btmp` binary logs for cross-validation; detect brute-force attacks (repeated `Failed password` entries); identify privilege escalation via sudo; track SSH key-based logins to map authorized_keys usage; detect `su` to other accounts; identify logins from unexpected IP addresses or at unusual times |
| **OS Scope** | Debian/Ubuntu (`auth.log`); RHEL/CentOS/Fedora (`secure`) |
| **Data Scope** | System |
| **Decoder Approach** | `grep 'Accepted\|Failed\|sudo\|su\[' /var/log/auth.log`; `grep 'Invalid user\|error: maximum authentication' /var/log/auth.log`; forward to SIEM in real-time for tamper resistance; `journalctl -u sshd` on systemd systems |
| **MITRE ATT&CK** | T1070.002 (Indicator Removal: Clear Linux or Mac System Logs), T1078 (Valid Accounts) |
| **References** | [VulnTech: System Logs](https://vulntech.com/tutorial/tutorial/learn-digital-forensics/linux-system-logs-forensics-var-log/); [Fareedfauzi: Linux Forensics Cheatsheet](https://fareedfauzi.github.io/cheatsheets/linux-forensics/) |

---

### 18. `/var/log/wtmp` — Successful Login History (Binary)

| Field | Value |
|-------|-------|
| **Location** | `/var/log/wtmp` |
| **Format** | Binary; `struct utmp` records, 384 bytes each; not human-readable with standard text tools |
| **Key Fields** | Per record: `ut_type` (login type), `ut_pid` (PID), `ut_line` (terminal: `pts/0`, `tty1`), `ut_user` (username), `ut_host` (remote IP or hostname), `ut_tv` (timestamp struct), `ut_addr_v6` (remote IPv6 address) |
| **Forensic Value** | Historical record of all successful logins, logouts, and reboots; reveals attacker session durations and entry points; reboots visible as `REBOOT` entries with `"~"` username; zeroed-out (nulled) records (timestamp = Unix epoch 1970-01-01) indicate log tampering; `btmp` entries before and after nulled `wtmp` entries bracket the intrusion timeline; parsed by `last`, `utmpdump`, Plaso/log2timeline |
| **OS Scope** | All Linux distributions |
| **Data Scope** | System |
| **Decoder Approach** | `last -f /var/log/wtmp`; `utmpdump /var/log/wtmp`; `utmpdump /var/log/wtmp \| grep "\[0\].*1970-01-01"` to detect tampered entries; Plaso `log2timeline.py` for timeline integration |
| **MITRE ATT&CK** | T1070.006 (Indicator Removal: Timestomp), T1070.002 |
| **References** | [Sandfly Security: utmpdump for Forensics](https://sandflysecurity.com/blog/using-linux-utmpdump-for-forensics-and-detecting-log-file-tampering); [Bromiley Medium: Logon History in *tmp Files](https://bromiley.medium.com/torvalds-tuesday-logon-history-in-the-tmp-files-83530b2acc28); [O'Reilly: utmp, wtmp, btmp, lastlog](https://www.oreilly.com/library/view/mastering-linux-security/9781838981778/0eb8bfb5-e9ce-4a05-b893-f39b9e42397e.xhtml) |

---

### 19. `/var/log/btmp` — Failed Login Attempts (Binary)

| Field | Value |
|-------|-------|
| **Location** | `/var/log/btmp` |
| **Format** | Binary; same `struct utmp` format as `wtmp`, 384 bytes per record |
| **Key Fields** | Same fields as `wtmp`; `ut_user` contains the username attempted (may reveal account enumeration); `ut_host` contains source IP; timestamp cluster patterns indicate brute-force |
| **Forensic Value** | Brute-force attack evidence; large file size (gigabytes) on internet-exposed hosts is normal; zeroed records indicate targeted log tampering covering tracks of successful intrusion; surrounding intact records bracket the intrusion timeline; usernames in failed attempts reveal enumerated account names; source IPs for attribution |
| **OS Scope** | All Linux distributions |
| **Data Scope** | System |
| **Decoder Approach** | `lastb -f /var/log/btmp`; `utmpdump /var/log/btmp`; `utmpdump /var/log/btmp \| grep "1970-01-01"` for tampered records; count failures per source IP to identify brute-force campaigns |
| **MITRE ATT&CK** | T1110 (Brute Force), T1070.002 |
| **References** | [Sandfly Security: utmpdump for Forensics](https://sandflysecurity.com/blog/using-linux-utmpdump-for-forensics-and-detecting-log-file-tampering); [TheGeekDiary: utmp/wtmp/btmp](https://www.thegeekdiary.com/what-is-the-purpose-of-utmp-wtmp-and-btmp-files-in-linux/) |

---

### 20. `/var/log/lastlog` — Last Login Per UID (Binary)

| Field | Value |
|-------|-------|
| **Location** | `/var/log/lastlog` |
| **Format** | Binary sparse file; each record indexed by UID (file offset = `UID * sizeof(struct lastlog)`); `struct lastlog` contains `ll_time` (timestamp), `ll_line` (terminal), `ll_host` (remote hostname/IP) |
| **Forensic Value** | Answers "when did each account last authenticate and from where?"; dormant accounts that suddenly show recent logins indicate credential compromise; zero timestamp indicates account has never logged in (or record was zeroed by attacker); cross-reference with `wtmp` — discrepancy indicates tampering; `lastlog` is sparse and thus very fast to parse even for systems with high UIDs |
| **OS Scope** | All Linux distributions |
| **Data Scope** | System |
| **Decoder Approach** | `lastlog` command (displays all entries); `lastlog -u <username>` for specific user; `lastlog -b 7` for logins older than 7 days; Python-native offline parsing via [LastLog-Audit](https://github.com/franckferman/LastLog-Audit) |
| **MITRE ATT&CK** | T1070.006, T1078 |
| **References** | [GitHub: LastLog-Audit](https://github.com/franckferman/LastLog-Audit); [DFIR Notes: Linux Forensics Logs](https://mahmoud-shaker.gitbook.io/dfir-notes/linux-forensics/linux-forensics-logs) |

---

### 21. `/run/utmp` (or `/var/run/utmp`) — Currently Logged-In Users (Binary)

| Field | Value |
|-------|-------|
| **Location** | `/run/utmp` or `/var/run/utmp` (symlinked on most distros) |
| **Format** | Binary; same `struct utmp` format; contains only currently active session records |
| **Key Fields** | Active session entries: username, terminal, source IP, login time; `who` and `w` commands read from this file |
| **Forensic Value** | Shows who is logged in at the moment of acquisition; during live response, reveals active attacker sessions; terminal identifiers (`pts/N`) cross-reference with process trees for session attribution; `utmpdump` reveals any zeroed entries that indicate in-progress tampering |
| **OS Scope** | All Linux distributions |
| **Data Scope** | System |
| **Decoder Approach** | `who` or `w` (live); `utmpdump /run/utmp`; `last -f /run/utmp` |
| **MITRE ATT&CK** | T1033 (System Owner/User Discovery) |
| **References** | [Sandfly Security: utmpdump for Forensics](https://sandflysecurity.com/blog/using-linux-utmpdump-for-forensics-and-detecting-log-file-tampering); [DFIR Notes: Linux Forensics Logs](https://mahmoud-shaker.gitbook.io/dfir-notes/linux-forensics/linux-forensics-logs) |

---

## Cloud and Container Credentials

### 22. AWS CLI Credentials — `~/.aws/credentials`

| Field | Value |
|-------|-------|
| **Location** | `~/.aws/credentials` (primary); `~/.aws/config` (profile configuration); environment variables `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` (supersede file) |
| **Format** | INI-style plaintext with profile sections: `[default]`, `[profile-name]` |
| **Key Fields** | `aws_access_key_id` (20-character AKIA... key ID), `aws_secret_access_key` (40-character secret), `aws_session_token` (temporary STS token — contains base64-encoded JSON with expiry); `~/.aws/config` may contain `role_arn` and `source_profile` for assumed roles |
| **Forensic Value** | Long-term access keys (`AKIA...` prefix) provide persistent cloud access independent of any password or MFA; temporary session tokens (`ASIA...` prefix) expire but may still be valid at time of acquisition; assumed-role chains in `~/.aws/config` reveal cloud privilege escalation paths; credentials survived system reimaging when cloud IAM was not rotated; correlate with CloudTrail for API usage timeline |
| **OS Scope** | All Linux distributions |
| **Data Scope** | User |
| **Decoder Approach** | `cat ~/.aws/credentials`; `cat ~/.aws/config`; `aws sts get-caller-identity` to verify active credentials; `env \| grep AWS_` for environment-variable credentials; check for credential files via `find / -name credentials -path "*/.aws/*"` |
| **MITRE ATT&CK** | T1552.001 (Unsecured Credentials: Credentials In Files), T1078.004 (Valid Accounts: Cloud Accounts) |
| **References** | [AWS EKS: Incident Response and Forensics](https://docs.aws.amazon.com/eks/latest/best-practices/incident-response-and-forensics.html); [Medium: AWS Forensics & Incident Response](https://cloudyforensics.medium.com/aws-forensics-incident-response-3e9533a26485) |

---

### 23. GCP Credentials — `~/.config/gcloud/`

| Field | Value |
|-------|-------|
| **Location** | `~/.config/gcloud/application_default_credentials.json` (ADC OAuth tokens); `~/.config/gcloud/credentials.db` (SQLite, gcloud CLI OAuth tokens); `~/.config/gcloud/access_tokens.db` (SQLite, cached access tokens); `~/.config/gcloud/legacy_credentials/<account>/adc.json` (plaintext backward-compat copy) |
| **Format** | `application_default_credentials.json`: JSON; `credentials.db`/`access_tokens.db`: SQLite 3 |
| **Key Fields** | `client_id`, `client_secret`, `refresh_token` (long-lived, used to mint new access tokens), `access_token` (short-lived, 60 min), `token_uri`; ADC tokens scope `https://www.googleapis.com/auth/cloud-platform` by default (cloud-wide access) |
| **Forensic Value** | Refresh tokens provide persistent cloud access and survive session logout; `legacy_credentials/adc.json` contains cleartext credential structure; ADC credentials created with `gcloud auth application-default login` scope broadly to all GCP APIs; often committed accidentally to version control or left on compromised hosts; specifically noted as "often leveraged in credential compromise incidents" |
| **OS Scope** | All Linux distributions with Google Cloud SDK |
| **Data Scope** | User |
| **Decoder Approach** | `cat ~/.config/gcloud/application_default_credentials.json`; `sqlite3 ~/.config/gcloud/credentials.db ".dump"`; `gcloud auth list` to show active accounts; `env \| grep GOOGLE` for `GOOGLE_APPLICATION_CREDENTIALS` override |
| **MITRE ATT&CK** | T1552.001, T1078.004 |
| **References** | [Google Cloud: How ADC Works](https://docs.cloud.google.com/docs/authentication/application-default-credentials); [GitHub: GCP Credential File Comparison](https://github.com/TheIc3Root/GCP-Credential-File-Comparison); [Medium: ADC with Docker](https://medium.com/datamindedbe/application-default-credentials-477879e31cb5) |

---

### 24. Azure CLI Credentials — `~/.azure/`

| Field | Value |
|-------|-------|
| **Location** | `~/.azure/msal_token_cache.json` or `~/.azure/msal_token_cache.bin` (MSAL token cache); `~/.azure/accessTokens.json` (legacy Azure CLI 1.x); `~/.azure/azureProfile.json` (account metadata) |
| **Format** | `msal_token_cache.json`: JSON with `AccessToken`, `RefreshToken`, `IdToken`, `Account`, `AppMetadata` sections; `.bin` variant is a serialized binary MSAL cache |
| **Key Fields** | `RefreshToken` objects contain `secret` (the actual refresh token), `home_account_id`, `target` (scopes), `realm`; `AccessToken` objects contain `secret` (JWT bearer token), `expires_on`, `cached_at` |
| **Forensic Value** | Refresh tokens provide persistent access to Azure resources; access tokens may still be valid at acquisition time (typically 1-hour TTL); token can be used with `az` CLI or direct REST API calls; scopes in `target` field reveal what Azure resources the token can access; identity tokens (`IdToken`) contain claims about the authenticated user (UPN, tenant ID, object ID) |
| **OS Scope** | All Linux distributions with Azure CLI |
| **Data Scope** | User |
| **Decoder Approach** | `cat ~/.azure/msal_token_cache.json`; parse JSON to extract `RefreshToken[*].secret` values; decode JWT access tokens at jwt.ms or via `python3 -c "import base64, json; print(json.loads(base64.b64decode(token.split('.')[1]+'==')))"`  |
| **MITRE ATT&CK** | T1552.001, T1078.004 |
| **References** | [GCP Credential Comparison (Azure context)](https://github.com/TheIc3Root/GCP-Credential-File-Comparison); [Medium: AWS Forensics (cloud credential patterns)](https://cloudyforensics.medium.com/aws-forensics-incident-response-3e9533a26485) |

---

### 25. Docker Registry Credentials — `~/.docker/config.json`

| Field | Value |
|-------|-------|
| **Location** | `~/.docker/config.json`; alternate: `${XDG_CONFIG_HOME}/containers/auth.json` (`~/.config/containers/auth.json`); legacy: `~/.dockercfg` |
| **Format** | JSON; `auths` object keys are registry URLs; values contain `auth` field (Base64-encoded `username:password`) or are empty if using a credential helper |
| **Key Fields** | `auths.<registry-url>.auth`: Base64 of `username:password` (trivially reversible, NOT encrypted); `credsStore`: name of credential helper binary; `credHelpers`: per-registry credential helper overrides |
| **Forensic Value** | `auth` field is Base64 — not encrypted — and reveals registry username and password (or token) with a single `base64 -d` decode; even when `auth` is empty, the registry URL in `auths` keys reveals which container registries the user authenticated with; Docker Hub tokens, ECR tokens, and private registry credentials stored here; service account key files used as Docker passwords appear in Base64 form |
| **OS Scope** | All Linux distributions with Docker |
| **Data Scope** | User |
| **Decoder Approach** | `cat ~/.docker/config.json \| jq '.auths \| keys'` (list registries); `echo "<base64_auth>" \| base64 -d` (decode credentials); `docker-credential-secretservice list` if credential helper is configured |
| **MITRE ATT&CK** | T1552.001, T1078.004, T1078.003 |
| **References** | [Docker Docs: docker login](https://docs.docker.com/reference/cli/docker/login/); [LinuxVox: Docker Registry Login Files](https://linuxvox.com/blog/where-are-the-docker-registry-login-files/); [Luis Cacho: Docker Login the Right Way](https://luiscachog.io/docker-login-the-right-way/) |

---

### 26. Kubernetes Config — `~/.kube/config`

| Field | Value |
|-------|-------|
| **Location** | `~/.kube/config` (default); path overridden by `KUBECONFIG` environment variable (can reference multiple files) |
| **Format** | YAML |
| **Key Fields** | `clusters[].cluster.server` (API server URL), `users[].user.token` (bearer token — direct API auth), `users[].user.client-certificate-data` (Base64 PEM cert), `users[].user.client-key-data` (Base64 PEM private key), `users[].user.exec` (credential plugin command — e.g., `aws eks get-token`), `contexts[]` (maps cluster + user + namespace) |
| **Forensic Value** | Bearer tokens in `token` field provide immediate API access without further authentication; client key material (`client-key-data`) provides certificate-based auth; EKS clusters using `aws eks get-token` exec plugin will regenerate tokens using the AWS credentials on the system (chain of compromise: AWS creds → EKS access); compromise of worker node credentials allows impersonation of `system:nodes` group — enabling enumeration of all pods and pod service account tokens |
| **OS Scope** | All Linux distributions with kubectl |
| **Data Scope** | User |
| **Decoder Approach** | `kubectl config view --raw` (shows decrypted values); `cat ~/.kube/config \| python3 -c "import sys,yaml; c=yaml.safe_load(sys.stdin); [print(u['user']) for u in c['users']]"`; `env \| grep KUBECONFIG` |
| **MITRE ATT&CK** | T1552.001, T1078.004, T1552.007 (Unsecured Credentials: Container API) |
| **References** | [AWS EKS: Incident Response and Forensics](https://docs.aws.amazon.com/eks/latest/best-practices/incident-response-and-forensics.html); [Datadog Security Labs: Attacking EKS](https://securitylabs.datadoghq.com/articles/amazon-eks-attacking-securing-cloud-identities/); [MITRE T1552.007](https://attack.mitre.org/techniques/T1552/007/) |

---

## Network Credentials

### 27. WiFi Credentials — `/etc/NetworkManager/system-connections/`

| Field | Value |
|-------|-------|
| **Location** | `/etc/NetworkManager/system-connections/*.nmconnection` (NetworkManager); `/etc/wpa_supplicant/wpa_supplicant.conf` (wpa_supplicant legacy) |
| **Format** | INI-style plaintext; mode 0600, readable only by root |
| **Key Fields** | `[wifi-security]` section: `key-mgmt=wpa-psk`, `psk=<plaintext_passphrase>`; `[connection]` section: `id=<SSID_name>`, `uuid=<connection_uuid>`; `psk-flags=1` means PSK is stored in GNOME Keyring instead of the file |
| **Forensic Value** | WiFi PSK stored in plaintext if `psk-flags=0` (default for many setups); exposes home/office network credentials that enable physical network re-access; reveals historical network connections (place of activity evidence); on unencrypted drives or stolen laptops, file is directly readable despite mode 0600; SSID history maps physical locations the device has been used |
| **OS Scope** | All Linux distributions using NetworkManager (most modern distros) |
| **Data Scope** | System |
| **Decoder Approach** | `sudo grep -r '^psk=' /etc/NetworkManager/system-connections/`; `sudo cat /etc/NetworkManager/system-connections/<SSID>.nmconnection`; `sudo nmcli connection show "<SSID>" \| grep psk` |
| **MITRE ATT&CK** | T1552.001 (Unsecured Credentials: Credentials In Files) |
| **References** | [Baeldung: WiFi Passwords Location](https://www.baeldung.com/linux/wifi-passwords-location); [ArchWiki: NetworkManager](https://wiki.archlinux.org/title/NetworkManager); [nm-settings Reference](https://people.freedesktop.org/~lkundrak/nm-docs/nm-settings.html) |

---

### 28. WireGuard VPN Configuration — `/etc/wireguard/`

| Field | Value |
|-------|-------|
| **Location** | `/etc/wireguard/wg0.conf` (primary interface config); `/etc/wireguard/privatekey` (private key file, if separated); `/etc/wireguard/keys/` (key directory, if used) |
| **Format** | INI-style plaintext; mode 0600, readable only by root |
| **Key Fields** | `[Interface]` section: `PrivateKey=<base64_private_key>` (32-byte Curve25519 key), `ListenPort`, `Address`; `[Peer]` sections: `PublicKey=<base64_public_key>`, `PresharedKey=<base64_psk>` (optional additional symmetric key), `AllowedIPs`, `Endpoint` (remote host:port); `SaveConfig=true` causes runtime state to be written back to file on shutdown |
| **Forensic Value** | `PrivateKey` in `wg0.conf` provides full VPN impersonation capability; `PresharedKey` per peer pair provides an additional credential layer; `Endpoint` fields reveal VPN server addresses and ports; `AllowedIPs` maps routed network ranges; `SaveConfig=true` means the file reflects the runtime state at last shutdown; WireGuard has no built-in comment support for key attribution — identification requires cross-referencing public keys |
| **OS Scope** | All Linux distributions (WireGuard in kernel since Linux 5.6) |
| **Data Scope** | System |
| **Decoder Approach** | `sudo cat /etc/wireguard/wg0.conf`; `sudo wg show` (live interface state); `wg pubkey < /etc/wireguard/privatekey` (derive public key from private key for identification) |
| **MITRE ATT&CK** | T1552.001, T1552.004 |
| **References** | [Ubuntu Server: WireGuard Security Tips](https://ubuntu.com/server/docs/how-to/wireguard-vpn/security-tips/); [ArchWiki: WireGuard](https://wiki.archlinux.org/title/WireGuard); [Linuxize: WireGuard on Ubuntu](https://linuxize.com/post/how-to-set-up-wireguard-vpn-on-ubuntu-20-04/) |

---

### 29. OpenVPN Configuration — `/etc/openvpn/`

| Field | Value |
|-------|-------|
| **Location** | `/etc/openvpn/*.conf`, `/etc/openvpn/client/*.conf`, `/etc/openvpn/server/*.conf`; `.ovpn` files may be copied here for autostart |
| **Format** | Plaintext; may contain inline certificate/key blocks (`<ca>`, `<cert>`, `<key>`, `<tls-auth>`, `<tls-crypt>`) |
| **Key Fields** | `auth-user-pass <file>` (plaintext username/password file); inline `<key>` blocks (RSA/EC private key); `tls-auth <keyfile> <direction>` (HMAC pre-shared key); `tls-crypt <keyfile>` (symmetric key encrypting TLS control channel); `remote <host> <port>` (VPN server) |
| **Forensic Value** | Inline private keys enable VPN impersonation; `auth-user-pass` files may contain plaintext credentials; `tls-auth`/`tls-crypt` keys provide VPN authentication bypass capability; remote server addresses reveal VPN infrastructure |
| **OS Scope** | All Linux distributions |
| **Data Scope** | System |
| **Decoder Approach** | `sudo cat /etc/openvpn/*.conf`; look for `auth-user-pass` and `<key>` inline sections; `grep -r 'BEGIN\|auth-user-pass' /etc/openvpn/` |
| **MITRE ATT&CK** | T1552.001, T1552.004 |
| **References** | [InfoSec Write-ups: OpenVPN and WireGuard on Linux](https://infosecwriteups.com/a-step-by-step-guide-to-setting-up-openvpn-and-wireguard-on-linux-for-secure-networking-83c05f65b146) |

---

## Application Credentials

### 30. Git Credentials — `~/.git-credentials`

| Field | Value |
|-------|-------|
| **Location** | `~/.git-credentials` (default credential store location for `git credential-store` helper); `~/.netrc` (also read by Git for credential lookup) |
| **Format** | Plaintext; one URL per line: `protocol://username:password@host` |
| **Key Fields** | Full credential URLs including plaintext passwords or personal access tokens (PATs); GitHub, GitLab, Bitbucket, and private Git server credentials |
| **Forensic Value** | Plaintext credentials for source code repositories; PATs often have broad scopes (repo, admin, read:org) and long expiry; stolen repository credentials enable source code exfiltration, CI/CD pipeline compromise, and secrets committed to repository history; correlate with `~/.gitconfig` to identify `credential.helper=store` configuration which activates this file |
| **OS Scope** | All Linux distributions |
| **Data Scope** | User |
| **Decoder Approach** | `cat ~/.git-credentials`; `cat ~/.netrc`; `git config --global credential.helper` to confirm helper type; `find /home -name ".git-credentials" 2>/dev/null` |
| **MITRE ATT&CK** | T1552.001 (Unsecured Credentials: Credentials In Files) |
| **References** | [MITRE T1552.001](https://attack.mitre.org/techniques/T1552/001/); [GitHub: Atomic Red Team T1552.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md); [Juggernaut-Sec: Password Hunting](https://juggernaut-sec.com/password-hunting-lpe/) |

---

### 31. `.netrc` — FTP/HTTP Credential Store

| Field | Value |
|-------|-------|
| **Location** | `~/.netrc` |
| **Format** | Plaintext; `machine <host> login <user> password <pass>` stanzas |
| **Key Fields** | `machine` (hostname or `default` wildcard), `login` (username), `password` (plaintext password); used by `ftp`, `curl`, `wget`, and Git |
| **Forensic Value** | Plaintext credentials for multiple services in a single file; `default` stanza applies to any unmatched host — a global credential; curl uses `.netrc` automatically when `-n` flag is present; historically used for FTP but also captures web service credentials; widely present on developer and server systems |
| **OS Scope** | All Linux distributions |
| **Data Scope** | User |
| **Decoder Approach** | `cat ~/.netrc`; `find /home /root -name ".netrc" 2>/dev/null` |
| **MITRE ATT&CK** | T1552.001 |
| **References** | [MITRE T1552.001](https://attack.mitre.org/techniques/T1552/001/); [Atomic Red Team T1552.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md) |

---

### 32. Shell History Files — `~/.bash_history`, `~/.zsh_history`

| Field | Value |
|-------|-------|
| **Location** | `~/.bash_history` (Bash); `~/.zsh_history` (Zsh, extended format with timestamps); `~/.python_history`, `~/.mysql_history`, `~/.psql_history` (per-application histories) |
| **Format** | Plaintext; one command per line (Bash); Zsh extended format: `: <timestamp>:<elapsed>;<command>`; controlled by `HISTFILE`, `HISTSIZE`, `HISTFILESIZE` environment variables |
| **Key Fields** | Command entries containing `-p <password>`, `--password`, `mysql -u root -p`, `curl -u user:pass`, `export SECRET=`, `PGPASSWORD=`, `sshpass -p`, `openssl` with embedded keys |
| **Forensic Value** | Credentials typed as command-line arguments are recorded verbatim; reveals tools and techniques used on the system; timeline of attacker activity when timestamps are available (Zsh); reveals targets of lateral movement (SSH commands, database connections); `HISTCONTROL=ignorespace` or `ignoreboth` means commands prefixed with a space are not logged — absence of history may indicate deliberate evasion; `~/.mysql_history` and `~/.psql_history` capture database queries including `ALTER USER` and `SET PASSWORD` |
| **OS Scope** | All Linux distributions |
| **Data Scope** | User |
| **Decoder Approach** | `cat ~/.bash_history`; `grep -E 'password\|passwd\|secret\|token\|key\|api' ~/.bash_history`; check `HISTCONTROL` and `HISTFILE` settings in `~/.bashrc`; `find /home /root -name ".*_history" 2>/dev/null` |
| **MITRE ATT&CK** | T1552.003 (Unsecured Credentials: Shell History) |
| **References** | [MITRE T1552.003](https://attack.mitre.org/techniques/T1552/003/); [ZeroDollarSoc: Bash History Credential Access](https://zerodollarsoc.com/blog/2021/04/05/t1552-003-bash-history-credential-access/); [Atomic Red Team T1552.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.003/T1552.003.md) |

---

## Memory-Resident Credentials

### 33. Process Environment Variables — `/proc/<PID>/environ`

| Field | Value |
|-------|-------|
| **Location** | `/proc/<PID>/environ` for each running process PID |
| **Format** | Binary; null-byte delimited `KEY=VALUE` pairs; readable by process owner or root (requires `CAP_SYS_PTRACE` for other processes) |
| **Key Fields** | `PASSWORD=`, `SECRET=`, `API_KEY=`, `TOKEN=`, `AWS_ACCESS_KEY_ID=`, `AWS_SECRET_ACCESS_KEY=`, `DATABASE_URL=`, `PGPASSWORD=`, `MYSQL_ROOT_PASSWORD=`, `REDIS_URL=` (common secret environment variable names) |
| **Forensic Value** | Applications (especially containers and 12-factor apps) frequently load secrets via environment variables; these persist in `/proc` for the lifetime of the process; reading environment of `sshd`, `sudo`, web servers, or database clients may reveal credentials; child processes inherit parent environment — a compromised shell may expose all inherited secrets; `HISTCONTROL` and `HISTFILE` settings reveal evasion configuration |
| **OS Scope** | All Linux distributions |
| **Data Scope** | User / System |
| **Decoder Approach** | `sudo cat /proc/<PID>/environ \| tr '\0' '\n'`; `sudo strings /proc/<PID>/environ \| grep -iE 'pass\|secret\|key\|token\|auth'`; Volatility3: `linux.environ` plugin; enumerate via `find /proc -maxdepth 2 -name environ` |
| **MITRE ATT&CK** | T1003.007 (OS Credential Dumping: Proc Filesystem), T1552.001 |
| **References** | [Medium: Linux Memory Analysis & Credential Hunting](https://medium.com/@cybersecplayground/linux-memory-analysis-credential-hunting-procfs-live-processes-12ddccfaa595); [Medium: Process Environment Forensics](https://medium.com/digital-forensics-deep-learning-and-dev/process-environment-forensics-952f3e688af9); [MITRE T1003.007](https://attack.mitre.org/techniques/T1003/007/) |

---

### 34. Process Memory — `/proc/<PID>/mem`

| Field | Value |
|-------|-------|
| **Location** | `/proc/<PID>/mem` (binary virtual memory image); `/proc/<PID>/maps` (memory map — required to identify readable regions) |
| **Format** | Binary; mapped virtual memory of the process; readable regions identified by `r` flag in `/proc/<PID>/maps`; requires `CAP_SYS_PTRACE` with `PTRACE_MODE_ATTACH` for other-process access (stricter than `environ`) |
| **Key Fields** | Heap and stack regions contain decrypted credentials, session tokens, and private keys that applications hold in memory; `rwxp` (read-write-execute private) regions may indicate injected code or shellcode; `[stack]` and `[heap]` labels in maps identify key regions |
| **Forensic Value** | The definitive source for cleartext credentials in memory: even encrypted-at-rest credentials are decrypted in memory during use; `sshd`, `sudo`, `gpg-agent`, `gnome-keyring-daemon`, and web browsers hold plaintext credentials in heap; `mimipenguin` exploits `gnome-keyring-daemon` memory; `procdump` on browser processes extracts cookies and passwords; `3snake` traces `sshd` read/write syscalls to capture passwords; CVE-2025-5054 and CVE-2025-4598 expose credential extraction via core dump race conditions |
| **OS Scope** | All Linux distributions; `ptrace_scope` setting (`/proc/sys/kernel/yama/ptrace_scope`) may restrict access (0=permissive, 1=restricted, 2=admin-only, 3=disabled) |
| **Data Scope** | User / System |
| **Decoder Approach** | Read maps first: `sudo cat /proc/<PID>/maps`; extract heap: `dd if=/proc/<PID>/mem bs=1 skip=<start_addr> count=<size>`; `strings /proc/<PID>/mem \| grep -iE 'password\|token\|secret'`; Volatility3: `linux.bash`, `linux.cmdline`, `linux.hashdump`, `linux.ssh_keys` plugins; GDB: `gdb -p <PID>` then `find &__data_start__, +9999999, "password"` |
| **MITRE ATT&CK** | T1003.007 (OS Credential Dumping: Proc Filesystem) |
| **References** | [Elastic: Potential Linux Credential Dumping via Proc Filesystem](https://www.elastic.co/guide/en/security/8.19/potential-linux-credential-dumping-via-proc-filesystem.html); [Medium: Leveraging /proc for Linux Live Forensics](https://medium.com/@mehrnoush/leveraging-the-proc-filesystem-for-linux-live-forensics-a-comprehensive-guide-9263f647c77f); [MITRE T1003.007](https://attack.mitre.org/techniques/T1003/007/) |

---

### 35. Process Command-Line Arguments — `/proc/<PID>/cmdline`

| Field | Value |
|-------|-------|
| **Location** | `/proc/<PID>/cmdline` for each running process PID |
| **Format** | Binary; null-byte delimited argument strings; readable by all users for own processes; requires ptrace permission for other-process access |
| **Key Fields** | Arguments containing `--password`, `-p`, `--token`, `--secret`, `-e PASSWORD=`, `mysql -u root -p<password>`, `psql -U user -W` (password prompts), `curl -H "Authorization: Bearer <token>"` |
| **Forensic Value** | Passwords and tokens passed as CLI arguments are visible to all users via `ps aux` and persist in `/proc/cmdline` for the lifetime of the process; scripts and automated jobs commonly pass credentials as arguments; correlate with shell history for pre-execution evidence; process start time from `/proc/<PID>/stat` provides temporal context |
| **OS Scope** | All Linux distributions |
| **Data Scope** | User / System |
| **Decoder Approach** | `sudo cat /proc/<PID>/cmdline \| tr '\0' ' '`; `ps auxe \| grep -iE 'pass\|secret\|token'`; Volatility3: `linux.cmdline` plugin; `find /proc -maxdepth 2 -name cmdline -exec sh -c 'tr "\0" " " < {}; echo' \;` |
| **MITRE ATT&CK** | T1003.007, T1552.001 |
| **References** | [Group-IB: /proc Filesystem Manipulation](https://www.group-ib.com/blog/linux-pro-manipulation/); [Kernel: /proc Filesystem Documentation](https://docs.kernel.org/filesystems/proc.html); [Andrea Fortuna: Peeking into /proc](https://andreafortuna.org/2026/01/19/proc-filesystem) |

---

### 36. Core Dump Files — `~/*.core`, `/var/lib/systemd/coredump/`, `/var/core/`

| Field | Value |
|-------|-------|
| **Location** | `/var/lib/systemd/coredump/` (systemd-coredump, RHEL/Fedora); `/var/lib/apport/coredump/` (Apport, Ubuntu/Debian); `/tmp/*.core`, `~/*.core` (application-configured paths); controlled by `core_pattern` in `/proc/sys/kernel/core_pattern` |
| **Format** | ELF binary (standard Linux core format); contains full snapshot of process virtual memory at crash time |
| **Key Fields** | All in-memory data at crash time: heap, stack, mapped libraries; includes decrypted credentials, session tokens, private keys, and cached authentication material; ELF PT_NOTE segments contain process metadata (registers, signal info) |
| **Forensic Value** | Core dumps capture the complete memory state at crash time — including all plaintext credentials the process held; CVE-2025-5054 (Apport) and CVE-2025-4598 (systemd-coredump) allow low-privilege users to extract `shadow` file contents by crashing `unix_chkpwd`; `strings` on a browser core dump extracts passwords and cookies; `mimipenguin`-style analysis on `gnome-keyring-daemon` core dumps; `/proc/sys/fs/suid_dumpable=0` disables core dumps for SUID programs (mitigation); files often world-readable by default |
| **OS Scope** | All Linux distributions; `systemd-coredump` on RHEL/Fedora; Apport on Ubuntu/Debian |
| **Data Scope** | User / System |
| **Decoder Approach** | `strings <corefile> \| grep -iE 'password\|token\|secret\|BEGIN.*KEY'`; `gdb <binary> <corefile>` then `info proc mappings` and `x/s <addr>`; Volatility3 can analyze ELF core files; `eu-stack` (elfutils) for stack trace extraction |
| **MITRE ATT&CK** | T1003.007, T1005 (Data from Local System) |
| **References** | [Infosecurity Magazine: Linux Vulnerabilities Expose Password Hashes](https://www.infosecurity-magazine.com/news/linux-vulnerabilities-expose/); [BankInfoSecurity: Linux Crash Dump Flaws](https://www.bankinfosecurity.com/linux-crash-dump-flaws-expose-passwords-encryption-keys-a-28560); [Embrace The Red: procdump on Linux](https://embracethered.com/blog/posts/2021/linux-procdump/) |

---

## MITRE ATT&CK Quick Reference

| Technique | Sub-technique | Name | Artifacts Covered |
|-----------|--------------|------|------------------|
| T1003 | .007 | OS Credential Dumping: Proc Filesystem | `/proc/<PID>/mem`, `/proc/<PID>/environ`, `/proc/<PID>/cmdline`, core dumps |
| T1003 | .008 | OS Credential Dumping: /etc/passwd and /etc/shadow | `/etc/passwd`, `/etc/shadow` |
| T1021 | .004 | Remote Services: SSH | SSH config, authorized_keys, known_hosts |
| T1033 | — | System Owner/User Discovery | `/run/utmp`, `w`, `who` |
| T1070 | .002 | Indicator Removal: Clear Linux Logs | `wtmp`, `btmp`, `auth.log` tampering |
| T1070 | .006 | Indicator Removal: Timestomp | `lastlog`, `wtmp` record zeroing |
| T1078 | .003 | Valid Accounts: Local Accounts | `/etc/passwd`, `/etc/shadow`, sudo |
| T1078 | .004 | Valid Accounts: Cloud Accounts | AWS credentials, GCP ADC, Azure MSAL |
| T1098 | .004 | Account Manipulation: SSH Authorized Keys | `~/.ssh/authorized_keys` |
| T1110 | — | Brute Force | `btmp`, `auth.log` |
| T1110 | .002 | Brute Force: Password Cracking | `/etc/shadow` hash cracking |
| T1136 | .001 | Create Account: Local Account | `/etc/passwd`, `/etc/group` |
| T1548 | .003 | Abuse Elevation Control Mechanism: Sudo | `/etc/sudoers`, `sudoers.d/` |
| T1552 | .001 | Unsecured Credentials: Credentials In Files | `.git-credentials`, `.netrc`, WiFi PSK, cloud credentials |
| T1552 | .003 | Unsecured Credentials: Shell History | `~/.bash_history`, `~/.zsh_history` |
| T1552 | .004 | Unsecured Credentials: Private Keys | SSH private keys, GPG private keys, VPN private keys |
| T1552 | .007 | Unsecured Credentials: Container API | `~/.kube/config`, Docker config |
| T1555 | — | Credentials from Password Stores | GNOME Keyring, KDE KWallet, kernel keyring |
| T1555 | .003 | Credentials from Web Browsers | Chrome Login Data, Firefox logins.json |

---

## Key Forensic Tool Reference

| Tool | Purpose | Artifacts |
|------|---------|-----------|
| `last` / `lastb` | Parse wtmp/btmp | Login history |
| `utmpdump` | Dump and detect tampering in binary log files | wtmp, btmp, utmp |
| `lastlog` | Display last login per user | lastlog |
| `secret-tool` | Query GNOME Keyring via D-Bus | GNOME Keyring |
| `ssh-keygen -l -f` | Display SSH key fingerprints | SSH keys |
| `sqlite3` | Parse browser and cloud credential databases | Chrome Login Data, Firefox key4.db, GCP credentials.db |
| `firepwd` | Decrypt Firefox credentials | logins.json + key4.db |
| `unshadow` | Merge passwd/shadow for password crackers | /etc/passwd, /etc/shadow |
| `john` / `hashcat` | Crack password hashes | /etc/shadow |
| `gpg --list-secret-keys` | Enumerate GPG private keys | ~/.gnupg/ |
| `keyctl show` | Display kernel keyring contents | Kernel keyrings |
| `volatility3` | Memory forensics | /proc/mem, core dumps |
| `mimipenguin` | Extract cleartext passwords from memory | gnome-keyring-daemon, sshd |
| `LaZagne` | Multi-source credential extraction | Browser, SSH, cloud, database credentials |
| Plaso / log2timeline | Timeline from binary logs | wtmp, btmp, lastlog |

---

*All artifact information verified against primary sources. Hash algorithm prefixes per [linux.die.net shadow(5)](https://linux.die.net/man/5/shadow) and [Baeldung on Linux](https://www.baeldung.com/linux/shadow-passwords). MITRE technique IDs from [attack.mitre.org](https://attack.mitre.org/tactics/TA0006/).*
