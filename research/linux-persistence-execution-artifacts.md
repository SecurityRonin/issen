# Linux Persistence & Execution Evidence Artifacts — Comprehensive Catalog

**Compiled:** 2026-04-13  
**Scope:** Linux (all distributions unless noted)  
**Primary use case:** Digital forensics, incident response, threat hunting  
**Coverage:** 40 artifacts spanning all major persistence categories

---

## Table of Contents

1. [Scheduled Execution — Cron](#1-scheduled-execution--cron)
   - /etc/crontab
   - /etc/cron.d/ drop-ins
   - Per-directory cron runners (daily/hourly/weekly/monthly)
   - /var/spool/cron/crontabs/{user}
   - /etc/anacrontab and /var/spool/anacron
   - AT job queue (/var/spool/at)
2. [Systemd Persistence](#2-systemd-persistence)
   - Service unit files (system-level)
   - Service unit files (user-level)
   - Systemd timer units
   - Systemd generators
3. [Init-Based Persistence (SysV / Upstart)](#3-init-based-persistence-sysv--upstart)
   - /etc/rc.local
   - /etc/init.d/* (SysV scripts)
   - /etc/inittab
   - Upstart /etc/init/*.conf
4. [Shell and Environment Persistence](#4-shell-and-environment-persistence)
   - ~/.bashrc / ~/.bash_profile / ~/.profile
   - /etc/profile and /etc/profile.d/*
   - Zsh startup files (~/.zshrc, ~/.zprofile, ~/.zlogin, ~/.zshenv)
   - /etc/bash.bashrc and /etc/environment
   - Shell history files
5. [Library / Dynamic Linker Persistence](#5-library--dynamic-linker-persistence)
   - /etc/ld.so.preload
   - /etc/ld.so.conf and /etc/ld.so.conf.d/*
6. [PAM (Pluggable Authentication Modules)](#6-pam-pluggable-authentication-modules)
   - /etc/pam.d/* and /etc/pam.conf
   - PAM module binaries
7. [Kernel Modules](#7-kernel-modules)
   - /etc/modules and /etc/modules-load.d/*
   - /proc/modules (live)
8. [SSH Persistence](#8-ssh-persistence)
   - ~/.ssh/authorized_keys
   - /etc/ssh/sshd_config
   - ~/.ssh/rc
9. [Sudo and Privilege Persistence](#9-sudo-and-privilege-persistence)
   - /etc/sudoers and /etc/sudoers.d/*
   - SUID/SGID binaries
10. [Package Manager Persistence](#10-package-manager-persistence)
    - /etc/apt/apt.conf.d/* (Debian/Ubuntu)
    - DPKG maintainer scripts
    - RPM/DNF plugins
11. [MOTD / Login Execution](#11-motd--login-execution)
    - /etc/update-motd.d/*
12. [Udev Rules](#12-udev-rules)
    - /etc/udev/rules.d/* and /lib/udev/rules.d/*
13. [XDG Autostart Entries](#13-xdg-autostart-entries)
    - ~/.config/autostart/*.desktop
    - /etc/xdg/autostart/*.desktop
14. [Web Shells](#14-web-shells)
    - /var/www/* and web document roots
15. [Git Hooks](#15-git-hooks)
    - .git/hooks/* (project-level)
    - /etc/gitconfig hooks.hooksPath
16. [Pre-OS Boot Persistence](#16-pre-os-boot-persistence)
    - GRUB configuration (/boot/grub/grub.cfg)
    - MBR / UEFI bootkits
17. [Traffic Signaling (Port Knocking)](#17-traffic-signaling-port-knocking)
    - knockd / iptables-based port knocking
18. [Account Manipulation](#18-account-manipulation)
    - /etc/passwd, /etc/shadow — backdoor users
19. [Cron Log Evidence](#19-cron-log-evidence)
    - /var/log/syslog, /var/log/cron

---

## 1. Scheduled Execution — Cron

### /etc/crontab (System Crontab)

| Field | Value |
|-------|-------|
| **Location** | `/etc/crontab` |
| **Format** | Text (7-field format: `minute hour dom month dow user command`) |
| **Key Fields** | Schedule fields (0-4), username field (col 6), command (col 7+); `MAILTO`, `PATH`, `SHELL` vars at top |
| **Forensic Value** | Proves scheduled command execution as any system user; attacker-added lines establish recurring malware execution or C2 callback intervals |
| **OS Scope** | All Linux |
| **Data Scope** | System |
| **Decoder Approach** | Line-by-line; skip comment lines (`#`); regex `^\s*(?!\s*#)(\S+\s+){5}\S+\s+.+$` for valid entries; parse `MAILTO=` to detect log suppression (`MAILTO=""`) |
| **MITRE ATT&CK** | T1053.003 (Cron) |
| **References** | [MITRE T1053.003](https://attack.mitre.org/techniques/T1053/003/) · [DFIR Cron Jobs](https://nk0.gitbook.io/dfir/linux/forensics/cron-jobs) |

**Forensic notes:** Attackers frequently set `MAILTO=""` to suppress cron-generated output emails, preventing log trails. Entries in `/etc/crontab` run with the user specified in column 6, unlike user crontabs. Look for commands referencing `/tmp`, `/var/tmp`, `/dev/shm`, or base64-encoded one-liners. Timestamps on the file itself (`stat /etc/crontab`) reveal when it was last modified.

---

### /etc/cron.d/* (Drop-in Crontab Files)

| Field | Value |
|-------|-------|
| **Location** | `/etc/cron.d/` |
| **Format** | Text (same 7-field format as `/etc/crontab`; one file per job or package) |
| **Key Fields** | Same as `/etc/crontab`; filename itself is forensically significant |
| **Forensic Value** | Attackers drop inconspicuous files here (e.g., named after legitimate packages) to persist scheduled tasks without editing the main crontab; survives package reinstalls |
| **OS Scope** | All Linux (systemd and SysV) |
| **Data Scope** | System |
| **Decoder Approach** | Enumerate all files; parse each like `/etc/crontab`; compare against package-manager manifest to find orphan files |
| **MITRE ATT&CK** | T1053.003 |
| **References** | [MITRE T1053.003](https://attack.mitre.org/techniques/T1053/003/) · [Linux Forensics Cheatsheet](https://fareedfauzi.github.io/cheatsheets/linux-forensics/) |

---

### /etc/cron.{daily,hourly,weekly,monthly}/ (Run-Parts Directories)

| Field | Value |
|-------|-------|
| **Location** | `/etc/cron.daily/`, `/etc/cron.hourly/`, `/etc/cron.weekly/`, `/etc/cron.monthly/` |
| **Format** | Executable scripts (shell, Python, Perl, etc.) invoked by `run-parts` |
| **Key Fields** | Script content; file ownership and permissions; modification timestamp |
| **Forensic Value** | Executable scripts in these directories run automatically at the named interval as root; attackers drop malicious scripts here because they appear alongside legitimate system-maintenance scripts (e.g., logrotate, apt-daily) |
| **OS Scope** | All Linux |
| **Data Scope** | System |
| **Decoder Approach** | List and read all files; check execute bit; hash against baseline; look for reverse-shell patterns, `wget`/`curl` download cradles, base64 payloads |
| **MITRE ATT&CK** | T1053.003 |
| **References** | [MITRE T1053.003](https://attack.mitre.org/techniques/T1053/003/) · [Elastic Linux Persistence Primer](https://www.elastic.co/security-labs/primer-on-persistence-mechanisms) |

---

### /var/spool/cron/crontabs/{username} (Per-User Crontabs)

| Field | Value |
|-------|-------|
| **Location** | `/var/spool/cron/crontabs/{username}` (Debian/Ubuntu: `/var/spool/cron/crontabs/`; RHEL: `/var/spool/cron/`) |
| **Format** | Text (5-field format: `minute hour dom month dow command`; no username column) |
| **Key Fields** | Schedule fields, command field; `MAILTO`, `PATH` env overrides at top of file |
| **Forensic Value** | Per-user cron jobs; does not require root to create (only `crontab -e`); frequently used by attackers after initial non-root compromise to maintain persistence within that user context |
| **OS Scope** | All Linux |
| **Data Scope** | User |
| **Decoder Approach** | Enumerate all files under the spool directory; parse 5-field crontab lines; correlate user name with `/etc/passwd` to validate user exists |
| **MITRE ATT&CK** | T1053.003 |
| **References** | [MITRE T1053.003](https://attack.mitre.org/techniques/T1053/003/) · [Cron Jobs DFIR](https://nk0.gitbook.io/dfir/linux/forensics/cron-jobs) |

---

### /etc/anacrontab and /var/spool/anacron/ (Anacron)

| Field | Value |
|-------|-------|
| **Location** | `/etc/anacrontab` (job definitions); `/var/spool/anacron/` (per-job timestamp files) |
| **Format** | Text; format: `period delay job-id command` |
| **Key Fields** | `period` (days), `delay` (minutes after boot), `job-id` (name used for timestamp file), `command` |
| **Forensic Value** | Anacron guarantees deferred execution of missed jobs on systems not running 24/7; attackers use it as a cron fallback on non-server systems (laptops, endpoints); timestamp files in `/var/spool/anacron/` reveal exact last-run dates |
| **OS Scope** | All Linux; common on desktop/laptop installs |
| **Data Scope** | System |
| **Decoder Approach** | Parse `/etc/anacrontab` for job lines; read timestamp files in `/var/spool/anacron/` (contain a single date string `YYYYMMDD`); correlate job last-run against system events |
| **MITRE ATT&CK** | T1053.003 |
| **References** | [anacron(8) man page](https://man7.org/linux/man-pages/man8/anacron.8.html) · [Cron vs Anacron - Tecmint](https://www.tecmint.com/cron-vs-anacron-schedule-jobs-using-anacron-on-linux/) |

---

### /var/spool/at/* (AT Job Queue)

| Field | Value |
|-------|-------|
| **Location** | `/var/spool/at/` (job files, binary-ish); `/var/spool/at/spool/` on some distros; access control via `/etc/at.allow`, `/etc/at.deny` |
| **Format** | Mixed text/binary; job files contain shell script header plus serialized environment |
| **Key Fields** | Execution time (encoded in filename), job script content, submitting user |
| **Forensic Value** | One-shot scheduled execution; attackers use `at` for deferred payload execution (e.g., hours after initial compromise to evade temporal correlation); job files persist until executed or deleted |
| **OS Scope** | All Linux |
| **Data Scope** | User / System |
| **Decoder Approach** | List files in `/var/spool/at/`; read each as text (skip binary header); parse `at -l` output equivalent; correlate job creation time with compromise timeline |
| **MITRE ATT&CK** | T1053.001 (At — Linux) |
| **References** | [MITRE T1053.001](https://attack.mitre.org/techniques/T1053/001/) · [Linux Forensics Cheatsheet](https://fareedfauzi.github.io/cheatsheets/linux-forensics/) |

---

## 2. Systemd Persistence

### System-Level Service Unit Files

| Field | Value |
|-------|-------|
| **Location** | `/etc/systemd/system/*.service` (admin-managed, highest priority); `/lib/systemd/system/*.service` or `/usr/lib/systemd/system/*.service` (package-installed) |
| **Format** | INI-style text (`[Unit]`, `[Service]`, `[Install]` sections) |
| **Key Fields** | `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`, `Restart=`, `RestartSec=`, `User=`, `WantedBy=`, `After=`, `Description=` |
| **Forensic Value** | Malicious service units survive reboots and run with configurable user context; `Restart=always` with short `RestartSec=` provides automatic respawn after kill; orphan `.service` files in `/etc/systemd/system/` not associated with any installed package are high-confidence IOCs |
| **OS Scope** | systemd-based Linux (Debian 8+, Ubuntu 16.04+, RHEL 7+, Fedora 15+, Arch) |
| **Data Scope** | System |
| **Decoder Approach** | Parse INI sections; extract `ExecStart` value; compare unit file list against package manager database; inspect `[Install]` `WantedBy` to understand boot integration |
| **MITRE ATT&CK** | T1543.002 (Systemd Service) |
| **References** | [MITRE T1543.002](https://attack.mitre.org/techniques/T1543/002/) · [Elastic Linux Persistence Primer](https://www.elastic.co/security-labs/primer-on-persistence-mechanisms) · [PANIX](https://github.com/Aegrah/PANIX) |

**Forensic notes:** Use `systemctl cat <unit>` to show effective unit content. Compare `systemctl list-units --type=service --state=enabled` against baseline. The `ExecStart` path pointing to `/tmp`, `/var/tmp`, `/dev/shm`, or hidden directories (`.` prefix) is strongly suspicious. Enabled units symlink into `/etc/systemd/system/multi-user.target.wants/` — check that directory for orphan symlinks.

---

### User-Level Service Unit Files

| Field | Value |
|-------|-------|
| **Location** | `~/.config/systemd/user/*.service`; `/etc/systemd/user/*.service`; `/usr/lib/systemd/user/*.service` |
| **Format** | INI-style text (same as system units) |
| **Key Fields** | Same as system units; also `WantedBy=default.target` for user-session autostart |
| **Forensic Value** | User-level services activate when the user logs in (or with lingering: at boot); do not require root to install; used by attackers to persist in user context without triggering admin-level artifact creation |
| **OS Scope** | systemd-based Linux with systemd user sessions enabled |
| **Data Scope** | User |
| **Decoder Approach** | Enumerate all user home directories; scan `~/.config/systemd/user/`; parse unit files; check for `loginctl enable-linger <user>` (lingering enables units to start at boot even without interactive login) |
| **MITRE ATT&CK** | T1543.002 |
| **References** | [MITRE T1543.002](https://attack.mitre.org/techniques/T1543/002/) · [Elastic Primer on Persistence](https://www.elastic.co/security-labs/primer-on-persistence-mechanisms) |

---

### Systemd Timer Units (*.timer)

| Field | Value |
|-------|-------|
| **Location** | `/etc/systemd/system/*.timer`; `/lib/systemd/system/*.timer`; `~/.config/systemd/user/*.timer` |
| **Format** | INI-style text; `[Timer]` section with `OnCalendar=`, `OnBootSec=`, `OnUnitActiveSec=` directives |
| **Key Fields** | `OnCalendar=` (cron-like schedule), `Unit=` (associated service), `Persistent=true` (catches up missed runs like anacron) |
| **Forensic Value** | Modern cron replacement; `Persistent=true` means missed runs are executed on next boot (similar to anacron); timer/service pairs are more flexible and harder to notice than crontab entries; timer last-run timestamps stored in systemd journal |
| **OS Scope** | systemd-based Linux |
| **Data Scope** | System / User |
| **Decoder Approach** | Parse `[Timer]` section; `journalctl -u <timer>.timer` to view execution history; `systemctl list-timers --all` equivalent on live system |
| **MITRE ATT&CK** | T1053.006 (Systemd Timers) |
| **References** | [MITRE T1053.006](https://attack.mitre.org/techniques/T1053/006/) · [Elastic Linux Persistence Sequel](https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms) |

---

### Systemd Generators

| Field | Value |
|-------|-------|
| **Location** | `/etc/systemd/system-generators/`; `/usr/lib/systemd/system-generators/`; `/run/systemd/system-generators/` |
| **Format** | Executable binary or script (receives 3 directory arguments: normal, early, late output dirs) |
| **Key Fields** | Executable name; output (`.service`/`.target` files written to temp directories during early boot); arguments received at invocation |
| **Forensic Value** | Generators run early in the boot process before most services start; a malicious generator can create or modify unit files at boot time, making the persistence mechanism highly resilient and difficult to detect; very rarely legitimately modified |
| **OS Scope** | systemd-based Linux |
| **Data Scope** | System |
| **Decoder Approach** | Enumerate executables in generator directories; compare against package manifest; hash and inspect any unknown executables; review output directories `/run/systemd/generator/` for runtime-generated units |
| **MITRE ATT&CK** | T1543.002 (closest mapping); also T1542 (Pre-OS Boot behavior) |
| **References** | [Hunting for Persistence Part 5: Systemd Generators — pberba.github.io](https://pberba.github.io/security/2022/02/07/linux-threat-hunting-for-persistence-systemd-generators/) · [Elastic Grand Finale on Linux Persistence](https://www.elastic.co/security-labs/the-grand-finale-on-linux-persistence) |

---

## 3. Init-Based Persistence (SysV / Upstart)

### /etc/rc.local (Legacy Startup Script)

| Field | Value |
|-------|-------|
| **Location** | `/etc/rc.local` |
| **Format** | Shell script; must be executable; returns exit code 0 on success |
| **Key Fields** | Any commands before the `exit 0` line |
| **Forensic Value** | Executed at the end of multi-user runlevel by init/systemd-rc-local.service; extremely common in real-world attacks due to simplicity and wide awareness; commands run as root; still present and functional on many modern systemd systems via `rc-local.service` compatibility shim |
| **OS Scope** | All Linux; deprecated but still functional on most distros |
| **Data Scope** | System |
| **Decoder Approach** | Read file; check if executable bit set; scan for non-comment lines after the shebang; look for download cradles, netcat listeners, reverse shells; correlate modification timestamp |
| **MITRE ATT&CK** | T1037.004 (RC Scripts) |
| **References** | [MITRE T1037.004](https://attack.mitre.org/techniques/T1037/004/) · [Detecting Linux Persistence — Wazuh](https://wazuh.com/blog/detecting-common-linux-persistence-techniques-with-wazuh/) |

---

### /etc/init.d/* (SysV Init Scripts)

| Field | Value |
|-------|-------|
| **Location** | `/etc/init.d/`; symlinked into `/etc/rc{0-6}.d/` with `S##name` (start) or `K##name` (kill) prefix |
| **Format** | Shell scripts conforming to LSB init script standard; must handle `start`, `stop`, `restart`, `status` arguments |
| **Key Fields** | Script body (especially `start)` case arm); `### BEGIN INIT INFO` header block |
| **Forensic Value** | On SysV and hybrid systems (via `systemd-sysv-generator`), scripts in `/etc/init.d/` enabled with `update-rc.d` are run at boot; attackers use these for deep persistence that survives systemd unit removal; the numeric prefix in `rc*.d/` symlinks determines execution order |
| **OS Scope** | SysV systems; also functional on systemd systems via compatibility |
| **Data Scope** | System |
| **Decoder Approach** | List all scripts; compare against package manifest; read `start)` case arm for commands; inspect `Required-Start` and `Default-Start` headers; check `/etc/rc2.d/` (default multi-user) for enabled symlinks |
| **MITRE ATT&CK** | T1037.004 |
| **References** | [MITRE T1037.004](https://attack.mitre.org/techniques/T1037/004/) · [PANIX init.d module](https://github.com/Aegrah/PANIX) |

---

### /etc/inittab (SysV Init Configuration)

| Field | Value |
|-------|-------|
| **Location** | `/etc/inittab` |
| **Format** | Text; format: `id:runlevels:action:process` |
| **Key Fields** | `action` field (e.g., `respawn`, `once`, `boot`, `bootwait`); `process` field |
| **Forensic Value** | On legacy SysV systems, `respawn` action causes init to automatically restart the process if it dies — a built-in persistence mechanism; `respawn` entries for unexpected programs (e.g., netcat, bash reverse shells) are definitive IOCs |
| **OS Scope** | SysV init (RHEL 5 and earlier, older Debian); not present on systemd systems |
| **Data Scope** | System |
| **Decoder Approach** | Parse colon-delimited fields; flag any `respawn` entries not matching known system daemons |
| **MITRE ATT&CK** | T1037.004 |
| **References** | [MITRE T1037.004](https://attack.mitre.org/techniques/T1037/004/) |

---

### Upstart /etc/init/*.conf

| Field | Value |
|-------|-------|
| **Location** | `/etc/init/*.conf` |
| **Format** | Text (Upstart job configuration language); `start on`, `stop on`, `exec`, `script`...`end script` stanzas |
| **Key Fields** | `exec` line or `script`/`end script` block; `start on` trigger conditions; `respawn` directive |
| **Forensic Value** | On Ubuntu 14.04 LTS and earlier (and some embedded systems), Upstart jobs with `respawn` provide automatic restart persistence; malicious jobs blend with system jobs in the same directory |
| **OS Scope** | Ubuntu 14.04 and earlier; some Debian variants; Chrome OS; embedded Linux |
| **Data Scope** | System |
| **Decoder Approach** | Enumerate `.conf` files; parse `exec` and `script` stanzas; look for non-package-provided files |
| **MITRE ATT&CK** | T1543 (Create or Modify System Process) |
| **References** | [MITRE T1543](https://attack.mitre.org/techniques/T1543/) |

---

## 4. Shell and Environment Persistence

### ~/.bashrc / ~/.bash_profile / ~/.profile / ~/.bash_logout

| Field | Value |
|-------|-------|
| **Location** | `~/.bashrc` (interactive non-login shells); `~/.bash_profile` (login shells, Bash-specific); `~/.profile` (login shells, POSIX sh); `~/.bash_logout` (on bash logout) |
| **Format** | Shell script (plain text) |
| **Key Fields** | Any `export`, command execution, or function definition outside of comments; embedded `eval`, `$(...)`, base64 decode patterns |
| **Forensic Value** | Sourced on every shell invocation for the user; attackers inject commands that establish reverse shells, exfiltrate data, or load LD_PRELOAD hooks; `~/.bash_logout` can erase evidence on logout; modification timestamps and content hashes provide timeline evidence |
| **OS Scope** | All Linux (user-specific) |
| **Data Scope** | User |
| **Decoder Approach** | Read file; regex scan for `curl`, `wget`, `nc`, `bash -i`, `python -c`, `perl -e`, `eval`, `base64`, `LD_PRELOAD` assignments; diff against skel (`/etc/skel/.bashrc`); check modification timestamp |
| **MITRE ATT&CK** | T1546.004 (Unix Shell Configuration Modification) |
| **References** | [MITRE T1546.004](https://attack.mitre.org/techniques/T1546/004/) · [Elastic Linux Persistence Primer](https://www.elastic.co/security-labs/primer-on-persistence-mechanisms) |

---

### /etc/profile and /etc/profile.d/*

| Field | Value |
|-------|-------|
| **Location** | `/etc/profile` (single file); `/etc/profile.d/*.sh` (drop-in scripts sourced by `/etc/profile`) |
| **Format** | Shell script |
| **Key Fields** | Environment variable assignments; sourced sub-scripts; `PATH` modifications; `export` statements |
| **Forensic Value** | System-wide shell initialization; modifying `/etc/profile` or dropping a script in `/etc/profile.d/` affects every user's login shell; attackers use this for system-wide LD_PRELOAD injection or PATH poisoning; `/etc/profile.d/` files not associated with installed packages are suspicious |
| **OS Scope** | All Linux |
| **Data Scope** | System |
| **Decoder Approach** | Read `/etc/profile`; enumerate and read `/etc/profile.d/*.sh`; compare against package manifest; detect `LD_PRELOAD`, unusual `PATH` prepending, or covert command execution |
| **MITRE ATT&CK** | T1546.004; T1574.006 (LD_PRELOAD via environment) |
| **References** | [MITRE T1546.004](https://attack.mitre.org/techniques/T1546/004/) · [Elastic Detection Rules](https://detection.fyi/elastic/detection-rules/linux/persistence_shell_configuration_modification/) |

---

### Zsh Startup Files (~/.zshrc, ~/.zprofile, ~/.zlogin, ~/.zshenv, ~/.zlogout)

| Field | Value |
|-------|-------|
| **Location** | `~/.zshenv` (all invocations); `~/.zprofile` (login, before `.zshrc`); `~/.zshrc` (interactive); `~/.zlogin` (login, after `.zshrc`); `~/.zlogout` (login exit) |
| **Format** | Shell script |
| **Key Fields** | Environment variables, command execution, `PATH` changes, `LD_PRELOAD` or `LD_LIBRARY_PATH` assignments |
| **Forensic Value** | `.zshenv` is sourced on *every* zsh invocation (including non-interactive and non-login), making it the most powerful persistence point in the zsh startup sequence; attackers targeting zsh users inject into `.zshenv` or `.zshrc`; system-wide equivalents at `/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin` |
| **OS Scope** | Systems where zsh is installed and used (common on modern Ubuntu, Arch, Kali, macOS compatibility) |
| **Data Scope** | User (and System for `/etc/zsh*`) |
| **Decoder Approach** | Load order: `.zshenv` → `.zprofile` → `.zshrc` → `.zlogin`; read each in order; detect same patterns as bash files; check `.zsh_history` for attacker commands |
| **MITRE ATT&CK** | T1546.004 |
| **References** | [Zsh Startup Files Documentation](https://zsh.sourceforge.io/Intro/intro_3.html) · [Elastic Detection Rules](https://detection.fyi/elastic/detection-rules/linux/persistence_shell_configuration_modification/) |

---

### Shell History Files

| Field | Value |
|-------|-------|
| **Location** | `~/.bash_history`; `~/.zsh_history`; `~/.python_history`; `~/.mysql_history`; `~/.psql_history`; `/root/.bash_history` |
| **Format** | Text (one command per line; zsh history optionally includes timestamps with `EXTENDED_HISTORY`) |
| **Key Fields** | Individual command lines; zsh timestamp prefix (`: <epoch>:0;<command>`); history gaps (deleted entries); HISTSIZE=0 or HISTFILE=/dev/null (anti-forensics) |
| **Forensic Value** | Primary record of attacker interactive activity; reveals lateral movement commands, tools downloaded, files accessed, persistence mechanisms installed; history truncation or `/dev/null` redirection is itself an IOC; zsh extended history timestamps enable precise event timeline reconstruction |
| **OS Scope** | All Linux (shell-specific) |
| **Data Scope** | User |
| **Decoder Approach** | Read raw text; for zsh extended history, parse `: <epoch>:<elapsed>;<command>` format; note gaps in timestamp sequence; correlate with `/var/log/auth.log` login times; check if `HISTFILE` is unset in shell config files |
| **MITRE ATT&CK** | T1552.003 (Bash History — credential discovery); general execution evidence |
| **References** | [Linux Forensics — Useful Artifacts (Medium)](https://tho-le.medium.com/linux-forensics-some-useful-artifacts-74497dca1ab2) · [Linux Forensics Cheatsheet](https://fareedfauzi.github.io/cheatsheets/linux-forensics/) |

---

## 5. Library / Dynamic Linker Persistence

### /etc/ld.so.preload

| Field | Value |
|-------|-------|
| **Location** | `/etc/ld.so.preload` |
| **Format** | Text; newline-separated list of absolute shared library paths |
| **Key Fields** | Each line: absolute path to a `.so` file; presence of unrecognized library paths |
| **Forensic Value** | Libraries listed here are loaded into *every* dynamically linked process on the system before all other libraries; a rootkit `.so` listed here can intercept any libc function (read, write, getdents, etc.) system-wide; the file existing at all on a non-development system is a red flag; active file descriptor held open to this file by a running process indicates protective locking |
| **OS Scope** | All Linux (glibc-based systems) |
| **Data Scope** | System |
| **Decoder Approach** | Check if file exists (`ls -la /etc/ld.so.preload`); read content; for each listed library path, verify it exists, check its hash, run `objdump -T` to see exported symbols and look for libc function overrides; run `ldd /bin/ls` and compare loaded libraries against expected baseline |
| **MITRE ATT&CK** | T1574.006 (Dynamic Linker Hijacking) |
| **References** | [Wiz Blog — Linux Rootkits Part 1: Dynamic Linker Hijacking](https://www.wiz.io/blog/linux-rootkits-explained-part-1-dynamic-linker-hijacking) · [MITRE T1574.006](https://attack.mitre.org/techniques/T1574/006/) · [0xMatheuZ — LD_PRELOAD Rootkit Detection](https://matheuzsecurity.github.io/hacking/ldpreload-rootkit/) |

---

### /etc/ld.so.conf and /etc/ld.so.conf.d/*

| Field | Value |
|-------|-------|
| **Location** | `/etc/ld.so.conf`; `/etc/ld.so.conf.d/*.conf` |
| **Format** | Text; one directory path per line; `/etc/ld.so.conf` typically just `include /etc/ld.so.conf.d/*.conf` |
| **Key Fields** | Directory paths added to the dynamic linker search path |
| **Forensic Value** | Attackers can add a directory containing a malicious `.so` to the linker search path; combined with library naming to shadow legitimate libraries; requires `ldconfig` to be run to take effect (or is pre-cached in `/etc/ld.so.cache`); check the cache with `ldconfig -p` |
| **OS Scope** | All Linux (glibc) |
| **Data Scope** | System |
| **Decoder Approach** | Read all conf files; identify non-standard directories; run `ldconfig -p` to see current cache state; verify each non-standard directory for unexpected `.so` files |
| **MITRE ATT&CK** | T1574.006 |
| **References** | [MITRE T1574.006](https://attack.mitre.org/techniques/T1574/006/) |

---

## 6. PAM (Pluggable Authentication Modules)

### /etc/pam.d/* and /etc/pam.conf

| Field | Value |
|-------|-------|
| **Location** | `/etc/pam.d/` (directory of per-service configs); `/etc/pam.conf` (single monolithic config, older systems) |
| **Format** | Text; each rule: `type control module-path module-arguments` |
| **Key Fields** | `type` (`auth`, `account`, `password`, `session`); `control` (`required`, `sufficient`, `optional`); `module-path` (absolute path to `.so` file or module name); `module-arguments` |
| **Forensic Value** | PAM controls authentication for all system services (ssh, sudo, login, su, gdm, etc.); a malicious module inserted as `auth sufficient` can bypass all authentication with a magic password; OrBit and other rootkits hook PAM to harvest credentials; modified `pam_unix.so` is a classic backdoor technique |
| **OS Scope** | All Linux |
| **Data Scope** | System |
| **Decoder Approach** | Read all files in `/etc/pam.d/`; flag `auth sufficient` rules with non-standard module paths; compare module paths against package manifest; hash `pam_unix.so` and compare against package-provided hash |
| **MITRE ATT&CK** | T1556.003 (Pluggable Authentication Modules) |
| **References** | [MITRE T1556.003](https://attack.mitre.org/techniques/T1556/003/) · [Elastic Security Labs — OrBit](https://www.elastic.co/security-labs/primer-on-persistence-mechanisms) |

---

### PAM Module Binaries

| Field | Value |
|-------|-------|
| **Location** | `/lib/security/` (32-bit); `/lib/x86_64-linux-gnu/security/` (64-bit Debian/Ubuntu); `/lib64/security/` (RHEL); `/usr/lib/security/` |
| **Format** | ELF shared library (`.so`) |
| **Key Fields** | File hash; modification timestamp; exported symbols (especially `pam_sm_authenticate`, `pam_sm_open_session`); strings inside binary |
| **Forensic Value** | Attackers replace or add module `.so` files here; a backdoored `pam_unix.so` that accepts a universal password is invisible to config file analysis alone; requires binary-level comparison against pristine package |
| **OS Scope** | All Linux |
| **Data Scope** | System |
| **Decoder Approach** | Enumerate all `.so` files in PAM module paths; hash each; compare against `dpkg -V` or `rpm -V` package verification; use `strings` on suspicious files to find hardcoded magic passwords or C2 addresses |
| **MITRE ATT&CK** | T1556.003 |
| **References** | [MITRE T1556.003](https://attack.mitre.org/techniques/T1556/003/) · [Linux Threat Hunting — 0xMatheuZ](https://matheuzsecurity.github.io/hacking/linux-threat-hunting-persistence/) |

---

## 7. Kernel Modules

### /etc/modules and /etc/modules-load.d/*

| Field | Value |
|-------|-------|
| **Location** | `/etc/modules` (Debian/Ubuntu static module list); `/etc/modules-load.d/*.conf` (systemd-modules-load managed); `/usr/lib/modules-load.d/*.conf` (package-provided) |
| **Format** | Text; one module name per line; `/etc/modules-load.d/*.conf` supports comments |
| **Key Fields** | Module names; any module not associated with hardware or an installed package |
| **Forensic Value** | Modules listed here are loaded at boot by `systemd-modules-load.service`; a rootkit LKM listed here ensures kernel-level persistence across reboots; file modification timestamp and package manifest comparison are primary detection methods |
| **OS Scope** | systemd-based Linux (`modules-load.d`); Debian/Ubuntu (`/etc/modules`) |
| **Data Scope** | System |
| **Decoder Approach** | Read all files; extract module names; cross-reference with installed packages; for any unknown module, locate its `.ko` file in `/lib/modules/$(uname -r)/` and hash it |
| **MITRE ATT&CK** | T1547.006 (Kernel Modules and Extensions) |
| **References** | [MITRE T1547.006](https://attack.mitre.org/techniques/T1547/006/) · [Wiz Blog — LKM Rootkits](https://www.wiz.io/blog/linux-rootkits-explained-part-2-loadable-kernel-modules) |

---

### /proc/modules (Live Kernel Module State)

| Field | Value |
|-------|-------|
| **Location** | `/proc/modules` (virtual filesystem; live only) |
| **Format** | Text; fields: `module_name size num_used_by_modules list_of_using_modules load_state memory_address` |
| **Key Fields** | Module name, memory address (offset 5), load state (`Live`, `Loading`, `Unloading`) |
| **Forensic Value** | Lists currently loaded kernel modules; rootkits manipulate the in-kernel linked list that `lsmod`/`/proc/modules` reads, causing themselves to disappear; cross-reference `/proc/modules` output with `/sys/module/` directory listing — hidden modules may still leave sysfs entries; compare against `/etc/modules` and package database; memory address discrepancies indicate tampering |
| **OS Scope** | All Linux (live system only; not available in disk forensics) |
| **Data Scope** | System |
| **Decoder Approach** | Read `/proc/modules`; parse space-delimited fields; list `/sys/module/` directory; diff both lists for discrepancies; check kernel log (`dmesg | grep -i module`) for load events; compare against memory image using Volatility's `linux_lsmod` plugin for rootkit detection |
| **MITRE ATT&CK** | T1547.006 |
| **References** | [MITRE T1547.006](https://attack.mitre.org/techniques/T1547/006/) · [Elastic — Declawing PUMAKIT](https://www.elastic.co/security-labs/declawing-pumakit) · [Hooked on Linux — Elastic](https://www.elastic.co/security-labs/linux-rootkits-2-caught-in-the-act) |

---

## 8. SSH Persistence

### ~/.ssh/authorized_keys

| Field | Value |
|-------|-------|
| **Location** | `~/.ssh/authorized_keys`; `~/.ssh/authorized_keys2` (legacy); `/root/.ssh/authorized_keys`; `/etc/ssh/authorized_keys` (if `AuthorizedKeysFile` is reconfigured) |
| **Format** | Text; one public key per line: `keytype base64-key comment`; optional key options prefix |
| **Key Fields** | Key type (`ssh-rsa`, `ecdsa-sha2-nistp256`, `ssh-ed25519`); public key material; comment field (often contains attacker-controlled info or is left blank); key options (`command=`, `no-pty`, `from=`) |
| **Forensic Value** | Adding an attacker-controlled public key grants persistent SSH access without knowing the user's password; survives password changes, account lockouts, and MFA if key authentication is enabled; `command=` option can restrict to specific commands (common in automated attack tooling); look for keys with no comment, unusual key types, or keys added at unusual times |
| **OS Scope** | All Linux |
| **Data Scope** | User |
| **Decoder Approach** | Read file; parse each line; flag keys added outside business hours or not matching organization's key comment format; correlate file modification time with login events in `/var/log/auth.log`; verify `AuthorizedKeysFile` directive in `/etc/ssh/sshd_config` for alternate paths |
| **MITRE ATT&CK** | T1098.004 (SSH Authorized Keys) |
| **References** | [MITRE T1098.004](https://attack.mitre.org/techniques/T1098/004/) · [Elastic SSH Authorized Keys Rule](https://www.elastic.co/guide/en/security/current/ssh-authorized-keys-file-modification.html) · [Atomic Red Team T1098.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098.004/T1098.004.md) |

---

### /etc/ssh/sshd_config

| Field | Value |
|-------|-------|
| **Location** | `/etc/ssh/sshd_config`; `/etc/ssh/sshd_config.d/*.conf` (drop-in directory, newer OpenSSH) |
| **Format** | Text; `Directive Value` pairs |
| **Key Fields** | `PermitRootLogin` (should be `no` or `prohibit-password`); `AuthorizedKeysFile` (alternate key file paths); `PasswordAuthentication`; `AcceptEnv` (environment variable injection); `PermitTunnel`; `AllowUsers`, `DenyUsers`; `Match` blocks |
| **Forensic Value** | Attackers modify sshd_config to re-enable root login, set alternate `AuthorizedKeysFile` paths (pointing to attacker-controlled files), enable password authentication (to use cracked credentials), or accept dangerous environment variables; `AcceptEnv LD_PRELOAD` allows library injection via SSH environment |
| **OS Scope** | All Linux |
| **Data Scope** | System |
| **Decoder Approach** | Parse directive-value pairs; flag `PermitRootLogin yes`, `AuthorizedKeysFile` with non-default paths, `AcceptEnv LD_PRELOAD`, or `PasswordAuthentication yes` when not expected; check modification timestamp and diff against package default |
| **MITRE ATT&CK** | T1098.004; T1556 (Modify Authentication Process) |
| **References** | [MITRE T1098.004](https://attack.mitre.org/techniques/T1098/004/) · [Wazuh — Detecting Linux Persistence](https://wazuh.com/blog/detecting-common-linux-persistence-techniques-with-wazuh/) |

---

### ~/.ssh/rc (SSH Per-User Session Initialization)

| Field | Value |
|-------|-------|
| **Location** | `~/.ssh/rc` |
| **Format** | Shell script (executed by sshd before the user's shell) |
| **Key Fields** | Any commands in the script body |
| **Forensic Value** | Executed by sshd on every SSH login for the user, before the user's shell starts; runs with user privileges; can be used to establish a parallel backdoor connection, log credentials, or modify the session environment; less commonly inspected than `authorized_keys`, providing stealth advantage |
| **OS Scope** | All Linux (OpenSSH) |
| **Data Scope** | User |
| **Decoder Approach** | Check existence; read content; flag any network connection attempts, file modifications, or credential exfiltration patterns |
| **MITRE ATT&CK** | T1098.004; T1037 (Boot or Logon Initialization Scripts) |
| **References** | [MITRE T1098.004](https://attack.mitre.org/techniques/T1098/004/) · [OpenSSH sshd man page](https://man.openbsd.org/sshd.8) |

---

## 9. Sudo and Privilege Persistence

### /etc/sudoers and /etc/sudoers.d/*

| Field | Value |
|-------|-------|
| **Location** | `/etc/sudoers` (main file; edit only with `visudo`); `/etc/sudoers.d/` (drop-in directory) |
| **Format** | Text; `user/group host=(runas_user:runas_group) [options:] command_list` |
| **Key Fields** | `NOPASSWD` tag (bypasses password prompt); `ALL=(ALL) NOPASSWD: ALL` (full unrestricted sudo); specific command with `NOPASSWD` (allows GTFOBin exploitation); `Defaults !tty_tickets` (weakens timestamp isolation); `Defaults timestamp_timeout=-1` (permanent sudo without re-authentication) |
| **Forensic Value** | `NOPASSWD` entries allow privilege escalation without authentication; attackers insert a rule for a compromised user account to gain persistent root access; drop-in files in `/etc/sudoers.d/` are harder to notice than modifications to the main file; `Defaults timestamp_timeout=-1` enables permanent sudo caching |
| **OS Scope** | All Linux |
| **Data Scope** | System |
| **Decoder Approach** | Parse sudoers syntax (skip comments, handle `!include`); grep for `NOPASSWD`; flag `timestamp_timeout=-1`; diff drop-in files against package manifest; use `sudo -l -U <user>` equivalent to enumerate effective privileges |
| **MITRE ATT&CK** | T1548.003 (Sudo and Sudo Caching) |
| **References** | [MITRE T1548.003](https://attack.mitre.org/techniques/T1548/003/) · [Splunk — NOPASSWD Detection](https://research.splunk.com/endpoint/ab1e0d52-624a-11ec-8e0b-acde48001122/) · [Elastic — Sudoers Modification](https://www.elastic.co/guide/en/security/current/potential-privilege-escalation-via-sudoers-file-modification.html) |

---

### SUID/SGID Binaries

| Field | Value |
|-------|-------|
| **Location** | Any filesystem path (common targets: `/usr/bin/`, `/usr/local/bin/`, `/tmp/`, hidden directories) |
| **Format** | ELF executable with setuid bit (`-rwsr-xr-x`) or setgid bit (`-rwxr-sr-x`) |
| **Key Fields** | File permissions (setuid/setgid bit); owner (root-owned SUID = elevates to root); path (non-standard paths are suspicious); modification timestamp |
| **Forensic Value** | A root-owned SUID binary executes as root regardless of the invoking user; attackers set the SUID bit on shells (`/bin/bash -p` retains effective UID), copies of interpreters, or custom binaries to create persistent privilege escalation paths; `/tmp`, `/var/tmp`, `/dev/shm` are common drop locations |
| **OS Scope** | All Linux |
| **Data Scope** | System |
| **Decoder Approach** | Enumerate: `find / -perm /4000 -type f 2>/dev/null`; compare against baseline whitelist; flag any SUID binaries in world-writable directories or not owned by root packages; check against GTFOBins list for exploitability |
| **MITRE ATT&CK** | T1548.001 (Setuid and Setgid) |
| **References** | [MITRE T1548.001](https://attack.mitre.org/techniques/T1548/001/) · [GTFOBins](https://gtfobins.github.io/) |

---

## 10. Package Manager Persistence

### /etc/apt/apt.conf.d/* (Debian/Ubuntu APT Hooks)

| Field | Value |
|-------|-------|
| **Location** | `/etc/apt/apt.conf.d/` |
| **Format** | Text; APT configuration directives; `DPkg::Pre-Install-Pkgs`, `APT::Update::Pre-Invoke`, `APT::Update::Post-Invoke`, `DPkg::Post-Invoke` hook directives |
| **Key Fields** | `Pre-Invoke`, `Post-Invoke` directives with shell command values; file creation timestamp and name |
| **Forensic Value** | APT hooks execute on every `apt-get install`, `apt upgrade`, or `apt update` operation; a malicious hook ensures code runs every time the system is patched — using system maintenance as a trigger; extremely stealthy because defenders expect activity during package operations |
| **OS Scope** | Debian, Ubuntu, and derivatives |
| **Data Scope** | System |
| **Decoder Approach** | Enumerate all files; parse for `Pre-Invoke`, `Post-Invoke`, `Pre-Install-Pkgs` directives; compare file list against package manifest; alert on any file not installed by a package |
| **MITRE ATT&CK** | T1546.016 (Installer Packages) |
| **References** | [MITRE T1546.016](https://attack.mitre.org/techniques/T1546/016/) · [Elastic — APT Package Manager Execution](https://www.elastic.co/guide/en/security/current/suspicious-apt-package-manager-execution.html) · [Elastic Sequel on Persistence](https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms) |

---

### DPKG Maintainer Scripts (preinst, postinst, prerm, postrm)

| Field | Value |
|-------|-------|
| **Location** | `/var/lib/dpkg/info/*.postinst`, `*.preinst`, `*.prerm`, `*.postrm`; also inside `.deb` packages under `DEBIAN/` |
| **Format** | Shell scripts |
| **Key Fields** | Script content; package name (filename prefix); `$1` argument handling (`install`, `configure`, `remove`, `purge` triggers) |
| **Forensic Value** | Maintainer scripts run as root during package installation, upgrade, and removal; a trojanized `.deb` package (or a legitimate package with a backdoored postinst) executes arbitrary code as root; `postinst configure` runs after every install/upgrade — including upgrades of the package itself |
| **OS Scope** | Debian, Ubuntu, and derivatives |
| **Data Scope** | System |
| **Decoder Approach** | Examine `/var/lib/dpkg/info/*.postinst` for recently modified files; diff against corresponding package's expected content; flag shell execution patterns consistent with download cradles or reverse shells |
| **MITRE ATT&CK** | T1546.016 |
| **References** | [MITRE T1546.016](https://attack.mitre.org/techniques/T1546/016/) · [Elastic — Unusual DPKG Execution](https://www.elastic.co/guide/en/security/current/unusual-dpkg-execution.html) |

---

## 11. MOTD / Login Execution

### /etc/update-motd.d/* (Dynamic MOTD Scripts)

| Field | Value |
|-------|-------|
| **Location** | `/etc/update-motd.d/` (numbered scripts, executed in ascending order by PAM); `/etc/motd` (static MOTD, shown if no dynamic scripts); `/run/motd.dynamic` (runtime cache) |
| **Format** | Executable scripts (any language); filename must be numeric-prefixed (e.g., `00-header`, `50-landscape-sysinfo`) |
| **Key Fields** | Script content; file permissions (must be executable); modification timestamp; any non-system-package-provided files |
| **Forensic Value** | Scripts in `/etc/update-motd.d/` run as **root** on every SSH login; attackers drop scripts here for instant, privileged code execution whenever any user connects over SSH; a Metasploit module (`exploit/linux/local/motd_persistence`) specifically automates this technique; egress network connections from MOTD-spawned processes are a high-confidence IOC |
| **OS Scope** | Ubuntu, Debian (and derivatives); less common on RHEL/Fedora |
| **Data Scope** | System |
| **Decoder Approach** | Enumerate all files; check execute bit; read content; compare against package manifest; monitor for processes with parent spawned from `/etc/update-motd.d/`; flag any egress network connections from update-motd processes |
| **MITRE ATT&CK** | T1037.004 (RC Scripts); also T1546 (Event Triggered Execution) |
| **References** | [Elastic — MOTD File Creation Detection](https://www.elastic.co/guide/en/security/current/message-of-the-day-motd-file-creation.html) · [Rapid7 — update-motd.d Metasploit Module](https://www.rapid7.com/db/modules/exploit/linux/local/motd_persistence/) · [Elastic — Process Spawned from MOTD](https://www.elastic.co/guide/en/security/current/process-spawned-from-message-of-the-day-motd.html) |

---

## 12. Udev Rules

### /etc/udev/rules.d/* and /lib/udev/rules.d/*

| Field | Value |
|-------|-------|
| **Location** | `/etc/udev/rules.d/` (admin-managed, highest priority); `/run/udev/rules.d/` (runtime); `/lib/udev/rules.d/` or `/usr/lib/udev/rules.d/` (package-provided); `/usr/local/lib/udev/rules.d/` |
| **Format** | Text; comma-separated key-operator-value statements; `ACTION`, `SUBSYSTEM`, `ENV{MAJOR}`, `ENV{MINOR}`, `RUN+=` |
| **Key Fields** | `ACTION==` (device event trigger: `add`, `change`, `remove`); `ENV{MAJOR}`/`ENV{MINOR}` (device node identifiers); `RUN+=` (command to execute); `SUBSYSTEM==` |
| **Forensic Value** | udev rules fire when kernel device events occur (e.g., when `/dev/random` is accessed); the `RUN+=` key executes a command as root in response; the **sedexp** malware exploited this for 2+ years without detection by triggering on `/dev/random` (major=1, minor=8); rules are processed on every matching kernel event, providing persistent and frequent execution without cron or systemd |
| **OS Scope** | All Linux (udev-based, i.e., modern Linux with systemd-udevd) |
| **Data Scope** | System |
| **Decoder Approach** | Enumerate all `.rules` files across all priority directories; parse `RUN+=` keys; flag any rule that triggers on common pseudo-devices (`/dev/random`, `/dev/null`, `/dev/zero`) with unusual `RUN` commands; compare against package manifest |
| **MITRE ATT&CK** | T1546.017 (Udev Rules) |
| **References** | [MITRE T1546.017](https://attack.mitre.org/techniques/T1546/017/) · [Aon — Unveiling sedexp](https://www.aon.com/en/insights/cyber-labs/unveiling-sedexp) · [Bleeping Computer — sedexp Malware](https://www.bleepingcomputer.com/news/security/stealthy-sedexp-linux-malware-evaded-detection-for-two-years/) · [Eder's Blog — Leveraging Linux udev for Persistence](https://ch4ik0.github.io/en/posts/leveraging-Linux-udev-for-persistence/) |

---

## 13. XDG Autostart Entries

### ~/.config/autostart/*.desktop and /etc/xdg/autostart/*.desktop

| Field | Value |
|-------|-------|
| **Location** | `~/.config/autostart/*.desktop` (user-level); `/etc/xdg/autostart/*.desktop` (system-level); also `$XDG_CONFIG_HOME/autostart/` and `$XDG_CONFIG_DIRS/autostart/` if env vars set |
| **Format** | Desktop Entry file (INI-like); `[Desktop Entry]` section with typed key=value pairs |
| **Key Fields** | `Type=Application` (required); `Exec=<command>` (executed on desktop login); `Name=`; `Hidden=true` (entry inactive); `NoDisplay=true` (hides from app menus but still executes); `X-GNOME-Autostart-enabled=true/false` |
| **Forensic Value** | `.desktop` files in autostart directories execute when the user's graphical desktop session starts; used by DISGOMOJI (padded with `#` chars to bloat file), EtherRAT, CrossRAT, RotaJakiro, Transparent Tribe, and Contagious Interview malware; `Hidden=true` and `NoDisplay=true` prevent GUI visibility while preserving execution; executes in user context with display server access (keylogging, screen capture) |
| **OS Scope** | Linux with XDG-compliant desktop environments (GNOME, KDE, XFCE, LXDE, etc.) |
| **Data Scope** | User (user-level) / System (system-level) |
| **Decoder Approach** | Enumerate both paths; parse INI format; extract `Exec` value; verify referenced binary exists and is not in a temporary directory; flag `NoDisplay=true` combined with unusual `Exec` values; check file size (DISGOMOJI padded with `#` to 100s of KB) |
| **MITRE ATT&CK** | T1547.013 (XDG Autostart Entries) |
| **References** | [MITRE T1547.013](https://attack.mitre.org/techniques/T1547/013/) · [Picus Security — T1547.013 Explained](https://www.picussecurity.com/resource/blog/t1547-013-xdg-autostart-entries) · [Elastic — Network Connections from XDG Autostart](https://www.elastic.co/guide/en/security/current/network-connections-initiated-through-xdg-autostart-entry.html) |

---

## 14. Web Shells

### Web Document Root Files (/var/www/* and equivalents)

| Field | Value |
|-------|-------|
| **Location** | `/var/www/html/` (Apache default); `/usr/share/nginx/html/` (Nginx default); `/srv/www/`; WSGI application directories; any path configured in web server VirtualHost/server block |
| **Format** | PHP (`.php`), JSP (`.jsp`), ASP, Python (`.py`), Perl (`.pl`), or other interpreted scripts; may be disguised with innocuous extensions (`.jpg`, `.txt`) or embedded in legitimate files |
| **Key Fields** | Presence of `system()`, `exec()`, `shell_exec()`, `passthru()`, `eval()`, `base64_decode()` (PHP); `Runtime.exec()` (Java); `os.system()` (Python); POST parameter parsing for command input |
| **Forensic Value** | Web shells provide persistent remote code execution via HTTP/HTTPS, blending C2 traffic with legitimate web traffic; the Equifax breach used ~30 web shells; survive OS-level persistence cleanup if web directories are not checked; child processes spawned from web server user (`www-data`, `apache`, `nginx`) executing shell commands are strong IOCs |
| **OS Scope** | All Linux running web server software |
| **Data Scope** | System |
| **Decoder Approach** | File integrity monitoring on all web-accessible directories; compare file listing against deployment manifests; scan PHP/JSP files for `eval(base64_decode(...))` patterns; monitor processes with parent `httpd`/`nginx`/`apache2` spawning shells (`bash`, `sh`, `dash`); check web access logs for POST requests to unexpected file paths |
| **MITRE ATT&CK** | T1505.003 (Web Shell) |
| **References** | [MITRE T1505.003](https://attack.mitre.org/techniques/T1505/003/) · [Hunting for Persistence Part 1 — pberba.github.io](https://pberba.github.io/security/2021/11/22/linux-threat-hunting-for-persistence-sysmon-auditd-webshell/) · [WA Cyber Security — T1505.003 Indicators](https://soc.cyber.wa.gov.au/guidelines/TTP_Hunt/ADS_forms/T1505.003-Linux-Webshell-Indicators/) |

---

## 15. Git Hooks

### .git/hooks/* (Project-Level Git Hooks)

| Field | Value |
|-------|-------|
| **Location** | `<repo>/.git/hooks/` (project-specific); global hook path set by `core.hooksPath` in `/etc/gitconfig`, `~/.gitconfig`, or `~/.config/git/config` |
| **Format** | Executable scripts (shell, Python, Ruby, etc.); specific filenames trigger on specific Git events |
| **Key Fields** | Hook name determines trigger: `pre-commit` (before commit), `post-checkout` (after checkout), `post-merge` (after merge), `post-commit`, `pre-push`; script content |
| **Forensic Value** | Scripts in `.git/hooks/` execute automatically when developers run git commands; attackers targeting development environments plant hooks that execute on every commit or checkout, running with the developer's privileges; `core.hooksPath` set in global gitconfig can redirect all hook execution to an attacker-controlled directory; particularly dangerous in CI/CD environments where hooks may run with elevated or service account privileges |
| **OS Scope** | All Linux systems with git installed and active repositories |
| **Data Scope** | User |
| **Decoder Approach** | Enumerate repositories; check each `.git/hooks/` for executable files (non-sample); inspect content for malicious patterns; check `~/.gitconfig` and `/etc/gitconfig` for `core.hooksPath` pointing to non-standard directories; monitor for child processes spawned from known hook script names |
| **MITRE ATT&CK** | T1546 (Event Triggered Execution) |
| **References** | [Elastic — Git Hook Process Execution](https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_git_hook_process_execution.toml) · [Elastic — Git Hook Child Process](https://www.elastic.co/guide/en/security/8.19/git-hook-child-process.html) · [git-scm.com — Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) |

---

## 16. Pre-OS Boot Persistence

### GRUB Configuration (/boot/grub/grub.cfg)

| Field | Value |
|-------|-------|
| **Location** | `/boot/grub/grub.cfg` (BIOS systems); `/boot/grub2/grub.cfg` (RHEL/Fedora); EFI System Partition (ESP) `/boot/efi/EFI/<distro>/grub.cfg`; `/etc/grub.d/` (generator scripts); `/etc/default/grub` (variable file) |
| **Format** | GRUB script (a DSL with `menuentry`, `set`, `linux`, `initrd` commands); `/etc/grub.d/` files are shell scripts that generate `grub.cfg` |
| **Key Fields** | `linux` command line (kernel parameters, especially `init=` override); `GRUB_CMDLINE_LINUX` in `/etc/default/grub`; custom `.cfg` files in GRUB config directory |
| **Forensic Value** | Modifying `grub.cfg` to set `init=/malware.sh` replaces the init system with an attacker payload at boot; PANIX demonstrates automated GRUB persistence by injecting `init=/grub-panix.sh` via a custom config file; BootHole (CVE-2020-10713) allows unsigned code execution via a buffer overflow in grub.cfg parsing; GRUB-level persistence survives OS reinstall if the bootloader is not reflashed |
| **OS Scope** | All Linux with GRUB2 bootloader |
| **Data Scope** | System |
| **Decoder Approach** | Hash `grub.cfg` and compare against generated baseline (`update-grub` output); look for `init=` parameters; enumerate `/etc/grub.d/` for unexpected scripts; use `efibootmgr -v` to inspect UEFI boot order for unauthorized entries |
| **MITRE ATT&CK** | T1542.003 (Bootkit); T1542 (Pre-OS Boot) |
| **References** | [MITRE T1542](https://attack.mitre.org/techniques/T1542/) · [Eclypsium — BootHole](https://eclypsium.com/blog/theres-a-hole-in-the-boot/) · [Elastic — Grand Finale on Linux Persistence](https://www.elastic.co/security-labs/the-grand-finale-on-linux-persistence) |

---

### MBR / UEFI Bootkit Artifacts

| Field | Value |
|-------|-------|
| **Location** | MBR: first 512 bytes of disk (sector 0); `boot.img` embedded there by GRUB; `core.img` in post-MBR gap (sectors 1-62 on MBR disks); UEFI: EFI System Partition (`/boot/efi/`), `*.efi` boot applications |
| **Format** | Binary (MBR); PE/EFI binary (UEFI) |
| **Key Fields** | MBR boot signature (`0x55AA` at offset 510-511); disk partition table (offsets 446-509); EFI binary hash; UEFI NVRAM boot variables |
| **Forensic Value** | Bootkits survive OS reinstallation; firmware-level persistence (T1542.001) is detectable only through firmware extraction and analysis; MBR-level bootkits are detectable by reading raw sector 0 and comparing against expected GRUB signature; UEFI Secure Boot prevents unsigned bootloaders, but can be disabled or bypassed |
| **OS Scope** | All Linux (firmware-level) |
| **Data Scope** | System |
| **Decoder Approach** | `dd if=/dev/sda bs=512 count=1 | xxd | head -40` to inspect MBR; compare against known GRUB2 `boot.img` signature; run CHIPSEC for UEFI integrity analysis; use `efibootmgr -v` for UEFI boot entry inspection |
| **MITRE ATT&CK** | T1542.001 (System Firmware); T1542.003 (Bootkit) |
| **References** | [MITRE T1542.001](https://attack.mitre.org/techniques/T1542/001/) · [MITRE T1542.003](https://attack.mitre.org/techniques/T1542/003/) · [Forensic Artifacts in Modern Linux Systems — Nikkel (DFCHF)](https://www.digitalforensics.ch/nikkel18.pdf) |

---

## 17. Traffic Signaling (Port Knocking)

### knockd / iptables-based Port Knocking Configuration

| Field | Value |
|-------|-------|
| **Location** | `/etc/knockd.conf` (knockd daemon config); `/var/log/knockd.log`; `/etc/iptables/rules.v4` and `/etc/iptables/rules.v6` (saved firewall rules); `/etc/nftables.conf`; knockd binary (typically `/usr/sbin/knockd`) |
| **Format** | Text (`/etc/knockd.conf` INI-like); binary log; iptables rules text format |
| **Key Fields** | `[openSSH]` or custom sequence stanza in knockd.conf; `sequence =` (the knock ports in order); `start_command =` (iptables command to execute on successful knock); `stop_command =`; log entries showing knock sequences received |
| **Forensic Value** | A running knockd daemon keeps a service port closed until a specific sequence of connection attempts is made; this renders standard port scanners blind to the backdoor; T1205.001 — real-world use by StrongPity APT and UNC3886; forensic artifacts include knockd.conf, knockd process in process list, and dynamic iptables rules added after successful knock; malware variants use raw sockets or libpcap (Cd00r technique) to listen for knock packets without requiring knockd — leaving no config file |
| **OS Scope** | All Linux |
| **Data Scope** | System |
| **Decoder Approach** | Check for `knockd` process; read `/etc/knockd.conf`; examine `/var/log/knockd.log` for sequence attempts; look for processes using `libpcap` (raw socket sniffers); analyze network packet captures for sequential SYN packets to closed ports from single source IPs; check current iptables/nftables rules for dynamic ACCEPT rules |
| **MITRE ATT&CK** | T1205.001 (Port Knocking); T1205.002 (Socket Filters) |
| **References** | [MITRE T1205.001](https://attack.mitre.org/techniques/T1205/001/) · [MITRE T1205.002](https://attack.mitre.org/versions/v15/techniques/T1205/002/) · [Corelight — T1205 Port Knocking](https://mitre-attack.corelight.com/persistence/t1205-port-knocking/index.html) |

---

## 18. Account Manipulation

### /etc/passwd, /etc/shadow — Backdoor User Accounts

| Field | Value |
|-------|-------|
| **Location** | `/etc/passwd` (user account info, world-readable); `/etc/shadow` (hashed passwords, root-readable); `/etc/group`; `/etc/gshadow` |
| **Format** | Text; `/etc/passwd`: `username:x:UID:GID:GECOS:home:shell`; `/etc/shadow`: `username:hash:last_change:...` |
| **Key Fields** | UID=0 for non-root username (hidden root account); shell field (`/bin/bash` vs `/usr/sbin/nologin`); home directory path; last password change date in shadow |
| **Forensic Value** | Attackers create UID=0 accounts (all UIDs equal to 0 have root privileges regardless of username) to maintain a hidden root backdoor; accounts with valid shells but no corresponding home directory are suspicious; `nologin` or `false` shell replacements are anti-forensic against shell access but don't prevent sudo; recently created accounts (correlate with `/var/log/auth.log` `useradd`/`adduser` events) |
| **OS Scope** | All Linux |
| **Data Scope** | System |
| **Decoder Approach** | Parse colon-delimited fields; flag all UID=0 entries other than `root`; flag accounts with valid shells (`/bin/bash`, `/bin/sh`, `/bin/zsh`) that have no human-assigned home directory; compare against baseline; check `/var/log/auth.log` for `useradd` or `adduser` events |
| **MITRE ATT&CK** | T1136.001 (Create Account: Local Account); T1098 (Account Manipulation) |
| **References** | [MITRE T1136.001](https://attack.mitre.org/techniques/T1136/001/) · [MITRE T1098](https://attack.mitre.org/techniques/T1098/) · [Linux Forensics — Useful Artifacts](https://tho-le.medium.com/linux-forensics-some-useful-artifacts-74497dca1ab2) |

---

## 19. Cron Log Evidence (Execution Artifacts)

### /var/log/syslog, /var/log/cron, and systemd Journal

| Field | Value |
|-------|-------|
| **Location** | `/var/log/syslog` (Debian/Ubuntu); `/var/log/cron` (RHEL/CentOS/Fedora); `/var/log/cron.log` (some Debian); systemd journal (`/var/log/journal/` or `journalctl -u cron`) |
| **Format** | Text (syslog format: `Month Day HH:MM:SS hostname process[PID]: message`); journal is binary |
| **Key Fields** | `CMD (command)` lines showing cron-executed commands; `(username) CRON [PID]` entries; `(CRON) error` entries (failed jobs); `ORPHAN` entries (crontabs for deleted users) |
| **Forensic Value** | Primary execution evidence for cron-based persistence; logs the exact command executed, the user, PID, and timestamp; correlating log entries with crontab file contents proves execution; absence of logs where crontab entries exist may indicate log tampering or `MAILTO=""` suppression |
| **OS Scope** | All Linux |
| **Data Scope** | System |
| **Decoder Approach** | Grep for `CRON` or `cron` facility in syslog; parse syslog timestamp format; extract CMD lines; correlate with crontab file contents; check for `ORPHAN` entries indicating deleted user crontabs that still ran |
| **MITRE ATT&CK** | T1053.003 (execution evidence) |
| **References** | [DFIR Cron Jobs](https://nk0.gitbook.io/dfir/linux/forensics/cron-jobs) · [Linux Forensics Cheatsheet](https://fareedfauzi.github.io/cheatsheets/linux-forensics/) |

---

## Supplementary Quick-Reference: Additional High-Value Artifacts

The following artifacts are well-documented but require briefer treatment; each maps to a primary category above.

| Artifact | Path | MITRE | Notes |
|----------|------|-------|-------|
| Systemd journal (binary log) | `/var/log/journal/` | General | `journalctl` decodes; contains service start/stop, kernel messages, process trees |
| Auth log | `/var/log/auth.log` (Debian) or `/var/log/secure` (RHEL) | T1078 | SSH logins, sudo usage, su attempts, PAM events |
| Last login records | `/var/log/wtmp`, `/var/log/btmp`, `/var/log/lastlog` | T1078 | Binary; decoded with `last`, `lastb`, `lastlog`; wtmp = successful logins, btmp = failed |
| /proc/net/tcp, /proc/net/tcp6 | `/proc/net/tcp` | T1049 | Hex-encoded local/remote addresses; reveals listening backdoor ports; rootkits may filter this |
| /proc/\*/maps | `/proc/<pid>/maps` | T1574.006 | Shows all mapped libraries per process; reveals LD_PRELOAD injections and memory-resident implants |
| /dev/shm contents | `/dev/shm/` | T1055 | World-writable RAM-backed tmpfs; common drop location for malware (no disk persistence, but survives until reboot) |
| ~/.ssh/known_hosts | `~/.ssh/known_hosts` | T1021.004 | Reveals hosts this user has SSH'd to; lateral movement evidence |
| /etc/hosts | `/etc/hosts` | T1565.001 | Attackers modify to redirect DNS (intercept update traffic, redirect to malicious mirrors) |
| /var/log/dpkg.log | `/var/log/dpkg.log` | T1546.016 | Package installation/removal log; reveals unauthorized package installs or tampered package timestamps |
| Systemd override.conf | `/etc/systemd/system/<unit>.d/override.conf` | T1543.002 | Drop-in overrides for legitimate services; can inject `ExecStartPost` into any existing service |
| /proc/sys/kernel/modules_disabled | `/proc/sys/kernel/modules_disabled` | T1547.006 | If `1`, module loading is locked (integrity measure); rootkits may bypass or reset this |
| /tmp and /var/tmp | `/tmp/`, `/var/tmp/` | General | World-writable; common staging areas; `/var/tmp/` survives reboots unlike `/tmp/` |

---

## Detection Engineering Summary

### Highest-Signal IOCs (act immediately)

1. `/etc/ld.so.preload` contains any entry — rootkit near-certain
2. cron entry or script referencing `/tmp`, `/var/tmp`, `/dev/shm`
3. systemd unit not in package manifest with `Restart=always`
4. `~/.ssh/authorized_keys` modification outside business hours
5. `/etc/update-motd.d/` file not in package manifest with execute bit
6. `/etc/sudoers.d/` file containing `NOPASSWD: ALL`
7. udev rule with `RUN+=` targeting pseudo-device like `/dev/random`
8. PAM module in service config pointing to non-standard path
9. XDG `.desktop` file with `NoDisplay=true` and unusual `Exec=` path
10. UID=0 account other than `root` in `/etc/passwd`

### Tool Mapping

| Tool | Primary Use |
|------|-------------|
| `auditd` | Kernel-level syscall and file access monitoring; essential for capturing `init_module`, file writes to key paths |
| `rkhunter` / `chkrootkit` | Signature-based rootkit and backdoor scanning |
| `AIDE` / `Tripwire` | File integrity monitoring for `/etc/`, `/lib/`, `/bin/`, `/usr/` |
| `Volatility` (Linux profile) | Memory forensics; detect kernel hooking, hidden processes, LKM rootkits |
| `chipsec` | UEFI/BIOS firmware integrity analysis |
| `dpkg -V` / `rpm -V` | Package file integrity verification (hash check) |
| `systemd-analyze` | Timeline of systemd unit start times; reveals anomalous early-boot services |
| `journalctl` | Structured log query; cross-reference service execution with known persistence artifacts |
| `PANIX` | Linux persistence simulation for detection engineering and red team testing |

---

## Primary References

- [MITRE ATT&CK TA0003 — Persistence](https://attack.mitre.org/tactics/TA0003/)
- [Elastic Security Labs — Primer on Linux Persistence Mechanisms](https://www.elastic.co/security-labs/primer-on-persistence-mechanisms)
- [Elastic Security Labs — Sequel on Persistence Mechanisms](https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms)
- [Elastic Security Labs — Grand Finale on Linux Persistence](https://www.elastic.co/security-labs/the-grand-finale-on-linux-persistence)
- [PANIX — Linux Persistence Tool (Aegrah/Elastic)](https://github.com/Aegrah/PANIX)
- [Hunting for Persistence in Linux Series — pberba.github.io](https://pberba.github.io/security/2022/02/07/linux-threat-hunting-for-persistence-systemd-generators/)
- [Wazuh — Detecting Common Linux Persistence Techniques](https://wazuh.com/blog/detecting-common-linux-persistence-techniques-with-wazuh/)
- [Linux Forensics Cheatsheet — fareedfauzi.github.io](https://fareedfauzi.github.io/cheatsheets/linux-forensics/)
- [Wiz Blog — Linux Rootkits Part 1: Dynamic Linker Hijacking](https://www.wiz.io/blog/linux-rootkits-explained-part-1-dynamic-linker-hijacking)
- [Wiz Blog — Linux Rootkits Part 2: Loadable Kernel Modules](https://www.wiz.io/blog/linux-rootkits-explained-part-2-loadable-kernel-modules)
- [Elastic Security Labs — Declawing PUMAKIT](https://www.elastic.co/security-labs/declawing-pumakit)
- [Aon Cyber Labs — Unveiling sedexp](https://www.aon.com/en/insights/cyber-labs/unveiling-sedexp)
- [Picus Security — T1547.013 XDG Autostart Entries](https://www.picussecurity.com/resource/blog/t1547-013-xdg-autostart-entries)
- [Rapid7 — update-motd.d Persistence Module](https://www.rapid7.com/db/modules/exploit/linux/local/motd_persistence/)
- [Eclypsium — BootHole (CVE-2020-10713)](https://eclypsium.com/blog/theres-a-hole-in-the-boot/)
- [Forensic Artifacts in Modern Linux Systems — Prof. Dr. Bruce Nikkel](https://www.digitalforensics.ch/nikkel18.pdf)
- [0xMatheuZ — Linux Threat Hunting Persistence](https://matheuzsecurity.github.io/hacking/linux-threat-hunting-persistence/)
- [Atomic Red Team — T1547.006](https://www.atomicredteam.io/atomic-red-team/atomics/T1547.006)
