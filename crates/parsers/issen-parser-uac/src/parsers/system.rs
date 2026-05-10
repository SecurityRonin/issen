use serde::Serialize;

/// A parsed login record from `last` command output.
#[derive(Debug, Clone, Serialize)]
pub struct LoginRecord {
    pub user: String,
    pub terminal: String,
    pub source: String,
    pub login_time: Option<String>,
    pub logout_time: Option<String>,
    pub duration: Option<String>,
}

/// System information parsed from UAC system artifacts.
#[derive(Debug, Clone, Serialize, Default)]
pub struct SystemInfo {
    pub hostname: Option<String>,
    pub uname: Option<String>,
    pub uptime: Option<String>,
}

/// A storage device discovered from UAC collection artifacts.
///
/// Combines data from `lsblk`, `fdisk -l`, and `/dev/disk/by-id/` to
/// determine the device name, size, model, bus interface, and media type.
#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub struct StorageDevice {
    /// Kernel device name (e.g. `sda`, `nvme0n1`, `sr0`).
    pub name: String,
    /// Human-readable size string from lsblk (e.g. `20G`, `500M`).
    pub size: String,
    /// Device type from lsblk TYPE column (e.g. `disk`, `rom`).
    pub device_type: String,
    /// Disk model from `fdisk -l` (e.g. `VBOX HARDDISK`, `Samsung 970 EVO`).
    pub model: String,
    /// Bus interface detected from `/dev/disk/by-id/` prefixes.
    pub interface: StorageInterface,
    /// Media type inferred from interface + model + device type.
    pub media_type: MediaType,
}

/// Storage bus interface.
#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub enum StorageInterface {
    Sata,
    Nvme,
    Usb,
    #[default]
    Unknown,
}

/// Physical media type.
#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub enum MediaType {
    Ssd,
    Hdd,
    Optical,
    #[default]
    Unknown,
}

/// Comprehensive system profile parsed from a UAC collection.
///
/// Aggregates data from multiple directories within the extraction:
/// - `live_response/network/` — hostname, FQDN, IP addresses, hostnamectl
/// - `live_response/system/` — uname, uptime, timedatectl, free
/// - `live_response/storage/` — mount info, lsblk, fdisk, /dev/disk/by-id
/// - `[root]/etc/` — locale.conf
#[derive(Debug, Clone, Serialize, Default)]
pub struct SystemProfile {
    pub hostname: Option<String>,
    pub fqdn: Option<String>,
    pub os_name: Option<String>,
    pub kernel: Option<String>,
    pub architecture: Option<String>,
    pub platform: Option<String>,
    pub timezone: Option<String>,
    pub ip_addresses: Vec<String>,
    pub locale: Option<String>,
    /// Per-user locale overrides (`username` → `LANG value`).
    /// Parsed from shell configs (.bashrc, .zshrc, .profile, etc.)
    pub user_locales: Vec<(String, String)>,
    pub atime_policy: Option<String>,
    pub uptime: Option<String>,
    /// OS version string from `/etc/debian_version`, `/etc/os-release`, etc.
    /// More specific than `os_name` (e.g. "13.4" vs "Debian GNU/Linux 13 (trixie)").
    pub os_version: Option<String>,
    /// Total physical RAM in kibibytes (from `free` output).
    pub ram_total_kb: Option<u64>,
    /// Storage devices discovered from lsblk + fdisk + /dev/disk/by-id.
    pub storage_devices: Vec<StorageDevice>,
}

/// Parse `last` command output.
///
/// Format: `user  tty  source  login_day login_time - logout_time  (duration)`
#[must_use]
pub fn parse_last_output(content: &str) -> Vec<LoginRecord> {
    let mut results = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("wtmp begins")
            || trimmed.starts_with("btmp begins")
        {
            continue;
        }

        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }

        let user = fields[0].to_string();
        let terminal = fields[1].to_string();

        let (source, time_start_idx) = if fields.len() > 4
            && (fields[2].contains('.') || fields[2].contains(':') || fields[2] == "0.0.0.0")
        {
            (fields[2].to_string(), 3)
        } else {
            (String::new(), 2)
        };

        let login_time = if time_start_idx + 2 <= fields.len() {
            Some(fields[time_start_idx..time_start_idx + 2].join(" "))
        } else {
            None
        };

        let logout_time = fields
            .iter()
            .position(|&f| f == "-")
            .and_then(|i| fields.get(i + 1).map(|s| (*s).to_string()));

        let duration = fields
            .iter()
            .find(|f| f.starts_with('('))
            .map(|f| f.trim_start_matches('(').trim_end_matches(')').to_string());

        results.push(LoginRecord {
            user,
            terminal,
            source,
            login_time,
            logout_time,
            duration,
        });
    }

    results
}

/// Parse system info from UAC system directory files.
#[must_use]
pub fn parse_system_info(dir: &std::path::Path) -> SystemInfo {
    let hostname = read_first_of(dir, &["hostname.txt"]).map(|s| s.trim().to_string());
    let uname = read_first_of(dir, &["uname_-a.txt", "uname-a.txt"]).map(|s| s.trim().to_string());
    let uptime = read_first_of(dir, &["uptime.txt"]).map(|s| s.trim().to_string());

    SystemInfo {
        hostname,
        uname,
        uptime,
    }
}

/// Parse a comprehensive system profile from the UAC collection root.
///
/// Searches across `live_response/network/`, `live_response/system/`,
/// `live_response/storage/`, and `[root]/etc/` for profile data.
#[must_use]
pub fn parse_system_profile(root: &std::path::Path) -> SystemProfile {
    let net_dir = root.join("live_response/network");
    let sys_dir = root.join("live_response/system");
    let storage_dir = root.join("live_response/storage");
    let hw_dir = root.join("live_response/hardware");
    let etc_dir = root.join("[root]/etc");

    let mut profile = SystemProfile::default();

    // Hostname — try network dir first (hostname -f gives FQDN), then system dir
    profile.hostname = read_first_of(&net_dir, &["hostname.txt"])
        .or_else(|| read_first_of(&sys_dir, &["hostname.txt"]))
        .map(|s| s.trim().to_string());

    profile.fqdn = read_first_of(&net_dir, &["hostname_-f.txt", "hostname-f.txt"])
        .map(|s| s.trim().to_string());

    // hostnamectl gives us OS, kernel, arch, platform in one file
    if let Some(content) = read_first_of(&net_dir, &["hostnamectl.txt"]) {
        parse_hostnamectl(&content, &mut profile);
    }

    // VM version from dmesg or dmidecode (best-effort)
    let vm_version = read_first_of(&hw_dir, &["dmesg.txt"])
        .and_then(|c| parse_vm_version_from_dmesg(&c))
        .or_else(|| {
            read_first_of(&hw_dir, &["dmidecode.txt"])
                .and_then(|c| parse_vm_version_from_dmidecode(&c))
        });
    if let Some(ref version) = vm_version {
        // Enrich platform: "VirtualBox (oracle)" → "VirtualBox 7.1.8 (oracle)"
        if let Some(ref mut platform) = profile.platform {
            if let Some(paren_pos) = platform.find(" (") {
                platform.insert_str(paren_pos, &format!(" {version}"));
            } else {
                platform.push_str(&format!(" {version}"));
            }
        }
    }

    // Timezone from timedatectl
    if let Some(content) = read_first_of(&sys_dir, &["timedatectl_status.txt", "timedatectl.txt"]) {
        profile.timezone = parse_timedatectl_timezone(&content);
    }

    // IP addresses from ip addr show
    if let Some(content) = read_first_of(&net_dir, &["ip_addr_show.txt", "ip-addr-show.txt"]) {
        profile.ip_addresses = parse_ip_addresses(&content);
    }

    // Uptime
    profile.uptime = read_first_of(&sys_dir, &["uptime.txt"]).map(|s| s.trim().to_string());

    // Locale from /etc/locale.conf or /etc/default/locale
    if let Some(content) = read_first_of(&etc_dir, &["locale.conf", "default/locale"]) {
        profile.locale = parse_locale_conf(&content);
    }

    // User locale overrides from home directories
    profile.user_locales = collect_user_locales(root);

    // OS version from /etc/debian_version (point release)
    if let Some(content) = read_first_of(&etc_dir, &["debian_version", "redhat-release"]) {
        profile.os_version = parse_os_version(&content);
        // Enrich os_name with point release if available
        if let (Some(ref mut os_name), Some(ref version)) =
            (&mut profile.os_name, &profile.os_version)
        {
            *os_name = enrich_os_name_with_version(os_name, version);
        }
    }

    // Atime policy from mount output
    if let Some(content) = read_first_of(&storage_dir, &["mount.txt"]) {
        profile.atime_policy = parse_mount_atime(&content);
    }

    // RAM from free output
    if let Some(content) = read_first_of(&sys_dir, &["free.txt"]) {
        profile.ram_total_kb = parse_free_ram(&content);
    }

    // Storage devices from lsblk + fdisk + /dev/disk/by-id
    let lsblk = read_first_of(&storage_dir, &["lsblk.txt"]);
    let fdisk = read_first_of(&storage_dir, &["fdisk_-l.txt", "fdisk-l.txt"]);
    let devdisk = read_first_of(&storage_dir, &["ls_-l_dev_disk.txt", "ls-l-dev-disk.txt"]);
    profile.storage_devices =
        parse_storage_devices(lsblk.as_deref(), fdisk.as_deref(), devdisk.as_deref());

    profile
}

/// Try reading the first matching file from a list of candidate names.
fn read_first_of(dir: &std::path::Path, names: &[&str]) -> Option<String> {
    for name in names {
        if let Ok(content) = std::fs::read_to_string(dir.join(name)) {
            if !content.trim().is_empty() {
                return Some(content);
            }
        }
    }
    None
}

/// Extract fields from `hostnamectl` output.
///
/// Format: padded label + colon + value, e.g.:
/// ```text
///  Static hostname: vbox
/// Operating System: Debian GNU/Linux 13 (trixie)
///           Kernel: Linux 6.12.74+deb13+1-amd64
///     Architecture: x86-64
///   Virtualization: oracle
///   Hardware Model: VirtualBox
/// ```
fn parse_hostnamectl(content: &str, profile: &mut SystemProfile) {
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some((key, value)) = trimmed.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            match key {
                "Static hostname" => {
                    if profile.hostname.is_none() {
                        profile.hostname = Some(value.to_string());
                    }
                }
                "Operating System" => profile.os_name = Some(value.to_string()),
                "Kernel" => profile.kernel = Some(value.to_string()),
                "Architecture" => profile.architecture = Some(value.to_string()),
                "Virtualization" => {
                    // Combine virtualization + hardware model for platform
                    profile.platform = Some(value.to_string());
                }
                "Hardware Model" => {
                    // Merge: "VirtualBox" or "oracle (VirtualBox)"
                    if let Some(ref virt) = profile.platform {
                        profile.platform = Some(format!("{value} ({virt})"));
                    } else {
                        profile.platform = Some(value.to_string());
                    }
                }
                "Chassis" => {
                    // If no virtualization found, chassis tells us physical vs vm
                    if profile.platform.is_none() && value != "vm" {
                        profile.platform = Some("Physical".to_string());
                    }
                }
                _ => {}
            }
        }
    }
}

/// Extract timezone from `timedatectl status` output.
///
/// Looks for `Time zone: America/New_York (EDT, -0400)`.
#[must_use]
pub fn parse_timedatectl_timezone(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Time zone:") {
            let tz = rest.trim();
            if !tz.is_empty() {
                return Some(tz.to_string());
            }
        }
    }
    None
}

/// Extract non-loopback IPv4 addresses from `ip addr show` output.
///
/// Parses `inet A.B.C.D/prefix` lines, skipping `127.0.0.0/8`.
#[must_use]
pub fn parse_ip_addresses(content: &str) -> Vec<String> {
    let mut addrs = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            // "192.168.4.22/22 brd 192.168.7.255 scope global ..."
            if let Some(addr) = rest.split_whitespace().next() {
                if !addr.starts_with("127.") {
                    // Strip CIDR prefix for display
                    let ip = addr.split('/').next().unwrap_or(addr);
                    addrs.push(ip.to_string());
                }
            }
        }
    }
    addrs
}

/// Extract LANG= value from a locale.conf or /etc/default/locale file.
#[must_use]
pub fn parse_locale_conf(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("LANG=") {
            let val = rest.trim_matches('"').trim();
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

/// Determine the atime policy for the root filesystem from `mount` output.
///
/// Checks mount options for `/` and returns `"noatime"`, `"relatime"`,
/// `"strictatime"`, or `"atime"` (default).
///
/// On Windows, atime is controlled by the `NtfsDisableLastAccessUpdate`
/// registry key — that requires a separate check path.
#[must_use]
pub fn parse_mount_atime(content: &str) -> Option<String> {
    for line in content.lines() {
        // Format: "device on /mountpoint type fstype (options)"
        let parts: Vec<&str> = line.split_whitespace().collect();
        // Look for root filesystem: "on / type"
        if parts.len() >= 6 && parts[1] == "on" && parts[2] == "/" && parts[3] == "type" {
            let opts = parts.get(5).unwrap_or(&"");
            let opts = opts.trim_start_matches('(').trim_end_matches(')');
            if opts.contains("noatime") {
                return Some("noatime".to_string());
            } else if opts.contains("relatime") {
                return Some("relatime".to_string());
            } else if opts.contains("strictatime") {
                return Some("strictatime".to_string());
            } else {
                return Some("atime (default)".to_string());
            }
        }
    }
    None
}

/// Parse OS version from `/etc/debian_version` or similar.
///
/// Returns the trimmed version string (e.g. "13.4", "trixie/sid", "22.04").
#[must_use]
pub fn parse_os_version(content: &str) -> Option<String> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

/// Enrich the OS name from `hostnamectl` with a point release from `/etc/debian_version`.
///
/// If `os_name` contains a bare major version (e.g. "Debian GNU/Linux 13 (trixie)")
/// and `version` has a point release (e.g. "13.4"), replaces "13" with "13.4".
/// Returns the original if no substitution applies.
#[must_use]
pub fn enrich_os_name_with_version(os_name: &str, version: &str) -> String {
    // Extract major version from the point release: "13.4" → "13"
    let major = version.split('.').next().unwrap_or("");
    if major.is_empty() || !major.chars().all(|c| c.is_ascii_digit()) {
        return os_name.to_string();
    }

    // Check if os_name already contains the full version (e.g. "22.04.3")
    if os_name.contains(version) {
        return os_name.to_string();
    }

    // Look for the bare major version surrounded by non-digit boundaries
    // e.g. "Debian GNU/Linux 13 (trixie)" → replace "13" with "13.4"
    let mut result = os_name.to_string();
    if let Some(pos) = os_name.find(major) {
        let after = pos + major.len();
        let before_ok = pos == 0 || !os_name.as_bytes()[pos - 1].is_ascii_digit();
        let after_ok = after >= os_name.len() || !os_name.as_bytes()[after].is_ascii_digit();
        // Make sure we're not replacing inside a larger number
        // and that the version has a point release (contains '.')
        if before_ok && after_ok && version.contains('.') {
            result = format!("{}{}{}", &os_name[..pos], version, &os_name[after..]);
        }
    }
    result
}

/// Extract locale override values from a shell config file content.
///
/// Looks for uncommented `export LANG=...` or `export LC_ALL=...` lines.
/// Returns the locale values found (e.g. `["ja_JP.UTF-8"]`).
#[must_use]
pub fn parse_shell_locale_overrides(content: &str) -> Vec<String> {
    let mut locales = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        // Skip comments
        if trimmed.starts_with('#') {
            continue;
        }
        // Match: export LANG=value or export LC_ALL=value
        for var in &["LANG=", "LC_ALL="] {
            let pattern = format!("export {var}");
            if let Some(pos) = trimmed.find(&pattern) {
                let val_start = pos + pattern.len();
                let val = trimmed[val_start..]
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_matches('"')
                    .trim_matches('\'');
                if !val.is_empty() {
                    locales.push(val.to_string());
                }
            }
        }
    }
    locales
}

/// Scan user home directories for locale overrides in shell configs.
///
/// Checks `[root]/home/*/` and `[root]/root/` for `.bashrc`, `.zshrc`,
/// `.zprofile`, `.bash_profile`, `.profile` files containing `export LANG=`
/// or `export LC_ALL=` directives.
///
/// Returns `(username, locale)` pairs for users who override the system locale.
#[must_use]
pub fn collect_user_locales(root: &std::path::Path) -> Vec<(String, String)> {
    let shell_configs = [
        ".bashrc",
        ".zshrc",
        ".zprofile",
        ".bash_profile",
        ".profile",
    ];
    let mut results = Vec::new();

    // Collect candidate home dirs: [root]/home/* and [root]/root
    let mut homes: Vec<(String, std::path::PathBuf)> = Vec::new();

    let home_dir = root.join("[root]/home");
    if home_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&home_dir) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    let username = entry.file_name().to_string_lossy().to_string();
                    homes.push((username, entry.path()));
                }
            }
        }
    }

    let root_home = root.join("[root]/root");
    if root_home.is_dir() {
        homes.push(("root".to_string(), root_home));
    }

    // Scan each home dir for locale overrides
    for (username, home_path) in &homes {
        let mut user_locale = None;
        for config_name in &shell_configs {
            let config_path = home_path.join(config_name);
            if let Ok(content) = std::fs::read_to_string(&config_path) {
                let overrides = parse_shell_locale_overrides(&content);
                if let Some(first) = overrides.into_iter().next() {
                    // LC_ALL takes precedence, but we take the first override found
                    user_locale = Some(first);
                    break;
                }
            }
        }
        if let Some(locale) = user_locale {
            results.push((username.clone(), locale));
        }
    }

    results.sort_by(|a, b| a.0.cmp(&b.0));
    results
}

/// Extract VirtualBox host version from `dmesg` output.
///
/// Looks for `vboxguest: host-version: 7.1.8r168469` and extracts the
/// version number before the 'r' (revision) suffix.
#[must_use]
pub fn parse_vm_version_from_dmesg(content: &str) -> Option<String> {
    for line in content.lines() {
        if let Some(pos) = line.find("vboxguest: host-version:") {
            let rest = &line[pos + "vboxguest: host-version:".len()..];
            let version = rest.trim().split_whitespace().next()?;
            // Strip revision suffix: "7.1.8r168469" → "7.1.8"
            let clean = version.split('r').next().unwrap_or(version);
            if !clean.is_empty() {
                return Some(clean.to_string());
            }
        }
    }
    None
}

/// Extract VirtualBox version from `dmidecode` output.
///
/// Looks for `vboxVer_7.1.8` in OEM Strings section.
#[must_use]
pub fn parse_vm_version_from_dmidecode(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(pos) = trimmed.find("vboxVer_") {
            let version = &trimmed[pos + "vboxVer_".len()..];
            let clean = version.trim();
            if !clean.is_empty() {
                return Some(clean.to_string());
            }
        }
    }
    None
}

/// Parse total RAM from `free` command output.
///
/// Looks for the `Mem:` line and extracts the `total` field (in kibibytes).
/// Format: `Mem:   8138104   2931872   4967944   6580   553244   5206232`
#[must_use]
pub fn parse_free_ram(content: &str) -> Option<u64> {
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Mem:") {
            return rest.split_whitespace().next().and_then(|s| s.parse().ok());
        }
    }
    None
}

/// Parse storage devices by combining data from `lsblk`, `fdisk -l`, and
/// `/dev/disk/by-id/` listing.
///
/// - `lsblk` provides device names, sizes, and types (disk/rom).
/// - `fdisk -l` provides disk models.
/// - `/dev/disk/by-id/` provides interface detection (ata-/nvme-/usb- prefixes).
#[must_use]
pub fn parse_storage_devices(
    lsblk: Option<&str>,
    fdisk: Option<&str>,
    devdisk: Option<&str>,
) -> Vec<StorageDevice> {
    let mut devices = Vec::new();

    // Step 1: Parse lsblk for top-level devices (disk/rom only, skip partitions)
    if let Some(content) = lsblk {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("NAME") {
                continue;
            }
            let fields: Vec<&str> = trimmed.split_whitespace().collect();
            if fields.len() < 6 {
                continue;
            }
            let dev_type = fields[5];
            if dev_type != "disk" && dev_type != "rom" {
                continue;
            }
            let name = fields[0]
                .trim_start_matches(|c: char| "|-`".contains(c))
                .to_string();
            let size = fields[3].to_string();

            devices.push(StorageDevice {
                name,
                size,
                device_type: dev_type.to_string(),
                ..StorageDevice::default()
            });
        }
    }

    // Step 2: Enrich with disk models from fdisk
    if let Some(content) = fdisk {
        let mut current_dev = String::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("Disk /dev/") {
                if let Some(colon_pos) = rest.find(':') {
                    current_dev = rest[..colon_pos].to_string();
                }
            }
            if let Some(model) = trimmed.strip_prefix("Disk model:") {
                let model = model.trim().to_string();
                if !model.is_empty() && !current_dev.is_empty() {
                    if let Some(dev) = devices.iter_mut().find(|d| d.name == current_dev) {
                        dev.model = model;
                    }
                }
            }
        }
    }

    // Step 3: Detect interface from /dev/disk/by-id/ symlinks
    if let Some(content) = devdisk {
        let mut in_by_id = false;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.contains("/dev/disk/by-id") {
                in_by_id = true;
                continue;
            }
            if trimmed.ends_with(':') && !trimmed.contains("by-id") {
                in_by_id = false;
                continue;
            }
            if !in_by_id {
                continue;
            }
            if let Some(arrow_pos) = trimmed.find("-> ../../") {
                let target = &trimmed[arrow_pos + 9..];
                let link_part = &trimmed[..arrow_pos];
                if link_part.contains("-part") {
                    continue;
                }
                let interface = if link_part.contains("ata-") {
                    StorageInterface::Sata
                } else if link_part.contains("nvme-") {
                    StorageInterface::Nvme
                } else if link_part.contains("usb-") {
                    StorageInterface::Usb
                } else {
                    StorageInterface::Unknown
                };
                if let Some(dev) = devices.iter_mut().find(|d| d.name == target) {
                    dev.interface = interface;
                }
            }
        }
    }

    // Step 4: Infer media type from interface + model + device_type
    for dev in &mut devices {
        dev.media_type = infer_media_type(dev);
    }

    devices
}

/// Infer physical media type from available device metadata.
///
/// - NVMe → always SSD
/// - device_type "rom" → Optical
/// - Model contains "SSD" → SSD
/// - SATA with no SSD indicator → HDD (conservative default)
fn infer_media_type(dev: &StorageDevice) -> MediaType {
    if dev.device_type == "rom" {
        return MediaType::Optical;
    }
    if matches!(dev.interface, StorageInterface::Nvme) {
        return MediaType::Ssd;
    }
    let model_upper = dev.model.to_uppercase();
    if model_upper.contains("SSD") || model_upper.contains("SOLID STATE") {
        return MediaType::Ssd;
    }
    if matches!(dev.interface, StorageInterface::Sata) || !dev.model.is_empty() {
        return MediaType::Hdd;
    }
    MediaType::Unknown
}

impl std::fmt::Display for StorageInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sata => write!(f, "SATA"),
            Self::Nvme => write!(f, "NVMe"),
            Self::Usb => write!(f, "USB"),
            Self::Unknown => write!(f, ""),
        }
    }
}

impl std::fmt::Display for MediaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ssd => write!(f, "SSD"),
            Self::Hdd => write!(f, "HDD"),
            Self::Optical => write!(f, "Optical"),
            Self::Unknown => write!(f, ""),
        }
    }
}

/// Format RAM size in human-readable units.
#[must_use]
pub fn format_ram_kb(kb: u64) -> String {
    if kb >= 1_048_576 {
        let gib = kb as f64 / 1_048_576.0;
        if gib >= 10.0 {
            format!("{:.0} GB", gib)
        } else {
            format!("{:.1} GB", gib)
        }
    } else {
        let mib = kb as f64 / 1_024.0;
        format!("{:.0} MB", mib)
    }
}

/// Format a single storage device for dashboard display.
///
/// Examples:
/// - `sda: 20G HDD (SATA) — VBOX HARDDISK`
/// - `nvme0n1: 500G SSD (NVMe) — Samsung 970 EVO`
/// - `sr0: 1024M Optical`
#[must_use]
pub fn format_storage_device(dev: &StorageDevice) -> String {
    let mut parts = vec![format!("{}: {}", dev.name, dev.size)];

    let media = dev.media_type.to_string();
    if !media.is_empty() {
        parts.push(media);
    }

    let iface = dev.interface.to_string();
    if !iface.is_empty() {
        parts.push(format!("({iface})"));
    }

    let mut result = parts.join(" ");

    if !dev.model.is_empty() {
        result.push_str(&format!(" — {}", dev.model));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_last_output() {
        let content = "root     pts/0        10.0.0.5         Mon Mar 24 19:38   still logged in\n\
                        admin    tty1                          Mon Mar 24 10:00 - 12:30  (02:30)\n\
                        \n\
                        wtmp begins Mon Mar 24 00:00:00 2026\n";
        let records = parse_last_output(content);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].user, "root");
        assert_eq!(records[0].terminal, "pts/0");
        assert_eq!(records[0].source, "10.0.0.5");
        assert_eq!(records[1].user, "admin");
    }

    #[test]
    fn test_parse_last_empty() {
        assert!(parse_last_output("").is_empty());
        assert!(parse_last_output("wtmp begins Mon Mar 24 00:00:00 2026\n").is_empty());
    }

    #[test]
    fn test_parse_system_info() {
        let dir = tempfile::tempdir().expect("tmpdir");
        std::fs::write(dir.path().join("hostname.txt"), "testhost\n").expect("write");
        // Test underscore variant (actual UAC naming)
        std::fs::write(dir.path().join("uname_-a.txt"), "Linux testhost 5.15.0\n").expect("write");

        let info = parse_system_info(dir.path());
        assert_eq!(info.hostname.as_deref(), Some("testhost"));
        assert!(info.uname.as_ref().expect("uname").contains("Linux"));
        assert!(info.uptime.is_none());
    }

    #[test]
    fn test_parse_system_info_hyphen_variant() {
        let dir = tempfile::tempdir().expect("tmpdir");
        // Test hyphen variant (older UAC naming)
        std::fs::write(dir.path().join("uname-a.txt"), "Linux host 5.10\n").expect("write");
        let info = parse_system_info(dir.path());
        assert!(info.uname.as_ref().expect("uname").contains("Linux"));
    }

    #[test]
    fn test_parse_hostnamectl() {
        let content = " Static hostname: vbox\n\
                        Icon name: computer-vm\n\
                        Chassis: vm\n\
                        Virtualization: oracle\n\
                        Operating System: Debian GNU/Linux 13 (trixie)\n\
                        Kernel: Linux 6.12.74+deb13+1-amd64\n\
                        Architecture: x86-64\n\
                        Hardware Model: VirtualBox\n";
        let mut profile = SystemProfile::default();
        parse_hostnamectl(content, &mut profile);
        assert_eq!(profile.hostname.as_deref(), Some("vbox"));
        assert_eq!(
            profile.os_name.as_deref(),
            Some("Debian GNU/Linux 13 (trixie)")
        );
        assert_eq!(
            profile.kernel.as_deref(),
            Some("Linux 6.12.74+deb13+1-amd64")
        );
        assert_eq!(profile.architecture.as_deref(), Some("x86-64"));
        assert_eq!(profile.platform.as_deref(), Some("VirtualBox (oracle)"));
    }

    #[test]
    fn test_parse_hostnamectl_physical() {
        let content = " Static hostname: server01\n\
                        Chassis: server\n\
                        Operating System: Ubuntu 22.04 LTS\n";
        let mut profile = SystemProfile::default();
        parse_hostnamectl(content, &mut profile);
        assert_eq!(profile.hostname.as_deref(), Some("server01"));
        assert_eq!(profile.platform.as_deref(), Some("Physical"));
    }

    #[test]
    fn test_parse_timedatectl_timezone() {
        let content = "               Local time: Tue 2026-03-24 19:39:35 EDT\n\
                        Time zone: America/New_York (EDT, -0400)\n\
                        System clock synchronized: yes\n";
        let tz = parse_timedatectl_timezone(content);
        assert_eq!(tz.as_deref(), Some("America/New_York (EDT, -0400)"));
    }

    #[test]
    fn test_parse_timedatectl_no_timezone() {
        assert_eq!(parse_timedatectl_timezone("no relevant data"), None);
    }

    #[test]
    fn test_parse_ip_addresses() {
        let content = "1: lo: <LOOPBACK,UP,LOWER_UP>\n\
                        inet 127.0.0.1/8 scope host lo\n\
                        2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP>\n\
                        inet 192.168.4.22/22 brd 192.168.7.255 scope global\n\
                        inet 10.0.0.5/24 brd 10.0.0.255 scope global\n";
        let addrs = parse_ip_addresses(content);
        assert_eq!(addrs, vec!["192.168.4.22", "10.0.0.5"]);
    }

    #[test]
    fn test_parse_ip_addresses_loopback_only() {
        let content = "inet 127.0.0.1/8 scope host lo\n";
        assert!(parse_ip_addresses(content).is_empty());
    }

    #[test]
    fn test_parse_locale_conf() {
        let content = "#  File generated by update-locale\nLANG=\"en_US.UTF-8\"\n";
        assert_eq!(parse_locale_conf(content).as_deref(), Some("en_US.UTF-8"));
    }

    #[test]
    fn test_parse_locale_conf_unquoted() {
        assert_eq!(
            parse_locale_conf("LANG=C.UTF-8\n").as_deref(),
            Some("C.UTF-8")
        );
    }

    #[test]
    fn test_parse_locale_conf_empty() {
        assert_eq!(parse_locale_conf("# comment only\n"), None);
    }

    #[test]
    fn test_parse_mount_atime_relatime() {
        let content = "/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)\n\
                        tmpfs on /tmp type tmpfs (rw,nosuid,nodev)\n";
        assert_eq!(parse_mount_atime(content).as_deref(), Some("relatime"));
    }

    #[test]
    fn test_parse_mount_atime_noatime() {
        let content = "/dev/nvme0n1p2 on / type btrfs (rw,noatime,compress=zstd)\n";
        assert_eq!(parse_mount_atime(content).as_deref(), Some("noatime"));
    }

    #[test]
    fn test_parse_mount_atime_default() {
        let content = "/dev/sda1 on / type ext4 (rw,errors=remount-ro)\n";
        assert_eq!(
            parse_mount_atime(content).as_deref(),
            Some("atime (default)")
        );
    }

    #[test]
    fn test_parse_mount_no_root() {
        let content = "tmpfs on /tmp type tmpfs (rw,nosuid)\n";
        assert_eq!(parse_mount_atime(content), None);
    }

    #[test]
    fn test_parse_system_profile_full() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let root = dir.path();

        // Create directory structure
        std::fs::create_dir_all(root.join("live_response/network")).expect("mkdir");
        std::fs::create_dir_all(root.join("live_response/system")).expect("mkdir");
        std::fs::create_dir_all(root.join("live_response/storage")).expect("mkdir");
        std::fs::create_dir_all(root.join("[root]/etc")).expect("mkdir");

        std::fs::write(root.join("live_response/network/hostname.txt"), "testbox\n")
            .expect("write");
        std::fs::write(
            root.join("live_response/network/hostname_-f.txt"),
            "testbox.lab.local\n",
        )
        .expect("write");
        std::fs::write(
            root.join("live_response/network/hostnamectl.txt"),
            " Static hostname: testbox\n\
             Operating System: Ubuntu 22.04 LTS\n\
             Kernel: Linux 5.15.0-generic\n\
             Architecture: x86-64\n\
             Chassis: server\n",
        )
        .expect("write");
        std::fs::write(
            root.join("live_response/system/timedatectl_status.txt"),
            "Time zone: Europe/London (BST, +0100)\n",
        )
        .expect("write");
        std::fs::write(
            root.join("live_response/network/ip_addr_show.txt"),
            "inet 127.0.0.1/8 scope host lo\n\
             inet 10.1.2.3/24 brd 10.1.2.255 scope global\n",
        )
        .expect("write");
        std::fs::write(
            root.join("live_response/system/uptime.txt"),
            " 14:30:00 up 3 days, 2:15\n",
        )
        .expect("write");
        std::fs::write(
            root.join("[root]/etc/locale.conf"),
            "LANG=\"en_GB.UTF-8\"\n",
        )
        .expect("write");
        std::fs::write(
            root.join("live_response/storage/mount.txt"),
            "/dev/sda1 on / type ext4 (rw,noatime)\n",
        )
        .expect("write");

        let profile = parse_system_profile(root);
        assert_eq!(profile.hostname.as_deref(), Some("testbox"));
        assert_eq!(profile.fqdn.as_deref(), Some("testbox.lab.local"));
        assert_eq!(profile.os_name.as_deref(), Some("Ubuntu 22.04 LTS"));
        assert_eq!(profile.kernel.as_deref(), Some("Linux 5.15.0-generic"));
        assert_eq!(profile.architecture.as_deref(), Some("x86-64"));
        assert_eq!(profile.platform.as_deref(), Some("Physical"));
        assert_eq!(
            profile.timezone.as_deref(),
            Some("Europe/London (BST, +0100)")
        );
        assert_eq!(profile.ip_addresses, vec!["10.1.2.3"]);
        assert_eq!(profile.locale.as_deref(), Some("en_GB.UTF-8"));
        assert_eq!(profile.atime_policy.as_deref(), Some("noatime"));
        assert!(profile.uptime.is_some());
    }

    #[test]
    fn test_parse_system_profile_empty_dir() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let profile = parse_system_profile(dir.path());
        assert!(profile.hostname.is_none());
        assert!(profile.os_name.is_none());
        assert!(profile.ip_addresses.is_empty());
    }

    // =====================================================================
    // TDD redo — tests written BEFORE implementations
    // =====================================================================

    // --- parse_free_ram: contract ---
    // Input: raw `free` output text
    // Output: Option<u64> total RAM in kibibytes
    // Must handle: standard format, tabs, large values, missing Mem line,
    //              non-numeric total, empty input, human-readable output

    #[test]
    fn free_ram_standard_format() {
        // Standard `free` output with space-separated columns
        let content = "\
               total        used        free      shared  buff/cache   available
Mem:         8138104     2931872     4967944        6580      553244     5206232
Swap:        1127420        3352     1124068";
        assert_eq!(parse_free_ram(content), Some(8138104));
    }

    #[test]
    fn free_ram_tab_separated() {
        // Some systems use tabs instead of spaces
        let content = "Mem:\t32879668\t8000000\t20000000\t100000\t4000000\t24000000\n";
        assert_eq!(parse_free_ram(content), Some(32879668));
    }

    #[test]
    fn free_ram_no_mem_line() {
        // Header only, no Mem: line — should return None
        let content = "               total        used        free\n";
        assert_eq!(parse_free_ram(content), None);
    }

    #[test]
    fn free_ram_empty_input() {
        assert_eq!(parse_free_ram(""), None);
    }

    #[test]
    fn free_ram_mem_line_no_value() {
        // Mem: line present but no numeric value after it
        let content = "Mem:\n";
        assert_eq!(parse_free_ram(content), None);
    }

    #[test]
    fn free_ram_human_readable_format() {
        // `free -h` produces "Mem:  7.8Gi  2.8Gi  4.7Gi ..."
        // This should return None — we only parse kibibyte values
        let content = "Mem:           7.8Gi       2.8Gi       4.7Gi\n";
        assert_eq!(parse_free_ram(content), None);
    }

    #[test]
    fn free_ram_large_server() {
        // 512 GB server — test u64 range
        let content = "Mem:       536870912   100000000   400000000\n";
        assert_eq!(parse_free_ram(content), Some(536870912));
    }

    // --- format_ram_kb: contract ---
    // Input: u64 kibibytes
    // Output: human-readable string with appropriate unit (MB or GB)
    // Rules: >= 1 GiB shows GB; < 10 GB shows 1 decimal; >= 10 GB shows integer

    #[test]
    fn format_ram_zero() {
        // Edge case: 0 KB
        assert_eq!(format_ram_kb(0), "0 MB");
    }

    #[test]
    fn format_ram_sub_gib() {
        // 512 MiB = 524288 KiB — should show MB
        assert_eq!(format_ram_kb(524288), "512 MB");
    }

    #[test]
    fn format_ram_exactly_one_gib() {
        // 1048576 KiB = 1.0 GiB — should show "1.0 GB" (< 10, 1 decimal)
        assert_eq!(format_ram_kb(1048576), "1.0 GB");
    }

    #[test]
    fn format_ram_fractional_gib() {
        // 8138104 KiB ≈ 7.76 GiB — should show "7.8 GB"
        assert_eq!(format_ram_kb(8138104), "7.8 GB");
    }

    #[test]
    fn format_ram_large_integer_gib() {
        // 16 GiB = 16777216 KiB — should show "16 GB" (>= 10, no decimal)
        assert_eq!(format_ram_kb(16777216), "16 GB");
    }

    #[test]
    fn format_ram_32g() {
        // 32879668 KiB ≈ 31.35 GiB — should show "31 GB"
        assert_eq!(format_ram_kb(32879668), "31 GB");
    }

    #[test]
    fn format_ram_tiny() {
        // Very small: 256 KiB — should still show MB (0 MB after rounding)
        let result = format_ram_kb(256);
        assert!(result.contains("MB"), "expected MB unit, got: {result}");
    }

    // --- infer_media_type: contract ---
    // Input: &StorageDevice with interface, model, device_type
    // Output: MediaType
    // Rules:
    //   rom → Optical (regardless of other fields)
    //   NVMe interface → SSD (always)
    //   Model contains "SSD" or "SOLID STATE" (case-insensitive) → SSD
    //   SATA with no SSD indicator → HDD
    //   Has a model but unknown interface → HDD (conservative)
    //   No model, unknown interface → Unknown

    #[test]
    fn infer_media_optical_rom() {
        let dev = StorageDevice {
            device_type: "rom".to_string(),
            interface: StorageInterface::Sata,
            ..StorageDevice::default()
        };
        assert_eq!(infer_media_type(&dev), MediaType::Optical);
    }

    #[test]
    fn infer_media_nvme_always_ssd() {
        let dev = StorageDevice {
            interface: StorageInterface::Nvme,
            device_type: "disk".to_string(),
            model: "Some Unknown Drive".to_string(),
            ..StorageDevice::default()
        };
        assert_eq!(infer_media_type(&dev), MediaType::Ssd);
    }

    #[test]
    fn infer_media_model_contains_ssd() {
        let dev = StorageDevice {
            interface: StorageInterface::Sata,
            device_type: "disk".to_string(),
            model: "Samsung SSD 860 EVO".to_string(),
            ..StorageDevice::default()
        };
        assert_eq!(infer_media_type(&dev), MediaType::Ssd);
    }

    #[test]
    fn infer_media_model_contains_solid_state() {
        let dev = StorageDevice {
            interface: StorageInterface::Sata,
            device_type: "disk".to_string(),
            model: "Intel Solid State Drive".to_string(),
            ..StorageDevice::default()
        };
        assert_eq!(infer_media_type(&dev), MediaType::Ssd);
    }

    #[test]
    fn infer_media_sata_hdd_default() {
        // SATA drive with a model that doesn't mention SSD → HDD
        let dev = StorageDevice {
            interface: StorageInterface::Sata,
            device_type: "disk".to_string(),
            model: "VBOX HARDDISK".to_string(),
            ..StorageDevice::default()
        };
        assert_eq!(infer_media_type(&dev), MediaType::Hdd);
    }

    #[test]
    fn infer_media_unknown_interface_with_model() {
        // Has model text but unknown interface → HDD (conservative)
        let dev = StorageDevice {
            interface: StorageInterface::Unknown,
            device_type: "disk".to_string(),
            model: "WDC WD10EZEX".to_string(),
            ..StorageDevice::default()
        };
        assert_eq!(infer_media_type(&dev), MediaType::Hdd);
    }

    #[test]
    fn infer_media_unknown_everything() {
        // No model, no interface, not rom → Unknown
        let dev = StorageDevice {
            interface: StorageInterface::Unknown,
            device_type: "disk".to_string(),
            model: String::new(),
            ..StorageDevice::default()
        };
        assert_eq!(infer_media_type(&dev), MediaType::Unknown);
    }

    #[test]
    fn infer_media_usb_flash_no_ssd_label() {
        // USB drive with no SSD label and no model — should be Unknown
        // (we can't tell if it's a USB HDD enclosure or a flash drive)
        let dev = StorageDevice {
            interface: StorageInterface::Usb,
            device_type: "disk".to_string(),
            model: String::new(),
            ..StorageDevice::default()
        };
        // USB with no model info → Unknown (can't determine media type)
        assert_eq!(infer_media_type(&dev), MediaType::Unknown);
    }

    // --- Display impls: contract ---

    #[test]
    fn display_storage_interface() {
        assert_eq!(StorageInterface::Sata.to_string(), "SATA");
        assert_eq!(StorageInterface::Nvme.to_string(), "NVMe");
        assert_eq!(StorageInterface::Usb.to_string(), "USB");
        assert_eq!(StorageInterface::Unknown.to_string(), "");
    }

    #[test]
    fn display_media_type() {
        assert_eq!(MediaType::Ssd.to_string(), "SSD");
        assert_eq!(MediaType::Hdd.to_string(), "HDD");
        assert_eq!(MediaType::Optical.to_string(), "Optical");
        assert_eq!(MediaType::Unknown.to_string(), "");
    }

    // --- parse_storage_devices: contract ---
    // Input: Optional content from lsblk, fdisk, /dev/disk/by-id listing
    // Output: Vec<StorageDevice> — only whole-disk devices, not partitions
    // Must handle: all three present, any subset, none, various device types

    #[test]
    fn storage_devices_all_sources_vbox() {
        let lsblk = "NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS\n\
                      sda      8:0    0   20G  0 disk \n\
                      |-sda1   8:1    0 18.9G  0 part /\n\
                      |-sda2   8:2    0    1K  0 part \n\
                      `-sda5   8:5    0  1.1G  0 part [SWAP]\n\
                      sr0     11:0    1 1024M  0 rom  \n";
        let fdisk = "Disk /dev/sda: 20 GiB, 21474836480 bytes, 41943040 sectors\n\
                     Disk model: VBOX HARDDISK   \n";
        let devdisk = "/dev/disk/by-id:\n\
                       total 0\n\
                       lrwxrwxrwx 1 root root  9 Mar 24 19:21 ata-VBOX_CD-ROM_VB2-01700376 -> ../../sr0\n\
                       lrwxrwxrwx 1 root root  9 Mar 24 19:18 ata-VBOX_HARDDISK_VB5541180d -> ../../sda\n\
                       lrwxrwxrwx 1 root root 10 Mar 24 19:18 ata-VBOX_HARDDISK_VB5541180d-part1 -> ../../sda1\n";

        let devices = parse_storage_devices(Some(lsblk), Some(fdisk), Some(devdisk));
        assert_eq!(devices.len(), 2, "should find sda + sr0, not partitions");

        assert_eq!(devices[0].name, "sda");
        assert_eq!(devices[0].size, "20G");
        assert_eq!(devices[0].model, "VBOX HARDDISK");
        assert_eq!(devices[0].interface, StorageInterface::Sata);
        assert_eq!(devices[0].media_type, MediaType::Hdd);

        assert_eq!(devices[1].name, "sr0");
        assert_eq!(devices[1].device_type, "rom");
        assert_eq!(devices[1].media_type, MediaType::Optical);
    }

    #[test]
    fn storage_devices_nvme() {
        let lsblk = "NAME        MAJ:MIN RM   SIZE RO TYPE MOUNTPOINTS\n\
                      nvme0n1     259:0    0   500G  0 disk \n\
                      |-nvme0n1p1 259:1    0   512M  0 part /boot\n\
                      `-nvme0n1p2 259:2    0 499.5G  0 part /\n";
        let fdisk = "Disk /dev/nvme0n1: 500 GiB\n\
                     Disk model: Samsung 970 EVO Plus\n";
        let devdisk = "/dev/disk/by-id:\n\
                       total 0\n\
                       lrwxrwxrwx 1 root root 13 Mar 24 10:00 nvme-Samsung_970_EVO_Plus -> ../../nvme0n1\n\
                       lrwxrwxrwx 1 root root 15 Mar 24 10:00 nvme-Samsung_970_EVO_Plus-part1 -> ../../nvme0n1p1\n";

        let devices = parse_storage_devices(Some(lsblk), Some(fdisk), Some(devdisk));
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].name, "nvme0n1");
        assert_eq!(devices[0].interface, StorageInterface::Nvme);
        assert_eq!(devices[0].media_type, MediaType::Ssd);
        assert_eq!(devices[0].model, "Samsung 970 EVO Plus");
    }

    #[test]
    fn storage_devices_sata_ssd_from_model() {
        // SATA SSD detected via model name containing "SSD"
        let lsblk = "NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS\n\
                      sda      8:0    0  256G  0 disk \n";
        let fdisk = "Disk /dev/sda: 256 GiB\n\
                     Disk model: Samsung SSD 860\n";
        let devdisk = "/dev/disk/by-id:\n\
                       lrwxrwxrwx 1 root root  9 Mar 24 10:00 ata-Samsung_SSD_860_EVO -> ../../sda\n";

        let devices = parse_storage_devices(Some(lsblk), Some(fdisk), Some(devdisk));
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].interface, StorageInterface::Sata);
        assert_eq!(devices[0].media_type, MediaType::Ssd);
    }

    #[test]
    fn storage_devices_lsblk_only() {
        // Only lsblk available — no model, no interface info
        let lsblk = "NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS\n\
                      sda      8:0    0  100G  0 disk \n";
        let devices = parse_storage_devices(Some(lsblk), None, None);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].name, "sda");
        assert_eq!(devices[0].model, "");
        assert_eq!(devices[0].interface, StorageInterface::Unknown);
        assert_eq!(devices[0].media_type, MediaType::Unknown);
    }

    #[test]
    fn storage_devices_no_data() {
        assert!(parse_storage_devices(None, None, None).is_empty());
    }

    #[test]
    fn storage_devices_usb_drive() {
        let lsblk = "NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS\n\
                      sdb      8:16   1   32G  0 disk \n";
        let devdisk = "/dev/disk/by-id:\n\
                       lrwxrwxrwx 1 root root 9 Mar 24 10:00 usb-SanDisk_Cruzer_1234 -> ../../sdb\n";
        let devices = parse_storage_devices(Some(lsblk), None, Some(devdisk));
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].interface, StorageInterface::Usb);
    }

    #[test]
    fn storage_devices_multiple_disks() {
        // Server with two SATA drives + NVMe boot
        let lsblk = "NAME        MAJ:MIN RM   SIZE RO TYPE MOUNTPOINTS\n\
                      sda           8:0    0     2T  0 disk \n\
                      sdb           8:16   0     2T  0 disk \n\
                      nvme0n1     259:0    0   256G  0 disk \n";
        let devices = parse_storage_devices(Some(lsblk), None, None);
        assert_eq!(devices.len(), 3);
        assert_eq!(devices[0].name, "sda");
        assert_eq!(devices[1].name, "sdb");
        assert_eq!(devices[2].name, "nvme0n1");
    }

    #[test]
    fn storage_devices_fdisk_multiple_models() {
        // fdisk output with multiple "Disk /dev/" and "Disk model:" pairs
        let lsblk = "NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS\n\
                      sda      8:0    0  500G  0 disk \n\
                      sdb      8:16   0    1T  0 disk \n";
        let fdisk = "Disk /dev/sda: 500 GiB\n\
                     Disk model: WDC WD5003ABYZ\n\
                     \n\
                     Disk /dev/sdb: 1 TiB\n\
                     Disk model: Seagate Barracuda\n";
        let devices = parse_storage_devices(Some(lsblk), Some(fdisk), None);
        assert_eq!(devices[0].model, "WDC WD5003ABYZ");
        assert_eq!(devices[1].model, "Seagate Barracuda");
    }

    // --- format_storage_device: contract ---
    // Input: &StorageDevice
    // Output: "name: size [MediaType] [(Interface)] [— model]"
    // Rules: omit media/interface/model when empty/Unknown

    #[test]
    fn format_device_full() {
        let dev = StorageDevice {
            name: "sda".to_string(),
            size: "20G".to_string(),
            device_type: "disk".to_string(),
            model: "VBOX HARDDISK".to_string(),
            interface: StorageInterface::Sata,
            media_type: MediaType::Hdd,
        };
        assert_eq!(
            format_storage_device(&dev),
            "sda: 20G HDD (SATA) — VBOX HARDDISK"
        );
    }

    #[test]
    fn format_device_nvme_ssd() {
        let dev = StorageDevice {
            name: "nvme0n1".to_string(),
            size: "500G".to_string(),
            device_type: "disk".to_string(),
            model: "Samsung 970 EVO Plus".to_string(),
            interface: StorageInterface::Nvme,
            media_type: MediaType::Ssd,
        };
        assert_eq!(
            format_storage_device(&dev),
            "nvme0n1: 500G SSD (NVMe) — Samsung 970 EVO Plus"
        );
    }

    #[test]
    fn format_device_optical_no_model() {
        let dev = StorageDevice {
            name: "sr0".to_string(),
            size: "1024M".to_string(),
            device_type: "rom".to_string(),
            model: String::new(),
            interface: StorageInterface::Sata,
            media_type: MediaType::Optical,
        };
        assert_eq!(format_storage_device(&dev), "sr0: 1024M Optical (SATA)");
    }

    #[test]
    fn format_device_minimal_info() {
        // Only name and size — no media type, no interface, no model
        let dev = StorageDevice {
            name: "sda".to_string(),
            size: "100G".to_string(),
            device_type: "disk".to_string(),
            model: String::new(),
            interface: StorageInterface::Unknown,
            media_type: MediaType::Unknown,
        };
        // Should just show "sda: 100G" with no trailing garbage
        assert_eq!(format_storage_device(&dev), "sda: 100G");
    }

    #[test]
    fn format_device_interface_but_no_model() {
        let dev = StorageDevice {
            name: "sdb".to_string(),
            size: "32G".to_string(),
            device_type: "disk".to_string(),
            model: String::new(),
            interface: StorageInterface::Usb,
            media_type: MediaType::Unknown,
        };
        assert_eq!(format_storage_device(&dev), "sdb: 32G (USB)");
    }

    // --- OS version enrichment tests ---

    #[test]
    fn test_parse_os_version_debian() {
        assert_eq!(parse_os_version("13.4\n").as_deref(), Some("13.4"));
    }

    #[test]
    fn test_parse_os_version_ubuntu() {
        // Ubuntu uses a codename like "jammy" in debian_version
        // but has VERSION_ID in os-release
        assert_eq!(
            parse_os_version("trixie/sid\n").as_deref(),
            Some("trixie/sid")
        );
    }

    #[test]
    fn test_parse_os_version_empty() {
        assert_eq!(parse_os_version(""), None);
        assert_eq!(parse_os_version("  \n"), None);
    }

    #[test]
    fn test_enrich_os_name_with_version() {
        assert_eq!(
            enrich_os_name_with_version("Debian GNU/Linux 13 (trixie)", "13.4"),
            "Debian GNU/Linux 13.4 (trixie)"
        );
    }

    #[test]
    fn test_enrich_os_name_with_version_ubuntu() {
        assert_eq!(
            enrich_os_name_with_version("Ubuntu 22.04.3 LTS", "22.04"),
            "Ubuntu 22.04.3 LTS" // already has point release, don't change
        );
    }

    #[test]
    fn test_enrich_os_name_with_version_no_match() {
        // If os_name doesn't contain a bare major version, return as-is
        assert_eq!(
            enrich_os_name_with_version("Arch Linux", "rolling"),
            "Arch Linux"
        );
    }

    // --- User locale override tests ---

    #[test]
    fn test_parse_user_locale_overrides_export_lang() {
        let content = "# some config\nexport LANG=ja_JP.UTF-8\nexport PATH=/usr/bin\n";
        let locales = parse_shell_locale_overrides(content);
        assert_eq!(locales, vec!["ja_JP.UTF-8".to_string()]);
    }

    #[test]
    fn test_parse_user_locale_overrides_lc_all() {
        let content = "export LC_ALL=C\n";
        let locales = parse_shell_locale_overrides(content);
        assert_eq!(locales, vec!["C".to_string()]);
    }

    #[test]
    fn test_parse_user_locale_overrides_commented() {
        // Commented lines should be ignored
        let content = "# export LANG=fr_FR.UTF-8\n";
        let locales = parse_shell_locale_overrides(content);
        assert!(locales.is_empty());
    }

    #[test]
    fn test_parse_user_locale_overrides_multiple() {
        let content = "export LANG=de_DE.UTF-8\nexport LC_ALL=C\n";
        let locales = parse_shell_locale_overrides(content);
        assert_eq!(locales, vec!["de_DE.UTF-8".to_string(), "C".to_string()]);
    }

    #[test]
    fn test_parse_user_locale_overrides_none() {
        let content = "alias ls='ls --color=auto'\nPATH=$HOME/bin:$PATH\n";
        let locales = parse_shell_locale_overrides(content);
        assert!(locales.is_empty());
    }

    #[test]
    fn test_collect_user_locales() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let root = dir.path();

        // Create user home dirs
        let worker_home = root.join("[root]/home/worker");
        let admin_home = root.join("[root]/home/admin");
        std::fs::create_dir_all(&worker_home).expect("mkdir");
        std::fs::create_dir_all(&admin_home).expect("mkdir");

        // worker has no locale override
        std::fs::write(worker_home.join(".bashrc"), "alias ls='ls -la'\n").expect("write");

        // admin overrides LANG in .bashrc
        std::fs::write(admin_home.join(".bashrc"), "export LANG=zh_CN.UTF-8\n").expect("write");

        let overrides = collect_user_locales(root);
        assert_eq!(overrides.len(), 1);
        assert_eq!(overrides[0].0, "admin");
        assert_eq!(overrides[0].1, "zh_CN.UTF-8");
    }

    #[test]
    fn test_collect_user_locales_root() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let root = dir.path();

        let root_home = root.join("[root]/root");
        std::fs::create_dir_all(&root_home).expect("mkdir");
        std::fs::write(root_home.join(".zshrc"), "export LC_ALL=C.UTF-8\n").expect("write");

        let overrides = collect_user_locales(root);
        assert_eq!(overrides.len(), 1);
        assert_eq!(overrides[0].0, "root");
        assert_eq!(overrides[0].1, "C.UTF-8");
    }

    #[test]
    fn test_collect_user_locales_empty() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let overrides = collect_user_locales(dir.path());
        assert!(overrides.is_empty());
    }

    // --- VM version detection tests ---

    #[test]
    fn test_parse_vm_version_from_dmesg() {
        let content = "[    2.448144] systemd[1]: Hostname set to <vbox>.\n\
                        [    3.359994] vboxguest: host-version: 7.1.8r168469 0x8000000f\n\
                        [    4.000000] some other line\n";
        assert_eq!(
            parse_vm_version_from_dmesg(content).as_deref(),
            Some("7.1.8")
        );
    }

    #[test]
    fn test_parse_vm_version_from_dmesg_no_vbox() {
        let content = "[    0.000000] Linux version 6.12\n[    1.000000] ACPI loaded\n";
        assert_eq!(parse_vm_version_from_dmesg(content), None);
    }

    #[test]
    fn test_parse_vm_version_from_dmidecode() {
        let content = "Handle 0x000B, DMI type 11\n\
                        OEM Strings\n\
                        \tString 1: vboxVer_7.1.8\n\
                        \tString 2: vboxRev_168469\n";
        assert_eq!(
            parse_vm_version_from_dmidecode(content).as_deref(),
            Some("7.1.8")
        );
    }

    #[test]
    fn test_parse_vm_version_from_dmidecode_no_vbox() {
        let content = "Handle 0x0001\n\tManufacturer: Dell Inc.\n";
        assert_eq!(parse_vm_version_from_dmidecode(content), None);
    }

    #[test]
    fn test_parse_vm_version_from_dmidecode_vmware() {
        // VMware doesn't use vboxVer_ format
        let content = "Handle 0x0001\n\tProduct Name: VMware Virtual Platform\n";
        assert_eq!(parse_vm_version_from_dmidecode(content), None);
    }

    #[test]
    fn test_parse_system_profile_with_vm_version() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let root = dir.path();

        std::fs::create_dir_all(root.join("live_response/network")).expect("mkdir");
        std::fs::create_dir_all(root.join("live_response/hardware")).expect("mkdir");

        std::fs::write(
            root.join("live_response/network/hostnamectl.txt"),
            " Static hostname: testvm\n\
             Virtualization: oracle\n\
             Hardware Model: VirtualBox\n",
        )
        .expect("write");

        std::fs::write(
            root.join("live_response/hardware/dmesg.txt"),
            "[    3.36] vboxguest: host-version: 7.1.8r168469 0x8000000f\n",
        )
        .expect("write");

        let profile = parse_system_profile(root);
        assert_eq!(
            profile.platform.as_deref(),
            Some("VirtualBox 7.1.8 (oracle)")
        );
    }
}
