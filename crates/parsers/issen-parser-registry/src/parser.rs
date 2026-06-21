//! Core registry hive parsing logic using our `winreg-core` / `winreg-artifacts`
//! fleet crates — the registry equivalent of `ntfs-core` (prefer over the
//! third-party `notatin`).

use std::io::Cursor;
use std::path::Path;

use issen_core::artifacts::ArtifactType;
use issen_core::timeline::event::{EventType, TimelineEvent};
use winreg_artifacts::registry_keys::walk_keys;
use winreg_artifacts::{lsadump, run_keys, sam, shimcache, svc_diff, typed_urls, userassist};
use winreg_core::hive::Hive;

/// Parse a Windows registry hive file and emit [`TimelineEvent`]s.
///
/// For each key, one event is emitted:
/// - `event_type = RegistryModify`, `source = Registry`
/// - `timestamp` from the key's LastWrite time
/// - `path` = full key path; `description` = "Registry key modified: <key_name>"
/// - metadata `{hive, key, value_count}`
///
/// # Errors
/// Returns `Err` only on unrecoverable I/O failure. A malformed or zero-byte
/// hive yields `Ok(vec![])`.
pub fn parse_hive(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    let meta = std::fs::metadata(path);
    if meta.map_or(0, |m| m.len()) == 0 {
        return Ok(vec![]);
    }
    let hive_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    let data = std::fs::read(path)?;
    Ok(parse_hive_bytes(data, hive_name, source_id))
}

/// Parse a registry hive from an in-memory byte buffer — the bytes a
/// [`DataSource`] yields during ingest. Returns an empty vec on any parse error
/// (not a valid hive: bad signature, checksum, or truncation).
///
/// [`DataSource`]: issen_core::plugin::traits::DataSource
#[must_use]
pub fn parse_hive_bytes(data: Vec<u8>, hive_name: &str, source_id: &str) -> Vec<TimelineEvent> {
    match Hive::from_bytes(data) {
        Ok(hive) => events_from_hive(&hive, hive_name, source_id),
        Err(_) => vec![],
    }
}

/// Emit one `RegistryModify` event per key, keyed on its LastWrite time.
fn events_from_hive(
    hive: &Hive<Cursor<Vec<u8>>>,
    hive_name: &str,
    source_id: &str,
) -> Vec<TimelineEvent> {
    let mut events = Vec::new();
    for key in walk_keys(hive) {
        let (timestamp_ns, timestamp_display) = match &key.last_written {
            Some(s) => (iso_to_ns(s), s.clone()),
            None => (0, String::new()),
        };

        let description = format!("Registry key modified: {}", key.name);

        let event = TimelineEvent::new(
            timestamp_ns,
            timestamp_display,
            EventType::RegistryModify,
            ArtifactType::Registry,
            key.path.clone(),
            description,
            source_id.to_string(),
        )
        .with_activity_category(issen_core::ActivityCategory::SystemState)
        .with_metadata("hive", serde_json::json!(hive_name))
        .with_metadata("key", serde_json::json!(key.path))
        .with_metadata("value_count", serde_json::json!(key.value_count));

        events.push(event);
    }
    events.extend(extract_named_values(hive, hive_name, source_id));
    events.extend(extract_run_keys(hive, hive_name, source_id));
    events.extend(extract_typed_urls(hive, hive_name, source_id));
    events.extend(extract_userassist(hive, hive_name, source_id));
    events.extend(extract_shimcache(hive, hive_name, source_id));
    events.extend(extract_services(hive, hive_name, source_id));
    events.extend(extract_sam_accounts(hive, hive_name, source_id));
    events.extend(extract_lsa_secrets(hive, hive_name, source_id));
    events
}

/// Enumerate the LSA secrets stored in a SECURITY hive via
/// `winreg-artifacts::lsadump` — which credential material exists
/// (`$MACHINE.ACC`, `DefaultPassword`, `DPAPI_SYSTEM`, `NL$KM`, …), with current
/// /old presence and ciphertext sizes. This surfaces the secret INVENTORY a
/// responder pivots from; it does NOT decrypt (plaintext needs the SYSTEM boot
/// key, out of scope here). Self-filters: a non-SECURITY hive yields none.
fn extract_lsa_secrets(
    hive: &Hive<Cursor<Vec<u8>>>,
    hive_name: &str,
    source_id: &str,
) -> Vec<TimelineEvent> {
    lsadump::parse_secrets(hive)
        .into_iter()
        .map(|s| {
            let (ts_ns, ts_display) = s.last_written.map_or((0, String::new()), |dt| {
                (
                    dt.timestamp_nanos_opt().unwrap_or(0),
                    dt.format("%Y-%m-%dT%H:%M:%S").to_string(),
                )
            });
            let presence = match (s.has_current, s.has_old) {
                (true, true) => "current+old",
                (true, false) => "current",
                (false, true) => "old",
                (false, false) => "none",
            };
            let mut event = TimelineEvent::new(
                ts_ns,
                ts_display,
                EventType::Other("lsa-secret".into()),
                ArtifactType::Registry,
                format!(r"Policy\Secrets\{}", s.name),
                format!("LSA secret: {} ({presence} present)", s.name),
                source_id.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::SystemState)
            .with_tag("lsa-secret")
            .with_metadata("hive", serde_json::json!(hive_name))
            .with_metadata("secret_name", serde_json::json!(s.name))
            .with_metadata("has_current", serde_json::json!(s.has_current))
            .with_metadata("has_old", serde_json::json!(s.has_old))
            .with_metadata("current_size", serde_json::json!(s.curr_size))
            .with_metadata("old_size", serde_json::json!(s.old_size));
            if s.is_interesting {
                event = event.with_tag("credential-material");
            }
            event
        })
        .collect()
}

/// Decode local user accounts from a SAM hive via `winreg-artifacts::sam` and
/// emit one account-inventory event per user: RID, login count, disabled/locked
/// state, and the password-last-set / last-login times. Keyed on
/// password-last-set (the account's own write proxy). Self-filters: a non-SAM
/// hive yields no users.
fn extract_sam_accounts(
    hive: &Hive<Cursor<Vec<u8>>>,
    hive_name: &str,
    source_id: &str,
) -> Vec<TimelineEvent> {
    sam::parse(hive)
        .into_iter()
        .map(|u| {
            let (ts_ns, ts_display) = match &u.password_last_set {
                Some(s) => (iso_to_ns(s), s.clone()),
                None => (0, String::new()),
            };
            let mut state = Vec::new();
            if u.is_disabled {
                state.push("disabled");
            }
            if u.is_locked {
                state.push("locked");
            }
            let state_label = if state.is_empty() {
                "enabled".to_string()
            } else {
                state.join(",")
            };
            TimelineEvent::new(
                ts_ns,
                ts_display,
                EventType::UserAccountChange,
                ArtifactType::Registry,
                format!("SAM\\{}", u.username),
                format!(
                    "Local account: {} (RID {}, {state_label}, {} logins)",
                    u.username, u.rid, u.login_count
                ),
                source_id.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::SystemState)
            .with_tag("local-account")
            .with_metadata("hive", serde_json::json!(hive_name))
            .with_metadata("username", serde_json::json!(u.username))
            .with_metadata("rid", serde_json::json!(u.rid))
            .with_metadata("login_count", serde_json::json!(u.login_count))
            .with_metadata(
                "account_flags",
                serde_json::json!(format!("0x{:08X}", u.account_flags)),
            )
            .with_metadata("is_disabled", serde_json::json!(u.is_disabled))
            .with_metadata("is_locked", serde_json::json!(u.is_locked))
            .with_metadata("last_login", serde_json::json!(u.last_login))
            .with_metadata("password_last_set", serde_json::json!(u.password_last_set))
            .with_metadata("account_expires", serde_json::json!(u.account_expires))
        })
        .collect()
}

/// Decode Windows services via `winreg-artifacts::svc_diff` and emit one
/// `ServiceInstall` event ONLY for services that look like genuine persistence
/// anomalies ([`service_signal`]) — never the benign baseline flood (453
/// services on DC01, 303 of them svc_diff empty-`ObjectName` false positives).
/// The event carries the `ImagePath` (the VALUE the generic key walk drops),
/// start type, account, `ServiceDll`/`FailureCommand` when present, and an
/// `anomaly_reason`. Keyed on the service key's `LastWrite` time (≈ install
/// time). The category is `Persistence`.
///
/// `svc_diff` resolves the live `ControlSet00N` from `Select\Current` (there is
/// no `CurrentControlSet` link in an offline SYSTEM hive), so it self-filters:
/// a hive with no Services key yields none.
fn extract_services(
    hive: &Hive<Cursor<Vec<u8>>>,
    hive_name: &str,
    source_id: &str,
) -> Vec<TimelineEvent> {
    svc_diff::parse(hive)
        .into_iter()
        .filter_map(|s| {
            // Signal-only: emit a timeline event ONLY for a genuine persistence
            // anomaly, never the hundreds of benign baseline services (the 453 on
            // DC01, 303 of them svc_diff empty-ObjectName false positives).
            let anomaly = service_signal(&s.image_path, s.start_type, s.service_type)?;
            let (ts_ns, ts_display) = s.last_written.map_or((0, String::new()), |dt| {
                (
                    dt.timestamp_nanos_opt().unwrap_or(0),
                    dt.format("%Y-%m-%dT%H:%M:%S").to_string(),
                )
            });
            let label = if s.display_name.is_empty() {
                s.name.clone()
            } else {
                format!("{} ({})", s.name, s.display_name)
            };
            let mut event = TimelineEvent::new(
                ts_ns,
                ts_display,
                EventType::ServiceInstall,
                ArtifactType::Registry,
                format!(r"Services\{}", s.name),
                format!(
                    "Suspicious service: {label} -> {} [{anomaly}]",
                    s.image_path
                ),
                source_id.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::Persistence)
            .with_tag("service")
            .with_tag("suspicious")
            .with_metadata("hive", serde_json::json!(hive_name))
            .with_metadata("service_name", serde_json::json!(s.name))
            .with_metadata("display_name", serde_json::json!(s.display_name))
            .with_metadata("image_path", serde_json::json!(s.image_path))
            .with_metadata("start_type", serde_json::json!(s.start_type))
            .with_metadata("service_type", serde_json::json!(s.service_type))
            .with_metadata("object_name", serde_json::json!(s.object_name))
            .with_metadata("description", serde_json::json!(s.description))
            .with_metadata("anomaly_reason", serde_json::json!(anomaly));
            // ServiceDll / FailureCommand (winreg-artifacts 0.2) — surface when
            // present (svchost-hosted persistence + recovery-command persistence).
            if let Some(dll) = &s.service_dll {
                event = event.with_metadata("service_dll", serde_json::json!(dll));
            }
            if let Some(fc) = &s.failure_command {
                event = event.with_metadata("failure_command", serde_json::json!(fc));
            }
            Some(event)
        })
        .collect()
}

/// Decide whether a service's configuration is a forensic *persistence anomaly*
/// worth a timeline event, vs benign baseline config — returning the anomaly
/// reason when it is signal, `None` when baseline.
///
/// Deliberately does NOT use `svc_diff`'s bundled `is_suspicious`, whose
/// empty-`ObjectName` rule false-flags 303 of 453 services on the real DC01 hive
/// (an empty `ObjectName` defaults to `LocalSystem`). The three low-FP rules:
/// 1. binary staged in a user-writable directory (a malware drop, T1543.003);
/// 2. a LOLBin / script-interpreter service image (fileless persistence);
/// 3. a `System32`-root own-process auto-start service whose binary is NOT a
///    known Windows service binary (`forensicnomicon::services`) — a masquerade
///    LEAD (T1036.005). Rule 3 surfaces the DC01 `coreupdater.exe` implant,
///    which hides in `System32` with a normal config and evades rules 1-2.
fn service_signal(image_path: &str, start_type: u32, service_type: u32) -> Option<String> {
    let lower = image_path
        .trim()
        .trim_start_matches(r"\??\")
        .to_ascii_lowercase();

    for dir in [
        r"\temp\",
        r"\tmp\",
        r"\appdata\",
        r"\users\public\",
        r"\programdata\",
        r"\downloads\",
        r"\$recycle.bin\",
    ] {
        if lower.contains(dir) {
            return Some(format!(
                "service binary staged in user-writable directory ({})",
                dir.trim_matches('\\')
            ));
        }
    }
    for lol in [
        "powershell",
        "pwsh",
        "cmd.exe",
        "wscript",
        "cscript",
        "mshta",
        "rundll32",
        "regsvr32",
        "msbuild",
        "installutil",
        "bitsadmin",
    ] {
        if lower.contains(lol) {
            return Some(format!(
                "service image is a script interpreter / LOLBin ({lol})"
            ));
        }
    }
    // service_type 16 = SERVICE_WIN32_OWN_PROCESS; start 0/1/2 = boot/system/auto.
    if service_type == 16 && matches!(start_type, 0..=2) {
        if let Some(base) = system_root_exe_basename(&lower) {
            if !forensicnomicon::services::is_known_service_binary(&base) {
                return Some(format!(
                    "auto-start own-process service binary '{base}' in System32 is not a known \
                     Windows service binary (possible masquerade, MITRE T1036.005)"
                ));
            }
        }
    }
    None
}

/// If `lower` (a lowercased `ImagePath`) is a bare `.exe` directly in the
/// `System32`/`SysWOW64` root (no further subdirectory), return its basename.
/// Handles `system32\drivers\x.sys` (rejected — subdir + `.sys`), quoted paths,
/// and trailing `svchost.exe -k <group>` args, so only a true root-level
/// own-process executable matches.
fn system_root_exe_basename(lower: &str) -> Option<String> {
    for marker in [r"\system32\", "system32\\", r"\syswow64\", "syswow64\\"] {
        if let Some(idx) = lower.rfind(marker) {
            let tail = &lower[idx + marker.len()..];
            let exe = tail.split([' ', '"']).next().unwrap_or(tail);
            // `lower` is already lowercased, so the literal ".exe" suffix match is
            // case-insensitive by construction (the clippy lint is a false positive).
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
            let is_bare_exe = exe.ends_with(".exe") && !exe.contains('\\') && !exe.is_empty();
            if is_bare_exe {
                return Some(exe.to_string());
            }
        }
    }
    None
}

/// Decode `AppCompatCache` (Shimcache) via `winreg-artifacts::shimcache` and
/// emit one Execution event per cached binary. Shimcache records that a binary
/// was *present* on the host (with its file last-modified time, NOT a run time)
/// — strong presence/execution-candidacy evidence that survives binary deletion.
/// Lives in the SYSTEM hive's current ControlSet; self-filters elsewhere.
fn extract_shimcache(
    hive: &Hive<Cursor<Vec<u8>>>,
    hive_name: &str,
    source_id: &str,
) -> Vec<TimelineEvent> {
    shimcache::parse(hive)
        .into_iter()
        .map(|e| {
            let (ts_ns, ts_display) = match &e.last_modified {
                Some(s) => (iso_to_ns(s), s.clone()),
                None => (0, String::new()),
            };
            TimelineEvent::new(
                ts_ns,
                ts_display,
                EventType::ProcessExec,
                ArtifactType::Registry,
                e.path.clone(),
                format!("Shimcache (AppCompatCache) entry: {}", e.path),
                source_id.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::Execution)
            .with_tag("shimcache")
            .with_metadata("hive", serde_json::json!(hive_name))
            .with_metadata("path", serde_json::json!(e.path))
            .with_metadata("entry_index", serde_json::json!(e.entry_index))
            .with_metadata("file_last_modified", serde_json::json!(e.last_modified))
        })
        .collect()
}

/// Decode `UserAssist` (Explorer-launched GUI program execution, ROT13-obscured)
/// via `winreg-artifacts::userassist` and emit one Execution event per program,
/// keyed on its last-run time, carrying the run count. This is among the
/// strongest interactive-execution artifacts (it records what a logged-in user
/// actually launched). Self-filters: a hive with no UserAssist values yields none.
fn extract_userassist(
    hive: &Hive<Cursor<Vec<u8>>>,
    hive_name: &str,
    source_id: &str,
) -> Vec<TimelineEvent> {
    userassist::parse(hive)
        .into_iter()
        .map(|u| {
            let (ts_ns, ts_display) = match &u.last_run {
                Some(s) => (iso_to_ns(s), s.clone()),
                None => (0, String::new()),
            };
            TimelineEvent::new(
                ts_ns,
                ts_display,
                EventType::ProcessExec,
                ArtifactType::Registry,
                u.program.clone(),
                format!(
                    "UserAssist execution: {} (run count {})",
                    u.program, u.run_count
                ),
                source_id.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::Execution)
            .with_tag("userassist")
            .with_metadata("hive", serde_json::json!(hive_name))
            .with_metadata("program", serde_json::json!(u.program))
            .with_metadata("run_count", serde_json::json!(u.run_count))
            .with_metadata("focus_count", serde_json::json!(u.focus_count))
            .with_metadata("focus_duration_ms", serde_json::json!(u.focus_duration_ms))
        })
        .collect()
}

/// Decode IE/Explorer `TypedURLs` (hand-typed addresses) via
/// `winreg-artifacts::typed_urls` and emit one BrowserActivity event per URL,
/// keyed on its last-visited time. A raw-IP or otherwise suspicious URL carries
/// the `suspicious` tag — these are high-signal IOCs (the attacker typing a C2
/// address). Self-filters: a hive with no TypedURLs values yields none.
fn extract_typed_urls(
    hive: &Hive<Cursor<Vec<u8>>>,
    hive_name: &str,
    source_id: &str,
) -> Vec<TimelineEvent> {
    typed_urls::parse(hive)
        .into_iter()
        .map(|u| {
            let (ts_ns, ts_display) = match &u.last_visited {
                Some(s) => (iso_to_ns(s), s.clone()),
                None => (0, String::new()),
            };
            let mut event = TimelineEvent::new(
                ts_ns,
                ts_display,
                EventType::Other("typed-url".into()),
                ArtifactType::Registry,
                u.url.clone(),
                format!("Typed URL: {}", u.url),
                source_id.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::BrowserActivity)
            .with_tag("typed-url")
            .with_metadata("hive", serde_json::json!(hive_name))
            .with_metadata("url", serde_json::json!(u.url))
            .with_metadata("suspicious", serde_json::json!(u.is_suspicious));
            if u.is_suspicious {
                event = event.with_tag("suspicious");
                if let Some(reason) = &u.suspicious_reason {
                    event = event.with_metadata("suspicious_reason", serde_json::json!(reason));
                }
            }
            event
        })
        .collect()
}

/// Decode autorun (Run / RunOnce / Winlogon) persistence entries via
/// `winreg-artifacts::run_keys` and emit one Persistence event per VALUE — the
/// command that runs at startup, which `walk_keys` (key-level only) drops. The
/// decoder self-filters by hive type (HKLM for SOFTWARE, HKCU for NTUSER.DAT),
/// so it is safe to call on every hive: a hive with no Run values yields none.
fn extract_run_keys(
    hive: &Hive<Cursor<Vec<u8>>>,
    hive_name: &str,
    source_id: &str,
) -> Vec<TimelineEvent> {
    run_keys::parse(hive)
        .into_iter()
        .map(|e| {
            let (ts_ns, ts_display) = e.last_written.map_or((0, String::new()), |dt| {
                (
                    dt.timestamp_nanos_opt().unwrap_or(0),
                    dt.format("%Y-%m-%dT%H:%M:%S").to_string(),
                )
            });
            let full_key = format!(r"{}\{}", e.key_path, e.value_name);
            let mut event = TimelineEvent::new(
                ts_ns,
                ts_display,
                EventType::RegistryModify,
                ArtifactType::Registry,
                full_key,
                format!(
                    "Registry autorun [{}]: {} = {}",
                    e.hive, e.value_name, e.command
                ),
                source_id.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::Persistence)
            .with_tag("persistence")
            .with_metadata("hive", serde_json::json!(hive_name))
            .with_metadata("autorun_hive", serde_json::json!(e.hive))
            .with_metadata("key", serde_json::json!(e.key_path))
            .with_metadata("value_name", serde_json::json!(e.value_name))
            .with_metadata("command", serde_json::json!(e.command))
            .with_metadata("suspicious", serde_json::json!(e.is_suspicious));
            if e.is_suspicious {
                event = event.with_tag("suspicious");
                if let Some(reason) = &e.suspicious_reason {
                    event = event.with_metadata("suspicious_reason", serde_json::json!(reason));
                }
            }
            event
        })
        .collect()
}

/// Read a REG_SZ named value as a string (None if key/value absent or wrong type).
fn str_value(hive: &Hive<Cursor<Vec<u8>>>, key_path: &str, name: &str) -> Option<String> {
    let v = hive
        .open_key(key_path)
        .ok()
        .flatten()?
        .value(name)
        .ok()
        .flatten()?;
    v.as_string()
        .ok()
        .map(|s| s.trim_end_matches('\0').to_string())
}

/// Resolve the live `ControlSet00N` from `Select\Current` (there is no
/// `CurrentControlSet` link in an offline SYSTEM hive).
fn current_control_set(hive: &Hive<Cursor<Vec<u8>>>) -> String {
    let n = hive
        .open_key("Select")
        .ok()
        .flatten()
        .and_then(|k| k.value("Current").ok().flatten())
        .and_then(|v| v.as_u32().ok())
        .unwrap_or(1);
    format!("ControlSet{n:03}")
}

/// Extract high-value **named values** (not just key-write timestamps) that
/// answer host-identity questions: OS version (SOFTWARE), timezone + computer
/// name (SYSTEM). Emitted as `system-info` events tagged for discovery.
fn extract_named_values(
    hive: &Hive<Cursor<Vec<u8>>>,
    hive_name: &str,
    source_id: &str,
) -> Vec<TimelineEvent> {
    let mut out = Vec::new();
    let mk = |desc: String, key: &str| {
        TimelineEvent::new(
            0,
            String::new(),
            EventType::Other("system-info".into()),
            ArtifactType::Registry,
            key.to_string(),
            desc,
            source_id.to_string(),
        )
        .with_activity_category(issen_core::ActivityCategory::SystemState)
        .with_tag("system-info")
        .with_metadata("hive", serde_json::json!(hive_name))
    };
    match hive_name.to_lowercase().as_str() {
        "software" => {
            let k = r"Microsoft\Windows NT\CurrentVersion";
            let product = str_value(hive, k, "ProductName");
            let build = str_value(hive, k, "CurrentBuild")
                .or_else(|| str_value(hive, k, "CurrentBuildNumber"));
            if product.is_some() || build.is_some() {
                out.push(
                    mk(
                        format!(
                            "OS version: {} (build {})",
                            product.as_deref().unwrap_or("?"),
                            build.as_deref().unwrap_or("?")
                        ),
                        k,
                    )
                    .with_metadata("product_name", serde_json::json!(product))
                    .with_metadata("current_build", serde_json::json!(build)),
                );
            }
        }
        "system" => {
            let cs = current_control_set(hive);
            let tz_key = format!(r"{cs}\Control\TimeZoneInformation");
            if let Some(tz) = str_value(hive, &tz_key, "TimeZoneKeyName")
                .filter(|s| !s.is_empty())
                .or_else(|| str_value(hive, &tz_key, "StandardName"))
            {
                out.push(
                    mk(format!("Timezone: {tz}"), &tz_key)
                        .with_metadata("timezone", serde_json::json!(tz)),
                );
            }
            let cn_key = format!(r"{cs}\Control\ComputerName\ComputerName");
            if let Some(cn) = str_value(hive, &cn_key, "ComputerName") {
                out.push(
                    mk(format!("Computer name: {cn}"), &cn_key)
                        .with_metadata("computer_name", serde_json::json!(cn)),
                );
            }
        }
        _ => {}
    }
    out
}

/// Convert a `walk_keys` ISO-8601 string (`%Y-%m-%dT%H:%M:%S`, UTC) to
/// nanoseconds since the Unix epoch; `0` if unparseable.
fn iso_to_ns(s: &str) -> i64 {
    chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S")
        .ok()
        .and_then(|ndt| ndt.and_utc().timestamp_nanos_opt())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn hive(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../../tests/data/dfirmadness-szechuan-sauce/extracted/szechuan-sauce-hives/{name}"
        ))
    }

    /// Real DC SOFTWARE hive: the named-value extraction must surface the OS
    /// version (F1: Windows Server 2012 R2, build 9600) — a parsed VALUE, not a
    /// key-write timestamp. Skips cleanly when the corpus is absent.
    #[test]
    fn real_software_hive_yields_os_version() {
        let p = hive("SOFTWARE");
        if !p.exists() {
            eprintln!("SKIP: SOFTWARE hive absent (see docs/corpus-catalog.md)");
            return;
        }
        let events = parse_hive(&p, "dc01-SOFTWARE").unwrap();
        let os = events
            .iter()
            .find(|e| e.description.starts_with("OS version:"))
            .expect("OS version system-info event");
        assert!(
            os.description.contains("9600"),
            "build 9600: {}",
            os.description
        );
        assert!(
            os.description.contains("2012 R2"),
            "Server 2012 R2: {}",
            os.description
        );
        assert!(matches!(&os.event_type, EventType::Other(s) if s == "system-info"));
    }

    /// Real DC SOFTWARE hive: the Run-key persistence decoder must surface the
    /// implant's autorun `coreupdate` (fileless PowerShell loaded from a
    /// registry blob) — a persistence VALUE, not just the Run key's write
    /// timestamp. This is the highest-value registry artifact and was dark
    /// (`walk_keys` emits the `Run` key, never the `coreupdate` value under it).
    #[test]
    fn real_software_hive_surfaces_run_key_persistence() {
        let p = hive("SOFTWARE");
        if !p.exists() {
            eprintln!("SKIP: SOFTWARE hive absent");
            return;
        }
        let events = parse_hive(&p, "dc01-SOFTWARE").unwrap();
        let persist = events
            .iter()
            .find(|e| e.description.contains("coreupdate"))
            .expect("coreupdate Run-key persistence event");
        assert_eq!(
            persist.activity_category,
            Some(issen_core::ActivityCategory::Persistence),
            "a Run-key autorun is a Persistence activity"
        );
        let blob = format!("{} {:?}", persist.description, persist.metadata).to_lowercase();
        assert!(
            blob.contains("powershell"),
            "the autorun command must be surfaced: {blob}"
        );
    }

    /// Real DC NTUSER.DAT: the TypedURLs decoder must surface the attacker's
    /// hand-typed C2 URL `http://194.61.24.102/` (a raw-IP IOC) as a
    /// BrowserActivity event — a registry VALUE the generic walk drops.
    #[test]
    fn real_ntuser_hive_surfaces_typed_url_c2() {
        let p = hive("NTUSER.DAT");
        if !p.exists() {
            eprintln!("SKIP: NTUSER.DAT hive absent");
            return;
        }
        let events = parse_hive(&p, "dc01-NTUSER").unwrap();
        let url = events
            .iter()
            .find(|e| e.description.contains("194.61.24.102"))
            .expect("typed-URL C2 event");
        assert_eq!(
            url.activity_category,
            Some(issen_core::ActivityCategory::BrowserActivity),
            "a typed URL is a BrowserActivity"
        );
    }

    /// Real DC NTUSER.DAT: the UserAssist decoder must surface the implant's
    /// interactive GUI execution `coreupdater.exe` (run 3×) as an Execution
    /// event with its run count — a registry VALUE the generic walk drops.
    #[test]
    fn real_ntuser_hive_surfaces_userassist_execution() {
        let p = hive("NTUSER.DAT");
        if !p.exists() {
            eprintln!("SKIP: NTUSER.DAT hive absent");
            return;
        }
        let events = parse_hive(&p, "dc01-NTUSER").unwrap();
        let exec = events
            .iter()
            .find(|e| e.description.to_lowercase().contains("coreupdater.exe"))
            .expect("UserAssist coreupdater.exe execution event");
        assert_eq!(
            exec.activity_category,
            Some(issen_core::ActivityCategory::Execution),
            "UserAssist is program execution"
        );
        let blob = format!("{:?}", exec.metadata);
        assert!(blob.contains("run_count"), "run count surfaced: {blob}");
    }

    /// Real DC SYSTEM hive: the Shimcache (AppCompatCache) decoder must surface
    /// the binaries that were present/run on the host. The attacker staged the
    /// VC++ runtime under `\Windows\Temp\{GUID}\` — `vcredist_x64.exe` appears in
    /// the cache and is dropped by the generic key walk. (Shimcache's timestamp
    /// is the binary's file mtime, not a run time — Execution category, presence
    /// evidence.)
    #[test]
    fn real_system_hive_surfaces_shimcache_execution() {
        let p = hive("SYSTEM");
        if !p.exists() {
            eprintln!("SKIP: SYSTEM hive absent");
            return;
        }
        let events = parse_hive(&p, "dc01-SYSTEM").unwrap();
        let shim = events
            .iter()
            .find(|e| e.description.to_lowercase().contains("vcredist_x64.exe"))
            .expect("Shimcache vcredist_x64.exe presence event");
        assert_eq!(
            shim.activity_category,
            Some(issen_core::ActivityCategory::Execution),
            "Shimcache is an Execution (presence) artifact"
        );
    }

    /// Real DC SAM hive: the SAM decoder must surface local account inventory.
    /// The built-in `Administrator` (RID 500) is decoded from the binary
    /// V-structure — its username is NOT a key name, so it can ONLY appear via
    /// the decoder, never the generic key walk. (Domain accounts live in
    /// NTDS.dit, not the local SAM; a DC's SAM carries only the built-ins.)
    #[test]
    fn real_sam_hive_surfaces_local_accounts() {
        let p = hive("SAM");
        if !p.exists() {
            eprintln!("SKIP: SAM hive absent");
            return;
        }
        let events = parse_hive(&p, "dc01-SAM").unwrap();
        // Target the decoded ACCOUNT event specifically — the SAM hive also has a
        // *key* literally named `Administrator` (`Users\Names\Administrator`) that
        // the generic walk emits, so match the decoder's "Local account:" event.
        let admin = events
            .iter()
            .find(|e| {
                e.description.starts_with("Local account:")
                    && e.description.contains("Administrator")
            })
            .expect("SAM Administrator account event");
        assert_eq!(
            admin.activity_category,
            Some(issen_core::ActivityCategory::SystemState),
            "a SAM account record is host (account) inventory"
        );
        let blob = format!("{:?}", admin.metadata);
        assert!(blob.contains("500"), "RID 500 surfaced: {blob}");
    }

    /// Real DC SECURITY hive: the LSA-secrets decoder must surface which secrets
    /// are stored — `$MACHINE.ACC` (machine account), `DefaultPassword`
    /// (autologon), `DPAPI_SYSTEM`, `NL$KM` (cached-cred key) — the credential
    /// material a responder pivots from. Names alone are key names the generic
    /// walk emits, so target the decoder's "LSA secret:" event (presence + sizes,
    /// NOT plaintext — decryption needs the SYSTEM boot key).
    #[test]
    fn real_security_hive_surfaces_lsa_secrets() {
        let p = hive("SECURITY");
        if !p.exists() {
            eprintln!("SKIP: SECURITY hive absent");
            return;
        }
        let events = parse_hive(&p, "dc01-SECURITY").unwrap();
        let secret = events
            .iter()
            .find(|e| {
                e.description.starts_with("LSA secret:") && e.description.contains("$MACHINE.ACC")
            })
            .expect("LSA secret $MACHINE.ACC event");
        assert_eq!(
            secret.activity_category,
            Some(issen_core::ActivityCategory::SystemState),
            "LSA secrets are host security-state inventory"
        );
    }

    /// Real DC SYSTEM hive: the service decoder (`svc_diff`) must surface the
    /// implant's service-based persistence `coreupdater`
    /// (`C:\Windows\System32\coreupdater.exe`, auto-start) as a `ServiceInstall`
    /// Persistence event with its image path — a registry VALUE the generic key
    /// walk drops. `svc_diff` resolves `Select\Current` -> `ControlSet00N`
    /// (there is no live `CurrentControlSet` link in an offline SYSTEM hive), so
    /// this only fires on the real DC hive, never a synthetic one missing that
    /// indirection.
    #[test]
    fn real_system_hive_emits_only_signal_services_incl_coreupdater_masquerade() {
        let p = hive("SYSTEM");
        if !p.exists() {
            eprintln!("SKIP: SYSTEM hive absent");
            return;
        }
        let events = parse_hive(&p, "dc01-SYSTEM").unwrap();
        let svc: Vec<_> = events
            .iter()
            .filter(|e| matches!(e.event_type, EventType::ServiceInstall))
            .collect();
        // Signal-only: the 453-service flood (303 empty-ObjectName FPs, benign
        // baseline services) must NOT be emitted — only genuine anomalies.
        assert!(
            svc.len() <= 5,
            "signal-only filter: expected a handful of service events, got {} (flood not filtered)",
            svc.len()
        );
        // The implant `coreupdater.exe` is a System32 masquerade (svc_diff does
        // not flag it; it evades path/interpreter rules). It must surface via the
        // known-good-catalog masquerade rule, with its image path + reason.
        let cu = svc
            .iter()
            .find(|e| e.description.to_lowercase().contains("coreupdater"))
            .expect("coreupdater masquerade service event");
        assert!(matches!(cu.event_type, EventType::ServiceInstall));
        let blob = format!("{} {:?}", cu.description, cu.metadata).to_lowercase();
        assert!(
            blob.contains("masquerade"),
            "coreupdater must be flagged as a masquerade lead: {blob}"
        );
        assert!(
            blob.contains(r"coreupdater.exe"),
            "the service image path must be surfaced: {blob}"
        );
        assert!(
            blob.contains("anomaly_reason"),
            "anomaly_reason metadata key must be present: {blob}"
        );
    }

    #[test]
    fn service_signal_flags_anomalies_not_baseline() {
        // Rule 1 — user-writable staging directory.
        assert!(service_signal(r"C:\Users\Public\evil.exe", 2, 16)
            .unwrap()
            .contains("user-writable"));
        assert!(service_signal(r"C:\Windows\Temp\x.exe", 2, 16).is_some());
        // Rule 2 — LOLBin / interpreter image.
        assert!(
            service_signal(r"C:\Windows\System32\cmd.exe /c evil", 2, 16)
                .unwrap()
                .contains("LOLBin")
        );
        assert!(service_signal("powershell -enc AAAA", 2, 16).is_some());
        // Rule 3 — System32 masquerade flagged; known/non-qualifying ones are not.
        assert!(
            service_signal(r"C:\Windows\System32\coreupdater.exe", 2, 16)
                .unwrap()
                .contains("masquerade")
        );
        assert!(service_signal(r"%SystemRoot%\System32\msdtc.exe", 2, 16).is_none());
        assert!(service_signal(r"C:\Windows\System32\spoolsv.exe", 2, 16).is_none());
        // ShareProcess (type 32) svchost is not an own-process masquerade.
        assert!(service_signal(r"C:\Windows\System32\svchost.exe -k netsvcs", 2, 32).is_none());
        // A driver in system32\drivers (subdir, .sys) and an empty path don't qualify.
        assert!(service_signal(r"system32\drivers\peauth.sys", 2, 16).is_none());
        assert!(service_signal("", 2, 16).is_none());
        // Manual-start (3) own-process System32 unknown is NOT auto-start → no lead.
        assert!(service_signal(r"C:\Windows\System32\coreupdater.exe", 3, 16).is_none());
    }

    /// Real DC SYSTEM hive: timezone (F3: Pacific — the clock-skew root cause)
    /// resolved through Select\Current -> ControlSet00N.
    #[test]
    fn real_system_hive_yields_pacific_timezone() {
        let p = hive("SYSTEM");
        if !p.exists() {
            eprintln!("SKIP: SYSTEM hive absent");
            return;
        }
        let events = parse_hive(&p, "dc01-SYSTEM").unwrap();
        let tz = events
            .iter()
            .find(|e| e.description.starts_with("Timezone:"))
            .expect("Timezone system-info event");
        assert!(
            tz.description.contains("Pacific"),
            "Pacific timezone: {}",
            tz.description
        );
    }
}
