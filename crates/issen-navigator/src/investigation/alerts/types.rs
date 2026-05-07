//! Core types for the forensic alert engine.

use issen_parser_uac::parsers::bodyfile::BodyfileEntry;
use issen_parser_uac::parsers::chkrootkit::ChkrootkitFinding;
use issen_parser_uac::parsers::configs::ConfigFile;
use issen_parser_uac::parsers::hash_execs::HashedExecutable;
use issen_parser_uac::parsers::network::NetworkConnection;
use issen_parser_uac::parsers::packages::InstalledPackage;
use issen_parser_uac::parsers::process::{CrontabEntry, ProcessInfo};
use issen_parser_uac::parsers::rootkit::RootkitFinding;
use issen_parser_uac::parsers::system::LoginRecord;

/// Severity level of a forensic alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity {
    /// Requires immediate attention.
    Critical = 0,
    /// Potentially suspicious, warrants investigation.
    Warning = 1,
    /// Informational finding.
    Info = 2,
}

impl AlertSeverity {
    /// Short prefix label for display.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Critical => "[!]",
            Self::Warning => "[w]",
            Self::Info => "[i]",
        }
    }
}

/// A single forensic alert raised by heuristic checks.
#[derive(Debug, Clone)]
pub struct Alert {
    pub severity: AlertSeverity,
    pub category: String,
    pub message: String,
    pub detail: String,
}

/// A Windows Event Log record for alert detection.
///
/// Populated from parsed EVTX files (Velociraptor collections, standalone
/// `.evtx`). Carries the subset of fields needed by Windows detection engines.
#[derive(Debug, Clone)]
pub struct WindowsEvent {
    /// Windows Event ID (e.g. 4624, 7045, 1102).
    pub event_id: u64,
    /// Event log channel (e.g. "Security", "System").
    pub channel: String,
    /// Provider name (e.g. "Microsoft-Windows-Security-Auditing").
    pub provider: String,
    /// Computer hostname from the event record.
    pub computer: String,
    /// Unix epoch timestamp (seconds).
    pub timestamp: i64,
    /// Free-form description assembled from EventData fields.
    pub description: String,
}

/// A parsed MFT file entry for cross-artifact correlation.
///
/// Produced from the Windows MFT (parsed separately from UAC bodyfile output).
/// The `is_deleted` flag is set when the MFT entry's `$FILE_NAME` attribute
/// indicates the file has been deleted (directory entry removed).
#[derive(Debug, Clone)]
pub struct MftFileEntry {
    /// Full file path as reconstructed from the MFT.
    pub path: String,
    /// Whether the MFT entry is marked as deleted.
    pub is_deleted: bool,
}

/// A timestamped network connection record for C2 beacon analysis.
///
/// Unlike `NetworkConnection` (which reflects the live socket state at
/// collection time), `TimestampedConnection` captures a single observed
/// connection event with a Unix epoch timestamp — suitable for inter-arrival
/// timing analysis.
#[derive(Debug, Clone)]
pub struct TimestampedConnection {
    /// Remote IP address (without port).
    pub remote_ip: String,
    /// Unix epoch seconds when this connection was observed.
    pub timestamp: i64,
}

/// Borrowed slices of parsed artifacts fed into the alert engine.
pub struct AlertInput<'a> {
    pub bodyfile: &'a [BodyfileEntry],
    pub network: &'a [NetworkConnection],
    pub processes: &'a [ProcessInfo],
    pub crontabs: &'a [CrontabEntry],
    pub chkrootkit: &'a [ChkrootkitFinding],
    pub rootkit_findings: &'a [RootkitFinding],
    pub configs: &'a [ConfigFile],
    pub hashes: &'a [HashedExecutable],
    pub packages: &'a [InstalledPackage],
    pub logins: &'a [LoginRecord],
    pub windows_events: &'a [WindowsEvent],
    /// MFT file entries (Windows collections); empty for Linux/macOS UAC.
    pub mft_entries: &'a [MftFileEntry],
    /// Timestamped connection log for C2 beacon timing analysis; empty when
    /// not available (e.g. UAC live-response only captures socket state).
    pub connection_log: &'a [TimestampedConnection],
}

/// A suspicious port entry with provenance for forensic traceability.
pub(super) struct SuspiciousPort {
    pub(super) port: u16,
    pub(super) source: &'static str,
    pub(super) description: &'static str,
}

/// Suspicious port database sourced from SIGMA detection rules and C2 framework defaults.
///
/// Sources:
/// - SIGMA `dbfc7c98` — "Potentially Suspicious Malware Callback Communication - Linux"
///   <https://github.com/SigmaHQ/sigma/blob/master/rules/linux/network_connection/net_connection_lnx_susp_malware_callback_port.yml>
/// - SIGMA `4b89abaa` — "Potentially Suspicious Malware Callback Communication" (Windows)
///   <https://github.com/SigmaHQ/sigma/blob/master/rules/windows/network_connection/net_connection_win_susp_malware_callback_port.yml>
/// - SIGMA `6d8c3d20` — "Communication To Uncommon Destination Ports"
///   <https://github.com/SigmaHQ/sigma/blob/master/rules/windows/network_connection/net_connection_win_susp_malware_callback_ports_uncommon.yml>
/// - Metasploit, Cobalt Strike, Sliver C2 default listener ports
pub(super) const SUSPICIOUS_PORTS: &[SuspiciousPort] = &[
    // --- C2 framework defaults ---
    SuspiciousPort {
        port: 4444,
        source: "SIGMA dbfc7c98 + Metasploit",
        description: "Metasploit default reverse shell handler",
    },
    SuspiciousPort {
        port: 50050,
        source: "Cobalt Strike",
        description: "Cobalt Strike team server default",
    },
    SuspiciousPort {
        port: 31337,
        source: "Sliver C2",
        description: "Sliver multiplayer/operator default",
    },
    // --- SIGMA dbfc7c98 (Linux malware callback) ---
    SuspiciousPort {
        port: 888,
        source: "SIGMA dbfc7c98",
        description: "known malware callback port",
    },
    SuspiciousPort {
        port: 999,
        source: "SIGMA dbfc7c98",
        description: "known malware callback port",
    },
    SuspiciousPort {
        port: 2200,
        source: "SIGMA dbfc7c98",
        description: "non-standard SSH / malware callback",
    },
    SuspiciousPort {
        port: 2222,
        source: "SIGMA dbfc7c98",
        description: "non-standard SSH / malware callback",
    },
    SuspiciousPort {
        port: 4000,
        source: "SIGMA dbfc7c98",
        description: "known malware callback port",
    },
    SuspiciousPort {
        port: 6789,
        source: "SIGMA dbfc7c98",
        description: "known malware callback port",
    },
    SuspiciousPort {
        port: 8531,
        source: "SIGMA dbfc7c98",
        description: "WSUS impersonation / callback",
    },
    SuspiciousPort {
        port: 50501,
        source: "SIGMA dbfc7c98",
        description: "known malware callback port",
    },
    SuspiciousPort {
        port: 51820,
        source: "SIGMA dbfc7c98 + Sliver C2",
        description: "WireGuard / Sliver WireGuard C2",
    },
    // --- SIGMA 4b89abaa (Windows malware callback, high-signal subset) ---
    SuspiciousPort {
        port: 666,
        source: "SIGMA 4b89abaa",
        description: "known malware callback port",
    },
    SuspiciousPort {
        port: 777,
        source: "SIGMA 4b89abaa",
        description: "known malware callback port",
    },
    SuspiciousPort {
        port: 1443,
        source: "SIGMA 4b89abaa",
        description: "TLS impersonation / callback",
    },
    SuspiciousPort {
        port: 1777,
        source: "SIGMA 4b89abaa",
        description: "known malware callback port",
    },
    SuspiciousPort {
        port: 2443,
        source: "SIGMA 4b89abaa",
        description: "TLS impersonation / callback",
    },
    SuspiciousPort {
        port: 4433,
        source: "SIGMA 4b89abaa",
        description: "TLS impersonation / callback",
    },
    SuspiciousPort {
        port: 4438,
        source: "SIGMA 4b89abaa",
        description: "known malware callback port",
    },
    SuspiciousPort {
        port: 4443,
        source: "SIGMA 4b89abaa",
        description: "TLS impersonation / callback",
    },
    SuspiciousPort {
        port: 4455,
        source: "SIGMA 4b89abaa",
        description: "known malware callback port",
    },
    SuspiciousPort {
        port: 5445,
        source: "SIGMA 4b89abaa",
        description: "known malware callback port",
    },
    SuspiciousPort {
        port: 5552,
        source: "SIGMA 4b89abaa",
        description: "known malware callback port",
    },
    SuspiciousPort {
        port: 7777,
        source: "SIGMA 4b89abaa",
        description: "known malware callback port",
    },
    SuspiciousPort {
        port: 8143,
        source: "SIGMA 4b89abaa",
        description: "IMAP impersonation / callback",
    },
    SuspiciousPort {
        port: 8843,
        source: "SIGMA 4b89abaa",
        description: "known malware callback port",
    },
    SuspiciousPort {
        port: 9943,
        source: "SIGMA 4b89abaa",
        description: "known malware callback port",
    },
    SuspiciousPort {
        port: 10101,
        source: "SIGMA 4b89abaa",
        description: "known malware callback port",
    },
    SuspiciousPort {
        port: 65535,
        source: "SIGMA 4b89abaa",
        description: "max port — common backdoor",
    },
    // --- SIGMA 6d8c3d20 (uncommon destination) + Sliver mTLS ---
    SuspiciousPort {
        port: 8888,
        source: "SIGMA 6d8c3d20 + Sliver C2",
        description: "Sliver mTLS default / uncommon HTTP",
    },
    // --- Additional well-known pentest ports ---
    SuspiciousPort {
        port: 1337,
        source: "convention",
        description: "leet port — common in pentest tools",
    },
    SuspiciousPort {
        port: 4445,
        source: "convention",
        description: "Metasploit alternate handler",
    },
    SuspiciousPort {
        port: 5555,
        source: "convention",
        description: "common backdoor / Android debug bridge",
    },
    SuspiciousPort {
        port: 6666,
        source: "convention",
        description: "common backdoor port",
    },
    SuspiciousPort {
        port: 6667,
        source: "convention",
        description: "IRC — frequently used for botnet C2",
    },
    SuspiciousPort {
        port: 9999,
        source: "convention",
        description: "common backdoor / pentest port",
    },
    SuspiciousPort {
        port: 3333,
        source: "convention",
        description: "common reverse shell port",
    },
];
