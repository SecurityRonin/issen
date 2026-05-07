//! Event handler modules for Windows Event Log forensic analysis.
//!
//! Each handler knows which event IDs it handles, can produce a human-readable
//! summary, and can extract structured key-value fields from an event.

use winevt_core::EvtxEvent;

/// Trait implemented by all event handlers.
pub trait EventHandler: Send + Sync {
    /// Returns true if this handler should process this event.
    fn handles(&self, event_id: u32, channel: &str) -> bool;

    /// Extract a human-readable summary from the event.
    fn summarize(&self, event: &EvtxEvent) -> Option<String>;

    /// Extract structured fields relevant to this handler.
    fn extract_fields(&self, event: &EvtxEvent) -> Vec<(String, String)>;
}

// --- Handler structs ---

pub struct LogonHandler;
pub struct ProcessHandler;
pub struct ServiceHandler;
pub struct SchedTaskHandler;
pub struct PowershellHandler;
pub struct RdpClientHandler;
pub struct RdpServerHandler;
pub struct WlanHandler;
pub struct LogClearedHandler;
pub struct BitsHandler;
pub struct AuditChangeHandler;
pub struct DefenderHandler;

// --- Helper for extracting optional data fields ---

fn get(event: &EvtxEvent, key: &str) -> String {
    event.data.get(key).cloned().unwrap_or_default()
}

fn field(event: &EvtxEvent, key: &str) -> Option<(String, String)> {
    event
        .data
        .get(key)
        .map(|v| (key.to_string(), v.clone()))
}

// --- Logon: 4624, 4625, 4634, 4647, 4648 ---

impl EventHandler for LogonHandler {
    fn handles(&self, event_id: u32, _channel: &str) -> bool {
        matches!(event_id, 4624 | 4625 | 4634 | 4647 | 4648)
    }

    fn summarize(&self, event: &EvtxEvent) -> Option<String> {
        let user = get(event, "TargetUserName");
        let domain = get(event, "TargetDomainName");
        let ltype = get(event, "LogonType");
        let ip = get(event, "IpAddress");
        let label = match event.event_id {
            4624 => "Logon",
            4625 => "Failed logon",
            4634 => "Logoff",
            4647 => "User initiated logoff",
            4648 => "Explicit credential logon",
            _ => return None,
        };
        Some(format!(
            "{label}: {domain}\\{user} type={ltype} src={ip}"
        ))
    }

    fn extract_fields(&self, event: &EvtxEvent) -> Vec<(String, String)> {
        ["TargetUserName", "TargetDomainName", "LogonType", "IpAddress", "SubStatus"]
            .iter()
            .filter_map(|k| field(event, k))
            .collect()
    }
}

// --- Process: 4688, 4689 ---

impl EventHandler for ProcessHandler {
    fn handles(&self, event_id: u32, _channel: &str) -> bool {
        matches!(event_id, 4688 | 4689)
    }

    fn summarize(&self, event: &EvtxEvent) -> Option<String> {
        let proc = get(event, "NewProcessName");
        let cmd = get(event, "CommandLine");
        let label = if event.event_id == 4688 {
            "Process created"
        } else {
            "Process exited"
        };
        Some(format!("{label}: {proc} [{cmd}]"))
    }

    fn extract_fields(&self, event: &EvtxEvent) -> Vec<(String, String)> {
        ["NewProcessName", "CommandLine", "ParentProcessName", "SubjectLogonId"]
            .iter()
            .filter_map(|k| field(event, k))
            .collect()
    }
}

// --- Service: 7045, 7034, 7036 ---

impl EventHandler for ServiceHandler {
    fn handles(&self, event_id: u32, _channel: &str) -> bool {
        matches!(event_id, 7045 | 7034 | 7036)
    }

    fn summarize(&self, event: &EvtxEvent) -> Option<String> {
        let name = get(event, "ServiceName");
        let label = match event.event_id {
            7045 => "Service installed",
            7034 => "Service crashed",
            7036 => "Service state change",
            _ => return None,
        };
        Some(format!("{label}: {name}"))
    }

    fn extract_fields(&self, event: &EvtxEvent) -> Vec<(String, String)> {
        ["ServiceName", "ImagePath", "ServiceType", "StartType", "AccountName"]
            .iter()
            .filter_map(|k| field(event, k))
            .collect()
    }
}

// --- Scheduled Task: 4698, 4702 ---

impl EventHandler for SchedTaskHandler {
    fn handles(&self, event_id: u32, _channel: &str) -> bool {
        matches!(event_id, 4698 | 4702)
    }

    fn summarize(&self, event: &EvtxEvent) -> Option<String> {
        let name = get(event, "TaskName");
        let label = if event.event_id == 4698 {
            "Scheduled task created"
        } else {
            "Scheduled task updated"
        };
        Some(format!("{label}: {name}"))
    }

    fn extract_fields(&self, event: &EvtxEvent) -> Vec<(String, String)> {
        ["TaskName", "TaskContent", "SubjectUserName"]
            .iter()
            .filter_map(|k| field(event, k))
            .collect()
    }
}

// --- PowerShell: 4103, 4104 (Operational), 400, 600 (Classic) ---

impl EventHandler for PowershellHandler {
    fn handles(&self, event_id: u32, channel: &str) -> bool {
        match event_id {
            400 | 600 | 4103 | 4104 => channel.contains("PowerShell"),
            _ => false,
        }
    }

    fn summarize(&self, event: &EvtxEvent) -> Option<String> {
        let script = event
            .data
            .get("ScriptBlockText")
            .or_else(|| event.data.get("HostApplication"))
            .cloned()
            .unwrap_or_default();
        let preview: String = script.chars().take(120).collect();
        Some(format!("PowerShell ({}): {preview}", event.event_id))
    }

    fn extract_fields(&self, event: &EvtxEvent) -> Vec<(String, String)> {
        ["ScriptBlockText", "HostApplication", "CommandLine", "Path"]
            .iter()
            .filter_map(|k| field(event, k))
            .collect()
    }
}

// --- RDP Client: 1024, 1102 (TermServClient) ---

impl EventHandler for RdpClientHandler {
    fn handles(&self, event_id: u32, channel: &str) -> bool {
        matches!(event_id, 1024 | 1102)
            && channel.contains("TerminalServices-RDPClient")
    }

    fn summarize(&self, event: &EvtxEvent) -> Option<String> {
        let server = get(event, "Value");
        let label = if event.event_id == 1024 {
            "RDP client connected to"
        } else {
            "RDP client disconnected from"
        };
        Some(format!("{label}: {server}"))
    }

    fn extract_fields(&self, event: &EvtxEvent) -> Vec<(String, String)> {
        ["Value"]
            .iter()
            .filter_map(|k| field(event, k))
            .collect()
    }
}

// --- RDP Server: 4778, 4779 ---

impl EventHandler for RdpServerHandler {
    fn handles(&self, event_id: u32, _channel: &str) -> bool {
        matches!(event_id, 4778 | 4779)
    }

    fn summarize(&self, event: &EvtxEvent) -> Option<String> {
        let user = get(event, "AccountName");
        let ip = get(event, "ClientAddress");
        let label = if event.event_id == 4778 {
            "RDP session reconnected"
        } else {
            "RDP session disconnected"
        };
        Some(format!("{label}: {user} from {ip}"))
    }

    fn extract_fields(&self, event: &EvtxEvent) -> Vec<(String, String)> {
        ["AccountName", "ClientAddress", "SessionName"]
            .iter()
            .filter_map(|k| field(event, k))
            .collect()
    }
}

// --- WLAN: 11000, 11001, 11010 ---

impl EventHandler for WlanHandler {
    fn handles(&self, event_id: u32, channel: &str) -> bool {
        matches!(event_id, 11000 | 11001 | 11010)
            && channel.contains("WLAN-AutoConfig")
    }

    fn summarize(&self, event: &EvtxEvent) -> Option<String> {
        let ssid = get(event, "SSID");
        let label = match event.event_id {
            11000 => "WLAN association started",
            11001 => "WLAN association succeeded",
            11010 => "WLAN network connected",
            _ => return None,
        };
        Some(format!("{label}: {ssid}"))
    }

    fn extract_fields(&self, event: &EvtxEvent) -> Vec<(String, String)> {
        ["SSID", "BSSID", "PHYType", "AuthAlgo"]
            .iter()
            .filter_map(|k| field(event, k))
            .collect()
    }
}

// --- Log Cleared: 1102 (Security), 104 (System) ---

impl EventHandler for LogClearedHandler {
    fn handles(&self, event_id: u32, channel: &str) -> bool {
        (event_id == 1102 && channel == "Security")
            || (event_id == 104 && channel == "System")
    }

    fn summarize(&self, event: &EvtxEvent) -> Option<String> {
        let user = get(event, "SubjectUserName");
        Some(format!(
            "Log cleared ({}): by {user}",
            event.channel
        ))
    }

    fn extract_fields(&self, event: &EvtxEvent) -> Vec<(String, String)> {
        ["SubjectUserName", "SubjectDomainName"]
            .iter()
            .filter_map(|k| field(event, k))
            .collect()
    }
}

// --- BITS Client: 59, 60, 61 ---

impl EventHandler for BitsHandler {
    fn handles(&self, event_id: u32, channel: &str) -> bool {
        matches!(event_id, 59..=61) && channel.contains("Bits-Client")
    }

    fn summarize(&self, event: &EvtxEvent) -> Option<String> {
        let name = get(event, "jobTitle");
        let url = get(event, "url");
        let label = match event.event_id {
            59 => "BITS job created",
            60 => "BITS job completed",
            61 => "BITS job error",
            _ => return None,
        };
        Some(format!("{label}: {name} url={url}"))
    }

    fn extract_fields(&self, event: &EvtxEvent) -> Vec<(String, String)> {
        ["jobTitle", "url", "fileTime", "bytesTransferred"]
            .iter()
            .filter_map(|k| field(event, k))
            .collect()
    }
}

// --- Audit Policy Change: 4719 ---

impl EventHandler for AuditChangeHandler {
    fn handles(&self, event_id: u32, _channel: &str) -> bool {
        event_id == 4719
    }

    fn summarize(&self, event: &EvtxEvent) -> Option<String> {
        let category = get(event, "CategoryId");
        let subcategory = get(event, "SubcategoryGuid");
        Some(format!(
            "Audit policy changed: category={category} sub={subcategory}"
        ))
    }

    fn extract_fields(&self, event: &EvtxEvent) -> Vec<(String, String)> {
        ["CategoryId", "SubcategoryGuid", "AuditPolicyChanges", "SubjectUserName"]
            .iter()
            .filter_map(|k| field(event, k))
            .collect()
    }
}

// --- Defender: 1116, 1117, 1118 ---

impl EventHandler for DefenderHandler {
    fn handles(&self, event_id: u32, _channel: &str) -> bool {
        matches!(event_id, 1116..=1118)
    }

    fn summarize(&self, event: &EvtxEvent) -> Option<String> {
        let threat = get(event, "Threat Name");
        let path = get(event, "Path");
        let label = match event.event_id {
            1116 => "Defender detected",
            1117 => "Defender action taken",
            1118 => "Defender action failed",
            _ => return None,
        };
        Some(format!("{label}: {threat} at {path}"))
    }

    fn extract_fields(&self, event: &EvtxEvent) -> Vec<(String, String)> {
        ["Threat Name", "Path", "Action Name", "Severity Name"]
            .iter()
            .filter_map(|k| field(event, k))
            .collect()
    }
}

/// Return all built-in handlers.
pub fn all_handlers() -> Vec<Box<dyn EventHandler>> {
    vec![
        Box::new(LogonHandler),
        Box::new(ProcessHandler),
        Box::new(ServiceHandler),
        Box::new(SchedTaskHandler),
        Box::new(PowershellHandler),
        Box::new(RdpClientHandler),
        Box::new(RdpServerHandler),
        Box::new(WlanHandler),
        Box::new(LogClearedHandler),
        Box::new(BitsHandler),
        Box::new(AuditChangeHandler),
        Box::new(DefenderHandler),
    ]
}
