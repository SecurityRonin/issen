use std::path::Path;

use anyhow::{Context, Result};
use rt_remote_access::model::RemoteAccessCategory;
use rt_remote_access::providers::filesystem::FilesystemProvider;
use rt_remote_access::providers::CompositeArtifactProvider;
use rt_remote_access::ScanConfig;

pub fn run(
    evidence_path: &Path,
    rules_dir: Option<&Path>,
    custom_rules: Option<&Path>,
    categories: Option<&str>,
    format: &str,
    db: Option<&Path>,
) -> Result<()> {
    if !evidence_path.exists() {
        anyhow::bail!("Evidence path does not exist: {}", evidence_path.display());
    }

    let mut composite = CompositeArtifactProvider::new();
    composite.add_provider(Box::new(FilesystemProvider::new(evidence_path)));

    let categories = categories.map(|s| {
        s.split(',')
            .filter_map(|c| match c.trim().to_lowercase().as_str() {
                "rmm" | "commercial_rmm" => Some(RemoteAccessCategory::CommercialRmm),
                "builtin" | "builtin_remote" => Some(RemoteAccessCategory::BuiltInRemoteAccess),
                "vpn" | "vpn_ztna" => Some(RemoteAccessCategory::VpnZtna),
                "tunneling" => Some(RemoteAccessCategory::Tunneling),
                "lateral" | "lateral_movement" => Some(RemoteAccessCategory::LateralMovement),
                "c2" | "c2_framework" => Some(RemoteAccessCategory::C2Framework),
                "webshell" | "web_shell" => Some(RemoteAccessCategory::WebShell),
                "firewall" | "firewall_config" => Some(RemoteAccessCategory::FirewallConfig),
                "hardware" | "hardware_remote" => Some(RemoteAccessCategory::HardwareRemote),
                other => {
                    eprintln!("Warning: unknown category '{other}', skipping");
                    None
                }
            })
            .collect()
    });

    let config = ScanConfig {
        lolrmm_dir: rules_dir.map(std::path::PathBuf::from),
        custom_rules_dir: custom_rules.map(std::path::PathBuf::from),
        categories,
    };

    let result = rt_remote_access::scan(&composite, &config);

    for warning in &result.warnings {
        eprintln!("Warning: {warning}");
    }

    if result.findings.is_empty() {
        println!("No remote access artifacts detected.");
    } else {
        println!("Found {} remote access tool(s):\n", result.findings.len());
        for finding in &result.findings {
            match format {
                "json" => {
                    let json =
                        serde_json::to_string_pretty(finding).unwrap_or_else(|_| "{}".into());
                    println!("{json}");
                }
                _ => {
                    println!(
                        "  {} [{}] — {} artifact(s)",
                        finding.tool_name,
                        finding.category,
                        finding.artifacts.len()
                    );
                    if let Some(first) = finding.first_seen {
                        println!("    First seen: {first}");
                    }
                    if let Some(last) = finding.last_seen {
                        println!("    Last seen:  {last}");
                    }
                }
            }
        }
    }

    if let Some(db_path) = db {
        let store = rt_timeline::store::TimelineStore::open(db_path)
            .with_context(|| format!("Failed to open database: {}", db_path.display()))?;
        rt_remote_access::store::initialize_findings_schema(&store)
            .context("Failed to create findings schema")?;
        for finding in &result.findings {
            rt_remote_access::store::insert_finding(&store, finding, "cli-scan")
                .context("Failed to insert finding")?;
            rt_remote_access::store::emit_cross_reference_event(&store, finding, "cli-scan")
                .context("Failed to emit cross-reference")?;
        }
        println!("\nFindings written to {}", db_path.display());
    }

    Ok(())
}
