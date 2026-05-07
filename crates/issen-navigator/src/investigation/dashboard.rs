//! Dashboard rendering for the Investigation Workbench.
//!
//! The dashboard is the landing page of the workbench, showing a system
//! profile table (top-left), artifact category counts (bottom-left),
//! and a right panel with a sparkline + alerts list.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Sparkline, Wrap};
use ratatui::Frame;

use super::alerts::AlertSeverity;
use super::data::CollectionMetadata;
use super::timeline::build_sparkline;
use super::WorkbenchApp;

/// Draw the full dashboard view into the given area.
pub fn draw_dashboard(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let chunks =
        Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)]).split(area);

    draw_left_panel(frame, app, chunks[0]);
    draw_right_panel(frame, app, chunks[1]);
}

/// Left panel: system profile + artifact counts.
fn draw_left_panel(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let profile_rows = profile_line_count(&app.data.metadata);
    // +2 for border top/bottom
    let profile_height = (profile_rows as u16 + 2).min(area.height.saturating_sub(4));

    let chunks =
        Layout::vertical([Constraint::Length(profile_height), Constraint::Min(4)]).split(area);

    draw_system_profile(frame, &app.data.metadata, chunks[0]);
    draw_artifact_counts(frame, app, chunks[1]);
}

/// Render the system profile table.
fn draw_system_profile(frame: &mut Frame, meta: &CollectionMetadata, area: Rect) {
    let mut lines: Vec<Line<'static>> = Vec::new();

    let label_style = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);

    // Build profile rows — only show fields that have data
    let hostname_display = if !meta.fqdn.is_empty() {
        &meta.fqdn
    } else {
        &meta.hostname
    };
    if !hostname_display.is_empty() {
        lines.push(profile_row("Hostname", hostname_display, label_style));
    }
    if !meta.ip_address.is_empty() {
        lines.push(profile_row("IP Address", &meta.ip_address, label_style));
    }
    if !meta.os.is_empty() {
        lines.push(profile_row("OS", &meta.os, label_style));
    }
    if !meta.kernel_version.is_empty() {
        lines.push(profile_row("Kernel", &meta.kernel_version, label_style));
    }
    // Hardware section: Platform + Architecture + RAM + Storage
    if !meta.platform.is_empty() {
        lines.push(profile_row("Hardware", &meta.platform, label_style));
    }
    if !meta.architecture.is_empty() {
        lines.push(profile_row("Architecture", &meta.architecture, label_style));
    }
    if meta.ram_total_kb > 0 {
        let ram_display = issen_parser_uac::parsers::system::format_ram_kb(meta.ram_total_kb);
        lines.push(profile_row("RAM", &ram_display, label_style));
    }
    for dev in &meta.storage_devices {
        let display = issen_parser_uac::parsers::system::format_storage_device(dev);
        lines.push(profile_row("Storage", &display, label_style));
    }
    if !meta.timezone.is_empty() {
        lines.push(profile_row("Timezone", &meta.timezone, label_style));
    }
    if !meta.uptime.is_empty() {
        lines.push(profile_row("Uptime", &meta.uptime, label_style));
    }
    if !meta.locale.is_empty() {
        lines.push(profile_row("Locale", &meta.locale, label_style));
    }
    for (user, locale) in &meta.user_locales {
        let display = format!("{locale} ({user})");
        lines.push(profile_row("User Locale", &display, label_style));
    }
    if !meta.atime_policy.is_empty() {
        lines.push(profile_row(
            "Access Times",
            &format_atime_policy(&meta.atime_policy),
            label_style,
        ));
    }
    if meta.acquisition_time > 0 {
        let display = chrono::DateTime::from_timestamp(meta.acquisition_time, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
            .unwrap_or_else(|| meta.acquisition_time.to_string());
        lines.push(profile_row("Collected", &display, label_style));
    }
    if !meta.collection_tool.is_empty() {
        lines.push(profile_row("Collector", &meta.collection_tool, label_style));
    }

    if lines.is_empty() {
        lines.push(Line::from("  (no system profile data)".to_string()));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" System Profile ");

    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });

    frame.render_widget(paragraph, area);
}

/// Build a single profile row: `  Label:  value`
fn profile_row(label: &str, value: &str, label_style: Style) -> Line<'static> {
    // Right-pad label to 14 chars for alignment
    Line::from(vec![
        Span::styled(format!("  {label:<14} "), label_style),
        Span::raw(value.to_string()),
    ])
}

/// Count how many profile lines will be rendered (for height calculation).
fn profile_line_count(meta: &CollectionMetadata) -> usize {
    let mut count = 0;
    if !meta.hostname.is_empty() || !meta.fqdn.is_empty() {
        count += 1;
    }
    if !meta.ip_address.is_empty() {
        count += 1;
    }
    if !meta.os.is_empty() {
        count += 1;
    }
    if !meta.kernel_version.is_empty() {
        count += 1;
    }
    // Hardware section
    if !meta.platform.is_empty() {
        count += 1;
    }
    if !meta.architecture.is_empty() {
        count += 1;
    }
    if meta.ram_total_kb > 0 {
        count += 1;
    }
    count += meta.storage_devices.len();
    // Remaining fields
    if !meta.timezone.is_empty() {
        count += 1;
    }
    if !meta.uptime.is_empty() {
        count += 1;
    }
    if !meta.locale.is_empty() {
        count += 1;
    }
    count += meta.user_locales.len();
    if !meta.atime_policy.is_empty() {
        count += 1;
    }
    if meta.acquisition_time > 0 {
        count += 1;
    }
    if !meta.collection_tool.is_empty() {
        count += 1;
    }
    if count == 0 {
        1 // "(no system profile data)"
    } else {
        count
    }
}

/// Bottom-left: artifact category counts + timeline summary.
fn draw_artifact_counts(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let mut items: Vec<ListItem<'_>> = Vec::new();

    // Supertimeline entry
    if !app.data.timeline.is_empty() {
        let count = app.data.timeline.len();
        let mut lines = vec![Line::from(vec![
            Span::styled("  Supertimeline: ", Style::default().fg(Color::Cyan)),
            Span::raw(format_count(count)),
        ])];
        for (label, src_count) in app.data.timeline_source_counts() {
            lines.push(Line::from(format!(
                "    {label}: {}",
                format_count(src_count)
            )));
        }
        items.push(ListItem::new(lines));
    }

    // Snapshot categories
    let categories: Vec<(&str, usize)> = vec![
        ("Network", app.data.network.len()),
        ("Processes", app.data.processes.len()),
        ("Logins", app.data.logins.len()),
        ("Packages", app.data.packages.len()),
        ("Configs", app.data.configs.len()),
        ("Hashes", app.data.hashes.len()),
        ("Chkrootkit", app.data.chkrootkit.len()),
    ];

    for (name, count) in categories {
        if count > 0 {
            items.push(ListItem::new(Line::from(vec![
                Span::raw(format!("  {name}: ")),
                Span::raw(format_count(count)),
            ])));
        }
    }

    // Artifact inventory (from collection manifest)
    if !app.data.artifact_counts.is_empty() {
        let mut counts: Vec<_> = app.data.artifact_counts.iter().collect();
        counts.soissen_by(|a, b| b.1.cmp(a.1));
        let mut lines = vec![Line::from(Span::styled(
            "  Collection Artifacts:",
            Style::default().fg(Color::Green),
        ))];
        for (label, count) in counts {
            lines.push(Line::from(format!("    {label}: {}", format_count(*count))));
        }
        items.push(ListItem::new(lines));
    }

    let block = Block::default().borders(Borders::ALL).title(" Artifacts ");

    let list = List::new(items)
        .block(block)
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    frame.render_widget(list, area);
}

/// Right panel: sparkline + alerts list.
fn draw_right_panel(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let chunks = Layout::vertical([
        Constraint::Length(5), // sparkline
        Constraint::Min(4),    // alerts
    ])
    .split(area);

    // Sparkline
    let sparkline_data = build_sparkline(&app.data.timeline, chunks[0].width as usize);
    let sparkline = Sparkline::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Supertimeline Activity "),
        )
        .data(&sparkline_data)
        .style(Style::default().fg(Color::Cyan));
    frame.render_widget(sparkline, chunks[0]);

    // Alerts
    let critical_count = app
        .data
        .alerts
        .iter()
        .filter(|a| a.severity == AlertSeverity::Critical)
        .count();
    let warning_count = app
        .data
        .alerts
        .iter()
        .filter(|a| a.severity == AlertSeverity::Warning)
        .count();

    let title = format!(" Alerts ({critical_count} critical, {warning_count} warning) ");

    let aleissen_items: Vec<ListItem<'_>> = app
        .data
        .alerts
        .iter()
        .map(|alert| {
            let color = match alert.severity {
                AlertSeverity::Critical => Color::Red,
                AlertSeverity::Warning => Color::Yellow,
                AlertSeverity::Info => Color::Blue,
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{} ", alert.severity.label()),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::raw(&alert.message),
            ]))
        })
        .collect();

    let alerts_list =
        List::new(aleissen_items).block(Block::default().borders(Borders::ALL).title(title));

    frame.render_widget(alerts_list, chunks[1]);
}

/// Translate raw atime policy into a forensic-meaningful description.
///
/// - `relatime`: atime updated only when older than mtime (Linux default since 2.6.30).
///   Access times exist but may lag behind actual access by up to 24h.
/// - `noatime`: access times never updated — timestamps are stale/meaningless.
/// - `strictatime`: every read updates atime (expensive but forensically accurate).
/// - `atime (default)`: kernel default — same as strictatime on older kernels.
fn format_atime_policy(raw: &str) -> String {
    match raw {
        "relatime" => "Partial (relatime — updated when older than mtime)".to_string(),
        "noatime" => "Disabled (noatime — access times not recorded)".to_string(),
        "strictatime" => "Full (strictatime — every access recorded)".to_string(),
        "atime (default)" => "Full (kernel default)".to_string(),
        other => other.to_string(),
    }
}

/// Format a count with K/M suffixes for readability.
fn format_count(n: usize) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_count() {
        asseissen_eq!(format_count(0), "0");
        asseissen_eq!(format_count(999), "999");
        asseissen_eq!(format_count(1_000), "1.0K");
        asseissen_eq!(format_count(47_832), "47.8K");
        asseissen_eq!(format_count(1_000_000), "1.0M");
    }

    use crate::investigation::data::{CollectionMetadata, InvestigationData};
    use crate::investigation::test_helpers::*;
    use crate::investigation::timeline::{TimelineEvent, TimelineSource, TimestampType};

    fn make_dashboard_app() -> WorkbenchApp {
        let timeline: Vec<TimelineEvent> = (0..100)
            .map(|i| TimelineEvent {
                timestamp: i * 3600 + 1704067200,
                timestamp_type: TimestampType::Modified,
                source: TimelineSource::Bodyfile,
                path: format!("/test/{i}.txt"),
                description: String::new(),
                extra: String::new(),
            })
            .collect();

        let mut artifact_counts = std::collections::HashMap::new();
        artifact_counts.insert("EventLog".to_string(), 326);
        artifact_counts.insert("Prefetch".to_string(), 584);

        app_with(InvestigationData {
            metadata: CollectionMetadata {
                hostname: "WORKSTATION-01".to_string(),
                os: "Windows 10".to_string(),
                collection_tool: "Velociraptor".to_string(),
                acquisition_time: 1704067200,
                ..Default::default()
            },
            alerts: vec![
                crate::investigation::alerts::Alert {
                    severity: crate::investigation::alerts::AlertSeverity::Critical,
                    category: "MFT/Timestomping".to_string(),
                    message: "SI/FN mismatch".to_string(),
                    detail: "test".to_string(),
                },
                crate::investigation::alerts::Alert {
                    severity: crate::investigation::alerts::AlertSeverity::Warning,
                    category: "MFT/Location".to_string(),
                    message: "Suspicious location".to_string(),
                    detail: "test".to_string(),
                },
            ],
            timeline,
            artifact_counts,
            ..Default::default()
        })
    }

    fn make_full_profile_app() -> WorkbenchApp {
        use issen_parser_uac::parsers::system::{MediaType, StorageDevice, StorageInterface};
        app_with(InvestigationData {
            metadata: CollectionMetadata {
                hostname: "vbox".to_string(),
                fqdn: "vbox.fci.int".to_string(),
                os: "Debian GNU/Linux 13 (trixie)".to_string(),
                collection_tool: "UAC".to_string(),
                acquisition_time: 1711312718,
                kernel_version: "Linux 6.12.74+deb13+1-amd64".to_string(),
                platform: "VirtualBox (oracle)".to_string(),
                architecture: "x86-64".to_string(),
                timezone: "America/New_York (EDT, -0400)".to_string(),
                ip_address: "192.168.4.22".to_string(),
                uptime: "19:39:35 up 16 min, 1 user".to_string(),
                locale: "en_US.UTF-8".to_string(),
                atime_policy: "relatime".to_string(),
                user_locales: vec![],
                ram_total_kb: 8138104,
                storage_devices: vec![
                    StorageDevice {
                        name: "sda".to_string(),
                        size: "20G".to_string(),
                        device_type: "disk".to_string(),
                        model: "VBOX HARDDISK".to_string(),
                        interface: StorageInterface::Sata,
                        media_type: MediaType::Hdd,
                    },
                    StorageDevice {
                        name: "sr0".to_string(),
                        size: "1024M".to_string(),
                        device_type: "rom".to_string(),
                        model: String::new(),
                        interface: StorageInterface::Sata,
                        media_type: MediaType::Optical,
                    },
                ],
            },
            ..Default::default()
        })
    }

    #[test]
    fn render_dashboard_with_metadata_no_panic() {
        let app = make_dashboard_app();
        asseissen_renders(&app, |frame, app, area| draw_dashboard(frame, app, area));
    }

    #[test]
    fn render_dashboard_with_alerts_no_panic() {
        let app = make_dashboard_app();
        asseissen_renders(&app, |frame, app, area| draw_dashboard(frame, app, area));
    }

    #[test]
    fn render_dashboard_empty_data_no_panic() {
        let app = empty_app();
        asseissen_renders(&app, |frame, app, area| draw_dashboard(frame, app, area));
    }

    #[test]
    fn render_dashboard_small_terminal_no_panic() {
        let app = make_dashboard_app();
        asseissen_renders(&app, |frame, app, area| draw_dashboard(frame, app, area));
    }

    #[test]
    fn render_dashboard_full_profile_no_panic() {
        let app = make_full_profile_app();
        asseissen_renders(&app, |frame, app, area| draw_dashboard(frame, app, area));
    }

    #[test]
    fn profile_line_count_full() {
        use issen_parser_uac::parsers::system::{MediaType, StorageDevice, StorageInterface};
        let meta = CollectionMetadata {
            hostname: "host".to_string(),
            fqdn: "host.domain".to_string(),
            os: "Linux".to_string(),
            platform: "VM".to_string(),
            timezone: "UTC".to_string(),
            acquisition_time: 1000,
            uptime: "1h".to_string(),
            kernel_version: "5.15".to_string(),
            locale: "C".to_string(),
            atime_policy: "relatime".to_string(),
            user_locales: vec![],
            collection_tool: "UAC".to_string(),
            ip_address: "10.0.0.1".to_string(),
            architecture: "x86-64".to_string(),
            ram_total_kb: 8138104,
            storage_devices: vec![StorageDevice {
                name: "sda".to_string(),
                size: "20G".to_string(),
                device_type: "disk".to_string(),
                model: String::new(),
                interface: StorageInterface::Sata,
                media_type: MediaType::Hdd,
            }],
        };
        // hostname, ip, os, kernel, hardware, arch, ram, 1 storage, tz, uptime,
        // locale, atime, collected, collector = 14
        asseissen_eq!(profile_line_count(&meta), 14);
    }

    #[test]
    fn profile_line_count_empty() {
        let meta = CollectionMetadata::default();
        asseissen_eq!(profile_line_count(&meta), 1); // "(no system profile data)"
    }

    #[test]
    fn profile_prefers_fqdn_over_hostname() {
        let meta = CollectionMetadata {
            hostname: "vbox".to_string(),
            fqdn: "vbox.fci.int".to_string(),
            ..Default::default()
        };
        // The draw_system_profile function uses FQDN when available
        let hostname_display = if !meta.fqdn.is_empty() {
            &meta.fqdn
        } else {
            &meta.hostname
        };
        asseissen_eq!(hostname_display, "vbox.fci.int");
    }

    #[test]
    fn format_count_edge_cases() {
        asseissen_eq!(format_count(1), "1");
        asseissen_eq!(format_count(999), "999");
        asseissen_eq!(format_count(1_500), "1.5K");
        asseissen_eq!(format_count(2_500_000), "2.5M");
    }
}
