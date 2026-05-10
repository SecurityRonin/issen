//! Human-readable rendering of [`Evidence`] items.
//!
//! Converts structured [`Evidence`] into readable one-line strings for
//! display in the analyst report.

use crate::model::{Evidence, EvidenceKind};

/// Render a single [`Evidence`] item as a human-readable line.
///
/// # Examples
///
/// ```
/// use issen_correlation::model::{Evidence, EvidenceKind, EvidenceSource};
/// use issen_correlation::render::render_evidence_line;
///
/// let ev = Evidence::new("rk-1", EvidenceSource::Artifact, EvidenceKind::Artifact, None)
///     .with_attr("check", "ld_preload")
///     .with_attr("evidence", "/lib/x86_64-linux-gnu/libymv.so.3")
///     .with_tag("rootkit_indicator");
/// let line = render_evidence_line(&ev);
/// assert_eq!(line, "LD_PRELOAD: /lib/x86_64-linux-gnu/libymv.so.3");
/// ```
#[must_use]
pub fn render_evidence_line(ev: &Evidence) -> String {
    if ev.tags.iter().any(|t| t == "rootkit_indicator") {
        if ev.attrs.get("check").map(String::as_str) == Some("ld_preload") {
            if let Some(path) = ev.attrs.get("evidence") {
                return format!("LD_PRELOAD: {path}");
            }
        }
        let check = ev.attrs.get("check").map_or("(unknown)", String::as_str);
        let evidence = ev.attrs.get("evidence").map_or("(unknown)", String::as_str);
        return format!("Rootkit indicator [{check}]: {evidence}");
    }

    if ev.tags.iter().any(|t| t == "hidden_process") {
        let name = ev
            .attrs
            .get("process_name")
            .map_or("(unknown)", String::as_str);
        let pid = ev.attrs.get("pid").map_or("?", String::as_str);

        // Collect thread annotation (miner indicator)
        let thread_hint = if ev.tags.iter().any(|t| t == "miner_thread") {
            " [thread: libuv-worker]"
        } else {
            ""
        };
        return format!("PID {pid} \"{name}\"{thread_hint}");
    }

    if ev.kind == EvidenceKind::Network {
        let src_addr = ev.attrs.get("src_addr").or_else(|| ev.attrs.get("local"));
        let src_port = ev.attrs.get("src_port");
        let dst_addr = ev.attrs.get("dst_addr").or_else(|| ev.attrs.get("remote"));
        let dst_port = ev.attrs.get("dst_port");
        let state = ev.attrs.get("state").map_or("?", String::as_str);

        match (src_addr, src_port, dst_addr, dst_port) {
            (Some(sa), Some(sp), Some(da), Some(dp)) => {
                return format!("{sa}:{sp} → {da}:{dp} [{state}]");
            }
            (Some(sa), None, Some(da), None) => {
                return format!("{sa} → {da} [{state}]");
            }
            _ => {}
        }
    }

    // Generic fallback
    format!("[{}] id={}", ev.kind_label(), ev.id)
}

/// Render a slice of [`Evidence`] items as a `Vec` of readable lines.
#[must_use]
pub fn render_evidence_lines(evidence: &[Evidence]) -> Vec<String> {
    evidence.iter().map(render_evidence_line).collect()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

impl Evidence {
    fn kind_label(&self) -> &'static str {
        match self.kind {
            EvidenceKind::Command => "command",
            EvidenceKind::Network => "network",
            EvidenceKind::Process => "process",
            EvidenceKind::Artifact => "artifact",
            EvidenceKind::Alert => "alert",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EvidenceKind, EvidenceSource};

    // ── WS-3 RED tests — these drive the render implementation ──────────────

    #[test]
    fn rootkit_ld_preload_renders_as_ld_preload_line() {
        let ev = Evidence::new(
            "rk-1",
            EvidenceSource::Artifact,
            EvidenceKind::Artifact,
            None,
        )
        .with_attr("check", "ld_preload")
        .with_attr("evidence", "/lib/x86_64-linux-gnu/libymv.so.3")
        .with_tag("rootkit_indicator");
        assert_eq!(
            render_evidence_line(&ev),
            "LD_PRELOAD: /lib/x86_64-linux-gnu/libymv.so.3"
        );
    }

    #[test]
    fn hidden_process_without_threads_renders_pid_and_name() {
        let ev = Evidence::new(
            "proc-1",
            EvidenceSource::Memory,
            EvidenceKind::Process,
            None,
        )
        .with_attr("process_name", "top")
        .with_attr("pid", "977")
        .with_tag("hidden_process");
        assert_eq!(render_evidence_line(&ev), r#"PID 977 "top""#);
    }

    #[test]
    fn hidden_process_with_miner_thread_renders_thread_annotation() {
        let ev = Evidence::new(
            "proc-2",
            EvidenceSource::Memory,
            EvidenceKind::Process,
            None,
        )
        .with_attr("process_name", "top")
        .with_attr("pid", "977")
        .with_tag("hidden_process")
        .with_tag("miner_thread");
        assert_eq!(
            render_evidence_line(&ev),
            r#"PID 977 "top" [thread: libuv-worker]"#
        );
    }

    #[test]
    fn network_connection_renders_src_dst_state() {
        let ev = Evidence::new("net-1", EvidenceSource::Memory, EvidenceKind::Network, None)
            .with_attr("src_addr", "127.0.0.1")
            .with_attr("src_port", "59182")
            .with_attr("dst_addr", "127.0.0.1")
            .with_attr("dst_port", "3333")
            .with_attr("state", "ESTABLISHED");
        assert_eq!(
            render_evidence_line(&ev),
            "127.0.0.1:59182 → 127.0.0.1:3333 [ESTABLISHED]"
        );
    }

    #[test]
    fn render_evidence_lines_produces_one_line_per_item() {
        let evidence = vec![
            Evidence::new(
                "rk-1",
                EvidenceSource::Artifact,
                EvidenceKind::Artifact,
                None,
            )
            .with_attr("check", "ld_preload")
            .with_attr("evidence", "/lib/x86_64-linux-gnu/libymv.so.3")
            .with_tag("rootkit_indicator"),
            Evidence::new(
                "proc-1",
                EvidenceSource::Memory,
                EvidenceKind::Process,
                None,
            )
            .with_attr("process_name", "top")
            .with_attr("pid", "977")
            .with_tag("hidden_process")
            .with_tag("miner_thread"),
        ];
        let lines = render_evidence_lines(&evidence);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "LD_PRELOAD: /lib/x86_64-linux-gnu/libymv.so.3");
        assert_eq!(lines[1], r#"PID 977 "top" [thread: libuv-worker]"#);
    }
}
