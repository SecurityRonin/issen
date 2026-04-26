use crate::model::Evidence;

#[must_use]
pub fn enrich_evidence(evidence: Vec<Evidence>) -> Vec<Evidence> {
    evidence
        .into_iter()
        .map(|mut item| {
            if let Some(command) = item.attrs.get("command") {
                if forensicnomicon::commands::is_reverse_shell_pattern(command) {
                    push_tag(&mut item.tags, "reverse_shell");
                }
                if forensicnomicon::commands::is_powershell_abuse(command) {
                    push_tag(&mut item.tags, "powershell_abuse");
                }
                if forensicnomicon::commands::is_download_tool_usage(command) {
                    push_tag(&mut item.tags, "download_tool");
                }
            }

            for key in ["dst_port", "src_port", "port"] {
                if let Some(port) = item
                    .attrs
                    .get(key)
                    .and_then(|value| value.parse::<u16>().ok())
                {
                    if forensicnomicon::ports::is_suspicious_port(port) {
                        push_tag(&mut item.tags, "suspicious_port");
                    }
                }
            }

            if let Some(name) = item.attrs.get("process_name") {
                if forensicnomicon::processes::is_known_malware_process(name) {
                    push_tag(&mut item.tags, "known_malware_process");
                }
            }

            item
        })
        .collect()
}

fn push_tag(tags: &mut Vec<String>, tag: &str) {
    if !tags.iter().any(|existing| existing == tag) {
        tags.push(tag.to_string());
    }
}
