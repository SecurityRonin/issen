use std::collections::HashMap;

use crate::model::Evidence;

/// Selects which attribute to group `Evidence` items by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterKey {
    /// Group by process ID (`SubjectRef::Process`).
    ByPid,
    /// Group by the `"user"` entry in `attrs`.
    ByUser,
    /// Group by the `"path"` entry in `attrs`.
    ByPath,
}

/// Groups `events` by the attribute selected by `key`.
///
/// Events that do not carry the requested attribute are collected under the
/// sentinel key `"__unknown__"`.
///
/// # Returns
/// A `HashMap` whose keys are string representations of the attribute value
/// and whose values are slices of references to the matching `Evidence` items.
#[must_use]
pub fn cluster_events<'a>(
    events: &'a [Evidence],
    key: &ClusterKey,
) -> HashMap<String, Vec<&'a Evidence>> {
    const UNKNOWN: &str = "__unknown__";
    let mut map: HashMap<String, Vec<&'a Evidence>> = HashMap::new();

    for ev in events {
        let bucket = match &key {
            ClusterKey::ByPid => {
                use crate::model::SubjectRef;
                match &ev.subject {
                    Some(SubjectRef::Process(pid)) => pid.to_string(),
                    _ => UNKNOWN.to_string(),
                }
            }
            ClusterKey::ByUser => ev
                .attrs
                .get("user")
                .cloned()
                .unwrap_or_else(|| UNKNOWN.to_string()),
            ClusterKey::ByPath => ev
                .attrs
                .get("path")
                .cloned()
                .unwrap_or_else(|| UNKNOWN.to_string()),
        };
        map.entry(bucket).or_default().push(ev);
    }

    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Evidence, EvidenceKind, EvidenceSource, SubjectRef};

    fn make_process_evidence(id: &str, pid: u32) -> Evidence {
        Evidence::new(
            id,
            EvidenceSource::Artifact,
            EvidenceKind::Process,
            Some(SubjectRef::Process(pid)),
        )
    }

    fn make_evidence_with_attrs(id: &str, attrs: &[(&str, &str)]) -> Evidence {
        let mut ev = Evidence::new(
            id,
            EvidenceSource::Artifact,
            EvidenceKind::Artifact,
            None,
        );
        for (k, v) in attrs {
            ev = ev.with_attr(*k, *v);
        }
        ev
    }

    // ── test 1: ByPid clusters events that share a PID ────────────────────────

    #[test]
    fn by_pid_groups_events_sharing_same_pid() {
        let events = vec![
            make_process_evidence("ev-1", 1234),
            make_process_evidence("ev-2", 1234),
            make_process_evidence("ev-3", 5678),
        ];

        let clusters = cluster_events(&events, &ClusterKey::ByPid);

        let group_1234 = clusters.get("1234").expect("cluster for pid 1234");
        assert_eq!(group_1234.len(), 2);
        assert!(group_1234.iter().any(|e| e.id == "ev-1"));
        assert!(group_1234.iter().any(|e| e.id == "ev-2"));

        let group_5678 = clusters.get("5678").expect("cluster for pid 5678");
        assert_eq!(group_5678.len(), 1);
        assert_eq!(group_5678[0].id, "ev-3");
    }

    // ── test 2: ByPid sends non-process evidence to __unknown__ ───────────────

    #[test]
    fn by_pid_places_non_process_subjects_in_unknown() {
        let events = vec![
            make_process_evidence("ev-proc", 42),
            make_evidence_with_attrs("ev-no-pid", &[("user", "root")]),
        ];

        let clusters = cluster_events(&events, &ClusterKey::ByPid);

        let unknown = clusters.get("__unknown__").expect("__unknown__ bucket");
        assert_eq!(unknown.len(), 1);
        assert_eq!(unknown[0].id, "ev-no-pid");
    }

    // ── test 3: ByUser groups events by "user" attribute ─────────────────────

    #[test]
    fn by_user_groups_events_by_user_attribute() {
        let events = vec![
            make_evidence_with_attrs("ev-1", &[("user", "alice")]),
            make_evidence_with_attrs("ev-2", &[("user", "alice")]),
            make_evidence_with_attrs("ev-3", &[("user", "bob")]),
        ];

        let clusters = cluster_events(&events, &ClusterKey::ByUser);

        let alice = clusters.get("alice").expect("cluster for alice");
        assert_eq!(alice.len(), 2);

        let bob = clusters.get("bob").expect("cluster for bob");
        assert_eq!(bob.len(), 1);
        assert_eq!(bob[0].id, "ev-3");
    }

    // ── test 4: ByUser sends events without "user" attr to __unknown__ ────────

    #[test]
    fn by_user_places_events_missing_user_attr_in_unknown() {
        let events = vec![
            make_evidence_with_attrs("ev-user", &[("user", "charlie")]),
            make_evidence_with_attrs("ev-no-user", &[("path", "/tmp/evil")]),
        ];

        let clusters = cluster_events(&events, &ClusterKey::ByUser);

        assert!(clusters.contains_key("charlie"));
        let unknown = clusters.get("__unknown__").expect("__unknown__ bucket");
        assert_eq!(unknown.len(), 1);
        assert_eq!(unknown[0].id, "ev-no-user");
    }

    // ── test 5: ByPath groups events by "path" attribute ─────────────────────

    #[test]
    fn by_path_groups_events_by_path_attribute() {
        let events = vec![
            make_evidence_with_attrs("ev-1", &[("path", "/etc/passwd")]),
            make_evidence_with_attrs("ev-2", &[("path", "/etc/passwd")]),
            make_evidence_with_attrs("ev-3", &[("path", "/tmp/xmrig")]),
            make_evidence_with_attrs("ev-4", &[("user", "root")]), // no path
        ];

        let clusters = cluster_events(&events, &ClusterKey::ByPath);

        let passwd = clusters.get("/etc/passwd").expect("cluster for /etc/passwd");
        assert_eq!(passwd.len(), 2);

        let xmrig = clusters.get("/tmp/xmrig").expect("cluster for /tmp/xmrig");
        assert_eq!(xmrig.len(), 1);

        let unknown = clusters.get("__unknown__").expect("__unknown__ bucket");
        assert_eq!(unknown.len(), 1);
        assert_eq!(unknown[0].id, "ev-4");
    }

    // ── test 6: empty input yields empty map ──────────────────────────────────

    #[test]
    fn empty_input_yields_empty_map() {
        let clusters = cluster_events(&[], &ClusterKey::ByPid);
        assert!(clusters.is_empty());
    }
}
