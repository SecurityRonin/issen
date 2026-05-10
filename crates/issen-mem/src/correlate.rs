/// Re-exports and smoke tests for memf-correlate integration.
pub use memf_correlate::event::{Entity, Finding, ForensicEvent, Severity};
pub use memf_correlate::process_tree::{ProcessNode, ProcessTree};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forensic_event_builder_smoke() {
        let event = ForensicEvent::builder()
            .source_walker("issen-mem-test")
            .entity(Entity::Process {
                pid: 1,
                name: "System".into(),
                ppid: None,
            })
            .finding(Finding::DefenseEvasion)
            .severity(Severity::High)
            .build();
        assert_eq!(event.source_walker, "issen-mem-test");
        assert_eq!(event.severity, Severity::High);
    }

    #[test]
    fn process_tree_from_empty_events() {
        let tree = ProcessTree::from_events(vec![]);
        assert!(tree.roots().is_empty());
    }

    #[test]
    fn process_tree_single_root() {
        let event = ForensicEvent::builder()
            .source_walker("issen-mem-test")
            .entity(Entity::Process {
                pid: 4,
                name: "System".into(),
                ppid: None,
            })
            .finding(Finding::Other("test".into()))
            .severity(Severity::Info)
            .build();
        let tree = ProcessTree::from_events(vec![event]);
        assert_eq!(tree.roots().len(), 1);
        assert_eq!(tree.roots()[0].pid, 4);
    }
}
