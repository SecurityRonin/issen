//! `issen-usb` — the USB cross-source correlation seam.
//!
//! `usb-forensic` is an orchestration-tier engine: it correlates USB device history
//! across setupapi / registry / LNK / event-log sources and emits
//! [`usb_forensic::TimelineEvent`]s (epoch **seconds**) plus
//! `forensicnomicon::report::Finding`s. issen's `ForensicParser` plugin path is
//! single-DataSource and its emitter carries only [`TimelineEvent`], so USB
//! correlation is wired here, in the correlation stage, instead of as a parser.
//!
//! This module owns the type-boundary conversion (usb-forensic → issen). The
//! artifact-locating seam (feeding issen's located setupapi/hive/LNK paths into
//! usb-forensic's `HistorySource`s) and the report routing are wired by the
//! correlation-stage caller.

use issen_core::artifacts::ArtifactType;
use issen_core::timeline::event::{EventType, TimelineEvent};

/// Stable issen event-type label for a usb-forensic [`Attribute`](usb_forensic::Attribute).
///
/// issen's `EventType` has no USB variant, so USB events ride `EventType::Other`
/// under [`ArtifactType::DeviceInstall`]. The labels are a published contract.
#[must_use]
pub fn attribute_label(attribute: &usb_forensic::Attribute) -> &'static str {
    "UsbEvent" // RED — real mapping in GREEN
}

/// Convert a `usb-forensic` cross-source timeline event into an issen [`TimelineEvent`].
///
/// usb-forensic timestamps are epoch **seconds**; issen uses **nanoseconds**.
#[must_use]
pub fn to_issen_event(
    _ev: &usb_forensic::TimelineEvent,
    _evidence_source_id: &str,
) -> TimelineEvent {
    // RED — stub yields an empty event so the assertions fail.
    TimelineEvent::new(
        0,
        String::new(),
        EventType::Other(String::new()),
        ArtifactType::DeviceInstall,
        String::new(),
        String::new(),
        String::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use usb_forensic::{Attribute, DeviceKey, SourceKind};

    fn sample() -> usb_forensic::TimelineEvent {
        usb_forensic::TimelineEvent {
            when: 1_700_000_000,
            device: DeviceKey("USBSTOR\\Disk&Ven_SanDisk\\1234".to_owned()),
            attribute: Attribute::FirstConnected,
            source: SourceKind::SetupApi,
            locator: "setupapi.dev.log:42".to_owned(),
        }
    }

    #[test]
    fn seconds_convert_to_nanoseconds() {
        let out = to_issen_event(&sample(), "evid-1");
        assert_eq!(out.timestamp_ns, 1_700_000_000_000_000_000);
    }

    #[test]
    fn source_is_device_install() {
        assert_eq!(
            to_issen_event(&sample(), "e").source,
            ArtifactType::DeviceInstall
        );
    }

    #[test]
    fn event_type_carries_the_attribute_label() {
        let out = to_issen_event(&sample(), "e");
        assert_eq!(
            out.event_type,
            EventType::Other("UsbFirstConnected".to_owned())
        );
    }

    #[test]
    fn locator_and_evidence_id_preserved() {
        let out = to_issen_event(&sample(), "evid-1");
        assert_eq!(out.artifact_path, "setupapi.dev.log:42");
        assert_eq!(out.evidence_source_id, "evid-1");
    }

    #[test]
    fn attribute_labels_are_distinct_and_stable() {
        assert_eq!(
            attribute_label(&Attribute::FirstConnected),
            "UsbFirstConnected"
        );
        assert_eq!(attribute_label(&Attribute::LastRemoved), "UsbLastRemoved");
        assert_ne!(
            attribute_label(&Attribute::FirstConnected),
            attribute_label(&Attribute::LastConnected)
        );
    }
}
