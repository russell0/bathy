//! The typed input and output shapes of the endpoint query tool.
//!
//! These live beside the fold rather than beside the other tool shapes
//! because they are stated in terms of a fold entry, and a fold entry is
//! defined here. Both derive `JsonSchema` and are committed under `schemas/`
//! like every other published contract.

use bathy_types::confidence::Confidence;
use bathy_types::event::PortState;
use bathy_types::ids::ScanId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::fold::Terminal;
use crate::wire::FoldEntry;

/// An inclusive port range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PortRange {
    pub low: u16,
    pub high: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        let (low, high) = if self.low <= self.high {
            (self.low, self.high)
        } else {
            (self.high, self.low)
        };
        (low..=high).contains(&port)
    }
}

/// Narrow a folded scan to the endpoints worth looking at.
///
/// Every field is optional, and an endpoint is kept only if it satisfies all
/// the fields that were supplied.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EndpointFilter {
    /// Keep only endpoints in this reachability state. An endpoint whose
    /// state was never observed is dropped by this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<PortState>,
    /// Keep only endpoints whose identified service matches this exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// Keep only endpoints identified with at least this confidence. An
    /// endpoint carrying no identification at all is dropped by this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_confidence: Option<Confidence>,
    /// Keep only endpoints whose port falls inside this inclusive range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_range: Option<PortRange>,
}

impl EndpointFilter {
    /// Whether one folded endpoint survives this filter.
    pub fn matches(&self, entry: &FoldEntry) -> bool {
        if let Some(state) = self.state
            && entry.state != Some(state)
        {
            return false;
        }
        if let Some(range) = self.port_range
            && !range.contains(entry.endpoint.port)
        {
            return false;
        }
        if let Some(service) = &self.service {
            match &entry.observation {
                Some(observation) if &observation.service == service => {}
                _ => return false,
            }
        }
        if let Some(minimum) = self.min_confidence {
            match &entry.observation {
                Some(observation) if observation.confidence >= minimum => {}
                _ => return false,
            }
        }
        true
    }
}

/// Fold a scan's event log into per-endpoint state and return the endpoints
/// that match a filter.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResultQueryInput {
    pub scan_id: ScanId,
    #[serde(default)]
    pub filter: EndpointFilter,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResultQueryOutput {
    /// The matching endpoints, ordered by target, then transport, then port.
    pub endpoints: Vec<FoldEntry>,
    /// How many endpoints matched.
    pub total: u64,
    /// How many endpoints the fold held before the filter was applied.
    pub total_before_filter: u64,
    /// Hosts a `host.discovered` event named. Never narrowed by the filter,
    /// which selects endpoints.
    ///
    /// **Empty is not evidence that no host is up.** No scan emits
    /// `host.discovered` in v0.1.
    ///
    /// This and `plan_hash` are here because the command-line surface
    /// reported them and this document did not. Both surfaces publish one
    /// document, and the way to make two answers agree is not to delete a
    /// fact from the one that had it.
    pub hosts_up: Vec<std::net::IpAddr>,
    /// The plan the scan announced when it started, or null if it never
    /// started. Two scans of the same plan cover the same work, which is what
    /// makes an endpoint missing from one of them meaningful.
    pub plan_hash: Option<bathy_types::ids::Digest>,
    /// How the scan ended, or null if it is still running or was stopped
    /// mid-flight. A scan that was refused by policy ends `denied` and has
    /// no endpoints because no packet was sent, not because nothing is
    /// listening.
    pub terminal: Option<Terminal>,
}

#[cfg(test)]
mod tests {
    use bathy_types::event::{Endpoint, Observation, Transport};

    use super::*;

    fn entry(port: u16, state: Option<PortState>, service: Option<(&str, f64)>) -> FoldEntry {
        FoldEntry {
            target: "10.0.0.1".parse().unwrap(),
            endpoint: Endpoint {
                transport: Transport::Tcp,
                port,
            },
            state,
            observation: service.map(|(name, confidence)| Observation {
                service: name.into(),
                product: None,
                version: None,
                confidence: Confidence::new(confidence).unwrap(),
            }),
            evidence_refs: Vec::new(),
            probe_id: None,
            rule_id: None,
        }
    }

    #[test]
    fn an_empty_filter_keeps_everything() {
        let f = EndpointFilter::default();
        assert!(f.matches(&entry(80, None, None)));
        assert!(f.matches(&entry(80, Some(PortState::Closed), None)));
    }

    #[test]
    fn a_state_filter_drops_an_endpoint_whose_state_was_never_observed() {
        let f = EndpointFilter {
            state: Some(PortState::Open),
            ..Default::default()
        };
        assert!(f.matches(&entry(80, Some(PortState::Open), None)));
        assert!(!f.matches(&entry(80, Some(PortState::Closed), None)));
        assert!(
            !f.matches(&entry(80, None, None)),
            "unknown reachability must not pass as open"
        );
    }

    #[test]
    fn a_confidence_floor_drops_an_unidentified_endpoint_rather_than_keeping_it() {
        let f = EndpointFilter {
            min_confidence: Some(Confidence::new(0.9).unwrap()),
            ..Default::default()
        };
        assert!(f.matches(&entry(80, None, Some(("http", 0.95)))));
        assert!(!f.matches(&entry(80, None, Some(("http", 0.5)))));
        assert!(!f.matches(&entry(80, None, None)));
    }

    #[test]
    fn a_port_range_is_inclusive_at_both_ends_and_tolerates_a_reversed_pair() {
        let f = EndpointFilter {
            port_range: Some(PortRange { low: 80, high: 90 }),
            ..Default::default()
        };
        assert!(f.matches(&entry(80, None, None)));
        assert!(f.matches(&entry(90, None, None)));
        assert!(!f.matches(&entry(91, None, None)));

        let reversed = EndpointFilter {
            port_range: Some(PortRange { low: 90, high: 80 }),
            ..Default::default()
        };
        assert!(reversed.matches(&entry(85, None, None)));
    }

    #[test]
    fn every_supplied_field_must_match_not_merely_one_of_them() {
        let f = EndpointFilter {
            state: Some(PortState::Open),
            service: Some("http".into()),
            ..Default::default()
        };
        assert!(f.matches(&entry(80, Some(PortState::Open), Some(("http", 0.9)))));
        assert!(
            !f.matches(&entry(80, Some(PortState::Open), Some(("ssh", 0.9)))),
            "a filter is a conjunction; matching the state alone is not enough"
        );
    }
}
