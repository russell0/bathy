#![forbid(unsafe_code)]

pub mod canonical;
pub mod confidence;
pub mod event;
pub mod ids;
pub mod nonempty;
pub mod request;
pub mod schema;
pub mod scope_dto;
pub mod task;

pub use canonical::{CanonicalError, canonical_json, plan_digest};
pub use confidence::{Confidence, ConfidenceError};
pub use event::{Endpoint, Event, EventBody, Observation, PortState, Target, Transport};
pub use ids::{Digest, EventId, IdError, ScanId, ScopeId};
pub use nonempty::{EmptyError, NonEmpty};
pub use request::{
    Budgets, EvidenceLevel, Objective, PortPreset, PortSelection, ScanRequest, ServiceDetection,
};
pub use scope_dto::ScopeManifestDto;
pub use task::{PolicyDecisionTag, TaskHandle, TaskStatus};
