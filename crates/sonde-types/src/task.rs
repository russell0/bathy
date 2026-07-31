use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{Digest, ScanId};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Pending,
    Running,
    Paused,
    Completed,
    Cancelled,
    Failed,
    /// Refused by policy. Terminal, and carries a `policy.denied` event.
    Denied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecisionTag {
    Approved,
    Denied,
}

/// Returned immediately by `scan.start`. Never blocks on scan completion.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskHandle {
    pub task_id: ScanId,
    pub plan_hash: Digest,
    pub policy_decision: PolicyDecisionTag,
    pub estimated_targets: u64,
    pub status: TaskStatus,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_example() -> String {
        format!(
            r#"{{
              "task_id": "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV",
              "plan_hash": "blake3:{}",
              "policy_decision": "approved",
              "estimated_targets": 256,
              "status": "pending"
            }}"#,
            "0".repeat(64)
        )
    }

    #[test]
    fn malformed_plan_hash_is_rejected() {
        // Proves `plan_hash` really deserializes through `Digest`'s own
        // strict parser (see `ids.rs`), not just through `String`: a
        // too-short hex body must fail here the same way it fails
        // `Digest::from_str` directly.
        let json = valid_example().replace(&"0".repeat(64), &"0".repeat(63));
        assert!(serde_json::from_str::<TaskHandle>(&json).is_err());
    }

    #[test]
    fn task_handle_round_trips_through_json() {
        let json = valid_example();
        let handle: TaskHandle = serde_json::from_str(&json).unwrap();
        assert_eq!(handle.estimated_targets, 256);
        assert_eq!(handle.policy_decision, PolicyDecisionTag::Approved);
        assert_eq!(handle.status, TaskStatus::Pending);

        let back = serde_json::to_value(&handle).unwrap();
        let round_tripped: TaskHandle = serde_json::from_value(back).unwrap();
        assert_eq!(round_tripped, handle);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let json = valid_example().replace(
            "\"estimated_targets\"",
            "\"stealth_mode\": true, \"estimated_targets\"",
        );
        assert!(serde_json::from_str::<TaskHandle>(&json).is_err());
    }

    #[test]
    fn task_status_and_policy_decision_serialize_snake_case() {
        assert_eq!(
            serde_json::to_string(&TaskStatus::Denied).unwrap(),
            "\"denied\""
        );
        assert_eq!(
            serde_json::to_string(&TaskStatus::Cancelled).unwrap(),
            "\"cancelled\""
        );
        assert_eq!(
            serde_json::to_string(&PolicyDecisionTag::Denied).unwrap(),
            "\"denied\""
        );
        assert_eq!(
            serde_json::to_string(&PolicyDecisionTag::Approved).unwrap(),
            "\"approved\""
        );
    }

    #[test]
    fn every_task_status_variant_round_trips() {
        for (status, wire) in [
            (TaskStatus::Pending, "\"pending\""),
            (TaskStatus::Running, "\"running\""),
            (TaskStatus::Paused, "\"paused\""),
            (TaskStatus::Completed, "\"completed\""),
            (TaskStatus::Cancelled, "\"cancelled\""),
            (TaskStatus::Failed, "\"failed\""),
            (TaskStatus::Denied, "\"denied\""),
        ] {
            assert_eq!(serde_json::to_string(&status).unwrap(), wire, "{status:?}");
            let back: TaskStatus = serde_json::from_str(wire).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn task_handle_schema_requires_every_field_and_denies_additional_properties() {
        let schema = schemars::schema_for!(TaskHandle);
        let value = serde_json::to_value(&schema).unwrap();
        let required: Vec<&str> = value["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        for field in [
            "task_id",
            "plan_hash",
            "policy_decision",
            "estimated_targets",
            "status",
        ] {
            assert!(required.contains(&field), "required was {required:?}");
        }
        assert_eq!(
            value.get("additionalProperties").and_then(|v| v.as_bool()),
            Some(false),
            "schema was {value:#}"
        );
    }
}
