//! What a refusal looks like to an agent.
//!
//! # Why a tool result and not a protocol error
//!
//! A JSON-RPC error is for a request that cannot be routed at all. Clients
//! render one opaquely, so the caller sees "the tool failed" and not the
//! reason. Everything an agent could act on -- an unknown scan, a digest that
//! names nothing, a manifest that will not load, a cursor that does not parse
//! -- is therefore a tool result carrying a stable code, marked as an error
//! so the client knows it did not succeed.
//!
//! # Why these particular codes
//!
//! They are the codes the command-line surface already publishes for the same
//! conditions. An operator who reproduces an agent's refusal from a shell has
//! to get the same answer, or the claim that one surface can do nothing the
//! other cannot is only true of the successes.

use bathy_evidence::{EvidenceError, LogError};
use bathy_scope::ManifestError;
use bathy_store::StoreError;
use rmcp::model::{CallToolResult, ContentBlock};
use serde::{Deserialize, Serialize};

/// A refusal an agent can branch on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolFailure {
    /// A stable identifier for what went wrong.
    pub error: String,
    /// One sentence for a human reading the transcript.
    pub detail: String,
}

impl ToolFailure {
    pub fn new(error: impl Into<String>, detail: impl std::fmt::Display) -> Self {
        Self {
            error: error.into(),
            detail: detail.to_string(),
        }
    }

    /// A failed `tools/call` result.
    ///
    /// The document goes in `content` as JSON text and **not** in
    /// `structuredContent`: a tool that declares an `outputSchema` promises
    /// that its structured result conforms to it, and a refusal does not have
    /// the shape of a success. Putting the failure in the structured slot
    /// would break that promise on exactly the path a client is least able to
    /// check.
    pub fn into_result(self) -> CallToolResult {
        let text = serde_json::to_string(&self).unwrap_or_else(|_| {
            format!(r#"{{"error":"{}","detail":"unserializable"}}"#, self.error)
        });
        CallToolResult::error(vec![ContentBlock::text(text)])
    }
}

pub type ToolResult<T> = Result<T, ToolFailure>;

/// A refusal on the `tools/call` path, which is one of two things.
///
/// Almost everything is a [`ToolFailure`] -- a successful JSON-RPC response
/// carrying an error document an agent can branch on, for the reasons above.
/// The exception is a condition the specification names a *protocol* error
/// for, where returning a tool result would be a second spelling of an answer
/// the protocol already defines. There is exactly one such condition here:
/// `-32021`, the client that lacks a capability the request cannot be
/// processed without (see [`crate::server::BathyMcpServer::start`]).
///
/// It is an enum rather than a `ToolFailure` field so the two cannot be
/// confused at a call site: `?` on a `ToolFailure` still produces the tool
/// result it always did, and reaching the protocol arm takes naming it.
#[derive(Debug)]
pub enum Refusal {
    /// An answer, marked as an error, with a stable code in its document.
    Tool(ToolFailure),
    /// A JSON-RPC error, because the specification requires one here.
    Protocol(Box<rmcp::ErrorData>),
}

impl From<ToolFailure> for Refusal {
    fn from(failure: ToolFailure) -> Self {
        Self::Tool(failure)
    }
}

impl From<rmcp::ErrorData> for Refusal {
    fn from(error: rmcp::ErrorData) -> Self {
        Self::Protocol(Box::new(error))
    }
}

pub fn manifest_error(path: &str, e: ManifestError) -> ToolFailure {
    ToolFailure::new("scope_invalid", format!("{path}: {e}"))
}

pub fn unreadable_manifest(path: &str, e: std::io::Error) -> ToolFailure {
    ToolFailure::new("scope_unreadable", format!("{path}: {e}"))
}

pub fn store_error(e: StoreError) -> ToolFailure {
    match e {
        StoreError::IdempotencyConflict { .. } => ToolFailure::new("idempotency_conflict", e),
        other => ToolFailure::new("store_unavailable", other),
    }
}

pub fn log_error(e: LogError) -> ToolFailure {
    ToolFailure::new("log_unreadable", e)
}

/// `EventLogReader::open` failed. Only an absent file is `no_such_scan_log`.
///
/// `open` validates every record on the way in, so a log that *exists* but
/// holds a record this build cannot read fails here too -- and it used to be
/// reported as `no_such_scan_log`, telling an agent branching on the code
/// that the scan is gone when the truth was that the log outlived a shape
/// change. The `detail` was accurate throughout and the code was not; an
/// agent branches on the code. They now agree: a log that is there and
/// unreadable is `log_unreadable`, the same code `read_from` already uses for
/// the same condition.
pub fn no_such_log(e: LogError) -> ToolFailure {
    match &e {
        LogError::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound => {
            ToolFailure::new("no_such_scan_log", e)
        }
        _ => log_error(e),
    }
}

pub fn evidence_error(e: EvidenceError) -> ToolFailure {
    match e {
        EvidenceError::NotFound(_) => ToolFailure::new("no_such_evidence", e),
        EvidenceError::Corrupt { .. } => ToolFailure::new("evidence_corrupt", e),
        other => ToolFailure::new("evidence_unavailable", other),
    }
}

pub fn no_such_scan(scan_id: impl std::fmt::Display) -> ToolFailure {
    ToolFailure::new("no_such_scan", format!("no scan {scan_id}"))
}

/// Arguments that are absent, or are not the shape the input schema declares.
pub fn bad_arguments(e: impl std::fmt::Display) -> ToolFailure {
    ToolFailure::new("bad_arguments", e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failure_result_is_marked_as_one_and_carries_a_parseable_document() {
        let result = ToolFailure::new("no_such_scan", "no scan scan_X").into_result();
        assert_eq!(result.is_error, Some(true));
        let text = result.content[0].as_text().unwrap().text.clone();
        let parsed: ToolFailure =
            serde_json::from_str(&text).expect("a failure is machine-readable");
        assert_eq!(parsed.error, "no_such_scan");
    }

    #[test]
    fn a_failure_never_occupies_the_structured_slot() {
        // The structured slot is promised to conform to the tool's declared
        // output schema. A refusal does not, so it must not go there.
        let result = ToolFailure::new("bad_arguments", "x").into_result();
        assert!(
            result.structured_content.is_none(),
            "a refusal in structuredContent would break the outputSchema promise"
        );
    }

    #[test]
    fn a_log_that_exists_but_will_not_read_is_not_reported_as_a_missing_log() {
        // The two conditions both arrive through `EventLogReader::open`,
        // because `open` validates every record. An agent branches on the
        // code, so the code has to tell them apart: "the scan is gone" and
        // "the scan is there and this build cannot read it" have completely
        // different remediations.
        let absent = LogError::Io {
            path: "/state/scan_x.jsonl".into(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "no such file"),
        };
        assert_eq!(no_such_log(absent).error, "no_such_scan_log");

        let unreadable = LogError::Malformed {
            path: "/state/scan_x.jsonl".into(),
            line: 3,
            detail: "missing field `rule_id`".into(),
        };
        let failure = no_such_log(unreadable);
        assert_eq!(
            failure.error, "log_unreadable",
            "a log that is plainly present must not be reported as absent"
        );
        assert!(
            failure.detail.contains("line 3"),
            "and the detail must still say which record, got: {}",
            failure.detail
        );

        // A permission error is also not absence.
        let denied = LogError::Io {
            path: "/state/scan_x.jsonl".into(),
            source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
        };
        assert_eq!(no_such_log(denied).error, "log_unreadable");
    }

    #[test]
    fn an_idempotency_conflict_is_the_only_store_failure_that_is_not_availability() {
        let conflict = StoreError::IdempotencyConflict {
            key: "k".into(),
            existing: format!("blake3:{}", "0".repeat(64)).parse().unwrap(),
            incoming: format!("blake3:{}", "1".repeat(64)).parse().unwrap(),
        };
        assert_eq!(store_error(conflict).error, "idempotency_conflict");
        assert_eq!(
            store_error(StoreError::NotFound(
                "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap()
            ))
            .error,
            "store_unavailable"
        );
    }

    #[test]
    fn a_missing_blob_and_a_corrupt_one_are_different_answers() {
        let digest = format!("blake3:{}", "0".repeat(64)).parse().unwrap();
        assert_eq!(
            evidence_error(EvidenceError::NotFound(digest)).error,
            "no_such_evidence"
        );
        assert_eq!(
            evidence_error(EvidenceError::Corrupt { digest }).error,
            "evidence_corrupt",
            "bytes that do not hash to the digest that named them are not merely absent"
        );
    }
}
