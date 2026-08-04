//! Exit codes, and the one place their meanings are written down.
//!
//! An agent shelling out to `bathy` branches on the process exit status
//! before it parses a byte of output, so these five numbers are a public
//! contract in exactly the way a wire format is. [`ExitCode::TABLE`] is the
//! single source both `--help` (AC-5.11) and the error mapping below are
//! rendered from -- a table nothing returns is documentation, not
//! behaviour, and two copies of it would drift.

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitCode {
    /// The command did what was asked.
    Success = 0,
    /// Anything that went wrong on our side or the caller's: a usage error,
    /// an unparseable argument, a missing scan, an I/O or engine failure.
    Operational = 1,
    /// The scope manifest refused this scan. **No packet was emitted.** This
    /// is deliberately distinct from `Operational`: a denial is a correct,
    /// expected answer from an authorization system, and an agent that
    /// retries it unchanged will be refused again.
    PolicyDenied = 2,
    /// The scan stopped because it reached its packet or runtime ceiling.
    /// Partial results are on disk and the scan is resumable.
    Exhausted = 3,
    /// The idempotency key was already used for a *different* plan. Nothing
    /// was started; the existing scan was left alone.
    IdempotencyConflict = 4,
}

impl ExitCode {
    /// The documented meanings, rendered verbatim into `--help`.
    ///
    /// Deliberately a `const` array rather than prose in a doc attribute:
    /// `every_documented_exit_code_is_produced_by_a_real_invocation` walks
    /// it, so a code added here without an invocation that produces it
    /// fails the suite rather than shipping as a promise.
    pub const TABLE: &'static [(ExitCode, &'static str)] = &[
        (ExitCode::Success, "success"),
        (
            ExitCode::Operational,
            "operational error: bad usage, bad argument, missing scan, I/O or engine failure",
        ),
        (
            ExitCode::PolicyDenied,
            "policy denial: the scope manifest refused this scan; no packet was emitted",
        ),
        (
            ExitCode::Exhausted,
            "budget or time exhaustion: the scan stopped at a ceiling and is resumable",
        ),
        (
            ExitCode::IdempotencyConflict,
            "idempotency conflict: this key was already used for a different plan",
        ),
    ];

    pub fn code(self) -> i32 {
        self as i32
    }

    /// The `--help` section. One place, so the table and the behaviour
    /// cannot disagree.
    pub fn help_section() -> String {
        let mut s = String::from("Exit codes:\n");
        for (code, meaning) in Self::TABLE {
            s.push_str(&format!("  {}  {meaning}\n", code.code()));
        }
        s
    }
}

impl fmt::Display for ExitCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code())
    }
}

/// Everything that can stop a command, carrying the exit code it maps to
/// and a stable machine-readable `error` tag alongside the human detail.
#[derive(Debug)]
pub enum CliError {
    /// See [`ExitCode::Operational`].
    Operational { error: String, detail: String },
    /// See [`ExitCode::PolicyDenied`]. `reason_code` is one of
    /// `bathy_types::DenyReason`'s four stable codes.
    Denied {
        reason_code: &'static str,
        detail: String,
    },
    /// See [`ExitCode::IdempotencyConflict`].
    Conflict { detail: String },
}

// There is deliberately no `CliError` variant for [`ExitCode::Exhausted`].
// A scan that stops at its packet or runtime ceiling has *succeeded* at
// producing partial results: it emits its ordinary run summary on stdout and
// the exit code alone carries "there is more to do." Routing it through the
// error channel would put the summary on stderr and lose it. See
// `commands::scan::exit_for`, which is where 3 is actually produced.

impl CliError {
    pub fn operational(error: impl Into<String>, detail: impl fmt::Display) -> Self {
        Self::Operational {
            error: error.into(),
            detail: detail.to_string(),
        }
    }

    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::Operational { .. } => ExitCode::Operational,
            Self::Denied { .. } => ExitCode::PolicyDenied,
            Self::Conflict { .. } => ExitCode::IdempotencyConflict,
        }
    }

    /// The machine-readable failure document. Emitted on **stdout** under
    /// `--json`, because under `--json` stdout is the answer channel and a
    /// refusal is an answer; the human sentence goes to stderr regardless.
    pub fn to_json(&self) -> serde_json::Value {
        let mut v = match self {
            Self::Operational { error, detail } => serde_json::json!({
                "error": error,
                "detail": detail,
            }),
            Self::Denied {
                reason_code,
                detail,
            } => serde_json::json!({
                "error": "policy_denied",
                "policy_decision": "denied",
                "reason_code": reason_code,
                "detail": detail,
            }),
            Self::Conflict { detail } => serde_json::json!({
                "error": "idempotency_conflict",
                "detail": detail,
            }),
        };
        v["exit_code"] = serde_json::json!(self.exit_code().code());
        v
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Operational { error, detail } => write!(f, "{error}: {detail}"),
            Self::Denied {
                reason_code,
                detail,
            } => write!(f, "denied ({reason_code}): {detail}"),
            Self::Conflict { detail } => write!(f, "idempotency conflict: {detail}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_help_section_names_every_code_in_the_table() {
        let help = ExitCode::help_section();
        for (code, meaning) in ExitCode::TABLE {
            assert!(help.contains(&code.code().to_string()), "{help}");
            assert!(help.contains(meaning), "{help}");
        }
    }

    #[test]
    fn the_table_covers_zero_through_four_with_no_repeats() {
        let codes: Vec<i32> = ExitCode::TABLE.iter().map(|(c, _)| c.code()).collect();
        assert_eq!(codes, vec![0, 1, 2, 3, 4], "{codes:?}");
    }

    #[test]
    fn every_error_carries_its_own_exit_code_into_its_json() {
        for err in [
            CliError::operational("bad_argument", "x"),
            CliError::Denied {
                reason_code: "target_out_of_scope",
                detail: "x".into(),
            },
            CliError::Conflict { detail: "x".into() },
        ] {
            let v = err.to_json();
            assert_eq!(v["exit_code"], err.exit_code().code());
            assert!(v["error"].is_string(), "{v}");
        }
    }
}
