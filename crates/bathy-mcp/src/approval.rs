//! The human-approval gate, and why it is an authorization boundary.
//!
//! A scan wider than the server's configured threshold does not begin. It
//! answers with a Multi Round-Trip Request result -- `resultType:
//! "input_required"` carrying an embedded `elicitation/create` -- and the
//! client is expected to put the question to a human, then retry the same
//! call with the answer and the server's opaque `requestState` echoed back.
//!
//! # `requestState` is attacker-controlled
//!
//! It round-trips through the client, so on the retry it is untrusted input
//! that happens to have originated here. A forgeable one is a **scope
//! bypass**: a caller hands back a blob claiming a human approved a scan no
//! human ever saw. That is the same class of defect as an unconsulted scope
//! check, and it is why this module exists as a type with one redemption
//! path rather than as a few lines inside the `scan.start` handler.
//!
//! Four properties, each of which is a separate way in:
//!
//! 1. **Integrity.** The blob is sealed with HMAC-SHA256 under a key that
//!    never leaves this process. A flipped byte fails to open.
//! 2. **Binding.** The seal's associated data carries the principal it was
//!    issued to *and* a digest of the arguments it was issued for. An
//!    approval for a `/24` cannot be replayed against a `/8`, and one issued
//!    to caller A cannot be redeemed by caller B. The binding is
//!    fail-closed: opening without it fails.
//! 3. **Expiry.** A time-to-live is sealed into the blob. A human's approval
//!    of a scan is an approval of *that* scan, now, not a standing grant.
//! 4. **Single use.** The seal cannot provide this -- a copy of a valid blob
//!    is a valid blob -- so redemption records the nonce and refuses a
//!    second presentation. This is the one property that has to be enforced
//!    here rather than by the codec.
//!
//! Every rejection returns before a task record is created and before the
//! scheduler is constructed, so no rejected path emits a packet.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bathy_types::ids::Digest;
use rmcp::model::{
    ElicitRequest, ElicitRequestParams, ElicitationSchema, InputRequest, InputRequiredResult,
    InputRequests, InputResponses,
};
use rmcp::model::{RequestStateCodec, SealOptions};
use serde::{Deserialize, Serialize};

/// The key in the `inputRequests` map, and the key the client's answer comes
/// back under in `inputResponses`.
pub const APPROVAL_KEY: &str = "approval";

/// Domain separation for the binding, so a blob sealed for this purpose can
/// never be opened as one sealed for another.
const BINDING_DOMAIN: &str = "bathy/mcp/scan.start/approval/v1";

/// What a caller is when it declined to say who it is.
///
/// On stdio there is no authenticated principal: the client is the process
/// that launched this one, and `clientInfo` is self-asserted. Binding to it
/// is therefore defence in depth rather than authentication -- the isolation
/// that actually holds is that one server process serves one client. The
/// binding still does real work: it stops a blob from being carried between
/// two clients of a shared remote deployment, which is the arrangement a
/// later transport would create.
pub const UNIDENTIFIED_PRINCIPAL: &str = "\u{0}unidentified";

/// The sealed payload. Never trusted until it has been opened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingApproval {
    /// Unique per issuance. Uniqueness, not unpredictability, is what is
    /// required: forgery is prevented by the seal, and this exists only so a
    /// redeemed blob can be recognised on a second presentation.
    pub nonce: u64,
    /// The plan the approval was issued for, restated so a redeemed approval
    /// can be checked against the plan the retry actually produced.
    pub plan_hash: String,
    pub estimated_targets: u64,
    pub threshold: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalError {
    /// The blob was forged, tampered with, issued to a different principal,
    /// or issued for different arguments. These are one error on purpose:
    /// distinguishing them tells an attacker which half to vary.
    Unverifiable,
    Expired,
    /// A blob that opened, but had already been redeemed.
    AlreadyUsed,
    /// The blob opened and was fresh, but the retry's plan is not the plan a
    /// human was shown.
    PlanChanged,
    /// The human said no, or the client returned something that is not an
    /// acceptance.
    Declined,
}

impl ApprovalError {
    /// The stable code an agent branches on.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unverifiable => "approval_unverifiable",
            Self::Expired => "approval_expired",
            Self::AlreadyUsed => "approval_already_used",
            Self::PlanChanged => "approval_plan_changed",
            Self::Declined => "approval_declined",
        }
    }

    pub fn detail(&self) -> &'static str {
        match self {
            Self::Unverifiable => {
                "the approval token did not verify against this server, this caller and \
                 these arguments; nothing was started and no packet was sent"
            }
            Self::Expired => {
                "the approval token has expired; ask again, so a human approves the scan \
                 that is about to run"
            }
            Self::AlreadyUsed => {
                "the approval token has already been redeemed; an approval authorizes one \
                 scan, not a standing grant"
            }
            Self::PlanChanged => {
                "the request no longer produces the plan this approval was issued for"
            }
            Self::Declined => "the approval was not granted",
        }
    }
}

/// Issues and redeems approval tokens for one server process.
pub struct ApprovalGate {
    codec: RequestStateCodec,
    ttl: Duration,
    /// A scan whose expanded target count exceeds this needs a human.
    threshold_targets: u64,
    /// Nonces already redeemed, with the moment they can be forgotten.
    /// Bounded by the time-to-live: an entry is dropped once no token
    /// carrying it could still open.
    redeemed: Mutex<HashMap<u64, u64>>,
    counter: AtomicU64,
}

impl ApprovalGate {
    pub fn new(signing_key: Vec<u8>, threshold_targets: u64, ttl: Duration) -> Self {
        Self {
            codec: RequestStateCodec::new(signing_key),
            ttl,
            threshold_targets,
            redeemed: Mutex::new(HashMap::new()),
            counter: AtomicU64::new(0),
        }
    }

    pub fn threshold_targets(&self) -> u64 {
        self.threshold_targets
    }

    /// Whether a scan of this size needs a human before it starts.
    pub fn requires_approval(&self, estimated_targets: u64) -> bool {
        estimated_targets > self.threshold_targets
    }

    /// The bytes a token is bound to. Fail-closed: redemption supplies the
    /// same bytes or the token does not open.
    fn binding(principal: &str, arguments_digest: &Digest) -> Vec<u8> {
        format!("{BINDING_DOMAIN}|principal={principal}|arguments={arguments_digest}").into_bytes()
    }

    /// Mint the result that asks a human, and the sealed state that lets the
    /// retry be believed.
    pub fn challenge(
        &self,
        principal: &str,
        arguments_digest: &Digest,
        plan_hash: &str,
        estimated_targets: u64,
        message: String,
    ) -> Result<InputRequiredResult, String> {
        let pending = PendingApproval {
            nonce: self.counter.fetch_add(1, Ordering::SeqCst),
            plan_hash: plan_hash.to_string(),
            estimated_targets,
            threshold: self.threshold_targets,
        };
        let binding = Self::binding(principal, arguments_digest);
        let sealed = self
            .codec
            .seal_json_with(
                &pending,
                &SealOptions::new().associated_data(&binding).ttl(self.ttl),
            )
            .map_err(|e| e.to_string())?;

        let schema: ElicitationSchema = ElicitationSchema::builder()
            .required_bool("approved")
            .optional_string("reason")
            .build()
            .map_err(|e| e.to_string())?;

        let mut requests = InputRequests::new();
        requests.insert(
            APPROVAL_KEY.to_string(),
            InputRequest::Elicitation(ElicitRequest::new(
                ElicitRequestParams::FormElicitationParams {
                    meta: None,
                    message,
                    requested_schema: schema,
                },
            )),
        );
        Ok(InputRequiredResult::new(Some(requests), Some(sealed)))
    }

    /// Verify a returned token and the answer that came with it.
    ///
    /// Returns `Ok` only when the token verifies against this key, this
    /// principal and these arguments, has not expired, has not been redeemed
    /// before, names the plan the retry actually produced, and is
    /// accompanied by an acceptance. Every other path is an error, and the
    /// caller must not start anything on any of them.
    pub fn redeem(
        &self,
        request_state: Option<&str>,
        responses: Option<&InputResponses>,
        principal: &str,
        arguments_digest: &Digest,
        plan_hash: &str,
    ) -> Result<PendingApproval, ApprovalError> {
        let sealed = request_state.ok_or(ApprovalError::Unverifiable)?;
        let binding = Self::binding(principal, arguments_digest);
        let pending: PendingApproval = self
            .codec
            .open_json_with(sealed, &binding)
            .map_err(|e| match e {
                rmcp::model::RequestStateError::Expired => ApprovalError::Expired,
                _ => ApprovalError::Unverifiable,
            })?;

        // Single use, enforced before the answer is even read: a replayed
        // token is refused whether or not it carries a valid acceptance.
        self.consume(pending.nonce)?;

        if pending.plan_hash != plan_hash {
            return Err(ApprovalError::PlanChanged);
        }
        if !granted(responses) {
            return Err(ApprovalError::Declined);
        }
        Ok(pending)
    }

    /// Record a nonce, refusing one already present. Also drops entries no
    /// live token could still carry, so the set cannot grow without bound.
    fn consume(&self, nonce: u64) -> Result<(), ApprovalError> {
        let now = now_ms();
        let forget_at = now.saturating_add(self.ttl.as_millis().min(u128::from(u64::MAX)) as u64);
        let mut redeemed = self.redeemed.lock().expect("approval nonce set");
        redeemed.retain(|_, expiry| *expiry > now);
        if redeemed.insert(nonce, forget_at).is_some() {
            return Err(ApprovalError::AlreadyUsed);
        }
        Ok(())
    }
}

/// Whether the client's answer is an acceptance.
///
/// Anything that is not an explicit accept carrying `approved: true` is a
/// refusal. A missing entry, a decline, a cancel, or an accept whose content
/// says `false` all mean no human said yes.
fn granted(responses: Option<&InputResponses>) -> bool {
    let Some(responses) = responses else {
        return false;
    };
    let Some(answer) = responses.get(APPROVAL_KEY) else {
        return false;
    };
    answer["action"] == "accept" && answer["content"]["approved"] == serde_json::Value::Bool(true)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"a-test-signing-key-of-decent-len";
    const PLAN: &str = "blake3:0000000000000000000000000000000000000000000000000000000000000000";

    fn gate() -> ApprovalGate {
        ApprovalGate::new(KEY.to_vec(), 64, Duration::from_secs(600))
    }

    fn digest(s: &str) -> Digest {
        Digest::of_bytes(s.as_bytes())
    }

    fn accepted() -> InputResponses {
        let mut m = InputResponses::new();
        m.insert(
            APPROVAL_KEY.into(),
            serde_json::json!({ "action": "accept", "content": { "approved": true } }),
        );
        m
    }

    fn issue(gate: &ApprovalGate, principal: &str, args: &Digest) -> String {
        gate.challenge(principal, args, PLAN, 256, "approve?".into())
            .unwrap()
            .request_state
            .expect("a challenge always carries state")
    }

    #[test]
    fn the_threshold_is_a_strict_ceiling_not_a_target() {
        let g = gate();
        assert!(!g.requires_approval(64), "at the threshold is still allowed");
        assert!(g.requires_approval(65));
    }

    #[test]
    fn a_token_issued_here_and_answered_yes_redeems_once() {
        let g = gate();
        let args = digest("args");
        let state = issue(&g, "alice", &args);
        assert_eq!(
            g.redeem(Some(&state), Some(&accepted()), "alice", &args, PLAN)
                .unwrap()
                .estimated_targets,
            256
        );
    }

    #[test]
    fn a_forged_token_does_not_open() {
        let g = gate();
        let args = digest("args");
        let state = issue(&g, "alice", &args);

        // Flip one character of the sealed body. `rs1.<body>.<tag>`.
        let mut parts: Vec<String> = state.split('.').map(str::to_string).collect();
        let body = &mut parts[1];
        let first = body.remove(0);
        body.insert(0, if first == 'A' { 'B' } else { 'A' });
        let forged = parts.join(".");
        assert_ne!(forged, state, "the fixture must actually differ");

        assert_eq!(
            g.redeem(Some(&forged), Some(&accepted()), "alice", &args, PLAN),
            Err(ApprovalError::Unverifiable)
        );
    }

    #[test]
    fn a_token_sealed_under_a_different_key_does_not_open() {
        let issuer = ApprovalGate::new(b"a-completely-different-key-here!!".to_vec(), 64, Duration::from_secs(600));
        let args = digest("args");
        let state = issue(&issuer, "alice", &args);
        assert_eq!(
            gate().redeem(Some(&state), Some(&accepted()), "alice", &args, PLAN),
            Err(ApprovalError::Unverifiable)
        );
    }

    #[test]
    fn a_token_is_single_use() {
        let g = gate();
        let args = digest("args");
        let state = issue(&g, "alice", &args);
        assert!(
            g.redeem(Some(&state), Some(&accepted()), "alice", &args, PLAN)
                .is_ok()
        );
        assert_eq!(
            g.redeem(Some(&state), Some(&accepted()), "alice", &args, PLAN),
            Err(ApprovalError::AlreadyUsed),
            "a copy of a valid token is a valid token; only the server can refuse it"
        );
    }

    #[test]
    fn a_token_issued_to_one_principal_is_not_redeemable_by_another() {
        let g = gate();
        let args = digest("args");
        let state = issue(&g, "alice", &args);
        assert_eq!(
            g.redeem(Some(&state), Some(&accepted()), "mallory", &args, PLAN),
            Err(ApprovalError::Unverifiable)
        );
    }

    #[test]
    fn a_token_issued_for_one_request_is_not_redeemable_for_another() {
        let g = gate();
        let state = issue(&g, "alice", &digest("scan a /24"));
        assert_eq!(
            g.redeem(
                Some(&state),
                Some(&accepted()),
                "alice",
                &digest("scan a /8"),
                PLAN
            ),
            Err(ApprovalError::Unverifiable),
            "an approval of one scan must not authorize a wider one"
        );
    }

    #[test]
    fn an_expired_token_is_refused_and_says_so() {
        let g = ApprovalGate::new(KEY.to_vec(), 64, Duration::from_millis(1));
        let args = digest("args");
        let state = issue(&g, "alice", &args);
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(
            g.redeem(Some(&state), Some(&accepted()), "alice", &args, PLAN),
            Err(ApprovalError::Expired)
        );
    }

    #[test]
    fn a_token_whose_plan_no_longer_matches_is_refused() {
        let g = gate();
        let args = digest("args");
        let state = issue(&g, "alice", &args);
        let other = "blake3:1111111111111111111111111111111111111111111111111111111111111111";
        assert_eq!(
            g.redeem(Some(&state), Some(&accepted()), "alice", &args, other),
            Err(ApprovalError::PlanChanged)
        );
    }

    #[test]
    fn no_token_at_all_is_refused_rather_than_treated_as_absent_approval() {
        let g = gate();
        assert_eq!(
            g.redeem(None, Some(&accepted()), "alice", &digest("args"), PLAN),
            Err(ApprovalError::Unverifiable)
        );
    }

    #[test]
    fn a_valid_token_without_an_acceptance_is_refused() {
        let g = gate();
        let args = digest("args");

        for (name, responses) in [
            ("no responses at all", None),
            ("empty map", Some(InputResponses::new())),
            (
                "declined",
                Some(InputResponses::from_iter([(
                    APPROVAL_KEY.to_string(),
                    serde_json::json!({ "action": "decline" }),
                )])),
            ),
            (
                "cancelled",
                Some(InputResponses::from_iter([(
                    APPROVAL_KEY.to_string(),
                    serde_json::json!({ "action": "cancel" }),
                )])),
            ),
            (
                "accepted but the answer was no",
                Some(InputResponses::from_iter([(
                    APPROVAL_KEY.to_string(),
                    serde_json::json!({ "action": "accept", "content": { "approved": false } }),
                )])),
            ),
            (
                "accepted with no content",
                Some(InputResponses::from_iter([(
                    APPROVAL_KEY.to_string(),
                    serde_json::json!({ "action": "accept" }),
                )])),
            ),
            (
                "an answer under some other key",
                Some(InputResponses::from_iter([(
                    "something-else".to_string(),
                    serde_json::json!({ "action": "accept", "content": { "approved": true } }),
                )])),
            ),
        ] {
            let state = issue(&g, "alice", &args);
            assert_eq!(
                g.redeem(Some(&state), responses.as_ref(), "alice", &args, PLAN),
                Err(ApprovalError::Declined),
                "{name} must not count as approval"
            );
        }
    }

    #[test]
    fn a_replayed_token_is_refused_even_when_the_answer_is_valid() {
        // The nonce is consumed before the answer is read, so a caller
        // cannot probe for a live token by replaying it with a decline.
        let g = gate();
        let args = digest("args");
        let state = issue(&g, "alice", &args);
        let declined = InputResponses::from_iter([(
            APPROVAL_KEY.to_string(),
            serde_json::json!({ "action": "decline" }),
        )]);
        assert_eq!(
            g.redeem(Some(&state), Some(&declined), "alice", &args, PLAN),
            Err(ApprovalError::Declined)
        );
        assert_eq!(
            g.redeem(Some(&state), Some(&accepted()), "alice", &args, PLAN),
            Err(ApprovalError::AlreadyUsed),
            "a refused presentation still spends the token"
        );
    }

    #[test]
    fn the_challenge_carries_an_elicitation_and_a_state_blob() {
        let g = gate();
        let result = g
            .challenge("alice", &digest("args"), PLAN, 256, "approve?".into())
            .unwrap();
        let rendered = serde_json::to_value(&result).unwrap();
        assert_eq!(rendered["resultType"], "input_required");
        assert_eq!(
            rendered["inputRequests"][APPROVAL_KEY]["method"],
            "elicitation/create"
        );
        assert!(
            rendered["requestState"].as_str().is_some_and(|s| !s.is_empty()),
            "{rendered:#}"
        );
    }

    #[test]
    fn the_sealed_state_does_not_leak_the_key_or_carry_a_secret() {
        // The seal signs, it does not encrypt. Nothing secret may go in it,
        // and this asserts what is actually in there.
        let g = gate();
        let state = issue(&g, "alice", &digest("args"));
        assert!(!state.contains(std::str::from_utf8(KEY).unwrap()));
    }

    #[test]
    fn two_challenges_carry_different_nonces_so_neither_spends_the_other() {
        let g = gate();
        let args = digest("args");
        let a = issue(&g, "alice", &args);
        let b = issue(&g, "alice", &args);
        assert!(
            g.redeem(Some(&a), Some(&accepted()), "alice", &args, PLAN)
                .is_ok()
        );
        assert!(
            g.redeem(Some(&b), Some(&accepted()), "alice", &args, PLAN)
                .is_ok(),
            "redeeming one approval must not invalidate a second, independent one"
        );
    }
}
