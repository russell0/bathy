//! The first request, answered rather than fatal.
//!
//! # What the SDK does, and why this exists
//!
//! Revision `2026-07-28` has no handshake: a client sends whatever request it
//! wants first, carrying the protocol version and its capabilities in that
//! request's `_meta`. `rmcp` implements that by peeking at the first message
//! and deciding, once, whether the connection is Modern or Legacy
//! (`rmcp::service::server::serve_server_with_ct_inner`). The decision is
//! `RequestMetaObject::missing_required_keys` -- `_meta` must carry
//! `io.modelcontextprotocol/protocolVersion` **and**
//! `io.modelcontextprotocol/clientCapabilities` -- and when it comes out
//! `false` the SDK returns `ServerInitializeError::ExpectedInitializeRequest`
//! from `serve` itself.
//!
//! That is fatal to the process, not to the request. `bathy serve mcp` exits,
//! standard output carries **nothing** -- no error object, no `-32022`, a
//! closed pipe -- and any scan running detached in that process dies with it.
//! It is reachable from a request a client can send by accident: an absent
//! `_meta`, a `_meta` that names only the version, or a version this server
//! does not implement named on its own. The last one is the sharpest, because
//! `-32022` with `data.supported` is precisely the answer the specification
//! requires there and precisely the answer the client does not get.
//!
//! # What this does
//!
//! Sits between the standard-input/output transport and the SDK, and applies
//! the SDK's own inline-lifecycle validation to the opening request. A request
//! that cannot open the lifecycle is answered with a JSON-RPC error and the
//! connection stays up; anything else is handed through untouched, and after
//! the lifecycle opens this type is a pass-through with a `bool` on it.
//!
//! **This is not a rule invented here.** Both halves are the SDK's:
//!
//! * The condition is [`RequestMetaObject::missing_required_keys`], called
//!   with the same protocol version the SDK calls it with, and the supported
//!   list comes from the server's own
//!   [`supported_protocol_versions`](rmcp::ServerHandler::supported_protocol_versions)
//!   rather than from a constant here.
//! * The errors are [`ErrorData::unsupported_protocol_version`] and
//!   [`ErrorData::invalid_params`], in the order and with the wording
//!   `rmcp::handler::server`'s `handle_request` uses for the *same* two
//!   conditions on every request after the first.
//!
//! `rmcp`'s own Streamable HTTP transport already does this -- see
//! `validate_request_protocol_version_meta` in
//! `rmcp::transport::streamable_http_server::tower`, which answers a bad
//! opener with an `invalid_params` JSON-RPC response and keeps serving. The
//! stdio path is the one that does not, so this supplies it there.
//!
//! Because that is the claim, it is not left as a claim: the protocol suite
//! asserts that every `_meta` shape gets the *same* answer as the opening
//! request and as a later one, so if this file and the SDK ever disagree the
//! test says so. See `crates/bathy/tests/mcp.rs`.
//!
//! Recorded as an SDK deviation in `docs/protocol-notes.md`, per AC-5.23.

use std::borrow::Cow;

use rmcp::model::{
    ClientJsonRpcMessage, ClientRequest, ErrorData, GetMeta, ProtocolVersion, RequestId,
    RequestMetaObject, ServerJsonRpcMessage,
};
use rmcp::service::RoleServer;
use rmcp::transport::Transport;

/// The revision that defines the inline lifecycle, and therefore the one whose
/// `_meta` contract an opening request is measured against -- even when the
/// request names an older application protocol version, which is the rule
/// `rmcp::handler::server` applies and the reason a bare unsupported version
/// is a `-32022` rather than silence.
const INLINE_LIFECYCLE_VERSION: ProtocolVersion = ProtocolVersion::V_2026_07_28;

/// What an opening message is, with respect to the lifecycle.
#[derive(Debug)]
pub(crate) enum Opener {
    /// Hand it to the SDK. The lifecycle is open from here on, and the SDK
    /// validates every later request itself.
    Opens,
    /// Hand it to the SDK, which answers it from inside its own pre-lifecycle
    /// loop and asks for another message. The lifecycle is *not* open
    /// afterwards, so the next message is classified again.
    Passes,
    /// Answer it here. The connection stays up.
    Refused(Box<ErrorData>, RequestId),
    /// Nothing to answer. A notification has no id by definition, and a
    /// response or an error names a request this server never sent; JSON-RPC
    /// has no reply for either, and the SDK's behaviour -- ending the process
    /// -- is the same defect in a quieter costume.
    Ignored,
}

/// Classify one message against the supported protocol versions.
///
/// Pure, so the table of shapes below is a unit test rather than a process.
pub(crate) fn classify(message: &ClientJsonRpcMessage, supported: &[ProtocolVersion]) -> Opener {
    let ClientJsonRpcMessage::Request(request) = message else {
        return Opener::Ignored;
    };
    match &request.request {
        // The Legacy handshake. Still legal to send, and the SDK's business.
        ClientRequest::InitializeRequest(_) => return Opener::Opens,
        // A base-protocol utility the specification permits before anything
        // else; the SDK answers it without opening the lifecycle.
        ClientRequest::PingRequest(_) => return Opener::Passes,
        _ => {}
    }

    let meta: &RequestMetaObject = request.request.get_meta();

    // Version first, exactly as `handle_request` orders it: a client that
    // names a version this server does not implement is told which ones it
    // does, and is told that whether or not the rest of `_meta` is complete.
    if let Some(requested) = meta.protocol_version()
        && !supported.contains(&requested)
    {
        return Opener::Refused(
            Box::new(ErrorData::unsupported_protocol_version(
                requested, supported,
            )),
            request.id.clone(),
        );
    }

    let missing = meta.missing_required_keys(&INLINE_LIFECYCLE_VERSION);
    if !missing.is_empty() {
        return Opener::Refused(
            Box::new(ErrorData::invalid_params(
                format!(
                    "request _meta is missing or has malformed required fields: {}",
                    missing.join(", ")
                ),
                None,
            )),
            request.id.clone(),
        );
    }

    Opener::Opens
}

/// A transport that answers an opening request the SDK would have died on.
pub struct AnswersTheOpener<T> {
    inner: T,
    supported: Cow<'static, [ProtocolVersion]>,
    open: bool,
}

impl<T> AnswersTheOpener<T> {
    /// `supported` is the server's own list, so the `-32022` this answers with
    /// cannot name a different set from the one the same server answers with
    /// one request later.
    pub fn new(inner: T, supported: Cow<'static, [ProtocolVersion]>) -> Self {
        Self {
            inner,
            supported,
            open: false,
        }
    }
}

impl<T> Transport<RoleServer> for AnswersTheOpener<T>
where
    T: Transport<RoleServer>,
{
    type Error = T::Error;

    fn send(
        &mut self,
        item: ServerJsonRpcMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        self.inner.send(item)
    }

    async fn receive(&mut self) -> Option<ClientJsonRpcMessage> {
        loop {
            let message = self.inner.receive().await?;
            if self.open {
                return Some(message);
            }
            match classify(&message, &self.supported) {
                Opener::Opens => {
                    self.open = true;
                    return Some(message);
                }
                Opener::Passes => return Some(message),
                Opener::Refused(error, id) => {
                    // A failure to write the refusal is a dead pipe, which is
                    // the SDK's `receive` returning `None` on the next turn.
                    // Nothing useful can be reported over a transport that
                    // will not carry a message.
                    let _ = self
                        .inner
                        .send(ServerJsonRpcMessage::error(*error, Some(id)))
                        .await;
                }
                Opener::Ignored => {}
            }
        }
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        self.inner.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::{ErrorCode, Implementation, InitializedNotification, JsonRpcVersion2_0};

    const SUPPORTED: [ProtocolVersion; 1] = [ProtocolVersion::V_2026_07_28];

    /// A `tools/list` whose `_meta` is exactly `meta`.
    fn opener(meta: serde_json::Value) -> ClientJsonRpcMessage {
        let params = if meta.is_null() {
            serde_json::json!({})
        } else {
            serde_json::json!({ "_meta": meta })
        };
        serde_json::from_value(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": params,
        }))
        .expect("a tools/list request parses")
    }

    fn version(v: &str) -> serde_json::Value {
        serde_json::json!({ "io.modelcontextprotocol/protocolVersion": v })
    }

    fn refusal(message: &ClientJsonRpcMessage) -> ErrorData {
        match classify(message, &SUPPORTED) {
            Opener::Refused(error, id) => {
                assert_eq!(id, RequestId::Number(1), "the refusal names the request");
                *error
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_complete_modern_meta_opens_the_lifecycle() {
        let mut meta = version("2026-07-28");
        meta["io.modelcontextprotocol/clientCapabilities"] = serde_json::json!({});
        meta["io.modelcontextprotocol/clientInfo"] =
            serde_json::to_value(Implementation::new("c", "0")).unwrap();
        assert!(matches!(classify(&opener(meta), &SUPPORTED), Opener::Opens));
    }

    #[test]
    fn client_info_is_not_required_by_the_draft_and_its_absence_opens_the_lifecycle() {
        // `RequestMetaObject::DRAFT_REQUIRED_KEYS` is version + capabilities.
        // Recorded as a test because the milestone review asserted all three
        // were required, and a shape this file lets through must be a shape
        // some test names.
        let mut meta = version("2026-07-28");
        meta["io.modelcontextprotocol/clientCapabilities"] = serde_json::json!({});
        assert!(matches!(classify(&opener(meta), &SUPPORTED), Opener::Opens));
    }

    #[test]
    fn a_meta_without_capabilities_is_refused_by_name_rather_than_by_silence() {
        let error = refusal(&opener(version("2026-07-28")));
        assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
        assert!(
            error
                .message
                .contains("io.modelcontextprotocol/clientCapabilities"),
            "the refusal must name the key that is missing: {}",
            error.message
        );
        assert!(
            !error
                .message
                .contains("io.modelcontextprotocol/protocolVersion"),
            "the version was supplied and must not be reported missing: {}",
            error.message
        );
    }

    #[test]
    fn an_absent_meta_is_refused_naming_both_required_keys() {
        let error = refusal(&opener(serde_json::Value::Null));
        assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
        for key in RequestMetaObject::DRAFT_REQUIRED_KEYS {
            assert!(
                error.message.contains(key),
                "the refusal must name {key}: {}",
                error.message
            );
        }
    }

    #[test]
    fn an_empty_meta_is_refused_naming_both_required_keys() {
        let error = refusal(&opener(serde_json::json!({})));
        assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
        for key in RequestMetaObject::DRAFT_REQUIRED_KEYS {
            assert!(error.message.contains(key), "{}", error.message);
        }
    }

    #[test]
    fn an_unsupported_version_alone_is_32022_with_the_list_this_server_does_implement() {
        // The sharpest shape: `_meta` is *also* incomplete, and the answer is
        // still the version error, because that is the one the client can act
        // on and it is the order the SDK's own handler uses.
        let error = refusal(&opener(version("2025-11-25")));
        assert_eq!(error.code, ErrorCode::UNSUPPORTED_PROTOCOL_VERSION);
        let data = error.data.expect("`-32022` carries data");
        assert_eq!(data["requested"], "2025-11-25");
        assert_eq!(data["supported"], serde_json::json!(["2026-07-28"]));
    }

    #[test]
    fn a_malformed_version_is_a_missing_key_rather_than_an_unsupported_one() {
        // A key that does not decode counts as absent, which is what
        // `missing_required_keys` documents and what the typed accessors do.
        let error = refusal(&opener(
            serde_json::json!({ "io.modelcontextprotocol/protocolVersion": 20260728 }),
        ));
        assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
        assert!(
            error
                .message
                .contains("io.modelcontextprotocol/protocolVersion"),
            "{}",
            error.message
        );
    }

    #[test]
    fn the_legacy_handshake_still_opens_the_lifecycle() {
        let initialize: ClientJsonRpcMessage = serde_json::from_value(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2026-07-28",
                "capabilities": {},
                "clientInfo": { "name": "c", "version": "0" },
            },
        }))
        .expect("an initialize request parses");
        assert!(matches!(classify(&initialize, &SUPPORTED), Opener::Opens));
    }

    #[test]
    fn a_ping_is_handed_through_without_opening_the_lifecycle() {
        let ping: ClientJsonRpcMessage = serde_json::from_value(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "ping",
        }))
        .expect("a ping parses");
        assert!(matches!(classify(&ping, &SUPPORTED), Opener::Passes));
    }

    #[test]
    fn a_notification_before_the_lifecycle_is_ignored_rather_than_fatal() {
        let notification = ClientJsonRpcMessage::Notification(rmcp::model::JsonRpcNotification {
            jsonrpc: JsonRpcVersion2_0,
            notification: InitializedNotification::default().into(),
        });
        assert!(matches!(
            classify(&notification, &SUPPORTED),
            Opener::Ignored
        ));
    }
}
