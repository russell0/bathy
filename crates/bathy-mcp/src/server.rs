//! The server, and the protocol facts that shape it.
//!
//! # This is a Modern server, and that is a decision, not a default
//!
//! Protocol version `2026-07-28` dropped the `initialize` handshake and
//! protocol-level sessions: a client sends whatever request it wants first,
//! carrying the protocol version and its own capabilities in that request's
//! `_meta`, and a server that waits to be initialized waits forever. Servers
//! **MUST** implement `server/discover` so a client can ask what is supported
//! without guessing.
//!
//! Two defaults in the SDK point the other way and are overridden here on
//! purpose:
//!
//! * `ProtocolVersion::default()` is `2025-11-25` -- a Legacy version. A
//!   server that takes the default advertises Legacy, and the newest thing it
//!   can then do is refuse to emit an approval request at all, because the
//!   Multi Round-Trip pattern the approval gate is built on only exists from
//!   `2026-07-28`. [`BathyMcpServer::get_info`] sets the version explicitly.
//! * `supported_protocol_versions` defaults to every version the SDK knows,
//!   including four this server does not implement. It is narrowed to the one
//!   that is actually implemented, so a client asking for an older one is
//!   told `-32022` with the list it can use instead, rather than being
//!   silently accepted and then failing on the first feature it relies on.
//!
//! # Transport
//!
//! Standard input and output. The two-endpoint HTTP+SSE transport is
//! deprecated, `Mcp-Session-Id` and the persistent GET stream are removed,
//! and stream resumability is gone -- so nothing here may assume a stream can
//! be resumed, and nothing does. The crate does not enable any HTTP transport
//! feature, so none of that is merely unused: it is not compiled in.
//!
//! Diagnostics go to standard error. Standard output is the transport, and
//! the protocol's own logging capability is deprecated in this version.

use std::borrow::Cow;
use std::sync::Arc;

use bathy_types::ids::Digest;
use rmcp::model::{
    CacheScope, CallToolRequestParams, CallToolResponse, CallToolResult, Implementation,
    ListToolsResult, PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerInfo,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData as McpError, ServerHandler};

use crate::approval::{ApprovalGate, UNIDENTIFIED_PRINCIPAL};
use crate::config::ServerConfig;
use crate::descriptors;
use crate::engine::Runtime;
use crate::error::{ToolFailure, ToolResult};
use crate::tools;

/// The one protocol version this server implements.
pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::V_2026_07_28;

pub struct BathyMcpServer {
    runtime: Arc<Runtime>,
    approval: Arc<ApprovalGate>,
}

impl BathyMcpServer {
    pub fn new(config: ServerConfig) -> Result<Self, String> {
        let runtime = Runtime::open(&config.state_dir)?;
        Ok(Self {
            runtime: Arc::new(runtime),
            approval: Arc::new(ApprovalGate::new(
                config.approval_signing_key,
                config.approval_threshold_targets,
                config.approval_ttl,
            )),
        })
    }

    pub fn runtime(&self) -> &Arc<Runtime> {
        &self.runtime
    }

    pub fn approval(&self) -> &Arc<ApprovalGate> {
        &self.approval
    }
}

/// Who the caller is, for the purpose of binding an approval to them.
///
/// On standard input and output there is no authenticated principal, so this
/// is what the client says it is. It is still worth binding to: the property
/// that actually holds here is that one server process serves one client, and
/// the binding is what keeps that true if this server is ever put behind a
/// transport where it is not.
fn principal_of(context: &RequestContext<RoleServer>) -> String {
    context.client_info().map_or_else(
        || UNIDENTIFIED_PRINCIPAL.to_string(),
        |Implementation { name, version, .. }| format!("{name}/{version}"),
    )
}

/// A digest over the arguments a call was made with, so an approval issued
/// for one request cannot be redeemed for another.
///
/// Taken over the canonical rendering of the arguments object rather than the
/// raw text, so a client that re-serializes its own request between the two
/// rounds -- which every client does, since it builds a fresh JSON-RPC
/// message -- still produces the same digest.
fn arguments_digest(arguments: &Option<rmcp::model::JsonObject>) -> Digest {
    let value = serde_json::Value::Object(arguments.clone().unwrap_or_default());
    Digest::of_bytes(canonical(&value).as_bytes())
}

/// Key-sorted, whitespace-free JSON. Deliberately not this project's
/// canonical-JSON encoder, which refuses non-integer numbers -- a budget
/// override is an integer, but an argument object is caller-shaped and may
/// hold anything the schema allows.
fn canonical(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            let body: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", serde_json::Value::String(k.clone()), canonical(&map[k])))
                .collect();
            format!("{{{}}}", body.join(","))
        }
        serde_json::Value::Array(items) => {
            let body: Vec<String> = items.iter().map(canonical).collect();
            format!("[{}]", body.join(","))
        }
        other => other.to_string(),
    }
}

impl ServerHandler for BathyMcpServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::new(ServerCapabilities::builder().enable_tools().build());
        // Not the SDK default, which is a Legacy version. See the module doc.
        info.protocol_version = PROTOCOL_VERSION;
        info.server_info = Implementation::new("bathy", env!("CARGO_PKG_VERSION"));
        info.instructions = Some(
            "Authorized network discovery. Every scan needs a scope manifest, named by \
             the path of a file an operator wrote; this server never accepts one inline. \
             Start with scope.validate, then scan.preview to see what a request would do \
             without sending anything, then scan.start."
                .into(),
        );
        info
    }

    /// Exactly one, and it is the one that is implemented.
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(&[PROTOCOL_VERSION])
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        // The set is compiled in and cannot change while this process runs,
        // so it is cacheable and shareable. The order is sorted by name,
        // asserted rather than assumed.
        Ok(ListToolsResult::with_all_items(descriptors::all())
            .with_ttl_ms(descriptors::TOOLS_TTL_MS)
            .with_cache_scope(CacheScope::Public))
    }

    fn get_tool(&self, name: &str) -> Option<rmcp::model::Tool> {
        descriptors::all().into_iter().find(|t| t.name == name)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        // An unknown tool is the one condition that genuinely is not
        // routable, so it is the one that gets a protocol error.
        if !descriptors::TOOL_NAMES.contains(&request.name.as_ref()) {
            return Err(McpError::invalid_params(
                format!("no tool named `{}`", request.name),
                Some(serde_json::json!({ "tools": descriptors::TOOL_NAMES })),
            ));
        }
        Ok(match self.dispatch(request, &context).await {
            Ok(response) => response,
            Err(failure) => CallToolResponse::Complete(failure.into_result()),
        })
    }
}

impl BathyMcpServer {
    async fn dispatch(
        &self,
        request: CallToolRequestParams,
        context: &RequestContext<RoleServer>,
    ) -> ToolResult<CallToolResponse> {
        let runtime = Arc::clone(&self.runtime);
        let name = request.name.clone();
        let arguments = request.arguments.clone();

        let result: CallToolResult = match name.as_ref() {
            "scope.validate" => {
                let input = tools::parse_input(arguments)?;
                let out = tools::scope::validate(input, &runtime.now())?;
                if out.decision == bathy_types::task::PolicyDecisionTag::Denied {
                    tools::refused(&out)?
                } else {
                    tools::complete(&out)?
                }
            }
            "scan.preview" => {
                let input = tools::parse_input(arguments)?;
                let out = tools::scan::preview(input, &runtime)?;
                if out.policy_decision == bathy_types::task::PolicyDecisionTag::Denied {
                    tools::refused(&out)?
                } else {
                    tools::complete(&out)?
                }
            }
            "scan.start" => return self.start(request, context).await,
            "scan.status" => {
                let input = tools::parse_input(arguments)?;
                tools::complete(&tools::scan::status(input, &runtime)?)?
            }
            "scan.events" => {
                let input = tools::parse_input(arguments)?;
                tools::complete(&tools::scan::events(input, &runtime)?)?
            }
            "scan.cancel" => {
                let input = tools::parse_input(arguments)?;
                tools::complete(&tools::scan::cancel(input, &runtime)?)?
            }
            "scan.resume" => {
                let input = tools::parse_input(arguments)?;
                tools::complete(&tools::scan::resume(input, &runtime)?)?
            }
            "result.query" => {
                let input = tools::parse_input(arguments)?;
                tools::complete(&tools::result::query(input, &runtime)?)?
            }
            "result.diff" => {
                let input = tools::parse_input(arguments)?;
                tools::complete(&tools::result::diff_scans(input, &runtime)?)?
            }
            "evidence.get" => {
                let input = tools::parse_input(arguments)?;
                tools::complete(&tools::evidence::get(input, &runtime)?)?
            }
            "fingerprint.explain" => {
                let input = tools::parse_input(arguments)?;
                tools::complete(&tools::fingerprint::explain(input)?)?
            }
            other => {
                return Err(ToolFailure::new(
                    "no_such_tool",
                    format!("no tool named `{other}`"),
                ));
            }
        };
        Ok(CallToolResponse::Complete(result))
    }

    /// `scan.start`, which is the only tool with a gate in front of it.
    ///
    /// The order below is the whole of the guarantee, and every step happens
    /// before the next can: the manifest decides, then the threshold decides,
    /// then a human decides, and only then is a scan record created and a
    /// scheduler built. Every early return leaves the store untouched and the
    /// network unaddressed.
    async fn start(
        &self,
        request: CallToolRequestParams,
        context: &RequestContext<RoleServer>,
    ) -> ToolResult<CallToolResponse> {
        let input: bathy_types::tools::ScanStartInput =
            tools::parse_input(request.arguments.clone())?;

        // 1. The manifest. A refusal here creates no task and sends nothing.
        let authorized = match tools::scan::admit(&input, &self.runtime)? {
            tools::scan::StartAdmission::Denied(out) => {
                return Ok(CallToolResponse::Complete(tools::refused(&*out)?));
            }
            tools::scan::StartAdmission::Authorized(scan) => scan,
        };

        // 2. The threshold. It is server configuration read from this
        //    process, never a request field: an agent cannot raise its own.
        if self.approval.requires_approval(authorized.estimated_targets()) {
            let principal = principal_of(context);
            let digest = arguments_digest(&request.arguments);
            let plan_hash = authorized.plan().hash().to_string();

            let Some(state) = request.request_state.as_deref() else {
                // 3a. Nobody has been asked yet. Ask, and start nothing.
                let message = format!(
                    "bathy is asking permission to scan {} address(es) with {} probe(s). \
                     This server requires a human decision above {} address(es). \
                     Manifest: {}. Plan: {}.",
                    authorized.estimated_targets(),
                    authorized.estimated_probes(),
                    self.approval.threshold_targets(),
                    input.manifest_path,
                    plan_hash,
                );
                let challenge = self
                    .approval
                    .challenge(
                        &principal,
                        &digest,
                        &plan_hash,
                        authorized.estimated_targets(),
                        message,
                    )
                    .map_err(|e| ToolFailure::new("approval_unissuable", e))?;
                return Ok(CallToolResponse::InputRequired(challenge));
            };

            // 3b. Somebody claims to have been asked. The claim is untrusted.
            self.approval
                .redeem(
                    Some(state),
                    request.input_responses.as_ref(),
                    &principal,
                    &digest,
                    &plan_hash,
                )
                .map_err(|e| ToolFailure::new(e.code(), e.detail()))?;
        }

        // 4. Only now.
        let out = tools::scan::begin(*authorized, &self.runtime)?;
        Ok(CallToolResponse::Complete(tools::complete(&out)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_advertised_protocol_version_is_the_modern_one_not_the_sdk_default() {
        assert_eq!(PROTOCOL_VERSION.as_str(), "2026-07-28");
        assert_ne!(
            ProtocolVersion::default().as_str(),
            PROTOCOL_VERSION.as_str(),
            "the SDK default is a Legacy version; if that ever changes this note \
             and the override it explains should be re-read, not silently kept"
        );
    }

    #[test]
    fn canonical_rendering_does_not_depend_on_key_order() {
        let a = serde_json::json!({ "b": 1, "a": [3, { "z": 1, "y": 2 }] });
        let b = serde_json::json!({ "a": [3, { "y": 2, "z": 1 }], "b": 1 });
        assert_eq!(canonical(&a), canonical(&b));
    }

    #[test]
    fn canonical_rendering_distinguishes_values_that_differ() {
        let a = serde_json::json!({ "targets": ["10.0.0.0/24"] });
        let b = serde_json::json!({ "targets": ["10.0.0.0/8"] });
        assert_ne!(canonical(&a), canonical(&b));
    }

    #[test]
    fn the_arguments_digest_ignores_ordering_but_not_content() {
        let one = serde_json::json!({ "manifest_path": "/x", "request": { "b": 1, "a": 2 } });
        let two = serde_json::json!({ "request": { "a": 2, "b": 1 }, "manifest_path": "/x" });
        let three = serde_json::json!({ "manifest_path": "/y", "request": { "a": 2, "b": 1 } });
        let obj = |v: serde_json::Value| Some(v.as_object().unwrap().clone());
        assert_eq!(
            arguments_digest(&obj(one)),
            arguments_digest(&obj(two.clone()))
        );
        assert_ne!(arguments_digest(&obj(two)), arguments_digest(&obj(three)));
    }

    #[test]
    fn a_caller_that_does_not_identify_itself_still_gets_a_stable_principal() {
        // Not the empty string, and not something a client could send as its
        // own name: an unidentified caller must not be able to collide with
        // an identified one, in either direction.
        assert!(UNIDENTIFIED_PRINCIPAL.contains('\u{0}'));
    }
}
