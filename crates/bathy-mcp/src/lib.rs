#![forbid(unsafe_code)]

//! `bathy-mcp`: authorized network discovery as eleven typed tools.
//!
//! This crate is the reason the project exists. An agent completes an
//! authorized inventory -- validate a scope, plan a scan, run it, follow it,
//! query the results, fetch the bytes that justified a finding -- without
//! ever constructing a command string or parsing a document format. There is
//! no tool here that takes a command, an argument vector or a flag, and there
//! is no tool here that accepts a scope manifest inline, because a caller
//! that can supply its own authorization has none.
//!
//! It contains **no scanning logic**. It parses typed arguments, loads a
//! scope manifest, calls the engine and renders the answer -- the same job
//! the `bathy` command does, over the same engine, which is what makes this
//! tool surface auditable from a shell.
//!
//! # The protocol
//!
//! Revision `2026-07-28`, over standard input and output. That revision is
//! not an increment on the session-based protocol most documentation
//! describes: it dropped the `initialize` handshake and protocol-level
//! sessions entirely. See [`server`] for what that changes, and
//! `docs/protocol-notes.md` for the whole record.

pub mod approval;
pub mod config;
pub mod descriptors;
pub mod engine;
pub mod error;
pub mod lifecycle;
pub mod server;
pub mod tools;

pub use config::ServerConfig;
pub use server::{BathyMcpServer, PROTOCOL_VERSION};

/// Serve the tool surface on this process's standard input and output until
/// the client disconnects.
///
/// Standard output is the transport, so nothing may be written to it that is
/// not a protocol message. Diagnostics go to standard error.
///
/// The transport is wrapped in [`lifecycle::AnswersTheOpener`], because the
/// SDK ends the process rather than the request when the first message cannot
/// open the inline lifecycle. That module says what the SDK does and why this
/// is here; `docs/protocol-notes.md` records it as a deviation.
pub async fn serve_stdio(config: ServerConfig) -> Result<(), String> {
    use rmcp::ServerHandler;
    use rmcp::service::{RoleServer, ServerInitializeError, ServiceExt};
    use rmcp::transport::IntoTransport;

    let server = BathyMcpServer::new(config)?;
    let supported = server.supported_protocol_versions();
    let stdio =
        IntoTransport::<RoleServer, std::io::Error, _>::into_transport(rmcp::transport::stdio());
    let running = match server
        .serve(lifecycle::AnswersTheOpener::new(stdio, supported))
        .await
    {
        Ok(running) => running,
        // The client hung up before it opened the lifecycle. That is a
        // session that ended, not a server that failed -- exactly like the
        // disconnect after the lifecycle *is* open, which `waiting()` below
        // returns `Ok` for. It is reachable on purpose now: a client whose
        // opening request is refused may read the refusal and leave, and a
        // supervisor must not read that as a crash to restart.
        Err(ServerInitializeError::ConnectionClosed(_)) => return Ok(()),
        Err(e) => return Err(format!("mcp transport: {e}")),
    };
    running.waiting().await.map_err(|e| format!("mcp: {e}"))?;
    Ok(())
}
