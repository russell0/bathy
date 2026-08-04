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
pub mod server;
pub mod tools;

pub use config::ServerConfig;
pub use server::{BathyMcpServer, PROTOCOL_VERSION};

/// Serve the tool surface on this process's standard input and output until
/// the client disconnects.
///
/// Standard output is the transport, so nothing may be written to it that is
/// not a protocol message. Diagnostics go to standard error.
pub async fn serve_stdio(config: ServerConfig) -> Result<(), String> {
    use rmcp::service::ServiceExt;

    let server = BathyMcpServer::new(config)?;
    let running = server
        .serve(rmcp::transport::stdio())
        .await
        .map_err(|e| format!("mcp transport: {e}"))?;
    running.waiting().await.map_err(|e| format!("mcp: {e}"))?;
    Ok(())
}
