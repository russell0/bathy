//! One module per command group.
//!
//! **None of this contains scanning logic.** Every command here translates
//! flags into a call on the engine API and translates the answer back; if a
//! decision about *what* to scan appears in this directory it belongs lower
//! down, in `bathy-plan`, `bathy-scope` or `bathy-engine`. The MCP server in
//! Task 4 is the same translator over the same API, which is what makes
//! "anything the MCP server can do the CLI can do" a structural property
//! rather than an aspiration.

pub mod evidence;
pub mod explain;
pub mod result;
pub mod scan;
pub mod scope;
