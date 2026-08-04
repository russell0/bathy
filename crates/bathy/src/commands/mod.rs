//! One module per command group.
//!
//! **None of this contains scanning logic.** Every command here translates
//! flags into a call on the engine API and translates the answer back; if a
//! decision about *what* to scan appears in this directory it belongs lower
//! down, in `bathy-plan`, `bathy-scope` or `bathy-engine`.
//!
//! # "Anything the MCP server can do the CLI can do" is now structural
//!
//! It used to be an aspiration with one exception written down (`scope`
//! called the tool implementation; everything else restated it), and M5 Task
//! 4's review found six documents that differed and four questions the tool
//! surface could ask that this one could not. So every command in this
//! directory now **calls the tool function and renders its typed output**.
//! There is one implementation of each answer, and the field sets cannot
//! drift because they are one Rust type.
//!
//! Two guards keep it that way, and both fail loudly:
//!
//! * `crates/bathy/tests/mcp.rs` compares the two surfaces as **whole
//!   documents**, for cases generated from the tool list the server
//!   advertises. A twelfth tool fails that test until somebody writes down
//!   how its subcommand answers the same question.
//! * The genuine differences are declared and asserted rather than skipped:
//!   `scan events` streams line-delimited events where the tool returns a
//!   paging envelope, and `scan start`/`scan resume` print the tool's
//!   document and then a run summary, because this surface runs the work the
//!   tool detaches.
//!
//! The dependency direction is deliberate and is the one `xtask`'s layer
//! table already permitted: `bathy-mcp` ranks immediately below `bathy`. The
//! tool functions themselves are not MCP-specific -- they are the engine's
//! operations, over typed inputs from `bathy-types`/`bathy-query` -- and if
//! `serve mcp` is ever feature-gated they must move to a crate below both
//! surfaces rather than be duplicated back into this one. See the fix
//! report for that decision.

pub mod evidence;
pub mod explain;
pub mod result;
pub mod scan;
pub mod scope;
pub mod serve;
