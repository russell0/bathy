//! The eleven tool implementations.
//!
//! Each is a function from a typed input to a typed output over the engine
//! handles in [`Runtime`](crate::engine::Runtime). None of them parses a
//! string a caller wrote into anything but the types declared in the input
//! schema, and none of them builds a command line, because there is nothing
//! here that runs one.

pub mod evidence;
pub mod fingerprint;
pub mod result;
pub mod scan;
pub mod scope;

use rmcp::model::{CallToolResult, JsonObject};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{ToolFailure, ToolResult, bad_arguments};

/// Turn a call's arguments into the typed input the schema declares.
///
/// Absent arguments are treated as an empty object so a tool whose fields all
/// have defaults can be called with none, and the type's own strictness --
/// unknown fields refused, ranges checked, identifiers parsed -- is what
/// rejects everything else.
pub fn parse_input<T: DeserializeOwned>(arguments: Option<JsonObject>) -> ToolResult<T> {
    let value = serde_json::Value::Object(arguments.unwrap_or_default());
    serde_json::from_value(value).map_err(bad_arguments)
}

/// A successful result: the typed value in `structuredContent`, and the same
/// value serialized as JSON text in `content` for clients that predate
/// structured results.
pub fn complete<T: Serialize>(value: &T) -> ToolResult<CallToolResult> {
    let rendered =
        serde_json::to_value(value).map_err(|e| ToolFailure::new("unserializable_result", e))?;
    Ok(CallToolResult::structured(rendered))
}

/// A refusal that is nonetheless an answer: a scope manifest saying no.
///
/// It keeps the structured slot -- the declared output shape has a place for
/// a denial, which is why it was designed with one -- and is marked as an
/// error, because an agent that treats "denied" as success will loop.
pub fn refused<T: Serialize>(value: &T) -> ToolResult<CallToolResult> {
    let rendered =
        serde_json::to_value(value).map_err(|e| ToolFailure::new("unserializable_result", e))?;
    Ok(CallToolResult::structured_error(rendered))
}
