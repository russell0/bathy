//! The MCP tool surface, driven over a real stdio transport.
//!
//! Every test here spawns the shipped `bathy` binary as `bathy serve mcp` and
//! speaks newline-delimited JSON-RPC to its standard input and output. Nothing
//! calls a handler function: a tool surface exercised through its internals is
//! not tested where it is used, and the protocol facts these tests are about
//! -- inline version negotiation, `server/discover`, `-32022`, the Multi
//! Round-Trip approval flow -- are properties of the wire, not of a function.
//!
//! The client itself, and the fixtures it needs, live in [`harness`]: this
//! file and `workflow.rs` both drive the server through it, and two
//! hand-written clients would be two definitions of what calling a tool
//! means.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

mod harness;
use harness::*;

// ---------------------------------------------------------------------------
// A JSON Schema check, over the constructs these schemas actually use.
// ---------------------------------------------------------------------------

/// Whether `value` satisfies `schema`, resolving `$ref` against `root`.
///
/// # Why this exists at all, and why its gaps are written down
///
/// `rmcp` does **not** validate a result against the tool's `outputSchema`
/// when `call_tool` is implemented directly, as it is here. So this function
/// is the only thing standing behind AC-5.28's promise that a structured
/// result conforms to the schema its own tool published, and the
/// specification's "clients **SHOULD** validate structured results against
/// this schema" means a real client would reject anything this misses.
///
/// A validator whose gaps are known is worth more than one assumed complete.
/// The first version of this function omitted `pattern` -- the one keyword
/// every identifier and digest in these schemas is constrained by, declared
/// 29 times -- so `scan_id: "not-an-identifier"` and `digest: "blake3:zzzz"`
/// both passed as conforming. That is why the list below is written out in
/// the same spirit as `xtask/src/readme.rs`'s `NOT MECHANICALLY CHECKED`
/// section: a green conformance test means these keywords agree, never that
/// the document is valid JSON Schema 2020-12.
///
/// ## Implemented
///
/// `$ref` (local `#/$defs/` only), `oneOf` (exactly one arm), `anyOf`,
/// `allOf`, `const`, `enum`, `type` (single and as a list), `pattern`,
/// `format` for `ip` and `date-time`, `required`, `properties`,
/// `additionalProperties` (`false` and as a subschema), `items`, `minItems`,
/// `minimum`, `maximum`, and boolean schemas. Every one of these is
/// exercised by a violating document in
/// [`validator`], so removing any single check fails a named test.
///
/// ## NOT CHECKED -- written out deliberately
///
/// None of these appears in the 27 committed schemas today, which is why
/// they are absent; each would silently pass if one did.
///
///   - `not`, `if`/`then`/`else`, `dependentSchemas`, `dependentRequired`.
///   - `patternProperties`, `propertyNames`, `minProperties`,
///     `maxProperties`, `unevaluatedProperties`.
///   - `prefixItems` (tuple validation), `contains`/`minContains`,
///     `maxItems`, `uniqueItems`, `unevaluatedItems`.
///   - `minLength`, `maxLength`, `multipleOf`, `exclusiveMinimum`,
///     `exclusiveMaximum`.
///   - `$ref` to anything but `#/$defs/<name>`: no `$id` resolution, no
///     JSON-Pointer traversal, no remote or recursive references. A
///     reference this cannot resolve is an error rather than a pass.
///   - `$dynamicRef`/`$dynamicAnchor`, `$vocabulary`.
///   - `format` beyond `ip` and `date-time`. The seven `format` values these
///     schemas use are `uint8`, `uint16`, `uint32`, `uint64`, `double`, `ip`
///     and `date-time`; the five numeric ones are emitted by `schemars`
///     alongside a `type` and a `minimum`/`maximum` that say the same thing
///     and *are* checked, so implementing them would add no coverage.
///   - `date-time` is checked for **shape**, not for calendar validity:
///     `2026-02-31T00:00:00.000Z` passes. A real date parser here would be a
///     second implementation of something `bathy-types` already owns.
///   - `default`: not applied. A property absent from the value is not
///     filled in before the rest of the schema is checked.
///   - Annotation keywords (`title`, `description`, `examples`, `readOnly`)
///     carry no assertion, which is correct, and are named here so their
///     absence from the list above is not mistaken for an omission.
fn conforms(root: &Value, schema: &Value, value: &Value) -> Result<(), String> {
    // A boolean schema. `true` accepts anything; `false` accepts nothing.
    if let Some(accepts) = schema.as_bool() {
        return if accepts {
            Ok(())
        } else {
            Err(format!("{value} is rejected by a `false` schema"))
        };
    }

    // `$ref`, and then whatever sits beside it. From draft 2019-09 onward
    // `$ref` is an ordinary keyword rather than one that replaces its object,
    // so returning here would skip every sibling keyword -- which is how the
    // first version of this function came to ignore constraints declared next
    // to a combinator.
    if let Some(reference) = schema["$ref"].as_str() {
        let name = reference
            .strip_prefix("#/$defs/")
            .ok_or_else(|| format!("unsupported reference {reference}"))?;
        let target = root["$defs"]
            .get(name)
            .ok_or_else(|| format!("dangling reference {reference}"))?;
        conforms(root, target, value).map_err(|e| format!("{reference}: {e}"))?;
    }

    // `oneOf` requires *exactly* one arm to match. Treating it as `anyOf` --
    // which this did -- accepts a document two disjoint variants both claim,
    // and in these schemas the arms are discriminated variants, so two
    // matching means the discriminator has stopped discriminating.
    if let Some(arms) = schema["oneOf"].as_array() {
        let matched = arms
            .iter()
            .filter(|arm| conforms(root, arm, value).is_ok())
            .count();
        if matched != 1 {
            return Err(format!(
                "{value} matches {matched} of the {} oneOf arms; oneOf requires exactly one",
                arms.len()
            ));
        }
    }
    if let Some(arms) = schema["anyOf"].as_array()
        && !arms.iter().any(|arm| conforms(root, arm, value).is_ok())
    {
        return Err(format!("{value} matches no anyOf arm of {schema}"));
    }
    if let Some(arms) = schema["allOf"].as_array() {
        for (index, arm) in arms.iter().enumerate() {
            conforms(root, arm, value).map_err(|e| format!("allOf[{index}]: {e}"))?;
        }
    }

    if let Some(constant) = schema.get("const")
        && constant != value
    {
        return Err(format!("{value} is not {constant}"));
    }
    if let Some(choices) = schema["enum"].as_array()
        && !choices.contains(value)
    {
        return Err(format!("{value} is not one of {choices:?}"));
    }
    if let Some(declared) = schema["type"].as_str()
        && !is_type(declared, value)
    {
        return Err(format!("expected {declared}, got {value}"));
    }
    if let Some(types) = schema["type"].as_array()
        && !types
            .iter()
            .any(|t| t.as_str().is_some_and(|t| is_type(t, value)))
    {
        return Err(format!("{value} matches none of {types:?}"));
    }

    if let Some(text) = value.as_str() {
        // The keyword every identifier and digest in these schemas is
        // constrained by. Compiled per call rather than cached: this runs a
        // few hundred times in one test, and a `LazyLock` map keyed by
        // pattern would be a cache to get wrong for no measurable gain.
        if let Some(pattern) = schema["pattern"].as_str() {
            let compiled = regex::Regex::new(pattern)
                .map_err(|e| format!("the schema's own pattern {pattern} does not compile: {e}"))?;
            if !compiled.is_match(text) {
                return Err(format!("`{text}` does not match {pattern}"));
            }
        }
        match schema["format"].as_str() {
            Some("ip") if text.parse::<IpAddr>().is_err() => {
                return Err(format!("`{text}` is not an IP address"));
            }
            Some("date-time") if !is_rfc3339_shaped(text) => {
                return Err(format!("`{text}` is not an RFC 3339 timestamp"));
            }
            _ => {}
        }
    }

    if let Some(object) = value.as_object() {
        for name in schema["required"].as_array().unwrap_or(&vec![]) {
            let name = name.as_str().unwrap_or_default();
            if !object.contains_key(name) {
                return Err(format!("required property `{name}` is absent from {value}"));
            }
        }
        // Read outside the `properties` branch on purpose: a schema that
        // declares `additionalProperties: false` and *no* `properties` at all
        // permits nothing, and checking it only when `properties` is present
        // is how a whole document escapes the check.
        let declared = schema["properties"].as_object();
        let extra = schema.get("additionalProperties");
        for (key, present) in object {
            if let Some(sub) = declared.and_then(|d| d.get(key)) {
                conforms(root, sub, present).map_err(|e| format!("{key}: {e}"))?;
                continue;
            }
            match extra {
                Some(Value::Bool(false)) => {
                    return Err(format!("`{key}` is not a declared property"));
                }
                Some(sub) => conforms(root, sub, present)
                    .map_err(|e| format!("additional property {key}: {e}"))?,
                None => {}
            }
        }
    }

    if let Some(items) = value.as_array() {
        if let Some(minimum) = schema["minItems"].as_u64()
            && (items.len() as u64) < minimum
        {
            return Err(format!("{} items, minimum {minimum}", items.len()));
        }
        if let Some(sub) = schema.get("items") {
            for (index, item) in items.iter().enumerate() {
                conforms(root, sub, item).map_err(|e| format!("[{index}]: {e}"))?;
            }
        }
    }

    if let Some(number) = value.as_f64() {
        if let Some(minimum) = schema["minimum"].as_f64()
            && number < minimum
        {
            return Err(format!("{number} is below the minimum {minimum}"));
        }
        if let Some(maximum) = schema["maximum"].as_f64()
            && number > maximum
        {
            return Err(format!("{number} is above the maximum {maximum}"));
        }
    }
    Ok(())
}

/// One `type` keyword against one value.
///
/// `integer` accepts a number whose fractional part is zero, which is what
/// the specification says and what the previous spelling of this -- "an
/// integer may be a number and a number may be an integer" -- did not: it
/// accepted `1.5` where `integer` was declared.
fn is_type(declared: &str, value: &Value) -> bool {
    match declared {
        "null" => value.is_null(),
        "boolean" => value.is_boolean(),
        "string" => value.is_string(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        "number" => value.is_number(),
        "integer" => match value {
            Value::Number(n) if n.is_f64() => n.as_f64().is_some_and(|f| f.fract() == 0.0),
            Value::Number(_) => true,
            _ => false,
        },
        _ => true,
    }
}

/// `YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM)`, by shape.
///
/// Shape and not calendar validity: see the NOT CHECKED list on [`conforms`].
fn is_rfc3339_shaped(text: &str) -> bool {
    static SHAPE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r"^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$",
        )
        .expect("a literal pattern")
    });
    SHAPE.is_match(text)
}

fn assert_conforms(tool: &str, schema: &Value, value: &Value) {
    if let Err(e) = conforms(schema, schema, value) {
        panic!(
            "{tool}'s result does not conform to its own published outputSchema: {e}\n\nresult: {value:#}\n\nschema: {schema:#}"
        );
    }
}

/// The checker, checked.
///
/// `every_real_result_conforms_to_the_output_schema_its_own_tool_published`
/// can only be as strong as [`conforms`] is, and a validator nothing attacks
/// is a validator that quietly accepts anything -- which is exactly what
/// happened: `pattern` was unimplemented and the conformance test passed
/// documents carrying `"blake3:zzzz"`.
///
/// So every keyword [`conforms`] claims to implement has a case here that
/// violates it and a positive control beside it. Deleting the code for any
/// one keyword fails a named test in this module rather than silently
/// widening what the suite accepts.
mod validator {
    use super::{conforms, is_rfc3339_shaped};
    use serde_json::{Value, json};

    fn accepts(schema: Value, value: Value) {
        if let Err(e) = conforms(&schema, &schema, &value) {
            panic!("the checker rejected a conforming document: {e}\n{value:#}\n{schema:#}");
        }
    }

    fn rejects(keyword: &str, schema: Value, value: Value) {
        assert!(
            conforms(&schema, &schema, &value).is_err(),
            "the checker accepted a document that violates `{keyword}`:\n{value:#}\n{schema:#}"
        );
    }

    /// The three patterns these schemas actually declare, and the two
    /// documents that passed as conforming before `pattern` was implemented.
    #[test]
    fn a_pattern_is_enforced_and_these_are_the_three_the_schemas_declare() {
        let cases = [
            (
                "^scan_[0-7][0-9A-HJKMNP-TV-Z]{25}$",
                "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV",
                "not-an-identifier",
            ),
            (
                "^blake3:[0-9a-f]{64}$",
                "blake3:0000000000000000000000000000000000000000000000000000000000000000",
                "blake3:zzzz",
            ),
            (
                "^scope_[0-7][0-9A-HJKMNP-TV-Z]{25}$",
                "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV",
                "scope_lowercase",
            ),
        ];
        for (pattern, good, bad) in cases {
            let schema = json!({ "type": "string", "pattern": pattern });
            accepts(schema.clone(), json!(good));
            rejects("pattern", schema, json!(bad));
        }
    }

    /// And through a `$ref`, which is how every one of them is actually
    /// reached: no result names a pattern inline.
    #[test]
    fn a_pattern_behind_a_ref_is_enforced_where_the_result_actually_carries_one() {
        let schema = json!({
            "$defs": { "ScanId": { "type": "string", "pattern": "^scan_[0-7][0-9A-HJKMNP-TV-Z]{25}$" } },
            "type": "object",
            "properties": { "scan_id": { "$ref": "#/$defs/ScanId" } },
            "required": ["scan_id"],
            "additionalProperties": false,
        });
        accepts(
            schema.clone(),
            json!({ "scan_id": "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV" }),
        );
        rejects("pattern", schema, json!({ "scan_id": "not-an-identifier" }));
    }

    #[test]
    fn a_reference_that_cannot_be_resolved_is_an_error_and_not_a_pass() {
        let schema = json!({ "$defs": {}, "$ref": "#/$defs/Absent" });
        rejects("$ref", schema, json!("anything"));
        let remote = json!({ "$ref": "https://example.invalid/schema.json" });
        rejects("$ref", remote, json!("anything"));
    }

    #[test]
    fn one_of_requires_exactly_one_arm_rather_than_at_least_one() {
        // Two arms that both accept the same string. `anyOf` says yes;
        // `oneOf` says no, and these schemas use `oneOf` for discriminated
        // variants, where two matching means the discriminator failed.
        let ambiguous = json!({
            "oneOf": [{ "type": "string" }, { "type": "string", "pattern": "^a" }]
        });
        rejects("oneOf", ambiguous, json!("abc"));

        let discriminated = json!({
            "oneOf": [
                { "type": "string", "enum": ["pending", "running"] },
                { "type": "string", "const": "denied" },
            ]
        });
        accepts(discriminated.clone(), json!("denied"));
        rejects("oneOf", discriminated, json!("cancelled"));
    }

    #[test]
    fn any_of_needs_one_arm_and_all_of_needs_every_arm() {
        let optional = json!({ "anyOf": [{ "type": "string" }, { "type": "null" }] });
        accepts(optional.clone(), json!(null));
        rejects("anyOf", optional, json!(7));

        let both = json!({ "allOf": [{ "type": "string" }, { "pattern": "^blake3:" }] });
        accepts(both.clone(), json!("blake3:x"));
        rejects("allOf", both, json!("sha256:x"));
    }

    /// The gap that let a whole family of constraints through: a combinator
    /// used to `return`, so anything declared beside it was never read.
    #[test]
    fn a_keyword_beside_a_combinator_is_still_checked() {
        let schema = json!({
            "anyOf": [{ "type": "string" }, { "type": "null" }],
            "pattern": "^scan_",
        });
        accepts(schema.clone(), json!("scan_x"));
        rejects("pattern beside anyOf", schema, json!("evt_x"));

        let after_ref = json!({
            "$defs": { "Text": { "type": "string" } },
            "$ref": "#/$defs/Text",
            "enum": ["one", "two"],
        });
        accepts(after_ref.clone(), json!("one"));
        rejects("enum beside $ref", after_ref, json!("three"));
    }

    #[test]
    fn a_declared_integer_does_not_accept_a_fractional_number() {
        let schema = json!({ "type": "integer", "format": "uint64", "minimum": 0 });
        accepts(schema.clone(), json!(3));
        rejects("type: integer", schema.clone(), json!(1.5));
        rejects("type: integer", schema, json!("3"));
        // A whole number written as a float is an integer, which is what the
        // specification says and what JSON gives no way to distinguish.
        accepts(json!({ "type": "integer" }), json!(3.0));
        // And `number` still takes both.
        accepts(json!({ "type": "number" }), json!(3));
        accepts(json!({ "type": "number" }), json!(0.75));
    }

    #[test]
    fn every_scalar_type_keyword_rejects_the_others() {
        let cases: &[(&str, Value, Value)] = &[
            ("null", json!(null), json!(0)),
            ("boolean", json!(true), json!("true")),
            ("string", json!("x"), json!(1)),
            ("array", json!([]), json!({})),
            ("object", json!({}), json!([])),
        ];
        for (declared, good, bad) in cases {
            let schema = json!({ "type": declared });
            accepts(schema.clone(), good.clone());
            rejects("type", schema, bad.clone());
        }
        let listed = json!({ "type": ["string", "null"] });
        accepts(listed.clone(), json!(null));
        rejects("type list", listed, json!(1));
    }

    #[test]
    fn const_and_enum_are_enforced() {
        rejects(
            "const",
            json!({ "const": "scan.completed" }),
            json!("scan.failed"),
        );
        rejects(
            "enum",
            json!({ "enum": ["open", "closed"] }),
            json!("filtered"),
        );
    }

    #[test]
    fn required_and_additional_properties_are_enforced_at_every_depth() {
        let schema = json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["outer"],
            "properties": {
                "outer": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["inner"],
                    "properties": { "inner": { "type": "string" } },
                }
            },
        });
        accepts(schema.clone(), json!({ "outer": { "inner": "x" } }));
        rejects("required", schema.clone(), json!({}));
        rejects("required (nested)", schema.clone(), json!({ "outer": {} }));
        rejects(
            "additionalProperties",
            schema.clone(),
            json!({ "outer": { "inner": "x" }, "surprise": 1 }),
        );
        rejects(
            "additionalProperties (nested)",
            schema,
            json!({ "outer": { "inner": "x", "surprise": 1 } }),
        );
    }

    /// The other half of `additionalProperties`, which the first version of
    /// this checker read only inside the `properties` branch: a schema that
    /// declares no properties at all and forbids extras permits nothing.
    #[test]
    fn additional_properties_false_without_any_declared_properties_permits_nothing() {
        let closed = json!({ "type": "object", "additionalProperties": false });
        accepts(closed.clone(), json!({}));
        rejects("additionalProperties", closed, json!({ "anything": 1 }));

        // And as a subschema rather than a boolean.
        let typed = json!({ "type": "object", "additionalProperties": { "type": "string" } });
        accepts(typed.clone(), json!({ "a": "x" }));
        rejects("additionalProperties subschema", typed, json!({ "a": 1 }));
    }

    #[test]
    fn items_and_min_items_are_enforced() {
        let schema = json!({ "type": "array", "minItems": 1, "items": { "type": "string" } });
        accepts(schema.clone(), json!(["x"]));
        rejects("minItems", schema.clone(), json!([]));
        rejects("items", schema, json!(["x", 2]));
    }

    #[test]
    fn minimum_and_maximum_are_enforced() {
        let schema = json!({ "type": "number", "minimum": 0.0, "maximum": 1.0 });
        accepts(schema.clone(), json!(0.5));
        rejects("minimum", schema.clone(), json!(-0.1));
        rejects("maximum", schema, json!(1.1));
    }

    #[test]
    fn the_two_formats_that_say_something_type_does_not_are_enforced() {
        let ip = json!({ "type": "string", "format": "ip" });
        accepts(ip.clone(), json!("10.0.0.1"));
        accepts(ip.clone(), json!("2001:db8::1"));
        rejects("format: ip", ip, json!("10.0.0.256"));

        let when = json!({ "type": "string", "format": "date-time" });
        accepts(when.clone(), json!("2026-08-04T12:00:00.000Z"));
        rejects("format: date-time", when, json!("yesterday"));

        // And the documented limit of the date-time check, asserted rather
        // than left as prose: it is a shape, not a calendar.
        assert!(
            is_rfc3339_shaped("2026-02-31T00:00:00.000Z"),
            "the NOT CHECKED list says calendar validity is not checked; if that \
             stops being true the list is what should change"
        );
    }

    #[test]
    fn a_boolean_schema_means_what_it_says() {
        accepts(json!(true), json!({ "anything": 1 }));
        rejects("false schema", json!(false), json!(null));
    }
}

// ---------------------------------------------------------------------------
// The protocol.
// ---------------------------------------------------------------------------

#[test]
fn the_server_answers_without_an_initialize_handshake() {
    // The whole shape of this revision. A server built from memory of the
    // session-based protocol waits to be initialized and never answers; this
    // test is the one that fails in that case, and it fails by timing out
    // rather than by asserting.
    let mut server = Server::start(64);
    let tools = server.tools();
    assert_eq!(tools.len(), 11);
}

// ---------------------------------------------------------------------------
// `_meta` shape, as a dimension of the fixture rather than as one value.
//
// This block exists because of what its absence hid. Every protocol test in
// this file used to go through `Server::meta()`, which emits all three keys --
// the one shape the shipped server could serve. Every other shape a client can
// send made `bathy serve mcp` exit with **nothing on standard output**: no
// `-32022`, no error object, a closed pipe, and any detached scan in that
// process gone with it. Thirty-eight tests passed over a server that did not
// work against a client shaped differently from the harness.
//
// That is the Global Constraint added at this very milestone -- *a fixture
// that satisfies every branch tests none of them* -- applied to the transport
// instead of to a filter. So `_meta` is a dimension here: the table below is
// the set of shapes a client can put on a request, and it is driven twice, as
// the request that opens the connection and as a request on an open one.
// ---------------------------------------------------------------------------

/// What the server owes a request carrying a given `_meta`.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Owed {
    /// A result. The shape is complete enough to serve.
    Result,
    /// `-32602`, naming exactly these `_meta` keys as missing or malformed.
    MissingKeys(&'static [&'static str]),
    /// `-32022`, carrying the list this server does implement.
    UnsupportedVersion,
}

const VERSION_KEY: &str = "io.modelcontextprotocol/protocolVersion";
const CAPABILITIES_KEY: &str = "io.modelcontextprotocol/clientCapabilities";
const INFO_KEY: &str = "io.modelcontextprotocol/clientInfo";

/// Every `_meta` shape a client can send, and what each is owed.
///
/// The `params` value is the *whole* params object, so "no `_meta` at all" is
/// a row rather than a special case.
fn meta_shapes() -> Vec<(&'static str, Value, Owed)> {
    let info = json!({ "name": "shape", "version": "0.0.0" });
    vec![
        (
            "version, clientInfo and capabilities",
            json!({ "_meta": { VERSION_KEY: PROTOCOL, INFO_KEY: info, CAPABILITIES_KEY: {} } }),
            Owed::Result,
        ),
        (
            // `RequestMetaObject::DRAFT_REQUIRED_KEYS` is version and
            // capabilities; `clientInfo` is optional in this revision. A row
            // rather than a remark, because the milestone review reported all
            // three as required and a shape the server accepts must be a shape
            // some test names.
            "version and capabilities, no clientInfo",
            json!({ "_meta": { VERSION_KEY: PROTOCOL, CAPABILITIES_KEY: {} } }),
            Owed::Result,
        ),
        (
            "declaring capabilities explicitly rather than emptily",
            json!({ "_meta": { VERSION_KEY: PROTOCOL, CAPABILITIES_KEY: { "elicitation": {} } } }),
            Owed::Result,
        ),
        (
            "version and clientInfo, no capabilities",
            json!({ "_meta": { VERSION_KEY: PROTOCOL, INFO_KEY: info } }),
            Owed::MissingKeys(&[CAPABILITIES_KEY]),
        ),
        (
            "version alone",
            json!({ "_meta": { VERSION_KEY: PROTOCOL } }),
            Owed::MissingKeys(&[CAPABILITIES_KEY]),
        ),
        (
            "capabilities alone",
            json!({ "_meta": { CAPABILITIES_KEY: {} } }),
            Owed::MissingKeys(&[VERSION_KEY]),
        ),
        (
            "an empty _meta",
            json!({ "_meta": {} }),
            Owed::MissingKeys(&[VERSION_KEY, CAPABILITIES_KEY]),
        ),
        (
            "no _meta at all",
            json!({}),
            Owed::MissingKeys(&[VERSION_KEY, CAPABILITIES_KEY]),
        ),
        (
            // A key that does not decode counts as absent, not as present and
            // wrong, so the answer names it missing rather than unsupported.
            "a malformed version",
            json!({ "_meta": { VERSION_KEY: 20_260_728, CAPABILITIES_KEY: {} } }),
            Owed::MissingKeys(&[VERSION_KEY]),
        ),
        (
            "an unsupported version, alone",
            json!({ "_meta": { "io.modelcontextprotocol/protocolVersion": "2025-11-25" } }),
            Owed::UnsupportedVersion,
        ),
        (
            "an unsupported version, with the rest of _meta",
            json!({ "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2025-11-25",
                INFO_KEY: info,
                CAPABILITIES_KEY: {},
            } }),
            Owed::UnsupportedVersion,
        ),
    ]
}

/// Assert one reply is what the shape is owed, and say which shape when not.
fn assert_owed(shape: &str, position: &str, owed: Owed, reply: &Value) {
    match owed {
        Owed::Result => assert!(
            reply.get("error").is_none() && reply.get("result").is_some(),
            "`{shape}` {position} is a shape a conformant client can send and \
             must be served: {reply}"
        ),
        Owed::MissingKeys(keys) => {
            assert_eq!(
                reply["error"]["code"],
                json!(-32602),
                "`{shape}` {position} must be an invalid-params error naming what \
                 is missing: {reply}"
            );
            let message = reply["error"]["message"].as_str().unwrap_or_default();
            for key in keys {
                assert!(
                    message.contains(key),
                    "`{shape}` {position}: the refusal must name `{key}`: {reply}"
                );
            }
            for key in [VERSION_KEY, CAPABILITIES_KEY] {
                assert!(
                    keys.contains(&key) || !message.contains(key),
                    "`{shape}` {position}: `{key}` was supplied and must not be \
                     reported missing: {reply}"
                );
            }
        }
        Owed::UnsupportedVersion => {
            assert_eq!(
                reply["error"]["code"],
                json!(-32022),
                "`{shape}` {position} must be refused with \
                 UnsupportedProtocolVersionError: {reply}"
            );
            assert_eq!(
                reply["error"]["data"]["supported"],
                json!([PROTOCOL]),
                "`{shape}` {position}: the refusal must name what the client can \
                 use instead: {reply}"
            );
        }
    }
}

#[test]
fn every_meta_shape_a_client_can_open_the_connection_with_is_answered_on_the_wire() {
    // One fresh server process per shape, and the shape is the *first* thing
    // that process ever sees. The harness fails loudly if standard output
    // closes without an answer, which is what every failing shape used to do.
    for (shape, params, owed) in meta_shapes() {
        let mut server = Server::start(64);
        let reply = server.request("tools/list", params);
        assert_owed(shape, "as the opening request", owed, &reply);
    }
}

#[test]
fn a_refused_opening_request_leaves_the_connection_serving() {
    // The other half of "answer the request, not the process". A refusal that
    // takes the transport down with it is a dead pipe with an error object in
    // front of it, and a client is meant to be able to correct itself.
    for (shape, params, owed) in meta_shapes() {
        if owed == Owed::Result {
            continue;
        }
        let mut server = Server::start(64);
        let reply = server.request("tools/list", params);
        assert_owed(shape, "as the opening request", owed, &reply);
        assert_eq!(
            server.tools().len(),
            11,
            "the connection did not survive `{shape}`, so the client cannot retry"
        );
    }
}

#[test]
fn an_opening_request_is_answered_exactly_as_the_same_request_is_answered_later() {
    // The drift guard between this project's transport wrapper and the SDK's
    // own per-request validation. The wrapper exists only because the SDK
    // applies that validation to every request *except* the one that opens the
    // connection; if the two ever disagree about a shape, the position of the
    // request would change the answer, which is precisely the bug being fixed.
    let mut open = Server::start(64);
    assert_eq!(open.tools().len(), 11, "the lifecycle opens");

    for (shape, params, _) in meta_shapes() {
        let later = open.request("tools/list", params.clone());
        let mut fresh = Server::start(64);
        let opening = fresh.request("tools/list", params);

        let strip = |reply: &Value| {
            let mut reply = reply.clone();
            // Ids differ by construction; nothing else may.
            reply.as_object_mut().unwrap().remove("id");
            reply
        };
        assert_eq!(
            strip(&opening),
            strip(&later),
            "`{shape}` was answered differently depending on whether it opened \
             the connection"
        );
    }
}

#[test]
fn a_client_that_hangs_up_after_a_refusal_is_not_reported_as_a_server_failure() {
    // A client may read a refusal and leave. That is a session that ended, and
    // a supervisor that restarts `bathy serve mcp` on a non-zero exit must not
    // be made to loop by one badly-shaped request.
    let (code, stdout, stderr) = serve_once(&[json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {},
    })]);
    assert!(
        stdout.contains("-32602"),
        "the refusal must reach the client before the process ends: {stdout}"
    );
    assert_eq!(code, 0, "exit {code}; stderr:\n{stderr}");
    assert!(
        !stderr.contains("mcp_server_failed"),
        "a client hanging up is not a server failure: {stderr}"
    );
}

#[test]
fn server_discover_advertises_the_implemented_version_its_capabilities_and_its_identity() {
    let mut server = Server::start(64);
    let reply = server.request(
        "server/discover",
        json!({ "_meta": Server::meta("harness") }),
    );
    let result = &reply["result"];
    assert!(reply.get("error").is_none(), "{reply}");

    assert_eq!(
        result["supportedVersions"],
        json!([PROTOCOL]),
        "discovery must advertise exactly what is implemented: {result:#}"
    );
    assert!(
        result["capabilities"]["tools"].is_object(),
        "a server with eleven tools must say so: {result:#}"
    );
    let identity = result["serverInfo"]
        .as_object()
        .or_else(|| result["_meta"]["io.modelcontextprotocol/serverInfo"].as_object())
        .unwrap_or_else(|| panic!("discovery carries no server identity: {result:#}"));
    assert_eq!(identity["name"], json!("bathy"), "{result:#}");
}

#[test]
fn discovery_is_cacheable_on_terms_this_server_chose_rather_than_inherited() {
    // `DiscoverResult::from_server_info` hard-codes `ttlMs: 0` and
    // `cacheScope: private`. Spec-legal, and a value nobody decided -- the
    // same class as the two Legacy defaults this server already overrides,
    // one method over. A discovery answer here is one protocol version, one
    // capability and eleven compiled-in tools.
    let mut server = Server::start(64);
    let result = server.request(
        "server/discover",
        json!({ "_meta": Server::meta("harness") }),
    )["result"]
        .clone();
    assert_eq!(
        result["cacheScope"],
        json!("public"),
        "an answer that is the same for every caller is not private: {result:#}"
    );
    assert!(
        result["ttlMs"].as_u64().is_some_and(|t| t > 0),
        "`ttlMs: 0` means immediately stale, for a document that cannot change \
         while the process runs: {result:#}"
    );
    // The same terms as `tools/list`, from the same constant: two answers
    // about one compiled-in tool set must not expire at different times.
    let tools = server.list_tools();
    assert_eq!(result["ttlMs"], tools["ttlMs"], "{result:#}\n{tools:#}");
    assert_eq!(result["cacheScope"], tools["cacheScope"]);
}

#[test]
fn every_result_carries_the_server_identity_the_specification_asks_for() {
    // "Servers SHOULD include `io.modelcontextprotocol/serverInfo` in every
    // result's `_meta`". `server/discover` did, because the SDK put it there;
    // `tools/list` and `tools/call` returned `_meta: null`. That is the SDK's
    // behaviour rather than a choice made here -- and it becomes a choice
    // once it has been read.
    const KEY: &str = "io.modelcontextprotocol/serverInfo";
    let ip = local_ipv4();
    let scope = Scope::for_local(ip);
    let mut server = Server::start(64);

    for (what, result) in [
        (
            "server/discover",
            server.request(
                "server/discover",
                json!({ "_meta": Server::meta("harness") }),
            )["result"]
                .clone(),
        ),
        ("tools/list", server.list_tools()),
        (
            "tools/call",
            server.call_raw(
                "scope.validate",
                json!({ "manifest_path": scope.path(), "targets": [ip.to_string()] }),
            ),
        ),
    ] {
        assert_eq!(
            result["_meta"][KEY]["name"],
            json!("bathy"),
            "{what} carries no server identity: {result:#}"
        );
    }

    // And on a refusal too, which is the result a client is most likely to be
    // holding when it wants to know whose server said no.
    let refused = server.call_raw("scan.status", json!({ "scan_id": "not-an-identifier" }));
    assert_eq!(refused["isError"], json!(true));
    assert_eq!(refused["_meta"][KEY]["name"], json!("bathy"), "{refused:#}");
}

#[test]
fn a_capability_this_server_does_not_declare_is_answered_as_absent_not_as_empty() {
    // The SDK answers four of these with a *successful empty result*: a
    // server that declares only `tools` would answer `prompts/list` with
    // `{"prompts": []}`, which says "I have prompts and there are none" where
    // the truth is "I do not implement prompts". The SDK is already
    // inconsistent -- `prompts/get` and `resources/read` default to `-32601`
    // -- so five of the nine undeclared methods told the truth and four did
    // not. Found by sweeping every `ServerHandler` default rather than by
    // fixing the one that was reported.
    let mut server = Server::start(64);
    let capabilities = server.request("server/discover", json!({ "_meta": Server::meta("h") }))
        ["result"]["capabilities"]
        .clone();
    assert!(
        capabilities["prompts"].is_null()
            && capabilities["resources"].is_null()
            && capabilities["completions"].is_null()
            && capabilities["logging"].is_null(),
        "this test is about methods whose capability is NOT declared: {capabilities:#}"
    );

    for method in [
        "completion/complete",
        "prompts/list",
        "prompts/get",
        "resources/list",
        "resources/templates/list",
        "resources/read",
        "logging/setLevel",
    ] {
        let reply = server.request(method, json!({ "_meta": Server::meta("harness") }));
        assert_eq!(
            reply["error"]["code"],
            json!(-32601),
            "{method} answered as though this server implemented it: {reply}"
        );
    }

    // And the server is still answering the capability it does declare.
    assert_eq!(server.tools().len(), 11);
}

#[test]
fn a_version_this_server_does_not_implement_is_answered_with_32022_and_the_list_it_does() {
    let mut server = Server::start(64);
    let reply = server.request(
        "tools/list",
        json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2025-11-25",
                "io.modelcontextprotocol/clientInfo": { "name": "legacy", "version": "0" },
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        }),
    );
    let error = &reply["error"];
    assert_eq!(
        error["code"],
        json!(-32022),
        "an unsupported version must be refused with UnsupportedProtocolVersionError, \
         not accepted and then failed on the first feature: {reply}"
    );
    assert_eq!(
        error["data"]["supported"],
        json!([PROTOCOL]),
        "the refusal must name what the client can use instead: {reply}"
    );

    // And the connection survives it: the client is meant to retry.
    assert_eq!(server.tools().len(), 11);
}

#[test]
fn an_initialize_from_a_legacy_client_is_answered_with_the_version_we_implement() {
    // A Legacy client opens with a handshake this revision no longer has. It
    // is answered rather than hung on, and the answer names the version this
    // server actually implements -- not the SDK's default, which is itself a
    // Legacy version. A server that echoed that default would tell a Legacy
    // client "we speak 2025-11-25", and every feature it then relied on would
    // fail one at a time instead of once, clearly, here.
    let mut server = Server::start(64);
    let reply = server.request(
        "initialize",
        json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "legacy", "version": "0.0.0" },
        }),
    );
    assert!(reply.get("error").is_none(), "{reply}");
    assert_eq!(
        reply["result"]["protocolVersion"],
        json!(PROTOCOL),
        "the handshake answered with a version this server does not implement: {reply}"
    );
    assert_eq!(
        reply["result"]["serverInfo"]["name"],
        json!("bathy"),
        "{reply}"
    );

    // And the session it opened is a *session*: the per-request `_meta` the
    // inline lifecycle requires is exactly what a handshake replaces, so a
    // Legacy client's next request carries none and must still be served.
    // This is the assertion that fails if the `_meta` validation in front of
    // the transport is applied to the whole connection rather than to the
    // request that opens it.
    let reply = server.request("tools/list", json!({}));
    assert!(
        reply.get("error").is_none(),
        "a handshaken client was then asked for the metadata the handshake \
         replaced: {reply}"
    );
    assert_eq!(reply["result"]["tools"].as_array().unwrap().len(), 11);
}

#[test]
fn the_tool_list_is_stable_ordered_and_cacheable() {
    let mut server = Server::start(64);
    let first = server.list_tools();

    let names: Vec<&str> = first["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, EXPECTED_TOOLS);
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(
        names, sorted,
        "the order must be intentional, not incidental"
    );

    assert!(
        first["ttlMs"].as_u64().is_some_and(|t| t > 0),
        "a list a client may cache must say for how long: {first:#}"
    );
    assert_eq!(first["cacheScope"], json!("public"), "{first:#}");

    let second = server.list_tools();
    assert_eq!(
        first["tools"], second["tools"],
        "two calls returned different lists"
    );
}

#[test]
fn nothing_shipped_speaks_the_deprecated_transport_or_assumes_a_stream_can_resume() {
    // Asserted over the crate's own manifest rather than over behaviour: the
    // HTTP transports, `Mcp-Session-Id` and stream resumability are absent
    // because the features that would compile them are not enabled, and that
    // is a stronger statement than "no test exercised them".
    let manifest = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../bathy-mcp/Cargo.toml"
    ))
    .expect("the server crate's manifest");
    let enabled = manifest
        .split("rmcp = ")
        .nth(1)
        .expect("the SDK dependency")
        .split(']')
        .next()
        .expect("its feature list");
    for forbidden in ["http", "sse", "client"] {
        assert!(
            !enabled.contains(forbidden),
            "the SDK feature list enables `{forbidden}`: {enabled}"
        );
    }
    assert!(enabled.contains("transport-io"), "{enabled}");
}

// ---------------------------------------------------------------------------
// The published schemas. Both absences, over the wire.
// ---------------------------------------------------------------------------

#[test]
fn exactly_eleven_tools_with_exactly_the_designed_names_are_advertised() {
    let mut server = Server::start(64);
    let mut names: Vec<String> = server
        .tools()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    assert_eq!(names, EXPECTED_TOOLS);
}

#[test]
fn no_advertised_input_schema_lets_an_agent_construct_a_command_line() {
    let mut server = Server::start(64);
    for tool in server.tools() {
        let name = tool["name"].as_str().unwrap();
        let schema = &tool["inputSchema"];
        assert_eq!(
            schema["type"],
            json!("object"),
            "{name} has no object schema"
        );
        assert!(
            schema.get("properties").is_some(),
            "{name} has no properties"
        );
        // Rendered whole, so a field hidden inside `$defs` -- a nested request
        // shape, a filter -- is covered too. Four such leaks have been found
        // in this project by looking at the whole document rather than at the
        // top level.
        let rendered = serde_json::to_string(schema).unwrap();
        for forbidden in [
            "\"command\"",
            "\"args\"",
            "\"flags\"",
            "\"argv\"",
            "\"raw\"",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "{name} exposes {forbidden}; agents must never construct command strings"
            );
        }
    }
}

#[test]
fn no_advertised_tool_accepts_an_inline_manifest_and_every_scope_taking_tool_names_a_path() {
    let scope_taking = [
        "scope.validate",
        "scan.preview",
        "scan.start",
        "scan.resume",
    ];
    let mut server = Server::start(64);
    for tool in server.tools() {
        let name = tool["name"].as_str().unwrap();
        let schema = &tool["inputSchema"];
        let rendered = serde_json::to_string(schema).unwrap();
        for forbidden in [
            "\"manifest_json\"",
            "\"manifest\"",
            "\"scope_manifest\"",
            "\"scope_id\"",
            "\"allowed_cidrs\"",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "{name} exposes {forbidden}: a caller that can pass a manifest can \
                 authorize itself"
            );
        }
        let names_a_path = schema["properties"]
            .as_object()
            .is_some_and(|p| p.contains_key("manifest_path"));
        assert_eq!(
            names_a_path,
            scope_taking.contains(&name),
            "{name} disagrees with the set of tools that take a manifest path"
        );
    }
}

#[test]
fn every_advertised_tool_declares_an_output_schema_and_explicit_annotations() {
    let mut server = Server::start(64);
    for tool in server.tools() {
        let name = tool["name"].as_str().unwrap();
        assert!(
            tool["outputSchema"].get("properties").is_some(),
            "{name} declares no usable outputSchema"
        );
        let annotations = tool["annotations"]
            .as_object()
            .unwrap_or_else(|| panic!("{name} carries no annotations"));
        for hint in [
            "readOnlyHint",
            "destructiveHint",
            "idempotentHint",
            "openWorldHint",
        ] {
            assert!(
                annotations.contains_key(hint),
                "{name} leaves {hint} unset. The default for an unannotated tool is \
                 already maximally cautious, so a safe posture here would be an \
                 accident rather than a decision"
            );
        }
    }
}

#[test]
fn the_three_tools_that_change_something_are_not_advertised_as_reads() {
    let mut server = Server::start(64);
    let tools = server.tools();

    for name in ["scan.start", "scan.resume"] {
        let a = &tool_named(&tools, name)["annotations"];
        assert_eq!(a["readOnlyHint"], json!(false), "{name}");
        assert_eq!(a["destructiveHint"], json!(true), "{name}");
        assert_eq!(
            a["openWorldHint"],
            json!(true),
            "{name} puts packets on someone else's network; saying otherwise \
             understates what this program does"
        );
    }
    let cancel = &tool_named(&tools, "scan.cancel")["annotations"];
    assert_eq!(cancel["readOnlyHint"], json!(false));
    assert_eq!(cancel["openWorldHint"], json!(false));

    for tool in &tools {
        let name = tool["name"].as_str().unwrap();
        if matches!(name, "scan.start" | "scan.resume" | "scan.cancel") {
            continue;
        }
        assert_eq!(tool["annotations"]["readOnlyHint"], json!(true), "{name}");
    }
}

#[test]
fn the_diff_tool_tells_an_agent_a_budget_change_alone_makes_it_say_it_cannot_tell() {
    // AC-5.37's disclosure half. This used to assert four keywords, and the
    // keywords survived rewriting the sentence they were meant to guard:
    // "is enough on its own" could become "may matter" and the conclusion
    // could be reversed, and `coverage_differs` still appeared elsewhere in
    // the paragraph. So the assertion is the *claim* -- the three clauses an
    // agent choosing between "nothing changed" and "we could not tell"
    // actually needs -- each as a contiguous run of words.
    let mut server = Server::start(64);
    let tools = server.tools();
    let description = tool_named(&tools, "result.diff")["description"]
        .as_str()
        .expect("result.diff carries a description")
        .to_string();
    // Rendered without the line breaks and emphasis the description carries,
    // so the claim is matched as a sentence rather than as a layout.
    let prose = description.replace(['\n', '*'], " ");
    let flattened: String = {
        let mut out = String::new();
        let mut spaced = false;
        for c in prose.chars() {
            if c.is_whitespace() {
                if !spaced {
                    out.push(' ');
                }
                spaced = true;
            } else {
                out.push(c);
                spaced = false;
            }
        }
        out
    };

    for clause in [
        // 1. A budget change *alone* is sufficient. This is the claim; the
        //    word doing the work is "enough on its own".
        "lowering a rate limit, raising a packet ceiling or extending a runtime cap \
         between the two runs is enough on its own",
        // 2. What that produces.
        "to make every one-sided endpoint undetermined and set the whole comparison to \
         `coverage_differs`",
        // 3. That it happens even when nothing about the endpoints changed --
        //    which is the part an agent would otherwise misread as a finding.
        "even though the two scans looked at exactly the same endpoints",
        // 4. And how to read the answer, stated as the two readings and which
        //    one is wrong.
        "read `coverage_differs` as \"the two runs were not the same authorization\", \
         never as \"the two runs did not cover the same ports\"",
    ] {
        assert!(
            flattened.contains(clause),
            "the advertised description no longer makes this claim:\n  {clause}\n\n\
             An agent choosing between \"nothing changed\" and \"we could not tell\" has \
             to be told that a budget change alone produces the second. Keyword presence \
             does not guard that -- this assertion exists because rewriting the sentence \
             and reversing its conclusion left the keywords intact.\n\n{flattened}"
        );
    }
}

// ---------------------------------------------------------------------------
// Results conform to the schemas that were declared for them.
// ---------------------------------------------------------------------------

#[test]
fn every_real_result_conforms_to_the_output_schema_its_own_tool_published() {
    let ip = local_ipv4();
    let scope = Scope::for_local(ip);
    let listener = Listener::bind(ip, true);
    let mut server = Server::start(64);
    let tools = server.tools();
    let schema_for = |name: &str| tool_named(&tools, name)["outputSchema"].clone();

    let started = server.call(
        "scan.start",
        json!({
            "manifest_path": scope.path(),
            "request": scan_request(&ip.to_string(), &listener.port(), "conformance"),
        }),
    );
    assert_conforms("scan.start", &schema_for("scan.start"), &started);
    let scan_id = started["handle"]["task_id"].as_str().unwrap().to_string();
    wait_for_terminal(&mut server, &scan_id);

    let digest = first_evidence_digest(&mut server, &scan_id);

    let cases: Vec<(&str, Value)> = vec![
        (
            "scope.validate",
            json!({ "manifest_path": scope.path(), "targets": [ip.to_string()] }),
        ),
        (
            "scan.preview",
            json!({
                "manifest_path": scope.path(),
                "request": scan_request(&ip.to_string(), &listener.port(), "preview"),
            }),
        ),
        ("scan.status", json!({ "scan_id": scan_id })),
        (
            "scan.events",
            json!({ "scan_id": scan_id, "after_sequence": 0, "limit": 5 }),
        ),
        ("result.query", json!({ "scan_id": scan_id })),
        (
            "result.diff",
            json!({ "before_scan_id": scan_id, "after_scan_id": scan_id }),
        ),
        ("evidence.get", json!({ "digest": digest })),
        ("fingerprint.explain", json!({ "rule_id": first_rule_id() })),
        ("scan.cancel", json!({ "scan_id": scan_id })),
    ];

    for (tool, arguments) in cases {
        let result = server.call(tool, arguments);
        assert_conforms(tool, &schema_for(tool), &result);
    }

    // `scan.resume` last: it is the one that would start work again.
    let resumed = server.call(
        "scan.resume",
        json!({ "manifest_path": scope.path(), "scan_id": scan_id }),
    );
    assert_conforms("scan.resume", &schema_for("scan.resume"), &resumed);
}

fn first_rule_id() -> String {
    let (code, stdout) = bathy(&["--json", "explain", "--list"]);
    assert_eq!(code, 0, "{stdout}");
    let first = stdout.lines().next().expect("this build has rules");
    let value: Value = serde_json::from_str(first).unwrap();
    value["rule_id"].as_str().unwrap().to_string()
}

// ---------------------------------------------------------------------------
// Behaviour.
// ---------------------------------------------------------------------------

#[test]
fn scan_start_returns_a_handle_immediately_rather_than_blocking_on_the_scan() {
    let ip = local_ipv4();
    let scope = Scope::for_local(ip);
    // A thousand ports, so a server that waited for completion could not
    // possibly answer inside the bound below.
    let mut server = Server::start(64);
    let began = Instant::now();
    let out = server.call(
        "scan.start",
        json!({
            "manifest_path": scope.path(),
            "request": {
                "targets": [ip.to_string()],
                "objective": "inventory_exposed_services",
                "ports": { "explicit": ["1-1000"] },
                "idempotency_key": "immediate",
                "max_packets_per_second": 5,
            },
        }),
    );
    let elapsed = began.elapsed();

    assert_eq!(out["policy_decision"], json!("approved"), "{out:#}");
    assert_eq!(out["handle"]["status"], json!("running"), "{out:#}");
    assert!(
        out["handle"]["plan_hash"]
            .as_str()
            .unwrap()
            .starts_with("blake3:"),
        "{out:#}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "scan.start took {elapsed:?}; at 5 packets per second a thousand ports cannot \
         have finished, so it blocked on completion"
    );
}

#[test]
fn an_out_of_scope_start_is_denied_and_creates_no_scan_and_sends_no_packet() {
    let ip = local_ipv4();
    let listener = Listener::bind(ip, false);
    // A manifest that authorizes somewhere else entirely.
    let scope = Scope::new(&["10.30.0.0/24"]);
    let mut server = Server::start(64);

    let result = server.call_raw(
        "scan.start",
        json!({
            "manifest_path": scope.path(),
            "request": scan_request(&ip.to_string(), &listener.port(), "denied"),
        }),
    );
    let out = &result["structuredContent"];
    assert_eq!(out["policy_decision"], json!("denied"), "{result:#}");
    assert_eq!(out["reason_code"], json!("target_out_of_scope"), "{out:#}");
    assert!(
        out.get("handle").is_none() || out["handle"].is_null(),
        "a denied start returned a task handle: {out:#}"
    );
    assert_eq!(
        result["isError"],
        json!(true),
        "an agent that reads a denial as success will retry it forever"
    );

    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        listener.accepts(),
        0,
        "a denied scan reached the listener it was refused permission to reach"
    );

    // No scan record either. The state directory holds nothing to ask about.
    let (code, _) = bathy(&[
        "--json",
        "--state-dir",
        &server.state_dir(),
        "scan",
        "status",
        "--scan",
        "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    ]);
    assert_eq!(code, 1, "a denied request must leave no scan behind");

    // The positive control: the same endpoint, authorized, is reached. Without
    // it the zero above would pass just as happily against an unreachable
    // listener.
    let allowed = Scope::for_local(ip);
    server.call(
        "scan.start",
        json!({
            "manifest_path": allowed.path(),
            "request": scan_request(&ip.to_string(), &listener.port(), "positive-control"),
        }),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while listener.accepts() == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        listener.accepts() >= 1,
        "the detector never detects anything: an authorized scan of the same endpoint \
         reached the listener 0 times, so the zero above means nothing"
    );
}

#[test]
fn repeating_a_start_with_the_same_key_and_plan_returns_the_same_scan() {
    let ip = local_ipv4();
    let scope = Scope::for_local(ip);
    let listener = Listener::bind(ip, false);
    let mut server = Server::start(64);
    let arguments = json!({
        "manifest_path": scope.path(),
        "request": scan_request(&ip.to_string(), &listener.port(), "same-key"),
    });

    let first = server.call("scan.start", arguments.clone());
    let second = server.call("scan.start", arguments);

    assert_eq!(
        first["handle"]["task_id"], second["handle"]["task_id"],
        "the same key and plan started a second scan"
    );
    assert_eq!(first["reused"], json!(false));
    assert_eq!(second["reused"], json!(true), "{second:#}");
}

#[test]
fn scan_events_pages_by_cursor_without_overlap_and_says_when_there_is_more() {
    let ip = local_ipv4();
    let scope = Scope::for_local(ip);
    let listener = Listener::bind(ip, true);
    let mut server = Server::start(64);

    let started = server.call(
        "scan.start",
        json!({
            "manifest_path": scope.path(),
            "request": {
                "targets": [ip.to_string()],
                "objective": "inventory_exposed_services",
                "ports": { "explicit": [format!("{}", listener.port()), "1-20"] },
                "idempotency_key": "paging",
            },
        }),
    );
    let scan_id = started["handle"]["task_id"].as_str().unwrap().to_string();
    wait_for_terminal(&mut server, &scan_id);

    let first = server.call(
        "scan.events",
        json!({ "scan_id": scan_id, "after_sequence": 0, "limit": 5 }),
    );
    let firsts: Vec<u64> = sequences(&first);
    assert_eq!(firsts.len(), 5, "{first:#}");
    assert_eq!(first["has_more"], json!(true), "{first:#}");

    let cursor = first["next_cursor"].as_u64().unwrap();
    assert_eq!(cursor, *firsts.last().unwrap());

    let second = server.call(
        "scan.events",
        json!({ "scan_id": scan_id, "after_sequence": cursor, "limit": 5 }),
    );
    let seconds = sequences(&second);
    assert!(!seconds.is_empty(), "{second:#}");
    assert!(
        seconds.iter().all(|s| !firsts.contains(s)),
        "pages overlapped: {firsts:?} then {seconds:?}"
    );

    // Reading past the end leaves the cursor alone rather than rewinding it.
    let end = server.call(
        "scan.events",
        json!({ "scan_id": scan_id, "after_sequence": 1_000_000, "limit": 5 }),
    );
    assert_eq!(end["events"], json!([]));
    assert_eq!(end["next_cursor"], json!(1_000_000));
    assert_eq!(end["has_more"], json!(false));
}

fn sequences(page: &Value) -> Vec<u64> {
    page["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["sequence"].as_u64().unwrap())
        .collect()
}

#[test]
fn evidence_get_returns_the_exact_bytes_a_finding_cited() {
    let ip = local_ipv4();
    let scope = Scope::for_local(ip);
    let listener = Listener::bind(ip, true);
    let mut server = Server::start(64);

    let started = server.call(
        "scan.start",
        json!({
            "manifest_path": scope.path(),
            "request": {
                "targets": [ip.to_string()],
                "objective": "inventory_exposed_services",
                "ports": { "explicit": [listener.port()] },
                "idempotency_key": "evidence",
                "service_detection": { "enabled": true, "intensity": 9 },
            },
        }),
    );
    let scan_id = started["handle"]["task_id"].as_str().unwrap().to_string();
    wait_for_terminal(&mut server, &scan_id);

    let digest = first_evidence_digest(&mut server, &scan_id);
    let out = server.call("evidence.get", json!({ "digest": digest }));

    let bytes = hex_decode(out["bytes_hex"].as_str().unwrap());
    assert!(
        !bytes.is_empty() && NGINX_RESPONSE.starts_with(&bytes[..bytes.len().min(17)]),
        "evidence.get returned bytes the finding did not cite: {:?}",
        String::from_utf8_lossy(&bytes)
    );
    assert_eq!(out["length"].as_u64().unwrap(), bytes.len() as u64);
    assert_eq!(out["truncated"], json!(false));

    // And it agrees with the command that fetches the same digest.
    let (code, stdout) = bathy(&[
        "--json",
        "--state-dir",
        &server.state_dir(),
        "evidence",
        "get",
        "--digest",
        &digest,
    ]);
    assert_eq!(code, 0, "{stdout}");
    let from_cli: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        from_cli["bytes_hex"], out["bytes_hex"],
        "the tool and the command disagree about the bytes behind one digest"
    );
    assert_eq!(from_cli["length"], out["length"]);

    let capped = server.call("evidence.get", json!({ "digest": digest, "max_bytes": 4 }));
    assert_eq!(capped["bytes_hex"].as_str().unwrap().len(), 8);
    assert_eq!(capped["truncated"], json!(true));
    assert_eq!(
        capped["length"], out["length"],
        "`length` is the stored length, not the returned one"
    );
}

#[test]
fn fingerprint_explain_returns_a_rationale_and_a_source_for_every_rule_this_build_has() {
    let (code, listing) = bathy(&["--json", "explain", "--list"]);
    assert_eq!(code, 0);
    let mut server = Server::start(64);
    let mut seen = 0;

    for line in listing.lines().filter(|l| !l.trim().is_empty()) {
        let rule: Value = serde_json::from_str(line).unwrap();
        let id = rule["rule_id"].as_str().unwrap();
        let out = server.call("fingerprint.explain", json!({ "rule_id": id }));
        assert!(!out["rationale"].as_str().unwrap().is_empty(), "{id}");
        assert!(
            !out["source"].as_str().unwrap().is_empty(),
            "{id} cites no source; an identification nobody can check is a guess"
        );
        // And it agrees with the command that explains the same rule.
        assert_eq!(out["source"], rule["source"], "{id}");
        assert_eq!(out["rationale"], rule["rationale"], "{id}");
        seen += 1;
    }
    assert!(seen > 0, "this build has no rules at all");
}

#[test]
fn cancel_and_resume_round_trip_through_the_tool_surface() {
    let ip = local_ipv4();
    let scope = Scope::for_local(ip);
    // The resumed run has to be shown to do *work*, not merely to return a
    // document saying it is running, and work means a packet. A listener
    // counting accepts is how the rest of this file measures that, and it is
    // the only measurement here that a stale cancel marker cannot fake.
    let listener = Listener::bind(ip, false);
    let mut server = Server::start(64);

    let started = server.call(
        "scan.start",
        json!({
            "manifest_path": scope.path(),
            "request": {
                "targets": [ip.to_string()],
                "objective": "inventory_exposed_services",
                // The listener's port is ephemeral, so it sorts after the
                // low range and is the last unit in the plan: work the
                // cancelled run cannot have reached at five packets per
                // second, and work the resumed run has to do. That ordering
                // is not assumed -- it is asserted below, before the resume.
                "ports": { "explicit": ["1-20", listener.port()] },
                "idempotency_key": "cancel-me",
                "max_packets_per_second": 5,
                // Off, so the run is paced by the rate limiter alone and a
                // probe's read timeout on the open port cannot stretch it.
                "service_detection": { "enabled": false, "intensity": 0 },
            },
        }),
    );
    let scan_id = started["handle"]["task_id"].as_str().unwrap().to_string();

    let cancelled = server.call("scan.cancel", json!({ "scan_id": scan_id }));
    assert_eq!(cancelled["cancellation_requested"], json!(true));
    assert_eq!(cancelled["resumable"], json!(true), "{cancelled:#}");

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let status = server.call("scan.status", json!({ "scan_id": scan_id }));
        if status["status"] == json!("cancelled") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the scan never reached `cancelled`; last status {status:#}. stderr:\n{}",
            server.diagnostics()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        listener.accepts(),
        0,
        "the cancelled run already reached the endpoint the resume is supposed to \
         reach, so the assertion below would pass without anything being resumed"
    );

    let resumed = server.call(
        "scan.resume",
        json!({ "manifest_path": scope.path(), "scan_id": scan_id }),
    );
    assert_eq!(resumed["status"], json!("running"), "{resumed:#}");
    assert_eq!(resumed["resumed"], json!(true), "{resumed:#}");
    assert!(
        resumed["resumed_from_unit"].as_u64().unwrap() < resumed["units_total"].as_u64().unwrap(),
        "a resume that starts past the end of the plan resumes nothing: {resumed:#}"
    );

    // And the resumed scan really runs, which is a different claim from the
    // document above and is the one that was missing. `scan.resume` clears
    // the cancel marker before spawning; without that clear the marker is
    // still on disk, `spawn_watcher` finds it on its very first look, and the
    // run is cancelled before it probes anything -- while still returning
    // exactly the `status: running, resumed: true` document asserted above.
    // Deleting both `bathy_engine::cancel::clear` calls used to leave every
    // test in this file passing.
    let deadline = Instant::now() + Duration::from_secs(30);
    while listener.accepts() == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        listener.accepts() >= 1,
        "the resumed scan reached the listener 0 times: it returned a `running` \
         document and then did nothing, which is what a stale cancel marker does. \
         stderr:\n{}",
        server.diagnostics()
    );

    // A cancel through the command line stops a scan this server started.
    let (code, _) = bathy(&[
        "--json",
        "--state-dir",
        &server.state_dir(),
        "scan",
        "cancel",
        "--scan",
        &scan_id,
    ]);
    assert_eq!(code, 0, "the two surfaces do not share a cancel protocol");
}

// ---------------------------------------------------------------------------
// The two surfaces answer the same question the same way.
//
// The plan's architecture says anything the MCP server can do, the CLI can
// do. That premise is what makes this surface auditable from a shell, and
// M5 Task 4's review found it false: six documents differed and four things
// the tools could do had no command-line spelling at all. The structural
// cause was that the only two whole-document comparisons covered exactly the
// two tools that had already been fixed, and every other comparison was
// field-by-field over the fields that happened to agree -- `evidence.get`
// compared `bytes_hex` and `length` and not `truncated`, which is the field
// that differed. A guard covering the instances already known.
//
// So the comparison below is **generated from the advertised tool list**.
// `parity_cases` matches on the name and has no wildcard arm that passes: a
// twelfth tool fails this test until somebody writes down how its
// subcommand answers the same question. And where the two surfaces differ on
// purpose, the difference is *declared* and asserted -- a field that stops
// differing fails just as loudly as one that starts.
// ---------------------------------------------------------------------------

/// How a tool's document and its subcommand's document are meant to relate.
enum Parity {
    /// Byte-for-byte the same JSON value.
    Identical,
    /// The command emits one JSON document per line where the tool returns a
    /// paging envelope. `array` names the tool field holding the same
    /// documents in the same order, and `envelope` is the exact set of extra
    /// top-level keys the tool's document is allowed to carry.
    LineStream {
        array: &'static str,
        envelope: &'static [&'static str],
    },
}

/// One question, asked of both surfaces.
struct Case {
    /// What the question is, for a failure message.
    what: &'static str,
    arguments: Value,
    argv: Vec<String>,
    parity: Parity,
}

/// Everything the cases below need to name a real scan in a real state
/// directory that both surfaces can read.
struct Fixture {
    state_dir: String,
    scope: String,
    scan_id: String,
    digest: String,
    rule_id: String,
    /// A second scan whose fold differs from `scan_id`'s only in confidence.
    /// See [`confidence_variant`].
    diff_after: String,
    request: Value,
    targets: String,
    ports: String,
    key: String,
}

impl Fixture {
    fn cli(&self, tail: &[&str]) -> Vec<String> {
        let mut argv = vec![
            "--json".to_string(),
            "--state-dir".to_string(),
            self.state_dir.clone(),
        ];
        argv.extend(tail.iter().map(|s| s.to_string()));
        argv
    }
}

/// The command line that asks the same question as `name`, and how the two
/// answers are meant to relate.
///
/// Returns more than one case where a tool takes an argument the command has
/// to be able to express: the filtered `result.query`, the capped
/// `evidence.get`, the bounded `scan.events`. Each of those is one of the
/// four things the tool surface could do and the command surface could not.
///
/// There is no wildcard arm. That is the whole structural point.
fn parity_cases(name: &str, f: &Fixture) -> Vec<Case> {
    let scan = json!({ "scan_id": f.scan_id });
    match name {
        "scope.validate" => vec![Case {
            what: "what a manifest authorizes",
            arguments: json!({ "manifest_path": f.scope, "targets": [f.targets] }),
            argv: f.cli(&[
                "scope",
                "validate",
                "--scope",
                &f.scope,
                "--targets",
                &f.targets,
            ]),
            parity: Parity::Identical,
        }],
        "scan.preview" => vec![Case {
            what: "what a request would do, without doing it",
            arguments: json!({
                "manifest_path": f.scope,
                "request": scan_request(&f.targets, &f.ports, "preview-not-an-attempt"),
            }),
            argv: f.cli(&[
                "scan",
                "preview",
                "--scope",
                &f.scope,
                "--targets",
                &f.targets,
                "--ports",
                &f.ports,
            ]),
            parity: Parity::Identical,
        }],
        // Asked with the fixture's own key and request, so both surfaces take
        // the reuse branch and neither starts anything. A *fresh* start mints
        // an identifier, so two fresh starts cannot be compared as documents
        // at all -- what makes them agree is that both call
        // `tools::scan::admit_into_store`, which is one implementation rather
        // than a claim. The reuse document exercises every field of
        // `ScanStartOutput` including the `reused` flag this command surface
        // used to report only as a sentence on standard error.
        "scan.start" => vec![Case {
            what: "an already-named scan, re-started",
            arguments: json!({ "manifest_path": f.scope, "request": f.request }),
            argv: f.cli(&[
                "scan",
                "start",
                "--scope",
                &f.scope,
                "--idempotency-key",
                &f.key,
                "--targets",
                &f.targets,
                "--ports",
                &f.ports,
            ]),
            parity: Parity::Identical,
        }],
        "scan.status" => vec![Case {
            what: "a scan's stored lifecycle record",
            arguments: scan,
            argv: f.cli(&["scan", "status", "--scan", &f.scan_id]),
            parity: Parity::Identical,
        }],
        "scan.events" => vec![
            Case {
                what: "a scan's event log",
                arguments: json!({ "scan_id": f.scan_id, "after_sequence": 0, "limit": 1000 }),
                argv: f.cli(&["scan", "events", "--scan", &f.scan_id, "--limit", "1000"]),
                parity: Parity::LineStream {
                    array: "events",
                    envelope: &["has_more", "next_cursor"],
                },
            },
            // `limit: 1` against a log with more than one event, so the bound
            // binds: a surface that ignored `--limit` would emit the rest and
            // the comparison would fail rather than agree for want of data.
            Case {
                what: "a bounded page of a scan's event log",
                arguments: json!({ "scan_id": f.scan_id, "after_sequence": 0, "limit": 1 }),
                argv: f.cli(&[
                    "scan", "events", "--scan", &f.scan_id, "--after", "0", "--limit", "1",
                ]),
                parity: Parity::LineStream {
                    array: "events",
                    envelope: &["has_more", "next_cursor"],
                },
            },
            // `--after 2`, not `--after 0`. The two cases above pass the
            // cursor's own default, so a surface that dropped `--after` on
            // the floor answered identically and survived the whole
            // workspace -- the same non-binding shape the `result.query`
            // filter controls below are about, and found by the same sweep.
            // Two events are skipped here, and the control below proves the
            // fixture's log is long enough for that to remove something.
            Case {
                what: "a scan's event log read from a cursor that is not the default",
                arguments: json!({ "scan_id": f.scan_id, "after_sequence": 2, "limit": 1000 }),
                argv: f.cli(&[
                    "scan", "events", "--scan", &f.scan_id, "--after", "2", "--limit", "1000",
                ]),
                parity: Parity::LineStream {
                    array: "events",
                    envelope: &["has_more", "next_cursor"],
                },
            },
        ],
        "scan.cancel" => vec![Case {
            what: "stopping a scan, and whether there is anything left to resume",
            arguments: scan,
            argv: f.cli(&["scan", "cancel", "--scan", &f.scan_id]),
            parity: Parity::Identical,
        }],
        // The fixture scan has run its plan out, so both surfaces take the
        // "nothing left to resume" branch and neither starts work -- one line
        // each, the same document, which is why `Identical` is the right
        // relation here. The branch that *does* start work is the one the
        // command runs to completion, and it prints this document first
        // followed by a run summary; that two-line shape is asserted
        // separately, at the end of this test, not by a `Parity` variant.
        // (An earlier draft of this comment named a `Parity::FirstLine`
        // variant. There is no such variant -- the enum has exactly
        // `Identical` and `LineStream` -- and there never was.)
        "scan.resume" => vec![Case {
            what: "resuming a scan with no unfinished units",
            arguments: json!({ "manifest_path": f.scope, "scan_id": f.scan_id }),
            argv: f.cli(&["scan", "resume", "--scope", &f.scope, "--scan", &f.scan_id]),
            parity: Parity::Identical,
        }],
        "result.query" => vec![
            Case {
                what: "a scan's fold",
                arguments: json!({ "scan_id": f.scan_id }),
                argv: f.cli(&["result", "query", "--scan", &f.scan_id]),
                parity: Parity::Identical,
            },
            // The question the review singled out: "endpoints identified with
            // confidence at least 0.8 on ports 1-1024". Every field of the
            // filter at once, so a field reachable from only one surface
            // fails here.
            Case {
                what: "a scan's fold, filtered on every field the filter has",
                arguments: json!({
                    "scan_id": f.scan_id,
                    "filter": {
                        "state": "open",
                        "service": "http",
                        "min_confidence": 0.8,
                        "port_range": { "low": 1, "high": 65535 },
                    },
                }),
                argv: f.cli(&[
                    "result",
                    "query",
                    "--scan",
                    &f.scan_id,
                    "--state",
                    "open",
                    "--service",
                    "http",
                    "--min-confidence",
                    "0.8",
                    "--port-range",
                    "1-65535",
                ]),
                parity: Parity::Identical,
            },
        ],
        "result.diff" => vec![
            Case {
                what: "two scans compared",
                arguments: json!({
                    "before_scan_id": f.scan_id,
                    "after_scan_id": f.diff_after,
                }),
                argv: f.cli(&[
                    "result",
                    "diff",
                    "--before",
                    &f.scan_id,
                    "--after",
                    &f.diff_after,
                ]),
                parity: Parity::Identical,
            },
            Case {
                what: "two scans compared, keeping confidence-only changes",
                arguments: json!({
                    "before_scan_id": f.scan_id,
                    "after_scan_id": f.diff_after,
                    "include_confidence_only": true,
                }),
                argv: f.cli(&[
                    "result",
                    "diff",
                    "--before",
                    &f.scan_id,
                    "--after",
                    &f.diff_after,
                    "--include-confidence-only",
                ]),
                parity: Parity::Identical,
            },
        ],
        "evidence.get" => vec![
            Case {
                what: "the bytes a finding cited",
                arguments: json!({ "digest": f.digest }),
                argv: f.cli(&["evidence", "get", "--digest", &f.digest]),
                parity: Parity::Identical,
            },
            Case {
                what: "a capped read of the bytes a finding cited",
                arguments: json!({ "digest": f.digest, "max_bytes": 4 }),
                argv: f.cli(&["evidence", "get", "--digest", &f.digest, "--max-bytes", "4"]),
                parity: Parity::Identical,
            },
        ],
        "fingerprint.explain" => vec![Case {
            what: "what a rule looks for and where the claim comes from",
            arguments: json!({ "rule_id": f.rule_id }),
            argv: f.cli(&["explain", &f.rule_id]),
            parity: Parity::Identical,
        }],
        other => panic!(
            "`{other}` is advertised as a tool and has no command-line comparison. \
             The plan's architecture says anything the MCP server can do the CLI can \
             do; a tool nobody wrote a comparison for is a tool nobody checked that \
             for. Add a case to `parity_cases`."
        ),
    }
}

/// The top-level keys on which two documents disagree, including keys present
/// in only one of them.
fn differing_keys(a: &Value, b: &Value) -> Vec<String> {
    let mut keys: Vec<String> = a
        .as_object()
        .into_iter()
        .flat_map(|m| m.keys().cloned())
        .chain(b.as_object().into_iter().flat_map(|m| m.keys().cloned()))
        .collect();
    keys.sort_unstable();
    keys.dedup();
    keys.into_iter().filter(|k| a[k] != b[k]).collect()
}

/// A second event log, identical to `scan_id`'s except that every
/// observation is less confident.
///
/// `result.diff` calls the difference between the two `confidence_only`,
/// which is the change class `include_confidence_only` decides the fate of.
/// Without it the two diff comparisons would be asked about a scan diffed
/// against itself, which has no changes at all -- so they would agree
/// whether or not the command surface passed the flag along, and the
/// comparison would prove nothing. It is written as a file in the same state
/// directory because that file is exactly what both surfaces read.
fn confidence_variant(state_dir: &str, scan_id: &str) -> String {
    let path = PathBuf::from(state_dir).join(format!("{scan_id}.jsonl"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("the fixture scan wrote no log at {path:?}: {e}"));
    let head = &scan_id[..scan_id.len() - 1];
    let last = scan_id.chars().last().unwrap();
    let variant = format!("{head}{}", if last == 'Z' { 'Y' } else { 'Z' });

    let mut rewritten = String::new();
    let mut observations = 0;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let mut event: Value = serde_json::from_str(line).expect("the log is JSONL");
        event["scan_id"] = json!(variant);
        if event["event_type"] == json!("service.observed") {
            event["observation"]["confidence"] = json!(0.5);
            observations += 1;
        }
        rewritten.push_str(&event.to_string());
        rewritten.push('\n');
    }
    assert!(
        observations > 0,
        "the fixture scan identified nothing, so there is no confidence to vary"
    );
    std::fs::write(
        PathBuf::from(state_dir).join(format!("{variant}.jsonl")),
        rewritten,
    )
    .expect("write the variant log");
    variant
}

fn json_lines(stdout: &str) -> Vec<Value> {
    stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("stdout line is not JSON ({e}): {line:?}"))
        })
        .collect()
}

#[test]
fn every_advertised_tool_and_its_subcommand_answer_the_same_question_the_same_way() {
    let ip = local_ipv4();
    let scope = Scope::for_local(ip);
    let listener = Listener::bind(ip, true);
    let mut server = Server::start(64);

    // One scan, run to completion, that every case below asks about. Both
    // surfaces read the same state directory, so a difference in the answer
    // is a difference in the surface and not in the question.
    let key = "parity";
    let request = json!({
        "targets": [ip.to_string()],
        "objective": "inventory_exposed_services",
        "ports": { "explicit": [listener.port()] },
        "idempotency_key": key,
        // The command surface's own defaults, spelled out: `plan_hash` covers
        // service detection, and the `scan.start` case below reaches the reuse
        // branch on both surfaces only if both describe the same plan.
        "service_detection": { "enabled": true, "intensity": 4 },
        "evidence_level": "headers",
    });
    let started = server.call(
        "scan.start",
        json!({ "manifest_path": scope.path(), "request": request }),
    );
    let scan_id = started["handle"]["task_id"].as_str().unwrap().to_string();
    wait_for_terminal(&mut server, &scan_id);

    let fixture = Fixture {
        diff_after: confidence_variant(&server.state_dir(), &scan_id),
        state_dir: server.state_dir(),
        scope: scope.path(),
        digest: first_evidence_digest(&mut server, &scan_id),
        rule_id: first_rule_id(),
        request: request.clone(),
        targets: ip.to_string(),
        ports: listener.port(),
        key: key.to_string(),
        scan_id,
    };

    let advertised: Vec<String> = server
        .tools()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    // Deliberately no assertion on the *count* here: the count is pinned by
    // `exactly_eleven_tools_with_exactly_the_designed_names_are_advertised`,
    // and if this test failed on the number first, the guard below -- that
    // every advertised tool has a comparison -- would never be the thing that
    // reported a twelfth tool nobody compared.

    let mut compared = 0;
    for name in &advertised {
        for case in parity_cases(name, &fixture) {
            let from_tool = server.call(name, case.arguments.clone());
            let argv: Vec<&str> = case.argv.iter().map(String::as_str).collect();
            let (code, stdout) = bathy(&argv);
            assert_eq!(code, 0, "{name} ({}): {argv:?}\n{stdout}", case.what);
            let lines = json_lines(&stdout);

            match case.parity {
                Parity::Identical => {
                    assert_eq!(
                        lines.len(),
                        1,
                        "{name} ({}): the command emitted {} documents where the tool \
                         returns one: {lines:#?}",
                        case.what,
                        lines.len()
                    );
                    assert_eq!(
                        from_tool,
                        lines[0],
                        "{name} and `{}` were asked {} against the same state and \
                         answered differently on {:?}. The premise that anything the \
                         server can do the CLI can do is what makes this surface \
                         auditable from a shell, and it decays silently.\n  \
                         tool: {from_tool:#}\n  cli:  {:#}",
                        argv.join(" "),
                        case.what,
                        differing_keys(&from_tool, &lines[0]),
                        lines[0],
                    );
                }
                Parity::LineStream { array, envelope } => {
                    // The envelope is the *declared* difference, and it is
                    // asserted in both directions: an extra field appearing on
                    // the tool's document fails here, and a declared field
                    // that stops existing fails here too.
                    let mut extra: Vec<&str> = from_tool
                        .as_object()
                        .expect("a paging document")
                        .keys()
                        .map(String::as_str)
                        .filter(|k| *k != array)
                        .collect();
                    extra.sort_unstable();
                    assert_eq!(
                        extra, envelope,
                        "{name} ({}): the paging envelope this command deliberately does \
                         not reproduce is declared as {envelope:?}; the tool's document \
                         carries {extra:?}. A new field is a new divergence, and it has \
                         to be decided rather than discovered.",
                        case.what
                    );
                    assert_eq!(
                        from_tool[array],
                        Value::Array(lines.clone()),
                        "{name} and `{}` disagree about the documents themselves, not \
                         merely their envelope ({})",
                        argv.join(" "),
                        case.what
                    );
                }
            }
            compared += 1;
        }
    }
    assert!(
        compared >= advertised.len(),
        "{compared} comparisons for {} tools",
        advertised.len()
    );

    // A control for the two `result.diff` cases above: the flag has to change
    // the tool's own answer, or the pair would agree whether or not the
    // command surface passed it along. It did not, when this was first
    // written -- both cases diffed a scan against itself, which has no
    // changes at all, and a mutation that dropped `--include-confidence-only`
    // on the floor survived.
    let dropped = server.call(
        "result.diff",
        json!({ "before_scan_id": fixture.scan_id, "after_scan_id": fixture.diff_after }),
    );
    let kept = server.call(
        "result.diff",
        json!({
            "before_scan_id": fixture.scan_id,
            "after_scan_id": fixture.diff_after,
            "include_confidence_only": true,
        }),
    );
    assert_ne!(
        dropped, kept,
        "`include_confidence_only` changed nothing about the tool's own answer, so \
         the two comparisons above prove nothing about the command that passes it"
    );

    // A control for the `--after 2` case above, the same shape as the filter
    // controls below: the cursor has to remove something from the tool's own
    // answer, or a command that ignored it would agree for want of data.
    let whole_log = server.call(
        "scan.events",
        json!({ "scan_id": fixture.scan_id, "after_sequence": 0, "limit": 1000 }),
    );
    let from_cursor = server.call(
        "scan.events",
        json!({ "scan_id": fixture.scan_id, "after_sequence": 2, "limit": 1000 }),
    );
    assert!(
        from_cursor["events"].as_array().unwrap().len()
            < whole_log["events"].as_array().unwrap().len(),
        "`after_sequence: 2` skipped nothing, so the comparison above proves nothing \
         about whether the command passes `--after`: {} vs {}",
        from_cursor["events"].as_array().unwrap().len(),
        whole_log["events"].as_array().unwrap().len()
    );

    // Controls for the filtered `result.query` case above -- **one per field
    // of the filter**, and this is the whole point of them.
    //
    // The combined case above passes `--state open --service http
    // --min-confidence 0.8 --port-range 1-65535` together and looks
    // exhaustive. It is not: the fixture's single endpoint satisfies all four
    // at once, so three of the four remove nothing, and a command surface
    // that dropped `--state`, `--service` or `--min-confidence` on the floor
    // produced a byte-identical document and survived the whole workspace.
    // That is the same defect the parity comparison itself was written to
    // fix -- a guard that covers the instances already known -- one level
    // down inside the fix. A fixture that satisfies every branch tests none
    // of them.
    //
    // So each field gets a value the fixture **excludes**, with `total == 0`
    // asserted against a non-zero unfiltered total first: proof the tool's
    // own answer narrowed, before the command is asked to reproduce it.
    let all = server.call("result.query", json!({ "scan_id": fixture.scan_id }));
    assert!(
        all["total"].as_u64().unwrap() > 0,
        "the fixture scan folded to no endpoints, so nothing below can be narrowed: {all:#}"
    );
    // `min_confidence` is asked of `diff_after` rather than the fixture scan:
    // that log is this test's own construction and every `service.observed`
    // in it carries confidence exactly 0.5 (see `confidence_variant`), so
    // 0.75 excludes it *by construction* rather than by whatever confidence
    // the interpreter happens to assign an nginx banner today.
    let narrowing: [(&str, &str, Value, Vec<&str>); 4] = [
        (
            "state",
            &fixture.scan_id,
            json!({ "state": "closed" }),
            vec!["--state", "closed"],
        ),
        (
            "service",
            &fixture.scan_id,
            json!({ "service": "ssh" }),
            vec!["--service", "ssh"],
        ),
        (
            "min_confidence",
            &fixture.diff_after,
            json!({ "min_confidence": 0.75 }),
            vec!["--min-confidence", "0.75"],
        ),
        (
            "port_range",
            &fixture.scan_id,
            json!({ "port_range": { "low": 1, "high": 1 } }),
            vec!["--port-range", "1-1"],
        ),
    ];
    for (field, scan_id, filter, flags) in narrowing {
        let narrowed = server.call(
            "result.query",
            json!({ "scan_id": scan_id, "filter": filter }),
        );
        assert!(
            narrowed["total_before_filter"].as_u64().unwrap() > 0,
            "`{field}`: the scan being filtered folded to nothing, so a `total` of 0 \
             below would prove nothing: {narrowed:#}"
        );
        assert_eq!(
            narrowed["total"],
            json!(0),
            "`{field}` narrowed nothing, so the comparison below proves nothing about \
             whether the command passes it: {narrowed:#}"
        );
        let mut tail = vec!["result", "query", "--scan", scan_id];
        tail.extend_from_slice(&flags);
        let argv = fixture.cli(&tail);
        let (code, stdout) = bathy(&argv.iter().map(String::as_str).collect::<Vec<_>>());
        assert_eq!(code, 0, "`{field}`: {stdout}");
        assert_eq!(
            json_lines(&stdout)[0],
            narrowed,
            "`{field}`: the command could not express the filter that narrowed the \
             tool's answer -- {argv:?}"
        );
    }

    // The one intended difference in *shape*, asserted rather than skipped.
    //
    // A fresh `scan.start` mints an identifier, so two fresh starts cannot be
    // compared as documents at all. What can be compared is the shape: the
    // command emits the tool's document first -- conforming to the schema the
    // tool published for it -- and then a run summary the tool has no
    // equivalent of, because the tool detaches a scheduler and this command
    // runs it to completion in its own process (AC-5.12).
    let tools = server.tools();
    let (code, stdout) = bathy(
        &fixture
            .cli(&[
                "scan",
                "start",
                "--scope",
                &fixture.scope,
                "--idempotency-key",
                "parity-fresh",
                "--targets",
                &fixture.targets,
                "--ports",
                &fixture.ports,
            ])
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    assert_eq!(code, 0, "{stdout}");
    let lines = json_lines(&stdout);
    assert_eq!(
        lines.len(),
        2,
        "a fresh start emits the tool's document and then its own run summary, \
         and nothing else: {lines:#?}"
    );
    assert_conforms(
        "scan.start",
        &tool_named(&tools, "scan.start")["outputSchema"],
        &lines[0],
    );
    assert_eq!(
        lines[0]["policy_decision"],
        json!("approved"),
        "{:#}",
        lines[0]
    );
    assert_eq!(lines[0]["reused"], json!(false), "{:#}", lines[0]);
    assert!(
        lines[1].get("units_completed").is_some() && lines[1].get("cancelled").is_some(),
        "the second document must be the run summary, which is the whole of what \
         this surface adds: {:#}",
        lines[1]
    );
}

#[test]
fn a_policy_denial_is_the_same_answer_and_the_exit_code_the_table_promises() {
    let ip = local_ipv4();
    let scope = Scope::for_local(ip);
    let mut server = Server::start(64);

    // A target the manifest does not cover is refused by both, with the same
    // code -- and on the command surface with the exit status the exit-code
    // table publishes, which is the half a document comparison cannot see.
    let refused = server.call_raw(
        "scope.validate",
        json!({ "manifest_path": scope.path(), "targets": ["8.8.8.8"] }),
    );
    assert_eq!(refused["isError"], json!(true));
    assert_eq!(
        refused["structuredContent"]["reason_code"],
        json!("target_out_of_scope")
    );
    let (code, stdout) = bathy(&[
        "--json",
        "--state-dir",
        &server.state_dir(),
        "scope",
        "validate",
        "--scope",
        &scope.path(),
        "--targets",
        "8.8.8.8",
    ]);
    assert_eq!(code, 2, "a policy denial is exit 2 on the command surface");
    let failure = json_lines(&stdout)
        .pop()
        .unwrap_or_else(|| panic!("a refusal must still be machine-readable: {stdout:?}"));
    // The two surfaces carry the code in different envelopes on purpose --
    // this one signals refusal with an exit status and a failure document,
    // that one with `isError` and a structured result -- but the code itself
    // is the engine's, on both, which is what an operator reproducing an
    // agent's refusal actually reads.
    assert_eq!(failure["error"], json!("policy_denied"), "{failure}");
    assert_eq!(
        failure["reason_code"], refused["structuredContent"]["reason_code"],
        "the two surfaces refused the same request with different codes"
    );

    // And the same for a start the manifest does not authorize: exit 2, the
    // engine's own code, on both.
    let elsewhere = Scope::new(&["10.30.0.0/24"]);
    let denied = server.call_raw(
        "scan.preview",
        json!({
            "manifest_path": elsewhere.path(),
            "request": scan_request(&ip.to_string(), "80", "denied-preview"),
        }),
    );
    assert_eq!(
        denied["structuredContent"]["reason_code"],
        json!("target_out_of_scope"),
        "{denied:#}"
    );
    let (code, stdout) = bathy(&[
        "--json",
        "--state-dir",
        &server.state_dir(),
        "scan",
        "preview",
        "--scope",
        &elsewhere.path(),
        "--targets",
        &ip.to_string(),
        "--ports",
        "80",
    ]);
    assert_eq!(code, 2, "{stdout}");
    assert_eq!(
        json_lines(&stdout).pop().unwrap()["reason_code"],
        json!("target_out_of_scope")
    );
}

// ---------------------------------------------------------------------------
// Refusals are typed answers, not panics and not prose.
// ---------------------------------------------------------------------------

#[test]
fn every_refusal_an_agent_can_provoke_is_a_typed_error_it_can_act_on() {
    let ip = local_ipv4();
    let scope = Scope::for_local(ip);
    let mut server = Server::start(64);
    let absent = "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV";

    let cases: Vec<(&str, Value, &str)> = vec![
        ("scan.status", json!({ "scan_id": absent }), "no_such_scan"),
        (
            "scan.events",
            json!({ "scan_id": absent, "after_sequence": 0, "limit": 5 }),
            "no_such_scan_log",
        ),
        ("scan.cancel", json!({ "scan_id": absent }), "no_such_scan"),
        (
            "evidence.get",
            json!({ "digest": format!("blake3:{}", "0".repeat(64)) }),
            "no_such_evidence",
        ),
        (
            "fingerprint.explain",
            json!({ "rule_id": "no.such.rule" }),
            "no_such_rule",
        ),
        (
            "scope.validate",
            json!({ "manifest_path": "/no/such/manifest.json" }),
            "scope_unreadable",
        ),
        (
            "scan.resume",
            json!({ "manifest_path": scope.path(), "scan_id": absent }),
            "no_such_scan",
        ),
        // A malformed cursor: the schema declares 1..=1000, so a caller that
        // ignores it is told which field and which bound.
        (
            "scan.events",
            json!({ "scan_id": absent, "after_sequence": 0, "limit": 0 }),
            "bad_limit",
        ),
        // Arguments that are not the declared shape at all.
        (
            "scan.status",
            json!({ "scan_id": "not-an-identifier" }),
            "bad_arguments",
        ),
        (
            "scan.preview",
            json!({ "manifest_path": scope.path() }),
            "bad_arguments",
        ),
    ];

    for (tool, arguments, expected) in cases {
        let failure = server.call_expecting_failure(tool, arguments.clone());
        assert_eq!(
            failure["error"],
            json!(expected),
            "{tool} {arguments} answered `{}` rather than `{expected}`",
            failure["error"]
        );
        assert!(
            failure["detail"].as_str().is_some_and(|d| !d.is_empty()),
            "{tool} refused with no explanation: {failure}"
        );
    }

    // An expired manifest refuses a start, and refuses it before anything is
    // created.
    let expired = server.call_raw(
        "scan.start",
        json!({
            "manifest_path": scope.expired(),
            "request": scan_request(&ip.to_string(), "80", "expired"),
        }),
    );
    assert_eq!(
        expired["structuredContent"]["reason_code"],
        json!("scope_expired"),
        "{expired:#}"
    );

    // An unknown tool is the one condition that is genuinely unroutable, so
    // it is the one that gets a protocol error rather than a tool result.
    let reply = server.request(
        "tools/call",
        json!({ "_meta": Server::meta("harness"), "name": "scan.everything", "arguments": {} }),
    );
    assert!(
        reply["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("scan.everything")),
        "{reply}"
    );

    // The server is still answering after all of that.
    assert_eq!(server.tools().len(), 11);
}

#[test]
fn a_resume_is_re_authorized_and_says_which_manifest_rule_refused_it() {
    // The security-relevant half of `scan.resume`: a resume is new network
    // activity, so the manifest is evaluated again rather than trusted from
    // when the scan was admitted. `every_refusal_an_agent_can_provoke...`
    // covered this tool only for `no_such_scan`, and a mutation that replaced
    // the propagated reason code and detail with literals survived -- the
    // typed answer on the re-authorization path was unasserted, while the
    // equivalent `scan.start` path was covered.
    let ip = local_ipv4();
    let scope = Scope::for_local(ip);
    let mut server = Server::start(64);

    let started = server.call(
        "scan.start",
        json!({
            "manifest_path": scope.path(),
            "request": scan_request(&ip.to_string(), "1-4", "resume-denials"),
        }),
    );
    let scan_id = started["handle"]["task_id"].as_str().unwrap().to_string();
    // Finished first, so the positive control at the end is not racing the
    // running scan's own writer for the event log.
    wait_for_terminal(&mut server, &scan_id);

    // A manifest that has lapsed since the scan was admitted.
    let expired = server.call_expecting_failure(
        "scan.resume",
        json!({ "manifest_path": scope.expired(), "scan_id": scan_id }),
    );
    assert_eq!(expired["error"], json!("scope_expired"), "{expired}");
    assert!(
        expired["detail"]
            .as_str()
            .is_some_and(|d| d.contains(SCOPE_ID)),
        "the refusal must name the manifest that refused: {expired}"
    );

    // A manifest that has been narrowed to somewhere else entirely.
    let elsewhere = Scope::new(&["10.30.0.0/24"]);
    let narrowed = server.call_expecting_failure(
        "scan.resume",
        json!({ "manifest_path": elsewhere.path(), "scan_id": scan_id }),
    );
    assert_eq!(
        narrowed["error"],
        json!("target_out_of_scope"),
        "{narrowed}"
    );
    assert!(
        narrowed["detail"]
            .as_str()
            .is_some_and(|d| d.contains(&ip.to_string())),
        "the refusal must name the address that is no longer authorized: {narrowed}"
    );

    // And the manifest that still authorizes it does not refuse, so the two
    // refusals above are about the manifest and not about the scan.
    let allowed = server.call(
        "scan.resume",
        json!({ "manifest_path": scope.path(), "scan_id": scan_id }),
    );
    assert_eq!(allowed["scan_id"], json!(scan_id), "{allowed:#}");
}

// ---------------------------------------------------------------------------
// The approval gate.
// ---------------------------------------------------------------------------

/// Start a server whose threshold is below any scan, and a listener that
/// counts anything it manages to send.
fn approval_fixture() -> (Server, Scope, Listener, Ipv4Addr) {
    let ip = local_ipv4();
    let scope = Scope::for_local(ip);
    let listener = Listener::bind(ip, false);
    // Zero: every scan is above it, so the gate is exercised by a one-address
    // request and no test needs to enumerate a /24 to reach it.
    let server = Server::start(0);
    (server, scope, listener, ip)
}

fn start_arguments(scope: &Scope, ip: Ipv4Addr, listener: &Listener, key: &str) -> Value {
    json!({
        "manifest_path": scope.path(),
        "request": scan_request(&ip.to_string(), &listener.port(), key),
    })
}

fn approved() -> Value {
    json!({ "approval": { "action": "accept", "content": { "approved": true } } })
}

fn assert_nothing_happened(server: &mut Server, listener: &Listener) {
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        listener.accepts(),
        0,
        "a rejected approval path emitted a packet"
    );
    let (code, stdout) = bathy(&[
        "--json",
        "--state-dir",
        &server.state_dir(),
        "scan",
        "status",
        "--scan",
        "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    ]);
    assert_eq!(code, 1, "{stdout}");
}

#[test]
fn a_scan_above_the_threshold_asks_a_human_and_starts_nothing() {
    let (mut server, scope, listener, ip) = approval_fixture();
    let result = server.call_raw(
        "scan.start",
        start_arguments(&scope, ip, &listener, "needs-approval"),
    );

    assert_eq!(
        result["resultType"],
        json!("input_required"),
        "the specification's approval mechanism is a Multi Round-Trip result, not a \
         bespoke status field no generic client would act on: {result:#}"
    );
    let requests = result["inputRequests"]
        .as_object()
        .unwrap_or_else(|| panic!("no inputRequests: {result:#}"));
    assert!(
        requests
            .values()
            .any(|r| r["method"] == "elicitation/create"),
        "approval must be carried as an embedded elicitation/create: {result:#}"
    );
    assert!(
        result["requestState"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "{result:#}"
    );
    assert!(
        result.get("structuredContent").is_none(),
        "an interrupted call has no result yet: {result:#}"
    );

    assert_nothing_happened(&mut server, &listener);
}

#[test]
fn a_client_that_declared_no_elicitation_is_refused_with_32021_rather_than_asked_anyway() {
    // Two normative sentences meet here. MRTR §Server Requirements: a server
    // MUST NOT send an `inputRequests` the client has not declared support
    // for. The base protocol: a request that cannot be processed without a
    // capability the client lacks MUST be answered `-32021` naming it.
    //
    // The safe answer is also the required one. The threshold has been
    // crossed and nobody has approved, so the scan must not begin -- and the
    // host is told the one thing it could change, rather than handed an
    // `input_required` it structurally cannot answer.
    let (mut server, scope, listener, ip) = approval_fixture();
    let reply = server.request(
        "tools/call",
        json!({
            "_meta": Server::meta_declaring("no-elicitation", json!({})),
            "name": "scan.start",
            "arguments": start_arguments(&scope, ip, &listener, "cannot-be-asked"),
        }),
    );

    assert_eq!(
        reply["error"]["code"],
        json!(-32021),
        "a client that cannot answer an elicitation must be told so, not sent one: {reply:#}"
    );
    assert!(
        reply["error"]["data"]["requiredCapabilities"]["elicitation"].is_object(),
        "the refusal must name the capability that is missing: {reply:#}"
    );
    assert!(
        reply.get("result").is_none(),
        "an error and a result are not both answers to one call: {reply:#}"
    );

    // And nothing was started: no packet, no scan record. A refusal that
    // began the scan anyway would be the scope bypass this gate exists to
    // prevent, wearing an error code.
    assert_nothing_happened(&mut server, &listener);

    // The connection survives it, and a client that *can* be asked still is.
    let asked = server.call_raw(
        "scan.start",
        start_arguments(&scope, ip, &listener, "can-be-asked"),
    );
    assert_eq!(asked["resultType"], json!("input_required"), "{asked:#}");
}

#[test]
fn a_scan_that_needs_no_approval_is_not_refused_for_want_of_a_capability_it_never_uses() {
    // The mirror image of the test above, and the reason the capability check
    // sits at the point the challenge would be minted rather than at the top
    // of the call: below the threshold nobody is asked, so nothing requires
    // the client to be askable. A blanket refusal of `scan.start` would pass
    // the test above and deny work the specification does not require a
    // capability for.
    let ip = local_ipv4();
    let scope = Scope::for_local(ip);
    let listener = Listener::bind(ip, false);
    let mut server = Server::start(64);

    let reply = server.request(
        "tools/call",
        json!({
            "_meta": Server::meta_declaring("no-elicitation", json!({})),
            "name": "scan.start",
            "arguments": start_arguments(&scope, ip, &listener, "under-threshold-no-elicitation"),
        }),
    );
    assert!(reply.get("error").is_none(), "{reply:#}");
    assert_eq!(
        reply["result"]["resultType"],
        json!("complete"),
        "{reply:#}"
    );
    assert_eq!(
        reply["result"]["structuredContent"]["policy_decision"],
        json!("approved"),
        "{reply:#}"
    );
}

#[test]
fn retrying_with_the_approval_and_the_request_state_starts_the_scan() {
    let (mut server, scope, listener, ip) = approval_fixture();
    let arguments = start_arguments(&scope, ip, &listener, "approve-me");
    let pending = server.call_raw("scan.start", arguments.clone());
    let state = pending["requestState"].as_str().unwrap().to_string();

    let result = server.retry_with_inputs("harness", "scan.start", arguments, &state, approved());
    assert_eq!(result["resultType"], json!("complete"), "{result:#}");
    let out = &result["structuredContent"];
    assert_eq!(out["policy_decision"], json!("approved"), "{out:#}");
    assert_eq!(out["handle"]["status"], json!("running"), "{out:#}");

    // And it really started: the listener sees it.
    let deadline = Instant::now() + Duration::from_secs(20);
    while listener.accepts() == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        listener.accepts() >= 1,
        "an approved scan reached nothing, so the refusals above prove nothing"
    );
}

#[test]
fn a_forged_request_state_cannot_authorize_a_scan() {
    let (mut server, scope, listener, ip) = approval_fixture();
    let arguments = start_arguments(&scope, ip, &listener, "forge");
    let pending = server.call_raw("scan.start", arguments.clone());
    let state = pending["requestState"].as_str().unwrap().to_string();

    // One byte of the authenticated blob.
    let mut forged: Vec<char> = state.chars().collect();
    let body = 4; // past the `rs1.` version prefix
    forged[body] = if forged[body] == 'A' { 'B' } else { 'A' };
    let forged: String = forged.into_iter().collect();
    assert_ne!(forged, state, "the fixture must actually differ");

    let failure = {
        let result =
            server.retry_with_inputs("harness", "scan.start", arguments, &forged, approved());
        assert_eq!(result["isError"], json!(true), "{result:#}");
        first_text(&result)
    };
    assert!(
        failure.contains("approval_unverifiable"),
        "a forged token was not refused as one: {failure}"
    );
    assert_nothing_happened(&mut server, &listener);
}

#[test]
fn a_replayed_request_state_cannot_authorize_a_second_scan() {
    let (mut server, scope, listener, ip) = approval_fixture();
    let arguments = start_arguments(&scope, ip, &listener, "replay");
    let pending = server.call_raw("scan.start", arguments.clone());
    let state = pending["requestState"].as_str().unwrap().to_string();

    let first = server.retry_with_inputs(
        "harness",
        "scan.start",
        arguments.clone(),
        &state,
        approved(),
    );
    assert_ne!(first["isError"], json!(true), "{first:#}");

    let second = server.retry_with_inputs("harness", "scan.start", arguments, &state, approved());
    assert_eq!(second["isError"], json!(true), "{second:#}");
    assert!(
        first_text(&second).contains("approval_already_used"),
        "an approval authorizes one scan, not a standing grant: {}",
        first_text(&second)
    );
}

#[test]
fn a_request_state_issued_to_one_caller_cannot_be_redeemed_by_another() {
    let (mut server, scope, listener, ip) = approval_fixture();
    let arguments = start_arguments(&scope, ip, &listener, "cross-principal");

    // There is no handshake in this revision, so the caller's identity rides
    // in each request's own metadata -- which is exactly what makes this
    // testable on one connection.
    let pending = server.call_as("caller-a", "scan.start", arguments.clone());
    let state = pending["requestState"].as_str().unwrap().to_string();

    let result = server.retry_with_inputs("caller-b", "scan.start", arguments, &state, approved());
    assert_eq!(result["isError"], json!(true), "{result:#}");
    assert!(
        first_text(&result).contains("approval_unverifiable"),
        "{}",
        first_text(&result)
    );
    assert_nothing_happened(&mut server, &listener);
}

#[test]
fn an_approval_for_one_scan_cannot_authorize_a_wider_one() {
    let (mut server, scope, listener, ip) = approval_fixture();
    let narrow = start_arguments(&scope, ip, &listener, "narrow");
    let pending = server.call_raw("scan.start", narrow);
    let state = pending["requestState"].as_str().unwrap().to_string();

    // The same key, the same manifest, a wider port range: a human approved
    // one port and this asks for four hundred.
    let wider = json!({
        "manifest_path": scope.path(),
        "request": {
            "targets": [ip.to_string()],
            "objective": "inventory_exposed_services",
            "ports": { "explicit": ["1-400"] },
            "idempotency_key": "narrow",
        },
    });

    let result = server.retry_with_inputs("harness", "scan.start", wider, &state, approved());
    assert_eq!(result["isError"], json!(true), "{result:#}");
    assert!(
        first_text(&result).contains("approval_unverifiable"),
        "an approval is bound to the request it was issued for: {}",
        first_text(&result)
    );
    assert_nothing_happened(&mut server, &listener);
}

#[test]
fn a_declined_or_missing_answer_starts_nothing_however_valid_the_token() {
    let (mut server, scope, listener, ip) = approval_fixture();

    for (name, responses) in [
        ("declined", json!({ "approval": { "action": "decline" } })),
        ("cancelled", json!({ "approval": { "action": "cancel" } })),
        (
            "accepted but answered no",
            json!({ "approval": { "action": "accept", "content": { "approved": false } } }),
        ),
        ("empty", json!({})),
    ] {
        let arguments = start_arguments(&scope, ip, &listener, name);
        let pending = server.call_raw("scan.start", arguments.clone());
        let state = pending["requestState"].as_str().unwrap().to_string();
        let result =
            server.retry_with_inputs("harness", "scan.start", arguments, &state, responses);
        assert_eq!(result["isError"], json!(true), "{name}: {result:#}");
        assert!(
            first_text(&result).contains("approval_declined"),
            "{name}: {}",
            first_text(&result)
        );
    }
    assert_nothing_happened(&mut server, &listener);
}

#[test]
fn the_approval_threshold_is_server_configuration_and_not_settable_from_a_request() {
    let (mut server, scope, listener, ip) = approval_fixture();

    // Every spelling an agent might reach for. The input schema refuses
    // unknown fields, so each is rejected before a plan exists -- which is
    // the mechanism: there is no field to set, not a check that it was not.
    for field in [
        "approval_threshold_targets",
        "approval_threshold",
        "threshold",
        "skip_approval",
        "auto_approve",
    ] {
        let mut arguments = start_arguments(&scope, ip, &listener, "raise-my-own");
        arguments[field] = json!(1_000_000);
        let failure = server.call_expecting_failure("scan.start", arguments);
        assert_eq!(
            failure["error"],
            json!("bad_arguments"),
            "{field}: {failure}"
        );
    }

    // And the gate still fires for an ordinary request.
    let result = server.call_raw(
        "scan.start",
        start_arguments(&scope, ip, &listener, "ordinary"),
    );
    assert_eq!(result["resultType"], json!("input_required"), "{result:#}");
    assert_nothing_happened(&mut server, &listener);
}

#[test]
fn a_scan_at_or_below_the_threshold_needs_no_approval() {
    // The mirror image, so the gate above is not passing merely because
    // everything is refused.
    let ip = local_ipv4();
    let scope = Scope::for_local(ip);
    let listener = Listener::bind(ip, false);
    let mut server = Server::start(64);

    let result = server.call_raw(
        "scan.start",
        start_arguments(&scope, ip, &listener, "under-threshold"),
    );
    assert_eq!(
        result["resultType"],
        json!("complete"),
        "a one-address scan under a sixty-four address threshold must not ask: {result:#}"
    );
}
