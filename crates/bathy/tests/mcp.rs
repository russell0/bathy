//! The MCP tool surface, driven over a real stdio transport.
//!
//! Every test here spawns the shipped `bathy` binary as `bathy serve mcp` and
//! speaks newline-delimited JSON-RPC to its standard input and output. Nothing
//! calls a handler function: a tool surface exercised through its internals is
//! not tested where it is used, and the protocol facts these tests are about
//! -- inline version negotiation, `server/discover`, `-32022`, the Multi
//! Round-Trip approval flow -- are properties of the wire, not of a function.
//!
//! The client is written out by hand rather than taken from the SDK, so a
//! server that only works against its own SDK's client would fail here.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_bathy");
const SCOPE_ID: &str = "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV";
const PROTOCOL: &str = "2026-07-28";
const NGINX_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nServer: nginx/1.26.0\r\nConnection: close\r\n\r\n<html></html>";

/// The eleven, in the order `tools/list` must return them.
const EXPECTED_TOOLS: &[&str] = &[
    "evidence.get",
    "fingerprint.explain",
    "result.diff",
    "result.query",
    "scan.cancel",
    "scan.events",
    "scan.preview",
    "scan.resume",
    "scan.start",
    "scan.status",
    "scope.validate",
];

// ---------------------------------------------------------------------------
// Fixtures, shared in shape with the command-line suite deliberately: the two
// surfaces are tested against the same manifests so a divergence shows up as
// a difference in the answer rather than a difference in the question.
// ---------------------------------------------------------------------------

fn local_ipv4() -> Ipv4Addr {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("bind an ephemeral UDP socket");
    socket
        .connect("192.0.2.1:9")
        .expect("a default route is required to run these tests");
    match socket.local_addr().expect("local_addr").ip() {
        IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => v4,
        other => panic!(
            "no routable IPv4 address on this machine (got {other}); these tests need \
             one because loopback is refused by every shipped manifest"
        ),
    }
}

struct Scope {
    _dir: tempfile::TempDir,
    path: PathBuf,
    expired: PathBuf,
}

impl Scope {
    fn new(allowed: &[&str]) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scope.json");
        let doc = json!({
            "id": SCOPE_ID,
            "description": "bathy MCP test fixture",
            "not_after": "2099-01-01T00:00:00.000Z",
            "allowed_cidrs": allowed,
            "denied_cidrs": [],
            "budget_ceiling": {
                "maximum_packets": 1_000_000,
                "maximum_runtime_seconds": 3600,
                "maximum_packets_per_second": 20_000,
            },
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&doc).unwrap()).expect("write scope");

        let expired = dir.path().join("expired.json");
        let mut lapsed = doc.clone();
        lapsed["not_after"] = json!("2000-01-01T00:00:00.000Z");
        std::fs::write(&expired, serde_json::to_vec_pretty(&lapsed).unwrap()).unwrap();

        Self {
            _dir: dir,
            path,
            expired,
        }
    }

    fn for_local(ip: Ipv4Addr) -> Self {
        Self::new(&[&format!("{ip}/32")])
    }

    fn path(&self) -> String {
        self.path.to_str().unwrap().to_string()
    }

    fn expired(&self) -> String {
        self.expired.to_str().unwrap().to_string()
    }
}

/// Counts accepted connections, so "no packet was emitted" can be measured
/// rather than asserted about the code that would have emitted one.
struct Listener {
    port: u16,
    accepts: Arc<AtomicUsize>,
}

impl Listener {
    fn bind(ip: Ipv4Addr, serve_http: bool) -> Self {
        let listener = TcpListener::bind((ip, 0)).expect("bind a listener on this machine");
        let port = listener.local_addr().unwrap().port();
        let accepts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&accepts);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                counter.fetch_add(1, Ordering::SeqCst);
                if !serve_http {
                    continue;
                }
                std::thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
                    let mut buf = [0u8; 1024];
                    if let Ok(n) = stream.read(&mut buf)
                        && n >= 4
                        && &buf[..4] == b"GET "
                    {
                        let _ = stream.write_all(NGINX_RESPONSE);
                    }
                });
            }
        });
        Self { port, accepts }
    }

    fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    fn port(&self) -> String {
        self.port.to_string()
    }
}

// ---------------------------------------------------------------------------
// The client.
// ---------------------------------------------------------------------------

struct Server {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    stderr: Arc<Mutex<String>>,
    next_id: u64,
    state: tempfile::TempDir,
}

impl Server {
    fn start(approval_threshold: u64) -> Self {
        Self::start_in(tempfile::tempdir().expect("tempdir"), approval_threshold)
    }

    fn start_in(state: tempfile::TempDir, approval_threshold: u64) -> Self {
        let mut child = Command::new(BIN)
            .args([
                "--state-dir",
                state.path().to_str().unwrap(),
                "serve",
                "mcp",
                "--approval-threshold-targets",
                &approval_threshold.to_string(),
            ])
            .env_remove("BATHY_STATE_DIR")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the bathy binary runs");

        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        // Drained on a thread so a chatty server cannot fill the pipe and
        // deadlock the test it is meant to be diagnosing.
        let stderr_buffer = Arc::new(Mutex::new(String::new()));
        let sink = Arc::clone(&stderr_buffer);
        let mut err = child.stderr.take().expect("stderr");
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = err.read(&mut buf) {
                if n == 0 {
                    return;
                }
                sink.lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&buf[..n]));
            }
        });

        Self {
            child,
            stdin,
            stdout,
            stderr: stderr_buffer,
            next_id: 0,
            state,
        }
    }

    fn state_dir(&self) -> String {
        self.state.path().to_str().unwrap().to_string()
    }

    fn diagnostics(&self) -> String {
        self.stderr.lock().unwrap().clone()
    }

    /// The per-request metadata a Modern client sends. There is no handshake
    /// in this revision: the version and the client's capabilities ride in
    /// every request.
    fn meta(client: &str) -> Value {
        json!({
            "io.modelcontextprotocol/protocolVersion": PROTOCOL,
            "io.modelcontextprotocol/clientInfo": { "name": client, "version": "0.0.0" },
            "io.modelcontextprotocol/clientCapabilities": { "elicitation": {} },
        })
    }

    /// Send one request and read the reply that matches its id.
    fn request(&mut self, method: &str, mut params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        if params.is_null() {
            params = json!({});
        }
        let message = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        writeln!(self.stdin, "{message}").expect("write a request");
        self.stdin.flush().expect("flush");

        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            assert!(
                Instant::now() < deadline,
                "no reply to {method} within 30s. A server built for the session-based \
                 protocol waits for `initialize` and never answers. stderr:\n{}",
                self.diagnostics()
            );
            let mut line = String::new();
            let read = self.stdout.read_line(&mut line).unwrap_or_else(|e| {
                panic!(
                    "reading a reply to {method}: {e}. stderr:\n{}",
                    self.diagnostics()
                )
            });
            assert!(
                read > 0,
                "the server closed its output without answering {method}. stderr:\n{}",
                self.diagnostics()
            );
            if line.trim().is_empty() {
                continue;
            }
            let value: Value = serde_json::from_str(line.trim()).unwrap_or_else(|e| {
                panic!("stdout carried something that is not a protocol message: {e}\n{line}")
            });
            // Notifications carry no id and are not the answer.
            if value.get("id").and_then(Value::as_u64) == Some(id) {
                return value;
            }
        }
    }

    fn list_tools(&mut self) -> Value {
        let reply = self.request("tools/list", json!({ "_meta": Self::meta("harness") }));
        reply["result"].clone()
    }

    fn tools(&mut self) -> Vec<Value> {
        self.list_tools()["tools"].as_array().cloned().unwrap()
    }

    /// A `tools/call`, returning the whole result object so a test can see
    /// `resultType`, `isError` and `structuredContent`.
    fn call_raw(&mut self, tool: &str, arguments: Value) -> Value {
        self.call_as("harness", tool, arguments)
    }

    fn call_as(&mut self, client: &str, tool: &str, arguments: Value) -> Value {
        let reply = self.request(
            "tools/call",
            json!({
                "_meta": Self::meta(client),
                "name": tool,
                "arguments": arguments,
            }),
        );
        assert!(
            reply.get("error").is_none(),
            "{tool} answered with a protocol error rather than a tool result: {reply}"
        );
        reply["result"].clone()
    }

    /// The retry half of a Multi Round-Trip exchange.
    fn retry_with_inputs(
        &mut self,
        client: &str,
        tool: &str,
        arguments: Value,
        request_state: &str,
        responses: Value,
    ) -> Value {
        let reply = self.request(
            "tools/call",
            json!({
                "_meta": Self::meta(client),
                "name": tool,
                "arguments": arguments,
                "requestState": request_state,
                "inputResponses": responses,
            }),
        );
        assert!(reply.get("error").is_none(), "{tool}: {reply}");
        reply["result"].clone()
    }

    /// A successful call's structured result, with the two invariants every
    /// success must satisfy checked on the way past.
    fn call(&mut self, tool: &str, arguments: Value) -> Value {
        let result = self.call_raw(tool, arguments);
        assert_ne!(
            result["isError"],
            json!(true),
            "{tool} refused: {}",
            first_text(&result)
        );
        assert!(
            result.get("structuredContent").is_some(),
            "{tool} returned no structuredContent: {result}"
        );
        // The text mirror the specification asks for, for clients that
        // predate structured results.
        let mirror: Value = serde_json::from_str(&first_text(&result))
            .unwrap_or_else(|e| panic!("{tool}'s text mirror is not the JSON result: {e}"));
        assert_eq!(
            mirror, result["structuredContent"],
            "{tool}'s text mirror and structured result disagree"
        );
        result["structuredContent"].clone()
    }

    /// The failure document of a call that was refused.
    fn call_expecting_failure(&mut self, tool: &str, arguments: Value) -> Value {
        let result = self.call_raw(tool, arguments);
        assert_eq!(
            result["isError"],
            json!(true),
            "{tool} succeeded where a refusal was required: {result}"
        );
        serde_json::from_str(&first_text(&result))
            .unwrap_or_else(|e| panic!("{tool}'s refusal is not machine-readable: {e}"))
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn first_text(result: &Value) -> String {
    result["content"]
        .as_array()
        .and_then(|c| c.first())
        .and_then(|b| b["text"].as_str())
        .unwrap_or_default()
        .to_string()
}

fn tool_named<'a>(tools: &'a [Value], name: &str) -> &'a Value {
    tools
        .iter()
        .find(|t| t["name"] == name)
        .unwrap_or_else(|| panic!("no tool named {name}"))
}

fn scan_request(targets: &str, ports: &str, key: &str) -> Value {
    // `ports` is split the way the command surface splits its own
    // comma-separated argument, so the two tests below hand both surfaces the
    // same port selection rather than two spellings of one.
    let explicit: Vec<&str> = ports.split(',').collect();
    json!({
        "targets": [targets],
        "objective": "inventory_exposed_services",
        "ports": { "explicit": explicit },
        "idempotency_key": key,
    })
}

/// Run the command-line surface, for the tests that assert the two agree.
fn bathy(args: &[&str]) -> (i32, String) {
    let out = Command::new(BIN)
        .args(args)
        .env_remove("BATHY_STATE_DIR")
        .output()
        .expect("the bathy binary runs");
    (
        out.status.code().expect("the process exited normally"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

// ---------------------------------------------------------------------------
// A JSON Schema check, over the constructs these schemas actually use.
// ---------------------------------------------------------------------------

/// Whether `value` satisfies `schema`, resolving `$ref` against `root`.
///
/// Deliberately small and deliberately strict about the things that matter
/// here: a declared `outputSchema` is a promise that the structured result
/// conforms, and the way that promise fails in practice is a field that is
/// required and absent, or a value of the wrong type.
fn conforms(root: &Value, schema: &Value, value: &Value) -> Result<(), String> {
    if let Some(reference) = schema["$ref"].as_str() {
        let name = reference
            .strip_prefix("#/$defs/")
            .ok_or_else(|| format!("unsupported reference {reference}"))?;
        let target = root["$defs"]
            .get(name)
            .ok_or_else(|| format!("dangling reference {reference}"))?;
        return conforms(root, target, value);
    }
    for combinator in ["oneOf", "anyOf"] {
        if let Some(arms) = schema[combinator].as_array() {
            return if arms.iter().any(|a| conforms(root, a, value).is_ok()) {
                Ok(())
            } else {
                Err(format!("{value} matches no {combinator} arm of {schema}"))
            };
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
    if let Some(declared) = schema["type"].as_str() {
        let actual = match value {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Number(n) if n.is_f64() => "number",
            Value::Number(_) => "integer",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        };
        let ok = declared == actual
            || (declared == "number" && actual == "integer")
            || (declared == "integer" && actual == "number");
        if !ok {
            return Err(format!("expected {declared}, got {actual} ({value})"));
        }
    }
    if let Some(types) = schema["type"].as_array()
        && !types
            .iter()
            .any(|t| conforms(root, &json!({ "type": t }), value).is_ok())
    {
        return Err(format!("{value} matches none of {types:?}"));
    }
    if let Some(object) = value.as_object() {
        for name in schema["required"].as_array().unwrap_or(&vec![]) {
            let name = name.as_str().unwrap_or_default();
            if !object.contains_key(name) {
                return Err(format!("required property `{name}` is absent from {value}"));
            }
        }
        if let Some(properties) = schema["properties"].as_object() {
            if schema["additionalProperties"] == json!(false) {
                for key in object.keys() {
                    if !properties.contains_key(key) {
                        return Err(format!("`{key}` is not a declared property"));
                    }
                }
            }
            for (key, sub) in properties {
                if let Some(present) = object.get(key) {
                    conforms(root, sub, present).map_err(|e| format!("{key}: {e}"))?;
                }
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

fn assert_conforms(tool: &str, schema: &Value, value: &Value) {
    if let Err(e) = conforms(schema, schema, value) {
        panic!(
            "{tool}'s result does not conform to its own published outputSchema: {e}\n\nresult: {value:#}\n\nschema: {schema:#}"
        );
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
    let mut server = Server::start(64);
    let tools = server.tools();
    let description = tool_named(&tools, "result.diff")["description"]
        .as_str()
        .expect("result.diff carries a description")
        .to_string();
    for phrase in ["budget", "rate limit", "coverage_differs", "same endpoints"] {
        assert!(
            description.contains(phrase),
            "the advertised description does not name `{phrase}`. An agent choosing \
             between \"nothing changed\" and \"we could not tell\" has to know that a \
             budget change alone produces the second: {description}"
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

fn wait_for_terminal(server: &mut Server, scan_id: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut cursor = 0u64;
    loop {
        let page = server.call(
            "scan.events",
            json!({ "scan_id": scan_id, "after_sequence": cursor, "limit": 200 }),
        );
        cursor = page["next_cursor"].as_u64().unwrap();
        let terminal = page["events"].as_array().unwrap().iter().any(|e| {
            matches!(
                e["event_type"].as_str(),
                Some("scan.completed") | Some("scan.failed") | Some("policy.denied")
            )
        });
        if terminal {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the scan never reached a terminal event. stderr:\n{}",
            server.diagnostics()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn first_evidence_digest(server: &mut Server, scan_id: &str) -> String {
    let fold = server.call("result.query", json!({ "scan_id": scan_id }));
    fold["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|e| e["evidence_refs"].as_array()?.first()?.as_str())
        .unwrap_or_else(|| panic!("no endpoint cited evidence: {fold:#}"))
        .to_string()
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

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
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
    let mut server = Server::start(64);

    let started = server.call(
        "scan.start",
        json!({
            "manifest_path": scope.path(),
            "request": {
                "targets": [ip.to_string()],
                "objective": "inventory_exposed_services",
                "ports": { "explicit": ["1-400"] },
                "idempotency_key": "cancel-me",
                "max_packets_per_second": 5,
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
// ---------------------------------------------------------------------------

#[test]
fn the_preview_tool_and_the_preview_subcommand_return_the_same_document() {
    let ip = local_ipv4();
    let scope = Scope::for_local(ip);
    let mut server = Server::start(64);

    let from_tool = server.call(
        "scan.preview",
        json!({
            "manifest_path": scope.path(),
            "request": scan_request(&ip.to_string(), "22,80", "preview-not-an-attempt"),
        }),
    );

    let (code, stdout) = bathy(&[
        "--json",
        "--state-dir",
        &server.state_dir(),
        "scan",
        "preview",
        "--scope",
        &scope.path(),
        "--targets",
        &ip.to_string(),
        "--ports",
        "22,80",
    ]);
    assert_eq!(code, 0, "{stdout}");
    let from_cli: Value = serde_json::from_str(stdout.trim()).unwrap();

    assert_eq!(
        from_tool, from_cli,
        "the tool surface and the command surface previewed the same request and \
         answered differently. That premise is what makes this tool surface auditable \
         from a shell, and it decays silently"
    );
}

#[test]
fn the_scope_tool_and_the_scope_subcommand_return_the_same_document() {
    let ip = local_ipv4();
    let scope = Scope::for_local(ip);
    let mut server = Server::start(64);

    let from_tool = server.call(
        "scope.validate",
        json!({ "manifest_path": scope.path(), "targets": [ip.to_string()] }),
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
        &ip.to_string(),
    ]);
    assert_eq!(code, 0, "{stdout}");
    let from_cli: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(from_tool, from_cli);

    // And a target the manifest does not cover is refused by both, with the
    // same code and the same exit status the exit-code table promises.
    let refused = server.call_raw(
        "scope.validate",
        json!({ "manifest_path": scope.path(), "targets": ["8.8.8.8"] }),
    );
    assert_eq!(refused["isError"], json!(true));
    assert_eq!(
        refused["structuredContent"]["reason_code"],
        json!("target_out_of_scope")
    );
    let (code, _) = bathy(&[
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
