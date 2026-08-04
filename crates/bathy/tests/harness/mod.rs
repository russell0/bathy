//! The stdio MCP client every test in this directory drives the server
//! through, and the fixtures it needs.
//!
//! It lives here rather than in `mcp.rs` because two test binaries speak to
//! this server -- `mcp.rs`, which is about the protocol and the tool
//! contracts, and `workflow.rs`, which is about an agent completing a job
//! through them. A second hand-written client would be a second definition
//! of what "calling a tool" means, and the first thing that would drift is
//! the invariant `Server::call` checks on every success.
//!
//! The client is written out by hand rather than taken from the SDK, so a
//! server that only works against its own SDK's client fails here.
//!
//! `#![allow(dead_code)]`: each test binary compiles the whole module and
//! uses a subset of it. Without this, an item used only by `workflow.rs`
//! warns when `mcp.rs` compiles, and `-D warnings` turns that into a failure
//! that says nothing about either test.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

pub const BIN: &str = env!("CARGO_BIN_EXE_bathy");
pub const SCOPE_ID: &str = "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV";
pub const PROTOCOL: &str = "2026-07-28";
pub const NGINX_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nServer: nginx/1.26.0\r\nConnection: close\r\n\r\n<html></html>";

/// The eleven, in the order `tools/list` must return them.
pub const EXPECTED_TOOLS: &[&str] = &[
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

pub fn local_ipv4() -> Ipv4Addr {
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

pub struct Scope {
    _dir: tempfile::TempDir,
    path: PathBuf,
    expired: PathBuf,
}

impl Scope {
    pub fn new(allowed: &[&str]) -> Self {
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

    pub fn for_local(ip: Ipv4Addr) -> Self {
        Self::new(&[&format!("{ip}/32")])
    }

    pub fn path(&self) -> String {
        self.path.to_str().unwrap().to_string()
    }

    pub fn expired(&self) -> String {
        self.expired.to_str().unwrap().to_string()
    }
}

/// Counts accepted connections, so "no packet was emitted" can be measured
/// rather than asserted about the code that would have emitted one.
pub struct Listener {
    port: u16,
    accepts: Arc<AtomicUsize>,
}

impl Listener {
    pub fn bind(ip: Ipv4Addr, serve_http: bool) -> Self {
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

    pub fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    pub fn port(&self) -> String {
        self.port.to_string()
    }
}

// ---------------------------------------------------------------------------
// The client.
// ---------------------------------------------------------------------------

pub struct Server {
    child: Child,
    stdin: ChildStdin,
    /// Lines the server has written, delivered by a reader thread.
    ///
    /// **Not a `BufReader<ChildStdout>` read on this thread, and that is the
    /// point.** `read_line` on a child that is alive and simply not answering
    /// blocks forever, so the 30-second deadline in [`Server::request`] --
    /// whose whole purpose is to fail a server that never answers rather than
    /// hang on one -- was checked only *between* reads and therefore never
    /// bound. A mutation that made the server silent turned every protocol
    /// test into an indefinite hang instead of a failure, which is a fixture
    /// that cannot report the defect it was written for. A channel makes the
    /// deadline real: `recv_timeout` returns whether or not anything came.
    stdout: std::sync::mpsc::Receiver<String>,
    stderr: Arc<Mutex<String>>,
    next_id: u64,
    state: tempfile::TempDir,
}

impl Server {
    pub fn start(approval_threshold: u64) -> Self {
        Self::start_in(tempfile::tempdir().expect("tempdir"), approval_threshold)
    }

    pub fn start_in(state: tempfile::TempDir, approval_threshold: u64) -> Self {
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
        // Read on a thread and delivered by channel, so the deadline in
        // `request` binds even when the server is alive and silent. See the
        // field's own comment. The sender is dropped when standard output
        // closes, which is how `request` tells "the server ended" from "the
        // server is thinking".
        let (lines, stdout) = std::sync::mpsc::channel();
        let out = BufReader::new(child.stdout.take().expect("stdout"));
        std::thread::spawn(move || {
            for line in out.lines() {
                let Ok(line) = line else { return };
                if lines.send(line).is_err() {
                    return;
                }
            }
        });
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

    pub fn state_dir(&self) -> String {
        self.state.path().to_str().unwrap().to_string()
    }

    pub fn diagnostics(&self) -> String {
        self.stderr.lock().unwrap().clone()
    }

    /// The per-request metadata a Modern client sends. There is no handshake
    /// in this revision: the version and the client's capabilities ride in
    /// every request.
    pub fn meta(client: &str) -> Value {
        Self::meta_declaring(client, json!({ "elicitation": {} }))
    }

    /// The same, with the client's capability declaration spelled out — for
    /// the tests about what a server may and may not ask a client to do.
    pub fn meta_declaring(client: &str, capabilities: Value) -> Value {
        json!({
            "io.modelcontextprotocol/protocolVersion": PROTOCOL,
            "io.modelcontextprotocol/clientInfo": { "name": client, "version": "0.0.0" },
            "io.modelcontextprotocol/clientCapabilities": capabilities,
        })
    }

    /// Send one request and read the reply that matches its id.
    pub fn request(&mut self, method: &str, mut params: Value) -> Value {
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
            let remaining = deadline.saturating_duration_since(Instant::now());
            let line = match self.stdout.recv_timeout(remaining) {
                Ok(line) => line,
                // The deadline, and it binds: a server that is alive and
                // simply not answering fails here rather than hanging the
                // suite forever. A server built for the session-based
                // protocol waits for `initialize` and never answers, and so
                // does one that swallows a request it cannot serve.
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!(
                    "no reply to {method} within 30s. stderr:\n{}",
                    self.diagnostics()
                ),
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => panic!(
                    "the server closed its output without answering {method}. stderr:\n{}",
                    self.diagnostics()
                ),
            };
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

    pub fn list_tools(&mut self) -> Value {
        let reply = self.request("tools/list", json!({ "_meta": Self::meta("harness") }));
        reply["result"].clone()
    }

    pub fn tools(&mut self) -> Vec<Value> {
        self.list_tools()["tools"].as_array().cloned().unwrap()
    }

    /// A `tools/call`, returning the whole result object so a test can see
    /// `resultType`, `isError` and `structuredContent`.
    pub fn call_raw(&mut self, tool: &str, arguments: Value) -> Value {
        self.call_as("harness", tool, arguments)
    }

    pub fn call_as(&mut self, client: &str, tool: &str, arguments: Value) -> Value {
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
    pub fn retry_with_inputs(
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
    pub fn call(&mut self, tool: &str, arguments: Value) -> Value {
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
    pub fn call_expecting_failure(&mut self, tool: &str, arguments: Value) -> Value {
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

pub fn first_text(result: &Value) -> String {
    result["content"]
        .as_array()
        .and_then(|c| c.first())
        .and_then(|b| b["text"].as_str())
        .unwrap_or_default()
        .to_string()
}

pub fn tool_named<'a>(tools: &'a [Value], name: &str) -> &'a Value {
    tools
        .iter()
        .find(|t| t["name"] == name)
        .unwrap_or_else(|| panic!("no tool named {name}"))
}

pub fn scan_request(targets: &str, ports: &str, key: &str) -> Value {
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

/// Drive a fresh `serve mcp` process with `messages`, close its input, and
/// wait for it: `(exit code, stdout, stderr)`.
///
/// [`Server`] keeps the pipe open for the life of the test, so it cannot see
/// what the process does when a client *leaves*. That is a distinct question
/// -- whether ending a session is reported as a failure -- and it needs the
/// process to be allowed to finish.
pub fn serve_once(messages: &[Value]) -> (i32, String, String) {
    let state = tempfile::tempdir().expect("tempdir");
    let mut child = Command::new(BIN)
        .args([
            "--state-dir",
            state.path().to_str().unwrap(),
            "serve",
            "mcp",
        ])
        .env_remove("BATHY_STATE_DIR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the bathy binary runs");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        for message in messages {
            writeln!(stdin, "{message}").expect("write a request");
        }
        // Dropped here: end of input is the client hanging up.
    }
    let out = child.wait_with_output().expect("the server exits");
    (
        out.status.code().expect("the process exited normally"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Run the command-line surface, for the tests that assert the two agree.
pub fn bathy(args: &[&str]) -> (i32, String) {
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

pub fn wait_for_terminal(server: &mut Server, scan_id: &str) {
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

pub fn first_evidence_digest(server: &mut Server, scan_id: &str) -> String {
    let fold = server.call("result.query", json!({ "scan_id": scan_id }));
    fold["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|e| e["evidence_refs"].as_array()?.first()?.as_str())
        .unwrap_or_else(|| panic!("no endpoint cited evidence: {fold:#}"))
        .to_string()
}

pub fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}
