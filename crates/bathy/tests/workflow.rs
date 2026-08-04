//! The headline claim, as a test: an agent completes an authorized inventory
//! through the eleven typed tools, over a real stdio transport, without ever
//! constructing a command string or parsing prose.
//!
//! Everything the workflow below decides -- which targets it is allowed to
//! scan, whether the plan was approved, whether the scan has finished, which
//! endpoints are worth reporting, which bytes back a finding -- is read from a
//! **typed field of `structuredContent`**. [`Agent::call`] nulls the text
//! mirror out of every result before the workflow can see it, so "no prose was
//! parsed" is a property of the only function that talks to the server rather
//! than a claim about the code underneath it. The mirror's *presence* is still
//! checked on every call, because the specification asks for it for Legacy
//! clients; its content is never read.
//!
//! The workflow includes a refusal on purpose. An inventory that only ever
//! succeeds demonstrates nothing about the safety properties, and the refusal
//! here is not decoration: the typed `out_of_scope` array in the denial is
//! what the agent uses to narrow its own request. A prose error would have
//! left it nothing to act on.
//!
//! `mcp.rs` is about the protocol and the tool contracts. This file is about
//! whether the surface is *sufficient* -- whether an agent holding only these
//! eleven tools can finish the job.

use std::collections::BTreeSet;
use std::net::TcpListener;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

mod harness;
use harness::*;

/// AC-5.24: "a complete authorized inventory ... completes in ten or fewer
/// typed tool calls".
///
/// # The condition, which used to be stated nowhere
///
/// This budget is **not** unconditional, and the M5 whole-branch review was
/// right to refuse to let that stand. The inventory is
/// [`TYPED_CALLS_BESIDES_POLLING`] calls plus however many `scan.events`
/// polls the scan's duration requires against a fixed backoff schedule --
/// and a scan's duration is a property of the machine. Re-paced to one packet
/// per second (the same shape as a machine six times slower) the workflow
/// takes eleven calls and fails here, on the budget rather than on the
/// deadline. So the honest form of the claim is:
///
/// > A complete authorized inventory takes six typed calls plus one poll per
/// > round trip until the scan is done. Against the shipped lab that is nine.
///
/// The six are asserted exactly, because that half **is** machine-independent
/// and it is the half the criterion is actually about: whether an agent
/// holding only these eleven tools can finish the job without constructing a
/// command line. The poll count is bounded rather than fixed, and the failure
/// message below says which of the two gave way, so a slow CI runner is
/// reported as a claim needing its condition restated rather than as a
/// surface that stopped working.
///
/// Making the poll count machine-independent is not available at this
/// surface, and that is a decision recorded elsewhere rather than an
/// oversight: `notifications/progress` would hold a response stream open for
/// the length of a scan, which clients and intermediaries time out
/// (`docs/protocol-notes.md`, "Progress notifications"). Polling a durable
/// cursor is the mechanism, and polling costs a call.
const CALL_BUDGET: usize = 10;

/// The part of the claim that does not depend on how fast this machine is:
/// `scope.validate` (denied), `scope.validate` (narrowed), `scan.preview`,
/// `scan.start`, `result.query`, `evidence.get`.
///
/// Asserted exactly rather than as a bound. A workflow that needed a seventh
/// typed call would mean the tool surface is not sufficient, which is a
/// different and much more serious thing than a slow scan needing an extra
/// poll -- and folding both into one `<= 10` made them indistinguishable.
const TYPED_CALLS_BESIDES_POLLING: usize = 6;

/// What the platform's temporary directory is written as in the rendered
/// transcript. See [`redacted`].
const TEMP_DIR_PLACEHOLDER: &str = "$TMPDIR";

/// The one substitution made to an otherwise verbatim capture.
///
/// The manifest paths in the transcript are real, and on macOS they carry
/// `DARWIN_USER_TEMP_DIR` -- a token stable per user per machine, and so a
/// linkable identifier in a way the RFC 1918 address and the two-second
/// ephemeral ports the document already discloses as local are not. It costs
/// nothing to remove: the path is meaningless to a reader either way. Done in
/// the emitter rather than in the rendered document, so a re-render cannot
/// bring it back.
///
/// A free function rather than three lines inline, because inline it was
/// reachable only with `BATHY_WORKFLOW_TRANSCRIPT` set -- so no test took the
/// branch, and removing the substitution entirely passed the whole suite.
fn redacted(rendered: String) -> String {
    let root = std::env::temp_dir();
    let root = root.to_str().expect("a printable temp directory");
    // The trailing separator is trimmed here and supplied by the path itself,
    // because macOS reports the temporary directory with one and Linux does
    // not. Without this the same code renders `$TMPDIR/x` on one platform and
    // `$TMPDIR//x` on the other, so the published document would depend on
    // which machine happened to render it -- which is the class of defect
    // this function exists to remove, one level up.
    rendered.replace(root.trim_end_matches('/'), TEMP_DIR_PLACEHOLDER)
}

/// A target the lab manifest does not authorize. Naming it costs nothing --
/// `scope.validate` emits no packet -- and it is what makes the refusal in
/// the middle of the workflow a real question rather than a rehearsal.
const UNAUTHORIZED: &str = "10.30.0.1";

// ---------------------------------------------------------------------------
// The agent's view of the server: typed results, and nothing else.
// ---------------------------------------------------------------------------

/// One call, kept so the transcript in `docs/examples/` can be generated from
/// a real run rather than written by hand (AC-5.26).
struct Step {
    tool: &'static str,
    arguments: Value,
    structured: Value,
    is_error: bool,
}

/// A `tools/call` result as an agent sees it: the typed document, and whether
/// the server flagged it a refusal.
///
/// There is no accessor for the text mirror, and the value behind
/// `structured` has already had it removed. That is the point: a workflow
/// built on this type *cannot* fall back to reading prose, so the claim does
/// not depend on anybody remembering not to.
struct Typed {
    structured: Value,
    is_error: bool,
}

impl Typed {
    /// A field this decision depends on. Absent is a failure, never a
    /// silently-null default: an agent that branches on a field the server
    /// did not send is guessing.
    fn field(&self, name: &str) -> &Value {
        self.structured.get(name).unwrap_or_else(|| {
            panic!(
                "no typed `{name}` in the result; an agent has nothing to branch on: {:#}",
                self.structured
            )
        })
    }

    fn text(&self, name: &str) -> &str {
        self.field(name)
            .as_str()
            .unwrap_or_else(|| panic!("`{name}` is not a string: {:#}", self.structured))
    }

    fn number(&self, name: &str) -> u64 {
        self.field(name)
            .as_u64()
            .unwrap_or_else(|| panic!("`{name}` is not an integer: {:#}", self.structured))
    }

    fn list(&self, name: &str) -> &[Value] {
        self.field(name)
            .as_array()
            .unwrap_or_else(|| panic!("`{name}` is not an array: {:#}", self.structured))
            .as_slice()
    }
}

/// An MCP client that can do exactly what the advertised surface allows.
struct Agent<'a> {
    server: &'a mut Server,
    /// Every tool name `tools/list` advertised. A call to anything else is a
    /// bug in the workflow, not a feature of the server.
    advertised: Vec<String>,
    transcript: Vec<Step>,
}

impl<'a> Agent<'a> {
    fn new(server: &'a mut Server) -> Self {
        let advertised: Vec<String> = server
            .tools()
            .iter()
            .map(|t| t["name"].as_str().expect("a tool has a name").to_string())
            .collect();
        assert_eq!(
            advertised, EXPECTED_TOOLS,
            "the workflow is a claim about a published eleven-tool surface"
        );
        Self {
            server,
            advertised,
            transcript: Vec::new(),
        }
    }

    /// One typed tool call.
    fn call(&mut self, tool: &'static str, arguments: Value) -> Typed {
        assert!(
            self.advertised.iter().any(|t| t == tool),
            "{tool} is not advertised; an agent cannot call what it was never told about"
        );
        let mut result = self.server.call_raw(tool, arguments.clone());

        // The specification asks for a JSON text mirror in `content` for
        // clients that predate structured results, so its absence is a
        // protocol defect and is checked. Its *content* is then discarded
        // unread -- see this file's module documentation. [forbidden-token]
        assert!(
            result.get("content").is_some(),
            "{tool} returned no text mirror at all"
        );
        result["content"] = Value::Null; // [forbidden-token]

        let structured = result
            .get("structuredContent")
            .cloned()
            .unwrap_or_else(|| panic!("{tool} returned no structuredContent: {result:#}"));
        let is_error = result["isError"] == json!(true);
        self.transcript.push(Step {
            tool,
            arguments,
            structured: structured.clone(),
            is_error,
        });
        Typed {
            structured,
            is_error,
        }
    }

    fn calls(&self) -> usize {
        self.transcript.len()
    }
}

// ---------------------------------------------------------------------------
// The lab.
//
// Three endpoints, chosen so the one filter the workflow uses has something
// to exclude in *each* of its two dimensions -- the Global Constraint "a
// fixture that satisfies every branch tests none of them". The control at the
// end of the test names both excluded endpoints and proves they were in the
// fold all along.
// ---------------------------------------------------------------------------

struct Lab {
    /// Open, and answers `GET` with an nginx banner: identified as `http`.
    http: Listener,
    /// Open, and closes every connection without saying anything: no service
    /// is identified, so the `service` half of the filter must drop it.
    silent: Listener,
    /// Nothing is listening: the `state` half of the filter must drop it.
    closed_port: u16,
}

impl Lab {
    fn bind(ip: std::net::Ipv4Addr) -> Self {
        // Bound and immediately released, so the port is real, routable and
        // has nothing behind it -- which is what makes a `closed` port state
        // an observation rather than a timeout.
        let vacated = TcpListener::bind((ip, 0)).expect("bind");
        let closed_port = vacated.local_addr().unwrap().port();
        drop(vacated);
        Self {
            http: Listener::bind(ip, true),
            silent: Listener::bind(ip, false),
            closed_port,
        }
    }

    fn ports(&self) -> Vec<String> {
        vec![
            self.http.port(),
            self.silent.port(),
            self.closed_port.to_string(),
        ]
    }
}

/// Find one endpoint in a `result.query` document by port.
fn endpoint_on(endpoints: &[Value], port: u16) -> Option<&Value> {
    endpoints
        .iter()
        .find(|e| e["endpoint"]["port"].as_u64() == Some(u64::from(port)))
}

// ---------------------------------------------------------------------------
// The claim.
// ---------------------------------------------------------------------------

#[test]
fn an_agent_completes_an_authorized_inventory_in_ten_typed_calls() {
    let ip = local_ipv4();
    let lab = Lab::bind(ip);
    let scope = Scope::for_local(ip);
    let mut server = Server::start(64);
    let mut agent = Agent::new(&mut server);

    // -- 1. The brief names two hosts. Only one of them is authorized, and
    //       the agent finds that out before it asks for anything else.
    let refusal = agent.call(
        "scope.validate",
        json!({
            "manifest_path": scope.path(),
            "targets": [ip.to_string(), UNAUTHORIZED],
        }),
    );
    assert!(
        refusal.is_error,
        "a denial an agent reads as success is a denial it retries forever"
    );
    assert_eq!(refusal.field("decision"), "denied");
    assert_eq!(
        refusal.field("reason_code"),
        "target_out_of_scope",
        "the denial must carry a stable code, not a sentence to interpret"
    );
    let refused: Vec<String> = refusal
        .list("out_of_scope")
        .iter()
        .map(|t| {
            t.as_str()
                .expect("a refused target is a string")
                .to_string()
        })
        .collect();
    assert_eq!(refused, vec![UNAUTHORIZED.to_string()]);

    // The refusal is machine-actionable, and this is what that means: the
    // agent narrows its own request from the typed list rather than giving up
    // or guessing which half was refused.
    let authorized: Vec<String> = [ip.to_string(), UNAUTHORIZED.to_string()]
        .into_iter()
        .filter(|t| !refused.contains(t))
        .collect();
    assert_eq!(authorized, vec![ip.to_string()]);

    // -- 2. The narrowed brief, confirmed rather than assumed.
    let validated = agent.call(
        "scope.validate",
        json!({ "manifest_path": scope.path(), "targets": authorized }),
    );
    assert!(!validated.is_error);
    assert_eq!(validated.field("decision"), "approved");
    assert_eq!(validated.number("in_scope_count"), 1);
    assert!(validated.list("out_of_scope").is_empty());
    assert!(
        !validated.field("expired").as_bool().expect("typed bool"),
        "an expired manifest authorizes nothing"
    );

    // -- 3. What the scan would do, before it does it.
    let request = json!({
        "targets": [ip.to_string()],
        "objective": "inventory_exposed_services",
        "ports": { "explicit": lab.ports() },
        "idempotency_key": "inventory-workflow",
        "service_detection": { "enabled": true, "intensity": 9 },
        // Paced, so that "the handle came back before the work was done" has
        // room to be observed rather than asserted about a scan that would
        // have finished either way. See the first poll below.
        "max_packets_per_second": 6,
    });
    let preview = agent.call(
        "scan.preview",
        json!({ "manifest_path": scope.path(), "request": request }),
    );
    assert!(!preview.is_error);
    assert_eq!(preview.field("policy_decision"), "approved");
    assert_eq!(preview.number("estimated_targets"), 1);
    assert_eq!(
        preview.number("estimated_probes"),
        3,
        "the estimate must come from the request the agent wrote"
    );
    let previewed_plan = preview.text("plan_hash").to_string();
    assert!(previewed_plan.starts_with("blake3:"));

    // -- 4. Start it. The handle comes back before the work is done.
    let started = agent.call(
        "scan.start",
        json!({ "manifest_path": scope.path(), "request": request }),
    );
    assert!(!started.is_error);
    assert_eq!(started.field("policy_decision"), "approved");
    let handle = &started.field("handle").clone();
    let scan_id = handle["task_id"].as_str().expect("a typed scan id");
    assert_eq!(handle["status"], "running");
    assert_eq!(
        handle["plan_hash"], previewed_plan,
        "the plan that ran is not the plan the agent previewed"
    );

    // -- 5. Poll the durable log to a terminal event, by cursor. The cursor
    //       is a typed field of the previous page, so paging is a fact the
    //       server states rather than an offset the agent tracks.
    let mut cursor = 0u64;
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let mut outcome: Option<String> = None;
    let mut pages = 0usize;
    let typed_calls_before_polling = agent.calls();
    let deadline = Instant::now() + Duration::from_secs(60);
    while outcome.is_none() {
        assert!(
            agent.calls() < CALL_BUDGET,
            "the inventory ran out of its ten-call budget while still polling"
        );
        assert!(
            Instant::now() < deadline,
            "the scan never reached a terminal event"
        );
        let page = agent.call(
            "scan.events",
            json!({ "scan_id": scan_id, "after_sequence": cursor, "limit": 200 }),
        );
        for event in page.list("events") {
            let sequence = event["sequence"].as_u64().expect("a typed sequence");
            assert!(
                seen.insert(sequence),
                "sequence {sequence} was delivered twice: paging from a cursor must \
                 not replay what the agent has already read"
            );
            if let Some(kind) = event["event_type"].as_str()
                && matches!(kind, "scan.completed" | "scan.failed" | "policy.denied")
            {
                outcome = Some(kind.to_string());
            }
        }
        pages += 1;
        // `scan.start` detached the work: this plan is paced to six packets
        // per second and takes upwards of a second, and this page was read
        // within a round-trip of the handle. A `scan.start` that ran the scan to
        // completion before answering would have made this first page
        // terminal already -- which is the failure this asserts, rather than
        // a wall-clock bound that a fast enough scan would satisfy either
        // way. (`mcp.rs` owns the strict two-second form of AC-5.16, over a
        // thousand-port plan.)
        assert!(
            !(pages == 1 && outcome.is_some()),
            "the first page after scan.start was already terminal: the handle was \
             not returned until the scan had finished"
        );
        let next = page.number("next_cursor");
        assert!(next >= cursor, "the cursor went backwards");
        cursor = next;
        if outcome.is_none() {
            // Backoff, the way an agent polling a scan would: four calls
            // then cover more than six seconds of scanning, so the budget
            // above binds on the number of round trips rather than on how
            // fast this machine happens to be.
            std::thread::sleep(Duration::from_millis(500) * 3u32.pow(pages as u32 - 1));
        }
    }
    assert_eq!(
        outcome.as_deref(),
        Some("scan.completed"),
        "the inventory did not run to plan exhaustion"
    );

    // -- 6. The answer: open endpoints that were identified as HTTP.
    let results = agent.call(
        "result.query",
        json!({
            "scan_id": scan_id,
            "filter": { "state": "open", "service": "http" },
        }),
    );
    assert!(!results.is_error);
    assert_eq!(
        results.field("terminal")["outcome"],
        "completed",
        "the query must say which kind of scan it is reporting on"
    );
    assert_eq!(results.field("plan_hash"), previewed_plan.as_str());
    let found = results.list("endpoints").to_vec();
    assert_eq!(results.number("total"), found.len() as u64);
    assert_eq!(
        found.len(),
        1,
        "exactly one endpoint in this lab is both open and HTTP: {found:#?}"
    );
    for endpoint in &found {
        assert_eq!(endpoint["state"], "open");
        assert_eq!(endpoint["observation"]["service"], "http");
    }
    let http = &found[0];
    assert_eq!(
        http["endpoint"]["port"].as_u64(),
        lab.http.port().parse::<u64>().ok()
    );
    assert_eq!(http["observation"]["product"], "nginx");
    assert!(
        http["observation"]["confidence"].as_f64().expect("typed") > 0.0,
        "a finding with no confidence is not a finding"
    );

    // -- 7. And the bytes the finding is standing on.
    let digest = http["evidence_refs"][0]
        .as_str()
        .expect("an identified service cites evidence");
    let evidence = agent.call("evidence.get", json!({ "digest": digest }));
    assert!(!evidence.is_error);
    let bytes = hex_decode(evidence.text("bytes_hex"));
    assert_eq!(evidence.number("length"), bytes.len() as u64);
    assert_eq!(evidence.field("truncated"), false);
    assert!(
        !bytes.is_empty() && NGINX_RESPONSE.starts_with(&bytes),
        "evidence.get returned bytes this endpoint never sent: {:?}",
        String::from_utf8_lossy(&bytes)
    );

    let inventory_calls = agent.calls();
    // The two halves of the claim, asserted separately because they fail for
    // different reasons and mean different things. See `CALL_BUDGET`.
    let typed_calls = inventory_calls - pages;
    assert_eq!(
        typed_calls, TYPED_CALLS_BESIDES_POLLING,
        "the inventory needed {typed_calls} typed calls besides polling, not \
         {TYPED_CALLS_BESIDES_POLLING}. This is the machine-independent half of \
         the claim: it changed because the tool surface changed, not because \
         this machine is slow."
    );
    assert!(
        inventory_calls <= CALL_BUDGET,
        "the inventory took {inventory_calls} calls: {typed_calls} typed and \
         {pages} polls. The typed half is unchanged, so the surface is fine and \
         the budget is what gave way -- this scan took longer than the backoff \
         schedule's window, which is a property of this machine. Restate the \
         condition on AC-5.24 and `docs/examples/agent-inventory-workflow.md`, \
         or slow the backoff; do not raise {CALL_BUDGET} silently."
    );
    // Belt and braces on the arithmetic above: `typed_calls` is a
    // subtraction, and a subtraction that quietly went wrong would make the
    // first assertion pass for the wrong reason.
    assert_eq!(
        typed_calls_before_polling + pages + 2,
        inventory_calls,
        "the call accounting does not add up: {typed_calls_before_polling} before \
         polling, {pages} polls, then result.query and evidence.get"
    );

    // -----------------------------------------------------------------
    // The control, and it is not part of the ten: everything above would
    // pass just as happily against a server that ignored the filter and
    // happened to have one endpoint. The same scan, asked without a filter,
    // must hold the two endpoints the filter excluded -- one for each of its
    // dimensions.
    // -----------------------------------------------------------------
    let everything = agent.call("result.query", json!({ "scan_id": scan_id }));
    let all = everything.list("endpoints").to_vec();
    assert_eq!(
        everything.number("total_before_filter"),
        results.number("total_before_filter"),
        "the two queries are reporting on different folds"
    );
    assert!(
        results.number("total") < results.number("total_before_filter"),
        "the filter excluded nothing, so nothing above tested it"
    );

    let closed = endpoint_on(&all, lab.closed_port)
        .unwrap_or_else(|| panic!("the vacated port is missing from the fold: {all:#?}"));
    assert_ne!(
        closed["state"], "open",
        "the port this test vacated answered as open; something else bound it, and \
         the `state` half of the filter had nothing to exclude"
    );
    assert!(
        endpoint_on(&found, lab.closed_port).is_none(),
        "a non-open endpoint survived a `state: open` filter"
    );

    let silent_port: u16 = lab.silent.port().parse().unwrap();
    let silent = endpoint_on(&all, silent_port)
        .unwrap_or_else(|| panic!("the silent port is missing from the fold: {all:#?}"));
    assert_eq!(
        silent["state"], "open",
        "the silent endpoint must be open, or it is excluded by `state` and says \
         nothing about `service`"
    );
    assert_ne!(
        silent["observation"]["service"], "http",
        "the silent endpoint was identified as HTTP; it answers nothing, so the \
         `service` half of the filter had nothing to exclude"
    );
    assert!(
        endpoint_on(&found, silent_port).is_none(),
        "an endpoint that is not HTTP survived a `service: http` filter"
    );

    // The transcript in `docs/examples/agent-inventory-workflow.md` is
    // generated from this run, not written by hand (AC-5.26).
    if let Ok(path) = std::env::var("BATHY_WORKFLOW_TRANSCRIPT") {
        let steps: Vec<Value> = agent
            .transcript
            .iter()
            .take(inventory_calls)
            .map(|s| {
                json!({
                    "tool": s.tool,
                    "arguments": s.arguments,
                    "structuredContent": s.structured,
                    "isError": s.is_error,
                })
            })
            .collect();
        let rendered = redacted(serde_json::to_string_pretty(&steps).unwrap());
        std::fs::write(path, rendered).expect("transcript");
    }
}

#[test]
fn the_rendered_transcript_carries_no_machine_local_temp_directory_token() {
    // `docs/examples/agent-inventory-workflow.md` is published, and this is
    // the only thing standing between it and a per-user-per-machine
    // identifier. The fixture is a real path under the real temporary
    // directory, so this fails on a platform whose temp root this does not
    // actually match rather than passing over a string nobody checked.
    let real = std::env::temp_dir().join(".tmpAbC123").join("scope.json");
    let real = real.to_str().expect("a printable path");
    let root = std::env::temp_dir();
    let root = root.to_str().expect("a printable temporary directory");
    let root = root.trim_end_matches('/');
    let transcript =
        format!(r#"[{{"tool":"scope.validate","arguments":{{"manifest_path":"{real}"}}}}]"#);
    assert!(
        transcript.contains(root),
        "the fixture must contain the token this test is about"
    );

    let out = redacted(transcript);
    assert!(
        !out.contains(root),
        "the published transcript carries the platform temporary directory: {out}"
    );
    assert!(
        out.contains("$TMPDIR/.tmpAbC123/scope.json"),
        "the substitution must keep the rest of the path, which is what makes \
         the transcript readable: {out}"
    );

    // And the committed document is what this is for, so check that too: a
    // redaction that works on a string but was never applied to the file is
    // the same defect one step later.
    let published = include_str!("../../../docs/examples/agent-inventory-workflow.md");
    for token in ["/var/folders/", "/private/var/folders/"] {
        assert!(
            !published.contains(token),
            "the published workflow document carries `{token}`"
        );
    }
    assert!(
        published.contains(TEMP_DIR_PLACEHOLDER),
        "the published workflow document shows no redacted path at all, so \
         either it was re-rendered without the substitution or the transcript \
         no longer carries a manifest path"
    );
}

/// AC-5.25, guarded at the source so it cannot rot silently.
///
/// The workflow above may not parse XML, split prose on whitespace, build a
/// command line, or read the text mirror -- the four ways a "typed" client
/// quietly stops being one. Lines that must name a forbidden token in order
/// to forbid or discard it carry `[forbidden-token]`, the same sentinel
/// convention the overview's `[phrase-rule]` uses and for the same reason: a
/// checker whose own statement of the rule trips it is a checker that gets
/// deleted.
///
/// What this does **not** claim: that no process is spawned. `harness` starts
/// the server the way any MCP host starts one. The claim is about the
/// workflow's own calls -- every argument above is a `json!` literal over
/// typed values, and every branch reads a field of a typed result.
#[test]
fn the_inventory_workflow_parses_no_prose_and_builds_no_command_line() {
    const FORBIDDEN: &[(&str, &str)] = &[
        ("quick_xml", "XML parsing"),                    // [forbidden-token]
        ("from_str::<Xml", "XML parsing"),               // [forbidden-token]
        ("split_whitespace", "parsing prose"),           // [forbidden-token]
        ("Command::new", "constructing a command line"), // [forbidden-token]
        ("first_text", "reading the text mirror"),       // [forbidden-token]
        ("[\"content\"]", "reading the text mirror"),    // [forbidden-token]
        ("server.call(", "the harness reads the mirror there"), // [forbidden-token]
    ];
    // `checked` is incremented inside the loop over `FORBIDDEN`, so
    // `checked == FORBIDDEN.len()` is `0 == 0` on an empty list -- the guard
    // is derived from the thing it guards and cannot see it disappear. The
    // M5 close-out review found this shape in `bathy-types`; it is here too,
    // one layer more expensive, because AC-5.25 is closed by this test alone.
    // Seven tokens, four families (XML, prose splitting, command lines, the
    // text mirror); the literal is what makes deleting one fail.
    assert_eq!(
        FORBIDDEN.len(),
        7,
        "the forbidden-token list was shortened; the `checked` count below is \
         computed from it and will still agree with itself"
    );
    let source = include_str!("workflow.rs");
    let mut checked = 0usize;
    for (token, why) in FORBIDDEN {
        for (number, line) in source.lines().enumerate() {
            if line.contains("[forbidden-token]") {
                continue;
            }
            assert!(
                !line.contains(token),
                "workflow.rs:{} uses `{token}` ({why}); the claim this file exists to \
                 make is that an agent needs none of it",
                number + 1
            );
        }
        checked += 1;
    }
    assert_eq!(
        checked,
        FORBIDDEN.len(),
        "every forbidden token must actually have been looked for"
    );
    assert!(
        source.contains("[forbidden-token]"),
        "the sentinel is gone, so the list above is checking a file that no longer \
         declares its own exceptions"
    );
}
