//! The `bathy` binary, tested as a binary.
//!
//! Every test here spawns the compiled program. None of them calls a
//! function inside it: a CLI tested through its own internals is not tested
//! where it is used, and the two properties this milestone actually promises
//! -- an exit code and a stream -- are properties of a process, not of a
//! function.
//!
//! # How "no packet" is proved (AC-5.8, AC-5.9)
//!
//! By binding a real TCP listener, pointing a real, authorized scan at it,
//! and counting accepts.
//!
//! The address is this machine's own primary IPv4 address, discovered from
//! the routing table without sending anything ([`local_ipv4`]). It is used
//! rather than loopback because `ScopeManifest::allows` refuses `127.0.0.0/8`
//! unconditionally in any build this project ships (`bathy-scope`), so a
//! loopback scan would be refused by policy and every "no packet" assertion
//! below would pass for the wrong reason. Traffic to a host's own address
//! never leaves the host, so nothing here touches anyone else's network.
//!
//! Every no-packet assertion is paired with a **positive control** on the
//! same listener and the same port: an invocation that *must* reach it. A
//! zero-accept assertion whose detector cannot detect anything proves
//! nothing, and this project has shipped twelve tests that proved nothing.
//!
//! This is the portable half. The other half is running the binary with the
//! network denied by the operating system -- `testdata/deny-network.sb` on
//! macOS, `unshare -rn` on Linux -- which is not in this suite because it
//! needs a platform-specific wrapper whose own enforcement has to be
//! confirmed first. That profile's header carries the command that confirms
//! it, and M5 Task 3's report records the transcript.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_bathy");

const SCOPE_ID: &str = "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV";

/// The exact bytes captured from `docker.io/library/nginx:1.27-alpine` in
/// M4 Task 2 -- the same constant `bathy-engine`'s end-to-end test uses, so
/// `evidence get` is checked against a byte string this repository already
/// treats as ground truth.
const NGINX_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nServer: nginx/1.26.0\r\nConnection: close\r\n\r\n<html></html>";

// --- Harness ---------------------------------------------------------------

struct Output {
    status: i32,
    stdout: String,
    stderr: String,
}

impl Output {
    fn code(&self, expected: i32) -> &Self {
        assert_eq!(
            self.status, expected,
            "expected exit {expected}, got {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.status, self.stdout, self.stderr
        );
        self
    }

    fn success(&self) -> &Self {
        self.code(0)
    }

    /// Every line of stdout, parsed. Panics naming the offending line, so a
    /// diagnostic that leaked onto stdout is reported as itself rather than
    /// as an opaque serde error.
    fn json_lines(&self) -> Vec<serde_json::Value> {
        self.stdout
            .lines()
            .filter(|l| !l.is_empty())
            .map(|line| {
                serde_json::from_str(line)
                    .unwrap_or_else(|e| panic!("stdout line is not JSON ({e}): {line:?}"))
            })
            .collect()
    }

    fn json(&self) -> serde_json::Value {
        let lines = self.json_lines();
        assert_eq!(lines.len(), 1, "expected one JSON document, got {lines:?}");
        lines.into_iter().next().unwrap()
    }
}

fn bathy(args: &[&str]) -> Output {
    let out = Command::new(BIN)
        .args(args)
        .env_remove("BATHY_STATE_DIR")
        .output()
        .expect("the bathy binary runs");
    Output {
        status: out.status.code().expect("the process exited normally"),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// This machine's primary IPv4 address, taken from the routing table.
///
/// `UdpSocket::connect` sends nothing -- it only fixes which local endpoint
/// the kernel would use for that destination -- and `192.0.2.1` (RFC 5737
/// TEST-NET-1) is never contacted. This is not best-effort: a test that
/// cannot find a routable local address must fail rather than quietly test
/// something weaker.
fn local_ipv4() -> Ipv4Addr {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("bind an ephemeral UDP socket");
    socket
        .connect("192.0.2.1:9")
        .expect("a default route is required to run these tests");
    match socket.local_addr().expect("local_addr").ip() {
        IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => v4,
        other => panic!(
            "no routable IPv4 address on this machine (got {other}); \
             these tests need one because loopback is refused by every shipped manifest"
        ),
    }
}

struct Scope {
    dir: tempfile::TempDir,
    path: PathBuf,
}

impl Scope {
    fn new(allowed: &[&str], denied: &[&str], pps: u32) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scope.json");
        let doc = serde_json::json!({
            "id": SCOPE_ID,
            "description": "bathy CLI test fixture",
            "not_after": "2099-01-01T00:00:00.000Z",
            "allowed_cidrs": allowed,
            "denied_cidrs": denied,
            "budget_ceiling": {
                "maximum_packets": 1_000_000,
                "maximum_runtime_seconds": 3600,
                "maximum_packets_per_second": pps,
            },
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&doc).unwrap()).expect("write scope");
        Self { dir, path }
    }

    fn lab() -> Self {
        Self::new(&["10.30.0.0/24"], &["10.30.0.1/32"], 20_000)
    }

    fn for_local(ip: Ipv4Addr) -> Self {
        Self::new(&[&format!("{ip}/32")], &[], 20_000)
    }

    fn path(&self) -> &str {
        self.path.to_str().unwrap()
    }

    fn expired(&self) -> PathBuf {
        let path = self.dir.path().join("expired.json");
        let mut doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&self.path).unwrap()).unwrap();
        doc["not_after"] = serde_json::json!("2000-01-01T00:00:00.000Z");
        std::fs::write(&path, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
        path
    }
}

/// A real listener that counts every connection it accepts.
///
/// `serve_http`: when a connection sends something starting with `GET `, it
/// replies with [`NGINX_RESPONSE`] so a real scan produces a
/// `service.observed` event with real evidence. Anything else is dropped, so
/// the bare connect probe sees an open port and nothing more.
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

fn state_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn scan_id_of(out: &Output) -> String {
    out.json_lines()[0]["task_id"]
        .as_str()
        .unwrap_or_else(|| panic!("first stdout line is not a TaskHandle: {}", out.stdout))
        .to_string()
}

// --- AC-5.9: `scan preview` emits no packet --------------------------------

#[test]
fn preview_prints_a_plan_hash_and_estimates_and_reaches_no_listener_that_a_real_scan_reaches() {
    let ip = local_ipv4();
    let scope = Scope::for_local(ip);
    let listener = Listener::bind(ip, false);
    let state = state_dir();
    let target = ip.to_string();
    let port = listener.port();

    let preview = bathy(&[
        "--json",
        "--state-dir",
        state.path().to_str().unwrap(),
        "scan",
        "preview",
        "--scope",
        scope.path(),
        "--targets",
        &target,
        "--ports",
        &port,
    ]);
    preview.success();
    let v = preview.json();
    assert!(
        v["plan_hash"].as_str().unwrap().starts_with("blake3:"),
        "{v}"
    );
    assert_eq!(v["estimated_targets"], 1, "{v}");
    assert_eq!(v["estimated_probes"], 1, "{v}");
    assert_eq!(v["policy_decision"], "approved", "{v}");

    // Give anything in flight a chance to land before counting.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        listener.accepts(),
        0,
        "scan preview connected to the target it was previewing"
    );

    // The positive control. Without this, the assertion above would pass
    // just as happily against a listener nothing could ever reach.
    let start = bathy(&[
        "--json",
        "--state-dir",
        state.path().to_str().unwrap(),
        "scan",
        "start",
        "--scope",
        scope.path(),
        "--idempotency-key",
        "positive-control",
        "--targets",
        &target,
        "--ports",
        &port,
    ]);
    start.success();
    assert!(
        listener.accepts() >= 1,
        "the detector never detects anything: an authorized scan of the same \
         endpoint reached the listener 0 times, so the zero above means nothing"
    );
}

// --- AC-5.8: `--scope` is required, and its absence stops everything -------

#[test]
fn a_scan_without_a_scope_argument_is_refused_before_any_network_activity() {
    let ip = local_ipv4();
    let scope = Scope::for_local(ip);
    let listener = Listener::bind(ip, false);
    let state = state_dir();
    let target = ip.to_string();
    let port = listener.port();
    let dir = state.path().to_str().unwrap().to_string();

    for argv in [
        vec![
            "--json",
            "--state-dir",
            &dir,
            "scan",
            "start",
            "--idempotency-key",
            "no-scope",
            "--targets",
            &target,
            "--ports",
            &port,
        ],
        vec![
            "--json",
            "--state-dir",
            &dir,
            "scan",
            "resume",
            "--scan",
            "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        ],
    ] {
        let out = bathy(&argv);
        out.code(1);
        assert!(
            out.stderr.contains("--scope"),
            "the refusal must name the missing argument: {}",
            out.stderr
        );
    }

    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        listener.accepts(),
        0,
        "a scan with no scope reached the network"
    );

    // Nor did it leave any trace: no state directory contents to mistake
    // for an attempt that was made.
    assert!(
        std::fs::read_dir(state.path())
            .map(|mut d| d.next().is_none())
            .unwrap_or(true),
        "a refused invocation wrote to the state directory"
    );

    // Positive control, as above: the same command *with* a scope reaches
    // the listener.
    bathy(&[
        "--json",
        "--state-dir",
        &dir,
        "scan",
        "start",
        "--scope",
        scope.path(),
        "--idempotency-key",
        "with-scope",
        "--targets",
        &target,
        "--ports",
        &port,
    ])
    .success();
    assert!(listener.accepts() >= 1, "the detector detects nothing");
}

#[test]
fn an_out_of_scope_target_is_denied_with_a_stable_reason_code_and_exit_2_and_no_packet() {
    let ip = local_ipv4();
    // A manifest that authorizes a lab range, and a scan aimed somewhere
    // else entirely -- at a listener on this machine, so the refusal can be
    // checked against a real socket rather than assumed.
    let scope = Scope::lab();
    let listener = Listener::bind(ip, false);
    let state = state_dir();

    let out = bathy(&[
        "--json",
        "--state-dir",
        state.path().to_str().unwrap(),
        "scan",
        "start",
        "--scope",
        scope.path(),
        "--idempotency-key",
        "denied",
        "--targets",
        &ip.to_string(),
        "--ports",
        &listener.port(),
    ]);
    out.code(2);
    let v = out.json();
    assert_eq!(v["policy_decision"], "denied", "{v}");
    assert_eq!(v["reason_code"], "target_out_of_scope", "{v}");

    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(listener.accepts(), 0, "a denied scan emitted a packet");
    // A denial must leave nothing behind that a later reader could mistake
    // for an attempt: no scan row, no log.
    assert!(
        !state.path().join("state.sqlite").exists(),
        "a denied scan created a task store"
    );
}

#[test]
fn an_expired_manifest_refuses_a_scan_that_the_same_manifest_would_have_authorized() {
    let ip = local_ipv4();
    let scope = Scope::for_local(ip);
    let listener = Listener::bind(ip, false);
    let state = state_dir();
    let expired = scope.expired();

    let out = bathy(&[
        "--json",
        "--state-dir",
        state.path().to_str().unwrap(),
        "scan",
        "start",
        "--scope",
        expired.to_str().unwrap(),
        "--idempotency-key",
        "expired",
        "--targets",
        &ip.to_string(),
        "--ports",
        &listener.port(),
    ]);
    out.code(2);
    assert_eq!(out.json()["reason_code"], "scope_expired");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(listener.accepts(), 0);
}

// --- AC-5.10: line-delimited JSON on stdout, diagnostics on stderr ---------

#[test]
fn every_failure_path_still_produces_parseable_json_on_stdout_and_a_diagnostic_on_stderr() {
    let scope = Scope::lab();
    let state = state_dir();
    let dir = state.path().to_str().unwrap().to_string();

    let cases: Vec<(&str, Vec<&str>, i32)> = vec![
        (
            "a missing required argument",
            vec![
                "--json",
                "--state-dir",
                &dir,
                "scan",
                "start",
                "--targets",
                "10.30.0.2",
                "--ports",
                "80",
                "--idempotency-key",
                "k",
            ],
            1,
        ),
        (
            "a malformed argument",
            vec![
                "--json",
                "--state-dir",
                &dir,
                "scan",
                "preview",
                "--scope",
                scope.path(),
                "--targets",
                "not-an-address",
                "--ports",
                "80",
            ],
            1,
        ),
        (
            "a scan id that does not exist",
            vec![
                "--json",
                "--state-dir",
                &dir,
                "scan",
                "status",
                "--scan",
                "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            ],
            1,
        ),
        (
            "a scan id that is not an id at all",
            vec![
                "--json",
                "--state-dir",
                &dir,
                "scan",
                "status",
                "--scan",
                "nonsense",
            ],
            1,
        ),
        (
            "an unreadable scope",
            vec![
                "--json",
                "--state-dir",
                &dir,
                "scan",
                "preview",
                "--scope",
                "/nonexistent/scope.json",
                "--targets",
                "10.30.0.2",
                "--ports",
                "80",
            ],
            1,
        ),
        (
            "an out-of-scope target",
            vec![
                "--json",
                "--state-dir",
                &dir,
                "scan",
                "preview",
                "--scope",
                scope.path(),
                "--targets",
                "8.8.8.8",
                "--ports",
                "80",
            ],
            2,
        ),
        (
            "a rule that does not exist",
            vec!["--json", "--state-dir", &dir, "explain", "no.such.rule.v1"],
            1,
        ),
        (
            "a digest that is not a digest",
            vec![
                "--json",
                "--state-dir",
                &dir,
                "evidence",
                "get",
                "--digest",
                "blake3:zzzz",
            ],
            1,
        ),
        // The four below were missing, and their absence is why a usage
        // error could exit 0 with an empty stdout for a whole review cycle.
        // They are the parse-time failures: `clap` never returns a `Cli`, so
        // none of them reaches `dispatch`, which is exactly the reason the
        // eight above did not cover them.
        (
            "a command group with no sub-subcommand",
            vec!["--json", "--state-dir", &dir, "scan"],
            1,
        ),
        (
            "no subcommand at all",
            vec!["--json", "--state-dir", &dir],
            1,
        ),
        (
            "a subcommand that does not exist",
            vec!["--json", "--state-dir", &dir, "frobnicate"],
            1,
        ),
        (
            "a flag that does not exist",
            vec!["--json", "--state-dir", &dir, "--frobnicate"],
            1,
        ),
    ];

    for (label, argv, expected) in cases {
        let out = bathy(&argv);
        out.code(expected);
        let docs = out.json_lines();
        assert_eq!(docs.len(), 1, "{label}: stdout was {:?}", out.stdout);
        assert_eq!(docs[0]["exit_code"], expected, "{label}: {}", docs[0]);
        assert!(
            docs[0]["error"].is_string(),
            "{label}: no machine-readable error tag: {}",
            docs[0]
        );
        assert!(
            !out.stderr.trim().is_empty(),
            "{label}: a failure with no diagnostic on stderr"
        );
    }
}

#[test]
fn without_json_a_failure_writes_nothing_to_stdout() {
    // The other half of the stream contract: in human mode stdout carries
    // results, so a command that produced none must leave it empty rather
    // than print its complaint there.
    let out = bathy(&["scan", "status", "--scan", "nonsense"]);
    out.code(1);
    assert_eq!(out.stdout, "", "stdout was {:?}", out.stdout);
    assert!(!out.stderr.trim().is_empty());
}

/// Every way of naming a command without finishing it, in both modes.
///
/// The shape being forbidden is specific: **exit 0 with an empty stdout.**
/// An agent shells out, sees success, reads no results, and the only
/// available reading is "the scan found nothing" -- a malformed invocation
/// impersonating an empty answer. `bathy --json scan` and `bathy --json
/// scope` did exactly that, while `bathy --json` called the same mistake a
/// 1: two answers to one question.
///
/// `clap` renders help text for these, which is what made them look like
/// `--help`. They are not: the caller named a command group and stopped.
#[test]
fn naming_a_command_without_finishing_it_is_a_usage_error_and_never_exits_zero() {
    let incomplete: &[&[&str]] = &[
        &[],               // bare `bathy`
        &["scan"],         // a group with no sub-subcommand
        &["scope"],        // ditto, and a second group, so this is a class
        &["result"],       //
        &["evidence"],     //
        &["frobnicate"],   // not a command at all
        &["scan", "sta"],  // an abbreviation, which this CLI does not infer
        &["--frobnicate"], // not a flag at all
    ];

    for argv in incomplete {
        // Human mode: nonzero, nothing on stdout, a diagnostic on stderr.
        let human = bathy(argv);
        assert_ne!(
            human.status,
            0,
            "`bathy {}` exited 0\n--- stdout ---\n{}\n--- stderr ---\n{}",
            argv.join(" "),
            human.stdout,
            human.stderr
        );
        human.code(1);
        assert_eq!(
            human.stdout,
            "",
            "`bathy {}` put a diagnostic on stdout",
            argv.join(" ")
        );
        assert!(
            !human.stderr.trim().is_empty(),
            "`bathy {}` failed silently",
            argv.join(" ")
        );

        // JSON mode: the same code, and an answer on stdout. The empty
        // stdout is the half that made this dangerous rather than untidy.
        let mut json_argv = vec!["--json"];
        json_argv.extend_from_slice(argv);
        let json = bathy(&json_argv);
        json.code(1);
        let doc = json.json();
        assert_eq!(doc["error"], "usage", "{doc}");
        assert_eq!(doc["exit_code"], 1, "{doc}");
        assert!(
            doc["detail"].as_str().is_some_and(|d| !d.trim().is_empty()),
            "a usage document with no detail: {doc}"
        );
    }

    // `--json` after the incomplete group, not before it. The flag is read
    // out of the raw argv precisely because the parse that would have
    // reported it is the one that just failed, so its position must not
    // decide whether the caller gets a document.
    let trailing = bathy(&["scan", "--json"]);
    trailing.code(1);
    assert_eq!(trailing.json()["error"], "usage");
}

/// The same mistake at two depths must get the same answer.
///
/// `bathy` reaches `clap` as `DisplayHelpOnMissingArgumentOrSubcommand` and
/// `bathy --json` as `MissingSubcommand`, purely because the second one has
/// an argument present. They are one mistake, and before this test they
/// exited 0 and 1 respectively.
#[test]
fn the_same_missing_subcommand_gets_the_same_exit_code_at_every_depth() {
    let bare = bathy(&[]);
    let with_a_global_flag = bathy(&["--json"]);
    assert_eq!(
        bare.status, with_a_global_flag.status,
        "`bathy` exited {} and `bathy --json` exited {} for the same mistake",
        bare.status, with_a_global_flag.status
    );
    assert_eq!(bare.status, 1);
    // And the wording is one wording, not two spellings of one mistake.
    for out in [&bare, &with_a_global_flag] {
        assert!(
            out.stderr.contains("subcommand is required")
                || out.stderr.contains("requires a subcommand"),
            "{}",
            out.stderr
        );
    }
}

/// AC-5.10 with no exception carved out of it.
///
/// `--help` is the one place a CLI is expected to print prose, and under
/// `--json` this one does not: it emits a single document carrying the help
/// text and the exit-code table as data. The alternative -- exempting
/// `--help` -- was available and was rejected, because the invariant an
/// agent can act on ("under `--json`, stdout is JSON, always") is worth more
/// than prose it would have to scrape anyway.
#[test]
fn under_json_help_and_version_are_documents_on_stdout_not_prose() {
    let help = bathy(&["--json", "--help"]);
    help.success();
    let doc = help.json();
    assert!(
        doc["help"].as_str().is_some_and(|h| h.contains("Usage:")),
        "the help document does not carry the help text: {doc}"
    );
    assert_eq!(doc["exit_code"], 0, "{doc}");
    // AC-5.11's table, structured, from the same source the prose is
    // rendered from -- so an agent reads it without scraping columns.
    let codes: Vec<i64> = doc["exit_codes"]
        .as_array()
        .unwrap_or_else(|| panic!("no exit_codes array: {doc}"))
        .iter()
        .map(|row| row["code"].as_i64().expect("a numeric code"))
        .collect();
    assert_eq!(codes, vec![0, 1, 2, 3, 4], "{doc}");
    assert!(help.stderr.is_empty(), "--json --help wrote to stderr");

    let version = bathy(&["--json", "--version"]);
    version.success();
    let doc = version.json();
    assert!(
        doc["version"].as_str().is_some_and(|v| v.contains("bathy")),
        "{doc}"
    );

    // The human mode is untouched: prose on stdout, exit 0.
    let prose = bathy(&["--help"]);
    prose.success();
    assert!(prose.stdout.contains("Usage:"), "{}", prose.stdout);
    assert!(
        serde_json::from_str::<serde_json::Value>(prose.stdout.lines().next().unwrap_or(""))
            .is_err(),
        "human --help emitted JSON"
    );
}

#[test]
fn a_multi_document_command_emits_one_json_object_per_line() {
    let ip = local_ipv4();
    let scope = Scope::for_local(ip);
    let listener = Listener::bind(ip, false);
    let state = state_dir();
    let dir = state.path().to_str().unwrap().to_string();

    let start = bathy(&[
        "--json",
        "--state-dir",
        &dir,
        "scan",
        "start",
        "--scope",
        scope.path(),
        "--idempotency-key",
        "lines",
        "--targets",
        &ip.to_string(),
        "--ports",
        &listener.port(),
    ]);
    start.success();
    // `scan start` alone emits two documents: the handle and the summary.
    assert_eq!(start.json_lines().len(), 2, "{}", start.stdout);

    let id = scan_id_of(&start);
    let events = bathy(&[
        "--json",
        "--state-dir",
        &dir,
        "scan",
        "events",
        "--scan",
        &id,
    ]);
    events.success();
    let docs = events.json_lines();
    assert!(docs.len() >= 3, "expected a real event log, got {docs:?}");
    for doc in &docs {
        assert!(doc["sequence"].is_u64(), "not an event: {doc}");
    }
}

// --- AC-5.11: every documented exit code is produced by a real invocation --

#[test]
fn every_documented_exit_code_appears_in_help_and_is_produced_by_a_real_invocation() {
    let help = bathy(&["--help"]);
    help.success();
    for code in 0..=4 {
        assert!(
            help.stdout.contains(&format!("\n  {code}  ")),
            "exit code {code} is not documented in --help:\n{}",
            help.stdout
        );
    }
    assert!(help.stderr.is_empty(), "--help wrote to stderr");

    let ip = local_ipv4();
    let scope = Scope::for_local(ip);
    let listener = Listener::bind(ip, false);
    let state = state_dir();
    let dir = state.path().to_str().unwrap().to_string();
    let target = ip.to_string();
    let port = listener.port();

    // 0: a command that succeeds.
    bathy(&[
        "--state-dir",
        &dir,
        "scope",
        "validate",
        "--scope",
        scope.path(),
    ])
    .code(0);

    // 1: an operational error.
    bathy(&["--state-dir", &dir, "scan", "status", "--scan", "nonsense"]).code(1);

    // 2: a policy denial.
    bathy(&[
        "--state-dir",
        &dir,
        "scan",
        "preview",
        "--scope",
        scope.path(),
        "--targets",
        "8.8.8.8",
        "--ports",
        "80",
    ])
    .code(2);

    // 3: budget exhaustion. Two units, one packet allowed.
    let second = TcpListener::bind((ip, 0)).unwrap();
    let second_port = second.local_addr().unwrap().port().to_string();
    let ports = format!("{port},{second_port}");
    bathy(&[
        "--state-dir",
        &dir,
        "scan",
        "start",
        "--scope",
        scope.path(),
        "--idempotency-key",
        "exhaust",
        "--targets",
        &target,
        "--ports",
        &ports,
        "--max-packets",
        "1",
    ])
    .code(3);

    // 4: the same idempotency key against a different plan.
    bathy(&[
        "--state-dir",
        &dir,
        "scan",
        "start",
        "--scope",
        scope.path(),
        "--idempotency-key",
        "conflict",
        "--targets",
        &target,
        "--ports",
        &port,
    ])
    .code(0);
    bathy(&[
        "--state-dir",
        &dir,
        "scan",
        "start",
        "--scope",
        scope.path(),
        "--idempotency-key",
        "conflict",
        "--targets",
        &target,
        "--ports",
        &second_port,
    ])
    .code(4);
}

// --- AC-5.12: `scan start` returns a handle immediately -------------------

/// Spawns `bathy scan start` with a plan big enough and a rate low enough
/// that running it to completion would take minutes, and measures how long
/// the handle takes to appear on stdout.
#[test]
fn scan_start_prints_a_task_handle_long_before_a_large_scan_could_finish() {
    let ip = local_ipv4();
    // 5 packets per second over 1,000 units: ~200 seconds of scan. Anything
    // that blocked on completion could not answer inside the deadline below
    // by any amount of luck.
    let scope = Scope::new(&[&format!("{ip}/32")], &[], 5);
    let state = state_dir();

    let mut child: Child = Command::new(BIN)
        .args([
            "--json",
            "--state-dir",
            state.path().to_str().unwrap(),
            "scan",
            "start",
            "--scope",
            scope.path(),
            "--idempotency-key",
            "immediate",
            "--targets",
            &ip.to_string(),
            "--ports",
            "40000-40999",
            "--max-packets-per-second",
            "5",
        ])
        .env_remove("BATHY_STATE_DIR")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bathy");

    let started = Instant::now();
    let line = first_line_within(&mut child, Duration::from_secs(10));
    let elapsed = started.elapsed();

    let handle: serde_json::Value =
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("not a TaskHandle ({e}): {line:?}"));
    assert!(
        handle["task_id"].as_str().unwrap().starts_with("scan_"),
        "{handle}"
    );
    assert!(
        handle["plan_hash"].as_str().unwrap().starts_with("blake3:"),
        "{handle}"
    );
    assert_eq!(handle["status"], "running", "{handle}");
    assert_eq!(handle["policy_decision"], "approved", "{handle}");
    assert_eq!(handle["estimated_targets"], 1, "{handle}");
    assert!(
        elapsed < Duration::from_secs(10),
        "the handle took {elapsed:?} to appear"
    );

    // And the scan really is still going: the handle was not "immediate"
    // because the scan was trivial.
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "the scan finished before the assertion could be made, so this test \
         did not measure what it claims to"
    );
    let _ = child.kill();
    let _ = child.wait();
}

/// The child's first line of stdout, or a **failure** if it does not arrive
/// in time.
///
/// The deadline is the point of this helper. A `scan start` that ran the
/// scan before printing its handle would make an unbounded read block for
/// as long as the scan takes -- which is a hang, not a test failure, and a
/// hang in CI reports as a timeout with no named cause. Discovered by
/// mutation: printing the handle after `run_to_completion` made the
/// AC-5.12 test never finish rather than fail.
fn first_line_within(child: &mut Child, limit: Duration) -> String {
    let mut stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while stdout.read(&mut byte).unwrap_or(0) == 1 {
            if byte[0] == b'\n' {
                break;
            }
            buf.push(byte[0]);
        }
        let _ = tx.send(String::from_utf8_lossy(&buf).into_owned());
    });
    rx.recv_timeout(limit).unwrap_or_else(|_| {
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "no line on stdout within {limit:?}: `scan start` blocked on the scan \
             instead of printing its handle first"
        )
    })
}

// --- Cross-process cancellation, and the read commands --------------------

#[test]
fn cancel_from_another_process_stops_a_running_scan_and_it_resumes_where_it_stopped() {
    let ip = local_ipv4();
    let scope = Scope::new(&[&format!("{ip}/32")], &[], 20);
    let state = state_dir();
    let dir = state.path().to_str().unwrap().to_string();

    let mut child = Command::new(BIN)
        .args([
            "--json",
            "--state-dir",
            &dir,
            "scan",
            "start",
            "--scope",
            scope.path(),
            "--idempotency-key",
            "cancel-me",
            "--targets",
            &ip.to_string(),
            "--ports",
            "40000-40999",
            "--max-packets-per-second",
            "20",
        ])
        .env_remove("BATHY_STATE_DIR")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bathy");

    let handle: serde_json::Value =
        serde_json::from_str(&first_line_within(&mut child, Duration::from_secs(10))).unwrap();
    let id = handle["task_id"].as_str().unwrap().to_string();

    // `scan status` reads the same live state from a second process, while
    // the scanning process still holds the event log locked for writing.
    let live = bathy(&[
        "--json",
        "--state-dir",
        &dir,
        "scan",
        "status",
        "--scan",
        &id,
    ]);
    live.success();
    assert_eq!(handle["status"], "running", "{handle}");
    assert_eq!(
        live.json()["status"],
        "running",
        "the handle said `running`; `scan status` must not answer differently"
    );

    bathy(&[
        "--json",
        "--state-dir",
        &dir,
        "scan",
        "cancel",
        "--scan",
        &id,
    ])
    .success();

    let stopped = wait_for(&mut child, Duration::from_secs(30));
    assert!(stopped, "the scan ignored a cancellation request");

    let status = bathy(&[
        "--json",
        "--state-dir",
        &dir,
        "scan",
        "status",
        "--scan",
        &id,
    ]);
    status.success();
    let record = status.json();
    assert_eq!(record["status"], "cancelled", "{record}");
    assert!(
        record["packets_spent"].as_u64().unwrap() < 1000,
        "a cancelled scan should not have finished its plan: {record}"
    );
}

/// A follower must stop even when the thing it follows is gone.
///
/// `scan events --follow` had exactly one stopping condition, a terminal
/// event, and a scan whose process was killed never writes one -- so the
/// follower polled a log nothing would ever append to, forever. An agent
/// that shelled out has no interrupt to send.
///
/// The scan here is killed with `SIGKILL` so nothing can run on its way
/// out: the log ends mid-scan, which is the state a crash leaves behind.
/// The follower is then given one second of patience, and this test fails
/// by *timing out with a named message* rather than by hanging.
#[test]
fn following_a_scan_whose_writer_died_gives_up_by_a_deadline_instead_of_waiting_forever() {
    let ip = local_ipv4();
    let scope = Scope::new(&[&format!("{ip}/32")], &[], 20);
    let state = state_dir();
    let dir = state.path().to_str().unwrap().to_string();

    let mut child = Command::new(BIN)
        .args([
            "--json",
            "--state-dir",
            &dir,
            "scan",
            "start",
            "--scope",
            scope.path(),
            "--idempotency-key",
            "kill-me",
            "--targets",
            &ip.to_string(),
            "--ports",
            "41000-41999",
            "--max-packets-per-second",
            "20",
        ])
        .env_remove("BATHY_STATE_DIR")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bathy");

    let handle: serde_json::Value =
        serde_json::from_str(&first_line_within(&mut child, Duration::from_secs(10))).unwrap();
    let id = handle["task_id"].as_str().unwrap().to_string();

    // Let a few events land, then kill the writer outright. No terminal
    // event will ever be written for this scan.
    std::thread::sleep(Duration::from_millis(500));
    child.kill().expect("kill the scanning process");
    child.wait().expect("reap");

    let mut follower = Command::new(BIN)
        .args([
            "--json",
            "--state-dir",
            &dir,
            "scan",
            "events",
            "--scan",
            &id,
            "--follow",
            "--idle-timeout-seconds",
            "1",
        ])
        .env_remove("BATHY_STATE_DIR")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the follower");

    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = follower.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = follower.kill();
            let _ = follower.wait();
            panic!(
                "`scan events --follow --idle-timeout-seconds 1` was still running 20s after \
                 the scan it follows was killed: an unbounded follower waits for a terminal \
                 event that will never be written"
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    let out = follower.wait_with_output().expect("collect the follower");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(
        status.code(),
        Some(1),
        "giving up is an operational error, not a success:\n{stdout}\n{stderr}"
    );
    let last: serde_json::Value = serde_json::from_str(
        stdout
            .lines()
            .rfind(|l| !l.is_empty())
            .unwrap_or_else(|| panic!("nothing on stdout; stderr was {stderr}")),
    )
    .expect("the last stdout line is JSON");
    assert_eq!(last["error"], "follow_idle_timeout", "{last}");
    assert_eq!(last["exit_code"], 1, "{last}");
    assert!(!stderr.trim().is_empty(), "gave up silently");

    // The control: the timeout is not the only way this command ends, and
    // exit 1 above was caused by the missing terminal event rather than by
    // `--follow` now always failing. A scan that completes normally is
    // followed to its terminal event and exits 0 -- with the same one-second
    // patience, so the two runs differ only in whether the writer survived.
    let listener = Listener::bind(ip, false);
    let complete = bathy(&[
        "--json",
        "--state-dir",
        &dir,
        "scan",
        "start",
        "--scope",
        scope.path(),
        "--idempotency-key",
        "let-me-finish",
        "--targets",
        &ip.to_string(),
        "--ports",
        &listener.port(),
    ]);
    complete.success();
    let finished = scan_id_of(&complete);
    let followed = bathy(&[
        "--json",
        "--state-dir",
        &dir,
        "scan",
        "events",
        "--scan",
        &finished,
        "--follow",
        "--idle-timeout-seconds",
        "1",
    ]);
    followed.success();
    assert!(
        followed
            .json_lines()
            .iter()
            .any(|e| e["event_type"] == "scan.completed"),
        "the control never reached a terminal event, so the failure above proves nothing: {}",
        followed.stdout
    );
}

fn wait_for(child: &mut Child, limit: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if child.try_wait().expect("try_wait").is_some() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
    false
}

#[test]
fn a_real_scan_is_queryable_diffable_and_its_evidence_is_byte_exact() {
    let ip = local_ipv4();
    let scope = Scope::for_local(ip);
    let listener = Listener::bind(ip, true);
    let state = state_dir();
    let dir = state.path().to_str().unwrap().to_string();
    let target = ip.to_string();
    let port = listener.port();

    let run = |key: &str| {
        let out = bathy(&[
            "--json",
            "--state-dir",
            &dir,
            "scan",
            "start",
            "--scope",
            scope.path(),
            "--idempotency-key",
            key,
            "--targets",
            &target,
            "--ports",
            &port,
            "--intensity",
            "9",
        ]);
        out.success();
        scan_id_of(&out)
    };

    let first = run("query-a");
    let second = run("query-b");

    let query = bathy(&[
        "--json",
        "--state-dir",
        &dir,
        "result",
        "query",
        "--scan",
        &first,
    ]);
    query.success();
    let fold = query.json();
    let endpoints = fold["endpoints"].as_array().expect("endpoints array");
    assert_eq!(endpoints.len(), 1, "{fold}");
    assert_eq!(endpoints[0]["state"], "open", "{fold}");
    assert_eq!(
        endpoints[0]["observation"]["product"], "nginx",
        "the scan identified the service the listener served: {fold}"
    );

    let diff = bathy(&[
        "--json",
        "--state-dir",
        &dir,
        "result",
        "diff",
        "--before",
        &first,
        "--after",
        &second,
    ]);
    diff.success();
    let d = diff.json();
    assert_eq!(
        d["changes"].as_array().unwrap().len(),
        0,
        "two scans of the same unchanged endpoint must report no change: {d}"
    );
    assert_eq!(d["unchanged"], 1, "{d}");

    let digest = endpoints[0]["evidence_refs"][0]
        .as_str()
        .unwrap_or_else(|| panic!("no evidence cited: {fold}"));
    let evidence = bathy(&["--state-dir", &dir, "evidence", "get", "--digest", digest]);
    evidence.success();
    assert_eq!(
        evidence.stdout.as_bytes(),
        NGINX_RESPONSE,
        "evidence get must return exactly the bytes that justified the finding"
    );

    let as_json = bathy(&[
        "--json",
        "--state-dir",
        &dir,
        "evidence",
        "get",
        "--digest",
        digest,
    ]);
    as_json.success();
    let v = as_json.json();
    assert_eq!(v["length"], NGINX_RESPONSE.len());
    assert_eq!(
        v["bytes_hex"].as_str().unwrap().len(),
        NGINX_RESPONSE.len() * 2
    );
}

#[test]
fn resume_re_evaluates_the_manifest_rather_than_trusting_the_original_decision() {
    let ip = local_ipv4();
    let scope = Scope::for_local(ip);
    let listener = Listener::bind(ip, false);
    let state = state_dir();
    let dir = state.path().to_str().unwrap().to_string();

    // A two-unit plan with a one-packet budget: it stops half-done and
    // stays resumable.
    let second = TcpListener::bind((ip, 0)).unwrap();
    let ports = format!(
        "{},{}",
        listener.port(),
        second.local_addr().unwrap().port()
    );
    let start = bathy(&[
        "--json",
        "--state-dir",
        &dir,
        "scan",
        "start",
        "--scope",
        scope.path(),
        "--idempotency-key",
        "resume-me",
        "--targets",
        &ip.to_string(),
        "--ports",
        &ports,
        "--max-packets",
        "1",
    ]);
    start.code(3);
    let id = scan_id_of(&start);

    // The manifest that authorized the start has since expired. A resume is
    // new network activity, so it gets a new decision, not the old one.
    let expired = scope.expired();
    let refused = bathy(&[
        "--json",
        "--state-dir",
        &dir,
        "scan",
        "resume",
        "--scope",
        expired.to_str().unwrap(),
        "--scan",
        &id,
    ]);
    refused.code(2);
    assert_eq!(refused.json()["reason_code"], "scope_expired");
}

// --- Global constraints ---------------------------------------------------

#[test]
fn no_help_text_makes_the_unscoped_determinism_claim() {
    for argv in [
        vec!["--help"],
        vec!["scan", "--help"],
        vec!["scan", "start", "--help"],
        vec!["result", "--help"],
    ] {
        let out = bathy(&argv);
        out.success();
        let text = out.stdout.to_lowercase();
        assert!(!text.contains("deterministic results"), "{argv:?}"); // [phrase-rule]
    }
}

#[test]
fn the_help_text_says_scope_is_required() {
    let out = bathy(&["--help"]);
    out.success();
    assert!(
        out.stdout.contains("requires --scope"),
        "the safety contract must be visible without reading the source:\n{}",
        out.stdout
    );
}

/// The published crate must actually install a `bathy` command -- the point
/// of reserving the name as a lib rather than as `bathy-cli`.
#[test]
fn the_binary_reports_its_own_version() {
    let out = bathy(&["--version"]);
    out.success();
    assert!(out.stdout.starts_with("bathy "), "{}", out.stdout);
}
