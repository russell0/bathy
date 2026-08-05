//! The engine's half of the `packetd` seam: spawning it, initializing it
//! from the authorization it validated against, and driving probes over it.
//!
//! # Why this module is here and not in `bathy-packetd`
//!
//! `packetd` is the only component that will hold `CAP_NET_RAW`, and the
//! argument for trusting it is that a person can read all of it. Everything
//! the *engine* needs in order to talk to it -- process spawning, the
//! handshake, the fallback decision, the mid-scan death policy -- is
//! unprivileged work that would otherwise grow the privileged process, so it
//! lives here. `crates/bathy-packetd` gains no line from M6 Task 4.
//!
//! # There is no compile-time edge to `bathy-packetd`, deliberately
//!
//! `xtask`'s `LAYERS` places `bathy-packetd` *above* `bathy-engine`, so this
//! crate cannot depend on it -- and should not. The engine spawns a
//! *process*, not a library: the two halves are mutually suspicious, and a
//! shared `Session` type in one address space would make that a claim rather
//! than a fact. The line types below are therefore this crate's own
//! statement of the protocol.
//!
//! **Two statements of one protocol are worth nothing unless something
//! checks they agree**, which is the rule this repository applies to
//! `packetd`'s duplicated scope check. The check here is by *execution*, not
//! by type equality: `crates/bathy-engine/tests/packetd_integration.rs` and
//! `crates/bathy-engine/tests/syn_vs_connect.rs` drive the **real
//! `bathy-packetd` binary** over a real pipe. A field renamed on either side
//! makes the handshake fail and takes AC-6.14, AC-6.15 and AC-6.16 red
//! together. A type-level assertion would not have caught a divergence in
//! what the *daemon* does with a field it still parses.
//!
//! # AC-6.17: where the allowlist comes from
//!
//! [`init_request`] takes a `&ScopeManifest` **and nothing else**. It is not
//! that it declines to read the request; there is no request in scope for it
//! to read. The raw `ScanRequest` cannot influence what a privileged process
//! is told it may touch, because the function that decides has no way to
//! name it. See the test module for the falsifier: a request whose targets
//! are a strict subset of the manifest still produces the manifest's own
//! CIDRs.
//!
//! # Failure policy, and why there are two reason codes
//!
//! - **It never started** (no `CAP_NET_RAW`, no binary, a refused
//!   handshake): the engine falls back to connect scanning and records
//!   [`ScanMode::TcpConnect`] on `scan.started` (AC-6.15). Nothing is lost
//!   but speed, and the result says which method produced it.
//! - **It died mid-scan**: the scan fails with `packetd_unavailable`
//!   (AC-6.16). Quietly finishing the remaining endpoints with connect
//!   probes would produce one result set assembled by two methods, which is
//!   incomparable with itself and which the operator believes is a SYN scan.
//! - **It refused a probe**: the scan fails with `packetd_refused`. A
//!   refusal means the engine asked a privileged process to touch something
//!   that process's own independent scope check rejected -- the two halves
//!   disagree about an authorization boundary. Recording the endpoint as
//!   indeterminate and carrying on would turn a security-relevant
//!   disagreement into a missing row.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bathy_scope::ScopeManifest;
use bathy_types::event::{PortState, ScanMode};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Where the daemon is, and whether the engine may use it.
///
/// `Option<PathBuf>` rather than a bare path with a "" sentinel: "no SYN
/// scanning was asked for" and "SYN scanning was asked for and the binary is
/// missing" are different situations, and only the second one is a fallback
/// worth logging.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PacketdConfig {
    /// The `bathy-packetd` binary. `None` means connect scanning was
    /// requested and no attempt to spawn anything will be made.
    pub binary: Option<PathBuf>,
}

impl PacketdConfig {
    /// Ask for SYN scanning through the daemon at `binary`.
    pub fn syn_via(binary: impl Into<PathBuf>) -> Self {
        Self {
            binary: Some(binary.into()),
        }
    }

    /// The mode this configuration asks for, before anything is spawned.
    pub fn requested_mode(&self) -> ScanMode {
        match self.binary {
            Some(_) => ScanMode::TcpSyn,
            None => ScanMode::TcpConnect,
        }
    }
}

// ---------------------------------------------------------------------------
// The line protocol, as this side states it.
// ---------------------------------------------------------------------------

/// A line the engine writes. Mirrors `bathy_packetd::protocol::Request`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Init {
        allowed_cidrs: Vec<IpNet>,
        denied_cidrs: Vec<IpNet>,
        packets_per_second: u32,
        max_packets: u64,
    },
    Probe {
        id: u64,
        target: IpAddr,
        port: u16,
    },
    Shutdown,
}

/// A line the engine reads. Mirrors `bathy_packetd::protocol::Response`.
///
/// `deny_unknown_fields` is the same mutual suspicion the other side
/// applies: a response carrying a field this build does not know is two
/// builds disagreeing about the protocol, and the engine must not act on the
/// half it happens to understand.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Ready { dropped_capabilities: bool },
    Result { id: u64, state: PortState },
    Refused { id: u64, reason: String },
    Fatal { detail: String },
}

impl Request {
    /// One line of JSON with its newline, ready for the pipe.
    fn to_line(&self) -> Result<String, PacketdError> {
        let mut line = serde_json::to_string(self)
            .map_err(|e| PacketdError::Unavailable(format!("serializing a request: {e}")))?;
        line.push('\n');
        Ok(line)
    }
}

/// The `Init` a session is opened with, derived from the manifest and from
/// nothing else (AC-6.17).
///
/// Every field comes from the authorization document the engine itself
/// validated against:
///
/// - `allowed_cidrs` / `denied_cidrs` are the manifest's, verbatim. Not the
///   request's targets: a request may name one host inside a /24, and
///   narrowing the daemon's allowlist to that host would make the daemon's
///   scope a function of the caller's ask rather than of the authorization.
///   It would also be *wrong* in the direction that matters -- the second
///   enforcement point would then be enforcing the first point's opinion.
/// - `packets_per_second` / `max_packets` are the manifest's **ceiling**,
///   not the request's budget. The engine's `BudgetLedger` enforces the
///   request's (tighter, already validated <= ceiling) budget; `packetd`'s
///   ceiling is a second, independent bound, and a second bound derived from
///   the same number as the first is not a second bound.
///
/// The signature is the criterion: this function has no parameter through
/// which a `ScanRequest` could reach it.
pub fn init_request(manifest: &ScopeManifest) -> Request {
    let ceiling = manifest.ceiling();
    Request::Init {
        allowed_cidrs: manifest.allowed().to_vec(),
        denied_cidrs: manifest.denied().to_vec(),
        packets_per_second: ceiling.maximum_packets_per_second,
        max_packets: ceiling.maximum_packets,
    }
}

// ---------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------

/// Why the engine could not get an answer out of `packetd`.
///
/// The split is the failure policy: [`Unavailable`](Self::Unavailable) is
/// recoverable by falling back before the scan starts, and the other two are
/// not recoverable at all once it has.
#[derive(Debug, thiserror::Error)]
pub enum PacketdError {
    /// It never got as far as a working session. The engine falls back.
    #[error("packetd is unavailable: {0}")]
    Unavailable(String),
    /// It answered before and does not answer now. AC-6.16.
    #[error("packetd stopped answering mid-scan: {0}")]
    Gone(String),
    /// It refused a probe its own scope check rejected.
    #[error("packetd refused probe {id} at {endpoint}: {reason}")]
    Refused {
        id: u64,
        endpoint: String,
        reason: String,
    },
}

impl PacketdError {
    /// The `scan.failed` reason code this error terminates a scan with, or
    /// `None` if it is the recoverable kind.
    ///
    /// A closed set, in one place, because the terminal reason is what an
    /// agent branches on.
    pub fn terminal_reason(&self) -> Option<&'static str> {
        match self {
            Self::Unavailable(_) => None,
            Self::Gone(_) => Some("packetd_unavailable"),
            Self::Refused { .. } => Some("packetd_refused"),
        }
    }
}

// ---------------------------------------------------------------------------
// The client.
// ---------------------------------------------------------------------------

/// One request to the worker thread, and the channel its answer comes back
/// on.
struct Job {
    request: Request,
    endpoint: String,
    reply: tokio::sync::oneshot::Sender<Result<PortState, PacketdError>>,
}

/// A running `packetd`, initialized and answering.
///
/// The pipes are blocking, and the loop that reads them runs on its own OS
/// thread rather than on the async runtime. A probe that waits out
/// `packetd`'s reply deadline waits over a second; parking a tokio worker
/// for that long would stall the rate limiter and make cancellation
/// (AC-3.25) as slow as the deadline. Nothing here uses `tokio::process`,
/// which would have added the `process` and `signal` features -- and their
/// crates -- to a workspace that has deliberately avoided both.
#[derive(Debug)]
pub struct PacketdClient {
    jobs: std::sync::mpsc::Sender<Job>,
    /// Held so the child can be killed from the async side while the worker
    /// thread is blocked reading from it. This is what AC-6.16's test uses
    /// to kill a real process for real.
    child: Arc<Mutex<Child>>,
    /// Whatever the daemon wrote to stderr, drained by its own thread so a
    /// full pipe can never block it.
    stderr: Arc<Mutex<String>>,
    next_id: AtomicU64,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl PacketdClient {
    /// Spawn `binary`, send the `Init` derived from `manifest`, and wait for
    /// `Ready`.
    ///
    /// Every failure here is [`PacketdError::Unavailable`] and therefore a
    /// fallback rather than a scan failure: the scan has not started, no
    /// packet has been emitted, and connect scanning answers the same
    /// question more slowly.
    ///
    /// A `Ready` claiming `dropped_capabilities: false` is refused. The
    /// daemon measures that field after its own drop (M6 Task 2); a `false`
    /// is the daemon telling the engine it is still privileged, and the
    /// engine must not stream targets to a process in that state just
    /// because it is willing to answer.
    pub fn start(binary: &Path, manifest: &ScopeManifest) -> Result<Self, PacketdError> {
        let mut child = Command::new(binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                PacketdError::Unavailable(format!("spawning {}: {e}", binary.display()))
            })?;

        let mut stdin = take_pipe(&mut child, child_stdin)?;
        let stdout = take_pipe(&mut child, child_stdout)?;
        let stderr = take_pipe(&mut child, child_stderr)?;

        let collected = Arc::new(Mutex::new(String::new()));
        let drain = Arc::clone(&collected);
        // Drained on its own thread: `packetd` writes its AC-6.6 guidance to
        // stderr before exiting 69, and a pipe nobody reads is a pipe that
        // can fill. It is also the text the fallback reason is made of, so
        // discarding it would mean logging "packetd failed" and nothing else.
        std::thread::spawn(move || {
            let mut text = String::new();
            let mut stderr = stderr;
            let _ = stderr.read_to_string(&mut text);
            if let Ok(mut slot) = drain.lock() {
                slot.push_str(&text);
            }
        });

        let mut reader = BufReader::new(stdout);
        let child = Arc::new(Mutex::new(child));

        let handshake = (|| -> Result<(), PacketdError> {
            let line = init_request(manifest).to_line()?;
            stdin
                .write_all(line.as_bytes())
                .and_then(|()| stdin.flush())
                .map_err(|e| PacketdError::Unavailable(format!("writing init: {e}")))?;
            match read_response(&mut reader)? {
                Some(Response::Ready {
                    dropped_capabilities: true,
                }) => Ok(()),
                Some(Response::Ready {
                    dropped_capabilities: false,
                }) => Err(PacketdError::Unavailable(
                    "packetd reported that it still holds capabilities; refusing to stream \
                     targets to a privileged process"
                        .to_string(),
                )),
                Some(Response::Fatal { detail }) => Err(PacketdError::Unavailable(format!(
                    "packetd refused the session: {detail}"
                ))),
                Some(other) => Err(PacketdError::Unavailable(format!(
                    "packetd answered init with {other:?} instead of ready"
                ))),
                None => Err(PacketdError::Unavailable(
                    "packetd exited before answering init".to_string(),
                )),
            }
        })();

        if let Err(e) = handshake {
            let detail = finish_and_describe(&child, &collected);
            kill_child(&child);
            return Err(PacketdError::Unavailable(format!("{e}{detail}")));
        }

        let (jobs, inbox) = std::sync::mpsc::channel::<Job>();
        let worker_stderr = Arc::clone(&collected);
        let worker = std::thread::spawn(move || serve(inbox, stdin, reader, worker_stderr));

        Ok(Self {
            jobs,
            child,
            stderr: collected,
            next_id: AtomicU64::new(1),
            worker: Some(worker),
        })
    }

    /// One SYN probe. Serial by construction: `packetd`'s protocol is one
    /// line in, one line out, and the daemon's own rate limiter paces it.
    pub async fn probe(&self, target: IpAddr, port: u16) -> Result<PortState, PacketdError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (reply, answer) = tokio::sync::oneshot::channel();
        let job = Job {
            request: Request::Probe { id, target, port },
            endpoint: format!("{target}:{port}"),
            reply,
        };
        if self.jobs.send(job).is_err() {
            return Err(PacketdError::Gone(self.postmortem()));
        }
        match answer.await {
            Ok(result) => result,
            Err(_) => Err(PacketdError::Gone(self.postmortem())),
        }
    }

    /// Kill the daemon. Used by [`Drop`] and by AC-6.16's test, which needs
    /// a real process to really die mid-scan.
    pub fn kill(&self) {
        kill_child(&self.child);
    }

    /// The daemon's process id, so a test can confirm the thing it killed is
    /// the thing that was running.
    pub fn pid(&self) -> Option<u32> {
        self.child.lock().ok().map(|child| child.id())
    }

    /// Whatever the daemon said on its way out, for a scan-failure detail
    /// that names a cause instead of a symptom.
    fn postmortem(&self) -> String {
        let said = self
            .stderr
            .lock()
            .map(|text| text.trim().to_string())
            .unwrap_or_default();
        if said.is_empty() {
            "the daemon exited without saying why".to_string()
        } else {
            said
        }
    }
}

impl Drop for PacketdClient {
    /// A scan that ends -- completed, cancelled or failed -- takes the
    /// daemon with it. One `packetd` is one session by design (its
    /// `Session` has no reset), so there is nothing to reuse and a survivor
    /// would be a privileged process holding raw sockets for nobody.
    fn drop(&mut self) {
        kill_child(&self.child);
        // Dropping the sender is what ends the worker's `recv` loop; the
        // kill is what unblocks it if it is mid-read.
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        if let Ok(mut child) = self.child.lock() {
            let _ = child.wait();
        }
    }
}

/// The worker thread: one job in, one line out, one line back.
///
/// Every exit path leaves the sender dropped, which is what turns a pending
/// or future [`PacketdClient::probe`] into [`PacketdError::Gone`] rather
/// than a hang.
fn serve(
    inbox: std::sync::mpsc::Receiver<Job>,
    mut stdin: ChildStdin,
    mut reader: BufReader<ChildStdout>,
    stderr: Arc<Mutex<String>>,
) {
    while let Ok(job) = inbox.recv() {
        let answer = exchange(&mut stdin, &mut reader, &job);
        let fatal = matches!(answer, Err(PacketdError::Gone(_)));
        let answer = match answer {
            Err(PacketdError::Gone(reason)) => {
                let said = stderr
                    .lock()
                    .map(|text| text.trim().to_string())
                    .unwrap_or_default();
                Err(PacketdError::Gone(if said.is_empty() {
                    reason
                } else {
                    format!("{reason}: {said}")
                }))
            }
            other => other,
        };
        let _ = job.reply.send(answer);
        if fatal {
            return;
        }
    }
}

/// One request/response exchange.
fn exchange(
    stdin: &mut ChildStdin,
    reader: &mut BufReader<ChildStdout>,
    job: &Job,
) -> Result<PortState, PacketdError> {
    let line = job.request.to_line()?;
    stdin
        .write_all(line.as_bytes())
        .and_then(|()| stdin.flush())
        .map_err(|e| PacketdError::Gone(format!("writing a probe: {e}")))?;
    let id = match job.request {
        Request::Probe { id, .. } => id,
        _ => 0,
    };
    match read_response(reader) {
        Ok(Some(Response::Result {
            id: answered,
            state,
        })) if answered == id => Ok(state),
        Ok(Some(Response::Result { id: answered, .. })) => Err(PacketdError::Gone(format!(
            "packetd answered probe {answered} while probe {id} was outstanding; the line \
             protocol is one request and one response, so a mismatched id means the two \
             sides have lost sync"
        ))),
        Ok(Some(Response::Refused { id: _, reason })) => Err(PacketdError::Refused {
            id,
            endpoint: job.endpoint.clone(),
            reason,
        }),
        Ok(Some(Response::Fatal { detail })) => {
            Err(PacketdError::Gone(format!("packetd went fatal: {detail}")))
        }
        Ok(Some(other)) => Err(PacketdError::Gone(format!(
            "packetd answered a probe with {other:?}"
        ))),
        Ok(None) => Err(PacketdError::Gone(
            "packetd closed its output mid-scan".to_string(),
        )),
        Err(e) => Err(PacketdError::Gone(format!("{e}"))),
    }
}

/// Read one response line. `Ok(None)` is end of stream.
fn read_response(reader: &mut BufReader<ChildStdout>) -> Result<Option<Response>, PacketdError> {
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) => Ok(None),
        Ok(_) => serde_json::from_str::<Response>(line.trim_end())
            .map(Some)
            .map_err(|e| {
                PacketdError::Gone(format!(
                    "packetd wrote a line this build cannot parse ({e}); the two halves \
                     disagree about the protocol"
                ))
            }),
        Err(e) => Err(PacketdError::Gone(format!("reading from packetd: {e}"))),
    }
}

fn child_stdin(child: &mut Child) -> Option<ChildStdin> {
    child.stdin.take()
}
fn child_stdout(child: &mut Child) -> Option<ChildStdout> {
    child.stdout.take()
}
fn child_stderr(child: &mut Child) -> Option<ChildStderr> {
    child.stderr.take()
}

/// `Stdio::piped()` was asked for, so these are `Some` -- but `expect` in a
/// scan path is a panic, and a fallback is available for every failure here.
fn take_pipe<T>(child: &mut Child, take: fn(&mut Child) -> Option<T>) -> Result<T, PacketdError> {
    take(child).ok_or_else(|| {
        PacketdError::Unavailable("packetd was spawned without a usable pipe".to_string())
    })
}

fn kill_child(child: &Arc<Mutex<Child>>) {
    if let Ok(mut child) = child.lock() {
        let _ = child.kill();
    }
}

/// The exit status and anything on stderr, as a suffix for a fallback
/// reason. This is the AC-6.6 guidance reaching the operator through the
/// engine's log instead of only through a terminal nobody was watching.
fn finish_and_describe(child: &Arc<Mutex<Child>>, stderr: &Arc<Mutex<String>>) -> String {
    let status = child
        .lock()
        .ok()
        .and_then(|mut child| child.wait().ok())
        .and_then(|status| status.code());
    let said = stderr
        .lock()
        .map(|text| text.trim().to_string())
        .unwrap_or_default();
    match (status, said.is_empty()) {
        (Some(code), false) => format!(" (exit {code}: {said})"),
        (Some(code), true) => format!(" (exit {code})"),
        (None, false) => format!(" ({said})"),
        (None, true) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAB_MANIFEST: &str = r#"{
        "id": "scope_01K2HZ8V5N3QR7BXMC4TDWF9GJ",
        "description": "test",
        "not_after": "2099-01-01T00:00:00.000Z",
        "allowed_cidrs": ["10.30.0.0/24"],
        "denied_cidrs": ["10.30.0.1/32"],
        "budget_ceiling": {
            "maximum_packets": 1000000,
            "maximum_runtime_seconds": 3600,
            "maximum_packets_per_second": 100000
        }
    }"#;

    /// A second manifest that differs in every field the `Init` reads. It is
    /// the narrowing control for the test below: without it, an
    /// `init_request` that returned a constant would satisfy the assertion
    /// that the first manifest's CIDRs appear.
    const OTHER_MANIFEST: &str = r#"{
        "id": "scope_01K2HZ8V5N3QR7BXMC4TDWF9GJ",
        "description": "test",
        "not_after": "2099-01-01T00:00:00.000Z",
        "allowed_cidrs": ["192.0.2.0/25", "198.51.100.0/24"],
        "denied_cidrs": [],
        "budget_ceiling": {
            "maximum_packets": 7,
            "maximum_runtime_seconds": 60,
            "maximum_packets_per_second": 3
        }
    }"#;

    fn manifest(json: &str) -> ScopeManifest {
        ScopeManifest::load(json).unwrap()
    }

    fn init_fields(manifest: &ScopeManifest) -> (Vec<String>, Vec<String>, u32, u64) {
        match init_request(manifest) {
            Request::Init {
                allowed_cidrs,
                denied_cidrs,
                packets_per_second,
                max_packets,
            } => (
                allowed_cidrs.iter().map(|c| c.to_string()).collect(),
                denied_cidrs.iter().map(|c| c.to_string()).collect(),
                packets_per_second,
                max_packets,
            ),
            other => panic!("init_request built {other:?}"),
        }
    }

    /// AC-6.17. The falsifier is the *shape* of the answer, not its
    /// presence: a request naming one host inside the manifest's /24 is the
    /// most plausible wrong implementation (`allowed_cidrs` derived from the
    /// targets the caller asked for), and it produces `10.30.0.10/32`, which
    /// this test rejects.
    #[test]
    fn the_init_allowlist_is_the_manifests_networks_and_not_the_requests_targets() {
        let (allowed, denied, pps, max) = init_fields(&manifest(LAB_MANIFEST));
        assert_eq!(allowed, vec!["10.30.0.0/24".to_string()]);
        assert_eq!(denied, vec!["10.30.0.1/32".to_string()]);
        assert_eq!(pps, 100_000);
        assert_eq!(max, 1_000_000);
    }

    /// The narrowing control. Every field the criterion is about differs
    /// from the fixture above, so an `init_request` that ignored its
    /// argument -- the exact shape of a hard-coded allowlist -- fails here
    /// while passing the test above.
    #[test]
    fn a_different_manifest_produces_a_different_init() {
        let (allowed, denied, pps, max) = init_fields(&manifest(OTHER_MANIFEST));
        assert_eq!(
            allowed,
            vec!["192.0.2.0/25".to_string(), "198.51.100.0/24".to_string()]
        );
        assert!(denied.is_empty());
        assert_eq!(pps, 3);
        assert_eq!(max, 7);
    }

    /// The ceiling, not the request's budget. A `packetd` ceiling derived
    /// from the same number the engine's ledger enforces is not a second
    /// bound, and AC-6.11 asks for a second bound.
    #[test]
    fn the_session_ceiling_comes_from_the_manifest_rather_than_from_any_budget() {
        let manifest = manifest(OTHER_MANIFEST);
        let (_, _, pps, max) = init_fields(&manifest);
        assert_eq!(max, manifest.ceiling().maximum_packets);
        assert_eq!(pps, manifest.ceiling().maximum_packets_per_second);
    }

    /// The line as `packetd`'s `deny_unknown_fields` deserializer will see
    /// it: tag, field names and CIDR spelling. This is the half of the
    /// protocol agreement that can be checked without a daemon; the other
    /// half is checked by running one.
    #[test]
    fn the_init_line_is_the_json_packetd_parses() {
        let line = init_request(&manifest(LAB_MANIFEST)).to_line().unwrap();
        assert_eq!(
            line,
            "{\"type\":\"init\",\"allowed_cidrs\":[\"10.30.0.0/24\"],\
             \"denied_cidrs\":[\"10.30.0.1/32\"],\"packets_per_second\":100000,\
             \"max_packets\":1000000}\n"
        );
    }

    #[test]
    fn a_probe_line_is_the_json_packetd_parses() {
        let line = Request::Probe {
            id: 4,
            target: "10.30.0.10".parse().unwrap(),
            port: 80,
        }
        .to_line()
        .unwrap();
        assert_eq!(
            line,
            "{\"type\":\"probe\",\"id\":4,\"target\":\"10.30.0.10\",\"port\":80}\n"
        );
    }

    /// Both `packetd` responses the engine acts on, parsed from the exact
    /// bytes the daemon writes. Taken from `Response::to_line`'s output
    /// shape; if either side renames a field this stops parsing.
    #[test]
    fn the_daemons_response_lines_parse_into_this_sides_types() {
        let ready: Response =
            serde_json::from_str(r#"{"type":"ready","dropped_capabilities":true}"#).unwrap();
        assert_eq!(
            ready,
            Response::Ready {
                dropped_capabilities: true
            }
        );
        let result: Response =
            serde_json::from_str(r#"{"type":"result","id":9,"state":"open"}"#).unwrap();
        assert_eq!(
            result,
            Response::Result {
                id: 9,
                state: PortState::Open
            }
        );
        let refused: Response =
            serde_json::from_str(r#"{"type":"refused","id":9,"reason":"out_of_session_scope"}"#)
                .unwrap();
        assert!(matches!(refused, Response::Refused { .. }));
    }

    /// The failure policy, as a table. `Unavailable` must be the only
    /// variant with no terminal reason: a `Gone` or a `Refused` that fell
    /// back would be the silent method change AC-6.16 exists to prevent.
    #[test]
    fn only_a_failure_to_start_is_recoverable() {
        assert_eq!(
            PacketdError::Unavailable("x".into()).terminal_reason(),
            None
        );
        assert_eq!(
            PacketdError::Gone("x".into()).terminal_reason(),
            Some("packetd_unavailable")
        );
        assert_eq!(
            PacketdError::Refused {
                id: 1,
                endpoint: "10.30.0.10:80".into(),
                reason: "out_of_session_scope".into(),
            }
            .terminal_reason(),
            Some("packetd_refused")
        );
    }

    #[test]
    fn a_config_without_a_binary_asks_for_connect_scanning() {
        assert_eq!(
            PacketdConfig::default().requested_mode(),
            ScanMode::TcpConnect
        );
        assert_eq!(
            PacketdConfig::syn_via("/nowhere/bathy-packetd").requested_mode(),
            ScanMode::TcpSyn
        );
    }

    /// Starting a daemon that does not exist is a fallback, not a crash,
    /// and the reason names the path so an operator can see what was tried.
    #[tokio::test]
    async fn a_missing_binary_is_unavailable_rather_than_fatal() {
        let e = PacketdClient::start(
            Path::new("/nonexistent/bathy-packetd"),
            &manifest(LAB_MANIFEST),
        )
        .expect_err("there is no daemon at that path");
        assert!(e.terminal_reason().is_none(), "{e}");
        assert!(format!("{e}").contains("/nonexistent/bathy-packetd"), "{e}");
    }

    /// A process that answers something other than `ready` does not become a
    /// session. `true` is on PATH everywhere this runs and exits 0 without
    /// writing a byte, which is the end-of-stream case.
    #[tokio::test]
    async fn a_process_that_never_says_ready_is_unavailable() {
        let e = PacketdClient::start(Path::new("/usr/bin/true"), &manifest(LAB_MANIFEST))
            .expect_err("`true` does not speak this protocol");
        assert!(e.terminal_reason().is_none(), "{e}");
        assert!(
            format!("{e}").contains("before answering init"),
            "the reason must name what was missing: {e}"
        );
    }
}
