//! The line protocol between the unprivileged engine and the privileged
//! helper, and the state machine that refuses on it.
//!
//! # Four refusals, and what happens after each
//!
//! Every acceptance criterion this module answers is a refusal, and for each
//! one the question that matters is not "does it refuse" but *what the
//! session does next*. A refusal that leaves the session usable is not a
//! refusal. So there is exactly one answer here, for all four: the session
//! enters [`State::Terminated`] and **stays there**. Every subsequent line --
//! including a perfectly well-formed `Init` -- is answered with
//! [`Response::Fatal`] and changes nothing. [`Session::is_terminated`] is
//! what the daemon polls to know it must exit.
//!
//! - **AC-6.1** Any message before `Init` is fatal. Not ignored, not queued.
//! - **AC-6.2** A second `Init` is fatal. Session scope is fixed for the
//!   process lifetime; a widening request is a bug or an attack and neither
//!   deserves a partial response. This is the criterion an attacker attacks,
//!   so it is an authorization boundary rather than a state-machine nicety:
//!   the widened allowlist is never parsed into the session, and the session
//!   cannot be revived to use it.
//! - **AC-6.3** An `Init` whose allowlist is empty is fatal. An empty
//!   allowlist must never mean "allow everything", and the way to guarantee
//!   that is to have no code path in which an empty allow set becomes a live
//!   session at all.
//! - **AC-6.4** Malformed input and oversized lines are fatal, not
//!   recoverable. `packetd` has no resynchronization mode. A privileged
//!   process that tries to resynchronize after garbage is a privileged
//!   process guessing.
//!
//! # Where the validation is, and why there is so little of it
//!
//! The milestone caps this crate at 800 lines of non-test Rust, which is a
//! design constraint and not a budget: a privileged process is reviewable by
//! a human or it is not trustworthy. So the refusals are pushed into the
//! *types* wherever they can go. A target that is not an IP address, a port
//! above 65535, a CIDR that does not parse and a field the protocol does not
//! define are all rejected by `serde` before any code in this file runs, and
//! land on the same fatal path as `{not json`. The only hand-written
//! validation in the whole module is the one thing a type cannot express:
//! that the allow set is non-empty.
//!
//! # The cap is enforced by the reader, not by the handler
//!
//! [`Session::handle_line`] takes a `&str`, so by the time it sees an
//! oversized line somebody has already allocated it. The cap that actually
//! bounds memory is in [`read_line`], which refuses to grow its buffer past
//! [`MAX_LINE_BYTES`] and never copies the bytes that would have exceeded it.
//! `handle_line` re-checks the length as a second line of defence, because
//! nothing stops a future caller from building a line some other way.

use std::io::BufRead;
use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// The largest line `packetd` will accept, in bytes, excluding the newline.
///
/// 8 KiB is far more than any legitimate message needs -- the longest is an
/// `Init` carrying an allowlist, and a hundred CIDRs fit in under 2 KiB. It
/// is a bound on what a hostile caller can make this process allocate per
/// line, not a capacity anyone should plan against.
pub const MAX_LINE_BYTES: usize = 8 * 1024;

// ---------------------------------------------------------------------------
// The wire types.
// ---------------------------------------------------------------------------

/// A request from the engine.
///
/// `deny_unknown_fields` is deliberate and is part of the mutual suspicion:
/// an unrecognized field means the caller and this process disagree about
/// what the protocol is, and a privileged process must not proceed on the
/// half of a message it happens to understand. It is also what makes a
/// misspelled `denied_cidrs` fatal rather than silently empty.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// The first message, and the only legal first message. Fixes the
    /// session's scope and budget for the lifetime of the process.
    ///
    /// Every field is required. There is no `#[serde(default)]` anywhere in
    /// this type: a default is this process filling in a security-relevant
    /// value on behalf of a caller it does not trust.
    Init {
        /// Parsed by `ipnet`, so a malformed CIDR is a parse failure and
        /// therefore fatal (AC-6.4) rather than a CIDR quietly dropped from
        /// an allow set.
        allowed_cidrs: Vec<IpNet>,
        denied_cidrs: Vec<IpNet>,
        packets_per_second: u32,
        max_packets: u64,
    },
    /// One probe request. `target` is an `IpAddr` and `port` a `u16`, so
    /// `"10.0.0.256"` and `70000` never reach any logic in this crate.
    Probe { id: u64, target: IpAddr, port: u16 },
    /// End the session cleanly. Legal only after `Init`.
    Shutdown,
}

/// A response from `packetd`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    /// `Init` was accepted. `dropped_capabilities` is *reported*, never
    /// asserted -- see [`Session::new`].
    Ready { dropped_capabilities: bool },
    /// A probe completed.
    Result { id: u64, state: PortState },
    /// A probe was rejected by this process. The session continues: a
    /// refusal is about one probe, and only the four fatals above are about
    /// the session.
    Refused { id: u64, reason: RefusalReason },
    /// The session is over. The daemon writes this line and exits non-zero;
    /// the session itself will answer every further line with another
    /// `Fatal` and do nothing else.
    Fatal { detail: String },
}

/// The observed reachability of one endpoint.
///
/// Four variants with the same wire strings as `bathy_types::PortState`,
/// pinned by `the_wire_strings_match_bathy_types`. This crate does not depend
/// on `bathy-types` for them -- see the note in `Cargo.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Indeterminate,
}

/// Why one probe was refused. A closed set, because the engine branches on
/// it: a free-text reason is a string comparison somebody gets wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalReason {
    /// The target is outside the session allowlist, or inside its denylist,
    /// or reserved (AC-6.9, AC-6.10). Decided by Task 3's independent check.
    OutOfSessionScope,
    /// The session's own packet ceiling is spent (AC-6.11).
    SessionBudgetExhausted,
    /// This build has no packet path: `bathy-packetd` currently ships the
    /// protocol and nothing that emits. A probe that reaches a build which
    /// cannot probe is refused rather than answered, because the alternative
    /// is a `Result` this process did not observe. Removed by M6 Task 3,
    /// which replaces the arm that produces it.
    ProbingUnavailable,
}

impl Response {
    /// The response as one line of JSON, without the newline.
    ///
    /// Infallible by construction: every field of every variant serializes,
    /// and there is no map with non-string keys and no float. The fallback
    /// exists so that this function needs no `unwrap` -- a privileged process
    /// that panics while reporting an error reports nothing.
    pub fn to_line(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            r#"{"type":"fatal","detail":"response serialization failed"}"#.to_string()
        })
    }
}

// ---------------------------------------------------------------------------
// The reader.
// ---------------------------------------------------------------------------

/// Why a line could not be read. Every variant is fatal to the session.
#[derive(Debug, thiserror::Error)]
pub enum LineError {
    /// The caller sent more than [`MAX_LINE_BYTES`] without a newline. The
    /// bytes past the cap are never copied into the buffer.
    #[error("line exceeds the {MAX_LINE_BYTES}-byte cap")]
    TooLong,
    /// The stream ended part-way through a line. An incomplete frame is not
    /// a short frame: the caller died mid-write, and this process does not
    /// guess at what it meant to say.
    #[error("input ended mid-line after {0} byte(s) with no newline")]
    Unterminated(usize),
    /// The line was not UTF-8. JSON is, so this is malformed input reported
    /// one layer earlier.
    #[error("line is not valid UTF-8")]
    NotUtf8,
    #[error("reading from the engine: {0}")]
    Io(#[from] std::io::Error),
}

/// Reads one newline-terminated line into `buf`, refusing to grow it past
/// [`MAX_LINE_BYTES`].
///
/// `Ok(None)` is a clean end of stream -- the engine closed the pipe between
/// messages, which is the ordinary way a session ends. `Ok(Some(line))` is a
/// complete line with the newline stripped; it may be empty, and an empty
/// line is not valid JSON, so the session will treat it as fatal.
///
/// The oversize refusal happens **before** the bytes are copied: the check is
/// against `buf.len() + chunk.len()`, and on failure nothing is appended and
/// nothing is consumed. That is what makes AC-6.4's "without allocating it"
/// a property of this function rather than a hope about the caller --
/// `a_line_over_the_cap_is_refused_without_the_buffer_ever_holding_it`
/// asserts the buffer length over a megabyte of input.
pub fn read_line<'b, R: BufRead>(
    reader: &mut R,
    buf: &'b mut Vec<u8>,
) -> Result<Option<&'b str>, LineError> {
    buf.clear();
    loop {
        let available = match reader.fill_buf() {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(LineError::Io(e)),
        };
        if available.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            return Err(LineError::Unterminated(buf.len()));
        }
        let newline_at = available.iter().position(|byte| *byte == b'\n');
        // `get(..at)` rather than `[..at]`: `clippy::indexing_slicing` is
        // denied in this crate, and the position is trusted here only
        // because it came from `position` on the same slice.
        let chunk = match newline_at {
            Some(at) => available.get(..at).unwrap_or_default(),
            None => available,
        };
        let chunk_len = chunk.len();
        // `saturating_add` rather than `+`: `clippy::arithmetic_side_effects`
        // is denied, and saturating at `usize::MAX` fails the comparison in
        // the safe direction anyway.
        if buf.len().saturating_add(chunk_len) > MAX_LINE_BYTES {
            return Err(LineError::TooLong);
        }
        buf.extend_from_slice(chunk);
        let consumed = match newline_at {
            Some(_) => chunk_len.saturating_add(1),
            None => chunk_len,
        };
        reader.consume(consumed);
        if newline_at.is_some() {
            return std::str::from_utf8(buf.as_slice())
                .map(Some)
                .map_err(|_| LineError::NotUtf8);
        }
    }
}

// ---------------------------------------------------------------------------
// The session.
// ---------------------------------------------------------------------------

/// The scope and budget an `Init` fixed, for the lifetime of the process.
///
/// Constructed in exactly one place ([`Session::handle_line`]'s `Init` arm)
/// and never mutated, which is the mechanical form of "session scope cannot
/// be widened after startup". Read by Task 3's independent scope check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionScope {
    allowed: Vec<IpNet>,
    denied: Vec<IpNet>,
    packets_per_second: u32,
    max_packets: u64,
}

impl SessionScope {
    pub fn allowed(&self) -> &[IpNet] {
        &self.allowed
    }
    pub fn denied(&self) -> &[IpNet] {
        &self.denied
    }
    pub fn packets_per_second(&self) -> u32 {
        self.packets_per_second
    }
    pub fn max_packets(&self) -> u64 {
        self.max_packets
    }
}

/// Where the session is. Three states, and the third is absorbing.
#[derive(Debug, Clone, PartialEq, Eq)]
enum State {
    /// Nothing but `Init` is legal (AC-6.1).
    AwaitingInit,
    /// `Init` was accepted. A second one is fatal (AC-6.2).
    Running(SessionScope),
    /// The session is over. Nothing leaves this state. `fatal` distinguishes
    /// the four refusals from a clean `Shutdown`; it decides the daemon's
    /// exit status and nothing else, because both alike accept no more work.
    Terminated { fatal: bool },
}

/// Said to a caller that keeps talking to a session that has ended. One
/// constant because it is produced from two places and a reviewer should be
/// able to see that they say the same thing.
const AFTER_THE_END: &str = "session already terminated; packetd does not resynchronize";

/// The protocol state machine.
///
/// One `Session` is one process lifetime. It is not `Clone` and there is no
/// `reset`: reviving a terminated session is the failure this whole type
/// exists to make impossible.
#[derive(Debug)]
pub struct Session {
    state: State,
    dropped_capabilities: bool,
}

impl Session {
    /// A fresh session awaiting `Init`.
    ///
    /// `dropped_capabilities` is what `main` **observed** after calling
    /// `drop_all_capabilities()` (M6 Task 2), and this type relays it in
    /// [`Response::Ready`]. It is a parameter rather than a constant because
    /// the alternative is this module fabricating a security-relevant claim
    /// from a constructor that never checked anything -- which is the
    /// "claimed but never enforced" defect class this repository has paid for
    /// repeatedly. See plan edit #1 on M6 Task 1.
    pub fn new(dropped_capabilities: bool) -> Self {
        Self {
            state: State::AwaitingInit,
            dropped_capabilities,
        }
    }

    /// True once the session has ended, whether fatally or by `Shutdown`.
    /// The daemon stops reading on this; the session answers every further
    /// line with a `Fatal` regardless.
    pub fn is_terminated(&self) -> bool {
        matches!(self.state, State::Terminated { .. })
    }

    /// True once one of the four fatals has fired. This is the only
    /// difference between a fatal end and a clean one, and it decides the
    /// daemon's exit status (M6 Task 2).
    pub fn ended_fatally(&self) -> bool {
        matches!(self.state, State::Terminated { fatal: true })
    }

    /// The scope this session was initialized with, or `None` before `Init`
    /// and after the session has ended.
    pub fn scope(&self) -> Option<&SessionScope> {
        match &self.state {
            State::Running(scope) => Some(scope),
            State::AwaitingInit | State::Terminated { .. } => None,
        }
    }

    /// Handle one line.
    ///
    /// `None` means "no response line" and happens for exactly one message:
    /// a `Shutdown` that the session accepts. The protocol has no goodbye
    /// response, and answering `Shutdown` with `Ready` would be this process
    /// telling the engine something untrue in order to satisfy a return type
    /// (plan edit #2 on M6 Task 1).
    ///
    /// Never panics, never blocks, and never returns anything but `Fatal`
    /// once the session has ended.
    pub fn handle_line(&mut self, line: &str) -> Option<Response> {
        if self.is_terminated() {
            return Some(self.terminate(AFTER_THE_END.to_string()));
        }
        // The reader's cap, restated where a `&str` arrives from anywhere
        // else. Bytes, not `chars`: the wire unit is bytes and a multi-byte
        // line must not be able to exceed the allocation bound by counting
        // small.
        if line.len() > MAX_LINE_BYTES {
            return Some(self.terminate(format!(
                "line of {} bytes exceeds the {MAX_LINE_BYTES}-byte cap",
                line.len()
            )));
        }
        let request = match serde_json::from_str::<Request>(line) {
            Ok(request) => request,
            Err(e) => {
                // The parse error, not the line: the line is attacker
                // controlled and this string is written to a log.
                return Some(self.terminate(format!("malformed request: {e}")));
            }
        };
        self.dispatch(request)
    }

    fn dispatch(&mut self, request: Request) -> Option<Response> {
        match (&self.state, request) {
            (
                State::AwaitingInit,
                Request::Init {
                    allowed_cidrs,
                    denied_cidrs,
                    packets_per_second,
                    max_packets,
                },
            ) => {
                if allowed_cidrs.is_empty() {
                    // AC-6.3. Stated as a refusal to *construct* the scope,
                    // so there is no path on which an empty allow set becomes
                    // a live session and no later check that could be the one
                    // that gets removed.
                    return Some(
                        self.terminate(
                            "init carries an empty allowlist; an empty allow set is not \
                         permission to scan anything"
                                .to_string(),
                        ),
                    );
                }
                self.state = State::Running(SessionScope {
                    allowed: allowed_cidrs,
                    denied: denied_cidrs,
                    packets_per_second,
                    max_packets,
                });
                Some(Response::Ready {
                    dropped_capabilities: self.dropped_capabilities,
                })
            }
            // AC-6.1: anything before `Init`, including `Shutdown`. There is
            // exactly one legal first message, which is a rule a reviewer can
            // check by reading; "everything except these two" is not.
            (State::AwaitingInit, other) => Some(self.terminate(format!(
                "{} arrived before init; packetd refuses all work before it has been \
                 told its scope",
                other.name()
            ))),
            // AC-6.2. The widened allowlist is dropped with this arm's `..`
            // and never reaches `SessionScope`.
            (State::Running(_), Request::Init { .. }) => Some(
                self.terminate(
                    "a second init would widen session scope after startup; scope is fixed \
                 for the process lifetime"
                        .to_string(),
                ),
            ),
            (State::Running(_), Request::Probe { id, .. }) => Some(Response::Refused {
                id,
                reason: RefusalReason::ProbingUnavailable,
            }),
            (State::Running(_), Request::Shutdown) => {
                // A clean end is still an end: the session stops accepting
                // work. The only thing that distinguishes it from a fatal is
                // the exit status the daemon will use.
                self.state = State::Terminated { fatal: false };
                None
            }
            // Unreachable through `handle_line`, which returns above. Kept
            // because "fatal implies terminated" should be a property of this
            // function too, not only of its caller.
            (State::Terminated { .. }, _) => Some(self.terminate(AFTER_THE_END.to_string())),
        }
    }

    /// Enter the absorbing state and report why. The single place `Fatal` is
    /// produced from, so "fatal implies terminated" holds by construction
    /// rather than by four correct call sites.
    fn terminate(&mut self, detail: String) -> Response {
        self.state = State::Terminated { fatal: true };
        Response::Fatal { detail }
    }
}

impl Request {
    /// The wire tag, for messages about a request this process is refusing.
    fn name(&self) -> &'static str {
        match self {
            Request::Init { .. } => "init",
            Request::Probe { .. } => "probe",
            Request::Shutdown => "shutdown",
        }
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use proptest::prelude::*;

    use super::*;

    /// A well-formed `init` line over the given allow set. Every fixture
    /// below builds its input from this, so a test that expects a refusal
    /// differs from one that expects acceptance by exactly the thing under
    /// test and nothing else.
    fn init_line(allowed: &[&str]) -> String {
        format!(
            r#"{{"type":"init","allowed_cidrs":[{}],"denied_cidrs":[],"packets_per_second":100,"max_packets":1000}}"#,
            allowed
                .iter()
                .map(|c| format!("\"{c}\""))
                .collect::<Vec<_>>()
                .join(",")
        )
    }

    /// A session that has accepted one `init` over a **narrow** allow set.
    ///
    /// `10.30.0.0/24` and not `0.0.0.0/0`: the second-init test asserts that
    /// a widening request is refused, and a fixture whose starting scope
    /// already permitted everything could not tell a refusal from a session
    /// that accepted the widening and looked identical afterwards.
    fn initialized_session() -> Session {
        let mut session = Session::new(true);
        let response = session.handle_line(&init_line(&["10.30.0.0/24"]));
        assert!(
            matches!(response, Some(Response::Ready { .. })),
            "fixture is supposed to start from an accepted init, got {response:?}"
        );
        session
    }

    const PROBE: &str = r#"{"type":"probe","id":1,"target":"10.30.0.7","port":80}"#;

    /// Every one of the four fatals is asserted with this, not with
    /// `matches!(r, Response::Fatal { .. })` alone. A refusal that leaves the
    /// session usable is not a refusal, and the three properties below are
    /// what "fatal" has to mean:
    ///
    /// 1. the response is `Fatal`;
    /// 2. the session is terminated, and terminated *fatally*;
    /// 3. the next line -- a **valid, in-scope** one, so the only reason it
    ///    can fail is the termination -- is refused too, and the session
    ///    does not come back.
    fn assert_fatal_and_unrecoverable(response: Option<Response>, session: &mut Session) {
        assert!(
            matches!(response, Some(Response::Fatal { .. })),
            "expected Fatal, got {response:?}"
        );
        assert!(
            session.is_terminated(),
            "a fatal must terminate the session"
        );
        assert!(
            session.ended_fatally(),
            "this end was fatal, not a shutdown"
        );
        assert!(
            session.scope().is_none(),
            "a terminated session must expose no scope to probe against"
        );

        let after = session.handle_line(&init_line(&["10.30.0.0/24"]));
        assert!(
            matches!(after, Some(Response::Fatal { .. })),
            "a valid init after a fatal must not revive the session, got {after:?}"
        );
        assert!(session.is_terminated() && session.ended_fatally());
        assert!(session.scope().is_none());

        let after_probe = session.handle_line(PROBE);
        assert!(
            matches!(after_probe, Some(Response::Fatal { .. })),
            "a terminated session must never answer a probe, got {after_probe:?}"
        );
    }

    // -- AC-6.1 -------------------------------------------------------------

    #[test]
    fn a_probe_before_init_is_fatal_and_the_session_never_recovers() {
        let mut session = Session::new(true);
        assert_fatal_and_unrecoverable(session.handle_line(PROBE), &mut session);
    }

    #[test]
    fn even_shutdown_before_init_is_fatal_because_exactly_one_first_message_is_legal() {
        let mut session = Session::new(true);
        let response = session.handle_line(r#"{"type":"shutdown"}"#);
        assert_fatal_and_unrecoverable(response, &mut session);
    }

    /// The narrowing control for AC-6.1: the same `init` this test refuses
    /// *after* a probe is accepted when it comes first. Without this, a
    /// `handle_line` that refused everything would pass the criterion.
    #[test]
    fn an_init_that_arrives_first_is_accepted() {
        let mut session = Session::new(true);
        let response = session.handle_line(&init_line(&["10.30.0.0/24"]));
        assert!(matches!(response, Some(Response::Ready { .. })));
        assert!(!session.is_terminated());
        assert_eq!(
            session.scope().map(|s| s.allowed().len()),
            Some(1),
            "the accepted init must be what the session runs on"
        );
    }

    // -- AC-6.2 -------------------------------------------------------------

    #[test]
    fn a_second_init_is_fatal_so_session_scope_cannot_be_widened() {
        let mut session = initialized_session();
        let narrow: Vec<IpNet> = session
            .scope()
            .map(|s| s.allowed().to_vec())
            .unwrap_or_default();
        assert_eq!(narrow, vec!["10.30.0.0/24".parse::<IpNet>().unwrap()]);

        let wider = init_line(&["0.0.0.0/0"]);
        let response = session.handle_line(&wider);
        assert_fatal_and_unrecoverable(response, &mut session);
    }

    /// The half of AC-6.2 that a `Fatal` alone does not cover: the widened
    /// allow set must never become *reachable*. A `dispatch` that stored the
    /// new scope and then reported `Fatal` would pass the test above.
    #[test]
    fn the_widened_allowlist_from_a_second_init_is_never_stored() {
        let mut session = initialized_session();
        let _ = session.handle_line(&init_line(&["0.0.0.0/0"]));
        assert!(
            session.scope().is_none(),
            "a session that refused a widening must expose no scope at all, \
             least of all the widened one"
        );
    }

    // -- AC-6.3 -------------------------------------------------------------

    #[test]
    fn an_init_with_an_empty_allowlist_is_fatal() {
        let mut session = Session::new(true);
        let response = session.handle_line(&init_line(&[]));
        assert_fatal_and_unrecoverable(response, &mut session);
    }

    /// The narrowing control for AC-6.3. The two inputs differ in one CIDR;
    /// if the empty case were accepted, `allowed()` would be empty here and
    /// "empty allowlist" would silently mean "allow everything" downstream.
    #[test]
    fn an_init_with_one_cidr_is_accepted_and_carries_it() {
        let mut session = Session::new(true);
        assert!(matches!(
            session.handle_line(&init_line(&["10.30.0.0/24"])),
            Some(Response::Ready { .. })
        ));
        assert_eq!(
            session.scope().map(|s| s.allowed()),
            Some(["10.30.0.0/24".parse::<IpNet>().unwrap()].as_slice())
        );
    }

    #[test]
    fn a_cidr_that_does_not_parse_is_fatal_rather_than_dropped_from_the_allow_set() {
        let mut session = Session::new(true);
        let response = session.handle_line(&init_line(&["10.30.0.0/24", "not-a-cidr"]));
        assert_fatal_and_unrecoverable(response, &mut session);
    }

    // -- AC-6.4 -------------------------------------------------------------

    #[test]
    fn malformed_json_is_fatal_rather_than_ignored() {
        let mut session = initialized_session();
        let response = session.handle_line("{not json");
        assert_fatal_and_unrecoverable(response, &mut session);
    }

    #[test]
    fn an_empty_line_is_fatal_rather_than_skipped() {
        let mut session = initialized_session();
        let response = session.handle_line("");
        assert_fatal_and_unrecoverable(response, &mut session);
    }

    #[test]
    fn an_unknown_field_is_fatal_because_the_caller_and_this_process_disagree() {
        let mut session = Session::new(true);
        let response = session.handle_line(
            r#"{"type":"init","allowed_cidrs":["10.30.0.0/24"],"denied_cidrs":[],"packets_per_second":100,"max_packets":1000,"allow_everything":true}"#,
        );
        assert_fatal_and_unrecoverable(response, &mut session);
    }

    #[test]
    fn a_target_that_is_not_an_address_and_a_port_out_of_range_are_both_fatal() {
        for line in [
            r#"{"type":"probe","id":1,"target":"10.30.0.256","port":80}"#,
            r#"{"type":"probe","id":1,"target":"example.com","port":80}"#,
            r#"{"type":"probe","id":1,"target":"10.30.0.7","port":70000}"#,
        ] {
            let mut session = initialized_session();
            let response = session.handle_line(line);
            assert!(
                matches!(response, Some(Response::Fatal { .. })),
                "{line} must be fatal, got {response:?}"
            );
            assert!(session.ended_fatally(), "{line}");
        }
    }

    /// A `&str` whose length is exactly the cap is a length the handler must
    /// **accept**, and one byte more must be refused *for its length*. Padded
    /// with the whitespace JSON already allows between tokens, so the two
    /// inputs differ in one byte and in nothing else -- a cap of zero, or one
    /// that refused every line, fails this pair.
    #[test]
    fn the_line_cap_refuses_one_byte_over_and_accepts_exactly_the_cap() {
        let base = init_line(&["10.30.0.0/24"]);
        let pad = MAX_LINE_BYTES.checked_sub(base.len()).unwrap();

        let at_cap = format!("{}{}", " ".repeat(pad), base);
        assert_eq!(at_cap.len(), MAX_LINE_BYTES);
        let mut session = Session::new(true);
        assert!(
            matches!(session.handle_line(&at_cap), Some(Response::Ready { .. })),
            "a line of exactly {MAX_LINE_BYTES} bytes is within the cap"
        );

        let over = format!("{}{}", " ".repeat(pad + 1), base);
        assert_eq!(over.len(), MAX_LINE_BYTES + 1);
        let mut session = Session::new(true);
        let response = session.handle_line(&over);
        match &response {
            Some(Response::Fatal { detail }) => assert!(
                detail.contains("cap"),
                "the refusal must be about the length, not about the JSON: {detail}"
            ),
            other => panic!("expected Fatal, got {other:?}"),
        }
        assert_fatal_and_unrecoverable(response, &mut session);
    }

    // -- read_line: the cap that actually bounds memory ----------------------

    fn read_one<'b>(input: &[u8], buf: &'b mut Vec<u8>) -> Result<Option<&'b str>, LineError> {
        read_line(&mut Cursor::new(input.to_vec()), buf)
    }

    #[test]
    fn a_line_over_the_cap_is_refused_without_the_buffer_ever_holding_it() {
        let huge = format!(
            r#"{{"type":"probe","id":1,"target":"{}","port":80}}{}"#,
            "A".repeat(1 << 20),
            "\n"
        );
        let mut buf = Vec::new();
        let outcome = read_one(huge.as_bytes(), &mut buf);
        assert!(matches!(outcome, Err(LineError::TooLong)), "{outcome:?}");
        assert!(
            buf.len() <= MAX_LINE_BYTES,
            "the reader copied {} bytes of a {}-byte line; the cap is supposed to \
             bound what a hostile caller can make this process allocate",
            buf.len(),
            huge.len()
        );
    }

    #[test]
    fn the_reader_accepts_a_line_of_exactly_the_cap_and_refuses_one_byte_more() {
        let mut at_cap = vec![b'x'; MAX_LINE_BYTES];
        at_cap.push(b'\n');
        let mut buf = Vec::new();
        assert_eq!(
            read_one(&at_cap, &mut buf).unwrap().map(str::len),
            Some(MAX_LINE_BYTES)
        );

        let mut over = vec![b'x'; MAX_LINE_BYTES + 1];
        over.push(b'\n');
        let mut buf = Vec::new();
        assert!(matches!(read_one(&over, &mut buf), Err(LineError::TooLong)));
    }

    #[test]
    fn a_clean_end_of_stream_is_not_an_error_but_a_truncated_line_is() {
        let mut buf = Vec::new();
        assert!(read_one(b"", &mut buf).unwrap().is_none());

        let mut buf = Vec::new();
        assert!(read_one(b"{\"type\":\"shut", &mut buf).is_err());
    }

    #[test]
    fn lines_are_returned_one_at_a_time_and_a_blank_line_is_a_line() {
        let mut reader = Cursor::new(b"one\n\ntwo\n".to_vec());
        let mut buf = Vec::new();
        assert_eq!(read_line(&mut reader, &mut buf).unwrap(), Some("one"));
        let mut buf = Vec::new();
        assert_eq!(read_line(&mut reader, &mut buf).unwrap(), Some(""));
        let mut buf = Vec::new();
        assert_eq!(read_line(&mut reader, &mut buf).unwrap(), Some("two"));
        let mut buf = Vec::new();
        assert_eq!(read_line(&mut reader, &mut buf).unwrap(), None);
    }

    #[test]
    fn a_line_that_is_not_utf8_is_refused_rather_than_lossily_decoded() {
        let mut buf = Vec::new();
        let outcome = read_one(b"\xff\xfe\n", &mut buf);
        assert!(matches!(outcome, Err(LineError::NotUtf8)), "{outcome:?}");
    }

    // -- the rest of the surface --------------------------------------------

    #[test]
    fn shutdown_after_init_ends_the_session_without_a_response_and_without_a_fatal() {
        let mut session = initialized_session();
        assert_eq!(session.handle_line(r#"{"type":"shutdown"}"#), None);
        assert!(session.is_terminated());
        assert!(
            !session.ended_fatally(),
            "a clean shutdown is not one of the four fatals"
        );
        // But it is still the end: talking to it afterwards is a protocol
        // violation, and that IS fatal.
        assert!(matches!(
            session.handle_line(PROBE),
            Some(Response::Fatal { .. })
        ));
        assert!(session.ended_fatally());
    }

    #[test]
    fn this_build_refuses_every_probe_because_it_has_no_packet_path() {
        let mut session = initialized_session();
        assert_eq!(
            session.handle_line(PROBE),
            Some(Response::Refused {
                id: 1,
                reason: RefusalReason::ProbingUnavailable,
            })
        );
        assert!(
            !session.is_terminated(),
            "a refusal is about one probe, not about the session"
        );
    }

    #[test]
    fn ready_reports_the_capability_state_it_was_given_rather_than_a_constant() {
        for dropped in [true, false] {
            let mut session = Session::new(dropped);
            assert_eq!(
                session.handle_line(&init_line(&["10.30.0.0/24"])),
                Some(Response::Ready {
                    dropped_capabilities: dropped
                })
            );
        }
    }

    #[test]
    fn the_wire_strings_match_bathy_types() {
        // `bathy-types` is a dev-dependency only -- see `Cargo.toml` for why
        // the privileged process does not link it. This is what makes the
        // local `PortState` a copy of a contract rather than a second one.
        for (local, shared) in [
            (PortState::Open, bathy_types::PortState::Open),
            (PortState::Closed, bathy_types::PortState::Closed),
            (PortState::Filtered, bathy_types::PortState::Filtered),
            (
                PortState::Indeterminate,
                bathy_types::PortState::Indeterminate,
            ),
        ] {
            assert_eq!(
                serde_json::to_string(&local).unwrap(),
                serde_json::to_string(&shared).unwrap()
            );
        }
    }

    #[test]
    fn every_response_renders_to_one_line_that_parses_back() {
        for response in [
            Response::Ready {
                dropped_capabilities: true,
            },
            Response::Result {
                id: 7,
                state: PortState::Open,
            },
            Response::Refused {
                id: 7,
                reason: RefusalReason::OutOfSessionScope,
            },
            Response::Fatal {
                detail: "why".to_string(),
            },
        ] {
            let line = response.to_line();
            assert!(!line.contains('\n'), "{line}");
            assert_eq!(serde_json::from_str::<Response>(&line).unwrap(), response);
        }
    }

    // -- properties over arbitrary bytes -------------------------------------

    proptest! {
        /// The parser must never panic, and must never let an arbitrary line
        /// past the `Init` gate. This is AC-6.1 stated over every input
        /// rather than over one.
        #[test]
        fn no_first_line_but_a_valid_init_is_ever_accepted(line in ".{0,400}") {
            let mut session = Session::new(true);
            let response = session.handle_line(&line);
            let is_init = serde_json::from_str::<Request>(&line)
                .map(|r| matches!(r, Request::Init { .. }))
                .unwrap_or(false);
            if !is_init {
                let fatal = matches!(response, Some(Response::Fatal { .. }));
                prop_assert!(fatal, "{line:?} was not refused before init");
                prop_assert!(session.is_terminated());
            }
        }

        /// Termination is absorbing over arbitrary follow-on traffic.
        #[test]
        fn nothing_revives_a_terminated_session(lines in prop::collection::vec(".{0,200}", 1..8)) {
            let mut session = Session::new(true);
            let first = matches!(session.handle_line("{not json"), Some(Response::Fatal { .. }));
            prop_assert!(first);
            for line in lines {
                let fatal = matches!(session.handle_line(&line), Some(Response::Fatal { .. }));
                prop_assert!(fatal, "{line:?} got a non-fatal answer from a dead session");
                prop_assert!(session.is_terminated());
                prop_assert!(session.scope().is_none());
            }
        }

        /// The reader terminates and stays inside its bound on any bytes at
        /// all -- including bytes with no newline in them, which is the
        /// shape that makes an unbounded reader unbounded.
        #[test]
        fn the_reader_never_exceeds_its_bound_on_arbitrary_bytes(
            data in prop::collection::vec(any::<u8>(), 0..4096)
        ) {
            let mut reader = Cursor::new(data);
            for _ in 0..8 {
                let mut buf = Vec::new();
                let more = {
                    let outcome = read_line(&mut reader, &mut buf);
                    matches!(outcome, Ok(Some(_)))
                };
                prop_assert!(buf.len() <= MAX_LINE_BYTES);
                if !more {
                    break;
                }
            }
        }
    }
}
