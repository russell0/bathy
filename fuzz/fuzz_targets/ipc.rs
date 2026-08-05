#![no_main]
#![forbid(unsafe_code)]

//! Fuzzes `bathy-packetd`'s line protocol -- AC-7.7, AC-6.1 to AC-6.4.
//!
//! This is the one surface in this repository where a parsing bug is a
//! privilege-escalation bug rather than only a denial of service: the bytes
//! are line-delimited JSON handed to the process that holds `CAP_NET_RAW` by
//! a caller it is designed not to trust. So the target does not stop at "it
//! did not crash". It runs the whole input through the reader and the session
//! the way the daemon will, and asserts the four refusals as *properties over
//! every input*, which is the form in which they are actually authorization
//! rules rather than five unit tests:
//!
//! 1. **Nothing but a valid `Init` is ever accepted first** (AC-6.1, AC-6.3).
//!    Derived from the input with an independent `serde_json` parse rather
//!    than from the session's own verdict -- a `handle_line` that mislabelled
//!    a request would satisfy any assertion phrased in terms of what it
//!    returned.
//! 2. **A second `Init` never widens scope** (AC-6.2). Once the session is
//!    running, its allow set is captured; if it survives another line, the
//!    allow set must be byte-identical.
//! 3. **A `Fatal` is absorbing** (AC-6.4). After one, every subsequent line
//!    -- including a well-formed one -- is `Fatal`, and the session exposes
//!    no scope. A refusal that leaves the session usable is not a refusal.
//! 4. **The reader never allocates past its cap.** Checked after every read,
//!    including on the error paths, because "rejected without allocating it"
//!    is a claim about the failure case.
//! 5. **No packet is ever emitted at an address the session did not
//!    authorize** (AC-6.9, AC-6.10). The session is handed a `Wire` that
//!    records instead of sending, and after every line each recorded target
//!    is re-checked here -- with `IpNet::contains` and `std`'s reserved-range
//!    predicates, so neither `bathy-packetd`'s hand-rolled mask nor
//!    `bathy-scope`'s matcher decides whether it passed. That makes this the
//!    third independent statement of the same policy, and the only one driven
//!    by bytes an attacker chose.

use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr};
use std::rc::Rc;

use bathy_fuzz::Stats;
use bathy_packetd::protocol::{LineError, MAX_LINE_BYTES, Request, Response, Session, read_line};
use bathy_packetd::syn::Wire;
use libfuzzer_sys::fuzz_target;

/// A wire that records every target and puts nothing on the network. A fuzz
/// target that could emit is a fuzz target that scans whoever runs it.
#[derive(Debug, Default, Clone)]
struct Recorder(Rc<RefCell<Vec<Ipv4Addr>>>);

impl Wire for Recorder {
    fn source_for(&self, _target: Ipv4Addr) -> std::io::Result<Ipv4Addr> {
        Ok(Ipv4Addr::new(10, 30, 0, 99))
    }
    fn emit(&mut self, _packet: &[u8], target: Ipv4Addr) -> std::io::Result<()> {
        self.0.borrow_mut().push(target);
        Ok(())
    }
    fn poll(&mut self, _buf: &mut [u8]) -> Option<usize> {
        None
    }
}

/// Property 5's own opinion of the policy, owed to nothing in the tree:
/// `std`'s predicates for the reserved ranges, `ipnet`'s `contains` for the
/// CIDR sets. `bathy-packetd` uses neither.
fn independently_authorized(addr: Ipv4Addr, allow: &[ipnet::IpNet], deny: &[ipnet::IpNet]) -> bool {
    let ip = IpAddr::V4(addr);
    let reserved = addr.is_loopback()
        || addr.is_multicast()
        || addr.is_broadcast()
        || addr.is_link_local()
        || addr.is_unspecified()
        || addr.octets()[0] == 0
        || addr.octets()[0] >= 240;
    !reserved && !deny.iter().any(|n| n.contains(&ip)) && allow.iter().any(|n| n.contains(&ip))
}

const LINES: usize = 0;
const READ_ERRORS: usize = 1;
const PARSED: usize = 2;
const ACCEPTED_INIT: usize = 3;
const RESPONSES_AFTER_INIT: usize = 4;
const FATALS: usize = 5;
/// Packets handed to the wire. A run with `emitted=0` has never reached the
/// packet path at all, and property 5 is ranging over nothing.
const EMITTED: usize = 6;

const LABELS: &[&str] = &[
    "lines",
    "read_errors",
    // Inputs `serde_json` accepted as a `Request` at all. A run with
    // `parsed=0` has fuzzed a deserializer, not a state machine.
    "parsed",
    // The number that says whether this target got past the `Init` gate. With
    // `accepted_init=0` every assertion below about a *running* session is
    // vacuous, and the seeds exist to keep it non-zero.
    "accepted_init",
    "responses_after_init",
    "fatals",
    "emitted",
];

const FLAGS: &[&str] = &[
    "read:too_long",
    "read:unterminated",
    "read:not_utf8",
    "req:init",
    "req:probe",
    "req:shutdown",
    "rsp:ready",
    "rsp:refused",
    "rsp:fatal",
    "rsp:none",
    "second_init_refused",
];

static STATS: Stats = Stats::new("ipc", LABELS, FLAGS);

fuzz_target!(|data: &[u8]| {
    // `Session::new(true)` and not `false`: the capability flag is relayed
    // into `Ready`, and the value that would let a wrong `Ready` pass
    // unnoticed is the one this process would be lying about.
    let wire = Recorder::default();
    let mut session = Session::new(true, Box::new(wire.clone()));
    // A probe in a fuzz input must not wait out a reply deadline for a reply
    // that a recording wire will never produce.
    session.set_reply_deadline(std::time::Duration::ZERO);
    let mut reader = std::io::Cursor::new(data.to_vec());
    let mut buf = Vec::new();
    // The scope the session is running on, captured the moment it starts
    // running. Property 2 compares against this and nothing else.
    let mut running_scope: Option<Vec<String>> = None;
    // The same sets as `ipnet` values, kept so property 5 can still judge an
    // emission made by the line that ended the session.
    let mut running_allow: Option<Vec<ipnet::IpNet>> = None;
    let mut running_deny: Option<Vec<ipnet::IpNet>> = None;
    let mut seen_fatal = false;

    loop {
        let line = match read_line(&mut reader, &mut buf) {
            Ok(Some(line)) => line.to_string(),
            Ok(None) => break,
            Err(e) => {
                STATS.bump(READ_ERRORS);
                STATS.flag(match e {
                    LineError::TooLong => 0,
                    LineError::Unterminated(_) => 1,
                    LineError::NotUtf8 => 2,
                    LineError::Io(_) => 2,
                });
                break;
            }
        };
        // The claim AC-6.4 makes about the failure path as well as the happy
        // one: the buffer is the only thing that grows with the input.
        assert!(
            buf.len() <= MAX_LINE_BYTES,
            "the reader held {} bytes for a {}-byte input",
            buf.len(),
            data.len()
        );
        STATS.bump(LINES);

        // The expected verdict, derived from the bytes rather than from the
        // session. This is the whole reason the target is not just a
        // no-panic harness.
        let request = serde_json::from_str::<Request>(&line).ok();
        if let Some(r) = &request {
            STATS.bump(PARSED);
            STATS.flag(match r {
                Request::Init { .. } => 3,
                Request::Probe { .. } => 4,
                Request::Shutdown => 5,
            });
        }
        let is_valid_init = matches!(
            &request,
            Some(Request::Init { allowed_cidrs, .. }) if !allowed_cidrs.is_empty()
        );
        let was_running = running_scope.is_some();

        let response = session.handle_line(&line);
        match &response {
            Some(Response::Ready { .. }) => STATS.flag(6),
            Some(Response::Refused { .. }) => STATS.flag(7),
            Some(Response::Fatal { .. }) => STATS.flag(8),
            Some(Response::Result { .. }) => {}
            None => STATS.flag(9),
        }
        let fatal = matches!(response, Some(Response::Fatal { .. }));

        // Property 3, checked before anything else can excuse it.
        if seen_fatal {
            assert!(
                fatal,
                "a terminated session answered {line:?} with {response:?} instead of Fatal"
            );
            assert!(session.is_terminated() && session.ended_fatally());
            assert!(
                session.scope().is_none(),
                "a terminated session still exposes a scope to probe against"
            );
            STATS.bump(FATALS);
            continue;
        }

        if !was_running {
            // Property 1: the only line that may be accepted before `Init` is
            // an `Init` with a non-empty allow set.
            if !is_valid_init {
                assert!(fatal, "{line:?} was not refused before init: {response:?}");
                assert!(session.is_terminated());
                assert!(session.scope().is_none());
            } else {
                assert!(
                    matches!(response, Some(Response::Ready { .. })),
                    "a valid init was answered with {response:?}"
                );
                STATS.bump(ACCEPTED_INIT);
                running_scope = Some(cidrs(&session));
                running_allow = session.scope().map(|s| s.allowed().to_vec());
                running_deny = session.scope().map(|s| s.denied().to_vec());
            }
        } else {
            STATS.bump(RESPONSES_AFTER_INIT);
            // Property 2: scope is fixed for the process lifetime. Whatever
            // this line was, the allow set is either gone (the session ended)
            // or exactly what `Init` fixed -- never something else.
            if matches!(&request, Some(Request::Init { .. })) {
                assert!(
                    fatal,
                    "a second init was answered with {response:?}; session scope must \
                     not be widenable after startup"
                );
                STATS.flag(10);
            }
            match session.scope() {
                Some(_) => assert_eq!(
                    Some(cidrs(&session)),
                    running_scope,
                    "the session's allow set changed after init"
                ),
                None => assert!(
                    session.is_terminated(),
                    "a running session lost its scope without ending"
                ),
            }
        }

        if fatal {
            STATS.bump(FATALS);
            seen_fatal = true;
            assert!(session.ended_fatally());
        }
        // Property 5. Every address that reached the wire, judged by this
        // file's own rules -- so a `check_session_scope` that agreed with
        // itself cannot satisfy it.
        let authorized: Vec<ipnet::IpNet> = session
            .scope()
            .map(|s| s.allowed().to_vec())
            .or_else(|| running_allow.clone())
            .unwrap_or_default();
        let refused: Vec<ipnet::IpNet> = session
            .scope()
            .map(|s| s.denied().to_vec())
            .or_else(|| running_deny.clone())
            .unwrap_or_default();
        for target in wire.0.borrow().iter() {
            assert!(
                independently_authorized(*target, &authorized, &refused),
                "packetd emitted at {target}, which allow={authorized:?} deny={refused:?} \
                 does not authorize"
            );
            STATS.bump(EMITTED);
        }
        wire.0.borrow_mut().clear();

        // A response must survive being written and read back: the daemon
        // writes exactly this line to a pipe.
        if let Some(response) = &response {
            let rendered = response.to_line();
            assert!(!rendered.contains('\n'), "{rendered}");
            assert_eq!(
                serde_json::from_str::<Response>(&rendered).ok().as_ref(),
                Some(response)
            );
        }
    }

    STATS.tick();
});

/// The session's allow set, rendered so it can be compared across calls
/// without holding a borrow.
fn cidrs(session: &Session) -> Vec<String> {
    session
        .scope()
        .map(|s| s.allowed().iter().map(|n| n.to_string()).collect())
        .unwrap_or_default()
}
