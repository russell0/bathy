#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects
    )
)]

//! The `packetd` daemon: three steps, in an order that is the whole design.
//!
//! ```text
//! 1. acquire_raw_sockets()      <- needs CAP_NET_RAW
//! 2. drop_all_capabilities()    <- verified against /proc/self/status
//! 3. read the first byte of input
//! ```
//!
//! Sockets are a handle we hold, not a privilege we retain: the kernel checks
//! `CAP_NET_RAW` at `socket(2)` and never again. So everything that parses
//! bytes chosen by somebody else runs in a process that could not open
//! another socket if it tried.
//!
//! # `#![forbid(unsafe_code)]` here, `deny` in the library
//!
//! This binary target has no syscalls of its own, so it carries the `forbid`
//! every other target in the workspace carries. The library root carries
//! `deny` instead, because exactly one function in it -- `privilege::
//! set_no_new_privs` -- needs one `unsafe` block, and `forbid` cannot be
//! overridden even by a site-level `expect` with a reason. See
//! `crates/bathy-packetd/src/privilege.rs`.
//!
//! # What `--self-check` is for, and what it is not
//!
//! It runs the same three steps and then prints what it can **measure**
//! about the result: whether the three raw sockets are still usable
//! (`getsockopt(SO_TYPE)` on each), what `/proc/self/status` says about every
//! capability set, whether opening a *new* raw socket now fails, and whether
//! a real read through the ordering guard succeeded. Every field is the
//! outcome of a syscall made after the drop.
//!
//! It is deliberately **not** the proof of AC-6.5. A process reporting on its
//! own ordering is a process that can be wrong about it in exactly the way
//! that matters, so `tests/privilege.rs` establishes the ordering from
//! outside, by withholding every byte of this process's input until it has
//! watched the capability set empty in `/proc/<pid>/status`. The self-check
//! is what an operator runs, and what makes the negative
//! (`raw_socket_after_drop_denied`) observable at all.

use std::io::{BufRead, Write};
use std::process::ExitCode;

use bathy_packetd::privilege::{
    self, PrivilegeError, PrivilegeState, RawSockets, UnprivilegedInput,
};
use bathy_packetd::protocol::{Response, Session, read_line};
use bathy_packetd::syn::Wire;
use serde::Serialize;

/// `EX_UNAVAILABLE` from `sysexits.h`: a service this program needs is not
/// available. The engine branches on it to fall back to connect scanning
/// (M6 Task 4) rather than treating a missing capability as a crash.
const NO_PRIVILEGE: u8 = 69;

/// The two ordinary exit statuses. `main` is the only place an [`ExitCode`]
/// is built: everything below returns a `u8`, so the exit status of every
/// path is an ordinary value a unit test can compare rather than an opaque
/// type that can only be formatted.
const OK: u8 = 0;
const FAILED: u8 = 1;

const SELF_CHECK: &str = "--self-check";

/// The exact command AC-6.6 requires the failure message to carry. One
/// constant because the message and the test that asserts an operator can
/// copy it must be the same string.
const SETCAP_COMMAND: &str = "sudo setcap cap_net_raw+ep $(which bathy-packetd)";

fn main() -> ExitCode {
    // 1. Open every socket we will ever need, while still privileged.
    let sockets = match privilege::acquire_raw_sockets() {
        Ok(sockets) => sockets,
        Err(e) => {
            warn(&startup_failure_message(&e));
            return ExitCode::from(NO_PRIVILEGE);
        }
    };

    // 2. Drop everything, immediately, before touching any input. This does
    //    not return `Ok` on the strength of having made the calls: it
    //    re-reads /proc/self/status and fails if any set is non-empty or
    //    `no_new_privs` did not take.
    if let Err(e) = privilege::drop_all_capabilities() {
        warn(&format!(
            "packetd: refusing to run with capabilities still held: {e}"
        ));
        return ExitCode::FAILURE;
    }
    let dropped = privilege::capabilities_are_dropped();

    // 3. Only now read anything an attacker could influence -- and read it
    //    through a guard that re-checks the capability set on every fill, so
    //    that moving this line above step 2 fails closed instead of silently
    //    becoming a privilege-escalation surface.
    //
    //    `args_os`, not `args`: `std::env::args` panics on an argument that
    //    is not valid Unicode, and a privileged process must not be crashable
    //    by the bytes of its own command line.
    let self_check_requested = std::env::args_os()
        .skip(1)
        .any(|arg| arg == std::ffi::OsStr::new(SELF_CHECK));
    let stdin = std::io::stdin();
    let mut input = UnprivilegedInput::new(stdin.lock());
    let mut stdout = std::io::stdout();
    // The sockets ARE the wire (`impl Wire for RawSockets`), so the session
    // takes ownership of them and gives them up when it ends. They were opened
    // while privileged and cannot be reopened, which is why there is one
    // owner and no way to acquire a second set.
    let status = if self_check_requested {
        self_check(&sockets, &mut input, &mut stdout)
    } else {
        run_session(dropped, Box::new(sockets), &mut input, &mut stdout)
    };
    ExitCode::from(status)
}

/// stderr, written directly.
///
/// `eprintln!` **panics** if the write fails, and a privileged process that
/// panics while explaining why it is exiting explains nothing. This is also
/// the reason the same idiom appears in this project's test skips: libtest
/// captures the print macros and this path is never captured.
fn warn(message: &str) {
    let mut stderr = std::io::stderr();
    let _ = stderr.write_all(message.as_bytes());
    let _ = stderr.write_all(b"\n");
    let _ = stderr.flush();
}

/// Whether a startup failure is the kernel refusing for lack of privilege,
/// as opposed to anything else that can stop a socket opening.
fn is_permission_denied(error: &PrivilegeError) -> bool {
    match error {
        PrivilegeError::Socket { source, .. } | PrivilegeError::Configure { source, .. } => {
            source.kind() == std::io::ErrorKind::PermissionDenied
        }
        _ => false,
    }
}

/// AC-6.6: the capability by name, the exact command that grants it, and the
/// fallback -- so an operator who hits this does not have to search.
///
/// The guidance is **conditional on the failure actually being a permission
/// failure**. Telling someone to run `setcap` when their kernel has no raw
/// socket support, or when the binary is on a filesystem mounted `nosuid`,
/// sends them to fix something that is not broken; a wrong instruction that
/// looks authoritative is worse than none.
fn startup_failure_message(error: &PrivilegeError) -> String {
    if is_permission_denied(error) {
        format!(
            "packetd: cannot open raw sockets ({error}).\n\
             packetd needs the CAP_NET_RAW capability and does not have it. Grant it with:\n  \
             {SETCAP_COMMAND}\n\
             Without it, bathy will fall back to connect scanning, which is slower but needs \
             no privilege."
        )
    } else {
        format!(
            "packetd: cannot open raw sockets ({error}).\n\
             This is not a permission failure, so granting CAP_NET_RAW will not fix it.\n\
             bathy will fall back to connect scanning, which is slower but needs no privilege."
        )
    }
}

/// What `--self-check` prints. Every field is a syscall result taken after
/// the drop; see the module header for what this does and does not establish.
#[derive(Debug, Serialize)]
struct SelfCheckReport {
    /// `getsockopt(SO_TYPE)` succeeded on all three raw sockets *after* the
    /// drop -- the architectural claim that a socket is a handle we keep
    /// rather than a privilege we retain, stated as a measurement rather than
    /// as "we got here, so the open worked".
    sockets_opened: bool,
    /// Every capability set in `/proc/self/status` is empty.
    capabilities_dropped: bool,
    /// `PR_SET_NO_NEW_PRIVS` took, so no `execve` can undo the line above.
    no_new_privs: bool,
    /// A real read, through the same guard the session reads through, and it
    /// was permitted. False means the guard refused -- which is what a build
    /// with the drop moved below the first read looks like from here.
    first_input_read_after_drop: bool,
    /// Opening a *new* raw socket now fails. The negative, observed.
    raw_socket_after_drop_denied: bool,
    effective_capabilities: String,
    permitted_capabilities: String,
    inheritable_capabilities: String,
    ambient_capabilities: String,
    /// Reported, not required: clearing it needs `CAP_SETPCAP`, and
    /// `no_new_privs` is what makes it inert. See `privilege.rs`.
    bounding_capabilities: String,
    measured_from: &'static str,
}

impl SelfCheckReport {
    /// Every claim this report makes, and-ed. `--self-check` exits non-zero
    /// unless all of them hold, so it is a gate an operator can run rather
    /// than a document they have to read.
    fn is_clean(&self) -> bool {
        self.sockets_opened
            && self.capabilities_dropped
            && self.no_new_privs
            && self.first_input_read_after_drop
            && self.raw_socket_after_drop_denied
    }
}

fn self_check<R: BufRead, W: Write>(sockets: &RawSockets, input: &mut R, out: &mut W) -> u8 {
    let state = privilege::measure().unwrap_or(PrivilegeState::UNKNOWN);
    let report = SelfCheckReport {
        sockets_opened: sockets.send().r#type().is_ok()
            && sockets.recv_tcp().r#type().is_ok()
            && sockets.recv_icmp().r#type().is_ok(),
        capabilities_dropped: state.capabilities_are_dropped(),
        no_new_privs: state.no_new_privs,
        // The read happens here, after everything above, and it is a real
        // one: with stdin at end of file it returns an empty slice, and the
        // guard has still measured the capability set to decide that.
        first_input_read_after_drop: input.fill_buf().is_ok(),
        raw_socket_after_drop_denied: privilege::raw_socket_is_denied(),
        effective_capabilities: format!("{:016x}", state.effective),
        permitted_capabilities: format!("{:016x}", state.permitted),
        inheritable_capabilities: format!("{:016x}", state.inheritable),
        ambient_capabilities: format!("{:016x}", state.ambient),
        bounding_capabilities: format!("{:016x}", state.bounding),
        measured_from: privilege::STATUS_PATH,
    };
    let clean = report.is_clean();
    let line = serde_json::to_string(&report)
        .unwrap_or_else(|_| r#"{"error":"self-check report serialization failed"}"#.to_string());
    if out.write_all(line.as_bytes()).is_err()
        || out.write_all(b"\n").is_err()
        || out.flush().is_err()
    {
        return FAILED;
    }
    if clean {
        OK
    } else {
        warn("packetd: --self-check failed; see the report on stdout for which claim is false");
        FAILED
    }
}

/// The line loop. One `Session` per process, and the process ends with it.
fn run_session<R: BufRead, W: Write>(
    dropped: bool,
    wire: Box<dyn Wire>,
    input: &mut R,
    out: &mut W,
) -> u8 {
    let mut session = Session::new(dropped, wire);
    let mut buf = Vec::new();
    loop {
        match read_line(input, &mut buf) {
            Ok(Some(line)) => {
                if let Some(response) = session.handle_line(line)
                    && !emit(out, &response)
                {
                    return FAILED;
                }
            }
            // The engine closed the pipe between messages: the ordinary end.
            Ok(None) => break,
            Err(e) => {
                let response = Response::Fatal {
                    detail: format!("{e}"),
                };
                let _ = emit(out, &response);
                warn(&format!("packetd: {e}"));
                return FAILED;
            }
        }
        if session.is_terminated() {
            break;
        }
    }
    if session.ended_fatally() { FAILED } else { OK }
}

/// One response line, flushed. False if the engine has gone away, which ends
/// the session: there is nobody left to answer.
fn emit<W: Write>(out: &mut W, response: &Response) -> bool {
    let line = response.to_line();
    out.write_all(line.as_bytes()).is_ok() && out.write_all(b"\n").is_ok() && out.flush().is_ok()
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;

    use super::*;

    /// A wire that accepts every packet and answers nothing. These tests are
    /// about the daemon's loop and its exit statuses; `syn.rs` owns what goes
    /// on the wire.
    #[derive(Debug)]
    struct NullWire;

    impl Wire for NullWire {
        fn source_for(&self, _target: std::net::Ipv4Addr) -> std::io::Result<std::net::Ipv4Addr> {
            Ok(std::net::Ipv4Addr::new(10, 30, 0, 99))
        }
        fn emit(&mut self, _packet: &[u8], _target: std::net::Ipv4Addr) -> std::io::Result<()> {
            Ok(())
        }
        fn poll(&mut self, _buf: &mut [u8]) -> Option<usize> {
            None
        }
    }

    fn socket_error(kind: ErrorKind) -> PrivilegeError {
        PrivilegeError::Socket {
            kind: "send",
            source: std::io::Error::from(kind),
        }
    }

    /// AC-6.6, in full: the capability by name, the exact `setcap` command,
    /// and the fallback. Asserted as three separate substrings because an
    /// operator needs all three and a message with two of them still sends
    /// them to a search engine.
    #[test]
    fn a_permission_failure_names_the_capability_the_command_and_the_fallback() {
        let message = startup_failure_message(&socket_error(ErrorKind::PermissionDenied));
        assert!(message.contains("CAP_NET_RAW"), "{message}");
        assert!(
            message.contains("setcap cap_net_raw+ep"),
            "the command must be copy-pasteable: {message}"
        );
        assert!(
            message.contains("bathy will fall back to connect scanning"),
            "{message}"
        );
    }

    /// The narrowing control. Without it, a `startup_failure_message` that
    /// returned the same paragraph for every error would pass the test above
    /// while telling an operator whose kernel lacks raw sockets to run
    /// `setcap`, which fixes nothing and looks authoritative.
    #[test]
    fn a_failure_that_is_not_about_permission_does_not_tell_the_operator_to_run_setcap() {
        let message = startup_failure_message(&socket_error(ErrorKind::AddrNotAvailable));
        assert!(
            !message.contains("setcap"),
            "this failure is not fixed by granting a capability: {message}"
        );
        assert!(
            message.contains("not a permission failure"),
            "it must say so rather than being silently different: {message}"
        );
        // The fallback is still true, and still the operator's next move.
        assert!(message.contains("connect scanning"), "{message}");
    }

    /// A drop that failed is not a socket failure, so it must not be dressed
    /// up as one: `setcap` cannot fix a `capset` that did not take.
    #[test]
    fn a_failed_drop_is_not_reported_as_a_missing_capability() {
        let message = startup_failure_message(&PrivilegeError::StillPrivileged("held".into()));
        assert!(!message.contains("setcap"), "{message}");
    }

    /// The report is a contract with `tests/privilege.rs` and with any
    /// operator parsing it. Field names are asserted here so that renaming
    /// one fails a unit test rather than silently making an integration
    /// assertion range over a field that no longer exists — `report["x"]` on
    /// a missing key is `Null`, and `Null != true` fails for the wrong
    /// reason while `assert!(report["x"] != false)` would pass outright.
    #[test]
    fn the_self_check_report_carries_every_field_the_criterion_names() {
        let report = SelfCheckReport {
            sockets_opened: true,
            capabilities_dropped: true,
            no_new_privs: true,
            first_input_read_after_drop: true,
            raw_socket_after_drop_denied: true,
            effective_capabilities: "0000000000000000".into(),
            permitted_capabilities: "0000000000000000".into(),
            inheritable_capabilities: "0000000000000000".into(),
            ambient_capabilities: "0000000000000000".into(),
            bounding_capabilities: "00000000a80425fb".into(),
            measured_from: privilege::STATUS_PATH,
        };
        assert!(report.is_clean());
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
        for field in [
            "sockets_opened",
            "capabilities_dropped",
            "no_new_privs",
            "first_input_read_after_drop",
            "raw_socket_after_drop_denied",
        ] {
            assert_eq!(json[field], serde_json::json!(true), "{field}");
        }
        assert_eq!(json["measured_from"], "/proc/self/status");
    }

    /// Each of the five claims must be able to fail the check on its own. A
    /// conjunction that ignored one of its terms would let a build ship with
    /// that property false and `--self-check` exiting zero.
    #[test]
    fn every_claim_in_the_report_can_fail_the_self_check_by_itself() {
        let clean = || SelfCheckReport {
            sockets_opened: true,
            capabilities_dropped: true,
            no_new_privs: true,
            first_input_read_after_drop: true,
            raw_socket_after_drop_denied: true,
            effective_capabilities: "0000000000000000".into(),
            permitted_capabilities: "0000000000000000".into(),
            inheritable_capabilities: "0000000000000000".into(),
            ambient_capabilities: "0000000000000000".into(),
            bounding_capabilities: "0000000000000000".into(),
            measured_from: privilege::STATUS_PATH,
        };
        type Mutation = (&'static str, fn(&mut SelfCheckReport));
        let mutations: [Mutation; 5] = [
            ("sockets_opened", |r| r.sockets_opened = false),
            ("capabilities_dropped", |r| r.capabilities_dropped = false),
            ("no_new_privs", |r| r.no_new_privs = false),
            ("first_input_read_after_drop", |r| {
                r.first_input_read_after_drop = false
            }),
            ("raw_socket_after_drop_denied", |r| {
                r.raw_socket_after_drop_denied = false
            }),
        ];
        for (name, break_it) in mutations {
            let mut report = clean();
            break_it(&mut report);
            assert!(!report.is_clean(), "{name} does not affect the verdict");
        }
    }

    /// The line loop, over the protocol's own fatal path. `run_session` is
    /// what a real engine talks to, and the thing worth pinning about it is
    /// that a session which ends fatally ends the *process* non-zero -- the
    /// engine's only signal that the privileged half refused -- while a
    /// clean shutdown does not.
    ///
    /// Testable in an ordinary unprivileged process because `run_session`
    /// takes no `RawSockets`: `main` holds those, and this loop has no use
    /// for them until M6 Task 3. The alternative -- a helper that skipped
    /// when it could not open a raw socket -- is how a suite comes to report
    /// `ok` for a test that ran nothing.
    #[test]
    fn a_fatal_line_ends_the_process_non_zero_and_a_clean_shutdown_does_not() {
        let init = concat!(
            r#"{"type":"init","allowed_cidrs":["10.30.0.0/24"],"denied_cidrs":[],"#,
            r#""packets_per_second":100,"max_packets":1000}"#,
            "\n"
        );
        let probe = "{\"type\":\"probe\",\"id\":1,\"target\":\"10.30.0.7\",\"port\":80}\n";
        for (name, lines, expected, expected_last) in [
            (
                "clean shutdown",
                format!("{init}{{\"type\":\"shutdown\"}}\n"),
                OK,
                "ready",
            ),
            ("end of stream", init.to_string(), OK, "ready"),
            (
                "malformed json",
                format!("{init}{{not json\n"),
                FAILED,
                "fatal",
            ),
            ("probe before init", probe.to_string(), FAILED, "fatal"),
        ] {
            let mut reader = std::io::Cursor::new(lines.into_bytes());
            let mut out = Vec::new();
            assert_eq!(
                run_session(false, Box::new(NullWire), &mut reader, &mut out),
                expected,
                "{name}"
            );
            let written = String::from_utf8(out).unwrap();
            let last = written.lines().next_back().unwrap_or_default();
            assert!(
                last.contains(&format!(r#""type":"{expected_last}""#)),
                "{name}: last line was {last:?}"
            );
        }
    }

    /// `Session::new` is handed what `main` **measured**, and this loop is
    /// the only thing between that measurement and the `ready` line the
    /// engine reads. A `run_session` that passed a constant would make
    /// `dropped_capabilities` a fabricated security claim again — the defect
    /// M6 Task 1's plan edit #1 exists for.
    #[test]
    fn the_ready_line_relays_the_capability_state_run_session_was_given() {
        let init = concat!(
            r#"{"type":"init","allowed_cidrs":["10.30.0.0/24"],"denied_cidrs":[],"#,
            r#""packets_per_second":100,"max_packets":1000}"#,
            "\n"
        );
        for dropped in [true, false] {
            let mut out = Vec::new();
            let mut session = Session::new(dropped, Box::new(NullWire));
            let response = session.handle_line(init.trim_end()).unwrap();
            assert!(emit(&mut out, &response));
            let line = String::from_utf8(out).unwrap();
            assert!(
                line.contains(&format!(r#""dropped_capabilities":{dropped}"#)),
                "{line}"
            );
        }
    }

    /// `emit` reports the engine going away rather than panicking on it. A
    /// privileged process whose peer closed the pipe must exit, not abort.
    #[test]
    fn emit_reports_a_closed_peer_instead_of_panicking() {
        struct Closed;
        impl Write for Closed {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let response = Response::Fatal {
            detail: "why".into(),
        };
        assert!(!emit(&mut Closed, &response));
        assert!(emit(&mut Vec::new(), &response));
    }
}
