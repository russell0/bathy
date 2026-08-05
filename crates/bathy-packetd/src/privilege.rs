//! Acquiring the one privilege this process needs, and giving it up before it
//! reads a byte.
//!
//! # The whole security argument, in one ordering
//!
//! `packetd` is the only component in this workspace that can put an
//! arbitrary packet on the wire, and the only one that will ever hold
//! `CAP_NET_RAW`. The argument for trusting it is not that its parser is
//! correct -- no parser is -- but that **by the time any attacker-influenced
//! byte reaches that parser, the capability is gone**:
//!
//! 1. [`acquire_raw_sockets`] opens every socket the process will ever need,
//!    while still privileged. A socket is a *handle we hold*, not a privilege
//!    we retain; the kernel checks `CAP_NET_RAW` at `socket(2)`, not at
//!    `sendto(2)`.
//! 2. [`drop_all_capabilities`] empties every capability set and sets
//!    `PR_SET_NO_NEW_PRIVS`, then **verifies both against `/proc/self/status`**
//!    and returns an error if either did not take. A drop that is claimed and
//!    not measured is the defect class this repository has paid for most.
//! 3. Only then does anything read input, and [`UnprivilegedInput`] makes that
//!    a property of the *reader* rather than a property of the order of two
//!    statements in `main`: it re-measures the capability set on every single
//!    `fill_buf` and refuses to yield a byte while one is held.
//!
//! Step 3 exists because of the Global Constraint on ordering guarantees: a
//! test that fails when the drop is *deleted* leaves the drop being *moved*
//! after the first read completely unguarded, and moving it is the actual
//! bug. `UnprivilegedInput` turns that move from a silent reordering into a
//! `PermissionDenied` on the first line the engine sends.
//!
//! # Where the `unsafe` is, and why there is only one block
//!
//! The Global Constraint permits `unsafe` in this crate for the raw-socket
//! and privilege-dropping syscalls. Almost none of it turned out to be
//! needed, because two reviewed crates already own those syscalls behind safe
//! APIs:
//!
//! - `socket2` opens the raw sockets. `Socket::new(Domain::IPV4, Type::RAW,
//!   ..)` *is* the `socket(2)` call; wrapping it again in `unsafe` would be
//!   writing a worse version of a crate already in the graph.
//! - `caps` clears the five capability sets. `caps::clear` *is* `capset(2)`.
//!
//! What is left is exactly one syscall neither crate exposes and that nothing
//! else in the graph can make: `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`. See
//! [`set_no_new_privs`] for the block and its `SAFETY:` comment. `libc` is
//! already in this crate's graph twice over (both `socket2` and `caps` depend
//! on it), so taking it directly adds no crate to the address space that
//! opens raw sockets -- which is the property `Cargo.toml` argues for at
//! length and which pulling in a third wrapper crate for one `prctl` would
//! have cost.
//!
//! # Fail closed, on every path
//!
//! [`PrivilegeState::UNKNOWN`] is *all capabilities held*, not none. Every
//! path that cannot measure -- a missing `/proc`, an unparseable mask, a
//! platform that has no capabilities at all -- therefore reads as
//! **privileged**, and every consumer of that answer refuses. The opposite
//! default would make an unreadable `/proc/self/status` look like a
//! successful drop.

use std::io::{self, BufRead, Read};

use socket2::{Domain, Protocol, Socket, Type};

/// The file the drop is verified against.
///
/// Deliberately `/proc` and not `caps::read`: the point of the verification
/// is that it does not go back through the same library that performed the
/// drop. A `caps::clear` that silently did nothing and a `caps::read` that
/// silently agreed with it would be one bug, not two.
pub const STATUS_PATH: &str = "/proc/self/status";

/// The three IP protocol numbers this process opens a socket for, spelled
/// here rather than taken from `libc` so that this module compiles and is
/// reviewable on every platform. They are wire constants fixed by IANA, not
/// platform details.
const IPPROTO_ICMP: i32 = 1;
const IPPROTO_TCP: i32 = 6;
const IPPROTO_RAW: i32 = 255;

/// Everything that can go wrong between "this process starts" and "this
/// process is safe to hand untrusted bytes to".
#[derive(Debug, thiserror::Error)]
pub enum PrivilegeError {
    #[error("opening the {kind} raw socket: {source}")]
    Socket {
        kind: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("configuring the {kind} raw socket: {source}")]
    Configure {
        kind: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("clearing the {set} capability set: {detail}")]
    Clear { set: &'static str, detail: String },
    #[error("setting PR_SET_NO_NEW_PRIVS: {0}")]
    NoNewPrivs(#[source] io::Error),
    #[error("reading {STATUS_PATH}: {0}")]
    Status(#[source] io::Error),
    /// The drop was performed and the measurement disagrees. Reported rather
    /// than ignored, and fatal at every call site.
    #[error("{0}")]
    StillPrivileged(String),
    /// There is no capability model to drop on this platform, so this process
    /// cannot establish the one property it exists to establish.
    #[error(
        "packetd cannot drop privilege on this platform: capabilities are a Linux mechanism, \
         and a process that cannot prove it gave privilege up must not go on to read input"
    )]
    Unsupported,
}

// ---------------------------------------------------------------------------
// Step 1 — the sockets, opened while privileged.
// ---------------------------------------------------------------------------

/// Every socket `packetd` will ever open, opened once, before the drop.
///
/// There is no method here that opens another one, and that is the design:
/// after [`drop_all_capabilities`] the kernel would refuse anyway, so a
/// second acquisition point could only be a bug that fails late. M6 Task 3
/// (SYN) and Task 5 (ICMP) send and receive through these three and add none.
#[derive(Debug)]
pub struct RawSockets {
    send: Socket,
    recv_tcp: Socket,
    recv_icmp: Socket,
}

impl RawSockets {
    /// The `IPPROTO_RAW` sending socket, with `IP_HDRINCL` already set, so a
    /// SYN carries the IP header this process built rather than one the
    /// kernel guessed at.
    pub fn send(&self) -> &Socket {
        &self.send
    }
    /// Receives TCP segments: SYN-ACK and RST replies (M6 Task 3).
    pub fn recv_tcp(&self) -> &Socket {
        &self.recv_tcp
    }
    /// Receives ICMP: echo replies and unreachables (M6 Task 5).
    pub fn recv_icmp(&self) -> &Socket {
        &self.recv_icmp
    }
}

fn raw_socket(protocol: i32, kind: &'static str) -> Result<Socket, PrivilegeError> {
    Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(protocol)))
        .map_err(|source| PrivilegeError::Socket { kind, source })
}

/// Opens every raw socket this process will ever need.
///
/// Fails with `PermissionDenied` when `CAP_NET_RAW` is absent, which is what
/// AC-6.6's guidance is keyed off. It is deliberately the *first* thing the
/// process does: an operator who has not granted the capability finds out at
/// startup, not on the first probe of a scan they have already waited for.
pub fn acquire_raw_sockets() -> Result<RawSockets, PrivilegeError> {
    let send = raw_socket(IPPROTO_RAW, "send")?;
    send.set_header_included_v4(true)
        .map_err(|source| PrivilegeError::Configure {
            kind: "send",
            source,
        })?;
    let recv_tcp = raw_socket(IPPROTO_TCP, "tcp-receive")?;
    let recv_icmp = raw_socket(IPPROTO_ICMP, "icmp-receive")?;
    Ok(RawSockets {
        send,
        recv_tcp,
        recv_icmp,
    })
}

/// Whether this process can still open a raw socket.
///
/// This is AC-6.5's claim stated as a *negative that can be observed*: after
/// the drop, the syscall that needed `CAP_NET_RAW` must fail. It is a real
/// `socket(2)`, not a reading of the capability mask, so it is true even if
/// the mask is lying.
pub fn raw_socket_is_denied() -> bool {
    raw_socket(IPPROTO_TCP, "probe").is_err()
}

// ---------------------------------------------------------------------------
// Step 2 — the drop, and the measurement that is allowed to contradict it.
// ---------------------------------------------------------------------------

/// The privilege-relevant fields of `/proc/self/status`.
///
/// Masks are `u64` bitsets exactly as the kernel renders them. Parsing is a
/// pure function ([`parse_status`]) so that every case -- a missing field, a
/// malformed mask, a kernel too old to report `NoNewPrivs` -- is a unit test
/// on any platform rather than a thing only reachable on Linux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivilegeState {
    pub effective: u64,
    pub permitted: u64,
    pub inheritable: u64,
    /// The kernel maintains `ambient ⊆ permitted ∩ inheritable`, so clearing
    /// permitted clears this too. It is measured and required to be zero
    /// anyway: this module's job is to check the outcome, not to recite an
    /// invariant a reader would have to already know.
    pub ambient: u64,
    /// Reported, never required: clearing the bounding set needs
    /// `CAP_SETPCAP`, which a process granted only `CAP_NET_RAW` does not
    /// have. See [`drop_all_capabilities`] for why that is survivable and
    /// what makes it so.
    pub bounding: u64,
    pub no_new_privs: bool,
}

impl PrivilegeState {
    /// What "we could not measure" means: **everything held**.
    ///
    /// The direction is the whole point. A default of zero would make an
    /// unreadable `/proc/self/status`, a truncated read, or a platform with
    /// no `/proc` at all indistinguishable from a successful drop, and every
    /// consumer here treats "dropped" as permission to start reading hostile
    /// input.
    pub const UNKNOWN: Self = Self {
        effective: u64::MAX,
        permitted: u64::MAX,
        inheritable: u64::MAX,
        ambient: u64::MAX,
        bounding: u64::MAX,
        no_new_privs: false,
    };

    /// True when no capability is held in any set this process can act on.
    ///
    /// The bounding set is excluded on purpose: it does not permit anything
    /// by itself, it only bounds what an `execve` could *gain*, and that door
    /// is closed by `no_new_privs` instead.
    pub fn capabilities_are_dropped(&self) -> bool {
        self.effective == 0 && self.permitted == 0 && self.inheritable == 0 && self.ambient == 0
    }

    /// The full property `packetd` requires before it reads anything: no
    /// capability held, and no way to acquire one.
    pub fn is_unprivileged(&self) -> bool {
        self.capabilities_are_dropped() && self.no_new_privs
    }
}

/// Parses the four capability masks and `NoNewPrivs` out of a
/// `/proc/self/status` document.
///
/// Starts from [`PrivilegeState::UNKNOWN`] and only ever *lowers* what it can
/// read, so a field that is absent, misspelled, or not hexadecimal leaves
/// that set reading as fully held. `u64::from_str_radix` failing means the
/// kernel wrote something this code does not understand, and the safe
/// interpretation of "I do not understand the capability mask" is not zero.
pub fn parse_status(text: &str) -> PrivilegeState {
    let mut state = PrivilegeState::UNKNOWN;
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        let mask = || u64::from_str_radix(value, 16).unwrap_or(u64::MAX);
        match key {
            "CapEff" => state.effective = mask(),
            "CapPrm" => state.permitted = mask(),
            "CapInh" => state.inheritable = mask(),
            "CapAmb" => state.ambient = mask(),
            "CapBnd" => state.bounding = mask(),
            "NoNewPrivs" => state.no_new_privs = value == "1",
            _ => {}
        }
    }
    state
}

/// Reads the current privilege state from `/proc/self/status`.
pub fn measure() -> Result<PrivilegeState, PrivilegeError> {
    let text = std::fs::read_to_string(STATUS_PATH).map_err(PrivilegeError::Status)?;
    Ok(parse_status(&text))
}

/// The measurement, with every failure collapsed into "still privileged".
///
/// This is the form the ordering guard and `Response::Ready` use, because
/// both of them have to answer a yes/no question and neither may answer it
/// optimistically.
pub fn capabilities_are_dropped() -> bool {
    measure().is_ok_and(|state| state.is_unprivileged())
}

/// Empties every capability set, forbids acquiring new privilege, and then
/// checks that both actually happened.
///
/// Order within the drop is `Ambient`, `Bounding`, `Inheritable`,
/// `Effective`, `Permitted`: permitted last, because a capability removed
/// from `Permitted` can never be raised back into `Effective`, so doing it
/// first would leave the remaining `caps::clear` calls unable to report
/// anything useful.
///
/// `Ambient` and `Bounding` are **best effort, and only because
/// `no_new_privs` makes them inert**. Clearing the bounding set requires
/// `CAP_SETPCAP`; the deployment this is designed for grants exactly
/// `CAP_NET_RAW` and nothing else, so the call fails with `EPERM` in the
/// normal case. What the bounding set can do is permit an `execve` of a
/// file-capability binary to gain a capability -- and `PR_SET_NO_NEW_PRIVS`,
/// which needs no privilege at all and therefore never fails for lack of
/// one, forbids exactly that. So the requirement is expressed on
/// `no_new_privs`, which always succeeds, rather than on `CapBnd`, which
/// cannot. The final measurement reports `bounding` either way, so a reader
/// can see which of the two happened.
pub fn drop_all_capabilities() -> Result<(), PrivilegeError> {
    clear_capability_sets()?;
    set_no_new_privs()?;
    refuse_unless_unprivileged(measure()?)
}

/// The verification, separated from the syscalls so that it can be tested
/// with a state nothing had to produce.
///
/// It exists because a `caps::clear` that silently did nothing would
/// otherwise be indistinguishable from one that worked, and everything after
/// this point treats "dropped" as permission to read hostile input. But on a
/// tree where the drop *does* work it is dead weight, and a mutation that
/// replaces its condition with `true` changes nothing observable -- it
/// survived exactly that, in the privileged container, before this function
/// existed. What it costs when it is wrong is the entire security property
/// of this process, so the answer is a test that can put it in the state it
/// guards against rather than deleting it.
fn refuse_unless_unprivileged(state: PrivilegeState) -> Result<(), PrivilegeError> {
    if state.is_unprivileged() {
        return Ok(());
    }
    Err(PrivilegeError::StillPrivileged(format!(
        "the capability drop did not take: {STATUS_PATH} reports CapEff={:016x} \
         CapPrm={:016x} CapInh={:016x} CapAmb={:016x} NoNewPrivs={}",
        state.effective, state.permitted, state.inheritable, state.ambient, state.no_new_privs,
    )))
}

#[cfg(target_os = "linux")]
fn clear_capability_sets() -> Result<(), PrivilegeError> {
    use caps::CapSet;

    // Inert once `no_new_privs` is set, and unclearable without CAP_SETPCAP.
    // The outcome is not taken on trust either way: the final measurement
    // reports `CapAmb` and `CapBnd` from `/proc/self/status`, and `CapAmb`
    // must be zero there whatever this call returned.
    for set in [CapSet::Ambient, CapSet::Bounding] {
        let _ = caps::clear(None, set);
    }
    for (set, name) in [
        (CapSet::Inheritable, "inheritable"),
        (CapSet::Effective, "effective"),
        (CapSet::Permitted, "permitted"),
    ] {
        caps::clear(None, set).map_err(|e| PrivilegeError::Clear {
            set: name,
            detail: e.to_string(),
        })?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn clear_capability_sets() -> Result<(), PrivilegeError> {
    Err(PrivilegeError::Unsupported)
}

/// `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` -- the one syscall in this
/// workspace that no crate in the graph exposes safely.
///
/// It makes the drop **irrevocable**: with the bit set, no `execve` this
/// process performs can ever grant it a capability, whatever is left in the
/// bounding set and whatever file capabilities exist on disk. Without it,
/// "all capabilities dropped" is a statement about right now rather than
/// about the rest of the process's life, and the bounding set could not be
/// cleared anyway (it needs `CAP_SETPCAP`, which this deployment does not
/// grant).
///
/// It is verified from outside this function: `NoNewPrivs: 1` appears in
/// `/proc/self/status` and [`drop_all_capabilities`] refuses to return `Ok`
/// without it, so the block below is checked by its effect and not only by
/// its return value.
#[cfg(target_os = "linux")]
#[expect(
    unsafe_code,
    reason = "PR_SET_NO_NEW_PRIVS is not exposed by `caps` or by `socket2`, and pulling a \
              third wrapper crate into the address space that opens raw sockets to avoid one \
              argument-only syscall would cost more review than it saves"
)]
fn set_no_new_privs() -> Result<(), PrivilegeError> {
    // SAFETY: `prctl` is a C variadic whose contract is entirely in its
    // argument *shape*, and every argument here is a compile-time constant of
    // the exact type the kernel documents for this option: `PR_SET_NO_NEW_PRIVS`
    // requires arg2 == 1 and arg3..arg5 == 0, and returns EINVAL rather than
    // acting if they are anything else. There is no pointer argument, so this
    // call reads and writes no memory belonging to this process: there is no
    // aliasing, no lifetime, no initialization and no alignment obligation to
    // discharge. It touches no shared mutable state, so it is sound to call
    // from any thread at any time. The only effect is to set one bit in this
    // process's task struct, which is idempotent and cannot be unset -- so a
    // repeat call is sound and a partial failure is not representable. Failure
    // is signalled by a negative return with `errno` set, which is handled
    // below rather than ignored.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(PrivilegeError::NoNewPrivs(io::Error::last_os_error()))
    }
}

#[cfg(not(target_os = "linux"))]
fn set_no_new_privs() -> Result<(), PrivilegeError> {
    Err(PrivilegeError::Unsupported)
}

// ---------------------------------------------------------------------------
// Step 3 — the reader that will not run while privileged.
// ---------------------------------------------------------------------------

/// What the guard says when it refuses. Named because a test asserts on it
/// and because an operator who sees it is looking at a build whose startup
/// order is wrong, which deserves to be unambiguous.
pub const ORDERING_VIOLATION: &str = "packetd attempted to read input while still holding a capability; refusing. This is a \
     build defect: raw sockets are opened, then every capability is dropped, and only then \
     is any attacker-influenced byte read.";

/// A reader that yields nothing while this process holds a capability.
///
/// The Global Constraint on ordering guarantees is why this type exists
/// rather than a comment in `main`: "the drop happens before the first read"
/// asserted only by a test that deletes the drop leaves *moving* the drop
/// after the read -- the actual bug -- unguarded. Here the ordering is a
/// precondition of reading at all, re-measured on every `fill_buf` rather
/// than cached, so there is no "already checked" flag for a reordering to
/// slip past.
///
/// The cost is one `/proc/self/status` read per protocol line, against a
/// network round trip per probe. That is the correct trade for the one
/// process in this repository where a parsing bug is privilege escalation.
#[derive(Debug)]
pub struct UnprivilegedInput<R> {
    inner: R,
}

impl<R> UnprivilegedInput<R> {
    pub fn new(inner: R) -> Self {
        Self { inner }
    }

    /// Consumes the guard. For a caller that has finished reading; there is
    /// no way to get bytes out of `inner` while the guard holds it.
    pub fn into_inner(self) -> R {
        self.inner
    }

    fn gate(&self) -> io::Result<()> {
        if capabilities_are_dropped() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                ORDERING_VIOLATION,
            ))
        }
    }
}

impl<R: Read> Read for UnprivilegedInput<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.gate()?;
        self.inner.read(buf)
    }
}

impl<R: BufRead> BufRead for UnprivilegedInput<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.gate()?;
        self.inner.fill_buf()
    }

    fn consume(&mut self, amount: usize) {
        self.inner.consume(amount);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real `/proc/self/status` extract, from the unprivileged container
    /// `linux-gate` runs in. Trimmed to the fields this module reads plus
    /// two it must ignore.
    const DROPPED: &str = "Name:\tbathy-packetd\n\
         Uid:\t1000\t1000\t1000\t1000\n\
         CapInh:\t0000000000000000\n\
         CapPrm:\t0000000000000000\n\
         CapEff:\t0000000000000000\n\
         CapAmb:\t0000000000000000\n\
         CapBnd:\t00000000a80425fb\n\
         NoNewPrivs:\t1\n";

    /// The same document as it looks *before* the drop, in a container
    /// started with `--cap-add=NET_RAW`: bit 13 (`CAP_NET_RAW`) held in the
    /// permitted and effective sets. The two fixtures differ in exactly the
    /// fields the drop changes, so a parser that ignored them would fail the
    /// pair rather than pass both.
    const HELD: &str = "Name:\tbathy-packetd\n\
         Uid:\t0\t0\t0\t0\n\
         CapInh:\t0000000000000000\n\
         CapPrm:\t0000000000002000\n\
         CapEff:\t0000000000002000\n\
         CapAmb:\t0000000000000000\n\
         CapBnd:\t00000000a80425fb\n\
         NoNewPrivs:\t0\n";

    #[test]
    fn a_status_document_with_every_set_empty_and_no_new_privs_reads_as_unprivileged() {
        let state = parse_status(DROPPED);
        assert_eq!(state.effective, 0);
        assert_eq!(state.permitted, 0);
        assert_eq!(state.inheritable, 0);
        assert_eq!(state.bounding, 0x0000_0000_a804_25fb);
        assert!(state.no_new_privs);
        assert!(state.capabilities_are_dropped());
        assert!(state.is_unprivileged());
    }

    #[test]
    fn cap_net_raw_still_held_reads_as_privileged() {
        let state = parse_status(HELD);
        assert_eq!(state.effective, 1 << 13, "CAP_NET_RAW is bit 13");
        assert!(!state.capabilities_are_dropped());
        assert!(!state.is_unprivileged());
    }

    /// The bounding set is the one mask that may legitimately stay full: it
    /// cannot be cleared without `CAP_SETPCAP`, and `no_new_privs` is what
    /// makes it inert. A `capabilities_are_dropped` that included it would
    /// make the normal, correct deployment report itself as privileged
    /// forever.
    #[test]
    fn a_full_bounding_set_does_not_make_a_dropped_process_privileged() {
        let state = parse_status(DROPPED);
        assert_ne!(state.bounding, 0, "the fixture is supposed to keep CapBnd");
        assert!(state.is_unprivileged());
    }

    /// Capabilities gone but `no_new_privs` unset is *not* the state this
    /// process may read input in: an `execve` could still gain privilege
    /// through a file-capability binary. Same document as [`DROPPED`] with
    /// one character changed.
    #[test]
    fn capabilities_dropped_without_no_new_privs_is_not_yet_unprivileged() {
        let state = parse_status(&DROPPED.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"));
        assert!(state.capabilities_are_dropped());
        assert!(
            !state.is_unprivileged(),
            "a drop that an exec can undo is not a drop"
        );
    }

    /// Every way of failing to read a mask must read as *held*. A parser
    /// whose default was zero would turn an empty file, a truncated read or a
    /// kernel that renamed a field into a clean bill of health.
    ///
    /// Each case leaves **exactly one** thing wrong and every other field
    /// readable and clean, which is what makes it a test of that field. The
    /// first version of the unparseable-mask case omitted `CapAmb` as well,
    /// so the state was privileged for a second reason and the case survived
    /// a mutation that made an unparseable mask read as zero.
    #[test]
    fn anything_unreadable_reads_as_still_privileged() {
        let clean = "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n\
                     CapEff:\t0000000000000000\nCapAmb:\t0000000000000000\n\
                     CapBnd:\t0000000000000000\nNoNewPrivs:\t1\n";
        assert!(
            parse_status(clean).is_unprivileged(),
            "the control: this document is the one shape that may read as dropped"
        );
        for (why, text) in [
            ("an empty document", String::new()),
            (
                "no capability fields at all",
                "Name:\tbathy-packetd\n".to_string(),
            ),
            (
                "one mask the kernel wrote in a form this code does not parse",
                clean.replace("CapEff:\t0000000000000000", "CapEff:\tnot-a-mask"),
            ),
            ("no NoNewPrivs line", clean.replace("NoNewPrivs:\t1\n", "")),
            ("a renamed field", clean.replace("CapPrm:", "CapPermitted:")),
        ] {
            let state = parse_status(&text);
            assert!(
                !state.is_unprivileged(),
                "{why}: {text:?} must not read as a successful drop"
            );
        }
    }

    /// Each capability set on its own has to be able to make the answer
    /// `false`. A conjunction that dropped one of its terms would let a
    /// process with that set populated read as unprivileged, and `CapAmb` is
    /// the one a reader is most likely to think is implied by the others.
    #[test]
    fn every_capability_set_can_make_this_process_privileged_by_itself() {
        let clean = "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n\
                     CapEff:\t0000000000000000\nCapAmb:\t0000000000000000\n\
                     CapBnd:\t0000000000000000\nNoNewPrivs:\t1\n";
        for field in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
            let held = clean.replace(
                &format!("{field}:\t0000000000000000"),
                &format!("{field}:\t0000000000002000"),
            );
            assert_ne!(held, clean, "{field} is not in the fixture");
            assert!(
                !parse_status(&held).capabilities_are_dropped(),
                "CAP_NET_RAW held in {field} alone must not read as dropped"
            );
        }
        // `CapBnd` is the exception, and it is an exception on purpose: it
        // permits nothing by itself and cannot be cleared without
        // CAP_SETPCAP. `no_new_privs` is what closes it.
        let bounded = clean.replace("CapBnd:\t0000000000000000", "CapBnd:\t00000000a80425fb");
        assert!(parse_status(&bounded).is_unprivileged());
    }

    #[test]
    fn the_unknown_state_is_fully_privileged_in_every_set() {
        assert!(!PrivilegeState::UNKNOWN.capabilities_are_dropped());
        assert!(!PrivilegeState::UNKNOWN.is_unprivileged());
    }

    /// The drop refuses to report success on a state that is not the state
    /// it was supposed to produce, and names the masks that are wrong -- so
    /// an operator reading the failure can see *which* set did not clear.
    #[test]
    fn a_drop_that_did_not_take_is_refused_rather_than_reported_as_done() {
        let clean = parse_status(DROPPED);
        assert!(
            refuse_unless_unprivileged(clean).is_ok(),
            "the control: a genuinely dropped process must be allowed to proceed"
        );

        for (why, state) in [
            ("CAP_NET_RAW still effective", parse_status(HELD)),
            (
                "no_new_privs did not take",
                parse_status(&DROPPED.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0")),
            ),
            ("nothing could be measured", PrivilegeState::UNKNOWN),
        ] {
            let error = refuse_unless_unprivileged(state)
                .expect_err(&format!("{why} must not be reported as a completed drop"));
            let text = error.to_string();
            assert!(text.contains("did not take"), "{why}: {text}");
            assert!(
                text.contains("CapEff="),
                "{why} must name the masks: {text}"
            );
            assert!(text.contains("NoNewPrivs="), "{why}: {text}");
        }
    }

    // -- the ordering guard --------------------------------------------------

    /// The guard, over the real `capabilities_are_dropped` rather than over a
    /// re-implementation of it. Written as an equivalence instead of as
    /// `assert!(err)` because the answer depends on where it runs — macOS has
    /// no `/proc`, `linux-gate`'s container has no capabilities but also no
    /// `no_new_privs`, and the privileged container runs this same suite as
    /// root — and a test that asserted one of those would be a test about
    /// which machine it was on. The equivalence holds everywhere and dies if
    /// the gate is removed anywhere it currently refuses.
    #[test]
    fn the_guard_yields_bytes_exactly_when_this_process_measures_as_unprivileged() {
        let mut guarded = UnprivilegedInput::new(io::Cursor::new(b"secret\n".to_vec()));
        match guarded.fill_buf() {
            Ok(bytes) => {
                assert!(
                    capabilities_are_dropped(),
                    "the guard handed over {} byte(s) to a process that still measures \
                     as privileged",
                    bytes.len()
                );
                assert_eq!(bytes, b"secret\n");
            }
            Err(e) => {
                assert!(
                    !capabilities_are_dropped(),
                    "the guard refused a process that has dropped everything"
                );
                assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
                assert!(
                    e.to_string().contains("while still holding a capability"),
                    "the refusal must say what is wrong: {e}"
                );
            }
        }
    }

    /// The narrowing control for the test above: the same reader, unguarded,
    /// does yield the bytes. Without this, a `fill_buf` that always failed
    /// would satisfy the guard's test.
    #[test]
    fn the_same_reader_without_the_guard_yields_its_bytes() {
        let mut plain = io::Cursor::new(b"secret\n".to_vec());
        assert_eq!(plain.fill_buf().unwrap(), b"secret\n");
    }

    /// `raw_socket_is_denied` has to be the negation of a *real* `socket(2)`,
    /// not a reading of a mask and not a constant. Stated that way rather
    /// than as `assert!(raw_socket_is_denied())` because this test also runs
    /// as root, inside the privileged container that exercises
    /// `tests/privilege.rs` — and there the true answer is the other one. A
    /// test that asserted the unprivileged answer would have been a test
    /// about which container it ran in.
    #[test]
    fn raw_socket_is_denied_is_the_negation_of_actually_opening_one() {
        let opened = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)).is_ok();
        assert_eq!(raw_socket_is_denied(), !opened);
    }
}
