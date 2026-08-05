#![deny(unsafe_code)]
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

//! `packetd`: the only privileged component in this workspace, and the only
//! one that will ever be permitted `unsafe`.
//!
//! # What this crate is for
//!
//! The engine is unprivileged and cannot emit a raw packet. `packetd` can.
//! The architecture is therefore deliberately **mutually suspicious**: the
//! engine treats `packetd` as an untrusted subordinate, and `packetd` treats
//! the engine as an untrusted caller. It enforces scope a second time,
//! independently of `bathy-scope`, so that a bug or a compromise in the
//! unprivileged half cannot become a packet at an address nobody authorized.
//!
//! [`protocol`] is the seam between those two distrusting halves, and it is
//! the first thing in the tree to run: everything else `packetd` does happens
//! only because a line arrived and this module accepted it.
//!
//! # `#![deny(unsafe_code)]`, and the one site that overrides it
//!
//! The Global Constraint permits `unsafe` in this crate, and only for the
//! raw-socket and privilege-dropping syscalls. It is `deny` rather than
//! `forbid` because `forbid` cannot be overridden even by a site-level
//! `expect` carrying a reason -- which would mean the whole crate losing the
//! lint for the sake of one function. Every other file here, and the
//! `main.rs` binary target beside this one, is still under the lint at
//! `forbid` or `deny` strength.
//!
//! There is **one** `unsafe` block in this crate:
//! [`privilege::set_no_new_privs`], which makes the capability drop
//! irrevocable via `prctl(PR_SET_NO_NEW_PRIVS, ...)`. Everything else that
//! looked like it would need `unsafe` is a safe call into a crate that
//! already owns the syscall: `socket2::Socket::new` *is* `socket(2)`, and
//! `caps::clear` *is* `capset(2)`. Writing either of them again by hand
//! would be adding `unsafe` to reimplement a reviewed dependency, which is
//! the opposite of what the allowance is for.
//!
//! The block carries a `SAFETY:` comment (AC-6.7), enforced by
//! `cargo run -p xtask -- check-packetd`, which also fails if this crate
//! ever has zero `unsafe` blocks *and* no crate-level `forbid` -- so the
//! criterion cannot come to range over nothing without somebody noticing.
//!
//! # No panics on the byte path (Global Constraint)
//!
//! The deny attribute above is not a formality here. Every other crate that
//! carries it parses bytes that make a *finding* wrong; this one parses bytes
//! that arrive at a process holding `CAP_NET_RAW`, which is the one place in
//! this repository where a parsing bug is a privilege-escalation bug rather
//! than only a denial of service. The lint was enabled from the crate's first
//! commit rather than retrofitted -- the three crates that were retrofitted a
//! week earlier turned up 102 real panic sites between them, one of which was
//! on the first line of a hostile-peer read path.
//!
//! What the lint does **not** see, and what was therefore checked by reading:
//! `clippy::indexing_slicing` does not cover `str` indexing (`&s[i..j]`) or a
//! third-party `Index` impl, and `clippy::panic` does not see `assert!` or
//! `unreachable!`. There is no `&s[..]`, no `unreachable!` and no `assert!`
//! in this crate's production code; [`protocol::read_line`] slices through
//! `slice::get` and `Vec::as_slice` for exactly that reason.
//!
//! Test code is exempt by compilation unit (`cfg_attr(not(test), ...)`), not
//! by a path list -- see `bathy-probe`'s crate doc for the full reasoning.

pub mod privilege;
pub mod protocol;
pub mod syn;

pub use privilege::{
    PrivilegeError, PrivilegeState, RawSockets, UnprivilegedInput, acquire_raw_sockets,
    capabilities_are_dropped, drop_all_capabilities,
};
pub use protocol::{
    LineError, MAX_LINE_BYTES, PortState, RefusalReason, Request, Response, Session, SessionScope,
    read_line,
};
pub use syn::{PROBE_MARKER, Prober, Reply, Wire, check_session_scope, classify_reply};
