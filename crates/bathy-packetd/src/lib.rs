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
//! # `#![forbid(unsafe_code)]`, for now
//!
//! The Global Constraint permits `unsafe` in this crate *and only for raw
//! socket syscalls*. Task 2 of M6 introduces the sockets and with them the
//! allowance. Until there is a syscall to make, the forbid stays on, because
//! "the crate that is allowed unsafe" and "the crate that uses unsafe" should
//! not be the same sentence a milestone earlier than necessary. When it comes
//! off, every block carries a `SAFETY:` comment (AC-6.7) and this paragraph
//! says so instead.
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

pub mod protocol;

pub use protocol::{
    LineError, MAX_LINE_BYTES, PortState, RefusalReason, Request, Response, Session, read_line,
};
