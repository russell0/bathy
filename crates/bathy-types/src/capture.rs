use crate::event::Transport;

/// A probe's raw, uninterpreted result: the unit of evidence this whole
/// milestone is built around.
///
/// `ProbeCapture` is stored verbatim -- exactly the bytes a peer sent, never
/// a parsed or summarized form -- and is the *sole* input to interpretation
/// (`bathy-interpret`, M4 Task 3). That is what makes a finding replayable
/// years later against a newer rule set: re-running interpretation over a
/// stored `ProbeCapture` must reproduce the original finding exactly,
/// without a network, because nothing besides these bytes fed the decision
/// in the first place.
///
/// # Why this type lives in `bathy-types`, not `bathy-probe`
///
/// `ProbeCapture` is produced by `bathy-probe` (M4 Task 1), but it belongs
/// to the contract layer for two independent reasons, either of which
/// would be sufficient on its own:
///
/// 1. **It is evidence an agent can ask for.** M5's `evidence.get` surfaces
///    stored evidence back out over MCP the same way `bathy-types::event`
///    types already are the wire contract for everything else a scan
///    reports (`service.observed`, etc.). Putting the evidence *shape* in
///    the same crate as the rest of the public contract keeps that
///    boundary in one place instead of split across a contract crate and a
///    probing crate that happens to also define a wire type.
/// 2. **`bathy-interpret` must be able to consume it without depending on
///    `bathy-probe`.** `bathy-interpret` is pure -- no I/O, no clock, no
///    async runtime (M4's binding carry-forward #3) -- and sits *below*
///    `bathy-probe` in this workspace's layer order (`xtask`'s `LAYERS`:
///    `bathy-types, ..., bathy-interpret, bathy-probe, ...`), specifically
///    so its replay tests and fuzz targets can construct a `ProbeCapture`
///    by hand from a stored fixture and feed it straight to the
///    interpretation rules, with no socket anywhere in the dependency
///    graph. If `ProbeCapture` were defined in `bathy-probe` instead,
///    `bathy-interpret` could not even *name* the type it interprets
///    without an upward, layer-order-violating dependency -- `bathy-types`
///    is the one crate every other layer may depend on, which is exactly
///    what a type shared by both a producer above the interpreter and the
///    interpreter itself needs.
///
/// Deliberately **not** `Serialize`/`Deserialize`/`JsonSchema` here, unlike
/// most of this crate's other public types: nothing in M4 Task 1 puts this
/// type on the wire or asks `xtask check-schemas` to track it (that check
/// covers exactly the four types named in `schema::all()`'s own doc
/// comment, closing AC-1.22 -- `ProbeCapture` is not one of them). Evidence
/// storage (`bathy-evidence`, extended for M4) and `evidence.get` (M5) are
/// later tasks' work to wire a wire/storage representation through; adding
/// derives speculatively now, ungoverned by any schema test, would be the
/// same "promise nobody is checking" shape this codebase has repeatedly
/// found and removed elsewhere.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeCapture {
    /// Stable and versioned, e.g. `tls-v1`. Recorded on every
    /// `service.observed` event so a finding can be traced back to the
    /// exact probe (and exact version of its behavior) that produced it.
    pub probe_id: &'static str,
    /// The transport the probe spoke over. Every M4 probe is TCP-only (see
    /// `bathy_probe::framework::ProbeIo`'s own doc comment), but the field
    /// is carried here -- rather than assumed -- because `ProbeCapture` is
    /// evidence: an `Endpoint` (`transport` + `port`, `bathy_types::event`)
    /// is what a `service.observed` event ultimately keys evidence to, and
    /// evidence that cannot itself say which transport it came from would
    /// force a reader to assume the answer instead of being told it.
    pub transport: Transport,
    pub port: u16,
    /// Bytes we sent, if any. `None` for listen-first protocols that never
    /// speak before the peer does.
    pub request: Option<Vec<u8>>,
    pub response: Vec<u8>,
    pub elapsed_micros: u64,
    /// `true` when `response` may not be the peer's whole reply: either the
    /// read cap was reached while more bytes were still available, or the
    /// probe's deadline elapsed before the peer signaled EOF. `false` means
    /// the peer closed the connection on its own before either bound was
    /// hit, so `response` is believed complete. See
    /// `bathy_probe::framework::ProbeIo::read_bounded` for exactly how this
    /// is decided -- including how it avoids the false positive of a peer
    /// that sends *precisely* the cap's worth of bytes and then closes
    /// cleanly, which is not truncation.
    pub truncated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ProbeCapture {
        ProbeCapture {
            probe_id: "tls-v1",
            transport: Transport::Tcp,
            port: 443,
            request: Some(vec![1, 2, 3]),
            response: vec![4, 5, 6],
            elapsed_micros: 1234,
            truncated: false,
        }
    }

    #[test]
    fn is_plain_data_with_value_equality() {
        // No hidden identity/interior state: two captures built from the
        // same field values compare equal, and changing any one field
        // breaks that equality. This is what lets a stored capture be
        // compared byte-for-byte against a freshly replayed one in M4
        // Task 4's replay harness.
        let a = sample();
        let b = sample();
        assert_eq!(a, b);

        let mut c = sample();
        c.truncated = true;
        assert_ne!(a, c);

        let mut d = sample();
        d.response = vec![9];
        assert_ne!(a, d);
    }

    #[test]
    fn request_is_none_for_listen_first_style_captures() {
        let mut c = sample();
        c.request = None;
        assert!(c.request.is_none());
    }
}
