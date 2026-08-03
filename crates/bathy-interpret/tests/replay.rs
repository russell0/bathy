//! The reproducibility claim, made testable.
//!
//! `bathy-interpret` is pure (see `src/lib.rs`'s module doc comment): no
//! I/O, no clock, no randomness, no async runtime, ever, anywhere in this
//! crate's own code. That buys exactly one thing, and this file is it: a
//! regression suite that replays a committed corpus of recorded
//! `ProbeCapture`s -- real bytes from real containers, or clearly labelled
//! synthetic edge cases -- through `interpret` and snapshot-compares the
//! result, entirely offline. Every future rule change is checked against
//! every service this project has ever seen, in milliseconds, with no
//! network involved at all (AC-4.17); a snapshot diff, not a silent
//! behavior change, is what a future contributor sees if a rule edit
//! changes what an existing capture resolves to (AC-4.19).
//!
//! # Fixture shape and provenance (AC-4.18)
//!
//! Each file under `testdata/captures/*.json` is a `{"captured_from": ...,
//! "capture": {...}}` object. `captured_from` states, in full, either the
//! exact lab image and digest a capture came from (`REAL CAPTURE: ...`,
//! matching M4 Task 2's own corroborated images/digests) or why a fixture is
//! `SYNTHETIC` -- a deliberately hand-built pathological or edge-case input,
//! never passed off as something a container actually said. See
//! `.superpowers/sdd/2026-07-31-bathy-m4-probes-interpret/task-4-report.md`
//! for the full provenance table and the commands used to capture each real
//! fixture (a plain Python `socket` script; `nmap` and
//! `nmap-service-probes`, both present on this development machine, were
//! never opened or run for this task).
//!
//! # Why this file defines its own fixture-only types (a brief defect, fixed)
//!
//! `bathy_types::ProbeCapture` is deliberately **not** `Deserialize`
//! (`crates/bathy-types/src/capture.rs`'s own doc comment: nothing in M4
//! puts it on the wire, so adding derives ungoverned by `xtask
//! check-schemas` would be a promise nobody is checking) and its `probe_id`
//! field is `&'static str`, not an owned `String` -- serde cannot populate a
//! `&'static str` from an arbitrary JSON document at all. This task's own
//! brief sketch (`task-4-brief.md`, Step 1) calls
//! `serde_json::from_str::<Fixture>` directly into a struct containing a raw
//! `ProbeCapture`; taken literally, that does not compile. It also omits a
//! required field: `ProbeCapture::transport` has no default and the brief's
//! own worked JSON example never sets it. Both are fixed here, not
//! papered over: [`FixtureCapture`] is a small, `Deserialize`-only shape
//! local to this test binary (owned `String`s, a base64-encoded
//! `request`/`response`, an explicit `"transport": "tcp"` on every
//! fixture), and [`to_probe_capture`] builds a real `ProbeCapture` from it
//! by hand -- resolving `probe_id` against
//! [`bathy_interpret::known_probe_ids`] rather than leaking a `String`,
//! which is also exactly the AC-4.18-adjacent "every probe_id must be one
//! the registry knows" check this file's own data-quality tests need.
//!
//! # Why this crate does not depend on `bathy-probe`, even here
//!
//! `bathy-probe`'s `ProbeRegistry` would be a *more* obvious source of
//! truth for "every real probe id" than this crate's own rule table. It is
//! deliberately not used: `bathy-interpret` sits *below* `bathy-probe` in
//! the workspace's layer order (`xtask`'s `LAYERS`), specifically so its
//! tests and fuzz targets need no upward dependency at all (see
//! `src/lib.rs`) -- and `xtask check-deps` enforces that boundary against a
//! package's dev-dependencies too, not only its normal ones. This test
//! binary's `known_probe_ids()` check therefore validates against this
//! crate's *own* rule registry (`bathy_interpret::known_probe_ids`, backed
//! by `rules::ALL_RULES`), which is in any case the only registry
//! `interpret` itself ever actually consults.

use std::collections::{BTreeMap, HashSet};
use std::ops::Range;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use bathy_interpret::{Interpretation, interpret, known_probe_ids};
use bathy_types::{ProbeCapture, Transport};
use serde::{Deserialize, Serialize};

const CORPUS_DIR: &str = "../../testdata/captures";

// --- Fixture deserialization (dev-only shape; see this file's module doc
// comment for why `ProbeCapture` itself cannot be deserialized directly). ---

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    captured_from: String,
    capture: FixtureCapture,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCapture {
    probe_id: String,
    transport: String,
    port: u16,
    request: Option<String>,
    response: String,
    elapsed_micros: u64,
    truncated: bool,
}

/// Builds a real `ProbeCapture` from a fixture's on-disk shape.
///
/// Panics (deliberately -- a fixture that fails to decode is a corpus
/// defect, and this is the corpus's own regression suite) on invalid
/// base64, an unrecognized `transport` string, or a `probe_id` this crate
/// has no rules for at all. `every_fixture_decodes_and_names_a_probe_id_the_registry_knows`
/// below turns that panic into a named, per-fixture test failure instead of
/// an opaque one from deep inside the main replay loop.
fn to_probe_capture(name: &str, fc: &FixtureCapture) -> ProbeCapture {
    let probe_id = known_probe_ids()
        .find(|&id| id == fc.probe_id)
        .unwrap_or_else(|| {
            panic!(
                "{name}: fixture names probe_id {:?}, which bathy-interpret has no rules for; \
             known ids: {:?}",
                fc.probe_id,
                known_probe_ids().collect::<Vec<_>>()
            )
        });
    let transport = match fc.transport.as_str() {
        "tcp" => Transport::Tcp,
        "udp" => Transport::Udp,
        other => panic!("{name}: unrecognized transport {other:?}, expected \"tcp\" or \"udp\""),
    };
    let request = fc.request.as_deref().map(|b64| {
        BASE64
            .decode(b64)
            .unwrap_or_else(|e| panic!("{name}: request is not valid base64: {e}"))
    });
    let response = BASE64
        .decode(&fc.response)
        .unwrap_or_else(|e| panic!("{name}: response is not valid base64: {e}"));
    ProbeCapture {
        probe_id,
        transport,
        port: fc.port,
        request,
        response,
        elapsed_micros: fc.elapsed_micros,
        truncated: fc.truncated,
    }
}

/// Every fixture under `testdata/captures/*.json`, sorted by filename for a
/// deterministic iteration order (snapshot naming is per-fixture and
/// order-independent either way, but a stable order makes this suite's own
/// output reproducible to read, and is what
/// `replaying_the_corpus_twice_gives_identical_results` and the mutation
/// exercise in the task report were run against).
fn load_corpus() -> Vec<(String, Fixture)> {
    let mut entries: Vec<(String, Fixture)> = std::fs::read_dir(CORPUS_DIR)
        .unwrap_or_else(|e| panic!("corpus directory {CORPUS_DIR} must exist: {e}"))
        .map(|entry| entry.expect("readable directory entry").path())
        .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("json"))
        .map(|path| {
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .expect("utf8 fixture filename")
                .to_string();
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            let fixture: Fixture = serde_json::from_str(&text)
                .unwrap_or_else(|e| panic!("{}: invalid fixture JSON: {e}", path.display()));
            (name, fixture)
        })
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
}

// --- Snapshot shape: `Interpretation` is deliberately not `Serialize` (see
// this crate's `src/lib.rs` -- adding a `serde` derive to a *public* type
// would pull `serde` into this crate's normal dependency tree, breaking the
// "exactly `bathy-types` and `regex`" purity claim AC-4.10 checks). This is
// a small, local, dev-only mirror built purely for snapshotting. ---

#[derive(Serialize)]
struct SnapshotSpan {
    start: usize,
    end: usize,
}

#[derive(Serialize)]
struct SnapshotInterpretation {
    service: String,
    product: Option<String>,
    version: Option<String>,
    confidence: f64,
    rule_id: &'static str,
    matched_span: SnapshotSpan,
    /// The actual bytes `matched_span` points at, hex-encoded -- so a
    /// snapshot reviewer can see *what* justified the claim, not just the
    /// offsets, and so a mutation that shifts `matched_span` without
    /// changing `.version`/`.product` (the same class of bug
    /// `crates/bathy-interpret/src/rules.rs`'s own unit tests guard against
    /// per-rule) is visible in the snapshot diff too.
    matched_bytes_hex: String,
    rationale: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn to_snapshot(response: &[u8], i: &Interpretation) -> SnapshotInterpretation {
    let Range { start, end } = i.matched_span.clone();
    SnapshotInterpretation {
        service: i.observation.service.clone(),
        product: i.observation.product.clone(),
        version: i.observation.version.clone(),
        confidence: i.observation.confidence.get(),
        rule_id: i.rule_id,
        matched_span: SnapshotSpan { start, end },
        matched_bytes_hex: hex(&response[start..end]),
        rationale: i.rationale.clone(),
    }
}

// --- From the brief (Step 1), fixed per this file's module doc comment. ---

/// The regression guard this whole task exists for: every recorded capture
/// replays, offline, to the same findings every time -- and a rule change
/// that alters an existing finding shows up as a snapshot diff naming
/// exactly which fixture and which field changed (AC-4.17, AC-4.19).
///
/// See this task's report for a real, reverted demonstration: temporarily
/// widening `http.protocol.bare.v1`'s confidence rung produced a visible
/// diff on every HTTP fixture's snapshot, not a silent pass.
#[test]
fn every_recorded_capture_reproduces_its_expected_findings() {
    let mut checked = 0;
    for (name, fixture) in load_corpus() {
        let capture = to_probe_capture(&name, &fixture.capture);
        let got = interpret(&capture);
        let snapshot: Vec<SnapshotInterpretation> = got
            .iter()
            .map(|i| to_snapshot(&capture.response, i))
            .collect();
        insta::assert_json_snapshot!(name.as_str(), snapshot);
        checked += 1;
    }
    assert!(
        checked >= 16,
        "corpus must cover at least 16 captures, found {checked}"
    );
}

/// AC-4.17's "no network" replay is exercised twice per fixture here: same
/// bytes in, byte-identical `Vec<Interpretation>` out (`Interpretation`
/// derives `PartialEq`), which is what makes this a *replay* corpus and not
/// just a one-shot snapshot.
#[test]
fn replaying_the_corpus_twice_gives_identical_results() {
    for (name, fixture) in load_corpus() {
        let capture = to_probe_capture(&name, &fixture.capture);
        assert_eq!(
            interpret(&capture),
            interpret(&capture),
            "{name}: two calls to interpret() on the same capture must be byte-identical"
        );
    }
}

// --- "The corpus is data, so test the data" (verification beyond the
// brief). ---

/// Every fixture must actually decode (valid JSON, valid base64, a
/// recognized `transport`) and must name a `probe_id`
/// [`bathy_interpret::known_probe_ids`] actually has rules for -- a corpus
/// entry for an id the interpreter can never match against would silently
/// contribute nothing to coverage while still counting toward the `>= 16`
/// total, which would be a corpus defect this suite itself should catch.
#[test]
fn every_fixture_decodes_and_names_a_probe_id_the_registry_knows() {
    let known: HashSet<&str> = known_probe_ids().collect();
    let mut checked = 0;
    for (name, fixture) in load_corpus() {
        assert!(
            known.contains(fixture.capture.probe_id.as_str()),
            "{name}: probe_id {:?} is not one bathy-interpret has rules for; known ids: {known:?}",
            fixture.capture.probe_id
        );
        // Decoding itself (base64, transport) must not panic -- exercised
        // directly here rather than only incidentally via the other tests,
        // so a fixture-decode failure is attributed to this test by name.
        let _ = to_probe_capture(&name, &fixture.capture);
        checked += 1;
    }
    assert!(checked >= 16);
}

/// AC-4.18's "at least two per probe" made a real assertion, not just an
/// eyeball count over `testdata/captures/`'s file list.
#[test]
fn corpus_covers_every_known_probe_id_at_least_twice() {
    let mut counts: BTreeMap<&'static str, usize> =
        known_probe_ids().map(|id| (id, 0usize)).collect();
    for (name, fixture) in load_corpus() {
        let capture = to_probe_capture(&name, &fixture.capture);
        *counts.get_mut(capture.probe_id).expect("validated above") += 1;
    }
    for (probe_id, n) in &counts {
        assert!(
            *n >= 2,
            "probe {probe_id} has only {n} corpus fixture(s), need at least 2 \
             (one that matches with a version, one that matches weakly or not at all)"
        );
    }
}

/// A capture's `response` must be non-empty, unless the fixture deliberately
/// documents itself as an empty-response case in `captured_from`. No
/// fixture in this corpus currently needs the exemption -- every real M4
/// probe's own `execute()` returns `Err(ProbeError::EmptyResponse)` rather
/// than ever producing a `ProbeCapture` with an empty `response` at all
/// (`crates/bathy-probe/src/probes/*.rs`, every probe), so a *genuine*
/// empty-response `ProbeCapture` cannot arise from any real probe run --
/// this check exists for a future synthetic fixture that wants to exercise
/// one anyway (e.g. a stored capture reconstructed from an older schema),
/// not because one exists in the corpus today.
#[test]
fn every_fixture_response_is_non_empty_unless_labelled_as_a_deliberate_empty_case() {
    const LABEL: &str = "empty response";
    for (name, fixture) in load_corpus() {
        let capture = to_probe_capture(&name, &fixture.capture);
        let labelled_empty = fixture.captured_from.to_lowercase().contains(LABEL);
        if !labelled_empty {
            assert!(
                !capture.response.is_empty(),
                "{name}: response is empty but captured_from does not contain {LABEL:?}"
            );
        }
    }
}

/// Belt-and-suspenders alongside `crates/bathy-interpret/src/interpret.rs`'s
/// own property test of the same fact over arbitrary bytes: every span
/// `interpret` produces against this corpus's *real* captured bytes is
/// actually a valid range into the response it came from.
#[test]
fn every_matched_span_in_the_corpus_is_a_valid_range_into_its_own_response() {
    for (name, fixture) in load_corpus() {
        let capture = to_probe_capture(&name, &fixture.capture);
        for i in interpret(&capture) {
            assert!(
                i.matched_span.start <= i.matched_span.end,
                "{name}: {}",
                i.rule_id
            );
            assert!(
                i.matched_span.end <= capture.response.len(),
                "{name}: {} span runs past the end of the response",
                i.rule_id
            );
        }
    }
}
