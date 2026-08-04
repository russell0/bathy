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

/// Resolved against this crate's own manifest directory, not the process's
/// current working directory (M4 whole-branch review, MINOR-2). The plan's
/// own AC-4.17 exit criterion runs this test binary *directly* --
/// `sandbox-exec -f deny-network.sb <path-to-compiled-replay-test-binary>`
/// -- rather than through `cargo test`, and `cargo test` is the only thing
/// that sets the cwd to the package root. Run as documented from the
/// workspace root, the previous cwd-relative `../../testdata/captures`
/// resolved to a path outside the repository and every one of these six
/// tests failed on a missing corpus directory. `CARGO_MANIFEST_DIR` is set
/// at compile time by Cargo for both invocations, so the binary carries its
/// own absolute corpus path and the documented command is correct as
/// written, from anywhere.
const CORPUS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/captures");

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

// --- AC-4.18: fixture provenance, made structural (M4 whole-branch
// review, IMPORTANT-2).
//
// `captured_from` is a required `String`, so a *missing* field already
// fails deserialization. An EMPTY one did not: blanking a real capture's
// entire provenance record -- image, digest, capture method, all of it --
// passed the whole suite. That is the evidentiary basis of this project's
// clean-room claim (see `README.md`'s "Clean room" section), which is a
// legal position, not a style preference, and it rested entirely on
// authorship discipline with no structural guard at all.
//
// The corpus content itself was already exemplary and needed no change:
// eight real captures each naming a full image and digest, nine clearly
// labelled `SYNTHETIC (not a container capture)` with stated reasoning, and
// not one fixture pretending to be something it is not. What follows makes
// that discipline enforced rather than merely observed.
//
// Deliberately a CLOSED vocabulary of exactly two prefixes rather than a
// "non-empty" check. Non-empty alone would accept `"x"`, or a plausible
// paragraph of prose that names no image at all -- and the failure mode
// being guarded against is not a blank field, it is a field that reads
// convincingly while sourcing nothing. Requiring every fixture to declare
// which of the two kinds it is forces the question to be answered.
//
// The nine synthetic fixtures are legitimate and must keep passing. Their
// existence is why AC-4.18's own plan text ("**Each** fixture records the
// lab image and digest it was captured from") is unsatisfiable as written
// -- a negative or no-match case has no container to have come from, and
// labelling it honestly is strictly better than manufacturing a digest for
// it. That is a plan defect, recorded as MINOR-4 for the controller; the
// implementation's call was the right one and is what is asserted here.

const REAL_PREFIX: &str = "REAL CAPTURE:";
const SYNTHETIC_PREFIX: &str = "SYNTHETIC";

/// Whether `s` contains a syntactically complete OCI content digest: the
/// literal `sha256:` followed by exactly 64 lowercase hex characters.
///
/// Written out by hand rather than with a regex on purpose -- `regex` is
/// this crate's one non-`bathy-types` *normal* dependency and the subject
/// of AC-4.10's purity claim; a dev-only need is not a reason to reach for
/// it here. The length check is what makes this more than a substring
/// search: `"sha256:"` alone, or a truncated digest, does not identify an
/// image and must not pass for provenance.
fn names_a_sha256_digest(s: &str) -> bool {
    s.match_indices("sha256:").any(|(i, _)| {
        let rest = &s[i + "sha256:".len()..];
        rest.len() >= 64
            && rest[..64]
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    })
}

/// AC-4.18. Every fixture declares which kind it is, and a fixture claiming
/// to be a real container capture names the digest that claim rests on.
#[test]
fn every_fixture_states_its_provenance_and_every_real_capture_names_an_image_digest() {
    let (mut real, mut synthetic) = (0usize, 0usize);
    for (name, fixture) in load_corpus() {
        let from = fixture.captured_from.trim();
        assert!(
            !from.is_empty(),
            "{name}: captured_from is empty. Every fixture must record where its bytes \
             came from -- either {REAL_PREFIX:?} with the lab image and its digest, or \
             {SYNTHETIC_PREFIX:?} with the reason the bytes were hand-built. This is \
             the evidentiary basis of the clean-room claim in README.md."
        );
        if let Some(detail) = from.strip_prefix(REAL_PREFIX) {
            real += 1;
            assert!(
                names_a_sha256_digest(from),
                "{name}: captured_from claims {REAL_PREFIX:?} but names no complete \
                 image digest (`sha256:` followed by 64 hex characters). A real capture \
                 must be reproducible from the exact image it came from, not merely \
                 asserted to exist. Got: {from:?}"
            );
            assert!(
                detail
                    .trim_start()
                    .split_whitespace()
                    .next()
                    .is_some_and(|w| { !w.starts_with("sha256:") && !w.starts_with("digest") }),
                "{name}: captured_from names a digest but no image reference before it. \
                 Record both, e.g. `REAL CAPTURE: docker.io/library/nginx:1.27-alpine, \
                 digest sha256:...`. Got: {from:?}"
            );
        } else if from.starts_with(SYNTHETIC_PREFIX) {
            synthetic += 1;
            assert!(
                from.len() > SYNTHETIC_PREFIX.len() + 20,
                "{name}: captured_from is labelled {SYNTHETIC_PREFIX:?} but states no \
                 reason. A hand-built fixture must say what it is built to exercise and \
                 why no container produced it. Got: {from:?}"
            );
            assert!(
                !names_a_sha256_digest(from),
                "{name}: captured_from is labelled {SYNTHETIC_PREFIX:?} yet names an \
                 image digest. Synthetic bytes did not come from that image; either \
                 the label is wrong or the digest is fabricated provenance. Got: {from:?}"
            );
        } else {
            panic!(
                "{name}: captured_from starts with neither {REAL_PREFIX:?} nor \
                 {SYNTHETIC_PREFIX:?}, so nothing here can tell whether these bytes came \
                 off a real wire or were written by hand -- which is the one thing this \
                 field exists to say. Got: {from:?}"
            );
        }
    }
    // Both arms must actually have been taken, or the assertions above are
    // checking a category the corpus no longer contains.
    assert!(
        real >= 8,
        "expected at least the eight real container captures M4 Task 2 recorded, found {real}"
    );
    assert!(
        synthetic >= 1,
        "expected at least one clearly-labelled synthetic fixture, found {synthetic}"
    );
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
