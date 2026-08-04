//! AC-7.15 — `interpret` throughput over the recorded replay corpus.
//!
//! A regression detector, not a marketing number. `interpret` is a pure
//! function over bytes somebody else controls, and it runs once per probe
//! capture on every open port of every scan, so a rule whose matcher becomes
//! quadratic in the response length is a scan that gets slower on exactly the
//! hosts that answer with the most data.
//!
//! The inputs are the committed captures in `testdata/captures/` — real
//! recorded responses, not synthetic strings. A throughput benchmark over
//! bytes no rule matches measures the rejection branch and calls it
//! throughput, which is the same mistake M7 Task 2 measured in a property-test
//! strategy that never reached the code it claimed to cover.
//!
//! The fixture shape is `tests/replay.rs`'s, for the reason stated there:
//! `bathy_types::ProbeCapture` is deliberately not `Deserialize` and its
//! `probe_id` is `&'static str`, so it is built by hand with the id resolved
//! against `known_probe_ids()`.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use bathy_interpret::{interpret, known_probe_ids};
use bathy_types::{ProbeCapture, Transport};
use criterion::{Criterion, criterion_group, criterion_main};

/// Compiled in rather than resolved from the working directory, so this runs
/// the same way under `cargo bench` from anywhere.
const CORPUS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/captures");

fn corpus() -> Vec<ProbeCapture> {
    let mut paths: Vec<_> = std::fs::read_dir(CORPUS_DIR)
        .expect("reading the capture corpus")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();

    let mut out = Vec::new();
    for path in paths {
        let text = std::fs::read_to_string(&path).expect("reading a capture");
        let value: serde_json::Value = serde_json::from_str(&text).expect("a capture is JSON");
        let capture = value["capture"].clone();
        let field = |name: &str| capture[name].as_str().map(str::to_owned);
        let id = field("probe_id").expect("a capture names a probe");
        let probe_id = known_probe_ids()
            .find(|known| *known == id)
            .unwrap_or_else(|| panic!("{}: unknown probe id {id}", path.display()));
        out.push(ProbeCapture {
            probe_id,
            transport: match field("transport").as_deref() {
                Some("udp") => Transport::Udp,
                _ => Transport::Tcp,
            },
            port: capture["port"].as_u64().unwrap_or(0) as u16,
            request: field("request").map(|r| BASE64.decode(r).expect("base64 request")),
            response: BASE64
                .decode(field("response").expect("a capture has a response"))
                .expect("base64 response"),
            elapsed_micros: capture["elapsed_micros"].as_u64().unwrap_or(0),
            truncated: capture["truncated"].as_bool().unwrap_or(false),
        });
    }
    assert!(
        !out.is_empty(),
        "the capture corpus is empty, so this benchmark would measure an empty loop"
    );
    out
}

fn bench(c: &mut Criterion) {
    let corpus = corpus();
    let bytes: u64 = corpus.iter().map(|c| c.response.len() as u64).sum();

    let mut group = c.benchmark_group("interpret");
    group.throughput(criterion::Throughput::Bytes(bytes));
    group.bench_function("whole_corpus", |b| {
        b.iter(|| {
            let mut produced = 0usize;
            for capture in &corpus {
                produced += std::hint::black_box(interpret(capture)).len();
            }
            produced
        })
    });

    // The single largest response on its own: the corpus average hides the
    // case that actually matters, a long HTTP body every HTTP rule scans.
    let largest = corpus
        .iter()
        .max_by_key(|c| c.response.len())
        .expect("non-empty");
    group.bench_function("largest_single_response", |b| {
        b.iter(|| std::hint::black_box(interpret(largest)).len())
    });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
