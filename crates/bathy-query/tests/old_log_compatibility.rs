//! A log written before `rule_id` existed still loads, and still folds.
//!
//! # The defect this exists to stop recurring
//!
//! `bd386e9` added a required `rule_id` to `service.observed`. From that
//! commit, a log written by the *previous* commit failed to deserialize --
//! and because one unreadable line fails the whole read, the failure was
//! total rather than partial: four other events in a five-event log were
//! fine and none of them could be reached. `result query`, `result diff`,
//! `scan events` and the MCP `result.query` / `scan.events` tools all
//! answered `no_such_scan_log`. `scan.status` kept working, because it reads
//! SQLite -- so the *derived index* survived and the *source of truth* did
//! not, which is the exact inversion `README.md` and `bathy-evidence`'s
//! module docs say cannot happen.
//!
//! There was no mechanism of any kind behind the guarantee: no default, no
//! version branch, no migration, and -- the reason it went unnoticed for a
//! milestone -- no test that any older log loads at all. The whole premise of
//! content-addressed evidence is that a finding is replayable against a newer
//! rule set years later. A log written last week failing to load today
//! falsifies that premise, and nothing in the tree would have said so.
//!
//! # Why the fixture is a file and not a literal
//!
//! `tests/fixtures/pre-rule-id-scan.jsonl` is a log from a **real scan** --
//! real bound listener, real TCP connect, real captured nginx banner, driven
//! through the same `ScanPlan` -> `TaskStore` -> `GroupCommitLog` ->
//! `Scheduler` stack `real_log_fold.rs` drives -- with the single
//! `,"rule_id":"..."` member removed from its `service.observed` line. That
//! member was appended as the last field of the variant in `bd386e9`, and
//! serde emits struct fields in declaration order, so removing it reproduces
//! the pre-`bd386e9` bytes exactly rather than approximately.
//!
//! A hand-written literal would test this author's model of the old format.
//! The Global Constraint that a fixture must **exclude** what the code under
//! test is supposed to handle applies with full force here: the fixture
//! genuinely lacks the field, and
//! `the_fixture_genuinely_lacks_the_field_or_it_tests_nothing` fails if
//! anyone ever "fixes" it by adding one.

use bathy_evidence::EventLogReader;
use bathy_query::{Terminal, fold_events};
use bathy_types::event::{Endpoint, EventBody, PortState, Transport};
use bathy_types::ids::ScanId;

/// The bytes a build older than `bd386e9` wrote.
const PRE_RULE_ID_LOG: &str = include_str!("fixtures/pre-rule-id-scan.jsonl");

/// The scan the fixture records. Its `FixedClock` seed makes the id stable,
/// which is why it can be a constant rather than something parsed out.
const FIXTURE_SCAN: &str = "scan_00000000070000000000000000";

/// The nginx-serving port in the fixture. Ephemeral at capture time, fixed
/// forever now that the bytes are committed.
const SERVICE_PORT: u16 = 62325;
/// The silent open port in the fixture -- no `service.observed` for it, which
/// is what makes the fold's two rows distinguishable.
const SILENT_PORT: u16 = 62326;

fn tcp(port: u16) -> Endpoint {
    Endpoint {
        transport: Transport::Tcp,
        port,
    }
}

/// Lays the fixture down where an `EventLogReader` will find it.
fn open_fixture() -> (tempfile::TempDir, ScanId) {
    let dir = tempfile::tempdir().unwrap();
    let scan_id: ScanId = FIXTURE_SCAN.parse().unwrap();
    std::fs::write(dir.path().join(format!("{scan_id}.jsonl")), PRE_RULE_ID_LOG).unwrap();
    (dir, scan_id)
}

#[test]
fn the_fixture_genuinely_lacks_the_field_or_it_tests_nothing() {
    assert!(
        !PRE_RULE_ID_LOG.contains("rule_id"),
        "the fixture must be a log from before the field existed; a fixture that \
         carries `rule_id` exercises none of the compatibility path it is here for"
    );
    assert!(
        PRE_RULE_ID_LOG.contains("\"event_type\":\"service.observed\""),
        "fixture sanity: the record whose shape changed must actually be present"
    );
}

#[test]
fn a_log_written_before_rule_id_existed_still_reads_in_full() {
    let (dir, scan_id) = open_fixture();
    let reader = EventLogReader::open(dir.path(), scan_id).expect("the log must open");
    let events = reader.read_from(0).expect("every record must deserialize");

    // The old failure was total: one unreadable line took the whole scan
    // with it. Asserting the count, and the gap-free sequence, is what
    // distinguishes "reads" from "reads the parts that did not change".
    assert_eq!(
        events.len(),
        5,
        "every record in the log, not the readable ones"
    );
    assert_eq!(
        events.iter().map(|e| e.sequence).collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5]
    );
}

#[test]
fn the_record_that_lost_a_field_keeps_every_field_it_did_have() {
    let (dir, scan_id) = open_fixture();
    let events = EventLogReader::open(dir.path(), scan_id)
        .unwrap()
        .read_from(0)
        .unwrap();

    let observed = events
        .iter()
        .find_map(|e| match &e.body {
            EventBody::ServiceObserved {
                observation,
                probe_id,
                rule_id,
                endpoint,
                ..
            } => Some((observation, probe_id, rule_id, endpoint)),
            _ => None,
        })
        .expect("the fixture's service.observed must be reachable");

    let (observation, probe_id, rule_id, endpoint) = observed;
    assert_eq!(endpoint.port, SERVICE_PORT);
    assert_eq!(observation.service, "http");
    assert_eq!(observation.product.as_deref(), Some("nginx"));
    assert_eq!(observation.version.as_deref(), Some("1.26.0"));
    assert_eq!(probe_id, "http-get-v1", "probe_id was never optional");
    assert_eq!(
        *rule_id, None,
        "absent means unattributed -- the build that wrote this record did not \
         record which rule decided, and nothing may invent one"
    );
}

#[test]
fn folding_an_old_log_answers_everything_it_can_and_claims_no_rule() {
    let (dir, scan_id) = open_fixture();
    let events = EventLogReader::open(dir.path(), scan_id)
        .unwrap()
        .read_from(0)
        .unwrap();
    let fold = fold_events(&events);

    assert_eq!(
        fold.terminal,
        Some(Terminal::Completed {
            probes_sent: 2,
            packets_spent: 7,
            findings: 2,
        })
    );
    assert_eq!(fold.endpoints.len(), 2, "both endpoints, not just the one");

    let service = &fold.endpoints[&("127.0.0.1".parse().unwrap(), tcp(SERVICE_PORT))];
    assert_eq!(service.state, Some(PortState::Open));
    assert_eq!(service.observation.as_ref().unwrap().service, "http");
    assert_eq!(service.probe_id.as_deref(), Some("http-get-v1"));
    assert_eq!(
        service.rule_id, None,
        "an unattributed record folds to a null rule, which is the same answer \
         the fold already gives for an endpoint nothing identified -- not a new \
         third state every consumer has to learn"
    );
    assert_eq!(
        service.evidence_refs.len(),
        1,
        "the evidence a pre-rule-id finding cited is still reachable, which is the \
         point of being able to read the log at all"
    );

    let silent = &fold.endpoints[&("127.0.0.1".parse().unwrap(), tcp(SILENT_PORT))];
    assert_eq!(silent.state, Some(PortState::Open));
    assert!(silent.observation.is_none());
}

#[test]
fn reading_an_old_record_and_writing_it_back_invents_nothing() {
    // `skip_serializing_if` rather than a defaulted `String`: a defaulted
    // `String` would round-trip this line into one carrying `"rule_id":""`,
    // a value its writer never wrote. An append-only evidence log whose
    // records change shape when they pass through a reader is not
    // content-addressed evidence.
    let line = PRE_RULE_ID_LOG
        .lines()
        .find(|l| l.contains("service.observed"))
        .unwrap();
    let event: bathy_types::event::Event = serde_json::from_str(line).unwrap();
    assert_eq!(
        serde_json::to_string(&event).unwrap(),
        line,
        "an old record must survive a read-write round trip byte for byte"
    );
}
