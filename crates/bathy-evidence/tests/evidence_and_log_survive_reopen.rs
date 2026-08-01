//! M2 milestone exit criterion (not tied to any single task's own AC list):
//! "An integration test writes evidence, appends an event referencing its
//! digest, closes everything, reopens, and reads both back intact."
//!
//! Exercises only `bathy-evidence`'s own public API (`EvidenceStore` +
//! `EventLog`) end to end, the way a real caller would: write the evidence
//! bytes first, then append an event whose `evidence_refs` cites the digest
//! that write produced -- the ordering this crate's own docs promise
//! (`evidence_refs` must never dangle) -- then drop every handle, reopen
//! fresh ones against the same directories, and confirm both the blob and
//! the event resolve to exactly what was written.

use bathy_evidence::{EventLog, EvidenceStore};
use bathy_types::clock::FixedClock;
use bathy_types::event::{EventBody, Target};
use bathy_types::ids::ScanId;
use bathy_types::nonempty::NonEmpty;

#[test]
fn evidence_and_its_referencing_event_survive_close_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let evidence_dir = dir.path().join("evidence");
    let events_dir = dir.path().join("events");
    let scan_id: ScanId = "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap();
    let clock = FixedClock::new("2026-08-01T15:04:31.182Z", 7).unwrap();
    let response_bytes = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n";

    let digest = {
        let evidence = EvidenceStore::open(&evidence_dir).unwrap();
        let digest = evidence.put(response_bytes).unwrap();

        let mut log = EventLog::open(&events_dir, scan_id).unwrap();
        log.append(
            EventBody::HostDiscovered {
                target: Target {
                    ip: "10.30.0.42".parse().unwrap(),
                },
                method: "icmp_echo".to_string(),
                evidence_refs: NonEmpty::new(digest),
            },
            &clock,
            "0.1.0",
        )
        .unwrap();

        digest
        // `evidence` and `log` both drop here -- "closes everything".
    };

    // Reopen fresh handles against the same directories, as a resumed scan
    // would after a process restart.
    let evidence = EvidenceStore::open(&evidence_dir).unwrap();
    let log = EventLog::open(&events_dir, scan_id).unwrap();

    assert_eq!(
        evidence.get(&digest).unwrap(),
        response_bytes,
        "evidence bytes must still verify against their digest after reopening"
    );

    let events = log.read_from(0).unwrap();
    assert_eq!(events.len(), 1);
    let EventBody::HostDiscovered { evidence_refs, .. } = &events[0].body else {
        panic!(
            "expected the host.discovered event written above, got {:?}",
            events[0].body
        );
    };
    assert_eq!(
        evidence_refs.as_slice(),
        &[digest],
        "the reopened event must still cite the same digest"
    );
    assert_eq!(
        evidence.get(evidence_refs.first()).unwrap(),
        response_bytes,
        "the digest an event references, after reopening both stores, must \
         still resolve to the exact bytes originally written -- the whole \
         point of writing evidence before the event that cites it"
    );
}
