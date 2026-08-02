//! Group commit: amortizing [`EventLog::append`]'s durability barrier across
//! a bounded batch instead of paying one `fsync` per event.
//!
//! Decided in M2 (`docs/superpowers/plans/2026-07-31-bathy-m2-evidence-state.md`,
//! "Durability contract"), implemented here in M3 because
//! [`crate::scheduler::Scheduler`] is the first caller that actually drives
//! `EventLog::append` in a hot loop. The M2 fix-wave measured a per-event
//! `fsync` (`EventLog::open`'s default, durable constructor) at **~5.28
//! ms/op, ~2281x** the non-durable path (`crates/bathy-evidence/examples/fsync_bench.rs`).
//! At the workspace's 1,000,000-packet budget ceiling, with one `port.state`
//! event per probed unit, that is **~88 minutes of pure `fsync` latency**
//! serialized into a single scan -- two to three orders of magnitude above
//! the network I/O it is meant to be recording. Wiring [`Scheduler`](crate::scheduler::Scheduler)
//! to [`EventLog::open`]'s per-event-syncing `append` directly is therefore
//! not viable at M3 scale; [`GroupCommitLog`] is the fix.
//!
//! # Design
//!
//! [`GroupCommitLog`] wraps an [`EventLog`] opened via
//! [`EventLog::open_without_durability_barrier`] (so `append` itself never
//! pays a per-event `fsync`) and calls [`EventLog::sync`] on a bounded
//! trigger: whichever of [`GroupCommitConfig::max_events`] appends or
//! [`GroupCommitConfig::max_interval`] elapsed comes first. A terminal event
//! (`scan.completed`, `scan.failed`, `policy.denied`) forces an immediate
//! sync regardless of either trigger, via [`is_terminal`].
//!
//! # Crash contract
//!
//! **A crash loses at most the last `max_events` events or `max_interval`
//! of buffered appends -- never a partially-written record.** Every
//! individual [`EventLog::append`] call fully writes and newline-terminates
//! its record before returning (see that method's own doc comment); group
//! commit only defers *when* the OS is asked to flush that write to durable
//! storage, never *whether* a write lands cleanly. A record is therefore
//! either durable after the next sync trigger, or entirely absent from a
//! post-crash read of the log -- there is no "half a JSON object" state to
//! observe.
//!
//! # Do not invert the asymmetry
//!
//! `EvidenceStore::put` (`bathy-evidence`, M4 territory) syncs per-put; this
//! type batches. That ordering -- evidence durability always leads event
//! durability -- is what lets a crash orphan a blob (harmless: nothing
//! references it yet) but never leaves a dangling `evidence_refs` entry
//! (the failure the M2 durability contract exists to prevent). Never batch
//! `EvidenceStore::put` the way this type batches `EventLog::append`.

use std::path::Path;

use tokio::time::{Duration, Instant};

use bathy_evidence::{EventLog, LogError};
use bathy_types::clock::Clock;
use bathy_types::event::{Event, EventBody};
use bathy_types::ids::ScanId;

/// The bounded group-commit trigger: `sync_data()` runs whenever
/// `max_events` appends have accumulated since the last sync, or
/// `max_interval` has elapsed since the last sync, whichever comes first.
///
/// Both are configurable, both have defaults (see [`Default`]), per the M2
/// durability contract's explicit requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupCommitConfig {
    pub max_events: u64,
    pub max_interval: Duration,
}

/// `max_events = 200`, `max_interval = 200ms`.
///
/// At the workspace's 1,000,000-packet budget ceiling (one `port.state`
/// event per probed unit), `max_events = 200` amortizes the ~5.28ms `fsync`
/// measured in M2 to one sync per 200 events: 1,000,000 / 200 = 5,000 syncs,
/// each ~5.28ms, totals **~26.4 seconds** of `fsync` latency, down from ~88
/// minutes for the per-event path -- see this task's report for the
/// measured (not just projected) throughput before and after. `max_interval
/// = 200ms` bounds staleness on a slow or bursty scan (a low port-count
/// target, or one gated hard by the rate limiter) that would otherwise
/// never accumulate 200 events between syncs: no scan's on-disk log lags
/// live state by more than a fifth of a second, durability-wise, regardless
/// of throughput.
impl Default for GroupCommitConfig {
    fn default() -> Self {
        Self {
            max_events: 200,
            max_interval: Duration::from_millis(200),
        }
    }
}

/// Whether `body` is one of the three terminal event kinds the M2 durability
/// contract requires an immediate sync for, regardless of either trigger.
fn is_terminal(body: &EventBody) -> bool {
    matches!(
        body,
        EventBody::ScanCompleted { .. }
            | EventBody::ScanFailed { .. }
            | EventBody::PolicyDenied { .. }
    )
}

/// See the module doc comment for the full design and crash contract.
pub struct GroupCommitLog {
    log: EventLog,
    config: GroupCommitConfig,
    pending: u64,
    last_sync: Instant,
}

impl GroupCommitLog {
    /// Opens `scan_id`'s log via [`EventLog::open_without_durability_barrier`]
    /// -- `append` on the returned handle never pays a per-event `fsync`;
    /// this type's own bounded trigger (`config`) is what makes prior
    /// appends durable instead.
    pub fn open(dir: &Path, scan_id: ScanId, config: GroupCommitConfig) -> Result<Self, LogError> {
        let log = EventLog::open_without_durability_barrier(dir, scan_id)?;
        Ok(Self {
            log,
            config,
            pending: 0,
            last_sync: Instant::now(),
        })
    }

    pub fn scan_id(&self) -> ScanId {
        self.log.scan_id()
    }

    pub fn last_sequence(&self) -> u64 {
        self.log.last_sequence()
    }

    pub fn read_from(&self, after_sequence: u64) -> Result<Vec<Event>, LogError> {
        self.log.read_from(after_sequence)
    }

    /// The real, syscall-level ground truth for how many `fsync`s this log
    /// has actually issued -- see `EventLog::sync_calls`'s own doc comment.
    /// This is what a test proving group commit's batching actually works
    /// must assert on (M3 Task 7 fix round 1, IMPORTANT-1): the internal
    /// `pending`/trigger bookkeeping this type does on top is unaffected by
    /// whether the wrapped log happens to also be durable underneath, so it
    /// cannot, on its own, distinguish "batching genuinely reduced syscalls"
    /// from "the wrapped log was secretly durable all along."
    pub fn sync_calls(&self) -> u64 {
        self.log.sync_calls()
    }

    /// Appends one record, then syncs if the bounded trigger has fired:
    /// `pending` reaching `config.max_events`, `config.max_interval` having
    /// elapsed since the last sync, or `body` being a terminal event kind
    /// (see [`is_terminal`]) -- checked in that order, so a terminal event
    /// always syncs even if it happens to also be the event that crosses
    /// one of the other two thresholds.
    pub fn append(
        &mut self,
        body: EventBody,
        clock: &dyn Clock,
        engine_version: &str,
    ) -> Result<Event, LogError> {
        let terminal = is_terminal(&body);
        let event = self.log.append(body, clock, engine_version)?;
        self.pending += 1;
        if terminal
            || self.pending >= self.config.max_events
            || self.last_sync.elapsed() >= self.config.max_interval
        {
            self.log.sync()?;
            self.pending = 0;
            self.last_sync = Instant::now();
        }
        Ok(event)
    }

    /// Forces a sync outside of `append`'s own trigger.
    ///
    /// [`Scheduler::run`](crate::scheduler::Scheduler::run) calls this
    /// unconditionally once, right before returning, regardless of why the
    /// scan stopped. Three of its four outcomes (plan exhaustion, budget
    /// exhaustion, time exhaustion) already end in a terminal event that
    /// `append` itself syncs immediately -- but cancellation (AC-3.27)
    /// deliberately emits *no* terminal event, so without this call a
    /// cancelled scan's last (at most `max_events`/`max_interval`) buffered
    /// appends would sit unsynced for as long as the process happens to
    /// keep the file open. That is still within the group-commit crash
    /// contract (a crash there loses no more than the same bound any other
    /// stop reason does), but a *clean*, non-crash return from `run` has no
    /// reason to leave anything less durable than it has to be, so the
    /// scheduler pays this one small, fixed cost once per run rather than
    /// none.
    pub fn force_sync(&mut self) -> Result<(), LogError> {
        self.log.sync()?;
        self.pending = 0;
        self.last_sync = Instant::now();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bathy_types::clock::FixedClock;

    fn scan_id() -> ScanId {
        "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap()
    }

    fn clock() -> FixedClock {
        FixedClock::new("2026-08-01T15:04:31.182Z", 7).unwrap()
    }

    fn progress(n: u64) -> EventBody {
        EventBody::Progress {
            probes_sent: n,
            probes_total: 1_000,
            packets_spent: n,
        }
    }

    fn open(config: GroupCommitConfig) -> (tempfile::TempDir, GroupCommitLog) {
        let dir = tempfile::tempdir().unwrap();
        let log = GroupCommitLog::open(dir.path(), scan_id(), config).unwrap();
        (dir, log)
    }

    #[test]
    fn appends_are_readable_immediately_even_before_a_sync_trigger_fires() {
        let (_d, mut log) = open(GroupCommitConfig {
            max_events: 100,
            max_interval: Duration::from_secs(100),
        });
        for i in 1..=5 {
            log.append(progress(i), &clock(), "0.1.0").unwrap();
        }
        // Far below `max_events`, and no time has passed under a paused
        // clock -- no sync has fired yet, but the data must still be
        // readable (same-process visibility does not depend on `fsync`).
        assert_eq!(log.read_from(0).unwrap().len(), 5);
        assert_eq!(log.last_sequence(), 5);
    }

    #[test]
    fn a_terminal_event_forces_a_sync_regardless_of_either_trigger() {
        // `max_events`/`max_interval` both set high enough that neither
        // trigger would fire on its own within this test -- the ONLY thing
        // that can explain a sync happening here is the terminal-event
        // check. Sync failures would surface as an `Err` from `append`
        // itself, so the direct proof is just that this returns `Ok` and
        // the log is fully readable afterward; the mutation test in this
        // task's report removes the `is_terminal` check and shows this
        // path is what changes (`pending` stays nonzero instead of
        // resetting -- see the counter-based test below for how that is
        // observed).
        let (_d, mut log) = open(GroupCommitConfig {
            max_events: 1_000,
            max_interval: Duration::from_secs(1_000),
        });
        log.append(progress(1), &clock(), "0.1.0").unwrap();
        assert_eq!(log.pending, 1);
        log.append(
            EventBody::ScanCompleted {
                probes_sent: 1,
                packets_spent: 1,
                findings: 0,
            },
            &clock(),
            "0.1.0",
        )
        .unwrap();
        assert_eq!(
            log.pending, 0,
            "a terminal event must reset the pending counter via a forced sync"
        );
    }

    #[test]
    fn policy_denied_and_scan_failed_are_also_terminal() {
        for body in [
            EventBody::PolicyDenied {
                reason_code: bathy_types::event::DenyReason::TargetOutOfScope,
                detail: "x".into(),
            },
            EventBody::ScanFailed {
                reason_code: "budget_exhausted".into(),
                detail: "x".into(),
            },
        ] {
            let (_d, mut log) = open(GroupCommitConfig {
                max_events: 1_000,
                max_interval: Duration::from_secs(1_000),
            });
            log.append(progress(1), &clock(), "0.1.0").unwrap();
            log.append(body, &clock(), "0.1.0").unwrap();
            assert_eq!(log.pending, 0);
        }
    }

    #[test]
    fn the_event_count_trigger_fires_at_exactly_max_events_not_one_over_or_under() {
        let (_d, mut log) = open(GroupCommitConfig {
            max_events: 3,
            max_interval: Duration::from_secs(1_000),
        });
        log.append(progress(1), &clock(), "0.1.0").unwrap();
        assert_eq!(log.pending, 1);
        log.append(progress(2), &clock(), "0.1.0").unwrap();
        assert_eq!(log.pending, 2, "must not sync before max_events is reached");
        log.append(progress(3), &clock(), "0.1.0").unwrap();
        assert_eq!(
            log.pending, 0,
            "must sync exactly when pending reaches max_events"
        );
    }

    // --- M3 Task 7 fix round 1, IMPORTANT-1: pin the real syscall count,
    // not the internal `pending` counter. The reviewer's exact repro: swap
    // `EventLog::open_without_durability_barrier` in `GroupCommitLog::open`
    // for the DURABLE `EventLog::open` -- every test above that only checks
    // `pending` keeps passing (the wrapper's own bookkeeping is unaffected),
    // silently reinstating the per-event fsync the whole module exists to
    // avoid. `sync_calls()` is the ground truth that mutation cannot hide
    // from: with 500 appends and `max_events = 50`, the correct
    // implementation issues on the order of 10 real syncs; a secretly-durable
    // wrapped log issues 500, plus whatever the wrapper's own batching adds
    // on top -- either way, far more than a generous upper bound the correct
    // implementation can never cross. ---

    #[test]
    fn batching_produces_far_fewer_real_sync_calls_than_events_appended() {
        let (_d, mut log) = open(GroupCommitConfig {
            max_events: 50,
            max_interval: Duration::from_secs(1_000), // the count trigger alone must carry this
        });
        for i in 1..=500u64 {
            log.append(progress(i), &clock(), "0.1.0").unwrap();
        }
        // 500 / 50 = 10 count-triggered syncs; generous upper bound (still
        // two orders of magnitude below 500) so this isn't brittle against
        // the exact batch-boundary count.
        assert!(
            log.sync_calls() <= 15,
            "expected on the order of 10 batched syncs for 500 appends at \
             max_events=50, got {} real sync_data() calls -- batching is not \
             actually reducing real fsync traffic",
            log.sync_calls()
        );
        assert!(
            log.sync_calls() < 500,
            "must be strictly fewer syncs than events appended -- {} syncs for \
             500 appends means every append is syncing, i.e. no batching at all",
            log.sync_calls()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_interval_trigger_fires_once_max_interval_has_elapsed() {
        let (_d, mut log) = open(GroupCommitConfig {
            max_events: 1_000_000,
            max_interval: Duration::from_millis(200),
        });
        log.append(progress(1), &clock(), "0.1.0").unwrap();
        assert_eq!(log.pending, 1);
        tokio::time::advance(Duration::from_millis(150)).await;
        log.append(progress(2), &clock(), "0.1.0").unwrap();
        assert_eq!(
            log.pending, 2,
            "must not sync before max_interval has elapsed"
        );
        tokio::time::advance(Duration::from_millis(60)).await;
        log.append(progress(3), &clock(), "0.1.0").unwrap();
        assert_eq!(
            log.pending, 0,
            "must sync once max_interval has elapsed since the last sync"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_sync_resets_the_interval_clock_not_just_the_counter() {
        let (_d, mut log) = open(GroupCommitConfig {
            max_events: 2,
            max_interval: Duration::from_millis(200),
        });
        log.append(progress(1), &clock(), "0.1.0").unwrap();
        log.append(progress(2), &clock(), "0.1.0").unwrap(); // event-count trigger fires here
        assert_eq!(log.pending, 0);
        tokio::time::advance(Duration::from_millis(150)).await;
        log.append(progress(3), &clock(), "0.1.0").unwrap();
        assert_eq!(
            log.pending, 1,
            "the interval clock must have restarted at the count-triggered \
             sync, not still be counting from GroupCommitLog::open"
        );
    }

    #[test]
    fn force_sync_resets_pending_and_is_callable_with_nothing_buffered() {
        let (_d, mut log) = open(GroupCommitConfig::default());
        log.force_sync().unwrap(); // nothing appended yet: harmless
        log.append(progress(1), &clock(), "0.1.0").unwrap();
        assert_eq!(log.pending, 1);
        log.force_sync().unwrap();
        assert_eq!(log.pending, 0);
    }

    #[test]
    fn default_config_matches_the_documented_values() {
        let d = GroupCommitConfig::default();
        assert_eq!(d.max_events, 200);
        assert_eq!(d.max_interval, Duration::from_millis(200));
    }

    #[test]
    fn scan_id_and_last_sequence_pass_through_to_the_wrapped_log() {
        let (_d, mut log) = open(GroupCommitConfig::default());
        assert_eq!(log.scan_id(), scan_id());
        assert_eq!(log.last_sequence(), 0);
        log.append(progress(1), &clock(), "0.1.0").unwrap();
        assert_eq!(log.last_sequence(), 1);
    }
}
