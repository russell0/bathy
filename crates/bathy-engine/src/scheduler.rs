//! The scheduler: budget-governed, cancellable, resumable execution of a
//! [`ScanPlan`]. This is the component that turns every other M1-M3 piece
//! into an actual scanner.
//!
//! # Six invariants
//!
//! 1. **Budget is reserved before emission, never after.** [`Scheduler::run`]
//!    calls [`BudgetLedger::try_spend_packets`] immediately before spawning a
//!    unit's probe, never after. A refused reservation ends the scan; it
//!    never emits "just one more" packet -- see the cancellable-wait/reserve
//!    ordering in the dispatch loop below for exactly where this happens.
//! 2. **Cancellation drains in-flight work rather than dropping it -- but
//!    "drain" means finish what was already paid for, never start
//!    something new.** Once a unit's CONNECT probe has been dispatched
//!    (its budget already spent), its result is always recorded, even
//!    after `cancel` fires -- see the unconditional drain loop after the
//!    dispatch loop breaks. M4 Task 5 fix round 1, CRITICAL-2: that same
//!    unconditional drain loop calls `record`, which (for an `Open`
//!    outcome) can itself start BRAND NEW probe traffic via
//!    `detect_service` -- an earlier version of this had no way to tell
//!    "finish draining the connect probe" apart from "begin a fresh
//!    reconnect," so a cancellation landing while a unit's connect probe
//!    was still in flight let `detect_service` open new sockets and write
//!    real bytes AFTER cancellation. `cancel` is now threaded through
//!    `record`/`detect_service` specifically so the connect probe's own
//!    already-spent packet is still drained (invariant holds), while
//!    `detect_service` refuses to start any NEW probe attempt once
//!    cancelled (the invariant's own "never starts something new" half,
//!    which nothing enforced before this fix) -- see `record`'s and
//!    `detect_service`'s own doc comments.
//! 3. **Resumption never re-probes and never skips.** `from_index` alone is
//!    not sufficient once probes complete out of order under concurrency: a
//!    previous (interrupted) run can have completed a unit *above* the
//!    first gap `TaskStore::next_pending_unit` reports, and naively
//!    dispatching every unit in `from_index..plan.len()` would re-probe it.
//!    `run` therefore loads the full set of already-completed indices once,
//!    at the start, and skips any unit already in it -- see `already_done`
//!    below. (This is a defect in the task brief's own Step 3 sketch, which
//!    dispatches `plan.units_from(from_index)` with no such check; see this
//!    task's report for the concrete race and the round-trip test that
//!    catches it.)
//! 4. **Five outcomes are distinct.** Plan exhaustion, cancellation, budget
//!    exhaustion, time exhaustion, and policy denial each get their own
//!    [`RunSummary`] field, and four of the five (all but cancellation)
//!    their own terminal event -- see AC-3.27. (Policy denial is a M3
//!    whole-branch-review addition, CRITICAL-1 below; the brief's own text
//!    only ever enumerated the first three.)
//! 5. **Scope is consulted on the actual emission path, not assumed.** M3
//!    whole-branch review, CRITICAL-1: `bathy-engine` had depended on
//!    `bathy-scope` since this crate's very first task, but nothing on the
//!    emission path ever called [`bathy_scope::ScopeManifest::allows`] --
//!    every scheduler test scanned loopback, which `allows` refuses
//!    categorically, and none of them noticed. Fixed at the type level:
//!    [`Scheduler::new`] takes a `manifest` and cannot be constructed
//!    without one, and `run` checks every unit's target against it
//!    immediately before dispatch -- see this type's own doc comment on the
//!    `manifest` field, and `run`'s doc comment, for the full reasoning.
//!
//!    A whole-branch RE-review (same milestone) found this was incomplete:
//!    per-target authorization is a genuine *re-check* -- `bathy_scope::evaluate`
//!    is the upstream call meant to validate it first, over the plan's full
//!    expanded target list, before this `Scheduler` is ever constructed --
//!    but `run` had no check at all for the other two things `evaluate`
//!    validates: that `manifest` is *the* manifest this `scan_id` was
//!    actually started under (not merely *a* manifest satisfying the type
//!    system), and that it is still active. Since `evaluate` has zero
//!    callers anywhere in this workspace as of this milestone, those two
//!    were not belt-and-braces the way the per-target check is -- they were
//!    the only belt, and there wasn't one. `run` now checks scope identity
//!    (against the scan record's own `scope_id`) and expiry up front, before
//!    `scan.started` or any unit is even considered, refusing the whole scan
//!    exactly like the per-target check does. See `run`'s own doc comment.
//!
//!    M4 Task 5 extends this same posture to the second connection service
//!    detection opens on an already-`Open` endpoint: [`Scheduler::detect_service`]
//!    re-checks `manifest.allows` immediately before its own reconnect,
//!    rather than trusting the per-unit check moments earlier (above) to
//!    still cover it -- see that method's own doc comment.
//! 6. **Evidence is stored before the event that cites it, never the
//!    reverse.** M4 Task 5's own carried rule (the analogous store/log
//!    ordering M3's review found inverted one layer up, at group-commit
//!    granularity -- see "Group commit" below): [`Scheduler::emit_service_observed`]
//!    calls [`bathy_evidence::EvidenceStore::put_capped`] and checks its
//!    `?` BEFORE calling `self.log(EventBody::ServiceObserved { .. })`. A
//!    crash between the two leaves an orphaned blob (harmless); the reverse
//!    would leave a `service.observed` event whose `evidence_refs` entry no
//!    `EvidenceStore::get` call could ever resolve. `evidence_level: none`
//!    is not a special case of this rule but a direct consequence of a
//!    type: `EventBody::ServiceObserved::evidence_refs` is
//!    `NonEmpty<Digest>`, so with no evidence stored there is no digest to
//!    cite and therefore no event -- see that method's own doc comment.
//!
//! # Group commit
//!
//! `run` never calls a per-event-syncing `EventLog::append` directly; it
//! goes through [`crate::durable_log::GroupCommitLog`], sharing one
//! `Arc<Mutex<_>>` with whatever else needs to read the same log (e.g. a
//! test harness, or a future status/streaming API) -- see that module's doc
//! comment for the crash contract and measured throughput.
//!
//! # `scan.started` is once per scan, not once per `run()` call
//!
//! A resumed scan calls `run` a second time on the same (reopened) log.
//! `from_index` alone cannot distinguish "genuinely fresh start" from
//! "resuming after index 0 with nothing yet completed", so `run` instead
//! asks the log itself: a `scan.started` is only emitted when the log is
//! still empty (`last_sequence() == 0`). See
//! `cancelled_run_resumes_to_a_full_gap_free_union_with_no_unit_probed_twice`
//! below, which asserts exactly one `scan.started` across two real `run()`
//! calls.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

use bathy_evidence::{EvidenceError, EvidenceStore, LogError};
use bathy_interpret::interpret;
use bathy_plan::{ScanPlan, ScanUnit};
use bathy_probe::{ProbeIo, ProbeRegistry, select_probes};
use bathy_scope::{BudgetLedger, ScopeManifest};
use bathy_store::{StoreError, TaskStore};
use bathy_types::clock::Clock;
use bathy_types::event::{DenyReason, EventBody, Observation, PortState, Target};
use bathy_types::ids::{Digest, ScanId};
use bathy_types::nonempty::NonEmpty;
use bathy_types::request::{EvidenceLevel, ServiceDetection};
use bathy_types::task::TaskStatus;

use crate::connect::{ConnectOutcome, probe_connect_with_local_signal};
use crate::durable_log::GroupCommitLog;
use crate::rate::RateLimiter;

#[cfg(test)]
use crate::durable_log::GroupCommitConfig;

/// Batch size at which accumulated per-unit completions are flushed to the
/// `TaskStore` resumption cursor (`store.mark_units_done`). Independent of
/// [`SchedulerConfig::progress_every`], which governs how often a
/// `scan.progress` *event* is emitted -- see [`Scheduler::flush_progress`].
/// Not configurable: this is purely an internal batching granularity for
/// SQLite writes, not a durability or observability contract like group
/// commit or `progress_every` are.
const STORE_FLUSH_BATCH: usize = 64;

/// Wall-clock elapsed time, in whole seconds, rounded UP -- never
/// `Duration::as_secs()`, which truncates.
///
/// M3 Task 7 fix round 2, CRITICAL-2's runtime half: review found that
/// every runtime-ceiling comparison in this module compared against
/// `started.elapsed().as_secs()`, which discards any sub-second remainder.
/// For the periodic in-run check (`run`'s own dispatch loop) that is a
/// small, self-correcting latency (at most ~1s before the NEXT check
/// catches up). For `total_elapsed_seconds` -- what gets PERSISTED via
/// `TaskStore::record_progress` and read back by the next resume's
/// `BudgetLedger::resumed` -- it is not self-correcting at all: a run
/// cancelled at, say, 800ms contributes exactly ZERO forever, on every
/// single cancel/resume round, because the next round starts a brand new
/// `Instant` and repeats the same truncation. Reviewer's repro: six rounds
/// of ~800ms cancellations against a 2-second ceiling accumulated 4.95
/// real seconds and 10,839 probed units while the persisted total stayed
/// at 0 -- the exact "unbounded under repeated cancel/resume" defect
/// CRITICAL-2 was opened for, still fully open after round 1's fix (which
/// closed the *seeding* mechanism but not this truncation in what gets fed
/// into it).
///
/// Rounding up instead of down means every run's contribution is always
/// **>=** its true elapsed time, so the cumulative persisted total can
/// never permanently fall behind real wall-clock time -- the defect is
/// closed exactly, not merely narrowed, regardless of how many
/// cancel/resume rounds occur. The cost is a systematic OVER-count of at
/// most ~1 second per round (e.g. 100 rounds of 10ms each could accrue up
/// to 100 counted seconds for 1 real second elapsed) -- but over-counting
/// against a ceiling whose entire purpose is to STOP a scan is the safe
/// failure direction: a scan can stop up to N seconds "early" after N
/// rounds, but it can never again run unboundedly past its budget the way
/// silent truncation allowed.
///
/// A full millisecond-precision rewrite of `BudgetLedger`/
/// `TaskStore::record_progress`/`schema.sql` (storing and comparing
/// milliseconds throughout instead of whole seconds) was considered and
/// rejected as disproportionate to what review actually asked to be fixed:
/// it would touch three crates, a schema column, and every existing
/// whole-seconds `BudgetLedger` test for a correctness property (a
/// cancel/resume loop's cumulative runtime can never regress) that this
/// one-line rounding change already delivers exactly, at the two places
/// `Instant::elapsed()` is turned into the `u64` seconds
/// `BudgetLedger::elapsed_exceeded`'s public API expects.
fn ceil_elapsed_seconds(elapsed: Duration) -> u64 {
    elapsed.as_secs_f64().ceil() as u64
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error(transparent)]
    Log(#[from] LogError),
    #[error(transparent)]
    Store(#[from] StoreError),
    /// M4 Task 5: `Scheduler::emit_service_observed`'s `EvidenceStore::put_capped`
    /// call. Propagated as a hard error, the same way a `Log`/`Store`
    /// failure already is -- a failed evidence write must never be silently
    /// swallowed while the probe budget it cost has already been spent; see
    /// this task's report for why "skip storing and continue" was rejected.
    #[error(transparent)]
    Evidence(#[from] EvidenceError),
    #[error("a scan worker task panicked or was cancelled by the runtime: {0}")]
    Join(#[from] tokio::task::JoinError),
    /// M3 whole-branch review, IMPORTANT-3: `run` refused to execute `plan`
    /// against `scan_id` because `plan.hash()` does not match the
    /// `plan_hash` the store recorded when this scan was started.
    /// `bathy-plan`'s own module doc calls the unit-index-to-target mapping
    /// "a compatibility surface in the same sense a wire format is" --
    /// resuming against a plan that does not hash to what was originally
    /// approved would silently point every remaining probe at the wrong
    /// host and port, not raise an error. Failing loudly here, before a
    /// single unit is dispatched, is what turns that into an error instead.
    #[error(
        "refusing to run scan {scan_id}: the supplied plan hashes to {actual}, but this scan \
         was started (and, if resuming, previously ran) against plan_hash {expected} -- \
         running a different plan against an existing scan_id would silently misdirect \
         every resumed probe at the wrong host and port"
    )]
    PlanMismatch {
        scan_id: ScanId,
        expected: Digest,
        actual: Digest,
    },
}

/// The outcome of one [`Scheduler::run`] call. See the module doc comment's
/// "Four invariants" section for what each field means and why exactly one
/// of `cancelled`/`budget_exhausted`/`time_exhausted` (or none, for plan
/// exhaustion) is ever set.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RunSummary {
    /// Units newly probed *by this call* -- not a running total across a
    /// resumed scan's every `run()` invocation, and not incremented for a
    /// unit skipped because a previous run already completed it.
    pub units_completed: u64,
    /// The budget ledger's total spend, which (v0.1: one packet per probe)
    /// includes every unit ever dispatched for this `scan_id`, across every
    /// `run()` call that shares the same ledger -- unlike `units_completed`,
    /// this is cumulative, mirroring `BudgetLedger::packets_spent`'s own
    /// contract.
    pub packets_spent: u64,
    pub open_ports: u64,
    pub cancelled: bool,
    pub budget_exhausted: bool,
    pub time_exhausted: bool,
    /// M3 whole-branch review, CRITICAL-1: set when `run`'s own re-check of
    /// a unit's target against [`Scheduler`]'s manifest (immediately before
    /// dispatch -- see that type's doc comment on its `manifest` field)
    /// refuses it. Stops the scan exactly like `budget_exhausted`/
    /// `time_exhausted` do -- see `run`'s doc comment for why this is
    /// treated as fatal to the whole scan rather than "skip this one unit
    /// and continue" -- and, unlike them, is not expected to ever trigger
    /// in correct operation: every target `run` sees should already have
    /// passed [`bathy_scope::evaluate`] before this `Scheduler` was ever
    /// constructed. Its own terminal event is `EventBody::PolicyDenied`.
    pub policy_denied: bool,
    /// M3 Task 7's carried requirement from Tasks 5/6: a count of probes
    /// whose `Filtered` outcome was attributable to a *local* resource or
    /// policy problem (ephemeral-port exhaustion, a local firewall) rather
    /// than genuine target/path silence -- see
    /// `crate::connect::probe_connect_with_local_signal`. Surfaced here so a
    /// caller can tell "the target is mostly closed/filtered" from "this
    /// machine is running out of its own resources," which the raw
    /// `port.state` events alone cannot distinguish (`Filtered` folds both
    /// into one wire value). This crate deliberately stops at the required
    /// minimum ("count them and surface the count") rather than also
    /// failing the scan outright when they dominate -- see this task's
    /// report for why.
    pub local_resource_failures: u64,
}

/// Tunables that are Task 7's own (as opposed to [`crate::durable_log::GroupCommitConfig`],
/// which a caller chooses independently when opening the
/// [`GroupCommitLog`](crate::durable_log::GroupCommitLog) it hands to
/// [`Scheduler::new`]).
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Maximum number of probes in flight at once. Clamped to at least 1.
    pub concurrency: usize,
    /// Per-probe TCP connect deadline, forwarded to
    /// [`crate::connect::probe_connect_with_local_signal`].
    pub connect_timeout: Duration,
    /// A `scan.progress` event is emitted at least once every
    /// `progress_every` newly-completed units (AC-3.30). Also clamped to at
    /// least 1 (a value of 0 would make every single completion emit a
    /// progress event, which is not "periodic," it is "every event," a
    /// meaningfully different and much noisier contract).
    pub progress_every: u64,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            concurrency: 256,
            connect_timeout: Duration::from_secs(2),
            progress_every: 500,
        }
    }
}

/// See the module doc comment.
pub struct Scheduler {
    limiter: RateLimiter,
    ledger: Mutex<BudgetLedger>,
    /// M3 whole-branch review, CRITICAL-1: the type-level fix. There is no
    /// `Scheduler::new` overload and no `Default` impl that omits this --
    /// constructing a `Scheduler` at all requires handing it a manifest, so
    /// "a scheduler was built with literally no scope awareness" (the
    /// defect this review found: `bathy-engine` depended on `bathy-scope`
    /// since Task 1 but nothing on the emission path ever called
    /// `allows`) cannot happen again by construction, not merely by
    /// convention.
    ///
    /// `run` checks THREE things against this before it will ever dispatch
    /// a unit -- see the module doc's invariant 5 for the full history:
    /// that this really is the manifest `scan_id` was started under (its
    /// `id` against the scan record's own `scope_id`), that it is still
    /// active (`is_expired`), and that each individual target is inside its
    /// allow set (`allows`). Only the last of those three is a genuine
    /// re-check of an upstream `bathy_scope::evaluate` call a future
    /// orchestrator (M5) is expected to make over the plan's full expanded
    /// target list -- the first two are not belt-and-braces on anything:
    /// `evaluate` has no caller anywhere in this workspace as of this
    /// milestone, so for scope identity and expiry, `run`'s own checks are
    /// currently the *only* enforcement that exists. Constructibility alone
    /// (this field being required) never proved either of those two; only
    /// `run`'s own checks do.
    manifest: Arc<ScopeManifest>,
    config: SchedulerConfig,
    log: Arc<Mutex<GroupCommitLog>>,
    store: Arc<TaskStore>,
    /// C2/M2: the SAME `Arc<dyn Clock>` the caller also hands to
    /// `TaskStore::open` for this scan -- never a second, independently
    /// constructed clock. Two clocks means two ULID generators and
    /// identifier collisions (M2's whole-branch review found this had
    /// already happened once in this repo's own suite). `Scheduler::new`
    /// does not construct a clock itself for exactly this reason: it only
    /// ever receives one, so there is nowhere for a second instance to
    /// sneak in.
    clock: Arc<dyn Clock>,
    scan_id: ScanId,
    engine_version: String,
    /// M4 Task 5: whether (and how hard) `record` attempts service
    /// identification on an `Open` endpoint, and how many probes
    /// `select_probes` is authorized to try -- see `detect_service`.
    /// Carried as plain request-derived config, the same way `manifest`
    /// and `ledger` are: nothing in `ScanPlan` retains this (see
    /// `bathy_plan::ScanPlan`'s own fields), so a caller must hand it to
    /// this constructor directly rather than have it rederived from the
    /// plan.
    service_detection: ServiceDetection,
    /// M4 Task 5: how much of a matched probe's raw response
    /// `emit_service_observed` is allowed to store as evidence --
    /// `EvidenceLevel::None` stores nothing and, by direct consequence of
    /// `EventBody::ServiceObserved::evidence_refs` being `NonEmpty<Digest>`,
    /// emits no event at all (AC-4.23). See that method's own doc comment.
    evidence_level: EvidenceLevel,
    /// M4 Task 5: where `emit_service_observed` stores a matched probe's raw
    /// response before appending the `service.observed` event that cites
    /// it -- never the other way around; see this module's own ordering
    /// rule at the top of this file.
    evidence: Arc<EvidenceStore>,
    /// M4 Task 5: the probes `detect_service` chooses from via
    /// `select_probes`. `Arc`-shared (not owned outright) purely so it can
    /// be built once by a caller and reused across scheduler instances --
    /// `ProbeRegistry::standard()` is deterministic and stateless, so
    /// sharing one instance costs nothing and avoids re-validating the
    /// eight probes' ids on every `Scheduler::new` call.
    probes: Arc<ProbeRegistry>,
}

/// One matched probe's identification, ready to be turned into a
/// `service.observed` event once its evidence has actually been stored --
/// see [`Scheduler::emit_service_observed`]. Deliberately does not carry a
/// `Digest`: computing one is [`EvidenceStore::put_capped`]'s job, not
/// [`Scheduler::detect_service`]'s, so this type cannot even represent
/// "evidence referenced before it is stored."
struct ServiceFinding {
    observation: Observation,
    /// The exact, untruncated bytes `capture.response` held. Capping
    /// happens in `emit_service_observed`, at the byte count
    /// `evidence_level` implies -- not here, so this type always carries
    /// the real, complete evidence regardless of what a caller later
    /// chooses to keep.
    evidence: Vec<u8>,
    probe_id: &'static str,
}

impl Scheduler {
    /// `log` and `store` are `Arc`-shared, not owned outright, so a caller
    /// (a test harness, a future status API) can keep its own handle to
    /// read the same live state this scheduler is writing -- `TaskStore` is
    /// already designed to be shared this way (see its own module doc), and
    /// [`GroupCommitLog::read_from`] is a plain, lock-free-once-acquired
    /// read that does not need to go through this scheduler at all.
    ///
    /// `clock` must be the exact `Arc<dyn Clock>` also passed to whatever
    /// `TaskStore::open` produced `store` -- see this type's own doc comment
    /// on the `clock` field for why.
    ///
    /// `manifest` is required, not optional -- see this type's own doc
    /// comment on its `manifest` field for why (CRITICAL-1).
    ///
    /// There is no separate `limiter` parameter. M3 whole-branch review,
    /// IMPORTANT-2: an earlier version of this constructor took a
    /// `RateLimiter` built by the caller from whatever pps value it chose,
    /// wholly independent of `ledger`'s own `maximum_packets_per_second` --
    /// `bathy_scope::evaluate` validates a request's pps against the
    /// manifest ceiling, and then nothing enforced that the ledger and the
    /// limiter actually agreed on what that ceiling *was*. Two options were
    /// available: derive the limiter from the ledger (making a mismatch
    /// unrepresentable), or keep both parameters and reject a mismatch at
    /// construction (making a mismatch representable but caught). This
    /// constructor derives: a caller cannot even ask for two different pps
    /// values in the first place, which is strictly stronger than
    /// validating that two independently-supplied ones happen to agree, and
    /// removes a parameter besides.
    /// M4 Task 5 added the last four parameters (`service_detection` through
    /// `probes`) -- see their own field doc comments on this type for what
    /// each governs.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ledger: BudgetLedger,
        manifest: Arc<ScopeManifest>,
        config: SchedulerConfig,
        log: Arc<Mutex<GroupCommitLog>>,
        store: Arc<TaskStore>,
        clock: Arc<dyn Clock>,
        scan_id: ScanId,
        engine_version: impl Into<String>,
        service_detection: ServiceDetection,
        evidence_level: EvidenceLevel,
        evidence: Arc<EvidenceStore>,
        probes: Arc<ProbeRegistry>,
    ) -> Self {
        let limiter = RateLimiter::new(ledger.packets_per_second());
        Self {
            limiter,
            ledger: Mutex::new(ledger),
            manifest,
            config,
            log,
            store,
            clock,
            scan_id,
            engine_version: engine_version.into(),
            service_detection,
            evidence_level,
            evidence,
            probes,
        }
    }

    fn ledger(&self) -> MutexGuard<'_, BudgetLedger> {
        self.ledger.lock().expect("budget ledger mutex poisoned")
    }

    fn log_guard(&self) -> MutexGuard<'_, GroupCommitLog> {
        self.log.lock().expect("event log mutex poisoned")
    }

    fn log(&self, body: EventBody) -> Result<(), EngineError> {
        self.log_guard()
            .append(body, self.clock.as_ref(), &self.engine_version)?;
        Ok(())
    }

    /// The TOTAL wall-clock runtime this scan has used, across every run --
    /// this ledger's own resumption baseline (`BudgetLedger::seconds_already_elapsed`,
    /// zero unless this `Scheduler` was built with `BudgetLedger::resumed`)
    /// plus how long `started` (THIS run's own `Instant`) has been running.
    /// M3 Task 7 fix round 1, CRITICAL-2: this is what gets persisted via
    /// `TaskStore::record_progress`, so the NEXT resume's fresh `Scheduler`
    /// can seed its own `BudgetLedger::resumed` with the true cumulative
    /// total rather than restarting the runtime clock at zero every time.
    ///
    /// M3 Task 7 fix round 2 (CRITICAL-2's runtime half, still open after
    /// round 1): uses [`ceil_elapsed_seconds`], not `Duration::as_secs()` --
    /// see that function's own doc comment for why truncating here is what
    /// let the accumulated total lose real elapsed time, forever, on every
    /// single run.
    fn total_elapsed_seconds(&self, started: Instant) -> u64 {
        self.ledger()
            .seconds_already_elapsed()
            .saturating_add(ceil_elapsed_seconds(started.elapsed()))
    }

    /// Whether this scan's log already ends in a terminal event
    /// (`scan.completed`, `scan.failed`, or `policy.denied`). See `run`'s
    /// own doc comment for why this makes a redundant `run` call after a
    /// non-cancelled stop a safe no-op instead of a duplicate terminal
    /// event.
    fn already_terminated(&self) -> Result<bool, EngineError> {
        let log = self.log_guard();
        let last_sequence = log.last_sequence();
        if last_sequence == 0 {
            return Ok(false);
        }
        let tail = log.read_from(last_sequence - 1)?;
        Ok(tail.last().is_some_and(|e| {
            matches!(
                &e.body,
                EventBody::ScanCompleted { .. }
                    | EventBody::ScanFailed { .. }
                    | EventBody::PolicyDenied { .. }
            )
        }))
    }

    /// Execute units `from_index..plan.len()`, skipping any already
    /// completed by a previous run of this same scan -- see the module doc
    /// comment's invariant 3.
    ///
    /// Ordering guarantees: a unit's completion is recorded (both as a
    /// `port.state` event and as a `TaskStore` resumption-cursor entry) in
    /// batches as work finishes, so a cancelled or crashed scan resumes
    /// from a genuinely unfinished unit. The scan stops on the first of:
    /// plan exhaustion, cancellation, packet budget exhaustion, or runtime
    /// exhaustion -- each reported distinctly in the returned
    /// [`RunSummary`] and (all but cancellation) as its own terminal event.
    ///
    /// # Calling `run` again after a scan has already terminated
    ///
    /// `run` is safe to call again on a scan that stopped by cancellation
    /// (AC-3.25/3.26: that is the whole point -- it resumes). It is a
    /// no-op, not an error, if the scan already ended in `scan.completed`
    /// or `scan.failed` (budget/time exhaustion) -- checked once, cheaply,
    /// against the log's own last event, so AC-3.28 ("ends with exactly one
    /// terminal event") holds even if a caller mistakenly invokes `run`
    /// again rather than checking `TaskRecord::status` first. This
    /// `Scheduler`'s `ledger` is one `BudgetLedger` for its whole lifetime
    /// -- "resuming" a budget- or time-exhausted scan with a *larger*
    /// budget is not what a second `run` call on the same `Scheduler` could
    /// do even without this guard (the ledger's ceiling does not change
    /// underneath it); that requires a new `Scheduler` (a fresh
    /// `BudgetLedger`) over the same `scan_id`, which this guard does not
    /// and cannot see, since it only inspects the log this instance was
    /// opened against.
    pub async fn run(
        &self,
        plan: &ScanPlan,
        from_index: u64,
        cancel: CancellationToken,
    ) -> Result<RunSummary, EngineError> {
        let started = Instant::now();
        let mut summary = RunSummary::default();

        // M3 whole-branch review, IMPORTANT-3: refuse to run a plan that
        // does not hash to what this scan_id was actually started (and, if
        // resuming, previously ran) against. Checked before anything else,
        // including `already_terminated` -- a mismatched plan handed to an
        // already-terminated scan is still a caller bug worth surfacing
        // loudly, not one this method should paper over by returning early
        // before ever looking at `plan` at all. See `EngineError::PlanMismatch`.
        let record = self
            .store
            .get(self.scan_id)?
            .ok_or(StoreError::NotFound(self.scan_id))?;
        let actual_hash = plan.hash();
        if record.plan_hash != actual_hash {
            return Err(EngineError::PlanMismatch {
                scan_id: self.scan_id,
                expected: record.plan_hash,
                actual: actual_hash,
            });
        }

        if self.already_terminated()? {
            summary.packets_spent = self.ledger().packets_spent();
            return Ok(summary);
        }

        // M3 whole-branch re-review, Global Constraint: two of the three
        // things `bathy_scope::evaluate` validates (scope identity and
        // manifest expiry -- the third, per-target authorization, is the
        // `allows` re-check inside the dispatch loop below) had NO check
        // anywhere on the emission path at all. That is a materially
        // different defect from CRITICAL-1's per-target gate: `evaluate`
        // has zero callers anywhere in this workspace, so the per-target
        // `allows` re-check below is genuinely belt-and-braces (a backstop
        // behind an upstream call that is expected, eventually, to exist),
        // but for scope identity and expiry THIS is currently the only
        // check that will ever run, upstream or not. `record` (already
        // loaded above for the plan_hash check) carries the scope_id this
        // scan_id was actually started under; `self.manifest` is merely *a*
        // manifest handed to `Scheduler::new` -- constructibility alone
        // never proved it is *the* manifest this scan was authorized
        // against, nor that it is still active. Checked once, up front,
        // exactly like `evaluate`'s own ordering (scope mismatch, then
        // expiry, before any target is even considered) -- and, like the
        // per-target check, refuses the WHOLE scan rather than a probe at a
        // time: `policy_denial` gates the entire dispatch section below via
        // the labeled block, so a scan denied here never even reaches
        // `scan.started`, `already_done`, or the plan's own unit list.
        let mut policy_denial: Option<(DenyReason, String)> = None;
        if record.scope_id != self.manifest.id() {
            policy_denial = Some((
                DenyReason::ScopeMismatch,
                format!(
                    "scan {} was started under scope {}, but this Scheduler was built with \
                     manifest {}",
                    self.scan_id,
                    record.scope_id,
                    self.manifest.id()
                ),
            ));
        } else if self.manifest.is_expired(&self.clock.now_rfc3339()) {
            policy_denial = Some((
                DenyReason::ScopeExpired,
                format!(
                    "manifest {} expired before {}",
                    self.manifest.id(),
                    self.clock.now_rfc3339()
                ),
            ));
        }

        'dispatch: {
            if policy_denial.is_some() {
                break 'dispatch;
            }

            // AC-3.28: exactly one `scan.started`, gated on the log's own
            // content rather than on `from_index` -- see the module doc.
            if self.log_guard().last_sequence() == 0 {
                self.log(EventBody::ScanStarted {
                    plan_hash: plan.hash(),
                    estimated_targets: plan.targets().len() as u64,
                    estimated_probes: plan.len(),
                })?;
            }

            // Invariant 3: the full set of units a PREVIOUS run already
            // completed, loaded once. `from_index` alone is a necessary but
            // not sufficient skip condition under concurrency -- see the
            // module doc.
            let already_done: HashSet<u64> = self
                .store
                .completed_units(self.scan_id)?
                .into_iter()
                .collect();

            let permits = Arc::new(Semaphore::new(self.config.concurrency.max(1)));
            let mut in_flight: JoinSet<(ScanUnit, ConnectOutcome, bool)> = JoinSet::new();
            let mut units = plan.units_from(from_index);
            let mut completed_batch: Vec<u64> = Vec::with_capacity(STORE_FLUSH_BATCH);
            let mut last_progress_emitted_at: u64 = 0;

            'drive: loop {
                if cancel.is_cancelled() {
                    summary.cancelled = true;
                    break 'drive;
                }
                if self
                    .ledger()
                    .elapsed_exceeded(ceil_elapsed_seconds(started.elapsed()))
                {
                    summary.time_exhausted = true;
                    break 'drive;
                }

                let Some(unit) = units.next() else {
                    break 'drive;
                };

                if already_done.contains(&unit.index) {
                    continue;
                }

                // M3 whole-branch review, CRITICAL-1: the actual
                // emission-path gate for PER-TARGET authorization. Checked
                // here -- immediately before the rate-limiter wait and the
                // budget reservation below, i.e. as early and as cheaply as
                // possible, and unconditionally, on every single unit --
                // rather than trusted to have already happened via whatever
                // upstream `bathy_scope::evaluate` call this `Scheduler`'s
                // caller may or may not have made. This is not expected to
                // ever trip in correct operation (every target `run` sees
                // should already have passed `evaluate` before this
                // `Scheduler` was even constructed), which is exactly why
                // it is treated as fatal to the whole scan -- like
                // budget/time exhaustion -- rather than "skip this one unit
                // and keep going": a manifest re-check failing mid-run
                // means something upstream is already wrong, and trimming
                // just the offending unit would be the "trimmed rather than
                // refused in full" behavior this project's own
                // authorization model rejects (see
                // `bathy_scope::policy::evaluate`'s doc comment).
                if !self.manifest.allows(unit.target) {
                    policy_denial = Some((
                        DenyReason::TargetOutOfScope,
                        format!(
                            "{} is not authorized by manifest {} (unit index {})",
                            unit.target,
                            self.manifest.id(),
                            unit.index
                        ),
                    ));
                    break 'drive;
                }

                // Cancellable wait for a rate-limiter token AND a
                // concurrency slot: a cancellation arriving mid-wait must
                // not be delayed behind either. Whichever branch `select!`
                // does not pick is dropped mid-poll -- so if `cancel` wins,
                // `unit` is simply abandoned: never marked done, and (per
                // invariant 1) no budget is ever reserved for it, so it is
                // correctly resumable.
                let acquired = tokio::select! {
                    biased;
                    () = cancel.cancelled() => None,
                    permit = async {
                        self.limiter.acquire(1).await;
                        permits.clone().acquire_owned().await.expect("semaphore is never closed")
                    } => Some(permit),
                };
                let Some(permit) = acquired else {
                    summary.cancelled = true;
                    break 'drive;
                };

                // AC-3.24: reserve budget BEFORE emission, as late as
                // possible -- immediately before the unit is actually
                // dispatched. A refused reservation ends the scan; `unit`
                // above is never spawned, so the total packets emitted can
                // never exceed `maximum_packets`.
                if self.ledger().try_spend_packets(1).is_err() {
                    drop(permit);
                    summary.budget_exhausted = true;
                    break 'drive;
                }

                let timeout = self.config.connect_timeout;
                in_flight.spawn(async move {
                    let (outcome, local) =
                        probe_connect_with_local_signal(unit.target, unit.endpoint.port, timeout)
                            .await;
                    drop(permit);
                    (unit, outcome, local)
                });

                while let Some(done) = in_flight.try_join_next() {
                    self.record(done?, &mut summary, &mut completed_batch, &cancel)
                        .await?;
                }
                if completed_batch.len() >= STORE_FLUSH_BATCH {
                    self.flush_progress(
                        &mut completed_batch,
                        summary.units_completed,
                        &mut last_progress_emitted_at,
                        plan.len(),
                        started,
                    )?;
                }
            }

            // Invariant 2: drain, never drop, work already in flight. These
            // CONNECT probes were already paid for out of the budget
            // (reserved before spawn, above), and their results are real
            // observations -- this loop runs unconditionally, regardless of
            // which branch above broke the dispatch loop.
            //
            // M4 Task 5 fix round 1, CRITICAL-2: draining the connect
            // probe's own already-in-flight result is still correct even
            // after cancellation -- that packet is already on the wire, and
            // recording its outcome costs nothing further. What is NOT
            // still correct is `record` treating that as license to start
            // BRAND NEW probe traffic for it (`detect_service`'s own
            // reconnects) -- `cancel` is passed through here specifically
            // so `record`/`detect_service` can tell "finish what was
            // already paid for" apart from "begin something new," which a
            // bare `&self` call could not distinguish. See `record`'s own
            // doc comment.
            while let Some(done) = in_flight.join_next().await {
                self.record(done?, &mut summary, &mut completed_batch, &cancel)
                    .await?;
            }
            self.flush_progress(
                &mut completed_batch,
                summary.units_completed,
                &mut last_progress_emitted_at,
                plan.len(),
                started,
            )?;
        }

        summary.packets_spent = self.ledger().packets_spent();

        // AC-3.27: four distinct terminal outcomes get their own event and
        // status (M3 whole-branch review, CRITICAL-1 added `policy_denied`
        // to what the brief's own text enumerated); cancellation
        // deliberately gets no event, but (IMPORTANT-1) does get a status.
        // M3 whole-branch review, IMPORTANT-1: `TaskStore::set_status` had
        // no caller outside its own tests -- a completed scan's status
        // stayed `Pending` forever, and `StartOutcome::Reused { status }`
        // (M2's mechanism for telling a repeat idempotency key what
        // happened to the original scan) could therefore never report
        // anything but `Pending`, indistinguishable from "never started".
        if summary.budget_exhausted {
            self.log(EventBody::ScanFailed {
                reason_code: "budget_exhausted".into(),
                detail: format!(
                    "packet budget spent after {} units",
                    summary.units_completed
                ),
            })?;
            self.store.set_status(self.scan_id, TaskStatus::Failed)?;
        } else if summary.time_exhausted {
            self.log(EventBody::ScanFailed {
                reason_code: "time_exhausted".into(),
                detail: format!(
                    "runtime budget elapsed after {} units",
                    summary.units_completed
                ),
            })?;
            self.store.set_status(self.scan_id, TaskStatus::Failed)?;
        } else if let Some((reason_code, detail)) = policy_denial {
            summary.policy_denied = true;
            self.log(EventBody::PolicyDenied {
                reason_code,
                detail,
            })?;
            self.store.set_status(self.scan_id, TaskStatus::Denied)?;
        } else if summary.cancelled {
            self.store.set_status(self.scan_id, TaskStatus::Cancelled)?;
        } else {
            self.log(EventBody::ScanCompleted {
                probes_sent: summary.units_completed,
                packets_spent: summary.packets_spent,
                findings: summary.open_ports,
            })?;
            self.store.set_status(self.scan_id, TaskStatus::Completed)?;
        }

        // A clean return from `run` -- of any kind, including cancellation,
        // which emits no terminal event of its own -- always leaves the log
        // as durable as the next group-commit trigger would have made it
        // anyway. See `GroupCommitLog::force_sync`'s own doc comment.
        self.log_guard().force_sync()?;
        self.store.record_progress(
            self.scan_id,
            self.log_guard().last_sequence(),
            summary.packets_spent,
            self.total_elapsed_seconds(started),
        )?;

        Ok(summary)
    }

    /// Maps one completed unit's [`ConnectOutcome`] to a `port.state` event
    /// and updates `summary`'s counters. Mapping: `Open -> PortState::Open`,
    /// `Closed -> Closed`, `Filtered -> Filtered`, `Unreachable -> Filtered`
    /// (the brief's own text adds "with the discovery method recorded
    /// separately" -- there is no such field on `EventBody::PortStateObserved`
    /// to record it in; see this task's report).
    ///
    /// Bookkeeping is updated only after the event is durably appended
    /// (well, appended -- durability is `GroupCommitLog`'s job): if logging
    /// fails, this unit is not counted as completed and not pushed onto
    /// `completed_batch`, so it is never marked done in the store either.
    ///
    /// # A narrow, accepted gap (M3 whole-branch review, MINOR)
    ///
    /// If `self.log(...)` below fails, `record` (and, via `?`, the whole
    /// `run` call) returns `Err` -- but the real probe already happened
    /// (the packet was already on the wire before `record` was ever
    /// called: see the dispatch loop's own comment on reserving budget
    /// "immediately before the unit is actually dispatched") and the
    /// budget for it was already spent in the in-memory `BudgetLedger`
    /// before that. Because `run` aborts without reaching its own final
    /// `flush_progress`/`record_progress` calls, that spend is never
    /// persisted for THIS unit either. A caller that retries `run` after
    /// such a failure (e.g. a transient disk error) therefore both
    /// re-probes this exact unit (it was never marked done, so it is not
    /// in `already_done` on the next `run`) and under-counts the persisted
    /// cumulative spend by one packet relative to what was actually put on
    /// the wire -- a narrow, real gap in the packets-per-second-of-actual-
    /// wire-traffic accounting under a rare failure mode (an event log
    /// write failing mid-run), not in the packet *ceiling* (a resumed
    /// ledger still enforces its ceiling correctly against whatever it WAS
    /// told was spent; it just cannot know about spend that was never
    /// persisted at all). Closing this fully would mean making a single
    /// unit's probe-and-record idempotent under retry -- either tolerating
    /// (and de-duplicating) a repeated real probe of the same unit, or
    /// giving the store a third state between "not started" and "done"
    /// for "attempted, outcome unknown" -- either of which is a real
    /// design question disproportionate to what a log-append failure
    /// (already rare; `EventLog::append` failing means a genuine I/O
    /// error) warrants fixing in this fix wave. Documented and accepted
    /// rather than silently left implicit.
    /// M4 Task 5: `record` is now `async` and (for an `Open` outcome, with
    /// `service_detection.enabled`) does real network I/O of its own --
    /// `detect_service`'s reconnect and probe attempts -- between logging
    /// `port.state` and (if a probe found something) `service.observed`.
    ///
    /// This deliberately keeps identification serialized through the same
    /// single call site that already owns event ordering for one unit,
    /// rather than spawning it onto the `JoinSet` alongside the connect
    /// probe itself: doing so would require `ledger`/`log`/`evidence` to
    /// each be `Arc`-shared into a `'static` task (today only `log`,
    /// `store`, and `evidence` already are; `ledger` is a plain `Mutex`
    /// owned by `self`), and -- more importantly -- would reintroduce
    /// exactly the ordering race this task's ordering rule exists to
    /// forbid: two independently-scheduled tasks racing to append
    /// `port.state` and `service.observed` for the same unit with no
    /// guarantee which lands first. Keeping both appends inside one
    /// sequential call, on the single thread that already drives `record`
    /// for every unit, makes "port.state before service.observed" true by
    /// construction (AC-4.21) rather than by a timing argument. The cost is
    /// that identification for one endpoint blocks the dispatch loop from
    /// advancing to the next unit while it runs -- accepted for this task;
    /// see this task's report.
    /// M4 Task 5 fix round 1, CRITICAL-2: `cancel` is now threaded through
    /// from `run` (both call sites below pass their own `cancel`), and
    /// forwarded to `detect_service`, which is what actually refuses to
    /// start a NEW probe attempt once cancelled -- see that method's own
    /// doc comment. This matters specifically because `record` is called,
    /// unconditionally, from the post-`'drive` drain loop in `run`: that
    /// loop's whole point (module doc invariant 2) is to finish
    /// ALREADY-DISPATCHED, already-paid-for work rather than drop it, and
    /// that is still correct for the connect probe itself -- but before
    /// this fix, `record` had no way to tell "drain what's already paid
    /// for" apart from "start brand new work," so a cancellation landing
    /// while a unit's connect probe was in flight would still let
    /// `detect_service` open a fresh reconnect and write real probe bytes
    /// AFTER cancellation, for every unit the drain loop touched --
    /// `cancellation_stops_new_probe_traffic_not_just_new_units` below
    /// reproduces this with a real listener and asserts zero bytes land
    /// post-cancel.
    async fn record(
        &self,
        done: (ScanUnit, ConnectOutcome, bool),
        summary: &mut RunSummary,
        completed_batch: &mut Vec<u64>,
        cancel: &CancellationToken,
    ) -> Result<(), EngineError> {
        let (unit, outcome, local_failure) = done;
        let state = match outcome {
            ConnectOutcome::Open => PortState::Open,
            ConnectOutcome::Closed => PortState::Closed,
            ConnectOutcome::Filtered | ConnectOutcome::Unreachable => PortState::Filtered,
        };
        self.log(EventBody::PortStateObserved {
            target: Target { ip: unit.target },
            endpoint: unit.endpoint,
            state,
            evidence_refs: None,
        })?;
        if outcome == ConnectOutcome::Open {
            summary.open_ports += 1;
            // AC-4.22: `service_detection.enabled = false` must send zero
            // probe bytes -- checked here, before `detect_service` is ever
            // called, so a disabled detection setting has no path at all to
            // the reconnect it gates, not merely an early return inside it.
            if self.service_detection.enabled
                && let Some(finding) = self.detect_service(&unit, cancel).await?
            {
                self.emit_service_observed(&unit, finding)?;
            }
        }
        if local_failure {
            summary.local_resource_failures += 1;
        }
        completed_batch.push(unit.index);
        summary.units_completed += 1;
        Ok(())
    }

    /// Attempts to identify the service behind `unit`, which `record` calls
    /// only after that unit's *own* connect probe already reported
    /// [`ConnectOutcome::Open`] -- this method never itself checks
    /// reachability, only identity.
    ///
    /// Tries [`select_probes`]'s candidates, in order, stopping at the
    /// first one whose [`bathy_interpret::interpret`] result is non-empty
    /// (the brief's own Step 3 wording). A candidate that fails to connect,
    /// fails to execute (`ProbeError`), or whose capture `interpret`s to
    /// nothing is skipped, not fatal -- `detect_service` moves on to the
    /// next candidate, or returns `Ok(None)` once the candidates (or the
    /// budget, see below) are exhausted.
    ///
    /// # Budget (AC-4.24)
    ///
    /// One packet is reserved, via the exact same [`BudgetLedger`] the
    /// connect probe already spent from, immediately before each
    /// individual probe attempt's own reconnect -- never before the
    /// candidate list is chosen, and never for more than one attempt at a
    /// time. A refused reservation stops trying further probes for *this*
    /// endpoint outright; unlike a refused connect-probe reservation in the
    /// main dispatch loop (which ends the whole scan), this only ends
    /// identification for the one unit already in progress -- the
    /// connect-probe reservation gates whether a NEW unit starts at all,
    /// while this gates whether an ALREADY-`Open` unit's identification
    /// continues, which is a strictly smaller decision and does not by
    /// itself mean the ledger has nothing left for the next unit's own
    /// connect-probe reservation (that check runs independently, in the
    /// dispatch loop, before this method is ever reached for the next
    /// unit).
    ///
    /// # Scope: the second connection is gated too
    ///
    /// Re-checks `self.manifest.allows(unit.target)` before dialing the
    /// reconnect, even though `unit.target` already passed this exact check
    /// in the dispatch loop moments earlier, before the connect probe whose
    /// `Open` outcome is what led here. Not dead code: this is the same
    /// belt-and-braces posture the module doc's invariant 5 describes for
    /// every other point that is about to put a packet on the wire, applied
    /// to the one this task adds -- a service probe that trusted an earlier
    /// check to still hold, rather than re-asking, would be the exact
    /// defect M3's whole-branch review found and closed, reopened one layer
    /// up. `detect_service_refuses_to_reconnect_when_the_manifest_denies_the_target`
    /// below calls this method directly against a denying manifest and
    /// asserts zero real accepts on a live listener, independent of
    /// whatever the outer dispatch loop's own gate does.
    ///
    /// # Pacing (M4 Task 5 fix round 1, CRITICAL-1)
    ///
    /// Each probe attempt's own reconnect is paced by
    /// [`RateLimiter::acquire`] -- the SAME limiter the dispatch loop's own
    /// connect probes go through (`Scheduler::new` derives it from the
    /// ledger, M3 whole-branch review IMPORTANT-2, precisely so there is
    /// only ever one throttle to diverge from). Before this fix, this
    /// method charged the budget ledger (counted) but never called
    /// `acquire` (paced), so probe reconnects went out at whatever rate the
    /// candidate loop could physically execute, up to `intensity` (9)
    /// times the authorized instantaneous rate per open endpoint --
    /// invisible to every existing pps test because those scan closed
    /// ports, where `detect_service` never runs at all.
    /// `maximum_packets_per_second` is not merely a throughput knob: it is
    /// an AUTHORIZATION term `bathy_scope::policy::evaluate` checks a
    /// request's pps against a manifest's ceiling for -- unpaced probe
    /// traffic is unauthorized traffic, not just impolite traffic.
    /// `probe_reconnects_are_paced_by_the_rate_limiter_not_only_counted`
    /// below measures this directly (1 pps, an open endpoint, two required
    /// packets) and asserts on wall-clock elapsed time, not merely on
    /// `packets_spent`.
    ///
    /// # Cancellation (M4 Task 5 fix round 1, CRITICAL-2)
    ///
    /// Checked at the top of every loop iteration, exactly mirroring the
    /// dispatch loop's own `cancel.is_cancelled()` check at the top of
    /// `'drive`: once cancelled, this method starts no further probe
    /// attempts (no budget reservation, no rate-limiter wait, no dial) --
    /// see `record`'s own doc comment for why this is reachable even from
    /// `run`'s unconditional post-cancellation drain loop, and
    /// `cancellation_stops_new_probe_traffic_not_just_new_units` below for
    /// the test. The rate-limiter wait itself is also cancellable (a
    /// `tokio::select!`, mirroring the dispatch loop's own), so a
    /// cancellation arriving while WAITING for a token is not delayed
    /// behind it.
    async fn detect_service(
        &self,
        unit: &ScanUnit,
        cancel: &CancellationToken,
    ) -> Result<Option<ServiceFinding>, EngineError> {
        if !self.manifest.allows(unit.target) {
            return Ok(None);
        }

        let candidates = select_probes(
            unit.endpoint.port,
            self.service_detection.intensity,
            &self.probes,
        );

        for probe in candidates {
            // CRITICAL-2: no new probe attempt starts once cancelled.
            if cancel.is_cancelled() {
                break;
            }

            // CRITICAL-1: paced, not merely counted -- cancellable so a
            // cancellation arriving mid-wait is not delayed behind it.
            let acquired = tokio::select! {
                biased;
                () = cancel.cancelled() => false,
                () = self.limiter.acquire(1) => true,
            };
            if !acquired {
                break;
            }

            if self.ledger().try_spend_packets(1).is_err() {
                break;
            }

            let addr = SocketAddr::new(unit.target, unit.endpoint.port);
            let dial =
                tokio::time::timeout(self.config.connect_timeout, TcpStream::connect(addr)).await;
            let Ok(Ok(stream)) = dial else {
                continue;
            };

            let mut io = ProbeIo::new(stream, unit.endpoint.port, self.config.connect_timeout);
            let Ok(capture) = probe.execute(&mut io).await else {
                continue;
            };

            let Some(top) = interpret(&capture).into_iter().next() else {
                continue;
            };

            return Ok(Some(ServiceFinding {
                observation: top.observation,
                evidence: capture.response,
                probe_id: capture.probe_id,
            }));
        }

        Ok(None)
    }

    /// Stores `finding`'s evidence, THEN appends `service.observed` citing
    /// the resulting digest -- see this module's own ordering rule at the
    /// top of this file. A crash between the two leaves an orphaned blob
    /// (harmless: nothing ever cited it); the reverse would leave a
    /// `service.observed` whose `evidence_refs` entry no `EvidenceStore::get`
    /// call could ever resolve, which is the exact failure this whole
    /// design exists to prevent.
    ///
    /// `EvidenceLevel::None` returns `Ok(())` immediately, storing nothing
    /// and appending nothing (AC-4.23). This is not a special case bolted
    /// on here -- it follows directly from `EventBody::ServiceObserved::
    /// evidence_refs` being `NonEmpty<Digest>`: with no bytes stored there
    /// is no digest to cite, and a `service.observed` finding without
    /// evidence is unrepresentable by that type. The alternative -- inventing
    /// a placeholder digest, or relaxing the field to `Option<NonEmpty<Digest>>`
    /// -- would let a finding exist with nothing backing it, which is the
    /// provenance guarantee this whole crate is built to uphold.
    fn emit_service_observed(
        &self,
        unit: &ScanUnit,
        finding: ServiceFinding,
    ) -> Result<(), EngineError> {
        let cap = match self.evidence_level {
            EvidenceLevel::None => return Ok(()),
            EvidenceLevel::Headers => 8 * 1024,
            EvidenceLevel::Full => 64 * 1024,
        };
        // Ordering is mandatory: `put_capped` (store) runs to completion,
        // its `?` checked, BEFORE `self.log(...)` (append) is ever called.
        let (digest, _truncated) = self.evidence.put_capped(&finding.evidence, cap)?;
        self.log(EventBody::ServiceObserved {
            target: Target { ip: unit.target },
            endpoint: unit.endpoint,
            observation: finding.observation,
            evidence_refs: NonEmpty::new(digest),
            probe_id: finding.probe_id.to_string(),
        })?;
        Ok(())
    }

    /// Forces the log durable, then flushes `completed` to the `TaskStore`
    /// resumption cursor (`mark_units_done`), then -- only once at least
    /// `progress_every` units have completed since the last emission --
    /// appends one `scan.progress` event (AC-3.30) and clears `completed`.
    ///
    /// # Ordering (M3 whole-branch review, CRITICAL-2)
    ///
    /// `self.log_guard().force_sync()` runs FIRST, unconditionally, before
    /// `mark_units_done` -- never the other way around. `mark_units_done`
    /// is a genuinely fsync'd SQLite commit (`synchronous=FULL`), and
    /// `bathy-evidence/src/lib.rs`'s own module doc calls the event log
    /// "the source of truth for a scan; SQLite state ... is a derived
    /// index rebuildable from it, never the other way around." An earlier
    /// version of this method called `mark_units_done` first and left the
    /// log's own `force_sync` to run only once, at the very end of `run` --
    /// which meant a crash between the two could leave the store durably
    /// reporting units complete that the log had not yet issued a single
    /// real `fsync` for at all. On resume, `already_done` (loaded from
    /// exactly what `mark_units_done` persisted) would then skip those
    /// units forever, permanently discarding observations the log never
    /// actually held durably in the first place -- the exact inversion the
    /// M2 durability contract ("never invert this") was written to
    /// prevent, just against a component M2 never had (one that writes
    /// both the log and the store). **The cursor `mark_units_done`/
    /// `record_progress` advance is durable only after the events it
    /// certifies are.** Costs one extra `fsync` per `STORE_FLUSH_BATCH`
    /// (64) units on top of whatever `GroupCommitLog`'s own bounded
    /// trigger would have done anyway.
    ///
    /// Two tests pin two different halves of this, deliberately not just
    /// one: `flush_progress_forces_a_log_sync_before_the_store_durably_marks_units_done`
    /// below proves a real sync is genuinely happening on this path at all
    /// (a concurrent observer never sees the store show completed units
    /// while `log.sync_calls()` is still zero) -- but M3 whole-branch
    /// RE-review found that test alone is decoration against the literal
    /// inversion this doc comment describes: `flush_progress` has no
    /// `.await` inside it, so swapping the two calls' *order* back (while
    /// keeping both present) is invisible to any concurrent poller, and a
    /// real crash between the two lines needs no `.await` point to
    /// reproduce. `a_failed_force_sync_leaves_the_store_resumption_cursor_untouched`
    /// is the test that actually pins the ORDER: it forces `force_sync`
    /// itself to fail (via the test-only `GroupCommitLog::fail_next_sync_for_tests`)
    /// and asserts `mark_units_done` never ran at all -- the property this
    /// paragraph claims -- which is only true if `force_sync` is called,
    /// and its `?` checked, BEFORE `mark_units_done`, not merely somewhere
    /// in the same function.
    ///
    /// `units_completed` is passed by value rather than borrowing
    /// `RunSummary` so this can run interleaved with `record`'s own `&mut
    /// RunSummary` borrow without a conflict; `packets_spent` is read fresh
    /// from the ledger rather than from `RunSummary` (whose own
    /// `packets_spent` field is only ever set once, at the very end of
    /// `run`) for the same reason.
    fn flush_progress(
        &self,
        completed: &mut Vec<u64>,
        units_completed: u64,
        last_progress_emitted_at: &mut u64,
        estimated_probes: u64,
        started: Instant,
    ) -> Result<(), EngineError> {
        if completed.is_empty() {
            return Ok(());
        }
        // CRITICAL-2: durable before durable-claimed-durable. See this
        // method's own doc comment. The `?` here is also why the ORDER
        // (not just the presence) of this call matters, not only for a
        // concurrent observer: if `force_sync` itself fails, this returns
        // before `mark_units_done` ever runs, so a failed sync can never
        // be followed by the store claiming the units it was supposed to
        // certify are durably done anyway.
        self.log_guard().force_sync()?;
        self.store.mark_units_done(self.scan_id, completed)?;
        if units_completed.saturating_sub(*last_progress_emitted_at)
            >= self.config.progress_every.max(1)
        {
            let packets_spent = self.ledger().packets_spent();
            self.log(EventBody::Progress {
                probes_sent: units_completed,
                probes_total: estimated_probes,
                packets_spent,
            })?;
            *last_progress_emitted_at = units_completed;
        }
        // C4 (M2): keep the cached resumption cursor (`scans.last_sequence`/
        // `packets_spent`/`elapsed_seconds`) in step with reality at the
        // same cadence as the unit-progress flush, rather than leaving
        // `record_progress` -- written for exactly this purpose and, before
        // M3 Task 7, called nowhere in the codebase outside its own tests --
        // permanently unused. `elapsed_seconds` (fix round 1, CRITICAL-2) is
        // what a future resume's fresh `BudgetLedger::resumed` seeds its
        // runtime baseline from.
        let last_sequence = self.log_guard().last_sequence();
        let packets_spent = self.ledger().packets_spent();
        self.store.record_progress(
            self.scan_id,
            last_sequence,
            packets_spent,
            self.total_elapsed_seconds(started),
        )?;
        completed.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, HashMap};
    use std::sync::atomic::{AtomicU64, Ordering};

    use tokio::net::{TcpListener, TcpStream};

    use bathy_evidence::EvidenceStore;
    use bathy_probe::ProbeRegistry;
    use bathy_store::StartRequest;
    use bathy_types::clock::FixedClock;
    use bathy_types::event::{Endpoint, Event, PortState, Transport};
    use bathy_types::ids::ScopeId;
    use bathy_types::nonempty::NonEmpty;
    use bathy_types::request::{
        Budgets, EvidenceLevel, Objective, PortSelection, ScanRequest, ServiceDetection,
    };

    // ------------------------------------------------------------------
    // Test harness. The brief's own Step 1 tests reference `harness(...)`,
    // `harness_with_many_units(...)`, `harness_with_packet_budget(...)`,
    // `h.run_to_completion()`, `h.log`, `h.store`, `h.plan`, `h.scan_id`,
    // `h.probed_indices()`, and `open_port()` without ever defining any of
    // them -- the brief is explicit that Step 3 is a sketch, not complete
    // code, and this harness is exactly the kind of gap that leaves for the
    // implementer to fill in. Built directly on real `TaskStore`/
    // `GroupCommitLog` instances (a real temp-dir SQLite file, a real JSONL
    // log) and real loopback sockets, not mocks -- matching every other
    // crate in this workspace's own test style.
    // ------------------------------------------------------------------

    fn scope_id() -> ScopeId {
        "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap()
    }

    fn budgets(packets: u64, runtime_seconds: u64, pps: u32) -> Budgets {
        Budgets {
            maximum_packets: packets,
            maximum_runtime_seconds: runtime_seconds,
            maximum_packets_per_second: pps,
        }
    }

    /// Binds a listener on 127.0.0.1 and spawns a background task that
    /// accepts (and immediately drops) every connection for as long as the
    /// test's runtime lives, then returns the bound port -- a plan unit
    /// addressing it resolves to `ConnectOutcome::Open`.
    async fn open_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                drop(s);
            }
        });
        port
    }

    /// Binds `n` real listeners on 127.0.0.1, each with its own accept
    /// counter, builds a harness whose plan addresses exactly those `n`
    /// ports, and returns both. The counter map is the real-accept-count
    /// ground truth several tests in this module need instead of (or
    /// alongside) a `BudgetLedger`/`TaskStore`-derived count: neither of
    /// those can distinguish correct behavior from one that only *looks*
    /// correct through its own accounting -- see CRITICAL-1 and CRITICAL-2
    /// in this task's fix-round-1 report.
    async fn harness_with_real_listeners(
        n: u64,
        budgets: Budgets,
        config: SchedulerConfig,
    ) -> (Harness, HashMap<u16, Arc<AtomicU64>>) {
        let mut counts: HashMap<u16, Arc<AtomicU64>> = HashMap::new();
        let mut ports: Vec<u16> = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let counter = Arc::new(AtomicU64::new(0));
            counts.insert(port, Arc::clone(&counter));
            ports.push(port);
            tokio::spawn(async move {
                while let Ok((s, _)) = listener.accept().await {
                    counter.fetch_add(1, Ordering::SeqCst);
                    drop(s);
                }
            });
        }
        let specs: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
        let spec_refs: Vec<&str> = specs.iter().map(String::as_str).collect();
        let h = make_harness(
            &["127.0.0.1"],
            &spec_refs,
            budgets,
            config,
            default_manifest(),
        );
        (h, counts)
    }

    /// Like [`harness_with_real_listeners`], but with a caller-chosen
    /// `service_detection` instead of this module's own default -- what
    /// `intensity_bounds_how_many_probe_candidates_are_attempted_not_a_hardcoded_value`
    /// below needs: a real accept counter is the only way to tell "the
    /// scheduler asked for exactly this many probe candidates" from "it
    /// asked for some hardcoded number that happens to look similar."
    async fn harness_with_real_listeners_and_detection(
        n: u64,
        budgets: Budgets,
        config: SchedulerConfig,
        service_detection: ServiceDetection,
    ) -> (Harness, HashMap<u16, Arc<AtomicU64>>) {
        let mut counts: HashMap<u16, Arc<AtomicU64>> = HashMap::new();
        let mut ports: Vec<u16> = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let counter = Arc::new(AtomicU64::new(0));
            counts.insert(port, Arc::clone(&counter));
            ports.push(port);
            tokio::spawn(async move {
                while let Ok((s, _)) = listener.accept().await {
                    counter.fetch_add(1, Ordering::SeqCst);
                    drop(s);
                }
            });
        }
        let specs: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
        let spec_refs: Vec<&str> = specs.iter().map(String::as_str).collect();
        let h = make_harness_with_detection(
            &["127.0.0.1"],
            &spec_refs,
            budgets,
            config,
            default_manifest(),
            service_detection,
            EvidenceLevel::Headers,
        );
        (h, counts)
    }

    /// Waits (bounded, polling -- never a blind fixed sleep) until the sum
    /// of `counts` reaches `expected_total`, or gives up after a generous
    /// ceiling. Every test in this module runs many acceptor tasks
    /// alongside real scheduler work on a single-threaded executor; a
    /// straggler that simply has not been polled yet (even though the
    /// underlying TCP handshake already completed at the kernel level) must
    /// get a chance to catch up before an assertion reads the counters, or
    /// the assertion is testing executor scheduling luck, not this crate.
    async fn settle_accept_counters(counts: &HashMap<u16, Arc<AtomicU64>>, expected_total: u64) {
        for _ in 0..500 {
            let total: u64 = counts.values().map(|c| c.load(Ordering::SeqCst)).sum();
            if total >= expected_total {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    struct Harness {
        _dir: tempfile::TempDir,
        scheduler: Scheduler,
        plan: ScanPlan,
        store: Arc<TaskStore>,
        log: Arc<Mutex<GroupCommitLog>>,
        scan_id: ScanId,
        /// The SAME `Arc<dyn Clock>` the harness's own `TaskStore`/`Scheduler`
        /// share -- exposed so a test can build a SECOND, independent
        /// `Scheduler` (a fresh `BudgetLedger`, e.g. via
        /// `BudgetLedger::resumed`) against the same scan without violating
        /// the C2/M2 one-clock-per-scan requirement (M3 Task 7 fix round 1,
        /// CRITICAL-2's own tests need exactly this).
        clock: Arc<dyn Clock>,
        /// The SAME manifest `scheduler` was built with -- exposed so
        /// `resume` can build a second `Scheduler` against the same
        /// authorization boundary without a caller having to thread it
        /// through separately (M3 whole-branch review, CRITICAL-1).
        manifest: Arc<ScopeManifest>,
        /// M4 Task 5: the SAME evidence store `scheduler` writes matched
        /// probe evidence into -- exposed so a test can call
        /// `EvidenceStore::contains`/`get` directly against whatever digest
        /// a `service.observed` event cited, without reopening a second
        /// store over the same directory.
        evidence: Arc<EvidenceStore>,
        /// M4 Task 5: the exact `ServiceDetection`/`EvidenceLevel` this
        /// harness's `scheduler` was built with -- exposed so `resume`
        /// (below) can build a second `Scheduler` for the same scan without
        /// silently reverting to different detection settings.
        service_detection: ServiceDetection,
        evidence_level: EvidenceLevel,
        /// M4 Task 5: the SAME probe registry `scheduler` was built with.
        probes: Arc<ProbeRegistry>,
    }

    impl Harness {
        async fn run_to_completion(&self) -> Result<RunSummary, EngineError> {
            self.scheduler
                .run(&self.plan, 0, CancellationToken::new())
                .await
        }

        fn events(&self) -> Vec<Event> {
            self.log.lock().unwrap().read_from(0).unwrap()
        }

        fn probed_indices(&self) -> Vec<u64> {
            self.store.completed_units(self.scan_id).unwrap()
        }

        /// M4 Task 5: the number of real blob files under this harness's
        /// evidence store's `blobs/` directory -- a filesystem-level count,
        /// not derived from the event log at all, so
        /// `evidence_level_none_stores_no_blobs_and_therefore_emits_no_service_observed`
        /// below can prove "zero blobs on disk" directly rather than only
        /// via the log's own absence of a citing event (which the type
        /// system already makes redundant -- see `emit_service_observed`'s
        /// own doc comment). Counts regular files only, skipping the
        /// `.tmp-*` names `EvidenceStore::put` uses for its
        /// write-then-rename staging (see `bathy_evidence::store`'s own doc
        /// comment) -- none should ever survive a clean test run, but a
        /// panic mid-`put` in some OTHER test sharing this process could
        /// theoretically leave one behind on a shared temp root, and this
        /// helper should not miscount because of that.
        fn evidence_blob_count(&self) -> u64 {
            fn walk(dir: &std::path::Path, count: &mut u64) {
                let Ok(entries) = std::fs::read_dir(dir) else {
                    return;
                };
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        walk(&path, count);
                    } else if !path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with(".tmp-"))
                    {
                        *count += 1;
                    }
                }
            }
            let mut count = 0;
            walk(&self.evidence_root(), &mut count);
            count
        }

        fn evidence_root(&self) -> std::path::PathBuf {
            self._dir.path().join("blobs")
        }

        /// Builds a SECOND, independent `Scheduler` for the SAME scan --
        /// same store, log, clock, scan_id -- but with a FRESH
        /// `BudgetLedger` seeded from whatever `record_progress` has
        /// currently persisted, via `BudgetLedger::resumed`. This is the
        /// shape a real resume takes: a new process (or at minimum a new
        /// `Scheduler`) picking up a scan a previous, cancelled run left
        /// off, and it is what M3 Task 7 fix round 1's CRITICAL-2 tests
        /// exercise -- a naive `BudgetLedger::new(budgets)` here would
        /// reproduce the exact hole the review found.
        /// M3 whole-branch review, CRITICAL-1: no separate `limiter_pps`
        /// parameter any more -- `budgets` alone determines the resumed
        /// scheduler's real throttle (IMPORTANT-2), and `manifest` reuses
        /// the SAME authorization boundary `self.scheduler` was built with,
        /// via the `manifest` field above.
        fn resume(&self, config: SchedulerConfig, budgets: Budgets) -> Scheduler {
            let record = self.store.get(self.scan_id).unwrap().unwrap();
            let ledger =
                BudgetLedger::resumed(budgets, record.packets_spent, record.elapsed_seconds);
            Scheduler::new(
                ledger,
                Arc::clone(&self.manifest),
                config,
                Arc::clone(&self.log),
                Arc::clone(&self.store),
                Arc::clone(&self.clock),
                self.scan_id,
                "0.1.0",
                self.service_detection,
                self.evidence_level,
                Arc::clone(&self.evidence),
                Arc::clone(&self.probes),
            )
        }
    }

    /// Like `make_harness`, but with a caller-chosen `GroupCommitConfig`.
    /// `make_harness` itself just delegates here with the default config;
    /// this is broken out only because ONE test below
    /// (`flush_progress_forces_a_log_sync_before_the_store_durably_marks_units_done`,
    /// CRITICAL-1's durability-ordering sibling, CRITICAL-2) needs to
    /// eliminate every OTHER source of a real log sync to isolate the
    /// mechanism it is actually testing.
    fn make_harness_with_group_commit(
        targets: &[&str],
        port_specs: &[&str],
        budgets: Budgets,
        config: SchedulerConfig,
        manifest: Arc<ScopeManifest>,
        group_commit: GroupCommitConfig,
    ) -> Harness {
        make_harness_core(
            targets,
            port_specs,
            budgets,
            config,
            manifest,
            group_commit,
            ServiceDetection::default(),
            EvidenceLevel::Headers,
        )
    }

    /// Like [`make_harness`], but with caller-chosen `service_detection`/
    /// `evidence_level` instead of this module's own defaults
    /// (`ServiceDetection::default()`, `EvidenceLevel::Headers`) -- what
    /// every M4 Task 5 test that needs detection disabled, a tighter
    /// intensity, or `EvidenceLevel::None` builds its harness with.
    fn make_harness_with_detection(
        targets: &[&str],
        port_specs: &[&str],
        budgets: Budgets,
        config: SchedulerConfig,
        manifest: Arc<ScopeManifest>,
        service_detection: ServiceDetection,
        evidence_level: EvidenceLevel,
    ) -> Harness {
        make_harness_core(
            targets,
            port_specs,
            budgets,
            config,
            manifest,
            GroupCommitConfig::default(),
            service_detection,
            evidence_level,
        )
    }

    /// The one real builder every `make_harness*` function above funnels
    /// into. Broken out (M4 Task 5) so adding `service_detection`/
    /// `evidence_level` knobs did not require touching either of this
    /// module's two pre-existing, widely-called builders' own signatures --
    /// every call site written before this task keeps compiling unchanged,
    /// getting this module's own defaults exactly as before.
    #[allow(clippy::too_many_arguments)]
    fn make_harness_core(
        targets: &[&str],
        port_specs: &[&str],
        budgets: Budgets,
        config: SchedulerConfig,
        manifest: Arc<ScopeManifest>,
        group_commit: GroupCommitConfig,
        service_detection: ServiceDetection,
        evidence_level: EvidenceLevel,
    ) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        // One shared `Arc<dyn Clock>` for both `TaskStore` and every
        // `GroupCommitLog::append` call this scheduler makes -- the M2/C2
        // requirement this task's dispatch carries forward: two
        // independently-constructed clocks means two ULID generators and a
        // real identifier-collision risk.
        let clock: Arc<dyn Clock> =
            Arc::new(FixedClock::new("2026-08-01T15:04:31.182Z", 7).unwrap());
        let store = Arc::new(TaskStore::open(dir.path(), Arc::clone(&clock)).unwrap());

        let request = ScanRequest {
            targets: NonEmpty::try_from(targets.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap(),
            authorization_scope_id: scope_id(),
            objective: Objective::InventoryExposedServices,
            ports: PortSelection::Explicit {
                explicit: NonEmpty::try_from(
                    port_specs.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                )
                .unwrap(),
            },
            service_detection,
            budgets,
            evidence_level,
            idempotency_key: "harness-key".into(),
        };
        let plan = ScanPlan::build(&request, 1_000_000).unwrap();

        let outcome = store
            .start_or_reuse(&StartRequest {
                idempotency_key: request.idempotency_key.clone(),
                plan_hash: plan.hash(),
                scope_id: request.authorization_scope_id,
                request_json: "{}".to_string(),
                estimated_targets: plan.targets().len() as u64,
                estimated_probes: plan.len(),
            })
            .unwrap();
        let scan_id = outcome.scan_id();

        let log = Arc::new(Mutex::new(
            GroupCommitLog::open(dir.path(), scan_id, group_commit).unwrap(),
        ));
        // M4 Task 5: opened at the SAME root the harness's own `TempDir`
        // owns -- `EvidenceStore::open` creates its own `blobs/`
        // subdirectory there, alongside the log and SQLite files, with no
        // name collision (see `bathy_evidence::store`'s own layout).
        let evidence = Arc::new(EvidenceStore::open(dir.path()).unwrap());
        let probes = Arc::new(ProbeRegistry::standard());

        let ledger = BudgetLedger::new(budgets);
        let scheduler = Scheduler::new(
            ledger,
            Arc::clone(&manifest),
            config,
            Arc::clone(&log),
            Arc::clone(&store),
            Arc::clone(&clock),
            scan_id,
            "0.1.0",
            service_detection,
            evidence_level,
            Arc::clone(&evidence),
            Arc::clone(&probes),
        );

        Harness {
            _dir: dir,
            scheduler,
            plan,
            store,
            log,
            scan_id,
            clock,
            manifest,
            evidence,
            service_detection,
            evidence_level,
            probes,
        }
    }

    fn make_harness(
        targets: &[&str],
        port_specs: &[&str],
        budgets: Budgets,
        config: SchedulerConfig,
        manifest: Arc<ScopeManifest>,
    ) -> Harness {
        make_harness_with_group_commit(
            targets,
            port_specs,
            budgets,
            config,
            manifest,
            GroupCommitConfig::default(),
        )
    }

    /// The manifest every helper in this module builds a `Scheduler` with,
    /// unless a test specifically needs a different one (the CRITICAL-1/
    /// IMPORTANT-1 "denied" tests below do, via
    /// `manifest_denying_loopback`). Built via
    /// `ScopeManifest::for_tests_allowing_loopback` -- see that
    /// constructor's own doc comment for why: virtually every test in this
    /// module drives real `127.0.0.1` sockets, which `ScopeManifest::allows`
    /// refuses categorically outside of this one, explicitly named,
    /// test-only exception (M3 whole-branch review, CRITICAL-1's own "the
    /// loopback problem is yours to solve for the tests" wrinkle -- every
    /// scheduler test in this module scans a refused address, so leaving
    /// this unsolved would mean CRITICAL-1's own fix could never pass this
    /// module's suite at all).
    fn default_manifest() -> Arc<ScopeManifest> {
        Arc::new(
            ScopeManifest::for_tests_allowing_loopback(
                r#"{
                  "id": "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV",
                  "description": "bathy-engine scheduler test fixture -- loopback allowed only via for_tests_allowing_loopback",
                  "not_after": "2099-01-01T00:00:00.000Z",
                  "allowed_cidrs": ["127.0.0.1/32"],
                  "budget_ceiling": {
                    "maximum_packets": 100000000,
                    "maximum_runtime_seconds": 100000000,
                    "maximum_packets_per_second": 100000000
                  }
                }"#,
            )
            .unwrap(),
        )
    }

    /// A manifest matching `scope_id()` that authorizes an unrelated subnet
    /// only, built through the ORDINARY, non-test `ScopeManifest::load` --
    /// `allows(127.0.0.1)` is `false` here for exactly the reason it would
    /// be for any real manifest scoped away from loopback, nothing to do
    /// with this module's own loopback exception. Used by the CRITICAL-1
    /// and IMPORTANT-1 "denied" tests below, which target 127.0.0.1
    /// specifically to prove the scheduler's own per-unit re-check -- not
    /// this test harness's loopback allowance -- is what refuses it.
    fn manifest_denying_loopback() -> Arc<ScopeManifest> {
        Arc::new(
            ScopeManifest::load(
                r#"{
                  "id": "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV",
                  "description": "CRITICAL-1 fixture: authorizes an unrelated subnet only",
                  "not_after": "2099-01-01T00:00:00.000Z",
                  "allowed_cidrs": ["10.30.0.0/24"],
                  "budget_ceiling": {
                    "maximum_packets": 1000000,
                    "maximum_runtime_seconds": 3600,
                    "maximum_packets_per_second": 1000000
                  }
                }"#,
            )
            .unwrap(),
        )
    }

    /// Re-opens a FRESH `TaskStore` against the harness's own database
    /// directory and reads back `scan_id`'s status -- proving IMPORTANT-1's
    /// fix persists (survives a reopen/reconnect), not merely that the
    /// harness's own already-open `Arc<TaskStore>` reflects an in-memory
    /// write.
    fn reopened_status(h: &Harness) -> TaskStatus {
        let reopened = TaskStore::open(h._dir.path(), Arc::clone(&h.clock)).unwrap();
        reopened.get(h.scan_id).unwrap().unwrap().status
    }

    /// M3 whole-branch re-review (Global Constraint, item 1): a manifest
    /// that would otherwise authorize loopback (via
    /// `for_tests_allowing_loopback`, matching `default_manifest`'s own
    /// shape) but carries a DIFFERENT `id` than `scope_id()` -- the value
    /// every harness's `ScanRequest.authorization_scope_id` (and therefore
    /// the scan record's own `scope_id` column) is built with. Proves
    /// `run`'s scope-identity check, not the allow-set match: this
    /// manifest's `allowed_cidrs` would happily let a 127.0.0.1 target
    /// through if scope identity weren't checked first.
    fn manifest_for_a_different_scope() -> Arc<ScopeManifest> {
        Arc::new(
            ScopeManifest::for_tests_allowing_loopback(
                r#"{
                  "id": "scope_01ARZ3NDEKTSV4RRFFQ69G5FBW",
                  "description": "Global Constraint fixture: right shape, wrong scope",
                  "not_after": "2099-01-01T00:00:00.000Z",
                  "allowed_cidrs": ["127.0.0.1/32"],
                  "budget_ceiling": {
                    "maximum_packets": 1000000,
                    "maximum_runtime_seconds": 3600,
                    "maximum_packets_per_second": 1000000
                  }
                }"#,
            )
            .unwrap(),
        )
    }

    /// M3 whole-branch re-review (Global Constraint, item 1): a manifest
    /// matching `scope_id()` and otherwise identical in shape to
    /// `default_manifest` (loopback allowed via `for_tests_allowing_loopback`),
    /// except `not_after` is years in the past -- `is_expired` against any
    /// `FixedClock` seed this module uses (all fixed to `2026-08-01...`)
    /// returns `true`. Proves `run`'s expiry check, not the scope-identity
    /// or allow-set checks.
    fn expired_manifest_allowing_loopback() -> Arc<ScopeManifest> {
        Arc::new(
            ScopeManifest::for_tests_allowing_loopback(
                r#"{
                  "id": "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV",
                  "description": "Global Constraint fixture: right scope, expired",
                  "not_after": "2020-01-01T00:00:00.000Z",
                  "allowed_cidrs": ["127.0.0.1/32"],
                  "budget_ceiling": {
                    "maximum_packets": 1000000,
                    "maximum_runtime_seconds": 3600,
                    "maximum_packets_per_second": 1000000
                  }
                }"#,
            )
            .unwrap(),
        )
    }

    fn small_config() -> SchedulerConfig {
        SchedulerConfig {
            concurrency: 32,
            connect_timeout: Duration::from_millis(500),
            progress_every: 500,
        }
    }

    fn harness(targets: &[&str], ports: &[u16]) -> Harness {
        let specs: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
        let spec_refs: Vec<&str> = specs.iter().map(String::as_str).collect();
        make_harness(
            targets,
            &spec_refs,
            budgets(1_000_000, 3_600, 1_000_000),
            small_config(),
            default_manifest(),
        )
    }

    /// A single target with `n` distinct closed ports (an unbound range, so
    /// every probe resolves near-instantly via `ECONNREFUSED`), paced by a
    /// deliberately modest rate limiter (`RateLimiter`'s capacity equals its
    /// configured pps, so a burst covering all of `n` at once would let the
    /// whole scan finish before a test could ever observe it mid-flight --
    /// see `cancellation_stops_promptly_and_leaves_a_resumable_cursor` and
    /// `progress_events_are_emitted_periodically_during_a_long_scan` below,
    /// which both depend on this). M3 whole-branch review, IMPORTANT-2: the
    /// pacing value now lives directly in `Budgets.maximum_packets_per_second`
    /// (there is no longer a separate limiter-pps parameter to diverge from
    /// it -- `Scheduler::new` derives its limiter from the ledger).
    fn harness_with_many_units(n: u64) -> Harness {
        let end = 20_000 + n - 1;
        let spec = format!("20000-{end}");
        make_harness(
            &["127.0.0.1"],
            &[spec.as_str()],
            budgets(1_000_000, 3_600, 1_000),
            SchedulerConfig {
                concurrency: 64,
                connect_timeout: Duration::from_millis(300),
                progress_every: 500,
            },
            default_manifest(),
        )
    }

    fn harness_with_packet_budget(budget: u64) -> Harness {
        make_harness(
            &["127.0.0.1"],
            &["20000-29999"], // 10,000 ports: "thousands of units" against a ceiling of `budget`
            budgets(budget, 3_600, 1_000_000),
            small_config(),
            default_manifest(),
        )
    }

    // ------------------------------------------------------------------
    // Brief's Step 1 tests, adapted to a real harness.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn a_completed_run_emits_started_then_states_then_completed() {
        let port = open_port().await;
        let h = harness(&["127.0.0.1"], &[port]);
        let summary = h.run_to_completion().await.unwrap();
        let events = h.events();
        assert!(matches!(
            events.first().unwrap().body,
            EventBody::ScanStarted { .. }
        ));
        assert!(matches!(
            events.last().unwrap().body,
            EventBody::ScanCompleted { .. }
        ));
        assert_eq!(summary.units_completed, 1);
    }

    // Real-time sleep, flagged per the dispatch's instruction: this exactly
    // mirrors the brief's own Step 1 test, and converting it to
    // `tokio::time::pause`d virtual time is not practical here -- the
    // 5,000-unit scan involves real loopback socket I/O whose completion
    // the paused clock does not control, so pausing time would not make
    // this deterministic, only decouple the 100ms delay from wall-clock
    // reality while the actual race (does cancellation land before the
    // scan finishes) stays exactly as real-time-dependent as before.
    // `harness_with_many_units`'s deliberately-paced rate limiter (see its
    // own doc comment) is what actually makes this reliable rather than
    // flaky, by guaranteeing the scan cannot finish faster than real
    // network/dispatch overhead would allow regardless of machine speed.
    #[tokio::test]
    async fn cancellation_stops_promptly_and_leaves_a_resumable_cursor() {
        let h = harness_with_many_units(5_000);
        let cancel = CancellationToken::new();
        let c = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            c.cancel();
        });
        let summary = h.scheduler.run(&h.plan, 0, cancel).await.unwrap();
        assert!(summary.cancelled);
        assert!(
            summary.units_completed < h.plan.len(),
            "must not have finished"
        );
        assert!(summary.units_completed > 0, "must have made progress");
        let next = h.store.next_pending_unit(h.scan_id, h.plan.len()).unwrap();
        assert!(next.is_some(), "a cancelled scan must leave a resume point");
    }

    // M3 Task 7 fix round 1, IMPORTANT-2: the test above only caught the
    // reviewer's `if summary.cancelled { in_flight.abort_all(); }` mutation
    // 7 times out of 8 -- nothing guarantees a probe is genuinely still
    // unresolved (as opposed to merely undrained-but-already-finished) at
    // the moment cancellation lands, so roughly 1 run in 8 raced the wrong
    // way and passed vacuously either way. This test makes that
    // deterministic: fill a listener's accept queue (the same technique
    // `connect.rs`'s own tests use) so the ONE dispatched probe below
    // cannot possibly resolve before its `connect_timeout` -- set far
    // longer than the real delay before cancellation fires -- guaranteeing
    // it is genuinely still in flight, not just probably so, when `cancel`
    // is observed.
    #[tokio::test]
    async fn cancellation_drains_a_probe_that_is_genuinely_still_unresolved() {
        // Two ports, each with its own accept queue filled (the same
        // technique `connect.rs`'s own tests use), so a probe against
        // either one cannot possibly resolve before its `connect_timeout`
        // -- set far longer than the delay before cancellation fires below,
        // so it is provably still in flight, not merely likely to be.
        //
        // `concurrency: 1` is what makes this deterministic rather than a
        // repeat of the ORIGINAL flaky test (a single-unit plan naturally
        // exhausts via "no more units" on its very next loop iteration
        // regardless of cancellation timing, since there is nothing left to
        // fetch -- confirmed empirically, that version never set
        // `summary.cancelled` at all). With concurrency 1, unit 0 dispatches
        // immediately and holds the only permit for 800ms; unit 1's
        // dispatch attempt then genuinely BLOCKS waiting for a permit, and
        // cancellation (20ms) wins that wait -- landing on the exact
        // cancellable-`select!` branch that sets `summary.cancelled = true`
        // -- while unit 0 is left genuinely, provably still unresolved in
        // `in_flight` for the drain step to pick up.
        let mut full_ports = Vec::new();
        let mut held = Vec::new();
        // `listeners` keeps every bound socket alive for the rest of the
        // test: a `TcpListener` that goes out of scope is dropped, which
        // unbinds the port -- any further connect (including the
        // scheduler's own probes below) then gets an immediate
        // `ECONNREFUSED` instead of hanging against the still-full backlog,
        // which is exactly what made an earlier version of this test flake
        // (both probes "completed" in ~7ms with `cancelled: false` instead
        // of ever actually hanging).
        let mut listeners = Vec::new();
        for _ in 0..2 {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let mut filled = false;
            for _ in 0..256 {
                match tokio::time::timeout(Duration::from_millis(150), TcpStream::connect(addr))
                    .await
                {
                    Ok(Ok(s)) => held.push(s),
                    _ => {
                        filled = true;
                        break;
                    }
                }
            }
            assert!(filled, "setup: expected the accept queue to fill");
            full_ports.push(addr.port());
            listeners.push(listener);
        }

        let specs: Vec<String> = full_ports.iter().map(|p| p.to_string()).collect();
        let spec_refs: Vec<&str> = specs.iter().map(String::as_str).collect();
        let h = make_harness(
            &["127.0.0.1"],
            &spec_refs,
            budgets(1_000_000, 3_600, 1_000_000),
            SchedulerConfig {
                concurrency: 1,
                connect_timeout: Duration::from_millis(800),
                progress_every: 500,
            },
            default_manifest(),
        );
        assert_eq!(h.plan.len(), 2);

        let cancel = CancellationToken::new();
        let c = cancel.clone();
        tokio::spawn(async move {
            // Enough for unit 0 to dispatch and unit 1's permit wait to
            // genuinely begin; nowhere near enough for either probe to
            // resolve on its own (800ms above).
            tokio::time::sleep(Duration::from_millis(20)).await;
            c.cancel();
        });

        let summary = h.scheduler.run(&h.plan, 0, cancel).await.unwrap();
        assert!(summary.cancelled);
        assert_eq!(
            summary.units_completed, 1,
            "unit 0, genuinely still in flight when cancellation fired, must be \
             drained and recorded, not dropped; unit 1 must never have been \
             dispatched at all"
        );
        assert_eq!(h.probed_indices(), vec![0]);
        drop(held);
        drop(listeners);
    }

    #[tokio::test]
    async fn exhausting_the_packet_budget_stops_the_scan_and_records_why() {
        let h = harness_with_packet_budget(10);
        let summary = h.run_to_completion().await.unwrap();
        assert!(summary.budget_exhausted);
        assert!(
            summary.packets_spent <= 10,
            "spent {} over a ceiling of 10",
            summary.packets_spent
        );
        let events = h.events();
        assert!(events.iter().any(|e| matches!(
            &e.body, EventBody::ScanFailed { reason_code, .. } if reason_code == "budget_exhausted"
        )));
    }

    #[tokio::test]
    async fn resuming_skips_completed_units_and_never_repeats_one() {
        let h = harness_with_many_units(200);
        h.store
            .mark_units_done(h.scan_id, &(0..50).collect::<Vec<_>>())
            .unwrap();
        // `h.probed_indices()` reports every index EVER marked done for this
        // scan_id, including the 0..50 pre-marked directly above (which
        // never went through the scheduler at all) -- so what this test
        // actually needs is the DELTA this specific `run()` call produces,
        // not the raw accumulated store state.
        let before: BTreeSet<u64> = h.probed_indices().into_iter().collect();
        let start = h
            .store
            .next_pending_unit(h.scan_id, h.plan.len())
            .unwrap()
            .unwrap();
        assert_eq!(start, 50);
        let summary = h
            .scheduler
            .run(&h.plan, start, CancellationToken::new())
            .await
            .unwrap();
        let after: BTreeSet<u64> = h.probed_indices().into_iter().collect();
        let newly_probed: Vec<u64> = after.difference(&before).copied().collect();
        assert!(
            newly_probed.iter().all(|i| *i >= 50),
            "resume must not re-probe completed units: {newly_probed:?}"
        );
        let unique: BTreeSet<_> = newly_probed.iter().collect();
        assert_eq!(unique.len(), newly_probed.len(), "no unit probed twice");
        assert_eq!(summary.units_completed, h.plan.len() - 50);
        assert_eq!(newly_probed.len() as u64, h.plan.len() - 50);
    }

    // Invariant 3's actual out-of-order hazard, made deterministic rather
    // than dependent on a real concurrency race landing a particular way:
    // a previous run can complete units ABOVE the first gap
    // `next_pending_unit` reports (e.g. index 60..70 finished before
    // 10..20 did) -- naively dispatching every unit in `10..plan.len()`
    // (the brief's own Step 3 sketch) would re-probe that island. This is
    // exactly the defect `already_done` (loaded once at the top of `run`)
    // exists to close; see the module doc comment's invariant 3.
    //
    // `store.completed_units`-based diffing (the shape
    // `resuming_skips_completed_units_and_never_repeats_one` above uses)
    // CANNOT catch a redundant re-probe of an already-marked-done unit:
    // `mark_units_done` is `INSERT OR IGNORE`, so a second, wrongful
    // `mark_units_done` call for an index already in the table is a
    // provably silent no-op at the store layer -- the store's own view is
    // identical whether the island was correctly skipped or wrongly
    // re-probed and then redundantly re-marked. This test uses the same
    // real, independent per-port accept-counter technique as
    // `cancelled_run_resumes_to_a_full_gap_free_union_with_no_unit_probed_twice`
    // instead, and -- critically -- performs one REAL connect against each
    // "already done" unit's port before marking it done, so each starts at
    // count 1 (as if a previous run's scheduler had genuinely probed it);
    // a wrongful re-probe during resume is then directly visible as that
    // port's count reaching 2, not silently absorbed by the store.
    #[tokio::test]
    async fn resuming_skips_a_completed_island_above_the_first_gap_not_just_a_contiguous_prefix() {
        // 40, not 100 -- see the `PLAN_SIZE` comment on
        // `budget_ceiling_is_never_exceeded_measured_by_real_accept_counts_not_the_ledger`
        // for why (this module's aggregate real-socket footprint under
        // `cargo test`'s default parallelism).
        const N: u64 = 40;
        let mut counts: HashMap<u16, Arc<AtomicU64>> = HashMap::new();
        let mut ports: Vec<u16> = Vec::with_capacity(N as usize);
        for _ in 0..N {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let counter = Arc::new(AtomicU64::new(0));
            counts.insert(port, Arc::clone(&counter));
            ports.push(port);
            tokio::spawn(async move {
                while let Ok((s, _)) = listener.accept().await {
                    counter.fetch_add(1, Ordering::SeqCst);
                    drop(s);
                }
            });
        }
        let specs: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
        let spec_refs: Vec<&str> = specs.iter().map(String::as_str).collect();
        // M4 Task 5: service detection is explicitly disabled for this
        // harness. This test's accept counters are the ground truth for
        // "was this unit's CONNECT probe issued more than once" -- a
        // property this test predates Task 5 and has nothing to do with
        // service identification. With detection left at this module's
        // default (enabled), an `Open` unit's own identification reconnects
        // would land on the SAME counter this test reads, inflating a
        // correctly-resumed unit's count past 1 for a reason unrelated to
        // what this test checks. `detect_service`'s own scope-gate and
        // budget behavior are covered directly by dedicated tests elsewhere
        // in this module instead.
        let h = make_harness_with_detection(
            &["127.0.0.1"],
            &spec_refs,
            budgets(1_000_000, 3_600, 1_000_000),
            SchedulerConfig {
                concurrency: 16,
                connect_timeout: Duration::from_secs(5),
                progress_every: 500,
            },
            default_manifest(),
            ServiceDetection {
                enabled: false,
                intensity: 0,
            },
            EvidenceLevel::Headers,
        );
        assert_eq!(h.plan.len(), N);

        // Simulate a previous run that genuinely probed units 0..5 and,
        // out of order, 20..25 -- one real connect per simulated unit, so
        // each port's counter is already 1 before resumption begins,
        // exactly as if the scheduler itself had probed it and a crash or
        // cancellation happened before the gap in between was closed.
        let island: BTreeSet<u64> = (20..25).collect();
        let already: BTreeSet<u64> = (0..5).chain(20..25).collect();
        for &i in &already {
            let port = h.plan.unit(i).unwrap().endpoint.port;
            tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
        }
        // Let the acceptors catch up before marking done, so every counter
        // genuinely reads 1 before resumption starts.
        for _ in 0..500 {
            let total: u64 = already
                .iter()
                .map(|i| {
                    let port = h.plan.unit(*i).unwrap().endpoint.port;
                    counts[&port].load(Ordering::SeqCst)
                })
                .sum();
            if total >= already.len() as u64 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        h.store
            .mark_units_done(h.scan_id, &already.iter().copied().collect::<Vec<_>>())
            .unwrap();

        let resume_from = h
            .store
            .next_pending_unit(h.scan_id, h.plan.len())
            .unwrap()
            .unwrap();
        assert_eq!(
            resume_from, 5,
            "the resume point is the first GAP, not a count of completed units"
        );

        h.scheduler
            .run(&h.plan, resume_from, CancellationToken::new())
            .await
            .unwrap();

        // Let any late acceptors catch up before asserting on final counts.
        for _ in 0..500 {
            let total: u64 = counts.values().map(|c| c.load(Ordering::SeqCst)).sum();
            if total >= N {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        for i in &island {
            let port = h.plan.unit(*i).unwrap().endpoint.port;
            let n = counts[&port].load(Ordering::SeqCst);
            assert_eq!(
                n, 1,
                "unit {i} (port {port}) must NOT be re-probed during resume, got {n} probes"
            );
        }
        for i in 5..N {
            if island.contains(&i) {
                continue;
            }
            let port = h.plan.unit(i).unwrap().endpoint.port;
            let n = counts[&port].load(Ordering::SeqCst);
            assert_eq!(
                n, 1,
                "unit {i} (port {port}) must be probed exactly once during resume, got {n}"
            );
        }
    }

    #[tokio::test]
    async fn every_open_port_produces_exactly_one_port_state_event() {
        let p1 = open_port().await;
        let p2 = open_port().await;
        let h = harness(&["127.0.0.1"], &[p1, p2]);
        h.run_to_completion().await.unwrap();
        let opens = h
            .events()
            .iter()
            .filter(|e| {
                matches!(
                    &e.body,
                    EventBody::PortStateObserved {
                        state: PortState::Open,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(opens, 2);
    }

    // M3 Task 7 fix round 1, IMPORTANT-3: AC-3.29's "no omissions" claim was
    // only ever exercised against OPEN ports (real listeners) -- the
    // dominant outcome in any real scan, `Closed`, had no counting coverage
    // at all. This mixes all three outcomes `record` maps to and counts
    // each precisely, including the total, so suppressing `port.state` for
    // any one state (the reviewer's own example mutation: skip `Closed`)
    // fails this test even though it would pass every open-port-only test
    // in this module.
    #[tokio::test]
    async fn every_port_state_produces_exactly_one_event_open_closed_and_filtered() {
        let open1 = open_port().await;
        let open2 = open_port().await;

        let closed1 = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let p = l.local_addr().unwrap().port();
            drop(l);
            p
        };
        let closed2 = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let p = l.local_addr().unwrap().port();
            drop(l);
            p
        };

        // A single filtered port: fill its accept queue (same technique as
        // elsewhere in this module) so the probe against it silently times
        // out rather than resolving either way.
        let filtered_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let filtered_addr = filtered_listener.local_addr().unwrap();
        let mut held = Vec::new();
        let mut filled = false;
        for _ in 0..256 {
            match tokio::time::timeout(
                Duration::from_millis(150),
                TcpStream::connect(filtered_addr),
            )
            .await
            {
                Ok(Ok(s)) => held.push(s),
                _ => {
                    filled = true;
                    break;
                }
            }
        }
        assert!(filled, "setup: expected the accept queue to fill");

        let ports = [open1, open2, closed1, closed2, filtered_addr.port()];
        let specs: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
        let spec_refs: Vec<&str> = specs.iter().map(String::as_str).collect();
        let h = make_harness(
            &["127.0.0.1"],
            &spec_refs,
            budgets(1_000_000, 3_600, 1_000_000),
            SchedulerConfig {
                concurrency: 8,
                connect_timeout: Duration::from_millis(300),
                progress_every: 500,
            },
            default_manifest(),
        );
        assert_eq!(h.plan.len(), 5);
        h.run_to_completion().await.unwrap();

        let events = h.events();
        let count_state = |state: PortState| {
            events
                .iter()
                .filter(
                    |e| matches!(&e.body, EventBody::PortStateObserved { state: s, .. } if *s == state),
                )
                .count()
        };
        assert_eq!(count_state(PortState::Open), 2, "2 real listeners");
        assert_eq!(
            count_state(PortState::Closed),
            2,
            "2 refused (unbound) ports"
        );
        assert_eq!(count_state(PortState::Filtered), 1, "1 full-backlog port");

        let total_port_state = events
            .iter()
            .filter(|e| matches!(&e.body, EventBody::PortStateObserved { .. }))
            .count();
        assert_eq!(
            total_port_state, 5,
            "no omissions across open, closed, AND filtered outcomes -- not just open ports"
        );
        drop(held);
        drop(filtered_listener);
    }

    #[tokio::test]
    async fn progress_events_are_emitted_periodically_during_a_long_scan() {
        let h = harness_with_many_units(2_000);
        h.run_to_completion().await.unwrap();
        let progress = h
            .events()
            .iter()
            .filter(|e| matches!(&e.body, EventBody::Progress { .. }))
            .count();
        assert!(progress >= 2, "expected periodic progress, saw {progress}");
    }

    // ------------------------------------------------------------------
    // Verification beyond the brief (task dispatch).
    // ------------------------------------------------------------------

    // Dispatch: "Progress events must be periodic, and the test must prove
    // periodicity, not merely that at least one was emitted." Checks the
    // actual `probes_sent` sequence steps by roughly `progress_every`
    // (500, from `harness_with_many_units`'s `SchedulerConfig`), not just
    // that two-or-more events happened to show up anywhere in the log.
    #[tokio::test]
    async fn progress_events_step_by_progress_every_not_just_appear_twice() {
        let h = harness_with_many_units(2_000);
        h.run_to_completion().await.unwrap();
        let sent: Vec<u64> = h
            .events()
            .iter()
            .filter_map(|e| match &e.body {
                EventBody::Progress { probes_sent, .. } => Some(*probes_sent),
                _ => None,
            })
            .collect();
        assert!(
            sent.len() >= 3,
            "expected several periodic progress events, saw {sent:?}"
        );
        for w in sent.windows(2) {
            let step = w[1] - w[0];
            // The meaningful half of "periodic": no step is smaller than
            // `progress_every` (500) -- this is exactly what the "fires on
            // every batch instead of periodically" mutation violates (see
            // this task's report: that mutation produces steps around
            // STORE_FLUSH_BATCH, ~64, not ~500). Deliberately no tight
            // UPPER bound per step: `flush_progress`'s inner
            // `try_join_next` drain has no cap on how many results it pulls
            // out of `in_flight` in one pass, so under real scheduling
            // contention (many probes all becoming ready in one burst) a
            // single flush can legitimately batch far more than
            // `STORE_FLUSH_BATCH` units at once -- confirmed empirically
            // (an earlier, tighter bound here flaked under `cargo test`'s
            // parallel load; see this task's fix-round-1 report). The
            // count assertion below is the upper-bound sanity check
            // instead.
            assert!(
                step >= 500,
                "progress step {step} is smaller than progress_every (500) -- \
                 not periodic: {sent:?}"
            );
        }
        assert!(*sent.last().unwrap() <= 2_000);
        // Total count stays small relative to the plan (2,000 units): the
        // same mutation above would also inflate this to dozens of events
        // instead of roughly 2000/500 = 4.
        assert!(
            sent.len() <= 20,
            "expected roughly periodic progress (around 4 events for 2,000 \
             units at progress_every=500), saw {} events: {sent:?}",
            sent.len()
        );
    }

    // AC-3.24, both directions (dispatch: "test the budget ceiling in both
    // directions"). Too permissive:
    #[tokio::test]
    async fn budget_ceiling_is_never_exceeded_by_even_one_packet() {
        // CRITICAL-1 (M3 Task 7 fix round 1): `summary.packets_spent` is
        // read straight out of `BudgetLedger`, which structurally CANNOT
        // report spending past its own ceiling (`try_spend_packets` refuses
        // any spend that would cross it) -- asserting on it alone is a
        // tautology true for ANY implementation, including one that reserves
        // budget AFTER dispatching (moving the reservation past `spawn`
        // still passed all 21 scheduler tests in the review that found
        // this). `units_completed` is the cheap fix: it counts what `record`
        // actually observed, not what the ledger is willing to admit to.
        let h = harness_with_packet_budget(10);
        let summary = h.run_to_completion().await.unwrap();
        assert!(summary.budget_exhausted);
        assert!(
            summary.units_completed <= 10,
            "units_completed={} must never exceed the ceiling of 10 -- this does \
             not read through BudgetLedger at all",
            summary.units_completed
        );
        assert_eq!(summary.packets_spent, 10);
    }

    // The strong version CRITICAL-1 also asks for: real accept counts on
    // real listeners, so the assertion cannot be laundered through
    // `BudgetLedger`/`RunSummary` at all -- it counts what was ACTUALLY
    // emitted onto real sockets, entirely independent of this crate's own
    // accounting.
    #[tokio::test]
    async fn budget_ceiling_is_never_exceeded_measured_by_real_accept_counts_not_the_ledger() {
        // 20, not the "thousands" the AC's own text asks for (that's what
        // `budget_ceiling_is_never_exceeded_by_even_one_packet` above,
        // against 10,000 CHEAP closed ports, already covers): 20 real
        // listeners is comfortably more than the ceiling of 10 while
        // keeping this test's own aggregate socket footprint modest --
        // `cargo test`'s default parallelism runs many of this module's
        // real-listener tests concurrently, and empirically (see this
        // task's fix-round-1 report) too many at once can transiently
        // exhaust local ephemeral ports on a loaded host, which is a test
        // environment artifact, not a `Scheduler` defect, but still
        // something worth not provoking unnecessarily.
        const PLAN_SIZE: u64 = 20;
        const CEILING: u64 = 10;
        let (h, counts) = harness_with_real_listeners(
            PLAN_SIZE,
            budgets(CEILING, 3_600, 1_000_000),
            small_config(),
        )
        .await;
        assert_eq!(h.plan.len(), PLAN_SIZE);

        let summary = h.run_to_completion().await.unwrap();
        assert!(summary.budget_exhausted);

        settle_accept_counters(&counts, summary.units_completed).await;
        let total_real_emissions: u64 = counts.values().map(|c| c.load(Ordering::SeqCst)).sum();
        assert!(
            total_real_emissions <= CEILING,
            "CRITICAL-1: real accept count {total_real_emissions} exceeds the ceiling \
             of {CEILING} -- this is what a BudgetLedger-read-back assertion can never \
             catch, since the ledger cannot report exceeding its own ceiling"
        );
    }

    // ... and too strict: a budget exactly equal to the plan's own size
    // must complete every unit, not stop one short.
    #[tokio::test]
    async fn a_budget_exactly_equal_to_the_plan_size_completes_every_unit() {
        let h = make_harness(
            &["127.0.0.1"],
            &["20000-20009"], // exactly 10 ports -> 10 units
            budgets(10, 3_600, 1_000_000),
            small_config(),
            default_manifest(),
        );
        assert_eq!(h.plan.len(), 10);
        let summary = h.run_to_completion().await.unwrap();
        assert_eq!(
            summary.units_completed, 10,
            "a budget exactly equal to the plan size must not stop one unit short"
        );
        assert_eq!(summary.packets_spent, 10);
        assert!(
            !summary.budget_exhausted,
            "the plan finished exactly at the ceiling -- that is plan exhaustion, not budget exhaustion"
        );
    }

    // --- CRITICAL-2 (M3 Task 7 fix round 1): the packet ceiling must be
    // enforced ACROSS a cancel/resume loop, not just within one run() call.
    // Cancellation deliberately emits no terminal event (AC-3.27), so a
    // cancelled scan resumed by a FRESH Scheduler/BudgetLedger must not get
    // a full new budget -- the review's repro: run1 spent=6, a naive fresh
    // ledger let run2 spend 10 more, TOTAL PROBED=16 against a ceiling of
    // 10. The fix is `BudgetLedger::resumed`, seeded from what
    // `record_progress` persisted; `Harness::resume` builds exactly that. ---

    #[tokio::test]
    async fn packet_ceiling_is_enforced_across_a_cancel_resume_loop_via_a_fresh_scheduler() {
        // 20, not 100 -- see the comment on `PLAN_SIZE` in
        // `budget_ceiling_is_never_exceeded_measured_by_real_accept_counts_not_the_ledger`
        // above for why: this test's own socket footprint (a full set of
        // real listeners) adds to this module's aggregate under `cargo
        // test`'s default parallelism, and 20 is still comfortably more
        // than the ceiling of 10.
        const PLAN_SIZE: u64 = 20;
        const CEILING: u64 = 10;
        // pps=3: `RateLimiter`'s capacity equals its configured pps, so a
        // burst >= CEILING (10) would let run1 dispatch and spend the
        // WHOLE ceiling before the poller task below ever gets scheduled
        // to observe partial progress and cancel -- confirmed empirically
        // (pps=25 made this test fail on `summary1.cancelled`, since the
        // whole 10-unit ceiling fit inside one burst with no yield point
        // in between). pps=3 forces a genuine `sleep` inside the limiter
        // after the first 3 dispatches, which is a real yield point the
        // executor uses to run the poller -- guaranteeing run1 genuinely
        // spends SOME (not zero, not all) of the ceiling before
        // cancellation lands, the exact shape of the review's own repro
        // (run1 spent=6). M3 whole-branch review, IMPORTANT-2: this pps now
        // lives directly in `scan_budgets` (there is no separate
        // limiter-pps parameter any more), so run2's resume below uses its
        // OWN, faster-pps `Budgets` value (`resume_budgets`) sharing the
        // same packet ceiling -- run2 does not need run1's deliberately
        // slow pacing, only its unspent budget.
        let scan_budgets = budgets(CEILING, 3_600, 3);
        let resume_budgets = budgets(CEILING, 3_600, 1_000_000);
        let (h, counts) =
            harness_with_real_listeners(PLAN_SIZE, scan_budgets, small_config()).await;
        assert_eq!(h.plan.len(), PLAN_SIZE);

        let cancel = CancellationToken::new();
        // Poll the REAL accept counters, not `store.completed_units`: with
        // only 10 total units possible before the ceiling trips (far below
        // `STORE_FLUSH_BATCH`, 64), `unit_progress` is never flushed mid-run
        // at all -- `completed_units` would read 0 until run1 has already
        // finished, so a store-based poll here can never observe progress
        // in time to cancel mid-flight (confirmed empirically: the first
        // version of this test, polling the store, always saw run1 run to
        // natural completion instead of being cancelled).
        let counts_for_poll = counts.clone();
        let c = cancel.clone();
        let poller = tokio::spawn(async move {
            loop {
                let done: u64 = counts_for_poll
                    .values()
                    .map(|c| c.load(Ordering::SeqCst))
                    .sum();
                if done >= 1 {
                    c.cancel();
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        });
        let summary1 = h.scheduler.run(&h.plan, 0, cancel).await.unwrap();
        poller.await.unwrap();
        assert!(summary1.cancelled);
        assert!(
            summary1.units_completed > 0,
            "run1 must have made SOME progress"
        );
        assert!(
            summary1.units_completed < CEILING,
            "run1 must not have exhausted the whole ceiling alone, or this test \
             does not actually exercise cross-run accumulation: spent {}",
            summary1.units_completed
        );

        // THE FIX under test: a fresh Scheduler/BudgetLedger for run2,
        // seeded from run1's persisted spend via `BudgetLedger::resumed` --
        // not a naive `BudgetLedger::new`, which would hand run2 a full,
        // unspent ceiling (reproduced below as a mutation).
        let resumed_scheduler = h.resume(small_config(), resume_budgets);
        let resume_from = h
            .store
            .next_pending_unit(h.scan_id, PLAN_SIZE)
            .unwrap()
            .unwrap();
        let summary2 = resumed_scheduler
            .run(&h.plan, resume_from, CancellationToken::new())
            .await
            .unwrap();
        assert!(
            summary2.budget_exhausted,
            "run2 must hit the SAME ceiling run1 was already eating into, not a fresh one"
        );

        // Cheap check, independent even of the accept counters: the total
        // units completed across BOTH runs must not exceed the ceiling.
        assert!(
            summary1.units_completed + summary2.units_completed <= CEILING,
            "total units completed across both runs ({} + {} = {}) must not exceed \
             the ceiling of {CEILING}",
            summary1.units_completed,
            summary2.units_completed,
            summary1.units_completed + summary2.units_completed
        );

        // The strong check: real accept counts, which cannot be laundered
        // through either run's own BudgetLedger.
        settle_accept_counters(&counts, summary1.units_completed + summary2.units_completed).await;
        let total_real_emissions: u64 = counts.values().map(|c| c.load(Ordering::SeqCst)).sum();
        assert!(
            total_real_emissions <= CEILING,
            "CRITICAL-2: real accept count across BOTH runs ({total_real_emissions}) \
             exceeds the ceiling of {CEILING} -- a fresh, unseeded ledger on resume \
             would allow exactly this"
        );
    }

    #[tokio::test]
    async fn runtime_ceiling_is_enforced_across_a_cancel_resume_loop_via_a_fresh_scheduler() {
        // Run 1 with a generous (1 hour) ceiling, cancelled after real wall
        // time has genuinely passed, so `elapsed_seconds` persists as >= 1
        // -- not calculated by hand, but the scheduler's own
        // `total_elapsed_seconds` doing real `Instant` bookkeeping.
        let h = harness_with_many_units(5_000);
        let cancel = CancellationToken::new();
        let c = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1_200)).await;
            c.cancel();
        });
        let summary1 = h.scheduler.run(&h.plan, 0, cancel).await.unwrap();
        assert!(summary1.cancelled);
        let record = h.store.get(h.scan_id).unwrap().unwrap();
        assert!(
            record.elapsed_seconds >= 1,
            "run1 ran for >1.2 real seconds; the persisted cursor must reflect \
             that, got {}",
            record.elapsed_seconds
        );

        // THE FIX under test: a fresh Scheduler with a ZERO-second runtime
        // ceiling, seeded from run1's persisted elapsed_seconds via
        // `BudgetLedger::resumed`. A ceiling of 1 (with baseline == 1) sits
        // exactly on `elapsed_exceeded`'s own `>` boundary and can flip
        // either way depending on `.as_secs()` truncation -- confirmed
        // empirically (it did, intermittently reporting a false negative
        // here). A ceiling of 0 has no such edge: baseline is already >= 1
        // and can only ever be `> 0`. Direct `Budgets` construction bypasses
        // `RawBudgets`'s deserialize-time "every budget must be >= 1" check,
        // which is fine for the same reason it's fine elsewhere in this
        // file (see `budgets`'s own doc comment) -- this never round-trips
        // through JSON.
        let tight_runtime_budgets = budgets(1_000_000, 0, 1_000_000);
        let resumed_scheduler = h.resume(small_config(), tight_runtime_budgets);
        let resume_from = h
            .store
            .next_pending_unit(h.scan_id, h.plan.len())
            .unwrap()
            .unwrap();
        let summary2 = resumed_scheduler
            .run(&h.plan, resume_from, CancellationToken::new())
            .await
            .unwrap();
        assert!(
            summary2.time_exhausted,
            "a resumed scheduler must inherit already-elapsed runtime, not restart the clock"
        );
        assert_eq!(
            summary2.units_completed, 0,
            "must stop before dispatching anything new"
        );
    }

    // M3 Task 7 fix round 2: `runtime_ceiling_is_enforced_across_a_cancel_resume_loop_via_a_fresh_scheduler`
    // above never observes CRITICAL-2's runtime-truncation defect. Its
    // single resume uses a ZERO-second ceiling specifically so the
    // baseline alone (already >= 1 from round 1's own truncation, which
    // rounds a >=1s round DOWN to something still >= 1) trips
    // `time_exhausted` immediately -- it reads back only ONE persisted
    // value and only checks that it is nonzero, never that a MULTI-round
    // accumulation is actually correct. This test drives three real
    // cancel/resume rounds, each ~1.3 real seconds, and checks the
    // persisted cumulative total after all three -- proving each round's
    // sub-second remainder is actually carried forward, not silently
    // dropped every single time.
    #[tokio::test]
    async fn runtime_baseline_accumulates_correctly_across_three_real_cancel_resume_rounds() {
        // 20,000, not 5,000: at ~1,300 units/round (1,000 burst + ~300
        // throttled in the remaining 0.3s of each 1.3s window) across three
        // rounds, a smaller plan runs out of units to dispatch before the
        // third round's cancellation ever fires -- confirmed empirically
        // (5,000 let round 3 exhaust the plan naturally instead of being
        // cancelled).
        let h = harness_with_many_units(20_000);
        // Generous on packets and runtime, but deliberately paced at 1,000
        // pps -- cancellation (not budget exhaustion) must be what stops
        // every round, so each round's own elapsed time is genuinely under
        // this test's control. M3 whole-branch review, IMPORTANT-2: the
        // pacing value now lives directly in this same `Budgets` (there is
        // no separate limiter-pps parameter any more).
        let generous_budgets = budgets(1_000_000, 1_000_000, 1_000);
        let mut resume_from = 0u64;
        for round in 0..3u32 {
            let cancel = CancellationToken::new();
            let c = cancel.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(1_300)).await;
                c.cancel();
            });
            // A fresh `Scheduler` every round (via `Harness::resume`), the
            // same shape a real process restart takes -- reusing one
            // `Scheduler`/`BudgetLedger` across rounds would never exercise
            // the persist-then-reseed path this test is actually about.
            let scheduler = h.resume(small_config(), generous_budgets);
            let summary = scheduler.run(&h.plan, resume_from, cancel).await.unwrap();
            assert!(
                summary.cancelled,
                "round {round} must be stopped by cancellation, not exhaust the plan \
                 (got {summary:?}) -- otherwise this round's own elapsed time is not \
                 under this test's control"
            );
            resume_from = h
                .store
                .next_pending_unit(h.scan_id, h.plan.len())
                .unwrap()
                .unwrap();
        }
        let record = h.store.get(h.scan_id).unwrap().unwrap();
        // Empirically: the fixed (ceil) code consistently persists 6 here
        // (ceil(~1.3s) = 2 per round x 3 rounds); the truncating bug this
        // test targets persists exactly 3 (floor(~1.3s) = 1 per round x 3
        // rounds) -- NOT 0, since 1.3s truncates to 1, not 0 (a 3-round
        // test using sub-1s rounds, matching the review's own repro more
        // literally, would show a starker 0-vs-N gap, but would then also
        // need `maximum_runtime_seconds` and the cancellation window tuned
        // finely enough to stay reliably under 1s of real elapsed time on
        // a loaded CI machine -- 1.3s rounds are more robust to scheduling
        // jitter while still cleanly separating the two behaviors, 3 vs 6).
        // 5 sits strictly between both observed values with margin on
        // either side.
        assert!(
            record.elapsed_seconds >= 5,
            "three rounds of ~1.3 real seconds each must accumulate to at least 5 \
             persisted seconds (expect ~6) -- got {}. Each round's own sub-second \
             remainder must be carried into the next round's baseline, not \
             truncated away every time.",
            record.elapsed_seconds
        );
    }

    #[tokio::test]
    async fn a_time_budget_of_zero_seconds_elapsed_stops_the_scan_and_records_why() {
        let h = make_harness(
            &["127.0.0.1"],
            &["20000-29999"],
            // 1s runtime ceiling, sizeable plan, pps=50 -- slow enough that
            // 1 second elapses before the plan finishes.
            budgets(1_000_000, 1, 50),
            small_config(),
            default_manifest(),
        );
        let summary = h.run_to_completion().await.unwrap();
        assert!(summary.time_exhausted);
        assert!(!summary.budget_exhausted);
        assert!(!summary.cancelled);
        let events = h.events();
        assert!(events.iter().any(|e| matches!(
            &e.body, EventBody::ScanFailed { reason_code, .. } if reason_code == "time_exhausted"
        )));
    }

    // AC-3.27: the three non-cancellation outcomes are mutually exclusive
    // and each carries its own, distinctly-worded `reason_code` -- collapsing
    // "budget_exhausted" and "time_exhausted" into one generic failure code
    // would make this indistinguishable to an operator.
    #[tokio::test]
    async fn budget_and_time_exhaustion_carry_different_reason_codes() {
        let h = harness_with_packet_budget(5);
        h.run_to_completion().await.unwrap();
        let codes: Vec<String> = h
            .events()
            .iter()
            .filter_map(|e| match &e.body {
                EventBody::ScanFailed { reason_code, .. } => Some(reason_code.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(codes, vec!["budget_exhausted".to_string()]);
    }

    // AC-3.28: exactly one `scan.started` naming the plan's own hash.
    #[tokio::test]
    async fn scan_started_carries_the_plan_hash() {
        let port = open_port().await;
        let h = harness(&["127.0.0.1"], &[port]);
        h.run_to_completion().await.unwrap();
        let events = h.events();
        let EventBody::ScanStarted { plan_hash, .. } = &events.first().unwrap().body else {
            panic!("first event must be scan.started");
        };
        assert_eq!(*plan_hash, h.plan.hash());
    }

    // AC-3.28: exactly one terminal event on a plain completed run -- not
    // just "the last event happens to be scan.completed" (the brief's own
    // test), but that no OTHER terminal event snuck in earlier too.
    #[tokio::test]
    async fn a_completed_run_has_exactly_one_terminal_event() {
        let port = open_port().await;
        let h = harness(&["127.0.0.1"], &[port]);
        h.run_to_completion().await.unwrap();
        let terminal = h
            .events()
            .iter()
            .filter(|e| {
                matches!(
                    &e.body,
                    EventBody::ScanCompleted { .. } | EventBody::ScanFailed { .. }
                )
            })
            .count();
        assert_eq!(terminal, 1);
    }

    // AC-3.27: cancellation gets NO terminal event at all -- distinguishing
    // "the scan finished" from "the scan ran out of money/time" is the
    // whole point; a cancelled scan is neither.
    #[tokio::test]
    async fn cancellation_emits_no_terminal_event() {
        let cancel = CancellationToken::new();
        cancel.cancel(); // already cancelled before run() even starts
        let h = harness_with_many_units(50);
        let summary = h.scheduler.run(&h.plan, 0, cancel).await.unwrap();
        assert!(summary.cancelled);
        let terminal = h
            .events()
            .iter()
            .filter(|e| {
                matches!(
                    &e.body,
                    EventBody::ScanCompleted { .. } | EventBody::ScanFailed { .. }
                )
            })
            .count();
        assert_eq!(
            terminal, 0,
            "cancellation must not emit scan.completed or scan.failed"
        );
        // Still exactly one scan.started, even for a scan cancelled before
        // its first unit.
        let started = h
            .events()
            .iter()
            .filter(|e| matches!(&e.body, EventBody::ScanStarted { .. }))
            .count();
        assert_eq!(started, 1);
    }

    // Invariant 1, stated directly rather than only inferred from
    // `packets_spent`: an ALREADY-cancelled token means the dispatch loop's
    // very first budget check is never reached, so units_completed and
    // packets_spent must both be exactly 0 -- not "some small number", zero.
    #[tokio::test]
    async fn a_pre_cancelled_token_dispatches_nothing_at_all() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let h = harness_with_many_units(50);
        let summary = h.scheduler.run(&h.plan, 0, cancel).await.unwrap();
        assert_eq!(summary.units_completed, 0);
        assert_eq!(summary.packets_spent, 0);
    }

    // `run` must be safe to call again on a scan that already reached a
    // terminal (non-cancellation) outcome -- a no-op, not a second
    // `scan.started`/`scan.completed` pair. See `run`'s own doc comment on
    // "Calling run again after a scan has already terminated".
    #[tokio::test]
    async fn resuming_a_completed_scan_is_a_safe_no_op() {
        let h = harness_with_many_units(10);
        let first = h.run_to_completion().await.unwrap();
        assert!(!first.cancelled);
        let second = h
            .scheduler
            .run(&h.plan, h.plan.len(), CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(second.units_completed, 0);
        assert!(!second.cancelled && !second.budget_exhausted && !second.time_exhausted);
        let events = h.events();
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(&e.body, EventBody::ScanStarted { .. }))
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(&e.body, EventBody::ScanCompleted { .. }))
                .count(),
            1,
            "a redundant run() call must not emit a second scan.completed"
        );
    }

    #[tokio::test]
    async fn resuming_a_budget_exhausted_scan_is_a_safe_no_op() {
        let h = harness_with_packet_budget(5);
        let first = h.run_to_completion().await.unwrap();
        assert!(first.budget_exhausted);
        let second = h
            .scheduler
            .run(&h.plan, first.units_completed, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(second.units_completed, 0);
        assert!(!second.budget_exhausted);
        let failed = h
            .events()
            .iter()
            .filter(|e| matches!(&e.body, EventBody::ScanFailed { .. }))
            .count();
        assert_eq!(
            failed, 1,
            "a redundant run() call must not emit a second scan.failed"
        );
    }

    // M3 Task 7's carried requirement (local-vs-target signal): a probe
    // refused specifically because THIS machine ran out of ephemeral ports
    // or was blocked by local policy is counted, not silently folded into
    // an indistinguishable `filtered` count.
    //
    // M3 Task 7 fix round 1, IMPORTANT-4: this test alone (checking only
    // that the counter stays at zero when nothing local failed) is
    // trivially true for a counter that never increments at all -- the
    // reviewer's exact finding. Forcing a REAL local failure all the way
    // through a real async `TcpStream::connect()` (as opposed to
    // `connect.rs`'s own `classifies_a_genuine_os_produced_addrnotavailable_error`,
    // which drives the classifier directly with a real OS error but not
    // through the full probe) would need genuine ephemeral-port exhaustion
    // or a real firewall rule -- still impractical to do portably and
    // deterministically in a test. The test below closes the actual gap
    // differently: `record` (private, but this module is a child of
    // `scheduler` and can call it) is the REAL, unmodified production
    // method that turns `(ScanUnit, ConnectOutcome, bool)` into
    // `RunSummary.local_resource_failures += 1` -- calling it directly with
    // `local_failure = true` proves that wiring end to end without
    // reimplementing it, exactly the kind of thing the reviewer's "call the
    // real classifier" fix asks for, applied to the aggregation step
    // instead of the classification step (which `connect.rs` already
    // covers with a genuine OS error).
    #[tokio::test]
    async fn local_resource_failures_increments_when_a_local_failure_is_actually_recorded() {
        let port = open_port().await;
        let h = harness(&["127.0.0.1"], &[port]);
        let mut summary = RunSummary::default();
        let mut completed_batch = Vec::new();
        let unit = h.plan.unit(0).unwrap();

        // The REAL `record` method, fed a local-failure outcome exactly as
        // `probe_connect_with_local_signal` would report one -- not a
        // reimplementation of its `+= 1` logic.
        h.scheduler
            .record(
                (unit, ConnectOutcome::Filtered, true),
                &mut summary,
                &mut completed_batch,
                &CancellationToken::new(),
            )
            .await
            .unwrap();

        assert_eq!(
            summary.local_resource_failures, 1,
            "record() must increment local_resource_failures when local_failure is true"
        );
        assert_eq!(
            summary.open_ports, 0,
            "sanity: this outcome was Filtered, not Open"
        );
    }

    #[tokio::test]
    async fn local_resource_failures_is_zero_when_nothing_local_failed() {
        let port = open_port().await;
        let h = harness(&["127.0.0.1"], &[port]);
        let summary = h.run_to_completion().await.unwrap();
        assert_eq!(summary.local_resource_failures, 0);
    }

    // C4/M2's `TaskStore::record_progress`, wired up by this task: the
    // cached cursor must reflect what actually happened, not stay at its
    // construction-time default.
    #[tokio::test]
    async fn record_progress_is_kept_in_step_with_the_log_and_ledger() {
        let port = open_port().await;
        let h = harness(&["127.0.0.1"], &[port]);
        let summary = h.run_to_completion().await.unwrap();
        let record = h.store.get(h.scan_id).unwrap().unwrap();
        assert_eq!(record.packets_spent, summary.packets_spent);
        assert_eq!(record.last_sequence, h.log.lock().unwrap().last_sequence());
        assert!(record.last_sequence > 0);
    }

    // Carried requirement (Tasks 5/6): empty `probe_ports` must be a hard
    // error "wherever the scheduler builds a `DiscoveryConfig`". This
    // scheduler never does -- neither `Scheduler::run` nor anything else in
    // `scheduler.rs` constructs a `DiscoveryConfig` or calls `discover_host`
    // at all (v0.1's scheduler probes every plan unit directly; the
    // Milestone Exit Criteria's own end-to-end test expects `scan.started`,
    // `port.state`, `scan.completed` only, no `host.discovered`). Not
    // pinned by an executable test here (an earlier version of this test
    // grepped this file's own source for the string "DiscoveryConfig",
    // which trivially matched this very comment -- a self-referential check
    // that could never usefully fail); see this task's report for the full
    // reasoning and why this carried requirement has no code footprint in
    // this task's actual deliverable.

    // ------------------------------------------------------------------
    // The real round trip: run, cancel mid-flight, resume, then assert the
    // union of BOTH runs' probed units equals the plan exactly with no
    // duplicates -- on the actual set (and, more strongly, on a per-unit
    // probe COUNT independent of TaskStore's own INSERT-OR-IGNORE
    // deduplication, which would silently hide a redundant probe rather
    // than reveal one).
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn cancelled_run_resumes_to_a_full_gap_free_union_with_no_unit_probed_twice() {
        // 30, not 90 -- see the `PLAN_SIZE` comment on
        // `budget_ceiling_is_never_exceeded_measured_by_real_accept_counts_not_the_ledger`
        // for why (this module's aggregate real-socket footprint under
        // `cargo test`'s default parallelism).
        const N: u64 = 30;
        // Real listeners, each with its own accept counter -- a port probed
        // twice across the two runs shows up directly as that port's
        // counter reaching 2, which a store-only check (deduplicated by
        // `unit_progress`'s PRIMARY KEY) could never reveal.
        let mut counts: HashMap<u16, Arc<AtomicU64>> = HashMap::new();
        let mut ports: Vec<u16> = Vec::with_capacity(N as usize);
        for _ in 0..N {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let counter = Arc::new(AtomicU64::new(0));
            counts.insert(port, Arc::clone(&counter));
            ports.push(port);
            tokio::spawn(async move {
                while let Ok((s, _)) = listener.accept().await {
                    counter.fetch_add(1, Ordering::SeqCst);
                    drop(s);
                }
            });
        }
        let specs: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
        let spec_refs: Vec<&str> = specs.iter().map(String::as_str).collect();
        // Deliberately slow (capacity well under N): forces real
        // throttling so the first run can genuinely be caught mid-flight
        // rather than completing before cancellation ever lands. Capacity 8
        // against N=30: the initial burst alone (8) is enough to satisfy
        // the poller's `done >= 5` threshold below, with the remaining 22
        // units throttled at 8/s (~2.75s to finish naturally) -- comfortable
        // margin for cancellation to land first.
        // `connect_timeout` is deliberately generous (not the ~500ms this
        // crate's other tests use): this test runs `cargo test`'s full
        // default parallel-test-thread load with many real listeners across
        // two `run()` calls, and a tight timeout here was observed to be
        // exceeded under that contention alone (a genuine loopback
        // connection arriving late, not a scheduler bug) -- confirmed by
        // rerunning under `--test-threads=1`, where it never flaked; see
        // this task's report.
        // M4 Task 5: service detection disabled -- see the identical note on
        // `resuming_skips_a_completed_island_above_the_first_gap_not_just_a_contiguous_prefix`
        // above; this test's per-port accept counters are ground truth for
        // "was this unit's CONNECT probe issued more than once across a
        // cancel/resume round," and an enabled detection setting would add
        // its own reconnects onto the exact same counters for an unrelated
        // reason.
        let h = make_harness_with_detection(
            &["127.0.0.1"],
            &spec_refs,
            // pps=8 folded directly into the ceiling-bearing `Budgets`
            // value (M3 whole-branch review, IMPORTANT-2: no more separate
            // limiter-pps parameter) -- see the comment above on why 8.
            budgets(1_000_000, 3_600, 8),
            SchedulerConfig {
                concurrency: 10,
                connect_timeout: Duration::from_secs(5),
                progress_every: 500,
            },
            default_manifest(),
            ServiceDetection {
                enabled: false,
                intensity: 0,
            },
            EvidenceLevel::Headers,
        );
        assert_eq!(h.plan.len(), N);

        // Cancel once a meaningful fraction has completed -- polled, not a
        // fixed sleep, so this is robust to machine speed rather than
        // timing-flaky. Polls the REAL accept counters, not
        // `store.completed_units`: `mark_units_done` only runs once
        // `completed_batch` reaches `STORE_FLUSH_BATCH` (64) or the run
        // ends, so with N below that (as here), the store would never show
        // ANY progress until run1 has already stopped one way or another --
        // a store-based poll would either race on the final flush alone or,
        // worse, never see progress at all and let run1 run to natural
        // completion instead of being cancelled (the same hazard fixed in
        // `packet_ceiling_is_enforced_across_a_cancel_resume_loop_via_a_fresh_scheduler`
        // above).
        let cancel = CancellationToken::new();
        let counts_for_poll = counts.clone();
        let c = cancel.clone();
        let poller = tokio::spawn(async move {
            loop {
                let done: u64 = counts_for_poll
                    .values()
                    .map(|c| c.load(Ordering::SeqCst))
                    .sum();
                if done >= 5 {
                    c.cancel();
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });

        let first = h.scheduler.run(&h.plan, 0, cancel).await.unwrap();
        poller.await.unwrap();
        assert!(first.cancelled);
        assert!(
            first.units_completed < N,
            "must not have finished in a single run: {}",
            first.units_completed
        );
        assert!(first.units_completed > 0, "must have made progress");

        let resume_from = h.store.next_pending_unit(h.scan_id, N).unwrap().unwrap();
        let second = h
            .scheduler
            .run(&h.plan, resume_from, CancellationToken::new())
            .await
            .unwrap();
        assert!(!second.cancelled);
        assert!(!second.budget_exhausted);
        assert!(!second.time_exhausted);

        // The union, as the actual SET (dispatch's own instruction: "assert
        // on the actual set, not on counts") -- every index done exactly
        // once.
        let done: BTreeSet<u64> = h
            .store
            .completed_units(h.scan_id)
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(
            done,
            (0..N).collect::<BTreeSet<u64>>(),
            "the union of both runs must equal the plan exactly"
        );

        // This test runs on a single-threaded (current-thread) executor
        // alongside 90 acceptor tasks, the poller task, and both scheduler
        // runs: a `connect()` completing (recorded above in `done`) proves
        // the kernel finished the TCP handshake, but a straggler acceptor
        // task may simply not have been *polled* yet to drain it from its
        // listener's backlog -- observed directly under `cargo test`'s
        // default parallel-test-thread load. Bounded, not a blind fixed
        // sleep: waits only as long as it takes every already-completed
        // probe to actually be accepted, or gives up after a generous
        // ceiling (in which case the assertions below fail for real).
        for _ in 0..500 {
            let total: u64 = counts.values().map(|c| c.load(Ordering::SeqCst)).sum();
            if total >= N {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // The stronger, count-based proof: no port was ever accepted
        // (probed) more than once across the two runs.
        for (port, counter) in &counts {
            let n = counter.load(Ordering::SeqCst);
            assert_eq!(n, 1, "port {port} was probed {n} times, expected exactly 1");
        }

        // AC-3.28 across the WHOLE scan lifecycle, not per run() call.
        let events = h.events();
        let started = events
            .iter()
            .filter(|e| matches!(&e.body, EventBody::ScanStarted { .. }))
            .count();
        let completed = events
            .iter()
            .filter(|e| matches!(&e.body, EventBody::ScanCompleted { .. }))
            .count();
        assert_eq!(
            started, 1,
            "exactly one scan.started across the whole scan lifecycle"
        );
        assert_eq!(
            completed, 1,
            "exactly one scan.completed across the whole scan lifecycle"
        );

        // Every completed unit produced exactly one port.state event too
        // (AC-3.29), across both runs combined.
        let port_states = events
            .iter()
            .filter(|e| matches!(&e.body, EventBody::PortStateObserved { .. }))
            .count();
        assert_eq!(port_states as u64, N);
    }

    // ------------------------------------------------------------------
    // M3 whole-branch review, CRITICAL-1: proven by execution, the same
    // way the review itself proved it -- a manifest that authorizes only
    // an unrelated subnet, a plan addressing a REAL bound listener on
    // 127.0.0.1, and a scheduler that must refuse to ever connect to it.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn scheduler_refuses_to_emit_a_single_packet_against_a_target_the_manifest_denies() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&accepted);
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(s);
            }
        });

        let port_spec = port.to_string();
        let h = make_harness(
            &["127.0.0.1"],
            &[port_spec.as_str()],
            budgets(1_000_000, 3_600, 1_000_000),
            small_config(),
            manifest_denying_loopback(),
        );

        let summary = h.run_to_completion().await.unwrap();

        assert!(
            summary.policy_denied,
            "the scheduler must refuse a target the manifest denies, got {summary:?}"
        );
        assert_eq!(summary.units_completed, 0, "no unit may be probed");
        assert_eq!(
            summary.packets_spent, 0,
            "no budget may be spent on a target the manifest refuses"
        );

        // Give a real TCP handshake every chance to register before
        // asserting it never happened -- a short, bounded wait, not a race
        // resolved by asserting immediately. A real loopback connect that
        // was actually attempted completes in well under a millisecond;
        // 100ms is generous.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "CRITICAL-1: a real TCP accept occurred against an address the manifest \
             refuses -- exactly the defect proven by execution in the review"
        );

        let events = h.events();
        let denials: Vec<&Event> = events
            .iter()
            .filter(|e| matches!(&e.body, EventBody::PolicyDenied { .. }))
            .collect();
        assert_eq!(
            denials.len(),
            1,
            "expected exactly one policy.denied event, got {denials:?}"
        );
        assert!(
            matches!(
                &denials[0].body,
                EventBody::PolicyDenied { reason_code, .. } if *reason_code == DenyReason::TargetOutOfScope
            ),
            "expected reason_code target_out_of_scope, got {:?}",
            denials[0].body
        );
        // No other terminal event alongside it.
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(
                    &e.body,
                    EventBody::ScanCompleted { .. } | EventBody::ScanFailed { .. }
                ))
                .count(),
            0
        );

        assert_eq!(
            h.store.get(h.scan_id).unwrap().unwrap().status,
            TaskStatus::Denied
        );
    }

    // The re-check must stop the WHOLE scan, not just skip the one denied
    // unit and keep going: an authorized unit sequenced AFTER a denied one
    // in the plan must never be dispatched either. Port-major ordering
    // (`bathy-plan`) makes this easy to construct: two targets on the same
    // single port means unit 0 and unit 1 are the two hosts, in target
    // order.
    #[tokio::test]
    async fn a_policy_denial_stops_the_whole_scan_not_just_the_offending_unit() {
        // `manifest_denying_loopback` authorizes only 10.30.0.0/24 -- driven
        // directly with two synthetic IPv4 addresses: one it denies
        // (8.8.8.8, sorts numerically first, so it's unit 0) and one it
        // WOULD allow if `allows` were ever reached for it (10.30.0.1, unit
        // 1) -- proving the scan halts at the first denial rather than
        // working through the rest of the plan. Neither address is ever
        // actually connected to: `summary.units_completed == 0` below is
        // exactly the proof that the scan stops before unit 0's own
        // (never-happens) dispatch, let alone unit 1's.
        let manifest = manifest_denying_loopback();
        assert!(!manifest.allows("8.8.8.8".parse::<std::net::IpAddr>().unwrap()));
        assert!(manifest.allows("10.30.0.1".parse::<std::net::IpAddr>().unwrap()));

        let h = make_harness(
            &["8.8.8.8", "10.30.0.1"],
            &["9"],
            budgets(1_000_000, 3_600, 1_000_000),
            small_config(),
            manifest,
        );
        // `expand_targets` sorts numerically: unit 0 is 8.8.8.8 (denied),
        // unit 1 is 10.30.0.1 (would be allowed).
        assert_eq!(h.plan.len(), 2);
        assert_eq!(
            h.plan.unit(0).unwrap().target,
            "8.8.8.8".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(
            h.plan.unit(1).unwrap().target,
            "10.30.0.1".parse::<std::net::IpAddr>().unwrap()
        );

        let summary = h.run_to_completion().await.unwrap();
        assert!(summary.policy_denied);
        assert_eq!(
            summary.units_completed, 0,
            "unit 1 (10.30.0.1, which the manifest WOULD allow) must never be \
             reached once unit 0 is refused"
        );
        assert!(h.probed_indices().is_empty());
    }

    // ------------------------------------------------------------------
    // M3 whole-branch RE-review, Global Constraint (item 1): the per-unit
    // `allows` re-check above proves per-TARGET authorization, but a
    // `Scheduler` is only required to hold *a* `ScopeManifest` -- nothing
    // before this fix ever checked it was *the* manifest this scan was
    // actually authorized under (`record.scope_id`), or that it was still
    // active (`is_expired`). `bathy_scope::evaluate` -- the upfront check
    // that validates both -- has zero callers anywhere in this workspace,
    // so unlike the per-target re-check, these two are not belt-and-braces:
    // they are the only belt. Both proven the same way CRITICAL-1's own
    // headline defect was: a real bound listener, and a real accept count
    // that must stay at zero.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn run_refuses_when_the_manifest_belongs_to_a_different_scope_than_the_scan_record() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&accepted);
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(s);
            }
        });

        let manifest = manifest_for_a_different_scope();
        // Fixture sanity: this manifest's own allow-set/loopback exception
        // WOULD authorize the target -- the only thing that can refuse it
        // is the scope-identity check.
        assert!(manifest.allows("127.0.0.1".parse::<std::net::IpAddr>().unwrap()));

        let port_spec = port.to_string();
        let h = make_harness(
            &["127.0.0.1"],
            &[port_spec.as_str()],
            budgets(1_000_000, 3_600, 1_000_000),
            small_config(),
            manifest,
        );
        // Fixture sanity: the scan record's own scope_id (from
        // `ScanRequest.authorization_scope_id`, via `scope_id()`) really is
        // different from the manifest's id above.
        assert_ne!(
            h.store.get(h.scan_id).unwrap().unwrap().scope_id,
            "scope_01ARZ3NDEKTSV4RRFFQ69G5FBW".parse().unwrap()
        );

        let summary = h.run_to_completion().await.unwrap();
        assert!(summary.policy_denied, "got {summary:?}");
        assert_eq!(summary.units_completed, 0);
        assert_eq!(summary.packets_spent, 0);

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "Global Constraint: a real TCP accept occurred under a manifest belonging \
             to a DIFFERENT authorization scope than the scan record names"
        );

        let events = h.events();
        assert!(
            events
                .iter()
                .any(|e| matches!(&e.body, EventBody::PolicyDenied { reason_code, .. } if *reason_code == DenyReason::ScopeMismatch)),
            "expected a policy.denied event with reason_code scope_mismatch, got {events:#?}"
        );
        assert_eq!(
            h.store.get(h.scan_id).unwrap().unwrap().status,
            TaskStatus::Denied
        );
    }

    #[tokio::test]
    async fn run_refuses_under_an_expired_manifest() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&accepted);
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(s);
            }
        });

        let manifest = expired_manifest_allowing_loopback();
        // Fixture sanity: expired against this module's own clock seed
        // (every harness's `FixedClock` is fixed to `2026-08-01T...`).
        assert!(manifest.is_expired("2026-08-01T15:04:31.182Z"));
        assert!(
            manifest.allows("127.0.0.1".parse::<std::net::IpAddr>().unwrap()),
            "fixture sanity: everything BUT expiry would authorize this target"
        );

        let port_spec = port.to_string();
        let h = make_harness(
            &["127.0.0.1"],
            &[port_spec.as_str()],
            budgets(1_000_000, 3_600, 1_000_000),
            small_config(),
            manifest,
        );

        let summary = h.run_to_completion().await.unwrap();
        assert!(summary.policy_denied, "got {summary:?}");
        assert_eq!(summary.units_completed, 0);
        assert_eq!(summary.packets_spent, 0);

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "Global Constraint: a real TCP accept occurred under an EXPIRED manifest"
        );

        let events = h.events();
        assert!(
            events
                .iter()
                .any(|e| matches!(&e.body, EventBody::PolicyDenied { reason_code, .. } if *reason_code == DenyReason::ScopeExpired)),
            "expected a policy.denied event with reason_code scope_expired, got {events:#?}"
        );
        assert_eq!(
            h.store.get(h.scan_id).unwrap().unwrap().status,
            TaskStatus::Denied
        );
    }

    // A scope-validity denial (scope mismatch or expiry) is a whole-scan,
    // pre-dispatch refusal: unlike the per-unit `target_out_of_scope` path
    // (which lets `scan.started` through before the loop discovers a bad
    // unit), this must refuse before `scan.started` is ever emitted --
    // there is no unit-by-unit discovery involved, the manifest is already
    // known to be wrong before the plan is even touched.
    #[tokio::test]
    async fn a_scope_validity_denial_emits_no_scan_started() {
        let manifest = expired_manifest_allowing_loopback();
        let h = make_harness(
            &["127.0.0.1"],
            &["9"],
            budgets(1_000_000, 3_600, 1_000_000),
            small_config(),
            manifest,
        );
        h.run_to_completion().await.unwrap();
        let events = h.events();
        assert_eq!(
            events.len(),
            1,
            "expected exactly the one policy.denied event, nothing else, got {events:#?}"
        );
        assert!(matches!(&events[0].body, EventBody::PolicyDenied { .. }));
    }

    // ------------------------------------------------------------------
    // M3 whole-branch review, CRITICAL-2: `flush_progress` must make the
    // log durable BEFORE the store durably marks units done -- never the
    // other way around (see that method's own doc comment for the full
    // reasoning). Two tests, deliberately, proving two different things --
    // see the RE-review note on the second one for why the first is not
    // enough by itself.
    // ------------------------------------------------------------------

    // An observer task, not an after-the-fact assertion: `flush_progress`
    // itself runs synchronously (no `.await` inside it), so within one call
    // there is no interleaving point a concurrent task could ever observe
    // -- what THIS test can catch shows up only BETWEEN calls, while `run`'s
    // own dispatch loop is `.await`ing the next rate-limiter permit or
    // socket connect. A `GroupCommitConfig` with a huge `max_events`/
    // `max_interval` removes every OTHER source of a real log sync during
    // the run, so `sync_calls()` can only ever advance via the explicit
    // `force_sync()` this fix adds to `flush_progress` -- isolating exactly
    // the mechanism under test, the same technique the reviewer used to
    // prove the bug (`68 completed units, 0 real fsyncs`).
    //
    // M3 whole-branch RE-review: this test alone is NOT sufficient, and the
    // re-review proved that concretely -- reverting `flush_progress` to its
    // literal original bug shape (`mark_units_done` first, no `force_sync`
    // call of its own at all) still leaves this test passing, because
    // `flush_progress` has no `.await` inside it: there is no interleaving
    // point within one call for a concurrent poller to ever observe, and a
    // real crash between the two lines needs no `.await` point to reproduce
    // either. What this test actually proves is that a real sync happens
    // SOMEWHERE on this path at all, at roughly the right cadence -- a real
    // property, worth keeping, just not the ordering one. See
    // `a_failed_force_sync_leaves_the_store_resumption_cursor_untouched`
    // below for the test that actually pins the order.
    #[tokio::test]
    async fn flush_progress_forces_a_log_sync_before_the_store_durably_marks_units_done() {
        const N: u64 = 512; // several STORE_FLUSH_BATCH (64) batches
        let end = 20_000 + N - 1;
        let spec = format!("20000-{end}");
        // pps=300: `RateLimiter`'s capacity equals its configured pps, so
        // the first 300 units burst through immediately and the remaining
        // ~212 are genuinely throttled -- real `.await` yield points spread
        // across roughly the whole run, giving the poller below many
        // chances to interleave between `flush_progress` calls (as opposed
        // to the whole 512-unit scan completing inside one scheduling
        // burst with no observable gap at all).
        let h = make_harness_with_group_commit(
            &["127.0.0.1"],
            &[spec.as_str()],
            budgets(1_000_000, 3_600, 300),
            SchedulerConfig {
                concurrency: 16,
                connect_timeout: Duration::from_millis(300),
                progress_every: 500,
            },
            default_manifest(),
            GroupCommitConfig {
                max_events: 1_000_000,
                max_interval: Duration::from_secs(1_000),
            },
        );

        let violation = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let violation_poll = Arc::clone(&violation);
        let store = Arc::clone(&h.store);
        let log = Arc::clone(&h.log);
        let scan_id = h.scan_id;
        let poller = tokio::spawn(async move {
            loop {
                let done = store.completed_units(scan_id).unwrap().len() as u64;
                let synced = log.lock().unwrap().sync_calls();
                if done > 0 && synced == 0 {
                    violation_poll.store(true, Ordering::SeqCst);
                    break;
                }
                if done >= N {
                    break;
                }
                tokio::task::yield_now().await;
            }
        });

        let summary = h.run_to_completion().await.unwrap();
        poller.await.unwrap();

        assert_eq!(summary.units_completed, N);
        assert!(
            !violation.load(Ordering::SeqCst),
            "observed the store durably reporting completed units while the log had \
             issued zero real fsync(s) -- CRITICAL-2's inverted durability ordering"
        );
        assert!(
            h.log.lock().unwrap().sync_calls() >= 1,
            "sanity: this run must have forced at least one real sync via force_sync \
             (max_events/max_interval were both configured to never trigger on their own)"
        );
    }

    // M3 whole-branch RE-review, CRITICAL-2 item 2: the actual ordering
    // pin. `GroupCommitLog::fail_next_sync_for_tests` (test-only, see its
    // own doc comment for why a genuine fsync failure isn't available
    // portably or safely in this workspace) makes the very next real sync
    // attempt fail instead of touching the log at all. Arming it before
    // `run` means `flush_progress`'s own `force_sync()?` call (the one
    // this fix wave added) is what fails -- and if `force_sync` genuinely
    // runs, and is genuinely checked, BEFORE `mark_units_done`, that `?`
    // must short-circuit the whole function before `mark_units_done` is
    // ever reached. `h.probed_indices()` (the store's own resumption
    // cursor) being completely empty afterward is only explainable by that
    // ordering; if `mark_units_done` ran first (or the two calls' order
    // were ever flipped back), this unit would show up as done despite the
    // sync that was supposed to certify it having failed.
    #[tokio::test]
    async fn a_failed_force_sync_leaves_the_store_resumption_cursor_untouched() {
        let port = open_port().await;
        let h = harness(&["127.0.0.1"], &[port]);
        h.log.lock().unwrap().fail_next_sync_for_tests();

        let err = h.run_to_completion().await.unwrap_err();
        assert!(
            matches!(err, EngineError::Log(_)),
            "expected the synthetic sync failure to propagate as EngineError::Log, \
             got {err:?}"
        );

        assert!(
            h.probed_indices().is_empty(),
            "force_sync failing must mean mark_units_done never ran at all -- the \
             store's resumption cursor must be completely untouched, not partially \
             advanced: {:?}",
            h.probed_indices()
        );
        // The scan never reached its terminal-event section either: no
        // status transition (IMPORTANT-1) ever ran, so the store's status
        // is still exactly its construction-time default.
        assert_eq!(
            h.store.get(h.scan_id).unwrap().unwrap().status,
            TaskStatus::Pending
        );
    }

    // ------------------------------------------------------------------
    // M3 whole-branch review, IMPORTANT-1: `TaskStore::set_status` had no
    // caller outside its own tests -- a scan's status stayed `Pending`
    // forever regardless of outcome. Each test below drives `run` to a
    // different terminal outcome and checks the persisted status survives
    // a fresh `TaskStore::open` against the same directory, not just that
    // the harness's own already-open connection reflects it.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn set_status_transitions_to_completed_on_plan_exhaustion_and_survives_reopen() {
        let port = open_port().await;
        let h = harness(&["127.0.0.1"], &[port]);
        let summary = h.run_to_completion().await.unwrap();
        assert!(
            !summary.cancelled
                && !summary.budget_exhausted
                && !summary.time_exhausted
                && !summary.policy_denied
        );
        assert_eq!(reopened_status(&h), TaskStatus::Completed);
    }

    #[tokio::test]
    async fn set_status_transitions_to_cancelled_on_cancellation_and_survives_reopen() {
        let cancel = CancellationToken::new();
        cancel.cancel(); // already cancelled before run() even starts
        let h = harness_with_many_units(50);
        let summary = h.scheduler.run(&h.plan, 0, cancel).await.unwrap();
        assert!(summary.cancelled);
        assert_eq!(reopened_status(&h), TaskStatus::Cancelled);
    }

    #[tokio::test]
    async fn set_status_transitions_to_failed_on_budget_exhaustion_and_survives_reopen() {
        let h = harness_with_packet_budget(5);
        let summary = h.run_to_completion().await.unwrap();
        assert!(summary.budget_exhausted);
        assert_eq!(reopened_status(&h), TaskStatus::Failed);
    }

    #[tokio::test]
    async fn set_status_transitions_to_denied_on_a_policy_refusal_and_survives_reopen() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                drop(s);
            }
        });
        let port_spec = port.to_string();
        let h = make_harness(
            &["127.0.0.1"],
            &[port_spec.as_str()],
            budgets(1_000_000, 3_600, 1_000_000),
            small_config(),
            manifest_denying_loopback(),
        );
        let summary = h.run_to_completion().await.unwrap();
        assert!(summary.policy_denied);
        assert_eq!(reopened_status(&h), TaskStatus::Denied);
    }

    // ------------------------------------------------------------------
    // M3 whole-branch review, IMPORTANT-2: `Scheduler::new` no longer takes
    // a separate `RateLimiter` -- it derives one from
    // `ledger.packets_per_second()`. This is a structural fix (a caller can
    // no longer even ask for two different pps values), but this test is
    // the behavioral guard: a scan's REAL throttle must actually track
    // whatever `Budgets.maximum_packets_per_second` says, not some
    // independently-configured value that happened to match by convention
    // in every other test in this module.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn the_schedulers_real_throttle_tracks_the_budgets_configured_pps_not_a_separate_value() {
        const N: u64 = 200;
        const PPS: u32 = 100; // deliberately below N
        let end = 20_000 + N - 1;
        let spec = format!("20000-{end}");
        let h = make_harness(
            &["127.0.0.1"],
            &[spec.as_str()],
            budgets(1_000_000, 3_600, PPS),
            SchedulerConfig {
                concurrency: 32,
                connect_timeout: Duration::from_millis(300),
                progress_every: 500,
            },
            default_manifest(),
        );

        let start = Instant::now();
        let summary = h.run_to_completion().await.unwrap();
        let elapsed = start.elapsed();
        assert_eq!(summary.units_completed, N);

        // `RateLimiter`'s bucket capacity equals its configured pps, so PPS
        // tokens are available immediately and the remaining `N - PPS` must
        // be paced at PPS/second -- a scan this size finishing near
        // instantly would mean the scheduler's real limiter was not built
        // from `PPS` at all. 50% of the theoretical minimum is a generous
        // lower bound: comfortably clear of scheduling jitter while still
        // failing hard for "not actually throttled."
        let theoretical_minimum = Duration::from_secs_f64((N - PPS as u64) as f64 / PPS as f64);
        assert!(
            elapsed >= theoretical_minimum.mul_f64(0.5),
            "a scan of {N} units at a configured {PPS} pps finished in {elapsed:?}, well \
             under the ~{theoretical_minimum:?} the configured throttle should have taken \
             -- the scheduler's real limiter does not appear to be built from Budgets' \
             own maximum_packets_per_second"
        );
    }

    // ------------------------------------------------------------------
    // M3 whole-branch review, IMPORTANT-3: `run` must refuse a plan that
    // does not hash to what this scan_id was actually started (and, if
    // resuming, previously ran) against.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn run_refuses_a_plan_whose_hash_does_not_match_the_scans_stored_plan_hash() {
        let port = open_port().await;
        let h = harness(&["127.0.0.1"], &[port]);

        // A DIFFERENT plan for the same request shape -- same targets, same
        // everything else, but a different (fixed, always-distinct-from-a-
        // real-ephemeral-port) port selection, so it hashes differently.
        // Built directly, without ever going through `TaskStore::start_or_reuse`
        // again for this scan_id, to isolate exactly the case `run` itself
        // must catch: whatever plan a caller hands it, on a scan_id that
        // already names a different one.
        let different_request = ScanRequest {
            targets: NonEmpty::try_from(vec!["127.0.0.1".to_string()]).unwrap(),
            authorization_scope_id: scope_id(),
            objective: Objective::InventoryExposedServices,
            ports: PortSelection::Explicit {
                explicit: NonEmpty::try_from(vec!["1".to_string()]).unwrap(),
            },
            service_detection: ServiceDetection::default(),
            budgets: budgets(1_000_000, 3_600, 1_000_000),
            evidence_level: EvidenceLevel::Headers,
            idempotency_key: "harness-key".into(),
        };
        let different_plan = ScanPlan::build(&different_request, 1_000_000).unwrap();
        assert_ne!(
            different_plan.hash(),
            h.plan.hash(),
            "test fixture sanity: the two plans must actually differ"
        );

        let err = h
            .scheduler
            .run(&different_plan, 0, CancellationToken::new())
            .await
            .unwrap_err();
        assert!(
            matches!(err, EngineError::PlanMismatch { .. }),
            "expected PlanMismatch, got {err:?}"
        );
        assert!(
            h.events().is_empty(),
            "a mismatched plan must not emit anything at all, not even scan.started"
        );
    }

    #[tokio::test]
    async fn run_accepts_a_plan_that_hashes_to_exactly_what_the_scan_was_started_with() {
        // The positive case, stated directly rather than only inferred from
        // every other test in this module happening to pass `h.plan`
        // itself: an explicitly REBUILT plan (a fresh `ScanPlan::build`
        // call, not `h.plan` by reference) that hashes identically must be
        // accepted exactly like the original.
        let port = open_port().await;
        let h = harness(&["127.0.0.1"], &[port]);
        let request = ScanRequest {
            targets: NonEmpty::try_from(vec!["127.0.0.1".to_string()]).unwrap(),
            authorization_scope_id: scope_id(),
            objective: Objective::InventoryExposedServices,
            ports: PortSelection::Explicit {
                explicit: NonEmpty::try_from(vec![port.to_string()]).unwrap(),
            },
            service_detection: ServiceDetection::default(),
            budgets: budgets(1_000_000, 3_600, 1_000_000),
            evidence_level: EvidenceLevel::Headers,
            idempotency_key: "harness-key".into(),
        };
        let rebuilt_plan = ScanPlan::build(&request, 1_000_000).unwrap();
        assert_eq!(rebuilt_plan.hash(), h.plan.hash(), "test fixture sanity");

        let summary = h
            .scheduler
            .run(&rebuilt_plan, 0, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(summary.units_completed, 1);
    }

    // ==================================================================
    // M4 Task 5: wiring probes and interpretation into the scheduler.
    // AC-4.20 through AC-4.24.
    //
    // The brief's own Step 1 sketch references `harness_with_http_stub()`,
    // `harness_with_http_stub_no_detection()`,
    // `harness_with_http_stub_evidence_none()`,
    // `harness_with_tight_budget_and_http_stub(3)`, `h.evidence`, and
    // `h.stub_request_count()` without defining any of them -- the same
    // "Step 3 is a sketch" gap this module's very first harness comment
    // (above) already documents for M3 Task 7. `HttpStub` and
    // `spawn_http_stub` below fill that gap; the harness-plus-stub
    // constructors below return `(Harness, HttpStub)` rather than adding a
    // `stub_request_count()` method onto `Harness` itself, since a stub is
    // not part of what every OTHER harness in this module needs.
    // ==================================================================

    /// A real TCP listener that plays BOTH roles a `service_detection`
    /// -enabled scan puts the SAME endpoint through: the scheduler's own
    /// connect probe (a bare connect, which writes nothing and reads
    /// nothing) and, if that reports `Open` and detection is enabled,
    /// `http-get-v1`'s own reconnect (writes a real `GET /` request, reads
    /// the reply) -- see `Scheduler::detect_service`'s own doc comment for
    /// why these are two independent TCP connections to the very same
    /// address, never one reused socket.
    ///
    /// Distinguishes the two by what arrives, not by call order (multiple
    /// units in flight concurrently means "first accept" is not reliably
    /// "the connect probe"): if the peer sends at least one byte within a
    /// short window, this replies with a canned response headers that
    /// `bathy_interpret::rules`'s `http.server.nginx.v1` matches (the exact
    /// shape `crate::probes::http`'s own unit tests and M4 Task 2's real
    /// nginx capture use); a bare connect-and-drop (`probe_connect_with_local_signal`
    /// writes nothing) sees the read time out at 0 bytes and gets no reply
    /// at all, matching real `ConnectOutcome::Open` semantics exactly.
    struct HttpStub {
        port: u16,
        accepts: Arc<AtomicU64>,
        requests: Arc<AtomicU64>,
        bytes_received: Arc<AtomicU64>,
    }

    impl HttpStub {
        fn port(&self) -> u16 {
            self.port
        }
        /// Every real TCP accept this listener has served -- both bare
        /// connects and real probe requests.
        fn accept_count(&self) -> u64 {
            self.accepts.load(Ordering::SeqCst)
        }
        /// Accepts that actually carried at least one byte from the peer --
        /// i.e., a real probe request, not a bare connect-and-drop.
        fn request_count(&self) -> u64 {
            self.requests.load(Ordering::SeqCst)
        }
        /// Total bytes received across every connection this listener has
        /// ever accepted. AC-4.22's own proof obligation ("count bytes the
        /// stub receives, not just the absence of events") reads this
        /// directly, rather than only checking that no `service.observed`
        /// event was emitted.
        fn bytes_received(&self) -> u64 {
            self.bytes_received.load(Ordering::SeqCst)
        }
    }

    const NGINX_RESPONSE: &[u8] =
        b"HTTP/1.1 200 OK\r\nServer: nginx/1.26.0\r\nConnection: close\r\n\r\n<html></html>";

    /// [`NGINX_RESPONSE`]'s own headers, followed by a synthetic `body_len`
    /// -byte body -- used by the evidence-cap tests below, which need a
    /// response big enough to actually exercise `emit_service_observed`'s
    /// own truncation at a KNOWN byte count, not merely "some bytes."
    fn nginx_response_with_body_len(body_len: usize) -> Vec<u8> {
        let mut v =
            b"HTTP/1.1 200 OK\r\nServer: nginx/1.26.0\r\nConnection: close\r\n\r\n".to_vec();
        v.extend(std::iter::repeat_n(b'A', body_len));
        v
    }

    /// Real listener that replies with `response` to any connection that
    /// sends at least one byte (see [`HttpStub`]'s own doc comment for why
    /// that -- not accept order -- is what distinguishes a bare connect
    /// probe from a real probe request). `response` is owned (`Arc`-shared
    /// into the acceptor task), not `&'static`, so callers can build a
    /// response at runtime (e.g. [`nginx_response_with_body_len`]) rather
    /// than being limited to a fixed constant.
    async fn spawn_http_stub_with_response(response: Vec<u8>) -> HttpStub {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepts = Arc::new(AtomicU64::new(0));
        let requests = Arc::new(AtomicU64::new(0));
        let bytes_received = Arc::new(AtomicU64::new(0));
        let response = Arc::new(response);
        let (a, r, b) = (
            Arc::clone(&accepts),
            Arc::clone(&requests),
            Arc::clone(&bytes_received),
        );
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut sock, _)) = listener.accept().await {
                a.fetch_add(1, Ordering::SeqCst);
                let (r, b, response) = (Arc::clone(&r), Arc::clone(&b), Arc::clone(&response));
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = tokio::time::timeout(Duration::from_millis(200), sock.read(&mut buf))
                        .await
                        .ok()
                        .and_then(|res| res.ok())
                        .unwrap_or(0);
                    if n > 0 {
                        b.fetch_add(n as u64, Ordering::SeqCst);
                        r.fetch_add(1, Ordering::SeqCst);
                        let _ = sock.write_all(&response).await;
                    }
                });
            }
        });
        HttpStub {
            port,
            accepts,
            requests,
            bytes_received,
        }
    }

    async fn spawn_http_stub() -> HttpStub {
        spawn_http_stub_with_response(NGINX_RESPONSE.to_vec()).await
    }

    /// `service_detection: ServiceDetection::default()` (enabled, intensity
    /// 4), `evidence_level: Headers` -- what most of this section's tests
    /// need.
    async fn harness_with_http_stub() -> (Harness, HttpStub) {
        let stub = spawn_http_stub().await;
        let h = make_harness_with_detection(
            &["127.0.0.1"],
            &[&stub.port().to_string()],
            budgets(1_000_000, 3_600, 1_000_000),
            small_config(),
            default_manifest(),
            ServiceDetection::default(),
            EvidenceLevel::Headers,
        );
        (h, stub)
    }

    async fn harness_with_http_stub_no_detection() -> (Harness, HttpStub) {
        let stub = spawn_http_stub().await;
        let h = make_harness_with_detection(
            &["127.0.0.1"],
            &[&stub.port().to_string()],
            budgets(1_000_000, 3_600, 1_000_000),
            small_config(),
            default_manifest(),
            ServiceDetection {
                enabled: false,
                intensity: 4,
            },
            EvidenceLevel::Headers,
        );
        (h, stub)
    }

    async fn harness_with_http_stub_evidence_none() -> (Harness, HttpStub) {
        let stub = spawn_http_stub().await;
        let h = make_harness_with_detection(
            &["127.0.0.1"],
            &[&stub.port().to_string()],
            budgets(1_000_000, 3_600, 1_000_000),
            small_config(),
            default_manifest(),
            ServiceDetection::default(),
            EvidenceLevel::None,
        );
        (h, stub)
    }

    // --- From the brief (Step 1), adapted: `h.stub_request_count()` and
    // `h.evidence` become the returned `stub`/`h.evidence` above -- see
    // this section's own header comment. ---

    #[tokio::test]
    async fn an_open_port_with_service_detection_emits_port_state_then_service_observed() {
        let (h, _stub) = harness_with_http_stub().await;
        h.run_to_completion().await.unwrap();
        let events = h.log.lock().unwrap().read_from(0).unwrap();
        let state_at = events
            .iter()
            .position(|e| matches!(&e.body, EventBody::PortStateObserved { .. }))
            .unwrap();
        let service_at = events
            .iter()
            .position(|e| matches!(&e.body, EventBody::ServiceObserved { .. }))
            .unwrap();
        assert!(
            state_at < service_at,
            "reachability is established before identification"
        );
        // Not just an event, a REAL finding: the exact shape the stub sent.
        match &events[service_at].body {
            EventBody::ServiceObserved {
                observation,
                probe_id,
                ..
            } => {
                assert_eq!(observation.service, "http");
                assert_eq!(observation.product.as_deref(), Some("nginx"));
                assert_eq!(probe_id, "http-get-v1");
            }
            other => panic!("expected ServiceObserved, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn evidence_is_stored_before_the_event_that_references_it() {
        let (h, _stub) = harness_with_http_stub().await;
        h.run_to_completion().await.unwrap();
        let mut checked = 0;
        for e in h.log.lock().unwrap().read_from(0).unwrap() {
            if let EventBody::ServiceObserved { evidence_refs, .. } = &e.body {
                for d in evidence_refs.iter() {
                    assert!(h.evidence.contains(d), "dangling evidence ref {d}");
                    assert!(h.evidence.get(d).is_ok());
                    checked += 1;
                }
            }
        }
        assert!(
            checked > 0,
            "test fixture sanity: expected >= 1 evidence ref to check"
        );
    }

    #[tokio::test]
    async fn service_detection_disabled_emits_no_service_events_and_sends_no_probes() {
        let (h, stub) = harness_with_http_stub_no_detection().await;
        h.run_to_completion().await.unwrap();
        assert!(
            !h.log
                .lock()
                .unwrap()
                .read_from(0)
                .unwrap()
                .iter()
                .any(|e| matches!(&e.body, EventBody::ServiceObserved { .. }))
        );
        assert_eq!(stub.request_count(), 0);
        // AC-4.22's stronger half, per this task's own review guidance:
        // count bytes the stub actually RECEIVED, not merely the absence of
        // a `service.observed` event -- a scheduler that connected and
        // wrote SOME bytes without them happening to form a request the
        // stub's own `n > 0` branch counted as a "request" would still pass
        // a request-count-only check.
        assert_eq!(
            stub.bytes_received(),
            0,
            "service_detection.enabled = false must put zero probe bytes on the wire"
        );
        // The plain connect probe itself still ran (this endpoint IS
        // `Open`) -- so this is genuinely "detection sent nothing," not
        // "nothing touched this port at all." Polled, not asserted
        // immediately: `run_to_completion` returning only means the
        // CLIENT-side `TcpStream::connect` resolved, not that this stub's
        // own spawned acceptor task has been polled far enough to have
        // incremented its counter yet.
        for _ in 0..200 {
            if stub.accept_count() >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(stub.accept_count() >= 1, "test fixture sanity");
    }

    #[tokio::test]
    async fn evidence_level_none_stores_no_blobs_and_therefore_emits_no_service_observed() {
        // Root-cause note (this task's report): the brief's own Step 1
        // sketch for this test (`evidence_level_none_stores_no_bodies_but_
        // still_reports_the_observation`) asserted a `ServiceObserved`
        // event WAS present even under `evidence_level: none`. That
        // contradicts this same brief's own Step 3 text and AC-4.23, both
        // of which say `evidence_level: none` "emits no service.observed
        // event at all" -- and it is not merely a documentation
        // disagreement: `EventBody::ServiceObserved::evidence_refs` is
        // `NonEmpty<Digest>`, so representing a finding with zero evidence
        // would require either a placeholder digest citing bytes nobody
        // stored (reintroducing the exact dangling-reference failure this
        // whole design exists to prevent) or relaxing the field to
        // `Option<NonEmpty<Digest>>` (weakening the type's own guarantee
        // for every OTHER evidence level too). Neither is acceptable, so
        // this test asserts the behavior the type actually allows, not the
        // brief's self-contradictory literal assertion.
        let (h, stub) = harness_with_http_stub_evidence_none().await;
        h.run_to_completion().await.unwrap();
        let events = h.log.lock().unwrap().read_from(0).unwrap();
        assert!(
            !events
                .iter()
                .any(|e| matches!(&e.body, EventBody::ServiceObserved { .. })),
            "evidence_level: none must emit no service.observed event"
        );
        assert_eq!(h.evidence_blob_count(), 0);
        // The probe still ran (budget was still spent identifying, even
        // though nothing gets kept) -- confirms this is "found nothing
        // worth keeping," not "never tried."
        assert!(stub.request_count() >= 1, "test fixture sanity");
    }

    #[tokio::test]
    async fn probe_packets_are_charged_to_the_same_budget_as_connect_probes() {
        // M3's review (carried into this task by the dispatch): asserting
        // only on `summary.packets_spent <= 3` proves nothing, because the
        // ledger cannot report exceeding its own ceiling by construction --
        // a bug that let MORE real packets go out than the ledger recorded
        // would look identical to correct behavior on that assertion alone.
        // This test's ground truth is a REAL listener's own accept counter,
        // like `budget_ceiling_is_never_exceeded_measured_by_real_accept_counts_not_the_ledger`
        // above uses for the plain connect-probe case.
        //
        // Deliberately a single unit whose peer never sends a matching
        // reply (a bare accept-and-drop, like `open_port()`): this keeps
        // every probe attempt sequential and deterministic (all inside one
        // `detect_service` call, never racing a second unit's own
        // dispatch), so the exact accept count this ceiling permits is
        // knowable ahead of time: 1 (the connect probe) + 2 (two probe
        // attempts, each failing to find a match and moving on) = 3, with
        // the third probe attempt's OWN budget reservation refused before
        // it ever reconnects.
        let (h, counts) =
            harness_with_real_listeners(1, budgets(3, 3_600, 1_000_000), small_config()).await;
        let summary = h.run_to_completion().await.unwrap();
        assert!(summary.packets_spent <= 3);

        settle_accept_counters(&counts, 3).await;
        let total: u64 = counts.values().map(|c| c.load(Ordering::SeqCst)).sum();
        assert_eq!(
            total, 3,
            "a budget of 3 must permit at most 3 REAL accepts across connect AND probe traffic, got {total}"
        );
        assert_eq!(summary.packets_spent, 3);
    }

    #[tokio::test]
    async fn service_detection_scope_gate_covers_the_second_connection_not_just_the_first() {
        // M3's review found the scheduler once emitted packets without
        // consulting scope at all; this task's dispatch calls out that
        // service detection opens a SECOND connection to the same
        // endpoint, and that connection must be gated too, not exempted
        // because the port scan already passed the first one. Calls
        // `detect_service` directly (private, but this module is a child
        // of `scheduler` -- see the existing precedent at `record`'s own
        // direct-call test above) against a manifest that denies the
        // target, so this is independent of whatever the outer dispatch
        // loop's own per-unit gate does (that gate would, in real
        // operation, already have refused the whole scan before
        // `detect_service` is ever reached -- this test isolates the
        // second, belt-and-braces check inside `detect_service` itself).
        let stub = spawn_http_stub().await;
        let h = make_harness_with_detection(
            &["127.0.0.1"],
            &[&stub.port().to_string()],
            budgets(1_000_000, 3_600, 1_000_000),
            small_config(),
            manifest_denying_loopback(),
            ServiceDetection::default(),
            EvidenceLevel::Headers,
        );
        let unit = ScanUnit {
            index: 0,
            target: "127.0.0.1".parse().unwrap(),
            endpoint: Endpoint {
                transport: Transport::Tcp,
                port: stub.port(),
            },
        };
        let result = h
            .scheduler
            .detect_service(&unit, &CancellationToken::new())
            .await
            .unwrap();
        assert!(
            result.is_none(),
            "a denied target must never be reconnected to for identification"
        );
        assert_eq!(
            stub.accept_count(),
            0,
            "a denied target's second connection must never even dial, let alone accept"
        );
    }

    // NOTE (M4 Task 5 fix round 1, per review): this section used to include
    // `an_observer_polling_concurrently_never_sees_a_dangling_evidence_ref`,
    // a `tokio::spawn`ed poller running concurrently with the scan. Deleted:
    // review measured it catching 0 of 12 real mutations (including the
    // literal store/log-order inversion it was written for -- see mutation
    // test 2 in this task's report) and it passed VACUOUSLY whenever
    // detection found nothing to report, with no `checked > 0` guard to
    // catch that. `emit_service_observed` has no `.await` between its
    // `put_capped` and `log` calls (both synchronous), so on this
    // codebase's `#[tokio::test]` single-threaded runtime nothing can ever
    // actually interleave between them -- a concurrent poller can only see
    // "neither yet" or "both already," identically for the correct order
    // and an inverted one, as long as the store call itself does not fail.
    // `a_failed_evidence_write_leaves_no_service_observed_event_that_would_have_cited_it`
    // below (real permission-denied injection) is the one test in this file
    // that actually discriminates the ordering, and it is kept.

    #[tokio::test]
    async fn port_state_precedes_service_observed_for_every_endpoint_and_no_evidence_ref_ever_dangles()
     {
        // A real end-to-end run over MULTIPLE endpoints, not just one --
        // walking every event, not only the first `port.state`/
        // `service.observed` pair, and checking `EvidenceStore::get` (not
        // merely `contains`, which does not verify the bytes) for every
        // single `evidence_refs` entry the whole run produced.
        let stub_a = spawn_http_stub().await;
        let stub_b = spawn_http_stub().await;
        let h = make_harness_with_detection(
            &["127.0.0.1"],
            &[&stub_a.port().to_string(), &stub_b.port().to_string()],
            budgets(1_000_000, 3_600, 1_000_000),
            small_config(),
            default_manifest(),
            ServiceDetection::default(),
            EvidenceLevel::Full,
        );
        let summary = h.run_to_completion().await.unwrap();
        assert_eq!(summary.open_ports, 2, "test fixture sanity");

        let events = h.log.lock().unwrap().read_from(0).unwrap();

        // Per-endpoint ordering: for every `service.observed`, the SAME
        // endpoint's `port.state` occurred earlier in the log.
        let mut service_observed_count = 0;
        for (i, e) in events.iter().enumerate() {
            if let EventBody::ServiceObserved { endpoint, .. } = &e.body {
                service_observed_count += 1;
                let state_index = events[..i].iter().position(|earlier| {
                    matches!(
                        &earlier.body,
                        EventBody::PortStateObserved { endpoint: ep, state: PortState::Open, .. }
                            if ep.port == endpoint.port
                    )
                });
                assert!(
                    state_index.is_some(),
                    "service.observed for port {} has no preceding port.state(open) for the \
                     same endpoint",
                    endpoint.port
                );
            }
        }
        assert_eq!(
            service_observed_count, 2,
            "both stubs must be identified, given AC-4.21 is being proven over more than one \
             endpoint"
        );

        // No dangling ref, walked over the WHOLE log, verified with `get`
        // (not just `contains`) so a corrupted-but-present blob would also
        // be caught.
        let mut checked = 0;
        for e in &events {
            if let EventBody::ServiceObserved { evidence_refs, .. } = &e.body {
                for d in evidence_refs.iter() {
                    let bytes = h.evidence.get(d).unwrap_or_else(|err| {
                        panic!(
                            "evidence_refs entry {d} does not resolve via EvidenceStore::get: {err}"
                        )
                    });
                    assert!(!bytes.is_empty());
                    checked += 1;
                }
            }
            if let EventBody::PortStateObserved {
                evidence_refs: Some(refs),
                ..
            } = &e.body
            {
                for d in refs.iter() {
                    assert!(
                        h.evidence.get(d).is_ok(),
                        "dangling port.state evidence ref {d}"
                    );
                    checked += 1;
                }
            }
        }
        assert_eq!(
            checked, 2,
            "expected exactly one evidence ref per identified endpoint"
        );
    }

    // The ordering proof that does not depend on cooperative task
    // scheduling happening to interleave: `emit_service_observed` itself
    // has no `.await` between its `put_capped` call and its `log` call (both
    // are synchronous), so on `#[tokio::test]`'s default single-threaded
    // runtime an observer task polling concurrently (above) can never
    // actually land IN BETWEEN them -- it can only ever see "neither yet"
    // or "both already," identically whether the two calls are in the
    // correct order or swapped. The real-world failure mode this whole
    // ordering rule defends against is a CRASH between the two lines, not a
    // scheduler interleaving, and the way M2/M3 proved the analogous
    // store/log ordering was to force a REAL failure on the store side and
    // assert the log side never ran -- `GroupCommitLog::fail_next_sync_for_tests`
    // for the group-commit case. `bathy-evidence` has no equivalent
    // test-only injection door, so this forces a REAL `EvidenceStore::put`
    // failure instead, via an unwritable `blobs/` directory -- no mock, a
    // genuine `EACCES` from the OS.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_failed_evidence_write_leaves_no_service_observed_event_that_would_have_cited_it() {
        use std::os::unix::fs::PermissionsExt;

        let (h, _stub) = harness_with_http_stub().await;
        let blobs = h.evidence_root();
        std::fs::create_dir_all(&blobs).unwrap();
        std::fs::set_permissions(&blobs, std::fs::Permissions::from_mode(0o555)).unwrap();

        let result = h.run_to_completion().await;

        // Restore write permission unconditionally (even on assertion
        // failure below) so the harness's `TempDir` can still clean itself
        // up on drop.
        std::fs::set_permissions(&blobs, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            result.is_err(),
            "a real EvidenceStore::put failure must propagate as a real error, not be swallowed"
        );
        let events = h.log.lock().unwrap().read_from(0).unwrap();
        assert!(
            !events
                .iter()
                .any(|e| matches!(&e.body, EventBody::ServiceObserved { .. })),
            "a failed evidence write must never be followed by the event that would have cited \
             it -- got {events:#?}"
        );
        // The port.state event for the same endpoint DID make it through --
        // this failure is specific to the evidence/service-observed path,
        // not a wholesale inability to log anything at all.
        assert!(
            events
                .iter()
                .any(|e| matches!(&e.body, EventBody::PortStateObserved { .. })),
            "port.state should still have been appended before the evidence write was attempted"
        );
    }

    // ==================================================================
    // M4 Task 5 fix round 1 (review): CRITICAL-1 (probe reconnects bypassed
    // the rate limiter), CRITICAL-2 (cancellation did not stop new probe
    // traffic), and three IMPORTANTs (evidence content, evidence-level
    // caps, and intensity were all unverified at the wiring level -- only
    // their PRESENCE/absence was ever asserted, not their actual values).
    // ==================================================================

    /// Finds the first `service.observed` event's cited digest. Shared by
    /// several tests below that need to read back what was actually
    /// stored, not merely confirm an event of that shape exists.
    fn first_service_observed_digest(events: &[Event]) -> Digest {
        events
            .iter()
            .find_map(|e| match &e.body {
                EventBody::ServiceObserved { evidence_refs, .. } => Some(*evidence_refs.first()),
                _ => None,
            })
            .expect("expected at least one service.observed event")
    }

    #[tokio::test]
    async fn probe_reconnects_are_paced_by_the_rate_limiter_not_only_counted() {
        // CRITICAL-1. 1 pps: the connect probe consumes the `RateLimiter`'s
        // one immediate/burst token ("the first burst is immediate" --
        // `rate::tests`), so the SECOND real packet -- `http-get-v1`'s own
        // successful reconnect -- can only leave once the bucket refills,
        // ~1 real second later, IF (and only if) `detect_service` actually
        // calls `self.limiter.acquire`. Measured on WALL-CLOCK elapsed
        // time, not `packets_spent`: the ledger counts spend regardless of
        // pacing, which is exactly how this defect survived every
        // pre-existing pps test (all of which scan closed ports, where
        // `detect_service` never runs at all).
        let stub = spawn_http_stub().await;
        let h = make_harness_with_detection(
            &["127.0.0.1"],
            &[&stub.port().to_string()],
            budgets(1_000_000, 3_600, 1),
            small_config(),
            default_manifest(),
            ServiceDetection::default(),
            EvidenceLevel::Headers,
        );
        let started = Instant::now();
        let summary = h.run_to_completion().await.unwrap();
        let elapsed = started.elapsed();

        assert_eq!(
            summary.packets_spent, 2,
            "test fixture sanity: connect + one matching probe"
        );
        assert_eq!(
            stub.request_count(),
            1,
            "test fixture sanity: identification succeeded on the very first probe candidate"
        );
        assert!(
            elapsed >= Duration::from_millis(900),
            "2 packets at 1 pps must take ~1s; took {elapsed:?} -- probe packets bypass the \
             RateLimiter entirely"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "sanity: must not hang well past the expected ~1s, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn cancellation_stops_new_probe_traffic_not_just_new_units() {
        // CRITICAL-2. `concurrency: 1`, `pps: 1`: unit 0's connect probe
        // consumes the limiter's one immediate token and resolves near
        // instantly (real loopback); the dispatch loop's very next action
        // is to try to dispatch unit 1, which genuinely BLOCKS for ~1s
        // waiting on the rate limiter to refill -- a wide, deterministic
        // window in which the background task below fires `cancel` well
        // before that wait would otherwise resolve. By the time `cancel`
        // lands, unit 0's connect result is already sitting in `in_flight`,
        // UNHARVESTED (nothing has called `try_join_next` again since
        // dispatching it) -- so it is exactly the "already-dispatched,
        // in-flight work" invariant 2 says must still be drained, when the
        // post-`'drive` unconditional drain loop picks it up and calls
        // `record`. Before this fix, that meant `detect_service` would
        // still open a fresh reconnect and write real bytes to `stub_a`
        // AFTER cancellation; after it, `detect_service`'s own
        // `cancel.is_cancelled()` check refuses to start anything.
        let stub_a = spawn_http_stub().await;
        let stub_b = spawn_http_stub().await;
        let h = make_harness_with_detection(
            &["127.0.0.1"],
            &[&stub_a.port().to_string(), &stub_b.port().to_string()],
            budgets(1_000_000, 3_600, 1),
            SchedulerConfig {
                concurrency: 1,
                ..small_config()
            },
            default_manifest(),
            ServiceDetection::default(),
            EvidenceLevel::Headers,
        );

        let cancel = CancellationToken::new();
        let cancel_after = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            cancel_after.cancel();
        });

        let summary = h.scheduler.run(&h.plan, 0, cancel).await.unwrap();
        assert!(
            summary.cancelled,
            "test fixture sanity: expected a genuine cancellation, got {summary:?}"
        );

        // Give any (incorrect) post-cancel probe traffic a moment to land
        // before asserting its absence -- polling-style generous wait, not
        // a blind assumption that "the run already returned" means every
        // background acceptor task has caught up.
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(
            stub_a.accept_count(),
            1,
            "unit 0's own connect probe is real, already-paid-for work and must still be \
             drained -- but nothing beyond it"
        );
        assert_eq!(
            stub_a.bytes_received(),
            0,
            "detect_service must not write any probe bytes for a unit whose connect probe only \
             completed AFTER cancellation was observed -- {} bytes were sent post-cancel",
            stub_a.bytes_received()
        );
        assert_eq!(
            stub_b.accept_count(),
            0,
            "test fixture sanity: unit 1 must never even be dispatched"
        );
    }

    #[tokio::test]
    async fn evidence_bytes_are_exactly_the_bytes_that_justified_the_finding() {
        // IMPORTANT: the strongest assertion in this file before this fix
        // was `!bytes.is_empty()` -- mutating `evidence: capture.response`
        // to a fixed placeholder survived all 91 tests. AC-4.20's real
        // property is that the cited bytes JUSTIFY the finding, not merely
        // that some non-empty blob exists under the digest.
        let (h, _stub) = harness_with_http_stub().await;
        h.run_to_completion().await.unwrap();
        let events = h.log.lock().unwrap().read_from(0).unwrap();
        let digest = first_service_observed_digest(&events);
        let bytes = h.evidence.get(&digest).unwrap();
        assert_eq!(
            bytes, NGINX_RESPONSE,
            "cited evidence must be the EXACT response bytes that justified the finding, not \
             merely some non-empty placeholder"
        );
    }

    #[tokio::test]
    async fn evidence_level_headers_caps_stored_evidence_at_exactly_eight_kib() {
        // IMPORTANT: mutating the `Headers`/`Full` cap constants to `1`
        // survived every existing test -- a 1-byte blob is still
        // non-empty. A response well over 8 KiB is required to actually
        // exercise the cap, not just its presence.
        let stub = spawn_http_stub_with_response(nginx_response_with_body_len(20_000)).await;
        let h = make_harness_with_detection(
            &["127.0.0.1"],
            &[&stub.port().to_string()],
            budgets(1_000_000, 3_600, 1_000_000),
            small_config(),
            default_manifest(),
            ServiceDetection::default(),
            EvidenceLevel::Headers,
        );
        h.run_to_completion().await.unwrap();
        let events = h.log.lock().unwrap().read_from(0).unwrap();
        let digest = first_service_observed_digest(&events);
        let bytes = h.evidence.get(&digest).unwrap();
        assert_eq!(
            bytes.len(),
            8 * 1024,
            "EvidenceLevel::Headers must cap stored evidence at exactly 8 KiB, got {} bytes",
            bytes.len()
        );
    }

    #[tokio::test]
    async fn evidence_level_full_caps_stored_evidence_at_exactly_sixty_four_kib() {
        // IMPORTANT, same shape as the Headers cap test above. Honest
        // limit, stated rather than glossed over: `ProbeIo::DEFAULT_READ_CAP`
        // is ALSO 64 KiB, so a response this large is already truncated to
        // exactly 64 KiB by the probe's own read cap before
        // `emit_service_observed` ever sees it -- this test cannot, on its
        // own, distinguish `emit_service_observed`'s cap from
        // `ProbeIo`'s having already done the truncating. It still pins
        // the CONSTANT the review flagged as unverified: a mutated
        // `Full => 1` (or any value other than 65536) still fails this
        // assertion regardless of which layer's cap "really" produced the
        // final length.
        let stub = spawn_http_stub_with_response(nginx_response_with_body_len(100_000)).await;
        let h = make_harness_with_detection(
            &["127.0.0.1"],
            &[&stub.port().to_string()],
            budgets(1_000_000, 3_600, 1_000_000),
            small_config(),
            default_manifest(),
            ServiceDetection::default(),
            EvidenceLevel::Full,
        );
        h.run_to_completion().await.unwrap();
        let events = h.log.lock().unwrap().read_from(0).unwrap();
        let digest = first_service_observed_digest(&events);
        let bytes = h.evidence.get(&digest).unwrap();
        assert_eq!(
            bytes.len(),
            64 * 1024,
            "EvidenceLevel::Full must cap stored evidence at exactly 64 KiB, got {} bytes",
            bytes.len()
        );
    }

    #[tokio::test]
    async fn intensity_bounds_how_many_probe_candidates_are_attempted_not_a_hardcoded_value() {
        // IMPORTANT: replacing `self.service_detection.intensity` with a
        // hardcoded `9` survived every existing test. A plain
        // accept-and-drop real listener (never replies to anything, so
        // EVERY probe candidate fails with `ProbeError::EmptyResponse` and
        // `detect_service` moves on to the next one) means the number of
        // real accepts is EXACTLY 1 (connect) + however many candidates
        // `select_probes` actually returned -- with `intensity: 1`, that
        // must be exactly 2, never 9 (all 8 registered probes, which is
        // what a value hardcoded to `9` would produce once `select_probes`
        // clamps it to the registry's own size).
        let (h, counts) = harness_with_real_listeners_and_detection(
            1,
            budgets(1_000_000, 3_600, 1_000_000),
            small_config(),
            ServiceDetection {
                enabled: true,
                intensity: 1,
            },
        )
        .await;
        h.run_to_completion().await.unwrap();
        settle_accept_counters(&counts, 2).await;
        // Extra grace beyond `settle_accept_counters`'s own early-break:
        // every real probe ATTEMPT already happened, synchronously, before
        // `run_to_completion` returned (each is `.await`ed in sequence
        // inside `detect_service`) -- what might still be lagging is only
        // the SERVER side's own bookkeeping for the very last accept.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let total: u64 = counts.values().map(|c| c.load(Ordering::SeqCst)).sum();
        assert_eq!(
            total, 2,
            "intensity: 1 must attempt exactly one probe candidate (1 connect + 1 probe \
             reconnect), got {total} real accepts -- a hardcoded intensity would ignore the \
             request's own authorized bound on probes-per-endpoint"
        );
    }

    #[tokio::test]
    async fn resuming_a_cancelled_scan_identifies_the_untouched_endpoint_without_re_probing() {
        // Minor gap noted by review: nothing previously exercised
        // resumption with `service_detection` enabled at all.
        //
        // Deliberately CANCELLATION, not budget exhaustion: `run`'s own
        // doc comment (and `resuming_a_budget_exhausted_scan_is_a_safe_no_op`
        // above) establish that a budget/time-exhausted scan already ended
        // in a terminal `scan.failed` event, and calling `run` again on
        // that same log is a safe NO-OP by design, not a resume -- a first
        // draft of this test tried to resume a budget-exhausted run and
        // measured exactly that (`units_completed: 0` on the "resumed"
        // call, i.e. no-op). Cancellation is the only scenario this
        // codebase actually resumes.
        //
        // Reuses `cancellation_stops_new_probe_traffic_not_just_new_units`'s
        // own proven construction (`concurrency: 1`, `pps: 1`, cancel at
        // 50ms): unit 0's connect resolves and lands in `in_flight`
        // unharvested while unit 1's own dispatch attempt genuinely blocks
        // on the rate limiter; cancelling in that window means run1's
        // unconditional drain loop harvests unit 0 (`Open`, its connect
        // WAS already paid for) but `detect_service` refuses to identify
        // it (cancelled), and unit 1 is never even reached.
        //
        // Worth recording as an honest, structural observation (not a new
        // defect this task's own review asked to fix): unit 0's own
        // identification is now lost FOR GOOD, even across resume --
        // invariant 3 ("resumption never re-probes") is unconditional on
        // `already_done` (a unit's CONNECT having completed), which has
        // no way to distinguish "connected and identified" from
        // "connected, identification cancelled." A future task could
        // track per-unit identification status separately if this gap
        // ever needs closing; out of scope for this fix round.
        let stub_a = spawn_http_stub().await;
        let stub_b = spawn_http_stub().await;
        let h = make_harness_with_detection(
            &["127.0.0.1"],
            &[&stub_a.port().to_string(), &stub_b.port().to_string()],
            budgets(1_000_000, 3_600, 1),
            SchedulerConfig {
                concurrency: 1,
                ..small_config()
            },
            default_manifest(),
            ServiceDetection::default(),
            EvidenceLevel::Headers,
        );

        let cancel = CancellationToken::new();
        let cancel_after = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            cancel_after.cancel();
        });

        let summary1 = h.scheduler.run(&h.plan, 0, cancel).await.unwrap();
        assert!(
            summary1.cancelled,
            "test fixture sanity: run1 must be cancelled, got {summary1:?}"
        );
        // Give the stub's own acceptor task a moment to catch up before
        // reading its counter -- see the settle note on other tests in
        // this section.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            stub_a.accept_count(),
            1,
            "test fixture sanity: unit 0's connect ran (paid-for work, correctly drained)"
        );
        assert_eq!(
            stub_a.request_count(),
            0,
            "test fixture sanity: unit 0's identification was correctly refused post-cancel"
        );
        assert_eq!(
            stub_b.accept_count(),
            0,
            "test fixture sanity: unit 1 must never have been reached by run1"
        );

        let events1 = h.log.lock().unwrap().read_from(0).unwrap();
        assert!(
            !events1
                .iter()
                .any(|e| matches!(&e.body, EventBody::ServiceObserved { .. })),
            "test fixture sanity: nothing identified in run1"
        );

        // Resume with a fresh, well-funded `Scheduler` over the SAME scan.
        let from_index = h
            .store
            .next_pending_unit(h.scan_id, h.plan.len())
            .unwrap()
            .unwrap();
        assert_eq!(
            from_index, 1,
            "test fixture sanity: unit 0 already marked done (its CONNECT completed), even \
             though it was never identified"
        );
        let scheduler2 = h.resume(small_config(), budgets(1_000_000, 3_600, 1_000_000));
        let summary2 = scheduler2
            .run(&h.plan, from_index, CancellationToken::new())
            .await
            .unwrap();
        assert!(!summary2.budget_exhausted);
        assert!(!summary2.cancelled);

        let events2 = h.log.lock().unwrap().read_from(0).unwrap();
        let service_observed_2 = events2
            .iter()
            .filter(|e| matches!(&e.body, EventBody::ServiceObserved { .. }))
            .count();
        assert_eq!(
            service_observed_2, 1,
            "unit 1 -- the only endpoint resumption actually re-drives -- must be identified \
             exactly once during run2"
        );

        // No unit's own probe traffic ran twice, across BOTH runs: unit 0
        // is never touched again (invariant 3), unit 1 is connected AND
        // identified exactly once, entirely within run2.
        assert_eq!(
            stub_a.accept_count(),
            1,
            "unit 0 must not be re-probed on resume, in any form"
        );
        assert_eq!(
            stub_b.accept_count(),
            2,
            "unit 1 must be fully connected AND identified during run2, exactly once"
        );
    }
}
