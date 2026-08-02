//! The scheduler: budget-governed, cancellable, resumable execution of a
//! [`ScanPlan`]. This is the component that turns every other M1-M3 piece
//! into an actual scanner.
//!
//! # Four invariants
//!
//! 1. **Budget is reserved before emission, never after.** [`Scheduler::run`]
//!    calls [`BudgetLedger::try_spend_packets`] immediately before spawning a
//!    unit's probe, never after. A refused reservation ends the scan; it
//!    never emits "just one more" packet -- see the cancellable-wait/reserve
//!    ordering in the dispatch loop below for exactly where this happens.
//! 2. **Cancellation drains in-flight work rather than dropping it.** Once a
//!    unit has been dispatched (its budget already spent), its result is
//!    always recorded, even after `cancel` fires -- see the unconditional
//!    drain loop after the dispatch loop breaks.
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
//! 4. **Four outcomes are distinct.** Plan exhaustion, cancellation, budget
//!    exhaustion, and time exhaustion each get their own [`RunSummary`]
//!    field, and three of the four (all but cancellation) their own
//!    terminal event -- see AC-3.27.
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
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

use bathy_evidence::LogError;
use bathy_plan::{ScanPlan, ScanUnit};
use bathy_scope::BudgetLedger;
use bathy_store::{StoreError, TaskStore};
use bathy_types::clock::Clock;
use bathy_types::event::{EventBody, PortState, Target};
use bathy_types::ids::ScanId;

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

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error(transparent)]
    Log(#[from] LogError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("a scan worker task panicked or was cancelled by the runtime: {0}")]
    Join(#[from] tokio::task::JoinError),
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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        limiter: RateLimiter,
        ledger: BudgetLedger,
        config: SchedulerConfig,
        log: Arc<Mutex<GroupCommitLog>>,
        store: Arc<TaskStore>,
        clock: Arc<dyn Clock>,
        scan_id: ScanId,
        engine_version: impl Into<String>,
    ) -> Self {
        Self {
            limiter,
            ledger: Mutex::new(ledger),
            config,
            log,
            store,
            clock,
            scan_id,
            engine_version: engine_version.into(),
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

        if self.already_terminated()? {
            summary.packets_spent = self.ledger().packets_spent();
            return Ok(summary);
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
        // completed, loaded once. `from_index` alone is a necessary but not
        // sufficient skip condition under concurrency -- see the module doc.
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
            if self.ledger().elapsed_exceeded(started.elapsed().as_secs()) {
                summary.time_exhausted = true;
                break 'drive;
            }

            let Some(unit) = units.next() else {
                break 'drive;
            };

            if already_done.contains(&unit.index) {
                continue;
            }

            // Cancellable wait for a rate-limiter token AND a concurrency
            // slot: a cancellation arriving mid-wait must not be delayed
            // behind either. Whichever branch `select!` does not pick is
            // dropped mid-poll -- so if `cancel` wins, `unit` is simply
            // abandoned: never marked done, and (per invariant 1) no budget
            // is ever reserved for it, so it is correctly resumable.
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

            // AC-3.24: reserve budget BEFORE emission, as late as possible
            // -- immediately before the unit is actually dispatched. A
            // refused reservation ends the scan; `unit` above is never
            // spawned, so the total packets emitted can never exceed
            // `maximum_packets`.
            if self.ledger().try_spend_packets(1).is_err() {
                drop(permit);
                summary.budget_exhausted = true;
                break 'drive;
            }

            let timeout = self.config.connect_timeout;
            in_flight.spawn(async move {
                let (outcome, local) =
                    probe_connect_with_local_signal(unit.target, unit.endpoint.port, timeout).await;
                drop(permit);
                (unit, outcome, local)
            });

            while let Some(done) = in_flight.try_join_next() {
                self.record(done?, &mut summary, &mut completed_batch)?;
            }
            if completed_batch.len() >= STORE_FLUSH_BATCH {
                self.flush_progress(
                    &mut completed_batch,
                    summary.units_completed,
                    &mut last_progress_emitted_at,
                    plan.len(),
                )?;
            }
        }

        // Invariant 2: drain, never drop, work already in flight. These
        // probes were already paid for out of the budget (reserved before
        // spawn, above), and their results are real observations -- this
        // loop runs unconditionally, regardless of which branch above broke
        // the dispatch loop.
        while let Some(done) = in_flight.join_next().await {
            self.record(done?, &mut summary, &mut completed_batch)?;
        }
        self.flush_progress(
            &mut completed_batch,
            summary.units_completed,
            &mut last_progress_emitted_at,
            plan.len(),
        )?;

        summary.packets_spent = self.ledger().packets_spent();

        // AC-3.27: three distinct terminal outcomes get their own event;
        // cancellation deliberately gets none.
        if summary.budget_exhausted {
            self.log(EventBody::ScanFailed {
                reason_code: "budget_exhausted".into(),
                detail: format!(
                    "packet budget spent after {} units",
                    summary.units_completed
                ),
            })?;
        } else if summary.time_exhausted {
            self.log(EventBody::ScanFailed {
                reason_code: "time_exhausted".into(),
                detail: format!(
                    "runtime budget elapsed after {} units",
                    summary.units_completed
                ),
            })?;
        } else if !summary.cancelled {
            self.log(EventBody::ScanCompleted {
                probes_sent: summary.units_completed,
                packets_spent: summary.packets_spent,
                findings: summary.open_ports,
            })?;
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
    fn record(
        &self,
        done: (ScanUnit, ConnectOutcome, bool),
        summary: &mut RunSummary,
        completed_batch: &mut Vec<u64>,
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
        }
        if local_failure {
            summary.local_resource_failures += 1;
        }
        completed_batch.push(unit.index);
        summary.units_completed += 1;
        Ok(())
    }

    /// Flushes `completed` to the `TaskStore` resumption cursor
    /// (`mark_units_done`), then -- only once at least `progress_every`
    /// units have completed since the last emission -- appends one
    /// `scan.progress` event (AC-3.30) and clears `completed`.
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
    ) -> Result<(), EngineError> {
        if completed.is_empty() {
            return Ok(());
        }
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
        // `packets_spent`) in step with reality at the same cadence as the
        // unit-progress flush, rather than leaving `record_progress` --
        // written for exactly this purpose and, before this task, called
        // nowhere in the codebase outside its own tests -- permanently
        // unused.
        let last_sequence = self.log_guard().last_sequence();
        let packets_spent = self.ledger().packets_spent();
        self.store
            .record_progress(self.scan_id, last_sequence, packets_spent)?;
        completed.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, HashMap};
    use std::sync::atomic::{AtomicU64, Ordering};

    use tokio::net::TcpListener;

    use bathy_store::StartRequest;
    use bathy_types::clock::FixedClock;
    use bathy_types::event::{Event, PortState};
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

    struct Harness {
        _dir: tempfile::TempDir,
        scheduler: Scheduler,
        plan: ScanPlan,
        store: Arc<TaskStore>,
        log: Arc<Mutex<GroupCommitLog>>,
        scan_id: ScanId,
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
    }

    fn make_harness(
        targets: &[&str],
        port_specs: &[&str],
        budgets: Budgets,
        config: SchedulerConfig,
        limiter_pps: u32,
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
            service_detection: ServiceDetection::default(),
            budgets,
            evidence_level: EvidenceLevel::Headers,
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
            GroupCommitLog::open(dir.path(), scan_id, GroupCommitConfig::default()).unwrap(),
        ));

        let ledger = BudgetLedger::new(budgets);
        let limiter = RateLimiter::new(limiter_pps);
        let scheduler = Scheduler::new(
            limiter,
            ledger,
            config,
            Arc::clone(&log),
            Arc::clone(&store),
            Arc::clone(&clock),
            scan_id,
            "0.1.0",
        );

        Harness {
            _dir: dir,
            scheduler,
            plan,
            store,
            log,
            scan_id,
        }
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
            1_000_000,
        )
    }

    /// A single target with `n` distinct closed ports (an unbound range, so
    /// every probe resolves near-instantly via `ECONNREFUSED`), paced by a
    /// deliberately modest rate limiter (`RateLimiter`'s capacity equals its
    /// configured pps, so a burst covering all of `n` at once would let the
    /// whole scan finish before a test could ever observe it mid-flight --
    /// see `cancellation_stops_promptly_and_leaves_a_resumable_cursor` and
    /// `progress_events_are_emitted_periodically_during_a_long_scan` below,
    /// which both depend on this).
    fn harness_with_many_units(n: u64) -> Harness {
        let end = 20_000 + n - 1;
        let spec = format!("20000-{end}");
        make_harness(
            &["127.0.0.1"],
            &[spec.as_str()],
            budgets(1_000_000, 3_600, 1_000_000),
            SchedulerConfig {
                concurrency: 64,
                connect_timeout: Duration::from_millis(300),
                progress_every: 500,
            },
            1_000,
        )
    }

    fn harness_with_packet_budget(budget: u64) -> Harness {
        make_harness(
            &["127.0.0.1"],
            &["20000-29999"], // 10,000 ports: "thousands of units" against a ceiling of `budget`
            budgets(budget, 3_600, 1_000_000),
            small_config(),
            1_000_000,
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
        const N: u64 = 100;
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
        let h = make_harness(
            &["127.0.0.1"],
            &spec_refs,
            budgets(1_000_000, 3_600, 1_000_000),
            SchedulerConfig {
                concurrency: 16,
                connect_timeout: Duration::from_secs(5),
                progress_every: 500,
            },
            1_000_000,
        );
        assert_eq!(h.plan.len(), N);

        // Simulate a previous run that genuinely probed units 0..10 and,
        // out of order, 60..70 -- one real connect per simulated unit, so
        // each port's counter is already 1 before resumption begins,
        // exactly as if the scheduler itself had probed it and a crash or
        // cancellation happened before the gap in between was closed.
        let island: BTreeSet<u64> = (60..70).collect();
        let already: BTreeSet<u64> = (0..10).chain(60..70).collect();
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
            resume_from, 10,
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
        for i in 10..N {
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
            // STORE_FLUSH_BATCH (64) is the internal granularity
            // `flush_progress` is checked at, so a step can overshoot
            // `progress_every` by at most that much.
            assert!(
                (500..=500 + STORE_FLUSH_BATCH as u64).contains(&step),
                "progress step {step} is not periodic: {sent:?}"
            );
        }
        assert!(*sent.last().unwrap() <= 2_000);
    }

    // AC-3.24, both directions (dispatch: "test the budget ceiling in both
    // directions"). Too permissive:
    #[tokio::test]
    async fn budget_ceiling_is_never_exceeded_by_even_one_packet() {
        let h = harness_with_packet_budget(10);
        let summary = h.run_to_completion().await.unwrap();
        assert_eq!(
            summary.packets_spent, 10,
            "must spend exactly the ceiling, not more, against a plan of thousands"
        );
        assert!(summary.budget_exhausted);
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
            1_000_000,
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

    #[tokio::test]
    async fn a_time_budget_of_zero_seconds_elapsed_stops_the_scan_and_records_why() {
        let h = make_harness(
            &["127.0.0.1"],
            &["20000-29999"],
            budgets(1_000_000, 1, 1_000_000), // 1s runtime ceiling, sizeable plan
            small_config(),
            50, // slow enough that 1 second elapses before the plan finishes
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
    // an indistinguishable `filtered` count. Exercised at the `Scheduler`
    // level by constructing a plan whose only unit's `ConnectOutcome`
    // classification is forced through `probe_connect_with_local_signal`'s
    // own local-error path is impractical to trigger for real on demand
    // (it requires genuinely exhausting local ephemeral ports or a real
    // firewall policy) -- covered directly instead in `connect.rs`'s own
    // `local_signal_is_true_only_for_addr_not_available_and_permission_denied`.
    // This test instead pins the *plumbing*: `RunSummary::local_resource_failures`
    // defaults to, and stays at, zero for an ordinary run with no local
    // failures, so a regression that always reports a nonzero count (or
    // never reports one at all, silently discarding a real signal) is
    // equally visible.
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
        const N: u64 = 90;
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
        // rather than completing before cancellation ever lands.
        // `connect_timeout` is deliberately generous (not the ~500ms this
        // crate's other tests use): this test runs `cargo test`'s full
        // default parallel-test-thread load with 90 real listeners across
        // two `run()` calls, and a tight timeout here was observed to be
        // exceeded under that contention alone (a genuine loopback
        // connection arriving late, not a scheduler bug) -- confirmed by
        // rerunning under `--test-threads=1`, where it never flaked; see
        // this task's report.
        let h = make_harness(
            &["127.0.0.1"],
            &spec_refs,
            budgets(1_000_000, 3_600, 1_000_000),
            SchedulerConfig {
                concurrency: 10,
                connect_timeout: Duration::from_secs(5),
                progress_every: 500,
            },
            25,
        );
        assert_eq!(h.plan.len(), N);

        // Cancel once a meaningful fraction has completed -- polled, not a
        // fixed sleep, so this is robust to machine speed rather than
        // timing-flaky.
        let cancel = CancellationToken::new();
        let store_for_poll = Arc::clone(&h.store);
        let scan_id = h.scan_id;
        let c = cancel.clone();
        let poller = tokio::spawn(async move {
            loop {
                let done = store_for_poll.completed_units(scan_id).unwrap().len();
                if done >= 10 {
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
}
