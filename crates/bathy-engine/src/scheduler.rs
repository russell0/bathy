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

    /// The TOTAL wall-clock runtime this scan has used, across every run --
    /// this ledger's own resumption baseline (`BudgetLedger::seconds_already_elapsed`,
    /// zero unless this `Scheduler` was built with `BudgetLedger::resumed`)
    /// plus how long `started` (THIS run's own `Instant`) has been running.
    /// M3 Task 7 fix round 1, CRITICAL-2: this is what gets persisted via
    /// `TaskStore::record_progress`, so the NEXT resume's fresh `Scheduler`
    /// can seed its own `BudgetLedger::resumed` with the true cumulative
    /// total rather than restarting the runtime clock at zero every time.
    fn total_elapsed_seconds(&self, started: Instant) -> u64 {
        self.ledger()
            .seconds_already_elapsed()
            .saturating_add(started.elapsed().as_secs())
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
                    started,
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
            started,
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
        started: Instant,
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
        limiter_pps: u32,
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
        let h = make_harness(&["127.0.0.1"], &spec_refs, budgets, config, limiter_pps);
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

        /// Builds a SECOND, independent `Scheduler` for the SAME scan --
        /// same store, log, clock, scan_id -- but with a FRESH
        /// `BudgetLedger` seeded from whatever `record_progress` has
        /// currently persisted, via `BudgetLedger::resumed`. This is the
        /// shape a real resume takes: a new process (or at minimum a new
        /// `Scheduler`) picking up a scan a previous, cancelled run left
        /// off, and it is what M3 Task 7 fix round 1's CRITICAL-2 tests
        /// exercise -- a naive `BudgetLedger::new(budgets)` here would
        /// reproduce the exact hole the review found.
        fn resume(&self, config: SchedulerConfig, limiter_pps: u32, budgets: Budgets) -> Scheduler {
            let record = self.store.get(self.scan_id).unwrap().unwrap();
            let ledger =
                BudgetLedger::resumed(budgets, record.packets_spent, record.elapsed_seconds);
            Scheduler::new(
                RateLimiter::new(limiter_pps),
                ledger,
                config,
                Arc::clone(&self.log),
                Arc::clone(&self.store),
                Arc::clone(&self.clock),
                self.scan_id,
                "0.1.0",
            )
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
            clock,
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
            1_000_000,
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
            1_000_000,
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
            1_000_000,
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
        let scan_budgets = budgets(CEILING, 3_600, 1_000_000);
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
        // (run1 spent=6).
        let (h, counts) =
            harness_with_real_listeners(PLAN_SIZE, scan_budgets, small_config(), 3).await;
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
        let resumed_scheduler = h.resume(small_config(), 1_000_000, scan_budgets);
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
        let resumed_scheduler = h.resume(small_config(), 1_000_000, tight_runtime_budgets);
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
            )
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
        let h = make_harness(
            &["127.0.0.1"],
            &spec_refs,
            budgets(1_000_000, 3_600, 1_000_000),
            SchedulerConfig {
                concurrency: 10,
                connect_timeout: Duration::from_secs(5),
                progress_every: 500,
            },
            8,
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
}
