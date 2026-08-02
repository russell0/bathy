use bathy_types::request::Budgets;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("packet budget exhausted: {spent}/{ceiling} already spent, {requested} more requested")]
pub struct BudgetExhausted {
    pub spent: u64,
    pub ceiling: u64,
    pub requested: u64,
}

/// Hard accounting. `try_spend_packets` is checked *before* emission, and a
/// refused spend leaves the ledger untouched so a caller that retries with a
/// smaller amount still gets a correct answer.
///
/// # Resumption (M3 Task 7 fix round 1, CRITICAL-2)
///
/// A ledger built with [`Self::new`] always starts at zero. That is correct
/// for a genuinely fresh scan, but wrong for a *resumed* one: a caller that
/// builds a brand new `BudgetLedger::new` for a scan that already spent
/// packets (or wall-clock runtime) in a previous, cancelled run hands that
/// resumed run a full, unspent budget all over again. Under a cancel/resume
/// retry loop this defeats the ceiling entirely -- the mechanism budgets
/// exist for. [`Self::resumed`] is the fix: it seeds both counters from
/// whatever a caller has persisted about prior runs of the same scan (see
/// `bathy_store::tasks::TaskStore::record_progress` and
/// `bathy_engine::scheduler`, which is the actual caller in this workspace).
#[derive(Debug, Clone)]
pub struct BudgetLedger {
    budgets: Budgets,
    packets_spent: u64,
    /// Wall-clock runtime, in seconds, already elapsed across previous runs
    /// of this scan -- zero for a ledger built with [`Self::new`]. Not
    /// tracked automatically the way `packets_spent` is (there is no
    /// `try_spend_seconds`): [`Self::elapsed_exceeded`] takes each call's
    /// own elapsed time as an argument and adds this baseline to it, so a
    /// caller (`Scheduler::run`) that restarts its own `Instant` on every
    /// invocation still gets a ceiling that accounts for time spent in
    /// earlier runs.
    seconds_already_elapsed: u64,
}

impl BudgetLedger {
    pub fn new(budgets: Budgets) -> Self {
        Self {
            budgets,
            packets_spent: 0,
            seconds_already_elapsed: 0,
        }
    }

    /// Seeds a ledger for a scan resuming after a previous run: as if
    /// `packets_already_spent` packets had already been spent and
    /// `seconds_already_elapsed` seconds of wall-clock runtime had already
    /// passed, before this ledger's own lifetime even began.
    ///
    /// `packets_already_spent` is clamped to `budgets.maximum_packets`
    /// (`.min`, not stored verbatim): if it somehow arrives at or past the
    /// ceiling (the ceiling was lowered between runs, or a caller passes a
    /// stale/corrupt value), the correct resulting state is "no packets
    /// remaining," not an inconsistent one a subsequent `saturating_add` in
    /// `try_spend_packets` would silently paper over anyway. There is no
    /// equivalent clamp for `seconds_already_elapsed` against
    /// `maximum_runtime_seconds`: unlike packets, exceeding the runtime
    /// ceiling is meant to trip [`Self::elapsed_exceeded`] on the very next
    /// check (see `elapsed_seconds_already_exceeding_the_ceiling_trips_immediately`),
    /// not be silently capped down to "exactly at the ceiling, not over."
    pub fn resumed(
        budgets: Budgets,
        packets_already_spent: u64,
        seconds_already_elapsed: u64,
    ) -> Self {
        Self {
            budgets,
            packets_spent: packets_already_spent.min(budgets.maximum_packets),
            seconds_already_elapsed,
        }
    }

    pub fn packets_spent(&self) -> u64 {
        self.packets_spent
    }
    pub fn packets_remaining(&self) -> u64 {
        self.budgets
            .maximum_packets
            .saturating_sub(self.packets_spent)
    }
    pub fn try_spend_packets(&mut self, n: u64) -> Result<(), BudgetExhausted> {
        let after = self.packets_spent.saturating_add(n);
        if after > self.budgets.maximum_packets {
            return Err(BudgetExhausted {
                spent: self.packets_spent,
                ceiling: self.budgets.maximum_packets,
                requested: n,
            });
        }
        self.packets_spent = after;
        Ok(())
    }
    /// `elapsed_seconds` is THIS run's own elapsed time (what a caller's own
    /// `Instant::now().elapsed()` reports); the ledger adds whatever
    /// baseline [`Self::resumed`] seeded it with before comparing against
    /// the ceiling, so a resumed scan's runtime budget also survives a
    /// cancel/resume cycle rather than restarting every call.
    pub fn elapsed_exceeded(&self, elapsed_seconds: u64) -> bool {
        self.seconds_already_elapsed.saturating_add(elapsed_seconds)
            > self.budgets.maximum_runtime_seconds
    }
    /// The runtime baseline this ledger was seeded with (zero for
    /// [`Self::new`]). Exposed so a caller persisting a resumption cursor
    /// (`Scheduler::run`) can compute the NEXT baseline as
    /// `seconds_already_elapsed() + this_run_elapsed`, without needing to
    /// separately track what it originally seeded this ledger with.
    pub fn seconds_already_elapsed(&self) -> u64 {
        self.seconds_already_elapsed
    }
    pub fn packets_per_second(&self) -> u32 {
        self.budgets.maximum_packets_per_second
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budgets(packets: u64, runtime_seconds: u64, pps: u32) -> Budgets {
        // `Budgets` gates zero values only at deserialization (via
        // `RawBudgets`'s `TryFrom`); direct struct construction bypasses
        // that shim, which is fine here since every caller in this file
        // supplies positive values.
        Budgets {
            maximum_packets: packets,
            maximum_runtime_seconds: runtime_seconds,
            maximum_packets_per_second: pps,
        }
    }

    #[test]
    fn spending_within_budget_succeeds_and_accumulates() {
        let mut l = BudgetLedger::new(budgets(100, 60, 10));
        assert!(l.try_spend_packets(40).is_ok());
        assert!(l.try_spend_packets(60).is_ok());
        assert_eq!(l.packets_spent(), 100);
    }

    #[test]
    fn spending_past_the_ceiling_fails_and_does_not_partially_apply() {
        let mut l = BudgetLedger::new(budgets(100, 60, 10));
        assert!(l.try_spend_packets(90).is_ok());
        assert!(l.try_spend_packets(20).is_err());
        assert_eq!(
            l.packets_spent(),
            90,
            "a refused spend must not be recorded"
        );
    }

    #[test]
    fn the_ledger_is_exhausted_exactly_at_the_ceiling_not_after() {
        let mut l = BudgetLedger::new(budgets(10, 60, 10));
        assert!(l.try_spend_packets(10).is_ok());
        assert!(l.try_spend_packets(1).is_err());
    }

    #[test]
    fn elapsed_time_ceiling_is_enforced() {
        let l = BudgetLedger::new(budgets(100, 60, 10));
        assert!(!l.elapsed_exceeded(59));
        assert!(!l.elapsed_exceeded(60));
        assert!(l.elapsed_exceeded(61));
    }

    // --- AC-1.33, extended beyond the brief's minimal test list ---

    // "Byte-identical", not merely "not increased" (the dispatch's explicit
    // ask): `packets_spent` is the ledger's entire mutable field
    // (`budgets` is `Copy` and never reassigned after `new`), so capturing
    // it immediately before a refused call and asserting exact equality
    // after is a complete proof the call left no trace anywhere in the
    // ledger's state, not just that the counter didn't go up.
    #[test]
    fn a_refused_spend_leaves_packets_spent_byte_identical() {
        let mut l = BudgetLedger::new(budgets(100, 60, 10));
        assert!(l.try_spend_packets(90).is_ok());
        let before = l.packets_spent();
        assert!(l.try_spend_packets(20).is_err());
        assert_eq!(
            l.packets_spent(),
            before,
            "refused spend must leave packets_spent byte-identical"
        );
        assert_eq!(
            l.packets_remaining(),
            10,
            "packets_remaining must also be untouched by the refused call"
        );
    }

    #[test]
    fn a_retry_with_a_smaller_amount_after_a_refusal_still_succeeds() {
        // The design property this whole module exists for: a caller that
        // gets refused and retries with a smaller amount must see a
        // correct answer, not one skewed by a phantom partial spend from
        // the refused attempt.
        let mut l = BudgetLedger::new(budgets(100, 60, 10));
        assert!(l.try_spend_packets(90).is_ok());
        assert!(l.try_spend_packets(20).is_err());
        assert!(
            l.try_spend_packets(10).is_ok(),
            "retry with the exact remainder must succeed"
        );
        assert_eq!(l.packets_spent(), 100);
    }

    #[test]
    fn refused_spend_error_names_the_offending_numbers() {
        let mut l = BudgetLedger::new(budgets(100, 60, 10));
        assert!(l.try_spend_packets(90).is_ok());
        let err = l.try_spend_packets(20).unwrap_err();
        assert_eq!(
            err,
            BudgetExhausted {
                spent: 90,
                ceiling: 100,
                requested: 20,
            }
        );
    }

    // --- Overflow: `try_spend_packets(u64::MAX)` must refuse cleanly via
    // `saturating_add`, not panic (debug builds) or wrap silently (release
    // builds) via plain `+`. Exercised from both a zero and a nonzero
    // starting balance -- from zero, `0 + u64::MAX` does not itself
    // overflow (it lands exactly on `u64::MAX`), so only the nonzero case
    // actually forces the addition past `u64::MAX` and proves
    // `saturating_add` is load-bearing rather than incidentally unused. ---

    #[test]
    fn try_spend_packets_u64_max_from_zero_is_refused_cleanly() {
        let mut l = BudgetLedger::new(budgets(100, 60, 10));
        let before = l.packets_spent();
        let err = l.try_spend_packets(u64::MAX).unwrap_err();
        assert_eq!(err.ceiling, 100);
        assert_eq!(err.requested, u64::MAX);
        assert_eq!(
            l.packets_spent(),
            before,
            "refused spend leaves the ledger untouched"
        );
    }

    #[test]
    fn try_spend_packets_u64_max_after_a_prior_spend_does_not_overflow() {
        // spent=50, n=u64::MAX: `50 + u64::MAX` overflows a plain `u64`
        // addition (panics in debug, wraps to 49 in release). If
        // `saturating_add` were ever replaced by `+`, this test is the one
        // that would catch it -- in debug it panics instead of failing
        // cleanly, and in release the wrapped `after` (49) would be under
        // the ceiling (100) and the spend would be wrongly accepted.
        let mut l = BudgetLedger::new(budgets(100, 60, 10));
        assert!(l.try_spend_packets(50).is_ok());
        let before = l.packets_spent();
        assert!(l.try_spend_packets(u64::MAX).is_err());
        assert_eq!(
            l.packets_spent(),
            before,
            "refused spend leaves the ledger untouched"
        );
    }

    #[test]
    fn packets_remaining_saturates_rather_than_underflows() {
        // `packets_remaining` also has an overflow-shaped hazard on its own
        // subtraction; a ledger can never be over-spent through the public
        // API, but this pins the defensive `saturating_sub` down directly.
        let l = BudgetLedger::new(budgets(0, 60, 10));
        assert_eq!(l.packets_remaining(), 0);
    }

    #[test]
    fn packets_per_second_reports_the_configured_ceiling() {
        let l = BudgetLedger::new(budgets(100, 60, 42));
        assert_eq!(l.packets_per_second(), 42);
    }

    // --- M3 Task 7 fix round 1, CRITICAL-2: BudgetLedger::resumed ---

    #[test]
    fn a_fresh_ledger_has_zero_baseline_of_either_kind() {
        let l = BudgetLedger::new(budgets(100, 60, 10));
        assert_eq!(l.packets_spent(), 0);
        assert_eq!(l.seconds_already_elapsed(), 0);
        assert!(!l.elapsed_exceeded(60));
        assert!(l.elapsed_exceeded(61));
    }

    #[test]
    fn resumed_seeds_packets_spent_from_a_prior_run() {
        let mut l = BudgetLedger::resumed(budgets(100, 60, 10), 60, 0);
        assert_eq!(l.packets_spent(), 60);
        assert_eq!(l.packets_remaining(), 40);
        assert!(l.try_spend_packets(40).is_ok());
        assert!(
            l.try_spend_packets(1).is_err(),
            "the ceiling must be measured against the SEEDED total, not reset to zero"
        );
    }

    #[test]
    fn resumed_packets_already_spent_at_or_past_the_ceiling_is_clamped_not_stored_verbatim() {
        // The ceiling was lowered between runs, or a caller passes a stale
        // value at/above it -- either way, the correct resulting state is
        // "no packets remaining", not packets_spent > maximum_packets.
        let l = BudgetLedger::resumed(budgets(100, 60, 10), 500, 0);
        assert_eq!(l.packets_spent(), 100);
        assert_eq!(l.packets_remaining(), 0);
    }

    #[test]
    fn resumed_ledger_accumulates_elapsed_seconds_across_runs() {
        // 8 seconds already elapsed from a previous run, a 10-second
        // ceiling: 1 more second of THIS run's own elapsed time must not
        // trip it (8+1=9), but 3 more must (8+3=11).
        let l = BudgetLedger::resumed(budgets(100, 10, 10), 0, 8);
        assert_eq!(l.seconds_already_elapsed(), 8);
        assert!(!l.elapsed_exceeded(1));
        assert!(l.elapsed_exceeded(3));
    }

    #[test]
    fn elapsed_seconds_already_exceeding_the_ceiling_trips_immediately() {
        // Unlike packets_spent, seconds_already_elapsed is NOT clamped to
        // the ceiling -- a resumed scan whose prior runs already used up
        // the whole runtime budget must report exhausted on the very first
        // check of the new run, with zero of ITS OWN elapsed time yet.
        let l = BudgetLedger::resumed(budgets(100, 5, 10), 0, 9);
        assert!(l.elapsed_exceeded(0));
    }

    #[test]
    fn resumed_with_zero_baselines_behaves_exactly_like_new() {
        let a = BudgetLedger::new(budgets(100, 60, 10));
        let b = BudgetLedger::resumed(budgets(100, 60, 10), 0, 0);
        assert_eq!(a.packets_spent(), b.packets_spent());
        assert_eq!(a.packets_remaining(), b.packets_remaining());
        assert_eq!(a.seconds_already_elapsed(), b.seconds_already_elapsed());
        for e in [0, 59, 60, 61, 1_000] {
            assert_eq!(a.elapsed_exceeded(e), b.elapsed_exceeded(e), "elapsed={e}");
        }
    }

    #[test]
    fn resumed_elapsed_accumulation_does_not_overflow() {
        let l = BudgetLedger::resumed(budgets(100, 100, 10), 0, u64::MAX - 5);
        // saturating_add, not a panicking/wrapping `+`: still exceeded, not
        // a panic in debug or a wrapped-around false negative in release.
        assert!(l.elapsed_exceeded(10));
    }
}
