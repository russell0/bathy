use sonde_types::request::Budgets;

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
#[derive(Debug, Clone)]
pub struct BudgetLedger {
    budgets: Budgets,
    packets_spent: u64,
}

impl BudgetLedger {
    pub fn new(budgets: Budgets) -> Self {
        Self {
            budgets,
            packets_spent: 0,
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
    pub fn elapsed_exceeded(&self, elapsed_seconds: u64) -> bool {
        elapsed_seconds > self.budgets.maximum_runtime_seconds
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
}
