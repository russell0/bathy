use std::sync::Mutex;

use tokio::time::{Duration, Instant, sleep};

/// Token bucket limiting packets per second.
///
/// Rate control is an accuracy feature as much as a politeness one: scanning
/// faster than a target's ICMP or SYN rate limit produces false `filtered`
/// results, so the budget that keeps us polite is the same budget that keeps
/// results honest.
pub struct RateLimiter {
    inner: Mutex<Bucket>,
    capacity: f64,
    refill_per_second: f64,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    /// `packets_per_second` is clamped to at least 1. A limiter configured
    /// for 0 pps would otherwise leave `refill_per_second` at `0.0`, and
    /// `acquire` would divide by it computing the wait duration -- not a
    /// panic (`f64` division by zero yields `inf`, not a trap), but `inf`
    /// tokens would never be needed and the bucket would never refill
    /// above zero either, so any `acquire` call past the first empties the
    /// bucket and then waits forever. 1 pps is the honest floor for "as
    /// slow as this can go", not a special "unlimited" case.
    pub fn new(packets_per_second: u32) -> Self {
        let capacity = packets_per_second.max(1) as f64;
        Self {
            inner: Mutex::new(Bucket {
                tokens: capacity,
                last: Instant::now(),
            }),
            capacity,
            refill_per_second: capacity,
        }
    }

    /// Blocks until `n` tokens are available, then spends them.
    ///
    /// `n` may exceed the bucket's own capacity (AC-3.17). The loop below
    /// consumes whatever is currently available, reduces `needed` by that
    /// amount, and sleeps for exactly the time the *remaining* shortfall
    /// takes to refill (capped at one second per iteration so a very large
    /// `n` still makes visible incremental progress rather than issuing one
    /// enormous sleep). This is what makes an oversized request converge on
    /// the mathematically correct total wait -- shortfall / refill rate --
    /// instead of either spinning forever waiting for a token level the
    /// bucket can never hold, or the naive-looking alternative "fix" of
    /// short-circuiting to return immediately whenever `n > capacity`. That
    /// alternative would also terminate (trivially), but it hands out
    /// unlimited packets for free on every oversized call and so silently
    /// defeats the whole limiter; see `a_request_larger_than_the_bucket_still_completes`
    /// below, which asserts on elapsed time and not just on termination, for
    /// the test that distinguishes the two.
    pub async fn acquire(&self, n: u32) {
        let mut needed = n as f64;
        loop {
            let wait = {
                let mut b = self.inner.lock().expect("rate limiter poisoned");
                let now = Instant::now();
                let elapsed = now.duration_since(b.last).as_secs_f64();
                b.tokens = (b.tokens + elapsed * self.refill_per_second).min(self.capacity);
                b.last = now;
                if b.tokens >= needed {
                    b.tokens -= needed;
                    return;
                }
                // Consume what is available and wait for the remainder, so
                // a request larger than the bucket makes progress instead
                // of spinning forever waiting for a level it can never
                // reach.
                needed -= b.tokens;
                b.tokens = 0.0;
                Duration::from_secs_f64((needed / self.refill_per_second).min(1.0))
                // `b` (the `MutexGuard`) is dropped here, at the end of this
                // block, before `wait` is used below -- the lock is never
                // held across the `.await` point that follows. Verified by
                // `clippy::await_holding_lock` (this task's report has the
                // mutation that confirms the lint actually fires if this
                // scoping is broken) rather than taken on faith.
            };
            sleep(wait).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Instant;

    use super::*;

    // --- From the brief ---

    #[tokio::test]
    async fn the_first_burst_is_immediate() {
        let l = RateLimiter::new(100);
        let t = Instant::now();
        for _ in 0..100 {
            l.acquire(1).await;
        }
        assert!(
            t.elapsed().as_millis() < 50,
            "initial bucket should be full"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn sustained_rate_matches_the_configured_pps() {
        let l = RateLimiter::new(100);
        let t = tokio::time::Instant::now();
        for _ in 0..300 {
            l.acquire(1).await;
        }
        // 100 immediate from the initial bucket, 200 more at 100/s ≈ 2s.
        let elapsed = t.elapsed().as_millis();
        assert!((1_900..=2_200).contains(&elapsed), "took {elapsed}ms");
    }

    // AC-3.17, strengthened beyond the brief's bare "must not deadlock":
    // the brief's version of this test only proves `acquire` *returns*,
    // which a naive "fix" that short-circuits oversized requests to return
    // immediately would also satisfy while completely defeating the rate
    // limit. Run under a paused clock and assert on elapsed *virtual* time
    // so the test also proves the rate the oversized request implies is
    // still correct: starting from a full 10-token bucket at 10 pps,
    // acquiring 25 must cost (25 - 10) / 10 = 1.5s, not ~0s.
    #[tokio::test(start_paused = true)]
    async fn a_request_larger_than_the_bucket_still_completes() {
        let l = RateLimiter::new(10);
        let t = tokio::time::Instant::now();
        l.acquire(25).await; // must not deadlock
        let elapsed = t.elapsed().as_millis();
        assert!(
            (1_450..=1_550).contains(&elapsed),
            "took {elapsed}ms, expected ~1500ms (10 free from the initial \
             bucket, the remaining 15 at 10/s); a much shorter time would \
             mean the oversized request was granted for free instead of \
             actually rate-limited"
        );
    }

    // --- Beyond the brief: capacity is a hard ceiling on banked tokens ---

    // None of the three tests above can distinguish a capped refill
    // (`.min(self.capacity)`) from an uncapped one, because none of them
    // ever leaves the limiter idle long enough to bank tokens past
    // capacity before drawing on it again. This test forces exactly that:
    // drain the bucket, sit idle for far longer than needed to refill to
    // capacity, and confirm a large-but-in-capacity acquire afterward is
    // immediate (proving refill happened) while a request that exceeds
    // capacity even after the idle period still pays the real remaining
    // cost (proving the idle period didn't bank tokens beyond capacity).
    #[tokio::test(start_paused = true)]
    async fn idle_time_does_not_bank_tokens_beyond_capacity() {
        let l = RateLimiter::new(10);
        l.acquire(10).await; // drain the initial burst completely
        tokio::time::sleep(Duration::from_secs(100)).await; // sit idle far past what capacity needs
        let t = tokio::time::Instant::now();
        l.acquire(10).await; // capacity refilled the bucket to 10, not 1000
        assert!(
            t.elapsed().as_millis() < 50,
            "a full-capacity acquire right after a long idle period should be immediate"
        );
        let t2 = tokio::time::Instant::now();
        l.acquire(5).await; // bucket is now empty again; this must cost real time
        let elapsed2 = t2.elapsed().as_millis();
        assert!(
            (450..=550).contains(&elapsed2),
            "took {elapsed2}ms, expected ~500ms; if the idle period had banked \
             tokens past capacity this would be near-instant instead"
        );
    }

    // --- Concurrency: the budget is shared, not per-caller ---

    // AC-3.16 as given only exercises a single caller. The limiter's actual
    // deployment is many concurrent probes drawing from one budget, so this
    // proves the shared `Mutex<Bucket>` really is shared: ten tasks each
    // acquiring 30 tokens from a 100-pps limiter must collectively see the
    // same ~2s sustained-rate shape as a single caller acquiring 300 would
    // (100 free from the initial burst, 200 more at 100/s). If each task
    // instead saw its own independent bucket, ten tasks asking for 30 each
    // would all be well under any one bucket's capacity and the whole
    // thing would finish near-instantly.
    #[tokio::test(start_paused = true)]
    async fn concurrent_acquirers_share_one_budget_not_one_each() {
        let l = Arc::new(RateLimiter::new(100));
        let t = tokio::time::Instant::now();
        let handles: Vec<_> = (0..10)
            .map(|_| {
                let l = Arc::clone(&l);
                tokio::spawn(async move {
                    for _ in 0..30 {
                        l.acquire(1).await;
                    }
                })
            })
            .collect();
        for h in handles {
            h.await.expect("acquirer task panicked");
        }
        let elapsed = t.elapsed().as_millis();
        assert!(
            (1_900..=2_200).contains(&elapsed),
            "took {elapsed}ms; ~2000ms expected for 300 total acquisitions \
             shared across one 100pps budget -- a much shorter time means \
             each task got its own independent bucket instead of sharing one"
        );
    }

    // --- Zero and extreme configured rates ---

    // `RateLimiter::new(0)` clamps to 1 pps (see the comment on `new`). The
    // clamp is deliberate, not an oversight, and both halves of that claim
    // are tested: the first token is still free (from the initial bucket,
    // which is also clamped to capacity 1), and a *second* immediate
    // acquire genuinely waits, proving the limiter still behaves like a
    // rate limiter -- 1 pps, not "unlimited" -- rather than silently
    // stalling forever (which is what `packets_per_second.max(1)` being
    // removed would do; see the mutation-testing notes in this task's
    // report).
    #[tokio::test]
    async fn zero_pps_is_clamped_to_one_and_the_first_token_is_free() {
        let l = RateLimiter::new(0);
        let t = Instant::now();
        l.acquire(1).await;
        assert!(
            t.elapsed().as_millis() < 50,
            "the clamped single token should be immediately available"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn zero_pps_still_enforces_a_one_pps_rate_after_the_first_token() {
        let l = RateLimiter::new(0);
        let t = tokio::time::Instant::now();
        l.acquire(1).await; // immediate: the initial, capacity-1 bucket
        l.acquire(1).await; // must wait ~1s to refill at the clamped 1 pps
        let elapsed = t.elapsed().as_millis();
        assert!((900..=1_100).contains(&elapsed), "took {elapsed}ms");
    }

    // `u32::MAX` pps must not overflow the `f64` capacity/refill math (both
    // fields are computed once, in `new`, from `packets_per_second as
    // f64`), and a subsequent large acquire well within that enormous
    // capacity must still be immediate rather than panicking or hanging.
    #[tokio::test]
    async fn u32_max_pps_does_not_overflow_the_f64_arithmetic() {
        let l = RateLimiter::new(u32::MAX);
        let t = Instant::now();
        l.acquire(1_000_000).await;
        assert!(
            t.elapsed().as_millis() < 50,
            "well within the u32::MAX-token bucket, should be immediate"
        );
    }
}
