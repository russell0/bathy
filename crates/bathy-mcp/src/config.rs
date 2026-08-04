//! How the server is configured, and what a caller may not configure.
//!
//! The approval threshold is here rather than in any tool's input schema, and
//! that placement is the point: a threshold an agent could set is not a
//! threshold. Nothing in this struct is reachable from a request.

use std::path::PathBuf;
use std::time::Duration;

/// A scan wider than this many addresses needs a human before it starts.
///
/// 64 is a `/26`: wide enough that routine single-host and small-subnet work
/// is uninterrupted, narrow enough that a `/24` sweep is a decision somebody
/// makes on purpose.
pub const DEFAULT_APPROVAL_THRESHOLD_TARGETS: u64 = 64;

/// How long an approval is good for.
///
/// A human's approval is an approval of that scan, then. Ten minutes is long
/// enough for a person to be asked and answer, and short enough that an
/// answer cannot be banked.
pub const DEFAULT_APPROVAL_TTL: Duration = Duration::from_secs(600);

pub struct ServerConfig {
    /// Where scan state, event logs and evidence live. The same directory the
    /// command-line surface uses, so a scan started through one surface is
    /// visible to the other.
    pub state_dir: PathBuf,
    pub approval_threshold_targets: u64,
    pub approval_ttl: Duration,
    /// The key the approval token is sealed under.
    ///
    /// Generated per process and never written down, because the token it
    /// signs is never meant to outlive the process that issued it: a server
    /// restart invalidating every outstanding approval is the correct
    /// behaviour, not a limitation. A persisted key would let an approval
    /// issued by one run be redeemed against another, which is the standing
    /// grant the time-to-live exists to prevent.
    pub approval_signing_key: Vec<u8>,
}

impl ServerConfig {
    pub fn new(state_dir: PathBuf) -> Self {
        Self {
            state_dir,
            approval_threshold_targets: DEFAULT_APPROVAL_THRESHOLD_TARGETS,
            approval_ttl: DEFAULT_APPROVAL_TTL,
            approval_signing_key: fresh_signing_key(),
        }
    }

    pub fn with_approval_threshold(mut self, targets: u64) -> Self {
        self.approval_threshold_targets = targets;
        self
    }

    pub fn with_approval_ttl(mut self, ttl: Duration) -> Self {
        self.approval_ttl = ttl;
        self
    }
}

/// A 32-byte key straight from the operating system.
///
/// Deliberately not this project's ULID generator, which is the sanctioned
/// source for identifiers and is the wrong source here: it is monotonic, so
/// several values minted inside one millisecond differ by an increment rather
/// than by fresh bits, and a key with eighty bits behind it is not a key.
fn fresh_signing_key() -> Vec<u8> {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).expect("the operating system provides randomness");
    key.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_servers_do_not_share_a_signing_key() {
        // If they did, an approval issued by one would be redeemable against
        // the other, and the per-process lifetime this design relies on would
        // not exist.
        assert_ne!(fresh_signing_key(), fresh_signing_key());
    }

    #[test]
    fn the_key_is_long_enough_to_be_a_key() {
        assert_eq!(fresh_signing_key().len(), 32);
    }

    #[test]
    fn every_byte_of_the_key_varies_rather_than_only_a_suffix() {
        // A monotonic generator produces keys that agree on a long prefix and
        // differ by an increment. Over enough samples each byte position must
        // be seen to move, or the source is a counter wearing a key's shape.
        let samples: Vec<Vec<u8>> = (0..24).map(|_| fresh_signing_key()).collect();
        for byte in 0..32 {
            let distinct: std::collections::BTreeSet<u8> =
                samples.iter().map(|k| k[byte]).collect();
            assert!(
                distinct.len() > 1,
                "byte {byte} never changed across {} keys",
                samples.len()
            );
        }
    }
}
