//! Target expansion: turning target specifications (bare addresses, CIDRs,
//! and inclusive `a-b` ranges) into the sorted, deduplicated address list
//! that `plan_hash` is computed over.
//!
//! # Expansion is not scope authorization
//!
//! [`usable_hosts`] excludes the network and broadcast address of any IPv4
//! prefix shorter than `/31`, because those two addresses are not useful
//! *scan targets*. `bathy_scope::ScopeManifest::allows` makes no such
//! exception: `IpNet::contains` has no special case for the first or last
//! address of a network, so a manifest that authorizes `10.30.0.0/24` also
//! authorizes `10.30.0.0` and `10.30.0.255` themselves, even though this
//! module would never place either address in a plan. "Is this address
//! inside the authorized range" and "is this address worth probing" are
//! different questions with different answers at the edges of a subnet.
//! This module answers only the second one, never consults scope, and
//! nothing here should be read as claiming the two agree.
//!
//! # IPv6
//!
//! IPv6 scanning is out of scope for v0.1: `ScopeManifest::allows` refuses
//! every IPv6 address unconditionally (see that function's doc comment in
//! `bathy-scope`), so a plan built from an expanded IPv6 target would be
//! guaranteed to have every one of its units denied at execution time.
//! Rather than let that happen downstream -- after a plan hash has been
//! computed and units have been counted -- [`classify`] refuses any IPv6
//! address or network at expansion time, with an error that says why. This
//! also means [`usable_hosts`] only ever has to handle IPv4: it can delegate
//! entirely to [`ipnet::Ipv4Net::hosts`] rather than needing a `v6.hosts()`
//! branch, which is worth calling out on its own -- `hosts()` on a large
//! IPv6 prefix is effectively unbounded (a `/64` alone is 2^64 addresses),
//! so a codepath that reached it would not just be denied later, it would
//! not finish expanding first.
//!
//! # The pre-count pass
//!
//! [`expand_targets`] walks every spec twice: once to add up how many
//! addresses it would produce, and only if that total fits under `max` does
//! it walk the specs again to actually build the set. This is a safety
//! property, not an optimization -- `10.0.0.0/8` requested with a cap of
//! 1024 must be refused without ever allocating room for the 16,777,214
//! addresses it would otherwise expand to.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use ipnet::{IpNet, Ipv4Net};

#[derive(Debug, thiserror::Error)]
pub enum TargetError {
    #[error("cannot parse target `{0}` as an address, CIDR, or a-b range")]
    Malformed(String),
    #[error("range `{0}` ends before it starts")]
    ReversedRange(String),
    #[error("target set expands to more than {max} addresses; narrow the request")]
    TooManyTargets { max: usize },
    #[error(
        "target `{0}` is IPv6; IPv6 scanning is out of scope for v0.1 and every \
         IPv6 address is denied by scope, so expanding it would only plan work \
         that is guaranteed to be refused later -- use an IPv4 target instead"
    )]
    Ipv6Unsupported(String),
}

/// Expand target specifications into a sorted, deduplicated address list.
///
/// The output is collected through a `BTreeSet` before becoming a `Vec`, so
/// input order, duplicate specs, and overlapping specs cannot change the
/// result -- and therefore cannot change `plan_hash`. That stability is what
/// makes idempotency and resumption meaningful: M2's task store refuses a
/// repeated idempotency key whose plan hash differs, so an expansion that
/// varied with input order would turn every retry into a spurious conflict.
///
/// `max` is enforced by counting before allocating (see the module doc):
/// an oversized request fails with [`TargetError::TooManyTargets`] before
/// any address is inserted anywhere.
pub fn expand_targets(specs: &[String], max: usize) -> Result<Vec<IpAddr>, TargetError> {
    // Count first, so an oversized request is refused before we allocate for it.
    let mut projected: u128 = 0;
    for spec in specs {
        projected = projected.saturating_add(count_of(spec)?);
        if projected > max as u128 {
            return Err(TargetError::TooManyTargets { max });
        }
    }

    let mut set: BTreeSet<IpAddr> = BTreeSet::new();
    for spec in specs {
        match classify(spec)? {
            Spec::Single(ip) => {
                set.insert(IpAddr::V4(ip));
            }
            Spec::Range(a, b) => {
                for n in u32::from(a)..=u32::from(b) {
                    set.insert(IpAddr::V4(Ipv4Addr::from(n)));
                }
            }
            Spec::Net(net) => {
                for ip in usable_hosts(net) {
                    set.insert(ip);
                }
            }
        }
    }
    Ok(set.into_iter().collect())
}

enum Spec {
    Single(Ipv4Addr),
    Range(Ipv4Addr, Ipv4Addr),
    Net(Ipv4Net),
}

/// Parse one target spec, in order: bare address, then CIDR, then `a-b`
/// range. An IPv6 address or network is recognized (so the error can say
/// "IPv6", not just "malformed") and rejected here -- see the module doc.
fn classify(spec: &str) -> Result<Spec, TargetError> {
    if let Ok(ip) = spec.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => Ok(Spec::Single(v4)),
            IpAddr::V6(_) => Err(TargetError::Ipv6Unsupported(spec.to_owned())),
        };
    }
    if let Ok(net) = spec.parse::<IpNet>() {
        return match net {
            IpNet::V4(v4) => Ok(Spec::Net(v4)),
            IpNet::V6(_) => Err(TargetError::Ipv6Unsupported(spec.to_owned())),
        };
    }
    if let Some((a, b)) = spec.split_once('-') {
        // IPv6 addresses cannot contain `-`, so this branch is unreachable
        // for IPv6 input; `a`/`b` failing to parse as `Ipv4Addr` covers
        // every malformed case here, including an empty side (`1.2.3.4-` or
        // `-1.2.3.4`), since `"".parse::<Ipv4Addr>()` is itself an error.
        let a = a
            .trim()
            .parse::<Ipv4Addr>()
            .map_err(|_| TargetError::Malformed(spec.to_owned()))?;
        let b = b
            .trim()
            .parse::<Ipv4Addr>()
            .map_err(|_| TargetError::Malformed(spec.to_owned()))?;
        if u32::from(b) < u32::from(a) {
            return Err(TargetError::ReversedRange(spec.to_owned()));
        }
        return Ok(Spec::Range(a, b));
    }
    Err(TargetError::Malformed(spec.to_owned()))
}

/// Hosts in an IPv4 network, excluding the network and broadcast addresses
/// for prefixes shorter than `/31`. RFC 3021 makes both addresses of a
/// `/31` usable (a point-to-point link), and a `/32` is a single host, so
/// neither is trimmed.
///
/// This delegates entirely to [`Ipv4Net::hosts`] rather than re-deriving
/// the network/broadcast boundary by hand. Two reasons: first, the library
/// already gets `/31` and `/32` right in one unconditional implementation
/// (verified against its own doctest, and by this module's boundary tests
/// below) instead of needing a special-cased branch here. Second, and more
/// importantly, `Ipv4Net::hosts` computes the trimmed boundary with
/// `saturating_add`/`saturating_sub`, not plain `+`/`-`; hand-rolled
/// `u32::from(net.network()) + 1` / `u32::from(net.broadcast()) - 1`
/// arithmetic (as an earlier draft of this function had) cannot actually
/// wrap for any prefix `Ipv4Net` will construct -- a network address always
/// has its host bits zeroed and a broadcast address always has them set, so
/// for a prefix shorter than `/31` (at least two host bits) neither can sit
/// at the `u32` boundary -- but that safety argument requires the "prefix
/// shorter than /31" invariant to keep holding across every future edit to
/// this function. Using the library's saturating arithmetic removes the
/// need to keep re-proving that; see `boundary_arithmetic_does_not_wrap_at_0_0_0_0_0`
/// below for the `0.0.0.0/0` case this reasoning was written to cover.
fn usable_hosts(net: Ipv4Net) -> impl Iterator<Item = IpAddr> {
    net.hosts().map(IpAddr::V4)
}

/// The number of addresses `classify(spec)` would expand to, without
/// actually enumerating them. Used by [`expand_targets`]'s pre-count pass.
fn count_of(spec: &str) -> Result<u128, TargetError> {
    Ok(match classify(spec)? {
        Spec::Single(_) => 1,
        Spec::Range(a, b) => (u32::from(b) - u32::from(a)) as u128 + 1,
        Spec::Net(v4) if v4.prefix_len() < 31 => (1u128 << (32 - v4.prefix_len())) - 2,
        Spec::Net(v4) => 1u128 << (32 - v4.prefix_len()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // ---- AC-3.1 ---------------------------------------------------------

    #[test]
    fn expands_a_slash_24_excluding_network_and_broadcast() {
        let out = expand_targets(&["10.30.0.0/24".into()], 100_000).unwrap();
        assert_eq!(out.len(), 254);
        assert_eq!(out[0], ip("10.30.0.1"));
        assert_eq!(out[253], ip("10.30.0.254"));
        assert!(!out.contains(&ip("10.30.0.0")), "network address");
        assert!(!out.contains(&ip("10.30.0.255")), "broadcast address");
    }

    // ---- AC-3.2 ---------------------------------------------------------

    #[test]
    fn slash_31_and_slash_32_keep_every_address() {
        // RFC 3021: a /31 is a point-to-point link, both addresses are usable.
        assert_eq!(
            expand_targets(&["10.0.0.0/31".into()], 100).unwrap().len(),
            2
        );
        assert_eq!(
            expand_targets(&["10.0.0.7/32".into()], 100).unwrap().len(),
            1
        );
    }

    /// Boundary arithmetic, per the module doc on [`usable_hosts`]: /30 has
    /// two usable addresses (network and broadcast trimmed), /31 and /32
    /// are re-covered here directly against the raw addresses (not just a
    /// length), and 0.0.0.0/0 is exercised through the lazy iterator so the
    /// ~4.3 billion middle addresses are never materialized -- this proves
    /// the boundary values themselves (first usable = .0.0.1, last usable =
    /// .255.254) without needing `expand_targets`'s size cap to intervene.
    #[test]
    fn boundary_arithmetic_slash_30_31_32() {
        let net = |s: &str| s.parse::<Ipv4Net>().unwrap();

        let hosts_30: Vec<_> = usable_hosts(net("10.0.0.0/30")).collect();
        assert_eq!(hosts_30, vec![ip("10.0.0.1"), ip("10.0.0.2")]);

        let hosts_31: Vec<_> = usable_hosts(net("10.0.0.0/31")).collect();
        assert_eq!(hosts_31, vec![ip("10.0.0.0"), ip("10.0.0.1")]);

        let hosts_32: Vec<_> = usable_hosts(net("10.0.0.7/32")).collect();
        assert_eq!(hosts_32, vec![ip("10.0.0.7")]);
    }

    /// `0.0.0.0/0` is the case the module doc calls out as the one where
    /// `network()+1` / `broadcast()-1` arithmetic sits closest to the `u32`
    /// boundary (network = 0.0.0.0, broadcast = 255.255.255.255). Proven
    /// two ways, neither of which enumerates the ~4.3 billion addresses in
    /// between:
    ///
    /// - `usable_hosts` is a lazy iterator (`Ipv4Net::hosts`, in turn
    ///   `Ipv4AddrRange`, is `DoubleEndedIterator`), so `.next()` and
    ///   `.next_back()` read just the first and last elements without
    ///   collecting the rest. This proves the boundary values directly:
    ///   first usable is 0.0.0.1 (not 0.0.0.0), last usable is
    ///   255.255.255.254 (not 255.255.255.255), and computing them doesn't
    ///   panic under debug-mode overflow checks.
    /// - `count_of` (the pre-count pass `expand_targets` actually runs) is
    ///   checked against the closed-form expectation `2^32 - 2` directly.
    ///
    /// This crate deliberately does *not* special-case `0.0.0.0/0` with its
    /// own named error the way IPv6 gets one: `Ipv6Unsupported` exists
    /// because IPv6 is unconditionally denied downstream regardless of
    /// `max`, so refusing early is strictly more informative than letting
    /// scope refuse every unit later. `0.0.0.0/0` has no such downstream
    /// certainty -- it is an ordinary (if enormous) IPv4 network, and the
    /// existing `TooManyTargets` cap already refuses it before allocating
    /// for any `max` a real caller would pass (its count, 4294967294, does
    /// not fit under any cap this codebase configures) -- see
    /// `zero_slash_zero_is_refused_by_the_general_cap_before_allocating`
    /// below. Giving it a bespoke error would be an arbitrary carve-out
    /// with no different failure mode than the general one.
    #[test]
    fn boundary_arithmetic_does_not_wrap_at_0_0_0_0_0() {
        let net: Ipv4Net = "0.0.0.0/0".parse().unwrap();

        let mut hosts = net.hosts();
        assert_eq!(hosts.next(), Some(Ipv4Addr::new(0, 0, 0, 1)));
        assert_eq!(hosts.next_back(), Some(Ipv4Addr::new(255, 255, 255, 254)));

        assert_eq!(count_of("0.0.0.0/0").unwrap(), (1u128 << 32) - 2);
    }

    #[test]
    fn zero_slash_zero_is_refused_by_the_general_cap_before_allocating() {
        let started = std::time::Instant::now();
        let err = expand_targets(&["0.0.0.0/0".into()], 1024).unwrap_err();
        // No panic (see boundary_arithmetic_does_not_wrap_at_0_0_0_0_0 for
        // why not) and no attempt to allocate: this returns in well under a
        // second, not after building a multi-billion-entry set.
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert!(matches!(err, TargetError::TooManyTargets { max: 1024 }));
    }

    // ---- AC-3.3 ---------------------------------------------------------

    #[test]
    fn accepts_a_bare_address_and_an_inclusive_range() {
        assert_eq!(
            expand_targets(&["10.0.0.5".into()], 100).unwrap(),
            vec![ip("10.0.0.5")]
        );
        let r = expand_targets(&["10.0.0.5-10.0.0.8".into()], 100).unwrap();
        assert_eq!(
            r,
            vec![
                ip("10.0.0.5"),
                ip("10.0.0.6"),
                ip("10.0.0.7"),
                ip("10.0.0.8"),
            ]
        );
    }

    #[test]
    fn output_is_sorted_and_deduplicated_so_the_plan_is_stable() {
        let a = expand_targets(
            &["10.0.0.2".into(), "10.0.0.1".into(), "10.0.0.2".into()],
            100,
        )
        .unwrap();
        let b = expand_targets(&["10.0.0.1".into(), "10.0.0.2".into()], 100).unwrap();
        assert_eq!(a, b, "input order and duplicates must not change the plan");
    }

    #[test]
    fn overlapping_cidrs_do_not_produce_duplicate_targets() {
        let out = expand_targets(&["10.0.0.0/30".into(), "10.0.0.1/32".into()], 100).unwrap();
        assert_eq!(out, vec![ip("10.0.0.1"), ip("10.0.0.2")]);
    }

    // ---- AC-3.4 ---------------------------------------------------------

    #[test]
    fn exceeding_the_cap_is_refused_before_allocation() {
        let err = expand_targets(&["10.0.0.0/8".into()], 1024).unwrap_err();
        assert!(matches!(err, TargetError::TooManyTargets { .. }));
    }

    /// The test above only proves the *error type*; per the task dispatch,
    /// that alone does not prove the cap is enforced *before* allocation --
    /// a check that ran after building the full 16,777,214-address set for
    /// `10.0.0.0/8` and then discarded it would return the exact same
    /// error. Mutation testing this file (moving the size check to after
    /// the build loop) confirmed exactly that: the assertion above kept
    /// passing while this timing assertion failed, going from low
    /// milliseconds to multiple seconds. This test is the one that actually
    /// distinguishes "refused before allocating" from "refused after".
    #[test]
    fn cap_is_enforced_before_allocation_not_after() {
        let started = std::time::Instant::now();
        let err = expand_targets(&["10.0.0.0/8".into()], 1024).unwrap_err();
        let elapsed = started.elapsed();
        assert!(matches!(err, TargetError::TooManyTargets { max: 1024 }));
        assert!(
            elapsed < std::time::Duration::from_millis(200),
            "expand_targets(\"10.0.0.0/8\", 1024) took {elapsed:?}; a bound this loose only \
             fails if the 16.7M-address set actually got built before the cap was checked"
        );
    }

    // ---- AC-3.5 ---------------------------------------------------------

    #[test]
    fn malformed_input_names_the_offending_string() {
        let err = expand_targets(&["not-an-address".into()], 100).unwrap_err();
        assert!(format!("{err}").contains("not-an-address"));
    }

    #[test]
    fn a_reversed_range_is_rejected() {
        assert!(expand_targets(&["10.0.0.8-10.0.0.5".into()], 100).is_err());
    }

    /// Per the task dispatch: `a-b` splits on the first `-`; a malformed
    /// spec with an empty side must be a clear error, not a panic or a
    /// silent empty result.
    #[test]
    fn range_with_a_missing_side_is_malformed_not_a_panic_or_empty_set() {
        let trailing = expand_targets(&["1.2.3.4-".into()], 100).unwrap_err();
        assert!(matches!(trailing, TargetError::Malformed(ref s) if s == "1.2.3.4-"));

        let leading = expand_targets(&["-1.2.3.4".into()], 100).unwrap_err();
        assert!(matches!(leading, TargetError::Malformed(ref s) if s == "-1.2.3.4"));
    }

    // ---- IPv6 -------------------------------------------------------------

    /// M1 decided IPv6 scanning is out of scope for v0.1, and
    /// `ScopeManifest::allows` refuses every IPv6 address unconditionally.
    /// Expansion refuses IPv6 up front instead: a scan of thousands of
    /// units that are all denied at execution time would be a strictly
    /// worse operator experience than an immediate, actionable error.
    #[test]
    fn a_bare_ipv6_address_is_refused_with_a_clear_error() {
        let err = expand_targets(&["::1".into()], 100).unwrap_err();
        assert!(matches!(err, TargetError::Ipv6Unsupported(ref s) if s == "::1"));
        assert!(format!("{err}").to_lowercase().contains("ipv6"));
    }

    #[test]
    fn an_ipv6_cidr_is_refused_with_a_clear_error_and_no_attempt_to_expand() {
        // A /32 IPv6 prefix is 2^96 addresses -- `v6.hosts()` on this would
        // not finish. This must fail immediately, not hang.
        let started = std::time::Instant::now();
        let err = expand_targets(&["2001:db8::/32".into()], 100).unwrap_err();
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert!(matches!(err, TargetError::Ipv6Unsupported(ref s) if s == "2001:db8::/32"));
    }

    #[test]
    fn ipv6_mixed_with_valid_ipv4_targets_is_still_refused() {
        let err = expand_targets(&["10.0.0.1".into(), "::1".into()], 100).unwrap_err();
        assert!(matches!(err, TargetError::Ipv6Unsupported(_)));
    }

    // ---- Determinism (property) --------------------------------------------

    /// A Fisher-Yates permutation driven entirely by proptest-generated
    /// integers, so this property test doesn't need a `rand`-crate
    /// dependency (only `proptest`, already a dev-dependency) to produce a
    /// genuine permutation: `swaps[k] % (i + 1)` is always a valid swap
    /// partner for position `i`, for any `swaps[k]` proptest hands us.
    fn permute<T: Clone>(items: &[T], swaps: &[usize]) -> Vec<T> {
        let mut v = items.to_vec();
        let n = v.len();
        for i in (1..n).rev() {
            let j = swaps[n - 1 - i] % (i + 1);
            v.swap(i, j);
        }
        v
    }

    fn target_spec_strategy() -> impl proptest::strategy::Strategy<Value = String> {
        use proptest::prelude::*;
        prop_oneof![
            (0u8..=255, 0u8..=255, 0u8..=255, 0u8..=255)
                .prop_map(|(a, b, c, d)| format!("{a}.{b}.{c}.{d}")),
            (0u8..=255, 0u8..=255, 24u8..=30).prop_map(|(a, b, p)| format!("10.{a}.{b}.0/{p}")),
        ]
    }

    proptest::proptest! {
        /// AC-3.3, as a property rather than a fixed example: for *any*
        /// spec list, permuting the input must not change
        /// `expand_targets`'s output. This is what makes `plan_hash` stable
        /// regardless of the order a caller happens to list targets in.
        #[test]
        fn any_permutation_of_specs_yields_an_identical_output_vector(
            (specs, swaps) in {
                use proptest::strategy::Strategy;
                proptest::collection::vec(target_spec_strategy(), 0..8).prop_flat_map(|specs| {
                    let len = specs.len();
                    (proptest::strategy::Just(specs), proptest::collection::vec(proptest::prelude::any::<usize>(), len))
                })
            }
        ) {
            let permuted = permute(&specs, &swaps);
            let original = expand_targets(&specs, 10_000).unwrap();
            let after_permutation = expand_targets(&permuted, 10_000).unwrap();
            proptest::prop_assert_eq!(original, after_permutation);
        }
    }
}
