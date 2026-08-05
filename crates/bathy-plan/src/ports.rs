//! Port selection: turning a [`PortSelection`] into the concrete, sorted,
//! deduplicated `u16` list a plan is built over.
//!
//! # The two datasets are not a frequency ranking
//!
//! [`TOP_100`] and [`COMMON_1000`] are derived solely from the IANA *Service
//! Name and Transport Protocol Port Number Registry*, following the
//! heuristic documented in `crates/bathy-plan/data/ports/README.md`: system ports (1-1023)
//! with a TCP assignment, ascending, then user ports (1024-49151) with a TCP
//! assignment, ascending. IANA records *assignments*, not *observed
//! prevalence* -- this is a reasonable starting set, not a measurement of
//! which ports actually tend to be open. See the README for what that means
//! in practice.

use bathy_types::request::{PortPreset, PortSelection};

const TOP_100: &str = include_str!("../data/ports/top-100.txt");
const COMMON_1000: &str = include_str!("../data/ports/common-1000.txt");

#[derive(Debug, thiserror::Error)]
pub enum PortError {
    #[error("cannot parse port specification `{0}`")]
    Malformed(String),
    #[error("port 0 is not a scannable port (from `{0}`)")]
    PortZero(String),
    #[error("range `{0}` ends before it starts")]
    ReversedRange(String),
}

/// Resolve a selection into a sorted, deduplicated port list.
///
/// Sorting here rather than at scan time keeps `plan_hash` independent of how
/// the caller happened to phrase the request -- the same reasoning as
/// `targets::expand_targets`, which this mirrors: `["80", "22", "80"]` and
/// `["22", "80"]` must resolve to the identical `Vec<u16>`.
pub fn resolve_ports(selection: &PortSelection) -> Result<Vec<u16>, PortError> {
    let mut ports: Vec<u16> = match selection {
        PortSelection::Preset { preset } => match preset {
            PortPreset::Top100 => parse_dataset(TOP_100),
            PortPreset::Common1000 => parse_dataset(COMMON_1000),
            // 1..=u16::MAX is 1..=65535: every scannable port, excluding 0
            // (not a scannable port) and stopping at 65535 (u16's own
            // ceiling), so this is 65535 ports, never 65536.
            PortPreset::All => (1..=u16::MAX).collect(),
        },
        PortSelection::Explicit { explicit } => {
            let mut out = Vec::new();
            for spec in explicit.iter() {
                if let Some((a, b)) = spec.split_once('-') {
                    let a: u16 = a.parse().map_err(|_| PortError::Malformed(spec.clone()))?;
                    let b: u16 = b.parse().map_err(|_| PortError::Malformed(spec.clone()))?;
                    if a == 0 {
                        return Err(PortError::PortZero(spec.clone()));
                    }
                    if b < a {
                        return Err(PortError::ReversedRange(spec.clone()));
                    }
                    out.extend(a..=b);
                } else {
                    let p: u16 = spec
                        .parse()
                        .map_err(|_| PortError::Malformed(spec.clone()))?;
                    if p == 0 {
                        return Err(PortError::PortZero(spec.clone()));
                    }
                    out.push(p);
                }
            }
            out
        }
    };
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

/// Parse one of the embedded datasets: one port per line, blank lines and
/// `#`-prefixed comment lines ignored. Sorted and deduplicated defensively,
/// even though `xtask gen-ports` already produces sorted, unique output --
/// the dataset files are committed, hand-editable text, not exclusively the
/// tool's own output, so this function shouldn't assume they stayed that way.
fn parse_dataset(raw: &str) -> Vec<u16> {
    let mut v: Vec<u16> = raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.parse().expect("dataset contains only valid ports"))
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use bathy_types::nonempty::NonEmpty;

    fn preset(preset: PortPreset) -> PortSelection {
        PortSelection::Preset { preset }
    }

    fn explicit(specs: &[&str]) -> PortSelection {
        PortSelection::Explicit {
            explicit: NonEmpty::try_from(specs.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .expect("test fixture lists are never empty"),
        }
    }

    // ---- AC-3.6 -----------------------------------------------------------

    #[test]
    fn presets_have_their_advertised_sizes() {
        assert_eq!(
            resolve_ports(&preset(PortPreset::Top100)).unwrap().len(),
            100
        );
        assert_eq!(
            resolve_ports(&preset(PortPreset::Common1000))
                .unwrap()
                .len(),
            1000
        );
        assert_eq!(
            resolve_ports(&preset(PortPreset::All)).unwrap().len(),
            65535
        );
    }

    #[test]
    fn presets_are_sorted_and_unique() {
        for p in [PortPreset::Top100, PortPreset::Common1000] {
            let v = resolve_ports(&preset(p)).unwrap();
            let mut s = v.clone();
            s.sort_unstable();
            s.dedup();
            assert_eq!(v, s, "{p:?} must be sorted and free of duplicates");
        }
    }

    #[test]
    fn top_100_is_a_subset_of_common_1000() {
        let small = resolve_ports(&preset(PortPreset::Top100)).unwrap();
        let large = resolve_ports(&preset(PortPreset::Common1000)).unwrap();
        assert!(small.iter().all(|p| large.contains(p)));
    }

    // `PortPreset::All` is 65535 ports, not 65536: confirm the boundary
    // directly, not just the length, per the task dispatch's explicit ask.
    // Port 0 is excluded; the range starts at 1 and ends at u16::MAX.
    #[test]
    fn all_preset_excludes_port_zero_and_spans_one_to_max() {
        let all = resolve_ports(&preset(PortPreset::All)).unwrap();
        assert_eq!(all.len(), 65535);
        assert!(!all.contains(&0), "port 0 is not a scannable port");
        assert_eq!(all.first(), Some(&1u16));
        assert_eq!(all.last(), Some(&u16::MAX));
        // No gaps: every port from 1 to 65535 appears exactly once.
        let expected: Vec<u16> = (1..=u16::MAX).collect();
        assert_eq!(all, expected);
    }

    // ---- AC-3.8 -------------------------------------------------------

    #[test]
    fn explicit_ports_and_ranges_parse() {
        let sel = explicit(&["22", "8000-8003", "80"]);
        assert_eq!(
            resolve_ports(&sel).unwrap(),
            vec![22, 80, 8000, 8001, 8002, 8003]
        );
    }

    #[test]
    fn explicit_selection_is_sorted_and_deduplicated_regardless_of_input_order() {
        // AC-3.6/dispatch: `["80","22","80"]` and `["22","80"]` must produce
        // identical output -- this is what keeps `plan_hash` stable.
        let a = resolve_ports(&explicit(&["80", "22", "80"])).unwrap();
        let b = resolve_ports(&explicit(&["22", "80"])).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, vec![22, 80]);
    }

    #[test]
    fn a_single_port_range_spanning_the_whole_space_resolves_without_being_slow() {
        // dispatch: "A range that spans the whole space (1-65535) must work
        // and must not be quadratic or allocate absurdly."
        let started = std::time::Instant::now();
        // Nothing is scanned here: `resolve_ports` is a pure expansion and
        // this asserts its cost. The whole port space is the input under
        // test, not a range aimed at a machine.  [fixture-rule]
        let v = resolve_ports(&explicit(&["1-65535"])).unwrap();
        let elapsed = started.elapsed();
        assert_eq!(v.len(), 65535);
        assert_eq!(v.first(), Some(&1u16));
        assert_eq!(v.last(), Some(&u16::MAX));
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "resolving 1-65535 took {elapsed:?}; that's consistent with quadratic behavior"
        );
    }

    // ---- AC-3.9 -------------------------------------------------------

    #[test]
    fn port_zero_is_rejected() {
        let sel = explicit(&["0"]);
        assert!(resolve_ports(&sel).is_err());
    }

    #[test]
    fn port_zero_error_names_the_offending_input() {
        let err = resolve_ports(&explicit(&["0"])).unwrap_err();
        assert!(matches!(err, PortError::PortZero(ref s) if s == "0"));
        // Exact match, not `.contains('0')`: the static text "port 0 is not
        // a scannable port" already contains a literal '0' on its own, so a
        // `.contains('0')` check is coincidentally satisfied even if the
        // `{0}` field were dropped from the format string entirely --
        // confirmed by mutation (see the task fix report). Asserting the
        // full rendered message is the only way this test actually fails
        // when the field stops being interpolated.
        assert_eq!(
            format!("{err}"),
            "port 0 is not a scannable port (from `0`)"
        );
    }

    #[test]
    fn port_zero_as_a_range_start_is_rejected_and_names_the_range() {
        let err = resolve_ports(&explicit(&["0-100"])).unwrap_err();
        assert!(matches!(err, PortError::PortZero(ref s) if s == "0-100"));
        assert!(format!("{err}").contains("0-100"));
    }

    #[test]
    fn a_reversed_or_malformed_range_is_rejected() {
        for bad in ["100-50", "80-", "-80", "http", "70000"] {
            let sel = explicit(&[bad]);
            assert!(resolve_ports(&sel).is_err(), "{bad} should be rejected");
        }
    }

    // Per the task dispatch: every rejection names the offending input, not
    // just the ones the brief's own minimal test already covers.
    #[test]
    fn every_rejection_names_the_offending_input() {
        for bad in ["100-50", "80-", "-80", "http", "70000", "", "65536", "-1"] {
            let err = resolve_ports(&explicit(&[bad])).unwrap_err();
            let msg = format!("{err}");
            assert!(
                msg.contains(bad),
                "error for `{bad}` did not name it: {msg}"
            );
        }
    }

    #[test]
    fn an_empty_port_spec_is_rejected() {
        let err = resolve_ports(&explicit(&[""])).unwrap_err();
        assert!(matches!(err, PortError::Malformed(ref s) if s.is_empty()));
    }

    #[test]
    fn out_of_range_port_numbers_are_rejected() {
        // u16's own ceiling is 65535; anything above it must be rejected,
        // not silently truncated or wrapped.
        for bad in ["65536", "70000", "999999"] {
            assert!(resolve_ports(&explicit(&[bad])).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_mixture_of_individual_ports_and_ranges_across_multiple_specs() {
        let sel = explicit(&["443", "1-3", "8080", "3-5"]);
        assert_eq!(resolve_ports(&sel).unwrap(), vec![1, 2, 3, 4, 5, 443, 8080]);
    }

    // ---- Determinism (property) -----------------------------------------
    //
    // The fixed two-case example above (`explicit_selection_is_sorted_and_
    // deduplicated_regardless_of_input_order`) only ever proves the property
    // holds for `["80","22","80"]` vs `["22","80"]`. This is the same
    // property as `targets::expand_targets`'s own
    // `any_permutation_of_specs_yields_an_identical_output_vector` --
    // reused here with the same `permute` shape -- because it protects the
    // same guarantee: `plan_hash` must not depend on the order a caller
    // happened to list ports in, and only a property test over arbitrary
    // permutations, not a couple of fixed examples, actually establishes
    // that for every input shape, not just the ones someone thought to
    // write down.

    /// A Fisher-Yates permutation driven entirely by proptest-generated
    /// integers -- identical in shape to `targets::tests::permute`, kept as
    /// its own copy here rather than shared, since both are private test
    /// helpers in different modules.
    fn permute<T: Clone>(items: &[T], swaps: &[usize]) -> Vec<T> {
        let mut v = items.to_vec();
        let n = v.len();
        for i in (1..n).rev() {
            let j = swaps[n - 1 - i] % (i + 1);
            v.swap(i, j);
        }
        v
    }

    /// Always a *valid* explicit port spec (a single port or an ascending
    /// range, both within 1..=65535) -- this property is about order
    /// independence of a selection that resolves successfully, not about
    /// error handling, which the AC-3.9 tests above already cover.
    fn valid_port_spec_strategy() -> impl proptest::strategy::Strategy<Value = String> {
        use proptest::prelude::*;
        prop_oneof![
            (1u16..=u16::MAX).prop_map(|p| p.to_string()),
            (1u16..=u16::MAX, 1u16..=u16::MAX).prop_map(|(x, y)| {
                let (a, b) = if x <= y { (x, y) } else { (y, x) };
                format!("{a}-{b}")
            }),
        ]
    }

    proptest::proptest! {
        /// For *any* non-empty list of valid port specs, permuting the input
        /// must not change `resolve_ports`'s output. This is what keeps
        /// `plan_hash` stable regardless of the order a caller lists ports
        /// in -- an order-dependent resolution would turn every idempotent
        /// retry with reordered ports into a spurious plan-hash conflict.
        #[test]
        fn any_permutation_of_a_valid_explicit_selection_yields_an_identical_output_vector(
            (specs, swaps) in {
                use proptest::strategy::Strategy;
                proptest::collection::vec(valid_port_spec_strategy(), 1..8).prop_flat_map(|specs| {
                    let len = specs.len();
                    (proptest::strategy::Just(specs), proptest::collection::vec(proptest::prelude::any::<usize>(), len))
                })
            }
        ) {
            let permuted = permute(&specs, &swaps);
            let as_selection = |v: &[String]| explicit(&v.iter().map(String::as_str).collect::<Vec<_>>());
            let original = resolve_ports(&as_selection(&specs)).unwrap();
            let after_permutation = resolve_ports(&as_selection(&permuted)).unwrap();
            proptest::prop_assert_eq!(original, after_permutation);
        }
    }

    // ---- AC-3.7 ---------------------------------------------------------

    // Checked mechanically rather than by eyeballing, matching AC-3.6's own
    // "assert in tests, not by eyeballing" standard: the README must state
    // where the data came from, that no Nmap data file was consulted, and
    // that the ranking is a documented heuristic rather than an observed-
    // prevalence measurement.
    #[test]
    fn readme_states_iana_provenance_no_nmap_consultation_and_the_heuristic_disclaimer() {
        const README: &str = include_str!("../data/ports/README.md");
        let lower = README.to_lowercase();
        assert!(
            README.contains("IANA"),
            "README must name IANA as the source"
        );
        assert!(
            lower.contains("no nmap data file was consulted"),
            "README must plainly state no Nmap data was consulted"
        );
        assert!(
            lower.contains("not") && lower.contains("frequency ranking"),
            "README must plainly state the ranking is not a frequency/prevalence ranking"
        );
        assert!(
            lower.contains("assignments") && lower.contains("prevalence"),
            "README must distinguish IANA assignments from observed prevalence"
        );
    }
}
