# sonde M3 — Deterministic Planner & Scanning Engine — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a working scanner. Expand targets deterministically, compute a stable `plan_hash`, and execute the plan under hard budget and rate control with cancellation and resumption — using unprivileged TCP connect scanning and TCP-based host discovery.

**Architecture:** The planner is a pure function from `ScanRequest` to an ordered, indexable list of scan units; nothing about it touches the network or the clock, which is what makes `plan_hash` stable and resumption possible from a single integer. The scheduler is the only component permitted to emit packets, and every emission passes a budget check and a rate-limiter token first.

**Tech Stack:** tokio (net, time, sync), tokio-util (CancellationToken), ipnet, socket2.

**Read first:** the overview's Global Constraints; M1 Task 6 (`plan_digest`, `canonical_json`); M1 Task 8 (`BudgetLedger`); M2 Task 4 (`next_pending_unit`).

---

### Task 1: Target expansion

**Files:**
- Create: `crates/sonde-plan/Cargo.toml`, `crates/sonde-plan/src/lib.rs`, `crates/sonde-plan/src/targets.rs`

**Interfaces:**
- Consumes: nothing internal.
- Produces: `expand_targets(&[String], max: usize) -> Result<Vec<IpAddr>, TargetError>`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

    #[test]
    fn expands_a_slash_24_excluding_network_and_broadcast() {
        let out = expand_targets(&["10.30.0.0/24".into()], 100_000).unwrap();
        assert_eq!(out.len(), 254);
        assert_eq!(out[0], ip("10.30.0.1"));
        assert_eq!(out[253], ip("10.30.0.254"));
        assert!(!out.contains(&ip("10.30.0.0")), "network address");
        assert!(!out.contains(&ip("10.30.0.255")), "broadcast address");
    }

    #[test]
    fn slash_31_and_slash_32_keep_every_address() {
        // RFC 3021: a /31 is a point-to-point link, both addresses are usable.
        assert_eq!(expand_targets(&["10.0.0.0/31".into()], 100).unwrap().len(), 2);
        assert_eq!(expand_targets(&["10.0.0.7/32".into()], 100).unwrap().len(), 1);
    }

    #[test]
    fn accepts_a_bare_address_and_an_inclusive_range() {
        assert_eq!(expand_targets(&["10.0.0.5".into()], 100).unwrap(), vec![ip("10.0.0.5")]);
        let r = expand_targets(&["10.0.0.5-10.0.0.8".into()], 100).unwrap();
        assert_eq!(r, vec![ip("10.0.0.5"), ip("10.0.0.6"), ip("10.0.0.7"), ip("10.0.0.8")]);
    }

    #[test]
    fn output_is_sorted_and_deduplicated_so_the_plan_is_stable() {
        let a = expand_targets(&["10.0.0.2".into(), "10.0.0.1".into(), "10.0.0.2".into()], 100).unwrap();
        let b = expand_targets(&["10.0.0.1".into(), "10.0.0.2".into()], 100).unwrap();
        assert_eq!(a, b, "input order and duplicates must not change the plan");
    }

    #[test]
    fn overlapping_cidrs_do_not_produce_duplicate_targets() {
        let out = expand_targets(&["10.0.0.0/30".into(), "10.0.0.1/32".into()], 100).unwrap();
        assert_eq!(out, vec![ip("10.0.0.1"), ip("10.0.0.2")]);
    }

    #[test]
    fn exceeding_the_cap_is_refused_before_allocation() {
        let err = expand_targets(&["10.0.0.0/8".into()], 1024).unwrap_err();
        assert!(matches!(err, TargetError::TooManyTargets { .. }));
    }

    #[test]
    fn malformed_input_names_the_offending_string() {
        let err = expand_targets(&["not-an-address".into()], 100).unwrap_err();
        assert!(format!("{err}").contains("not-an-address"));
    }

    #[test]
    fn a_reversed_range_is_rejected() {
        assert!(expand_targets(&["10.0.0.8-10.0.0.5".into()], 100).is_err());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p sonde-plan targets`
Expected: FAIL — `expand_targets` not found.

- [ ] **Step 3: Write the implementation**

```rust
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
}

/// Expand target specifications into a sorted, deduplicated address list.
///
/// The output is a `BTreeSet` before becoming a `Vec`, so input order and
/// duplicate or overlapping specifications cannot change `plan_hash`. That
/// stability is what makes idempotency and resumption meaningful.
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
                set.insert(ip);
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
    Single(IpAddr),
    Range(Ipv4Addr, Ipv4Addr),
    Net(IpNet),
}

fn classify(spec: &str) -> Result<Spec, TargetError> {
    if let Ok(ip) = spec.parse::<IpAddr>() {
        return Ok(Spec::Single(ip));
    }
    if let Ok(net) = spec.parse::<IpNet>() {
        return Ok(Spec::Net(net));
    }
    if let Some((a, b)) = spec.split_once('-') {
        let (a, b) = (
            a.trim().parse::<Ipv4Addr>().map_err(|_| TargetError::Malformed(spec.to_owned()))?,
            b.trim().parse::<Ipv4Addr>().map_err(|_| TargetError::Malformed(spec.to_owned()))?,
        );
        if u32::from(b) < u32::from(a) {
            return Err(TargetError::ReversedRange(spec.to_owned()));
        }
        return Ok(Spec::Range(a, b));
    }
    Err(TargetError::Malformed(spec.to_owned()))
}

/// Hosts in a network, excluding the network and broadcast addresses for
/// prefixes shorter than /31. RFC 3021 makes both addresses of a /31 usable,
/// and a /32 is a single host, so neither is trimmed.
fn usable_hosts(net: IpNet) -> Box<dyn Iterator<Item = IpAddr>> {
    match net {
        IpNet::V4(v4) if v4.prefix_len() < 31 => {
            let first = u32::from(v4.network()) + 1;
            let last = u32::from(v4.broadcast()) - 1;
            Box::new((first..=last).map(|n| IpAddr::V4(Ipv4Addr::from(n))))
        }
        IpNet::V4(v4) => Box::new(Ipv4Net::hosts(&v4).map(IpAddr::V4)),
        IpNet::V6(v6) => Box::new(v6.hosts().map(IpAddr::V6)),
    }
}

fn count_of(spec: &str) -> Result<u128, TargetError> {
    Ok(match classify(spec)? {
        Spec::Single(_) => 1,
        Spec::Range(a, b) => (u32::from(b) - u32::from(a)) as u128 + 1,
        Spec::Net(IpNet::V4(v4)) if v4.prefix_len() < 31 => {
            (1u128 << (32 - v4.prefix_len())) - 2
        }
        Spec::Net(IpNet::V4(v4)) => 1u128 << (32 - v4.prefix_len()),
        Spec::Net(IpNet::V6(v6)) => 1u128 << (128 - v6.prefix_len()),
    })
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p sonde-plan targets` — expected 8 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/sonde-plan
git commit -m "feat(plan): order-independent target expansion with pre-allocation size check"
```

**Acceptance criteria:**
- **AC-3.1** A `/24` expands to 254 addresses, excluding network and broadcast.
- **AC-3.2** A `/31` yields 2 addresses and a `/32` yields 1 (RFC 3021).
- **AC-3.3** Output is sorted and deduplicated: permuting the input or adding overlapping specs yields an identical vector.
- **AC-3.4** Oversized target sets are refused by counting before allocating; `10.0.0.0/8` with a cap of 1024 does not allocate 16M addresses.
- **AC-3.5** Malformed specs and reversed ranges are errors whose message names the offending input.

---

### Task 2: Port sets and the clean-room port dataset

**Files:**
- Create: `crates/sonde-plan/src/ports.rs`
- Create: `data/ports/top-100.txt`, `data/ports/common-1000.txt`
- Create: `data/ports/README.md`
- Modify: `xtask/src/main.rs` (add `gen-ports`)

**Interfaces:**
- Consumes: `PortSelection`, `PortPreset`.
- Produces: `resolve_ports(&PortSelection) -> Result<Vec<u16>, PortError>`.

> **Clean-room note — read before starting.** Nmap's `nmap-services` frequency data must not be consulted, opened, or referenced. Our port rankings are derived only from the IANA *Service Name and Transport Protocol Port Number Registry*, which is published for unrestricted use. IANA records assignments, not observed prevalence, so our v0.1 ranking is a documented heuristic, not a measurement. `data/ports/README.md` must say so plainly. Replacing this with a ranking from our own measurement is v0.2 work and is the single largest gap between sonde and a mature scanner — do not let the README imply otherwise.

- [ ] **Step 1: Write `data/ports/README.md`**

```markdown
# Port datasets

## Provenance

Derived solely from the IANA Service Name and Transport Protocol Port Number
Registry. No Nmap data file was consulted in producing these lists.

## What the ranking means, and what it does not

IANA records *assignments*, not *observed prevalence*. These lists are ordered
by a documented heuristic:

1. System ports (0–1023) with a TCP assignment, ascending.
2. User ports (1024–49151) with a TCP assignment, ascending.

This is a reasonable starting set. It is **not** a frequency ranking, and it
will scan some ports that are almost never open while missing some high
non-assigned ports that commonly are. A prevalence ranking requires our own
measurement study and is tracked as issue #1 for v0.2.

## Regenerating

    cargo run -p xtask -- gen-ports --registry path/to/service-names-port-numbers.csv
```

- [ ] **Step 2: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use sonde_types::request::{PortPreset, PortSelection};

    #[test]
    fn presets_have_their_advertised_sizes() {
        assert_eq!(resolve_ports(&preset(PortPreset::Top100)).unwrap().len(), 100);
        assert_eq!(resolve_ports(&preset(PortPreset::Common1000)).unwrap().len(), 1000);
        assert_eq!(resolve_ports(&preset(PortPreset::All)).unwrap().len(), 65535);
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

    #[test]
    fn explicit_ports_and_ranges_parse() {
        let sel = PortSelection::Explicit {
            explicit: vec!["22".into(), "8000-8003".into(), "80".into()],
        };
        assert_eq!(resolve_ports(&sel).unwrap(), vec![22, 80, 8000, 8001, 8002, 8003]);
    }

    #[test]
    fn port_zero_is_rejected() {
        let sel = PortSelection::Explicit { explicit: vec!["0".into()] };
        assert!(resolve_ports(&sel).is_err());
    }

    #[test]
    fn a_reversed_or_malformed_range_is_rejected() {
        for bad in ["100-50", "80-", "-80", "http", "70000"] {
            let sel = PortSelection::Explicit { explicit: vec![bad.into()] };
            assert!(resolve_ports(&sel).is_err(), "{bad} should be rejected");
        }
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p sonde-plan ports` — expected FAIL.

- [ ] **Step 4: Write the implementation**

```rust
use sonde_types::request::{PortPreset, PortSelection};

const TOP_100: &str = include_str!("../../../data/ports/top-100.txt");
const COMMON_1000: &str = include_str!("../../../data/ports/common-1000.txt");

#[derive(Debug, thiserror::Error)]
pub enum PortError {
    #[error("cannot parse port specification `{0}`")]
    Malformed(String),
    #[error("port 0 is not a scannable port")]
    PortZero,
    #[error("range `{0}` ends before it starts")]
    ReversedRange(String),
}

/// Resolve a selection into a sorted, deduplicated port list.
///
/// Sorting here rather than at scan time keeps `plan_hash` independent of how
/// the caller happened to phrase the request.
pub fn resolve_ports(selection: &PortSelection) -> Result<Vec<u16>, PortError> {
    let mut ports: Vec<u16> = match selection {
        PortSelection::Preset { preset } => match preset {
            PortPreset::Top100 => parse_dataset(TOP_100),
            PortPreset::Common1000 => parse_dataset(COMMON_1000),
            PortPreset::All => (1..=u16::MAX).collect(),
        },
        PortSelection::Explicit { explicit } => {
            let mut out = Vec::new();
            for spec in explicit {
                if let Some((a, b)) = spec.split_once('-') {
                    let a: u16 = a.parse().map_err(|_| PortError::Malformed(spec.clone()))?;
                    let b: u16 = b.parse().map_err(|_| PortError::Malformed(spec.clone()))?;
                    if a == 0 {
                        return Err(PortError::PortZero);
                    }
                    if b < a {
                        return Err(PortError::ReversedRange(spec.clone()));
                    }
                    out.extend(a..=b);
                } else {
                    let p: u16 = spec.parse().map_err(|_| PortError::Malformed(spec.clone()))?;
                    if p == 0 {
                        return Err(PortError::PortZero);
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
```

Generate the two datasets with `xtask gen-ports` following the documented heuristic, then commit them. Verify by hand that `top-100.txt` contains 100 lines and `common-1000.txt` contains 1000, and that the former is a subset of the latter.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p sonde-plan ports` — expected 6 passed.

- [ ] **Step 6: Commit**

```bash
git add crates/sonde-plan data/ports xtask
git commit -m "feat(plan): clean-room IANA-derived port datasets and port resolution"
```

**Acceptance criteria:**
- **AC-3.6** `top-100` and `common-1000` contain exactly 100 and 1000 sorted unique ports, and `top-100` is a strict subset of `common-1000`.
- **AC-3.7** `data/ports/README.md` states the IANA provenance, states that no Nmap data was consulted, and states plainly that the ranking is a heuristic rather than a prevalence measurement.
- **AC-3.8** Explicit selections accept individual ports and inclusive ranges, and return sorted unique output.
- **AC-3.9** Port 0, reversed ranges, out-of-range values, and non-numeric specs are all rejected with a message naming the input.

---

### Task 3: The plan and its hash

**Files:**
- Create: `crates/sonde-plan/src/plan.rs`

**Interfaces:**
- Consumes: `expand_targets`, `resolve_ports`, `canonical_json`, `plan_digest`.
- Produces: `ScanPlan` with `build(&ScanRequest, max_targets) -> Result<Self>`, `hash() -> Digest`, `len() -> u64`, `unit(index: u64) -> Option<ScanUnit>`, `units_from(index) -> impl Iterator<Item = ScanUnit>`; `ScanUnit { index, target: IpAddr, endpoint: Endpoint }`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_count_is_targets_times_ports() {
        let plan = ScanPlan::build(&request_over("10.0.0.0/30", &["22", "80"]), 100_000).unwrap();
        assert_eq!(plan.len(), 2 * 2); // /30 → .1 and .2
    }

    #[test]
    fn units_are_port_major_so_consecutive_probes_hit_different_hosts() {
        let plan = ScanPlan::build(&request_over("10.0.0.0/29", &["22", "80"]), 100_000).unwrap();
        let first_six: Vec<_> = (0..6).map(|i| plan.unit(i).unwrap()).collect();
        // Port 22 across all six hosts before port 80 begins.
        assert!(first_six.iter().all(|u| u.endpoint.port == 22));
        let hosts: Vec<_> = first_six.iter().map(|u| u.target).collect();
        let unique: std::collections::BTreeSet<_> = hosts.iter().collect();
        assert_eq!(unique.len(), 6, "no host is probed twice in a row");
    }

    #[test]
    fn unit_index_is_stable_and_addressable() {
        let plan = ScanPlan::build(&request_over("10.0.0.0/29", &["22", "80"]), 100_000).unwrap();
        for i in 0..plan.len() {
            assert_eq!(plan.unit(i).unwrap().index, i);
        }
        assert!(plan.unit(plan.len()).is_none());
    }

    #[test]
    fn plan_hash_ignores_target_and_port_ordering() {
        let a = ScanPlan::build(&request_over_specs(&["10.0.0.1", "10.0.0.2"], &["80", "22"]), 100).unwrap();
        let b = ScanPlan::build(&request_over_specs(&["10.0.0.2", "10.0.0.1"], &["22", "80"]), 100).unwrap();
        assert_eq!(a.hash(), b.hash());
    }

    #[test]
    fn plan_hash_ignores_the_idempotency_key() {
        let mut r1 = request_over("10.0.0.0/30", &["22"]);
        let mut r2 = r1.clone();
        r1.idempotency_key = "run-one".into();
        r2.idempotency_key = "run-two".into();
        assert_eq!(
            ScanPlan::build(&r1, 100).unwrap().hash(),
            ScanPlan::build(&r2, 100).unwrap().hash()
        );
    }

    #[test]
    fn plan_hash_changes_when_budgets_change() {
        let mut r1 = request_over("10.0.0.0/30", &["22"]);
        let mut r2 = r1.clone();
        r2.budgets.maximum_packets = r1.budgets.maximum_packets + 1;
        assert_ne!(
            ScanPlan::build(&r1, 100).unwrap().hash(),
            ScanPlan::build(&r2, 100).unwrap().hash(),
            "a different budget is a different plan and must not reuse an idempotency key"
        );
    }

    #[test]
    fn resuming_from_an_index_yields_exactly_the_remaining_units() {
        let plan = ScanPlan::build(&request_over("10.0.0.0/29", &["22", "80"]), 100).unwrap();
        let remaining: Vec<_> = plan.units_from(9).collect();
        assert_eq!(remaining.len() as u64, plan.len() - 9);
        assert_eq!(remaining[0].index, 9);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p sonde-plan plan` — expected FAIL.

- [ ] **Step 3: Write the implementation**

```rust
use std::net::IpAddr;

use serde_json::json;
use sonde_types::canonical::plan_digest;
use sonde_types::event::{Endpoint, Transport};
use sonde_types::ids::Digest;
use sonde_types::request::ScanRequest;

use crate::ports::resolve_ports;
use crate::targets::expand_targets;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanUnit {
    pub index: u64,
    pub target: IpAddr,
    pub endpoint: Endpoint,
}

/// A fully enumerated, deterministically ordered scan.
///
/// The unit list is never persisted. Resumption stores only the highest
/// completed index and rebuilds the plan from the original request, which is
/// why the ordering below must never change for a given engine version.
#[derive(Clone, Debug)]
pub struct ScanPlan {
    targets: Vec<IpAddr>,
    ports: Vec<u16>,
    hash: Digest,
}

impl ScanPlan {
    pub fn build(request: &ScanRequest, max_targets: usize) -> Result<Self, PlanError> {
        let targets = expand_targets(&request.targets, max_targets)?;
        let ports = resolve_ports(&request.ports)?;

        // Hash the normalized request with the idempotency key removed: the key
        // names an attempt, the hash names the work. Budgets ARE included, so
        // reusing a key with a larger budget is a conflict rather than a silent
        // widening.
        let mut normalized = serde_json::to_value(request).expect("request serializes");
        normalized.as_object_mut().expect("request is an object").remove("idempotency_key");
        let canonical = json!({
            "engine_plan_version": 1,
            "request": normalized,
            "expanded_targets": targets.iter().map(|t| t.to_string()).collect::<Vec<_>>(),
            "resolved_ports": ports,
        });
        let hash = plan_digest(&canonical)?;
        Ok(Self { targets, ports, hash })
    }

    pub fn hash(&self) -> Digest {
        self.hash
    }
    pub fn targets(&self) -> &[IpAddr] {
        &self.targets
    }
    pub fn len(&self) -> u64 {
        self.targets.len() as u64 * self.ports.len() as u64
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Port-major ordering: every host is probed on port *p* before any host is
    /// probed on port *p+1*. Consecutive units therefore hit different hosts,
    /// which spreads load across the target network instead of hammering one
    /// address — better for the target and better for result quality, since a
    /// host that rate-limits will distort a host-major scan far more.
    pub fn unit(&self, index: u64) -> Option<ScanUnit> {
        if index >= self.len() {
            return None;
        }
        let hosts = self.targets.len() as u64;
        let port_index = (index / hosts) as usize;
        let host_index = (index % hosts) as usize;
        Some(ScanUnit {
            index,
            target: self.targets[host_index],
            endpoint: Endpoint { transport: Transport::Tcp, port: self.ports[port_index] },
        })
    }

    pub fn units_from(&self, index: u64) -> impl Iterator<Item = ScanUnit> + '_ {
        (index..self.len()).filter_map(|i| self.unit(i))
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p sonde-plan plan` — expected 7 passed.

- [ ] **Step 5: Add a property test for plan stability**

```rust
proptest::proptest! {
    /// Plan determinism, stated directly: building the same request twice must
    /// produce the same hash and the same unit at every index.
    #[test]
    fn identical_requests_produce_identical_plans(seed in 0u8..64) {
        let r = request_over(&format!("10.0.{seed}.0/30"), &["22", "80", "443"]);
        let a = ScanPlan::build(&r, 10_000).unwrap();
        let b = ScanPlan::build(&r, 10_000).unwrap();
        proptest::prop_assert_eq!(a.hash(), b.hash());
        proptest::prop_assert_eq!(a.len(), b.len());
        for i in 0..a.len() {
            proptest::prop_assert_eq!(a.unit(i), b.unit(i));
        }
    }
}
```

- [ ] **Step 6: Commit**

```bash
git add crates/sonde-plan
git commit -m "feat(plan): deterministic port-major plan with stable plan_hash"
```

**Acceptance criteria:**
- **AC-3.10** `plan_hash` is identical for requests differing only in target order, port order, or `idempotency_key`.
- **AC-3.11** `plan_hash` differs when budgets differ, so an idempotency key cannot be reused to widen a scan.
- **AC-3.12** Units are port-major: consecutive indices address different hosts.
- **AC-3.13** `unit(i).index == i` for all `i < len()`, and `unit(len())` is `None`.
- **AC-3.14** The expanded target list is never persisted — resumption uses only an index plus the stored request. Verify by grepping the schema for any column holding addresses.
- **AC-3.15** A property test confirms building a request twice yields identical hash, length, and unit-at-index.

---

### Task 4: Rate limiter and budget-governed emission

**Files:**
- Create: `crates/sonde-engine/Cargo.toml`, `crates/sonde-engine/src/lib.rs`, `crates/sonde-engine/src/rate.rs`

**Interfaces:**
- Consumes: `BudgetLedger`.
- Produces: `RateLimiter::new(pps: u32) -> Self`, `async fn acquire(&self, n: u32)`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn the_first_burst_is_immediate() {
        let l = RateLimiter::new(100);
        let t = Instant::now();
        for _ in 0..100 {
            l.acquire(1).await;
        }
        assert!(t.elapsed().as_millis() < 50, "initial bucket should be full");
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

    #[tokio::test]
    async fn a_request_larger_than_the_bucket_still_completes() {
        let l = RateLimiter::new(10);
        l.acquire(25).await; // must not deadlock
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p sonde-engine rate` — expected FAIL.

- [ ] **Step 3: Write the implementation**

```rust
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
    pub fn new(packets_per_second: u32) -> Self {
        let capacity = packets_per_second.max(1) as f64;
        Self {
            inner: Mutex::new(Bucket { tokens: capacity, last: Instant::now() }),
            capacity,
            refill_per_second: capacity,
        }
    }

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
                // Consume what is available and wait for the remainder, so a
                // request larger than the bucket makes progress instead of
                // spinning forever waiting for a level it can never reach.
                needed -= b.tokens;
                b.tokens = 0.0;
                Duration::from_secs_f64((needed / self.refill_per_second).min(1.0))
            };
            sleep(wait).await;
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p sonde-engine rate` — expected 3 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/sonde-engine
git commit -m "feat(engine): token-bucket rate limiter with oversized-request progress"
```

**Acceptance criteria:**
- **AC-3.16** Sustained acquisition matches the configured packets-per-second within 10% under a paused Tokio clock.
- **AC-3.17** `acquire(n)` where `n` exceeds bucket capacity completes rather than deadlocking.

---

### Task 5: TCP connect scanning

**Files:**
- Create: `crates/sonde-engine/src/connect.rs`

**Interfaces:**
- Consumes: `Endpoint`, `PortState`.
- Produces: `async fn probe_connect(target: IpAddr, port: u16, timeout: Duration) -> ConnectOutcome`, `enum ConnectOutcome { Open, Closed, Filtered, Unreachable }`, `fn classify_io_error(&std::io::Error) -> ConnectOutcome`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_listening_socket_reports_open() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let out = probe_connect("127.0.0.1".parse().unwrap(), port, Duration::from_secs(2)).await;
        assert_eq!(out, ConnectOutcome::Open);
    }

    #[tokio::test]
    async fn a_refused_connection_reports_closed() {
        // Bind then drop, so the port is almost certainly unbound and refusing.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let out = probe_connect("127.0.0.1".parse().unwrap(), port, Duration::from_secs(2)).await;
        assert_eq!(out, ConnectOutcome::Closed);
    }

    #[tokio::test]
    async fn a_timeout_reports_filtered_not_closed() {
        // TEST-NET-1 (RFC 5737) is reserved for documentation and never routes.
        let out = probe_connect("192.0.2.1".parse().unwrap(), 80, Duration::from_millis(300)).await;
        assert!(
            matches!(out, ConnectOutcome::Filtered | ConnectOutcome::Unreachable),
            "a silent drop is filtered, never closed; got {out:?}"
        );
    }

    #[test]
    fn error_classification_distinguishes_refused_from_unreachable() {
        use std::io::{Error, ErrorKind};
        assert_eq!(
            classify_io_error(&Error::from(ErrorKind::ConnectionRefused)),
            ConnectOutcome::Closed
        );
        assert_eq!(
            classify_io_error(&Error::from(ErrorKind::HostUnreachable)),
            ConnectOutcome::Unreachable
        );
        assert_eq!(
            classify_io_error(&Error::from(ErrorKind::NetworkUnreachable)),
            ConnectOutcome::Unreachable
        );
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p sonde-engine connect` — expected FAIL.

- [ ] **Step 3: Write the implementation**

```rust
use std::net::{IpAddr, SocketAddr};

use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

/// The result of one connect attempt.
///
/// `Closed` and `Filtered` are kept distinct because they carry opposite
/// information: a refusal proves a host is alive and reachable, whereas
/// silence proves only that something in the path is not answering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectOutcome {
    Open,
    Closed,
    Filtered,
    Unreachable,
}

pub fn classify_io_error(e: &std::io::Error) -> ConnectOutcome {
    use std::io::ErrorKind::*;
    match e.kind() {
        ConnectionRefused => ConnectOutcome::Closed,
        HostUnreachable | NetworkUnreachable | NetworkDown => ConnectOutcome::Unreachable,
        TimedOut => ConnectOutcome::Filtered,
        _ => ConnectOutcome::Filtered,
    }
}

pub async fn probe_connect(target: IpAddr, port: u16, budget: Duration) -> ConnectOutcome {
    let addr = SocketAddr::new(target, port);
    match timeout(budget, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            // Close immediately: v0.1 connect scanning establishes reachability
            // only. Service probing owns the socket in M4 and reuses it there
            // rather than reconnecting.
            drop(stream);
            ConnectOutcome::Open
        }
        Ok(Err(e)) => classify_io_error(&e),
        Err(_elapsed) => ConnectOutcome::Filtered,
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p sonde-engine connect` — expected 4 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/sonde-engine
git commit -m "feat(engine): unprivileged TCP connect probing with filtered/closed distinction"
```

**Acceptance criteria:**
- **AC-3.18** A listening socket yields `Open`; a refusing port yields `Closed`; a silently dropped connection yields `Filtered` or `Unreachable` and never `Closed`.
- **AC-3.19** `classify_io_error` maps `ConnectionRefused` to `Closed` and both unreachable kinds to `Unreachable`.
- **AC-3.20** These tests run without elevated privileges.

---

### Task 6: Host discovery

**Files:**
- Create: `crates/sonde-engine/src/discovery.rs`

**Interfaces:**
- Consumes: `probe_connect`, `RateLimiter`.
- Produces: `async fn discover_host(IpAddr, &DiscoveryConfig, &RateLimiter) -> DiscoveryResult`, `DiscoveryConfig { probe_ports: Vec<u16>, timeout: Duration }`, `DiscoveryResult { up: bool, method: String, packets_spent: u64 }`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_listening_host_is_discovered_via_the_open_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let cfg = DiscoveryConfig { probe_ports: vec![port], timeout: Duration::from_secs(2) };
        let r = discover_host("127.0.0.1".parse().unwrap(), &cfg, &limiter()).await;
        assert!(r.up);
        assert_eq!(r.method, "tcp-connect-open");
    }

    #[tokio::test]
    async fn a_refusing_port_still_proves_the_host_is_up() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let cfg = DiscoveryConfig { probe_ports: vec![port], timeout: Duration::from_secs(2) };
        let r = discover_host("127.0.0.1".parse().unwrap(), &cfg, &limiter()).await;
        assert!(r.up, "a refusal is positive evidence of a live host");
        assert_eq!(r.method, "tcp-connect-refused");
    }

    #[tokio::test]
    async fn discovery_stops_at_the_first_conclusive_probe() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = listener.local_addr().unwrap().port();
        let cfg = DiscoveryConfig {
            probe_ports: vec![open, 9, 9, 9],
            timeout: Duration::from_secs(2),
        };
        let r = discover_host("127.0.0.1".parse().unwrap(), &cfg, &limiter()).await;
        assert_eq!(r.packets_spent, 1, "must not probe remaining ports after a conclusive answer");
    }

    #[tokio::test]
    async fn an_unroutable_host_is_reported_down_after_exhausting_probes() {
        let cfg = DiscoveryConfig {
            probe_ports: vec![80, 443],
            timeout: Duration::from_millis(200),
        };
        let r = discover_host("192.0.2.1".parse().unwrap(), &cfg, &limiter()).await;
        assert!(!r.up);
        assert_eq!(r.packets_spent, 2);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p sonde-engine discovery` — expected FAIL.

- [ ] **Step 3: Write the implementation**

```rust
use std::net::IpAddr;

use tokio::time::Duration;

use crate::connect::{ConnectOutcome, probe_connect};
use crate::rate::RateLimiter;

pub struct DiscoveryConfig {
    /// Tried in order. Defaults to 443, 80, 22 — chosen because a host that
    /// answers on none of these and is silent is usually genuinely absent.
    pub probe_ports: Vec<u16>,
    pub timeout: Duration,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self { probe_ports: vec![443, 80, 22], timeout: Duration::from_secs(2) }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryResult {
    pub up: bool,
    /// Recorded on the `host.discovered` event so a finding can be explained.
    pub method: String,
    pub packets_spent: u64,
}

/// Unprivileged host discovery.
///
/// Both an accepted and a refused connection prove the host is up; only
/// silence and unreachability are inconclusive. Probing stops at the first
/// conclusive answer, so a live host normally costs one packet rather than
/// the whole probe list.
pub async fn discover_host(
    target: IpAddr,
    config: &DiscoveryConfig,
    limiter: &RateLimiter,
) -> DiscoveryResult {
    let mut spent = 0u64;
    for port in &config.probe_ports {
        limiter.acquire(1).await;
        spent += 1;
        match probe_connect(target, *port, config.timeout).await {
            ConnectOutcome::Open => {
                return DiscoveryResult { up: true, method: "tcp-connect-open".into(), packets_spent: spent };
            }
            ConnectOutcome::Closed => {
                return DiscoveryResult { up: true, method: "tcp-connect-refused".into(), packets_spent: spent };
            }
            ConnectOutcome::Filtered | ConnectOutcome::Unreachable => continue,
        }
    }
    DiscoveryResult { up: false, method: "no-response".into(), packets_spent: spent }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p sonde-engine discovery` — expected 4 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/sonde-engine
git commit -m "feat(engine): TCP host discovery treating refusal as liveness evidence"
```

**Acceptance criteria:**
- **AC-3.21** A refused connection marks the host up with method `tcp-connect-refused`.
- **AC-3.22** Discovery short-circuits at the first conclusive probe and reports the true packet count.
- **AC-3.23** A silent host is reported down only after every configured probe port is exhausted.

---

### Task 7: The scheduler — cancellation, budgets, resumption

**Files:**
- Create: `crates/sonde-engine/src/scheduler.rs`

**Interfaces:**
- Consumes: everything above, `EventLog`, `TaskStore`, `BudgetLedger`, `PolicyDecision`.
- Produces: `Scheduler::new(...)`, `async fn run(&self, plan: &ScanPlan, from_index: u64, cancel: CancellationToken) -> Result<RunSummary>`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_completed_run_emits_started_then_states_then_completed() {
        let h = harness(&["127.0.0.1"], &[open_port().await]);
        let summary = h.run_to_completion().await.unwrap();
        let events = h.log.read_from(0).unwrap();
        assert!(matches!(events.first().unwrap().body, EventBody::ScanStarted { .. }));
        assert!(matches!(events.last().unwrap().body, EventBody::ScanCompleted { .. }));
        assert_eq!(summary.units_completed, 1);
    }

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
        assert!(summary.units_completed < h.plan.len(), "must not have finished");
        assert!(summary.units_completed > 0, "must have made progress");
        let next = h.store.next_pending_unit(h.scan_id, h.plan.len()).unwrap();
        assert!(next.is_some(), "a cancelled scan must leave a resume point");
    }

    #[tokio::test]
    async fn exhausting_the_packet_budget_stops_the_scan_and_records_why() {
        let h = harness_with_packet_budget(10);
        let summary = h.run_to_completion().await.unwrap();
        assert!(summary.budget_exhausted);
        assert!(summary.packets_spent <= 10, "spent {} over a ceiling of 10", summary.packets_spent);
        let events = h.log.read_from(0).unwrap();
        assert!(events.iter().any(|e| matches!(
            &e.body, EventBody::ScanFailed { reason_code, .. } if reason_code == "budget_exhausted"
        )));
    }

    #[tokio::test]
    async fn resuming_skips_completed_units_and_never_repeats_one() {
        let h = harness_with_many_units(200);
        h.store.mark_units_done(h.scan_id, &(0..50).collect::<Vec<_>>()).unwrap();
        let start = h.store.next_pending_unit(h.scan_id, h.plan.len()).unwrap().unwrap();
        assert_eq!(start, 50);
        let summary = h.scheduler.run(&h.plan, start, CancellationToken::new()).await.unwrap();
        let probed = h.probed_indices();
        assert!(probed.iter().all(|i| *i >= 50), "resume must not re-probe completed units");
        let unique: std::collections::BTreeSet<_> = probed.iter().collect();
        assert_eq!(unique.len(), probed.len(), "no unit probed twice");
        assert_eq!(summary.units_completed, h.plan.len() - 50);
    }

    #[tokio::test]
    async fn every_open_port_produces_exactly_one_port_state_event() {
        let h = harness(&["127.0.0.1"], &[open_port().await, open_port().await]);
        h.run_to_completion().await.unwrap();
        let opens = h.log.read_from(0).unwrap().iter().filter(|e| matches!(
            &e.body, EventBody::PortStateObserved { state: PortState::Open, .. }
        )).count();
        assert_eq!(opens, 2);
    }

    #[tokio::test]
    async fn progress_events_are_emitted_periodically_during_a_long_scan() {
        let h = harness_with_many_units(2_000);
        h.run_to_completion().await.unwrap();
        let progress = h.log.read_from(0).unwrap().iter()
            .filter(|e| matches!(&e.body, EventBody::Progress { .. }))
            .count();
        assert!(progress >= 2, "expected periodic progress, saw {progress}");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p sonde-engine scheduler` — expected FAIL.

- [ ] **Step 3: Write the implementation**

```rust
use std::sync::Arc;

use tokio::sync::Semaphore;
use tokio::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

use sonde_scope::budget::BudgetLedger;
use sonde_types::event::{Endpoint, EventBody, PortState, Target};

use crate::connect::{ConnectOutcome, probe_connect};
use crate::rate::RateLimiter;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RunSummary {
    pub units_completed: u64,
    pub packets_spent: u64,
    pub open_ports: u64,
    pub cancelled: bool,
    pub budget_exhausted: bool,
    pub time_exhausted: bool,
}

pub struct Scheduler {
    pub limiter: RateLimiter,
    pub ledger: std::sync::Mutex<BudgetLedger>,
    pub concurrency: usize,
    pub connect_timeout: Duration,
    pub progress_every: u64,
}

impl Scheduler {
    /// Execute units `from_index..plan.len()`.
    ///
    /// Ordering guarantees: unit completion is recorded in batches as work
    /// finishes, so a cancelled or crashed scan resumes from the first
    /// genuinely unfinished unit. The scan stops on the first of: plan
    /// exhaustion, cancellation, packet budget exhaustion, or runtime
    /// exhaustion — each of which is reported distinctly in `RunSummary` and
    /// as a terminal event.
    pub async fn run(
        &self,
        plan: &ScanPlan,
        from_index: u64,
        cancel: CancellationToken,
    ) -> Result<RunSummary, EngineError> {
        let started = Instant::now();
        let mut summary = RunSummary::default();

        self.log(EventBody::ScanStarted {
            plan_hash: plan.hash(),
            estimated_targets: plan.targets().len() as u64,
            estimated_probes: plan.len(),
        })?;

        let permits = Arc::new(Semaphore::new(self.concurrency));
        let mut in_flight = tokio::task::JoinSet::new();
        let mut units = plan.units_from(from_index);
        let mut completed_batch: Vec<u64> = Vec::with_capacity(64);

        loop {
            if cancel.is_cancelled() {
                summary.cancelled = true;
                break;
            }
            if self.ledger.lock().unwrap().elapsed_exceeded(started.elapsed().as_secs()) {
                summary.time_exhausted = true;
                break;
            }

            // Reserve budget BEFORE emitting. A refused reservation ends the
            // scan; it never emits "just one more" packet.
            let Some(unit) = units.next() else { break };
            if self.ledger.lock().unwrap().try_spend_packets(1).is_err() {
                summary.budget_exhausted = true;
                break;
            }

            self.limiter.acquire(1).await;
            let permit = permits.clone().acquire_owned().await.expect("semaphore open");
            let timeout = self.connect_timeout;
            in_flight.spawn(async move {
                let outcome = probe_connect(unit.target, unit.endpoint.port, timeout).await;
                drop(permit);
                (unit, outcome)
            });

            while let Some(done) = in_flight.try_join_next() {
                self.record(done?, &mut summary, &mut completed_batch)?;
            }
            if completed_batch.len() >= 64 {
                self.flush_progress(&mut completed_batch, &summary)?;
            }
        }

        // Drain work already in flight so their results are not lost, even on
        // cancellation: they were paid for out of the budget.
        while let Some(done) = in_flight.join_next().await {
            self.record(done?, &mut summary, &mut completed_batch)?;
        }
        self.flush_progress(&mut completed_batch, &summary)?;

        if summary.budget_exhausted {
            self.log(EventBody::ScanFailed {
                reason_code: "budget_exhausted".into(),
                detail: format!("packet budget spent after {} units", summary.units_completed),
            })?;
        } else if summary.time_exhausted {
            self.log(EventBody::ScanFailed {
                reason_code: "time_exhausted".into(),
                detail: format!("runtime budget elapsed after {} units", summary.units_completed),
            })?;
        } else if !summary.cancelled {
            self.log(EventBody::ScanCompleted {
                probes_sent: summary.units_completed,
                packets_spent: summary.packets_spent,
                findings: summary.open_ports,
            })?;
        }
        Ok(summary)
    }
}
```

Implement `record` (map `ConnectOutcome` to `PortState`, emit a `port.state` event, push the unit index onto the batch, update counters) and `flush_progress` (call `store.mark_units_done`, emit a `Progress` event every `progress_every` units, clear the batch).

Mapping: `Open → PortState::Open`, `Closed → Closed`, `Filtered → Filtered`, `Unreachable → Filtered` (with the discovery method recorded separately).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p sonde-engine scheduler` — expected 6 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/sonde-engine
git commit -m "feat(engine): budget-governed scheduler with cancellation and resumption"
```

**Acceptance criteria:**
- **AC-3.24** Budget is reserved *before* emission; total packets never exceed `maximum_packets`. Verify with a budget of 10 against a plan of thousands of units.
- **AC-3.25** Cancellation halts the scan promptly, drains in-flight work, and leaves `next_pending_unit` pointing at a genuine resume point.
- **AC-3.26** Resuming from index *n* probes no unit below *n* and probes no unit twice.
- **AC-3.27** Budget exhaustion, time exhaustion, and cancellation are reported as three distinct outcomes with distinct terminal events (`budget_exhausted`, `time_exhausted`, and no terminal failure event for cancellation).
- **AC-3.28** Every scan begins with exactly one `scan.started` carrying the `plan_hash` and ends with exactly one terminal event.
- **AC-3.29** Every probed unit produces exactly one `port.state` event — no duplicates, no omissions.
- **AC-3.30** `scan.progress` events are emitted periodically during long scans.

---

## Milestone Exit Criteria

- [ ] `cargo test --workspace` green; clippy clean; `xtask check-deps` and `check-schemas` clean.
- [ ] AC-3.1 through AC-3.30 each demonstrated by a named passing test.
- [ ] An end-to-end test scans `127.0.0.1` against two locally bound ports and produces a valid, gap-free event log containing `scan.started`, two `port.state` events with `state: open`, and `scan.completed`.
- [ ] A scan cancelled mid-flight can be resumed to completion, and the union of both runs' probed units equals the plan exactly, with no duplicates.
- [ ] **This milestone ships a usable scanner.** Tag `v0.1.0-alpha.1`.
