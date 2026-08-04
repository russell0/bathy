#![no_main]
#![forbid(unsafe_code)]

//! Fuzzes scope-manifest loading and the deny-by-default gate -- AC-7.7.
//!
//! A manifest is the authorization boundary: `ScopeManifest::allows` is the
//! single function standing between a request and a packet on somebody
//! else's wire. Its input is a JSON document from outside the process.
//!
//! A panic in `load` is a denial of service. A *wrong answer* from `allows`
//! is worse than that, so this target does not stop at "it did not crash".
//! It re-derives the allow and deny sets from the raw document with the same
//! CIDR parser the manifest uses, and asserts the three properties
//! `ScopeManifest`'s own doc comment states as absolute, over addresses
//! chosen to straddle them:
//!
//! 1. Deny-by-default -- `allows` is true only on an allow-set match.
//! 2. Deny beats allow, always.
//! 3. Reserved ranges are refused whatever the document says.
//!
//! Deriving the expected answer from the document rather than from the
//! loaded manifest is the point: a `load` that silently dropped, widened or
//! reordered a CIDR would satisfy any assertion phrased in terms of the
//! object it returned.

use std::net::{IpAddr, Ipv4Addr};

use bathy_fuzz::Stats;
use bathy_scope::{ManifestError, ScopeManifest};
use ipnet::IpNet;
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

const UTF8: usize = 0;
const JSON: usize = 1;
const LOADED: usize = 2;
const REJECTED: usize = 3;
const ALLOW_DECISIONS: usize = 4;
const ALLOWED_TRUE: usize = 5;

const LABELS: &[&str] = &[
    "utf8",
    "json",
    // The number that says whether this target reached anything past
    // `serde_json`: a run with `loaded=0` has fuzzed a deserializer, not a
    // policy engine.
    "loaded",
    "rejected",
    "allow_decisions",
    // Non-zero is what proves the *positive* branch of `allows` was reached
    // and not only its refusals.
    "allowed_true",
];

const FLAGS: &[&str] = &[
    "err:malformed",
    "err:no_allowed_cidrs",
    "err:bad_cidr",
    "err:bad_expiry",
    "err:no_usable_allowed_cidrs",
    "ok:expired",
    "ok:unexpired",
    "ok:had_signature",
    "ok:denied_non_empty",
];

static STATS: Stats = Stats::new("manifest", LABELS, FLAGS);

/// Addresses chosen to straddle every branch of `allows`: ordinary unicast
/// inside common private ranges, a public address, and one member of each
/// category `is_ordinary_unicast` refuses outright.
const PROBES: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
    IpAddr::V4(Ipv4Addr::new(10, 30, 0, 10)),
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 7)),
    IpAddr::V4(Ipv4Addr::new(172, 16, 4, 4)),
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
    // Refused regardless of the document: loopback, link-local, multicast,
    // broadcast, unspecified, and the reserved 240/4.
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
    IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
    IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1)),
];

/// The CIDR strings the *document* listed under `field`, parsed with the
/// same parser `load` uses. `None` when the field is absent or not a list of
/// strings, which is a document `load` will have rejected anyway.
fn cidrs(document: &Value, field: &str) -> Option<Vec<IpNet>> {
    let list = document.get(field)?.as_array()?;
    list.iter()
        .map(|v| v.as_str()?.parse::<IpNet>().ok())
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        STATS.tick();
        return;
    };
    STATS.bump(UTF8);

    let document: Option<Value> = serde_json::from_str(text).ok();
    if document.is_some() {
        STATS.bump(JSON);
    }

    let manifest = match ScopeManifest::load(text) {
        Ok(manifest) => manifest,
        Err(e) => {
            STATS.bump(REJECTED);
            STATS.flag(match e {
                ManifestError::Malformed(_) => 0,
                ManifestError::NoAllowedCidrs => 1,
                ManifestError::BadCidr(_) => 2,
                ManifestError::BadExpiry(_) => 3,
                ManifestError::NoUsableAllowedCidrs => 4,
            });
            STATS.tick();
            return;
        }
    };
    STATS.bump(LOADED);

    // The clock comes from the INPUT, not from a date written here.
    //
    // It was `"2026-08-04T00:00:00.000Z"`, which partitions `ok:expired` and
    // `ok:unexpired` on a frozen instant: as the tree ages and new seeded
    // manifests are written with later expiries, every document drifts to one
    // side and one of the two flags stops being reached, with nothing to say
    // the split has gone vacuous. Deriving the year from the input keeps both
    // branches reachable for any document, forever, and costs one byte.
    //
    // `is_expired` parses its argument every call and fails closed; a clock
    // string it cannot read must never read as "still valid".
    // Over ALL the bytes, not the first one: every document that reaches
    // this line starts with `{`, so a clock derived from `data[0]` is a
    // frozen clock with extra steps -- measured, not assumed (it put all
    // twelve committed seeds in the same year and left `ok:expired`
    // unreached). A cheap hash of the whole input spreads the seeds across
    // the range and stays deterministic per input, which is what a fuzzer
    // needs to reproduce a crash.
    let year = 1970
        + data
            .iter()
            .fold(0u32, |a, b| a.wrapping_mul(31).wrapping_add(u32::from(*b)))
            % 120;
    let clock = format!("{year:04}-06-15T12:00:00.000Z");
    if manifest.is_expired(&clock) {
        STATS.flag(5);
    } else {
        STATS.flag(6);
    }
    assert!(
        manifest.is_expired("not a timestamp"),
        "a clock value `is_expired` cannot parse must fail closed"
    );
    if manifest.had_signature() {
        STATS.flag(7);
    }
    assert!(
        !manifest.signature_verified(),
        "v0.1 verifies no signature, so `signature_verified` must never be true"
    );

    // A document that loaded is, by construction, valid JSON with parseable
    // CIDR lists -- so these are `Some` here, and the expected answer below
    // is derived from the document rather than from the object under test.
    let (Some(allowed), Some(denied)) = (
        document.as_ref().and_then(|d| cidrs(d, "allowed_cidrs")),
        document
            .as_ref()
            .map(|d| cidrs(d, "denied_cidrs").unwrap_or_default()),
    ) else {
        panic!("a manifest loaded from a document this target could not re-read: {text:?}");
    };
    if !denied.is_empty() {
        STATS.flag(8);
    }

    for ip in PROBES {
        let verdict = manifest.allows(*ip);
        STATS.bump(ALLOW_DECISIONS);
        if verdict {
            STATS.bump(ALLOWED_TRUE);
        }

        if verdict {
            // Property 1 and property 2, from the document's own sets.
            assert!(
                allowed.iter().any(|n| n.contains(ip)),
                "{ip} was authorized by a manifest whose document lists {allowed:?} as \
                 allowed -- deny-by-default was bypassed"
            );
            assert!(
                !denied.iter().any(|n| n.contains(ip)),
                "{ip} was authorized despite matching the document's deny set {denied:?} -- \
                 deny must beat allow"
            );
            // Property 3, in the direction that matters: no reserved
            // address may ever be authorized, whatever the document says.
            assert!(
                !matches!(ip, IpAddr::V4(v4) if v4.is_loopback()
                    || v4.is_multicast()
                    || v4.is_broadcast()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || v4.octets()[0] == 0
                    || v4.octets()[0] >= 240),
                "{ip} is a reserved address and was authorized anyway"
            );
        }
    }

    STATS.tick();
});
