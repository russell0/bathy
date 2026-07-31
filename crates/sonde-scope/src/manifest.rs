use std::net::IpAddr;

use ipnet::IpNet;
use serde::Deserialize;
use sonde_types::ids::ScopeId;
use sonde_types::request::Budgets;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("malformed manifest: {0}")]
    Malformed(#[from] serde_json::Error),
    #[error("a manifest must list at least one allowed CIDR")]
    NoAllowedCidrs,
    #[error("invalid CIDR `{0}`")]
    BadCidr(String),
    /// `not_after` is not a parseable RFC 3339 instant. Rejected at load
    /// time rather than accepted-then-mis-compared: see the module-level
    /// note on `is_expired` for why this manifest must never load with an
    /// expiry nobody can evaluate correctly.
    #[error("`not_after` is not a valid RFC 3339 timestamp: `{0}`")]
    BadExpiry(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    id: ScopeId,
    description: String,
    not_after: String,
    allowed_cidrs: Vec<String>,
    #[serde(default)]
    denied_cidrs: Vec<String>,
    budget_ceiling: Budgets,
    /// Reserved for v0.2 detached-signature verification. Accepted and
    /// stored but NOT verified in v0.1. Reserving the field now means
    /// adding verification later is not a breaking schema change;
    /// accepting it silently would be dishonest, so `ScopeManifest::load`
    /// prints a warning to stderr when it is present and
    /// `signature_verified()` always returns `false` regardless of
    /// whether a signature is present or what it contains.
    #[serde(default)]
    signature: Option<String>,
}

/// An authorization to scan. Deny-by-default: an address is in scope only if
/// it matches the allow set, does not match the deny set, and is an ordinary
/// unicast address.
///
/// Three properties are absolute and enforced here regardless of what a
/// manifest document says:
///
/// 1. **Deny-by-default.** [`allows`](Self::allows) returns `true` only when
///    all three of allow-match, deny-non-match, and ordinary-unicast hold.
/// 2. **Deny beats allow, always.** The deny check runs before the allow
///    check and returns early; there is no "more specific prefix wins"
///    logic anywhere in this type.
/// 3. **Reserved ranges are refused regardless of what the manifest says.**
///    [`is_ordinary_unicast`] is consulted first, before either CIDR set,
///    and a manifest cannot construct a `ScopeManifest` that skips it --
///    there is no code path in this type that calls `.contains()` on
///    `allowed`/`denied` without going through `is_ordinary_unicast` first.
#[derive(Debug, Clone)]
pub struct ScopeManifest {
    id: ScopeId,
    description: String,
    not_after: OffsetDateTime,
    allowed: Vec<IpNet>,
    denied: Vec<IpNet>,
    ceiling: Budgets,
    /// Whether the loaded document carried a `signature` field at all.
    /// Deliberately *not* the signature's contents -- nothing downstream of
    /// `load` should ever be able to inspect or act on an unverified
    /// signature value, only know that one was present.
    had_signature: bool,
}

impl ScopeManifest {
    pub fn load(json: &str) -> Result<Self, ManifestError> {
        let raw: Raw = serde_json::from_str(json)?;
        if raw.allowed_cidrs.is_empty() {
            return Err(ManifestError::NoAllowedCidrs);
        }
        let parse = |v: &Vec<String>| -> Result<Vec<IpNet>, ManifestError> {
            v.iter()
                .map(|c| {
                    c.parse::<IpNet>()
                        .map_err(|_| ManifestError::BadCidr(c.clone()))
                })
                .collect()
        };
        let not_after = OffsetDateTime::parse(&raw.not_after, &Rfc3339)
            .map_err(|_| ManifestError::BadExpiry(raw.not_after.clone()))?;

        if raw.signature.is_some() {
            // Loud on purpose: a signature field that looks like it should
            // mean something but doesn't is more dangerous than no
            // signature at all, because a human skimming the manifest may
            // assume it was checked. `sonde-scope` has no logging
            // framework dependency (nor should the deny-by-default policy
            // path acquire one just for this), so this goes straight to
            // stderr rather than being silently swallowed.
            eprintln!(
                "WARNING: scope manifest {} carries a `signature` field; \
                 signatures are accepted and stored but NOT cryptographically \
                 verified in this version. Do not treat its presence as proof \
                 of authenticity.",
                raw.id
            );
        }

        Ok(Self {
            id: raw.id,
            description: raw.description,
            not_after,
            allowed: parse(&raw.allowed_cidrs)?,
            denied: parse(&raw.denied_cidrs)?,
            ceiling: raw.budget_ceiling,
            had_signature: raw.signature.is_some(),
        })
    }

    pub fn id(&self) -> ScopeId {
        self.id
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn ceiling(&self) -> Budgets {
        self.ceiling
    }

    /// Always `false` in v0.1: a manifest's `signature` field, if present,
    /// is stored (see [`had_signature`](Self::had_signature)) but never
    /// cryptographically checked. This method exists so a caller can ask
    /// the honest question ("was this verified?") and get an honest answer,
    /// rather than a caller mistaking "the field parsed" for "the signature
    /// was checked".
    pub fn signature_verified(&self) -> bool {
        false
    }

    /// Whether the loaded document carried a `signature` field, regardless
    /// of its contents. Does not imply the signature means anything --
    /// see [`signature_verified`](Self::signature_verified).
    pub fn had_signature(&self) -> bool {
        self.had_signature
    }

    /// `now_rfc3339` is parsed as a real RFC 3339 instant and compared
    /// against `not_after` as instants, not as strings.
    ///
    /// The original design compared `now_rfc3339 > self.not_after` as plain
    /// strings, which is correct only when both sides are fixed-width UTC
    /// with identical fractional-second precision and the same "Z" suffix.
    /// RFC 3339 does not guarantee that: `+hh:mm`/`-hh:mm` are valid
    /// alternatives to `Z`, and fractional seconds are optional and
    /// variable-width. A non-`Z` offset can also shift which *calendar
    /// date* appears in the string relative to the equivalent UTC instant,
    /// which is where lexicographic comparison actually breaks (a same-
    /// offset, same-date difference like `+00:00` vs `.000Z` alone does
    /// not, since the digits before the offset/fraction still compare
    /// correctly char-by-char). Concretely, verified empirically (see
    /// `is_expired_lexicographic_comparison_would_have_been_wrong` below):
    /// with `not_after = "2026-09-01T00:00:00Z"`, the string
    /// `"2026-08-31T20:00:00-08:00"` (which denotes `2026-09-01T04:00:00Z`
    /// -- four hours *after* `not_after`, genuinely expired) sorts
    /// lexicographically *before* `not_after`'s string, because its
    /// `2026-08-31` calendar-date text is smaller than `2026-09-01` even
    /// though the real instant is later. A naive `now_str > not_after_str`
    /// would report `false` (not expired) for an already-expired manifest
    /// -- the dangerous direction, since it would let scanning continue
    /// past the authorized window.
    ///
    /// This implementation parses both sides with `time`'s `Rfc3339`
    /// well-known format (which accepts any conformant encoding: either
    /// offset form, any fractional-second precision) and compares the
    /// resulting instants directly, so format differences that denote the
    /// same instant can never change the answer. `not_after` was already
    /// validated at [`load`](Self::load) time, so only `now_rfc3339` can
    /// fail to parse here; if it does, this fails closed -- a clock value
    /// this type cannot understand is treated as "the manifest has
    /// expired", never as "the manifest is still valid". Reject-non-conforming
    /// -formats-at-load-time was the other option the design considered and
    /// rejected: `now_rfc3339` is supplied per-call by a caller (e.g. an
    /// injected clock), not fixed once at construction, so there is no
    /// single load-time gate that could validate it once and be done.
    pub fn is_expired(&self, now_rfc3339: &str) -> bool {
        match OffsetDateTime::parse(now_rfc3339, &Rfc3339) {
            Ok(now) => now > self.not_after,
            Err(_) => true,
        }
    }

    pub fn allows(&self, ip: IpAddr) -> bool {
        // Property 3: reserved ranges are refused before either CIDR set is
        // even consulted. No manifest, however permissive, can route around
        // this check.
        if !is_ordinary_unicast(ip) {
            return false;
        }
        // Property 2: deny beats allow. This check runs, and can return
        // `false`, before the allow check ever executes.
        if self.denied.iter().any(|n| n.contains(&ip)) {
            return false;
        }
        // Property 1: deny-by-default. Only an explicit allow-set match
        // reaches `true`.
        self.allowed.iter().any(|n| n.contains(&ip))
    }
}

/// Addresses that are never legitimate scan targets, regardless of what a
/// manifest says. A manifest is written by a human and can be wrong; these
/// categories cause collateral traffic or self-scans and are refused
/// outright.
///
/// # IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`)
///
/// Refused outright, before any of the native IPv6 checks below run, rather
/// than being unwrapped and evaluated as the IPv4 address they denote. This
/// is a deliberate decision, not an oversight:
///
/// - `Ipv6Addr::is_loopback`, `is_multicast`, `is_unspecified`, and the
///   `fe80::/10` mask below all key off the *IPv6* bit pattern. None of them
///   recognize `::ffff:127.0.0.1` as loopback, `::ffff:224.0.0.1` as
///   multicast, or `::ffff:169.254.1.1` as link-local, because in raw IPv6
///   terms none of those bit patterns match `::1`, `ff00::/8`, or
///   `fe80::/10`. Left unhandled, a manifest that permissively allows an
///   IPv6 range (the IPv6 analogue of the `0.0.0.0/0` case AC-1.25 already
///   covers for IPv4) would let a v4-mapped reserved address slip past this
///   backstop entirely -- the exact class of hole property 3 exists to
///   close.
/// - Unwrapping and re-evaluating as IPv4 was the alternative considered.
///   It was rejected as strictly more code on the safety boundary for no
///   safety benefit: an operator who wants to authorize `10.30.0.0/24`
///   writes that CIDR, not `::ffff:10.30.0.0/120`; a v4-mapped address
///   reaching `allows()` at all is already anomalous input this codebase
///   does not need to make meaningful. Refusing it outright is the
///   conservative reading of "when unsure, refuse" -- it cannot be
///   mistakenly authorized under any manifest, ever, which unwrap-and-
///   reevaluate cannot promise (it would still depend on the allow/deny
///   CIDR sets being IPv4-shaped and correct).
fn is_ordinary_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.octets()[0] == 0)
        }
        IpAddr::V6(v6) => {
            if v6.to_ipv4_mapped().is_some() {
                return false;
            }
            !(v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                // link-local fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    const MANIFEST: &str = r#"{
      "id": "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV",
      "description": "Lab subnet, August 2026 inventory",
      "not_after": "2026-09-01T00:00:00.000Z",
      "allowed_cidrs": ["10.30.0.0/24"],
      "denied_cidrs": ["10.30.0.1/32"],
      "budget_ceiling": {
        "maximum_packets": 1000000,
        "maximum_runtime_seconds": 3600,
        "maximum_packets_per_second": 20000
      }
    }"#;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn allows_address_inside_allow_set() {
        let m = ScopeManifest::load(MANIFEST).unwrap();
        assert!(m.allows(ip("10.30.0.42")));
    }

    #[test]
    fn deny_list_overrides_allow_list() {
        let m = ScopeManifest::load(MANIFEST).unwrap();
        assert!(!m.allows(ip("10.30.0.1")));
    }

    #[test]
    fn address_outside_allow_set_is_denied() {
        let m = ScopeManifest::load(MANIFEST).unwrap();
        assert!(!m.allows(ip("10.31.0.1")));
        assert!(!m.allows(ip("8.8.8.8")));
    }

    #[test]
    fn broadcast_multicast_and_loopback_are_never_allowed_even_if_listed() {
        let permissive = MANIFEST.replace(r#"["10.30.0.0/24"]"#, r#"["0.0.0.0/0"]"#);
        let m = ScopeManifest::load(&permissive).unwrap();
        assert!(!m.allows(ip("127.0.0.1")), "loopback");
        assert!(!m.allows(ip("224.0.0.1")), "multicast");
        assert!(!m.allows(ip("255.255.255.255")), "broadcast");
        assert!(!m.allows(ip("169.254.1.1")), "link-local");
        assert!(m.allows(ip("10.30.0.42")), "ordinary unicast still allowed");
    }

    #[test]
    fn expiry_is_enforced() {
        let m = ScopeManifest::load(MANIFEST).unwrap();
        assert!(!m.is_expired("2026-08-15T00:00:00.000Z"));
        assert!(m.is_expired("2026-09-02T00:00:00.000Z"));
    }

    #[test]
    fn manifest_with_no_allowed_cidrs_is_rejected() {
        let empty = MANIFEST.replace(r#"["10.30.0.0/24"]"#, "[]");
        assert!(ScopeManifest::load(&empty).is_err());
    }

    // --- AC-1.28: IPv6 loopback, multicast, unspecified, and fe80::/10
    // link-local are refused even when the manifest permissively allows
    // ::/0. Mirrors `broadcast_multicast_and_loopback_are_never_allowed_
    // even_if_listed` above but for the IPv6-native reserved ranges; the
    // brief's own Step 1 test block never exercises IPv6 at all, so this
    // (and the boundary tests below) are the tests that actually prove
    // AC-1.28. ---

    fn permissive_ipv6_manifest() -> ScopeManifest {
        let permissive = MANIFEST.replace(r#"["10.30.0.0/24"]"#, r#"["::/0"]"#);
        ScopeManifest::load(&permissive).unwrap()
    }

    #[test]
    fn ipv6_reserved_ranges_are_never_allowed_even_if_listed() {
        let m = permissive_ipv6_manifest();
        assert!(!m.allows(ip("::1")), "loopback");
        assert!(!m.allows(ip("ff02::1")), "multicast");
        assert!(!m.allows(ip("::")), "unspecified");
        assert!(!m.allows(ip("fe80::1")), "link-local");
        assert!(
            m.allows(ip("2001:db8::1")),
            "ordinary v6 unicast still allowed"
        );
    }

    // The dispatch's explicit ask: prove the `(segments()[0] & 0xffc0) ==
    // 0xfe80` mask is right at its boundaries, not just "some address deep
    // inside fe80::/10 is denied". `fe80::` is the first address in range;
    // `febf:ffff:...` is the last (10-bit prefix, so the top 10 bits must
    // match `fe80`'s top 10 bits -- 0xfebf shares them, 0xfec0 does not);
    // `fec0::` is one step past the range and must NOT be caught by this
    // check (it used to denote deprecated IPv6 site-local addresses, which
    // is a different, non-reserved category as far as this function is
    // concerned).
    #[test]
    fn fe80_slash_10_boundary_is_exact() {
        let m = permissive_ipv6_manifest();
        assert!(
            !m.allows(ip("fe80::")),
            "fe80:: is the first address in fe80::/10"
        );
        assert!(
            !m.allows(ip("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff")),
            "febf:ffff:... is the last address in fe80::/10"
        );
        assert!(
            m.allows(ip("fec0::")),
            "fec0:: is one step past fe80::/10 and must not be caught by the mask"
        );
    }

    // --- IPv4-mapped IPv6 addresses: the decision documented on
    // `is_ordinary_unicast` above. `::ffff:127.0.0.1` etc. must be refused
    // outright, even under a manifest permissive enough to allow both
    // `0.0.0.0/0` and `::/0` -- proving this isn't rescued by the allow set
    // being IPv4-shaped and simply failing to match by family. ---

    fn permissive_dual_stack_manifest() -> ScopeManifest {
        let permissive = MANIFEST.replace(r#"["10.30.0.0/24"]"#, r#"["0.0.0.0/0", "::/0"]"#);
        ScopeManifest::load(&permissive).unwrap()
    }

    #[test]
    fn ipv4_mapped_ipv6_addresses_are_refused_outright() {
        let m = permissive_dual_stack_manifest();
        assert!(
            !m.allows(ip("::ffff:127.0.0.1")),
            "v4-mapped loopback must be refused"
        );
        assert!(
            !m.allows(ip("::ffff:224.0.0.1")),
            "v4-mapped multicast must be refused"
        );
        assert!(
            !m.allows(ip("::ffff:10.30.0.42")),
            "v4-mapped address inside the ordinary allow range must still be \
             refused: mapped addresses are refused outright, not evaluated \
             as their embedded IPv4 address"
        );
        // Sanity check the fixture actually is dual-stack-permissive, so
        // the assertions above are proving the mapped-address guard and not
        // just an accidentally-too-narrow manifest.
        assert!(m.allows(ip("10.30.0.42")), "plain v4 unicast still allowed");
        assert!(
            m.allows(ip("2001:db8::1")),
            "plain v6 unicast still allowed"
        );
    }

    // --- Expiry comparison: differently-formatted-but-equal-instant RFC
    // 3339 strings must compare correctly regardless of offset notation or
    // fractional-second precision. See the doc comment on `is_expired` for
    // the exact, empirically-verified case where a naive lexicographic `>`
    // on the raw strings gets this wrong (a non-`Z` offset that shifts the
    // *calendar date* in the string relative to the equivalent UTC
    // instant) -- reproduced directly as its own test below, not just
    // asserted in prose. ---

    #[test]
    fn is_expired_treats_equivalent_offset_and_zulu_forms_as_equal_instants() {
        let m = ScopeManifest::load(MANIFEST).unwrap(); // not_after: 2026-09-01T00:00:00.000Z
        // Same instant as not_after, spelled with an explicit +00:00 offset
        // and no fractional seconds. Equal instants are not "after", so
        // must not be expired.
        assert!(!m.is_expired("2026-09-01T00:00:00+00:00"));
        // One second after not_after, same alternate formatting: must be
        // expired.
        assert!(m.is_expired("2026-09-01T00:00:01+00:00"));
        // A non-UTC (+01:00) offset denoting the instant one second
        // *before* not_after (local 00:59:59+01:00 == 2026-08-31T23:59:59Z):
        // must not be expired.
        assert!(!m.is_expired("2026-09-01T00:59:59+01:00"));
        // Same non-UTC offset, denoting exactly not_after itself
        // (local 01:00:00+01:00 == 2026-09-01T00:00:00Z): equal instants are
        // not "after", so must not be expired either.
        assert!(!m.is_expired("2026-09-01T01:00:00.000+01:00"));
    }

    // The concrete, empirically-verified case (see the doc comment on
    // `is_expired`) where naive lexicographic string comparison gets the
    // *dangerous* direction wrong: a manifest that is genuinely expired is
    // reported as not-expired, which would let scanning continue past the
    // authorized window. `-08:00` pushes the real UTC instant to
    // `2026-09-01T04:00:00Z` -- four hours after `not_after` -- while the
    // string's own calendar-date text (`2026-08-31`) sorts *before*
    // `not_after`'s (`2026-09-01`). Verified with plain Python string
    // comparison before writing this test: `"2026-08-31T20:00:00-08:00" >
    // "2026-09-01T00:00:00Z"` is `False` under naive lexicographic `>`,
    // which is backwards -- the real-time answer is `True` (expired).
    #[test]
    fn is_expired_lexicographic_comparison_would_have_been_wrong() {
        let not_after_str = "2026-09-01T00:00:00Z";
        let now_str = "2026-08-31T20:00:00-08:00";

        // Self-contained proof that the brief's original `now_rfc3339 >
        // self.not_after` (plain `&str` `>`) really would have gotten this
        // wrong, independent of and in addition to exercising this crate's
        // actual (correct) implementation below. If a future refactor ever
        // reintroduces a plain string comparison, this assertion documents
        // exactly why that must not happen -- it is not testing
        // `ScopeManifest` at all, just the raw claim.
        assert!(
            !(now_str > not_after_str),
            "plain string comparison must say \"not after\" here (that's \
             the bug): {now_str:?} > {not_after_str:?} was {}",
            now_str > not_after_str
        );

        // The actual behavior this crate must have: `now_str` denotes
        // 2026-09-01T04:00:00Z, four hours after not_after, and must be
        // reported as expired despite the naive comparison above saying
        // otherwise.
        let m = ScopeManifest::load(MANIFEST).unwrap(); // not_after: 2026-09-01T00:00:00.000Z
        assert!(
            m.is_expired(now_str),
            "this instant is 2026-09-01T04:00:00Z, four hours after \
             not_after, and must be reported as expired even though its \
             own calendar-date text sorts before not_after's"
        );
        // And the instant one second before not_after itself, in the same
        // -08:00 offset notation, must not be expired -- proving this
        // isn't just "always expired regardless of the offset used".
        assert!(!m.is_expired("2026-08-31T15:59:59-08:00"));
    }

    #[test]
    fn is_expired_fails_closed_on_an_unparseable_now() {
        let m = ScopeManifest::load(MANIFEST).unwrap();
        // Not RFC 3339 at all. Per "when unsure, refuse": an input this
        // type cannot understand must never be treated as "not expired".
        assert!(m.is_expired("not a timestamp"));
        assert!(m.is_expired(""));
    }

    #[test]
    fn manifest_with_unparseable_not_after_is_rejected_at_load_time() {
        let bad = MANIFEST.replace("2026-09-01T00:00:00.000Z", "not-a-timestamp");
        let err = ScopeManifest::load(&bad).unwrap_err();
        assert!(matches!(err, ManifestError::BadExpiry(_)), "got {err:?}");
    }

    // --- The signature field: accepted and stored, never trusted. ---

    #[test]
    fn signature_verified_is_always_false_with_no_signature_present() {
        let m = ScopeManifest::load(MANIFEST).unwrap();
        assert!(!m.had_signature());
        assert!(!m.signature_verified());
    }

    #[test]
    fn signature_verified_is_always_false_even_when_a_signature_is_present() {
        let with_sig = MANIFEST.replace(
            r#""budget_ceiling""#,
            r#""signature": "deadbeef", "budget_ceiling""#,
        );
        let m = ScopeManifest::load(&with_sig).unwrap();
        assert!(m.had_signature());
        assert!(
            !m.signature_verified(),
            "a stored signature must never be reported as verified"
        );
    }

    #[test]
    fn unknown_fields_are_still_rejected() {
        let extra = MANIFEST.replace(r#""description""#, r#""stealth_mode": true, "description""#);
        assert!(ScopeManifest::load(&extra).is_err());
    }

    #[test]
    fn a_bad_cidr_is_rejected_with_the_offending_string() {
        let bad = MANIFEST.replace(r#"["10.30.0.0/24"]"#, r#"["not-a-cidr"]"#);
        let err = ScopeManifest::load(&bad).unwrap_err();
        assert!(
            matches!(&err, ManifestError::BadCidr(c) if c == "not-a-cidr"),
            "got {err:?}"
        );
    }

    // --- Property test: the single most important invariant this crate
    // provides. Beyond the brief's unit tests (which each try one or two
    // fixed addresses), generate addresses across the whole IPv4 space and
    // assert `allows()` never permits anything outside the allow set, never
    // permits a denied address, and never permits a reserved address --
    // regardless of what the manifest's CIDRs say. Task 8 adds an
    // equivalent property test over `evaluate()`; this one is scoped to
    // `allows()` itself, which is the function every other property in the
    // system is built on top of. ---

    proptest::proptest! {
        #[test]
        fn allows_never_permits_anything_outside_the_allow_set(
            octets in proptest::collection::vec(0u8..=255, 4)
        ) {
            let m = ScopeManifest::load(MANIFEST).unwrap(); // allows 10.30.0.0/24, denies 10.30.0.1/32
            let addr = IpAddr::V4(std::net::Ipv4Addr::new(
                octets[0], octets[1], octets[2], octets[3],
            ));
            let decided_allow = m.allows(addr);

            let in_allow_cidr =
                octets[0] == 10 && octets[1] == 30 && octets[2] == 0;
            let in_deny_cidr = in_allow_cidr && octets[3] == 1;
            let is_reserved = !is_ordinary_unicast(addr);

            if decided_allow {
                proptest::prop_assert!(in_allow_cidr, "{} was allowed but is outside 10.30.0.0/24", addr);
                proptest::prop_assert!(!in_deny_cidr, "{} was allowed but matches the deny set 10.30.0.1/32", addr);
                proptest::prop_assert!(!is_reserved, "{} was allowed but is a reserved-range address", addr);
            }
            // The converse also matters: nothing legitimately in-scope is
            // ever refused for the wrong reason (deny/reserved never
            // over-fire on an address that is neither denied nor reserved).
            if in_allow_cidr && !in_deny_cidr && !is_reserved {
                proptest::prop_assert!(decided_allow, "{} is inside the allow set, not denied, and ordinary, but was refused", addr);
            }
        }

        /// A second, manifest-permissive-to-everything property: with
        /// `0.0.0.0/0` allowed and nothing denied, `allows()` must still
        /// refuse exactly the reserved-range addresses and nothing else --
        /// i.e. `allows(ip) == is_ordinary_unicast(ip)` for every generated
        /// IPv4 address. This isolates property 3 (the reserved-range
        /// backstop) from properties 1 and 2, which the test above already
        /// covers.
        #[test]
        fn permissive_manifest_allows_exactly_the_non_reserved_addresses(
            octets in proptest::collection::vec(0u8..=255, 4)
        ) {
            let permissive = MANIFEST.replace(r#"["10.30.0.0/24"]"#, r#"["0.0.0.0/0"]"#)
                .replace(r#""denied_cidrs": ["10.30.0.1/32"],"#, "");
            let m = ScopeManifest::load(&permissive).unwrap();
            let addr = IpAddr::V4(std::net::Ipv4Addr::new(
                octets[0], octets[1], octets[2], octets[3],
            ));
            proptest::prop_assert_eq!(m.allows(addr), is_ordinary_unicast(addr), "addr = {}", addr);
        }
    }
}
