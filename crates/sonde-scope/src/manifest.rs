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
        let allowed = parse(&raw.allowed_cidrs)?;
        let denied = parse(&raw.denied_cidrs)?;

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

        // Fix round 3: IPv6 scanning is out of scope for v0.1 (see
        // `is_ordinary_unicast`'s doc comment and the Gap Register in
        // docs/superpowers/plans/2026-07-31-sonde-v0.1-overview.md), so
        // `allows()` refuses every IPv6 address no matter what this
        // manifest says -- an IPv6 entry in `allowed_cidrs` can never
        // match anything. Warn rather than fail: the manifest may also
        // carry perfectly valid IPv4 CIDRs, and an operator drafting a
        // manifest ahead of v0.2 should not be blocked from doing so.
        // Staying silent would repeat the exact failure mode the loud
        // signature warning above exists to avoid -- an agent that thinks
        // it authorized something and gets no error, when in fact the
        // entry can never take effect.
        let ipv6_allow_entries: Vec<&str> = raw
            .allowed_cidrs
            .iter()
            .zip(allowed.iter())
            .filter(|(_, net)| matches!(net, IpNet::V6(_)))
            .map(|(s, _)| s.as_str())
            .collect();
        if !ipv6_allow_entries.is_empty() {
            eprintln!(
                "WARNING: scope manifest {} lists IPv6 CIDR(s) in \
                 allowed_cidrs ({}); IPv6 scanning is unsupported in v0.1 \
                 and every IPv6 address is refused regardless of this \
                 manifest -- these entries can never match.",
                raw.id,
                ipv6_allow_entries.join(", ")
            );
        }

        Ok(Self {
            id: raw.id,
            description: raw.description,
            not_after,
            allowed,
            denied,
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
/// # The IPv6 arm: a v0.1 scope decision, not a reserved-range check
///
/// Three fix rounds enumerated IPv4-in-IPv6 embedding and transition
/// prefixes: four in round 1, a fifth (IPv4-mapped) already present, a
/// sixth (IPv4-translated) and a seventh (Teredo, added proactively) in
/// round 2, and an eighth (ISATAP) found by round 2's own re-review despite
/// an explicit warning that the count was "a floor, not a proof of
/// completeness". Three rounds, three closed enumerations, three
/// subsequent findings -- that is a signal about the *approach*, not about
/// any round's thoroughness (see the task report's fix-round-3 section for
/// the controller's reasoning in full).
///
/// The actual fix follows from a scope decision made independently of this
/// bug hunt: **`docs/superpowers/plans/2026-07-31-sonde-v0.1-overview.md`'s
/// Gap Register states IPv6 scanning is out of scope for v0.1.** This
/// crate had been hardening a code path the product does not ship. Given
/// that, the IPv6 arm below refuses **every IPv6 address unconditionally**,
/// as its first and only action -- not a narrower reserved-range check, a
/// blanket refusal. This is immune to every embedding or transition scheme,
/// enumerated below or not, which is exactly the property three rounds of
/// enumerate-and-patch could not achieve. It also satisfies AC-1.28 more
/// strongly than literally required (loopback/multicast/unspecified/
/// `fe80::/10` refused): every IPv6 address is refused, reserved or not.
///
/// [`ipv6_is_ordinary_by_prefix_rules`] below holds the full prefix-guard
/// logic developed across all three rounds, including the eighth (ISATAP)
/// guard added this round. It is **not called from this function in
/// v0.1** -- it is parked, `#[allow(dead_code)]`, unreachable in the live
/// path, and exists solely as the documented starting point for v0.2 when
/// IPv6 scanning ships (at which point the `IpAddr::V6` arm below should
/// call it instead of returning `false`). See that function's own doc
/// comment for the full prefix table, the RFCs swept, what was
/// deliberately excluded and why, and the mechanisms (NAT64/SIIT
/// Network-Specific Prefix, 6rd) that remain structurally unguardable by
/// any fixed mask.
fn is_ordinary_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.octets()[0] == 0
                // 240.0.0.0/4: IANA-reserved "martian" space (includes the
                // 255.255.255.255 limited-broadcast address already caught
                // above by `is_broadcast`; both checks are kept because they
                // document different intents -- `is_broadcast` documents
                // "this is *the* broadcast address", this documents "this
                // whole /4 is reserved". `Ipv4Addr::is_reserved()` exists in
                // std but is nightly-only as of this MSRV, hence the
                // hand-rolled range check.
                || v4.octets()[0] >= 240)
        }
        IpAddr::V6(_) => {
            // v0.1 SCOPE DECISION -- see this function's doc comment above.
            // IPv6 scanning is not supported in this release, so no IPv6
            // address of any kind is ever a valid scan target. This
            // unconditional `false` is the only thing standing between an
            // IPv6 embedding/transition bypass and the outside world right
            // now -- see the task report's fix-round-3 mutation evidence,
            // which proves by direct experiment that `ipv6_is_ordinary_by_
            // prefix_rules` below provides zero protection on its own: with
            // this `false` mutated away, both an ordinary IPv6 address and
            // an ISATAP-embedded-loopback address become reachable again,
            // with nothing else catching either.
            false
        }
    }
}

/// The full IPv6 reserved-range and IPv4-embedding/transition-prefix guard
/// logic developed across fix rounds 0 through 3. **Not called by
/// [`is_ordinary_unicast`] in v0.1** -- see that function's doc comment for
/// why. Kept intact, not deleted, as the documented starting point for
/// v0.2: when IPv6 scanning ships, `is_ordinary_unicast`'s `IpAddr::V6` arm
/// should call this function instead of returning `false` unconditionally.
/// `#[allow(dead_code)]` because nothing outside this module's tests calls
/// it in v0.1; do not remove that attribute by deleting the function
/// instead -- the research stays, it just is not live.
///
/// # Eight standardized IPv4-in-IPv6 embedding and transition prefixes
///
/// | Prefix | Scheme | RFC |
/// |---|---|---|
/// | `::/96` | IPv4-compatible (deprecated) | 4291 §2.5.5.1 |
/// | `::ffff:0:0/96` | IPv4-mapped | 4291 §2.5.5.2 |
/// | `::ffff:0:0:0/96` | IPv4-translated (SIIT) | 2765 §3.5, retained by 6145 |
/// | `64:ff9b::/96` | NAT64 well-known prefix | 6052 |
/// | `64:ff9b:1::/48` | NAT64 local-use prefix | 8215 |
/// | `2002::/16` | 6to4 | 3056 |
/// | `2001::/32` | Teredo (embeds an *obfuscated* IPv4 address/port) | 4380, updated by 8190 |
/// | interface ID `0000:5EFE:*` or `0200:5EFE:*`, any prefix | ISATAP | 5214 §6.1 |
///
/// This count (eight) is still **a floor, not a proof of completeness** --
/// each of the first seven was found by a systematic sweep of RFC 4291,
/// RFC 6052/8215, RFC 2765/6145, RFC 3056, RFC 4380, and the IANA IPv6
/// Special-Purpose Address Registry (see the task report for the full
/// 25-row registry table and every excluded block's reasoning), and that
/// same sweep's own re-review still found an eighth (ISATAP) it had missed
/// -- and had actively mis-reasoned about, see below. Whatever number is
/// written here next is not guaranteed to be the last one either; that is
/// the entire reason this logic is parked behind a blanket refusal rather
/// than trusted as the live defense.
///
/// ISATAP is structurally different from the other seven: it has no fixed
/// global *prefix* at all. The embedded IPv4 address instead sits in the
/// low 32 bits of the interface identifier (segments 6-7), immediately
/// preceded by a fixed 32-bit marker at segments 4-5 (`0000:5EFE` for a
/// publicly-routable embedded address, `0200:5EFE` -- the "locally
/// administered" bit set -- for a private/martian one), riding on *any*
/// unicast prefix the deploying site chooses for segments 0-3. The guard
/// below is therefore independent of segments 0-3, unlike every other
/// guard in this function, which all key off fixed high-order bits. A
/// prior sweep (fix round 2) excluded ISATAP with the reasoning "not an
/// IANA-reserved bit pattern, just a convention" -- that reasoning was
/// factually wrong and is not repeated here: `00-00-5E` is IANA's own
/// registered OUI (Organizationally Unique Identifier), assigned
/// specifically for this use by RFC 5214 itself. It is guardable, and is
/// guarded, by the differently-shaped (suffix-anchored, not prefix-
/// anchored) check below. Segment positions verified against a real
/// `"2001:db8::5efe:7f00:1".parse::<Ipv6Addr>().segments()` probe before
/// writing the guard, not derived by reasoning alone -- see the task
/// report for the probe output.
///
/// # Known, structural limitations (not fixable by adding more guards here)
///
/// - **NAT64/SIIT "Network-Specific Prefix"** (RFC 6052 §3.1, and the
///   corresponding option in RFC 6145): an operator may choose *any* of
///   their own globally-routed prefixes as a translation prefix instead of
///   the fixed Well-Known Prefix or the fixed IPv4-translated format. Such
///   an address is bit-for-bit indistinguishable from ordinary global
///   unicast -- no fixed mask could ever catch it without external
///   configuration input this function does not have and a scope manifest
///   does not currently provide a place to declare.
/// - **6rd** (IPv6 Rapid Deployment, RFC 5969): the 6to4-like mechanism an
///   ISP runs using its *own* chosen IPv6 prefix (the "6rd domain prefix")
///   instead of 6to4's fixed `2002::/16`. Same class of limitation as NAT64
///   NSP, for the same reason: no fixed signature exists to match against,
///   by design of the mechanism itself. Named explicitly here (a prior
///   sweep round omitted it despite being asked to check for it) so its
///   absence from the table above reads as a documented, deliberate
///   exclusion rather than a gap nobody looked for.
#[allow(dead_code)]
fn ipv6_is_ordinary_by_prefix_rules(v6: std::net::Ipv6Addr) -> bool {
    let s = v6.segments();
    !(v6.is_loopback()
        || v6.is_multicast()
        || v6.is_unspecified()
        // link-local fe80::/10
        || (s[0] & 0xffc0) == 0xfe80
        // ::/96 -- IPv4-compatible (deprecated, RFC 4291 §2.5.5.1): top 96
        // bits (segments 0..=5) all zero, low 32 bits free.
        || (s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0)
        // ::ffff:0:0/96 -- IPv4-mapped (RFC 4291 §2.5.5.2).
        || v6.to_ipv4_mapped().is_some()
        // ::ffff:0:0:0/96 -- IPv4-translated (SIIT, RFC 2765 §3.5, retained
        // by RFC 6145). One segment offset from the mapped form above:
        // 0xffff lives in segment 4, not segment 5.
        || (s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0xffff && s[5] == 0)
        // 64:ff9b::/96 -- NAT64 well-known prefix (RFC 6052).
        || (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0)
        // 64:ff9b:1::/48 -- NAT64 local-use prefix (RFC 8215).
        || (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001)
        // 2002::/16 -- 6to4 (RFC 3056).
        || s[0] == 0x2002
        // 2001::/32 -- Teredo (RFC 4380, updated by RFC 8190). Refuses the
        // whole prefix without attempting to decode the obfuscated payload.
        || (s[0] == 0x2001 && s[1] == 0)
        // ISATAP (RFC 5214 §6.1): fixed marker at segments 4-5, independent
        // of segments 0-3. See this function's doc comment above.
        || (s[4] == 0 && s[5] == 0x5efe)
        || (s[4] == 0x0200 && s[5] == 0x5efe))
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

    /// Parses directly to `Ipv6Addr` (not `IpAddr`), for calling the parked
    /// [`ipv6_is_ordinary_by_prefix_rules`] directly -- used wherever a
    /// pre-fix-round-3 test asserted a boundary address was still *allowed*
    /// through the public `allows()` API. Under the v0.1 blanket IPv6
    /// refusal, `allows()` refuses every IPv6 address regardless of prefix,
    /// so those assertions no longer hold through the public API; the
    /// mask-precision claim they were proving is still real and still
    /// tested, just against the parked function directly. See the
    /// "Fix round 3" comment block below.
    fn ipv6(s: &str) -> std::net::Ipv6Addr {
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
        // Fix round 3: all four assertions below still pass, now via the
        // v0.1 blanket IPv6 refusal (see `is_ordinary_unicast`'s doc
        // comment) rather than the individual is_loopback/is_multicast/
        // is_unspecified/fe80-mask checks each was originally written to
        // prove -- those checks still exist, parked and unreachable, in
        // `ipv6_is_ordinary_by_prefix_rules`. The fifth original assertion
        // here ("ordinary v6 unicast still allowed") no longer holds under
        // the blanket policy; it was moved to its own dedicated test below,
        // `ordinary_global_unicast_ipv6_is_refused_because_ipv6_scanning_is_out_of_scope_for_v0_1`,
        // which states the v0.1 reasoning explicitly rather than silently
        // dropping the coverage.
        let m = permissive_ipv6_manifest();
        assert!(!m.allows(ip("::1")), "loopback");
        assert!(!m.allows(ip("ff02::1")), "multicast");
        assert!(!m.allows(ip("::")), "unspecified");
        assert!(!m.allows(ip("fe80::1")), "link-local");
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
        // Fix round 3: under the v0.1 blanket IPv6 refusal, `m.allows()`
        // refuses fec0:: too (like every IPv6 address), so this boundary
        // can no longer be proven through the public API. The
        // mask-precision claim itself is still real and still worth
        // proving -- tested directly against the parked v0.2 guard
        // function instead.
        assert!(
            ipv6_is_ordinary_by_prefix_rules(ipv6("fec0::")),
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
        // Sanity check the fixture actually is dual-stack-permissive for
        // IPv4, so the assertions above are proving the mapped-address
        // guard and not just an accidentally-too-narrow manifest.
        assert!(m.allows(ip("10.30.0.42")), "plain v4 unicast still allowed");
        // Fix round 3: the fixture's "::/0" allow entry can no longer make
        // any IPv6 address allowed -- the v0.1 blanket refusal (see
        // `is_ordinary_unicast`) refuses every IPv6 address regardless of
        // the manifest. The original "plain v6 unicast still allowed"
        // assertion here was removed rather than inverted in place, since
        // its removal is itself the interesting fact: see the dedicated
        // test `ordinary_global_unicast_ipv6_is_refused_because_ipv6_scanning_is_out_of_scope_for_v0_1`
        // below for where that coverage now lives, stated explicitly.
    }

    // --- Fix round 1 (CRITICAL): the other four IPv4-in-IPv6 embedding
    // schemes. The reviewer's direct probe against a `::/0`-allowing
    // manifest confirmed `allows()` returned `true` for every row below --
    // a false allow, the dangerous direction. Each is a reserved IPv4
    // address (loopback or multicast) wearing a different IPv6 dress; see
    // the table in `is_ordinary_unicast`'s doc comment for the RFC behind
    // each prefix. ---

    fn ip6_addr(segments: [u16; 8]) -> std::net::Ipv6Addr {
        std::net::Ipv6Addr::from(segments)
    }

    // Fix round 3: every "boundary must still be allowed" assertion in the
    // four tests below was rewritten to call `ipv6_is_ordinary_by_prefix_
    // rules` directly instead of `m.allows()`, for the same reason given on
    // `fe80_slash_10_boundary_is_exact` above -- the v0.1 blanket IPv6
    // refusal means `m.allows()` refuses every boundary address too, for a
    // reason unrelated to prefix-mask precision. Each "must be refused"
    // assertion is untouched and still goes through the real `m.allows()`.

    #[test]
    fn ipv4_compatible_ipv6_addresses_are_refused_outright() {
        let m = permissive_dual_stack_manifest();
        // ::7f00:1 == ::127.0.0.1, the IPv4-compatible form of loopback.
        // Reviewer's reproduction case.
        assert!(
            !m.allows(ip("::7f00:1")),
            "IPv4-compatible loopback (::127.0.0.1) must be refused"
        );
        // Boundary: one bit outside ::/96 (segment 5, the last of the top
        // 96 bits, set instead of zero) must NOT be caught by this rule.
        assert!(
            ipv6_is_ordinary_by_prefix_rules(ip6_addr([0, 0, 0, 0, 0, 1, 0x7f00, 1])),
            "an address one bit outside ::/96 must not be caught by the \
             IPv4-compatible guard"
        );
    }

    #[test]
    fn nat64_well_known_prefix_addresses_are_refused_outright() {
        let m = permissive_dual_stack_manifest();
        // 64:ff9b::7f00:1 == NAT64-embedded 127.0.0.1. Reviewer's
        // reproduction case.
        assert!(
            !m.allows(ip("64:ff9b::7f00:1")),
            "NAT64-embedded loopback must be refused"
        );
        // 64:ff9b::e000:1 == NAT64-embedded 224.0.0.1 (multicast).
        // Reviewer's reproduction case.
        assert!(
            !m.allows(ip("64:ff9b::e000:1")),
            "NAT64-embedded multicast must be refused"
        );
        // Boundary: one bit outside 64:ff9b::/96 must not be caught.
        assert!(
            ipv6_is_ordinary_by_prefix_rules(ip6_addr([0x0064, 0xff9b, 0, 0, 0, 1, 0x7f00, 1])),
            "an address one bit outside 64:ff9b::/96 must not be caught by \
             the NAT64 well-known-prefix guard"
        );
    }

    #[test]
    fn nat64_local_use_prefix_addresses_are_refused_outright() {
        let m = permissive_dual_stack_manifest();
        assert!(
            !m.allows(ip("64:ff9b:1::7f00:1")),
            "NAT64 local-use-prefix-embedded loopback must be refused"
        );
        // Boundary: segment 2 one past the /48 (0x0001 -> 0x0002) must not
        // be caught by this rule. It also must not be caught by the
        // well-known-prefix rule above, since that one requires segment 2
        // to be exactly zero.
        assert!(
            ipv6_is_ordinary_by_prefix_rules(ipv6("64:ff9b:2::1")),
            "an address one step past 64:ff9b:1::/48 must not be caught by \
             the NAT64 local-use-prefix guard"
        );
    }

    #[test]
    fn six_to_four_addresses_are_refused_outright() {
        let m = permissive_dual_stack_manifest();
        // 2002:7f00:1::1 == 6to4-embedded 127.0.0.1 (the 6to4 address for
        // 127.0.0.1 encodes the IPv4 address in segments 1-2). Reviewer's
        // reproduction case.
        assert!(
            !m.allows(ip("2002:7f00:1::1")),
            "6to4-embedded loopback must be refused"
        );
        // Boundary given directly in the fix instructions: 2003::1 (one
        // step past 2002::/16) must not be caught by the 6to4 guard.
        assert!(
            ipv6_is_ordinary_by_prefix_rules(ipv6("2003::1")),
            "2003::1 is one step past 2002::/16 and must not be caught by \
             the 6to4 guard"
        );
    }

    // --- Fix round 2 (CRITICAL): the sixth IPv4-in-IPv6 embedding scheme,
    // found by a re-review after round 1 shipped -- IPv4-translated
    // addresses, ::ffff:0:0:0/96 (RFC 2765 SIIT, retained by RFC 6145).
    // Genuinely distinct from IPv4-mapped by a one-segment offset: 0xffff
    // sits in segment 4 here, not segment 5, so `to_ipv4_mapped()` legitimately
    // returns `None` for these addresses and none of the round-1 guards
    // matched either. Segment layout confirmed via a real parse-and-inspect
    // probe before writing the guard (see the task report for the raw
    // output), per the reviewer's explicit instruction not to reason about
    // the offset from memory alone. ---

    #[test]
    fn ipv4_translated_ipv6_addresses_are_refused_outright() {
        let m = permissive_dual_stack_manifest();
        // ::ffff:0:127.0.0.1 -- the reviewer's exact reproduction case.
        // segments = [0, 0, 0, 0, 0xffff, 0, 0x7f00, 1] (confirmed by probe).
        assert!(
            !m.allows(ip("::ffff:0:127.0.0.1")),
            "IPv4-translated loopback must be refused"
        );
        // ::ffff:0:0:0 -- the bare prefix address itself.
        assert!(
            !m.allows(ip("::ffff:0:0:0")),
            "the IPv4-translated prefix address itself must be refused"
        );
        // Boundary: segment 5 set to 1 instead of 0 -- one value outside
        // ::ffff:0:0:0/96 -- must not be caught by this guard. Confirmed by
        // the same probe that `to_ipv4_mapped()` is still `None` for this
        // address (segment 4 isn't where the mapped-form guard looks), and
        // it doesn't match any other guard either (segment 0 isn't 0x64 or
        // 0x2002, segments 0..=5 aren't all zero).
        assert!(
            ipv6_is_ordinary_by_prefix_rules(ipv6("::ffff:1:127.0.0.1")),
            "an address one segment-value outside ::ffff:0:0:0/96 must not \
             be caught by the IPv4-translated guard"
        );
    }

    // --- Fix round 2: Teredo, added proactively during the round-2 sweep
    // (not from a reported bypass) since it is an explicitly-named IPv6
    // transition prefix (RFC 4380) that also embeds an IPv4 address, albeit
    // obfuscated rather than in the clear. Refused as a whole prefix like
    // everything else in this table -- this guard does not attempt to
    // decode the obfuscated payload. ---

    #[test]
    fn teredo_addresses_are_refused_outright() {
        let m = permissive_dual_stack_manifest();
        // Any address in 2001::/32 is refused regardless of what its low 96
        // bits (server address, flags, obfuscated port/client address)
        // contain -- this simple in-prefix address is sufficient to prove
        // the whole-prefix guard, without needing to construct a
        // fully-obfuscation-valid Teredo address.
        assert!(
            !m.allows(ip("2001::1")),
            "an address in the Teredo prefix 2001::/32 must be refused"
        );
        // Boundary: 2001:1::1 (IANA's own PCP-anycast address, segments[1]
        // == 1 rather than Teredo's required 0) is one segment-value
        // outside 2001::/32 and must not be caught by this guard. It is a
        // real IANA special-purpose address in its own right (RFC 7723),
        // deliberately not guarded here -- see the task report's sweep for
        // why single-host anycast addresses like this one are out of scope
        // for an IPv4-embedding fix.
        assert!(
            ipv6_is_ordinary_by_prefix_rules(ipv6("2001:1::1")),
            "2001:1::1 is one segment-value outside 2001::/32 and must not \
             be caught by the Teredo guard"
        );
    }

    // --- Fix round 3 (CRITICAL, ISATAP): the eighth IPv4-in-IPv6 embedding
    // scheme, found by the round-2 re-review. Signals via a fixed 32-bit
    // marker in the *interface identifier* (segments 4-5), not a network
    // prefix -- so it rides on any unicast prefix a site chooses, unlike
    // every other guard above. `00-00-5E` is IANA's own registered OUI,
    // reserved for exactly this use by RFC 5214 -- a prior sweep round
    // wrongly called this "not IANA-reserved, just a convention" and
    // excluded it on that basis; that reasoning was factually wrong, not
    // just incomplete, and is corrected in `ipv6_is_ordinary_by_prefix_
    // rules`'s own doc comment. Segment positions verified against a real
    // `"2001:db8::5efe:7f00:1".parse::<Ipv6Addr>().segments()` probe before
    // writing the guard -- see the task report for the probe output. ---

    #[test]
    fn isatap_prefix_guard_is_precise() {
        // Tests the parked guard directly, not through `m.allows()`: in
        // v0.1 every IPv6 address is refused regardless of this guard (see
        // the "Fix round 3" tests below), so precision has to be proven
        // against the guard function itself, same as every other boundary
        // test rewritten this round.
        assert!(
            !ipv6_is_ordinary_by_prefix_rules(ipv6("2001:db8::5efe:7f00:1")),
            "ISATAP-embedded loopback (0000:5EFE marker) must be caught"
        );
        assert!(
            !ipv6_is_ordinary_by_prefix_rules(ipv6("2001:db8::200:5efe:7f00:1")),
            "ISATAP-embedded loopback (0200:5EFE marker) must be caught"
        );
        // Boundary: segment 4 one value away from either recognized marker
        // (0x0001, matching neither 0x0000 nor 0x0200) must not be caught.
        assert!(
            ipv6_is_ordinary_by_prefix_rules(ip6_addr([
                0x2001, 0x0db8, 0, 0, 1, 0x5efe, 0x7f00, 1
            ])),
            "an address whose segment 4 matches neither ISATAP marker must \
             not be caught by the ISATAP guard"
        );
        // Boundary: segment 5 one value away from the marker (0x5eff,
        // matching neither), with segment 4 == 0, must not be caught.
        assert!(
            ipv6_is_ordinary_by_prefix_rules(ip6_addr([
                0x2001, 0x0db8, 0, 0, 0, 0x5eff, 0x7f00, 1
            ])),
            "an address whose segment 5 is one past the ISATAP marker must \
             not be caught by the ISATAP guard"
        );
    }

    // --- Fix round 3 (CONTROLLER DECISION): IPv6 scanning is out of scope
    // for v0.1 (docs/superpowers/plans/2026-07-31-sonde-v0.1-overview.md's
    // Gap Register). `is_ordinary_unicast`'s IPv6 arm now refuses every
    // IPv6 address unconditionally, as its first and only action --
    // immune to every embedding/transition scheme, enumerated above or
    // not. Every IPv6-refusal test in this file (added across rounds 0-3)
    // still passes -- they all still assert `false` -- but now for this
    // single, broader reason rather than for the individual prefix guard
    // each was originally written to prove; see the comments added to
    // those tests above. The two tests below are the ones that actually
    // prove the blanket policy itself, rather than incidentally passing
    // because of it. ---

    #[test]
    fn ordinary_global_unicast_ipv6_is_refused_because_ipv6_scanning_is_out_of_scope_for_v0_1() {
        let m = permissive_ipv6_manifest(); // allows ::/0
        // 2606:4700:4700::1111 is a real, non-reserved, globally-routed
        // address (Cloudflare's public DNS) -- not loopback, not
        // multicast, not link-local, and not within any of the eight
        // IPv4-embedding/transition prefixes above (confirmed by the same
        // probe used to verify the ISATAP segment layout: segments =
        // [0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111], matching none of
        // them). If IPv6 scanning were supported, this is exactly the kind
        // of address a manifest should be able to authorize. It is refused
        // anyway: this is the v0.1 scope decision documented on
        // `is_ordinary_unicast`, not a bug and not evidence that some
        // reserved-range check misfired.
        assert!(
            !m.allows(ip("2606:4700:4700::1111")),
            "ordinary IPv6 unicast must be refused in v0.1 -- IPv6 scanning \
             is out of scope for this release, not because this address is \
             reserved"
        );
    }

    #[test]
    fn isatap_addresses_are_refused_by_the_v0_1_blanket_policy() {
        let m = permissive_ipv6_manifest();
        // Both markers, embedding raw (unobfuscated) 127.0.0.1, on the
        // documentation prefix standing in for "any site-chosen prefix" --
        // ISATAP does not use a fixed global prefix. Refused here by the
        // v0.1 blanket policy; the mutation evidence in the task report
        // proves the parked ISATAP-specific guard alone provides no
        // protection right now (removing the blanket refusal makes these
        // addresses allowed again, with nothing else catching them).
        assert!(
            !m.allows(ip("2001:db8::5efe:7f00:1")),
            "ISATAP-embedded loopback (0000:5EFE marker) must be refused"
        );
        assert!(
            !m.allows(ip("2001:db8::200:5efe:7f00:1")),
            "ISATAP-embedded loopback (0200:5EFE marker) must be refused"
        );
    }

    #[test]
    fn manifest_with_ipv6_allowed_cidr_still_loads_successfully() {
        // Fix round 3: an IPv6 entry in `allowed_cidrs` must warn, not
        // fail to load -- the manifest may also carry valid IPv4 CIDRs,
        // and an operator drafting a manifest ahead of v0.2 (when IPv6
        // scanning lands) should not be blocked from doing so. The warning
        // text itself is manually verified (see the task report), same as
        // the signature warning above it in `load` -- this test proves the
        // load-time behavior (succeeds; IPv4 entries stay usable; the IPv6
        // entry can never match anything), not the warning's wording.
        let with_ipv6 = MANIFEST.replace(r#"["10.30.0.0/24"]"#, r#"["10.30.0.0/24", "::/0"]"#);
        let m = ScopeManifest::load(&with_ipv6).unwrap();
        assert!(m.allows(ip("10.30.0.42")), "the IPv4 entry stays usable");
        assert!(
            !m.allows(ip("2001:db8::1")),
            "the IPv6 entry can never match anything, per the v0.1 blanket \
             refusal"
        );
    }

    // --- Fix round 1 (Important): 240.0.0.0/4 IANA-reserved martian space
    // was allowed. `Ipv4Addr::is_reserved()` is nightly-only at this MSRV,
    // hence the hand-rolled `octets()[0] >= 240` range check. ---

    #[test]
    fn ipv4_reserved_martian_space_is_refused() {
        let permissive = MANIFEST.replace(r#"["10.30.0.0/24"]"#, r#"["0.0.0.0/0"]"#);
        let m = ScopeManifest::load(&permissive).unwrap();
        assert!(!m.allows(ip("240.0.0.1")), "240.0.0.0/4 must be refused");
        assert!(
            !m.allows(ip("255.0.0.1")),
            "255.0.0.0/8 (inside 240.0.0.0/4) must be refused"
        );
        // Already refused for a different reason (is_multicast, not the new
        // >= 240 check) -- confirm it's unaffected and still refused.
        assert!(
            !m.allows(ip("239.255.255.255")),
            "the top of multicast space must still be refused"
        );
        // Ordinary unicast just below the new threshold: must remain
        // allowed.
        assert!(
            m.allows(ip("223.1.2.3")),
            "223.1.2.3 is ordinary unicast and must remain allowed"
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
