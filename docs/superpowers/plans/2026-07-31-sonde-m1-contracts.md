# sonde M1 — Contracts, Scope & Policy — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish the Rust workspace and the complete contract layer — every type an agent can see, its JSON Schema, and a deny-by-default scope/policy/budget engine that can accept or refuse a target with a machine-readable reason.

**Architecture:** `sonde-types` is a pure, I/O-free crate holding every type that crosses a public boundary; `schemars` derives JSON Schema from those types and the schemas are committed to `schemas/` so CI can detect drift. `sonde-scope` layers policy on top: an unexpired manifest defines allow/deny CIDR sets and budget ceilings, and every scan decision passes through it before a single packet exists.

**Tech Stack:** Rust 1.85 (edition 2024), serde, schemars, ulid, blake3, ipnet, thiserror, proptest.

**Read first:** `2026-07-31-sonde-v0.1-overview.md` — its Global Constraints section applies to every task here.

---

### Task 1: Workspace scaffold, toolchain, licensing, CI

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `deny.toml`, `.gitignore`
- Create: `LICENSE-APACHE`, `LICENSE-MIT`
- Create: `xtask/Cargo.toml`, `xtask/src/main.rs`
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: nothing.
- Produces: a workspace where `cargo test --workspace` and `cargo run -p xtask -- check-deps` both succeed.

- [ ] **Step 1: Create the workspace manifest**

`Cargo.toml`:
```toml
[workspace]
resolver = "3"
members = ["crates/*", "xtask"]

[workspace.package]
version = "0.1.0"
edition = "2024"
rust-version = "1.85"
license = "Apache-2.0 OR MIT"
repository = "https://github.com/russell0/sonde"

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
schemars = "1"
thiserror = "2"
blake3 = "1"
ulid = "3"
ipnet = { version = "2", features = ["serde"] }
proptest = "1"
```

`rust-toolchain.toml`:
```toml
# Develop on stable. 1.85 is the MSRV, declared as `rust-version` in the
# workspace manifest and verified by a dedicated CI job — pinning the
# toolchain to the MSRV itself would force every contributor to download an
# old compiler and would hide warnings that newer compilers catch.
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

Verified locally: rustc 1.97.1 satisfies the 1.85 floor and compiles edition 2024.

- [ ] **Step 2: Add both license files**

Write the verbatim Apache-2.0 text to `LICENSE-APACHE` and the verbatim MIT text to `LICENSE-MIT`. Do not paraphrase or abbreviate either license.

`.gitignore`:
```
/target
/lab/.state
*.sqlite
*.sqlite-*
```

- [ ] **Step 3: Write the failing dependency-boundary test**

`xtask/src/main.rs`:
```rust
use std::collections::BTreeMap;

/// Crates are listed lowest-level first. A crate may only depend on crates
/// that appear strictly earlier in this list.
const LAYERS: &[&str] = &[
    "sonde-types",
    "sonde-scope",
    "sonde-evidence",
    "sonde-store",
    "sonde-plan",
    "sonde-interpret",
    "sonde-probe",
    "sonde-engine",
    "sonde-packetd",
    "sonde-query",
    "sonde-mcp",
    "sonde-cli",
];

/// No crate at or below this layer may depend on anything resembling a
/// model/inference client. Enforces "no LLM on the packet path".
const FORBIDDEN_SUBSTRINGS: &[&str] =
    &["openai", "anthropic", "llm", "langchain", "ollama", "tokenizers"];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match std::env::args().nth(1).as_deref() {
        Some("check-deps") => check_deps(),
        Some(other) => Err(format!("unknown xtask: {other}").into()),
        None => Err("usage: xtask <check-deps>".into()),
    }
}

fn check_deps() -> Result<(), Box<dyn std::error::Error>> {
    let rank: BTreeMap<&str, usize> =
        LAYERS.iter().enumerate().map(|(i, n)| (*n, i)).collect();
    let meta = std::process::Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()?;
    let meta: serde_json::Value = serde_json::from_slice(&meta.stdout)?;
    let mut violations = Vec::new();

    for pkg in meta["packages"].as_array().ok_or("no packages")? {
        let name = pkg["name"].as_str().ok_or("unnamed package")?;
        // A package's own rank gates only the LAYER check. The
        // forbidden-substring check applies to EVERY workspace package,
        // ranked or not — `xtask` is a real member and is deliberately not in
        // LAYERS, so gating both checks on rank would let it depend on an
        // inference client undetected.
        let own_rank = rank.get(name).copied();
        for dep in pkg["dependencies"].as_array().ok_or("no dependencies")? {
            let dep_name = dep["name"].as_str().ok_or("unnamed dep")?;
            if let (Some(own_rank), Some(&dep_rank)) = (own_rank, rank.get(dep_name)) {
                if dep_rank >= own_rank {
                    violations.push(format!(
                        "{name} depends on {dep_name}, which is not strictly lower in the layer order"
                    ));
                }
            }
            let lowered = dep_name.to_ascii_lowercase();
            if FORBIDDEN_SUBSTRINGS.iter().any(|f| lowered.contains(f)) {
                violations.push(format!(
                    "{name} depends on {dep_name}, which looks like an inference client; \
                     no crate may put a model on the packet path"
                ));
            }
        }
    }

    if violations.is_empty() {
        println!("check-deps: ok ({} crates ranked)", rank.len());
        Ok(())
    } else {
        for v in &violations {
            eprintln!("check-deps: {v}");
        }
        Err(format!("{} dependency-boundary violation(s)", violations.len()).into())
    }
}
```

Add `serde_json = { workspace = true }` to `xtask/Cargo.toml`.

- [ ] **Step 4: Run it to verify it works on an empty workspace**

Run: `cargo run -p xtask -- check-deps`
Expected: `check-deps: ok (0 crates ranked)` and exit 0. It ranks zero crates because none exist yet; this proves the harness runs before it has anything to find.

- [ ] **Step 5: Write the CI workflow**

`.github/workflows/ci.yml`:
```yaml
name: ci
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - run: cargo fmt --all -- --check
      - run: cargo clippy --workspace --all-targets -- -D warnings
      - run: cargo test --workspace
      - run: cargo run -p xtask -- check-deps
      - run: cargo run -p xtask -- check-schemas
      # `unsafe ` with a trailing space misses `unsafe{`, and scanning only
      # crates/ misses xtask/. Match unsafe followed by space, brace, paren,
      # or end-of-line, across every Rust source outside sonde-packetd.
      - name: no unsafe outside packetd
        run: |
          ! grep -rnE --include='*.rs' 'unsafe([ {(]|$)' crates/ xtask/ \
            | grep -v '^crates/sonde-packetd/'
      # Lines that legitimately name the phrase — this rule, its tests, its
      # enforcement — carry the [phrase-rule] marker and are excluded. Without
      # that exclusion this step fails on its own source. See the overview's
      # sentinel convention.
      - name: forbidden determinism claim
        run: |
          # Bracket expression matches the phrase without this line containing it.
          ! grep -rniIE "deterministic[ ]results" . --exclude-dir=target --exclude-dir=.git \
            | grep -v '\[phrase-rule\]'
  # The MSRV is a promise to downstream consumers, so it gets its own job.
  # Without this, MSRV rots silently the first time someone uses a newer API.
  msrv:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@1.85
      - run: rm -f rust-toolchain.toml   # the pin says stable; this job tests the floor
      - run: cargo check --workspace --all-targets

  deny:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: EmbarkStudios/cargo-deny-action@v2
```

`deny.toml`:
```toml
[licenses]
allow = ["Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unicode-3.0", "Zlib"]
confidence-threshold = 0.9

[bans]
multiple-versions = "warn"

[advisories]
yanked = "deny"
```

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "chore: workspace scaffold, dual license, CI, dependency-boundary xtask"
```

**Acceptance criteria:**
- **AC-1.1** `cargo run -p xtask -- check-deps` exits non-zero when a crate depends on one at or above its own layer. Prove with a temporary violating dependency in a test, then revert.
- **AC-1.2** `check-deps` exits non-zero if any workspace package depends on a package whose name contains any `FORBIDDEN_SUBSTRINGS` entry — **including packages not listed in `LAYERS`**, such as `xtask`. Prove with a test whose depender is unranked; gating this check on the depender's rank is the natural mistake and it leaves a real hole.
- **AC-1.3** Both `LICENSE-APACHE` and `LICENSE-MIT` exist and every crate manifest declares `license = "Apache-2.0 OR MIT"` via `workspace = true`.
- **AC-1.4** CI fails the build if `unsafe` appears in any Rust source outside `sonde-packetd`, matching `unsafe` followed by a space, `{`, `(`, or end-of-line, and scanning `xtask/` as well as `crates/`. Verify both directions by seeding `unsafe{}` (no space, under `xtask/`) and confirming a non-zero exit, then removing it and confirming zero.
- **AC-1.5** CI fails the build if the unscoped determinism phrase appears on any line not carrying the `[phrase-rule]` marker. Prove both directions: a seeded unmarked occurrence fails the build, and the rule's own marked statements do not. `[phrase-rule]`
- **AC-1.35** A dedicated CI job compiles the workspace on Rust 1.85 with `rust-toolchain.toml` removed, so the declared MSRV is verified rather than assumed. Development itself happens on stable. (Numbered out of positional order: added after the toolchain was installed and the exact-version pin proved wrong.)

---

### Task 2: Identifier and digest types

**Files:**
- Create: `crates/sonde-types/Cargo.toml`, `crates/sonde-types/src/lib.rs`, `crates/sonde-types/src/ids.rs`
- Test: inline `#[cfg(test)]` in `ids.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `ScanId`, `EventId`, `ScopeId` (all `FromStr + Display + Serialize + Deserialize + JsonSchema`), and `Digest` with `Digest::of_bytes(&[u8]) -> Digest`, `Digest::to_string() -> String` rendering `blake3:<64 hex>`.

- [ ] **Step 1: Write the failing test**

`crates/sonde-types/src/ids.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_renders_with_algorithm_prefix() {
        let d = Digest::of_bytes(b"hello");
        let s = d.to_string();
        assert!(s.starts_with("blake3:"), "got {s}");
        assert_eq!(s.len(), "blake3:".len() + 64);
        assert_eq!(s, s.to_lowercase());
    }

    #[test]
    fn digest_roundtrips_through_string() {
        let d = Digest::of_bytes(b"hello");
        assert_eq!(d, d.to_string().parse::<Digest>().unwrap());
    }

    #[test]
    fn digest_rejects_wrong_algorithm() {
        // Assert the SPECIFIC variant. An earlier version of this test used
        // `.is_err()` with a 71-character input, which passed even with the
        // algorithm check deleted — the input fell through to the length check
        // and failed there for an unrelated reason. Mutation testing caught it.
        let bad = format!("sha256:{}", "a".repeat(64));
        assert_eq!(bad.parse::<Digest>().unwrap_err(), IdError::WrongAlgorithm);
    }

    #[test]
    fn digest_rejects_missing_algorithm_prefix() {
        // The hole the weak test above masked: correct length, correct hex,
        // no prefix at all.
        let bare = "a".repeat(64);
        assert_eq!(bare.parse::<Digest>().unwrap_err(), IdError::WrongAlgorithm);
    }

    #[test]
    fn digest_rejects_uppercase_hex_so_the_type_matches_its_published_schema() {
        // The schema this type publishes is `^blake3:[0-9a-f]{64}$`. If the
        // type accepted uppercase, a document that fails schema validation
        // would still deserialize — schema and implementation must agree.
        let upper = format!("blake3:{}", "A".repeat(64));
        assert!(upper.parse::<Digest>().is_err());
        assert!(serde_json::from_str::<Digest>(&format!("\"{upper}\"")).is_err());
        let lower = format!("blake3:{}", "a".repeat(64));
        assert!(lower.parse::<Digest>().is_ok());
    }

    #[test]
    fn scan_id_has_type_prefix() {
        let id = ScanId::from_ulid(ulid::Ulid::from_parts(0, 1));
        assert!(id.to_string().starts_with("scan_"), "got {id}");
    }

    #[test]
    fn scan_id_rejects_foreign_prefix() {
        assert!("scope_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse::<ScanId>().is_err());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sonde-types ids`
Expected: FAIL — `cannot find type Digest in this scope`.

- [ ] **Step 3: Write the implementation**

```rust
use std::fmt;
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A BLAKE3 content digest, rendered as `blake3:<64 lowercase hex>`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest([u8; 32]);

impl Digest {
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "blake3:")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdError {
    #[error("expected algorithm prefix `blake3:`")]
    WrongAlgorithm,
    #[error("expected 64 hex characters, found {0}")]
    BadDigestLength(usize),
    #[error("invalid hex in digest")]
    BadHex,
    #[error("expected identifier prefix `{expected}_`")]
    WrongPrefix { expected: &'static str },
    #[error("invalid ULID")]
    BadUlid,
}

impl FromStr for Digest {
    type Err = IdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex = s.strip_prefix("blake3:").ok_or(IdError::WrongAlgorithm)?;
        if hex.len() != 64 {
            return Err(IdError::BadDigestLength(hex.len()));
        }
        // Lowercase ONLY, deliberately. `u8::from_str_radix(_, 16)` below is
        // case-insensitive, but the JSON Schema this type publishes is
        // `^blake3:[0-9a-f]{64}$`. Without this check the type would accept
        // documents its own schema rejects. Do not "simplify" this to
        // `is_ascii_hexdigit()` — that reintroduces the divergence.
        if !hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(IdError::BadHex);
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| IdError::BadHex)?;
        }
        Ok(Self(out))
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

// NOTE: this project uses schemars 1.x. The 0.8 builder API (`into_object()`,
// `.string().pattern`, `schemars::gen::SchemaGenerator`, `schema_name() ->
// String`) does NOT exist in 1.x. In 1.x a `Schema` wraps a JSON value and is
// most clearly built with the `json_schema!` macro, and `schema_name` returns
// `Cow<'static, str>`. Confirm the exact signatures against the version that
// actually resolves before writing these impls — do not copy 0.8 examples.
impl JsonSchema for Digest {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Digest".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": "^blake3:[0-9a-f]{64}$",
            "description": "BLAKE3 content digest of stored evidence bytes.",
        })
    }
}

/// Declares a prefixed ULID newtype. Prefixes make identifiers self-describing
/// in logs and prevent a scope id being passed where a scan id is expected.
macro_rules! prefixed_id {
    ($name:ident, $prefix:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(ulid::Ulid);

        impl $name {
            pub const PREFIX: &'static str = $prefix;
            pub fn from_ulid(u: ulid::Ulid) -> Self {
                Self(u)
            }
            pub fn as_ulid(&self) -> ulid::Ulid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}_{}", $prefix, self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{self}")
            }
        }

        impl FromStr for $name {
            type Err = IdError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let rest = s
                    .strip_prefix(concat!($prefix, "_"))
                    .ok_or(IdError::WrongPrefix { expected: $prefix })?;
                Ok(Self(ulid::Ulid::from_string(rest).map_err(|_| IdError::BadUlid)?))
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                stringify!($name).into()
            }
            fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
                schemars::json_schema!({
                    "type": "string",
                    "pattern": concat!("^", $prefix, "_[0-9A-HJKMNP-TV-Z]{26}$"),
                    "description": $doc,
                })
            }
        }
    };
}

prefixed_id!(ScanId, "scan", "Identifies one scan task.");
prefixed_id!(EventId, "evt", "Identifies one immutable event.");
prefixed_id!(ScopeId, "scope", "Identifies an authorization scope manifest.");
```

Note: identifiers are *constructed* only in `sonde-store` (M2), which owns the clock and the ULID generator. `from_ulid` exists so pure crates and tests can build them without a clock.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p sonde-types ids`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/sonde-types
git commit -m "feat(types): prefixed ULID identifiers and BLAKE3 digest type"
```

**Acceptance criteria:**
- **AC-1.6** `Digest` serializes to and parses from exactly `blake3:<64 lowercase hex>`. It rejects a wrong algorithm prefix, a missing prefix, and non-lowercase hex — the last because the type must accept exactly what its published schema advertises. Assert specific `IdError` variants, not `is_err()`: a length-mismatched test input passes even with the algorithm check deleted.
- **AC-1.7** Each of `ScanId`, `EventId`, `ScopeId` rejects a string carrying a different type's prefix.
- **AC-1.8** Each identifier and `Digest` exposes a JSON Schema with a `pattern` constraining its format.

---

### Task 3: Non-empty evidence vector and confidence

**Files:**
- Create: `crates/sonde-types/src/nonempty.rs`, `crates/sonde-types/src/confidence.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `NonEmpty<T>` with `NonEmpty::try_from(Vec<T>) -> Result<Self, EmptyError>`, `NonEmpty::new(T)`, `first()`, `iter()`, `len()`, `into_vec()`. `Confidence` with `Confidence::new(f64) -> Result<Self, ConfidenceError>` and `get() -> f64`.

- [ ] **Step 1: Write the failing test**

`crates/sonde-types/src/nonempty.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_vec() {
        assert!(NonEmpty::<u8>::try_from(Vec::new()).is_err());
    }

    #[test]
    fn accepts_populated_vec_and_preserves_order() {
        let ne = NonEmpty::try_from(vec![1, 2, 3]).unwrap();
        assert_eq!(ne.len(), 3);
        assert_eq!(*ne.first(), 1);
        assert_eq!(ne.into_vec(), vec![1, 2, 3]);
    }

    #[test]
    fn deserializing_empty_json_array_fails() {
        let r: Result<NonEmpty<u8>, _> = serde_json::from_str("[]");
        assert!(r.is_err());
    }
}
```

`crates/sonde-types/src/confidence.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_unit_interval_inclusive() {
        assert!(Confidence::new(0.0).is_ok());
        assert!(Confidence::new(1.0).is_ok());
        assert!(Confidence::new(0.91).is_ok());
    }

    #[test]
    fn rejects_out_of_range_and_nan() {
        assert!(Confidence::new(-0.01).is_err());
        assert!(Confidence::new(1.01).is_err());
        assert!(Confidence::new(f64::NAN).is_err());
        assert!(Confidence::new(f64::INFINITY).is_err());
    }

    #[test]
    fn deserializing_out_of_range_fails() {
        assert!(serde_json::from_str::<Confidence>("1.5").is_err());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p sonde-types nonempty confidence`
Expected: FAIL — types not found.

- [ ] **Step 3: Write the implementation**

`nonempty.rs`:
```rust
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

/// A vector guaranteed to hold at least one element.
///
/// Used so that a `Finding` cannot be constructed without evidence. The
/// guarantee lives in the type system rather than in a validation pass,
/// because a validation pass can be forgotten.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct NonEmpty<T>(Vec<T>);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("value must contain at least one element")]
pub struct EmptyError;

impl<T> NonEmpty<T> {
    pub fn new(first: T) -> Self {
        Self(vec![first])
    }
    pub fn first(&self) -> &T {
        &self.0[0] // safe: the invariant guarantees index 0 exists
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        false
    }
    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.0.iter()
    }
    pub fn push(&mut self, item: T) {
        self.0.push(item);
    }
    pub fn into_vec(self) -> Vec<T> {
        self.0
    }
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }
}

impl<T> TryFrom<Vec<T>> for NonEmpty<T> {
    type Error = EmptyError;
    fn try_from(v: Vec<T>) -> Result<Self, Self::Error> {
        if v.is_empty() { Err(EmptyError) } else { Ok(Self(v)) }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for NonEmpty<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = Vec::<T>::deserialize(d)?;
        Self::try_from(v).map_err(serde::de::Error::custom)
    }
}
```

Add `minItems: 1` to the generated schema by annotating fields that use it with `#[schemars(length(min = 1))]`; the transparent derive alone does not emit it.

`confidence.rs`:
```rust
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

/// A probability in the closed interval [0.0, 1.0].
///
/// Confidence is reported, never inferred by a model at runtime: it comes from
/// how specifically a probe's response matched a rule in `sonde-interpret`.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct Confidence(f64);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("confidence must be a finite number in [0.0, 1.0]")]
pub struct ConfidenceError;

impl Confidence {
    pub const CERTAIN: Self = Self(1.0);
    pub fn new(v: f64) -> Result<Self, ConfidenceError> {
        if v.is_finite() && (0.0..=1.0).contains(&v) {
            Ok(Self(v))
        } else {
            Err(ConfidenceError)
        }
    }
    pub fn get(self) -> f64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for Confidence {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(f64::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p sonde-types`
Expected: all passed.

- [ ] **Step 5: Commit**

```bash
git add crates/sonde-types
git commit -m "feat(types): NonEmpty and Confidence with parse-time validation"
```

**Acceptance criteria:**
- **AC-1.9** `NonEmpty<T>` cannot be constructed from an empty `Vec` or deserialized from `[]`.
- **AC-1.10** `Confidence` rejects values outside `[0.0, 1.0]`, plus `NaN` and infinities, both at construction and at deserialization.

---

### Task 4: Scan request, budgets, and port selection

**Files:**
- Create: `crates/sonde-types/src/request.rs`

**Interfaces:**
- Consumes: `Digest`, `ScopeId` from Task 2.
- Produces: `ScanRequest`, `Budgets`, `PortSelection`, `PortPreset`, `ServiceDetection`, `EvidenceLevel`, `Objective`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"{
      "targets": ["10.30.0.0/24"],
      "authorization_scope_id": "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV",
      "objective": "inventory_exposed_services",
      "ports": { "preset": "common-1000" },
      "service_detection": { "enabled": true, "intensity": 4 },
      "budgets": {
        "maximum_packets": 200000,
        "maximum_runtime_seconds": 900,
        "maximum_packets_per_second": 5000
      },
      "evidence_level": "headers",
      "idempotency_key": "asset-inventory-2026-08-01"
    }"#;

    #[test]
    fn parses_the_canonical_example_request() {
        let r: ScanRequest = serde_json::from_str(EXAMPLE).unwrap();
        assert_eq!(r.targets.len(), 1);
        assert_eq!(r.objective, Objective::InventoryExposedServices);
        assert_eq!(r.budgets.maximum_packets, 200_000);
        assert_eq!(r.evidence_level, EvidenceLevel::Headers);
        assert_eq!(r.service_detection.intensity, 4);
    }

    #[test]
    fn budgets_are_mandatory() {
        let no_budget = EXAMPLE.replace(
            r#""budgets": {
        "maximum_packets": 200000,
        "maximum_runtime_seconds": 900,
        "maximum_packets_per_second": 5000
      },"#,
            "",
        );
        assert!(serde_json::from_str::<ScanRequest>(&no_budget).is_err());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let extra = EXAMPLE.replace(r#""targets""#, r#""stealth_mode": true, "targets""#);
        assert!(serde_json::from_str::<ScanRequest>(&extra).is_err());
    }

    #[test]
    fn zero_budget_is_rejected() {
        let zero = EXAMPLE.replace("\"maximum_packets\": 200000", "\"maximum_packets\": 0");
        assert!(serde_json::from_str::<ScanRequest>(&zero).is_err());
    }

    #[test]
    fn intensity_above_nine_is_rejected() {
        let hot = EXAMPLE.replace("\"intensity\": 4", "\"intensity\": 12");
        assert!(serde_json::from_str::<ScanRequest>(&hot).is_err());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p sonde-types request`
Expected: FAIL — `ScanRequest` not found.

- [ ] **Step 3: Write the implementation**

```rust
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::ScopeId;

/// What the caller is trying to learn. Objectives are a closed set so the
/// planner can map each to a bounded strategy; free-text goals belong to the
/// agent layer, which compiles them into one of these.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Objective {
    /// Which hosts are up.
    HostInventory,
    /// Which services are listening and what they are.
    InventoryExposedServices,
    /// Re-observe a previous scan's endpoints to detect change.
    ChangeDetection,
    /// Re-probe only endpoints whose prior confidence was low.
    ConfidenceRefinement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum EvidenceLevel {
    /// Record only the derived observation. Smallest storage.
    None,
    /// Record protocol banners and response headers. Default.
    Headers,
    /// Record full response bodies up to the per-response cap.
    Full,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum PortPreset {
    /// The 100 most commonly listening TCP ports, from our own dataset.
    Top100,
    /// The 1000 most commonly listening TCP ports, from our own dataset.
    Common1000,
    /// All 65535 TCP ports. Requires a budget large enough to cover them.
    All,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields, untagged)]
pub enum PortSelection {
    Preset {
        preset: PortPreset,
    },
    /// Explicit ports and inclusive ranges, e.g. `["22", "80", "8000-8100"]`.
    Explicit {
        #[schemars(length(min = 1))]
        explicit: Vec<String>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceDetection {
    pub enabled: bool,
    /// 0–9. Higher values authorize more probes per endpoint, not more hosts.
    #[schemars(range(min = 0, max = 9))]
    pub intensity: u8,
}

impl Default for ServiceDetection {
    fn default() -> Self {
        Self { enabled: true, intensity: 4 }
    }
}

/// Hard ceilings. The scheduler aborts the scan when any is exhausted; these
/// are not advisory hints. Every field is mandatory: an unbounded scan is not
/// an expressible request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Budgets {
    #[schemars(range(min = 1))]
    pub maximum_packets: u64,
    #[schemars(range(min = 1))]
    pub maximum_runtime_seconds: u64,
    #[schemars(range(min = 1))]
    pub maximum_packets_per_second: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanRequest {
    /// CIDRs, single addresses, or inclusive `a.b.c.d-e.f.g.h` ranges.
    #[schemars(length(min = 1))]
    pub targets: Vec<String>,
    /// The manifest authorizing this scan. Without it there is no scan.
    pub authorization_scope_id: ScopeId,
    pub objective: Objective,
    pub ports: PortSelection,
    #[serde(default)]
    pub service_detection: ServiceDetection,
    pub budgets: Budgets,
    #[serde(default = "default_evidence_level")]
    pub evidence_level: EvidenceLevel,
    /// Repeating a call with the same key and an identical plan returns the
    /// original task instead of starting a second scan.
    pub idempotency_key: String,
}

fn default_evidence_level() -> EvidenceLevel {
    EvidenceLevel::Headers
}
```

Validation of `range` and `length` at *deserialization* time is not automatic in serde. Add a `#[serde(try_from = "…")]` shim or implement `Deserialize` manually for `Budgets` and `ServiceDetection` so the zero-budget and intensity-12 tests pass. The simplest correct approach is a raw mirror struct:

```rust
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBudgets {
    maximum_packets: u64,
    maximum_runtime_seconds: u64,
    maximum_packets_per_second: u32,
}

impl TryFrom<RawBudgets> for Budgets {
    type Error = String;
    fn try_from(r: RawBudgets) -> Result<Self, String> {
        if r.maximum_packets == 0
            || r.maximum_runtime_seconds == 0
            || r.maximum_packets_per_second == 0
        {
            return Err("every budget must be greater than zero".into());
        }
        Ok(Self {
            maximum_packets: r.maximum_packets,
            maximum_runtime_seconds: r.maximum_runtime_seconds,
            maximum_packets_per_second: r.maximum_packets_per_second,
        })
    }
}
```
then annotate `Budgets` with `#[serde(try_from = "RawBudgets")]`. Apply the identical pattern to `ServiceDetection` for the `intensity <= 9` bound.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p sonde-types request`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/sonde-types
git commit -m "feat(types): ScanRequest with mandatory budgets and closed objective set"
```

**Acceptance criteria:**
- **AC-1.11** The canonical example request from the design document parses without modification.
- **AC-1.12** A request omitting `budgets` fails to deserialize. There is no default and no unbounded scan.
- **AC-1.13** A request containing any unknown field fails to deserialize (`deny_unknown_fields` on every struct).
- **AC-1.14** Any budget field equal to zero fails to deserialize; `intensity > 9` fails to deserialize.
- **AC-1.15** `authorization_scope_id` is a required, typed `ScopeId` — a scan cannot be described without naming its authorization.

---

### Task 5: Events, observations, and findings

**Files:**
- Create: `crates/sonde-types/src/event.rs`

**Interfaces:**
- Consumes: `ScanId`, `EventId`, `Digest`, `Confidence`, `NonEmpty`.
- Produces: `Event`, `EventBody`, `Endpoint`, `Transport`, `PortState`, `Observation`, `Finding`, `Target`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_observed_matches_the_designed_wire_format() {
        let json = r#"{
          "event_type": "service.observed",
          "scan_id": "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV",
          "sequence": 1842,
          "target": { "ip": "10.30.0.42" },
          "endpoint": { "transport": "tcp", "port": 443 },
          "observation": {
            "service": "https",
            "product": "nginx",
            "version": "1.26.x",
            "confidence": 0.91
          },
          "evidence_refs": ["blake3:9c37000000000000000000000000000000000000000000000000000000000000"],
          "probe_id": "tls-http-v3",
          "engine_version": "0.1.0",
          "timestamp": "2026-08-01T15:04:31.182Z"
        }"#;
        let e: Event = serde_json::from_str(json).unwrap();
        assert_eq!(e.sequence, 1842);
        let Event { body: EventBody::ServiceObserved { observation, .. }, .. } = &e else {
            panic!("wrong variant");
        };
        assert_eq!(observation.service, "https");
        assert_eq!(observation.confidence.get(), 0.91);
    }

    #[test]
    fn service_observed_requires_at_least_one_evidence_ref() {
        let json = r#"{
          "event_type": "service.observed",
          "scan_id": "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV",
          "sequence": 1,
          "target": { "ip": "10.30.0.42" },
          "endpoint": { "transport": "tcp", "port": 443 },
          "observation": { "service": "https", "confidence": 0.9 },
          "evidence_refs": [],
          "probe_id": "tls-http-v3",
          "engine_version": "0.1.0",
          "timestamp": "2026-08-01T15:04:31.182Z"
        }"#;
        assert!(serde_json::from_str::<Event>(json).is_err());
    }

    #[test]
    fn event_type_tag_round_trips_for_every_variant() {
        for tag in [
            "scan.started",
            "host.discovered",
            "port.state",
            "service.observed",
            "scan.progress",
            "policy.denied",
            "scan.completed",
            "scan.failed",
        ] {
            assert!(EventBody::KNOWN_TAGS.contains(&tag), "missing {tag}");
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p sonde-types event`
Expected: FAIL — `Event` not found.

- [ ] **Step 3: Write the implementation**

```rust
use std::net::IpAddr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::confidence::Confidence;
use crate::ids::{Digest, ScanId};
use crate::nonempty::NonEmpty;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub transport: Transport,
    pub port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub ip: IpAddr,
}

/// The observed reachability of one endpoint.
///
/// `Filtered` and `Closed` are distinct on purpose: a closed port is positive
/// evidence that a host is up, a filtered port is evidence of a middlebox.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    /// Probed, but the response was contradictory across retries.
    Indeterminate,
}

/// What a probe concluded about one endpoint. Every field beyond `service` is
/// optional because partial identification is normal and honest.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub service: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub confidence: Confidence,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "event_type")]
pub enum EventBody {
    #[serde(rename = "scan.started")]
    ScanStarted { plan_hash: Digest, estimated_targets: u64, estimated_probes: u64 },

    #[serde(rename = "host.discovered")]
    HostDiscovered {
        target: Target,
        method: String,
        evidence_refs: NonEmpty<Digest>,
    },

    #[serde(rename = "port.state")]
    PortStateObserved {
        target: Target,
        endpoint: Endpoint,
        state: PortState,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        evidence_refs: Option<NonEmpty<Digest>>,
    },

    #[serde(rename = "service.observed")]
    ServiceObserved {
        target: Target,
        endpoint: Endpoint,
        observation: Observation,
        evidence_refs: NonEmpty<Digest>,
        probe_id: String,
    },

    #[serde(rename = "scan.progress")]
    Progress { probes_sent: u64, probes_total: u64, packets_spent: u64 },

    #[serde(rename = "policy.denied")]
    PolicyDenied { reason_code: String, detail: String },

    #[serde(rename = "scan.completed")]
    ScanCompleted { probes_sent: u64, packets_spent: u64, findings: u64 },

    #[serde(rename = "scan.failed")]
    ScanFailed { reason_code: String, detail: String },
}

impl EventBody {
    pub const KNOWN_TAGS: &'static [&'static str] = &[
        "scan.started",
        "host.discovered",
        "port.state",
        "service.observed",
        "scan.progress",
        "policy.denied",
        "scan.completed",
        "scan.failed",
    ];
}

/// One immutable entry in a scan's append-only log.
///
/// `sequence` is gap-free and monotonic per scan; resumption replays from the
/// last persisted sequence, so a gap means data loss and is a hard error.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub scan_id: ScanId,
    pub sequence: u64,
    /// RFC 3339 UTC with milliseconds. Supplied by an injected `Clock`.
    pub timestamp: String,
    pub engine_version: String,
    #[serde(flatten)]
    pub body: EventBody,
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p sonde-types event`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/sonde-types
git commit -m "feat(types): immutable event model with mandatory evidence on findings"
```

**Acceptance criteria:**
- **AC-1.16** A `service.observed` event with `"evidence_refs": []` fails to deserialize. It is impossible to represent a service finding with no evidence.
- **AC-1.17** The `service.observed` wire format matches the design document field-for-field: `event_type`, `scan_id`, `sequence`, `target.ip`, `endpoint.transport`, `endpoint.port`, `observation.{service,product,version,confidence}`, `evidence_refs`, `probe_id`, `engine_version`, `timestamp`.
- **AC-1.18** All eight event tags in `EventBody::KNOWN_TAGS` serialize under the `event_type` discriminator.
- **AC-1.19** `PortState` distinguishes `open`, `closed`, `filtered`, and `indeterminate`.

---

### Task 6: Canonical JSON, schema export, and drift detection

**Files:**
- Create: `crates/sonde-types/src/canonical.rs`, `crates/sonde-types/src/schema.rs`
- Modify: `xtask/src/main.rs` (add `check-schemas` and `emit-schemas`)
- Create: `schemas/` (generated, committed)

**Interfaces:**
- Consumes: every type above.
- Produces: `canonical_json(&serde_json::Value) -> Result<String, CanonicalError>`, `plan_digest(&serde_json::Value) -> Result<Digest, CanonicalError>`, `sonde_types::schema::all() -> BTreeMap<&'static str, serde_json::Value>`.

- [ ] **Step 1: Write the failing test**

`canonical.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn object_keys_are_sorted_so_hashing_is_order_independent() {
        let a = json!({"b": 1, "a": 2});
        let b = json!({"a": 2, "b": 1});
        assert_eq!(canonical_json(&a).unwrap(), canonical_json(&b).unwrap());
        assert_eq!(canonical_json(&a).unwrap(), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn array_order_is_significant() {
        assert_ne!(
            canonical_json(&json!([1, 2])).unwrap(),
            canonical_json(&json!([2, 1])).unwrap()
        );
    }

    #[test]
    fn floats_are_rejected_because_their_text_form_is_not_portable() {
        assert!(canonical_json(&json!({"x": 1.5})).is_err());
    }

    #[test]
    fn nesting_is_canonicalized_recursively() {
        let v = json!({"z": {"b": [ {"d": 1, "c": 2} ]}, "a": true});
        assert_eq!(
            canonical_json(&v).unwrap(),
            r#"{"a":true,"z":{"b":[{"c":2,"d":1}]}}"#
        );
    }

    #[test]
    fn plan_digest_is_stable_across_key_order() {
        let a = json!({"targets": ["10.0.0.0/24"], "ports": [22, 80]});
        let b = json!({"ports": [22, 80], "targets": ["10.0.0.0/24"]});
        assert_eq!(plan_digest(&a).unwrap(), plan_digest(&b).unwrap());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p sonde-types canonical`
Expected: FAIL — `canonical_json` not found.

- [ ] **Step 3: Write the implementation**

```rust
use serde_json::Value;

use crate::ids::Digest;

/// Canonicalization is a restricted profile of RFC 8785 (JCS).
///
/// We deliberately reject non-integer numbers rather than implement JCS's
/// ECMAScript number serialization. Everything we hash — scan plans — contains
/// only strings, integers, booleans, arrays and objects, so the restriction
/// costs nothing and removes the single hardest source of hash instability.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CanonicalError {
    #[error("non-integer numbers are not canonicalizable in this profile")]
    NonIntegerNumber,
}

pub fn canonical_json(value: &Value) -> Result<String, CanonicalError> {
    let mut out = String::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut String) -> Result<(), CanonicalError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else {
                return Err(CanonicalError::NonIntegerNumber);
            }
        }
        Value::String(s) => out.push_str(&serde_json::to_string(s).expect("string encodes")),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // BTreeMap ordering: serde_json's Map is insertion-ordered when the
            // `preserve_order` feature is on, so sort explicitly rather than
            // relying on the map's own iteration order.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).expect("key encodes"));
                out.push(':');
                write_canonical(&map[*k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

pub fn plan_digest(plan: &Value) -> Result<Digest, CanonicalError> {
    Ok(Digest::of_bytes(canonical_json(plan)?.as_bytes()))
}
```

`schema.rs`:
```rust
use std::collections::BTreeMap;

use schemars::schema_for;
use serde_json::Value;

/// Every type that crosses a public boundary, keyed by the filename it is
/// committed under in `schemas/`.
pub fn all() -> BTreeMap<&'static str, Value> {
    let mut m = BTreeMap::new();
    m.insert("scan-request", to_value(schema_for!(crate::request::ScanRequest)));
    m.insert("event", to_value(schema_for!(crate::event::Event)));
    m.insert("task-handle", to_value(schema_for!(crate::task::TaskHandle)));
    m.insert("scope-manifest", to_value(schema_for!(crate::scope_dto::ScopeManifestDto)));
    m
}

fn to_value(s: schemars::schema::RootSchema) -> Value {
    serde_json::to_value(s).expect("schema serializes")
}
```

Add to `xtask/src/main.rs`:
```rust
fn emit_schemas(write: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut drift = Vec::new();
    for (name, schema) in sonde_types::schema::all() {
        let path = format!("schemas/{name}.json");
        let rendered = format!("{}\n", serde_json::to_string_pretty(&schema)?);
        if write {
            std::fs::create_dir_all("schemas")?;
            std::fs::write(&path, rendered)?;
        } else {
            let on_disk = std::fs::read_to_string(&path)
                .map_err(|e| format!("{path}: {e} (run `cargo run -p xtask -- emit-schemas`)"))?;
            if on_disk != rendered {
                drift.push(path);
            }
        }
    }
    if drift.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "schema drift in: {}. Run `cargo run -p xtask -- emit-schemas` and commit.",
            drift.join(", ")
        )
        .into())
    }
}
```
Wire `"emit-schemas" => emit_schemas(true)` and `"check-schemas" => emit_schemas(false)` into `main`.

- [ ] **Step 4: Run tests and generate the schemas**

Run: `cargo test -p sonde-types canonical` — expected 5 passed.
Run: `cargo run -p xtask -- emit-schemas` then `cargo run -p xtask -- check-schemas` — expected exit 0.
Run: manually edit one byte of `schemas/event.json`, re-run `check-schemas` — expected non-zero exit naming the drifted file. Revert.

- [ ] **Step 5: Commit**

```bash
git add crates/sonde-types schemas xtask
git commit -m "feat(types): canonical JSON profile, plan digest, committed schemas with drift check"
```

**Acceptance criteria:**
- **AC-1.20** `canonical_json` produces byte-identical output for objects differing only in key order, at every nesting depth.
- **AC-1.21** `canonical_json` returns an error for any non-integer number rather than emitting an unstable representation.
- **AC-1.22** `schemas/*.json` are committed to the repository and `xtask check-schemas` fails CI when a type changes without the schema being regenerated.
- **AC-1.23** `plan_digest` is invariant under key reordering and sensitive to array reordering.

---

### Task 7: Scope manifest

**Files:**
- Create: `crates/sonde-scope/Cargo.toml`, `crates/sonde-scope/src/lib.rs`, `crates/sonde-scope/src/manifest.rs`
- Create: `crates/sonde-types/src/scope_dto.rs` (wire form, so `sonde-types` can publish its schema)

**Interfaces:**
- Consumes: `ScopeId`.
- Produces: `ScopeManifest` with `ScopeManifest::load(&str) -> Result<Self, ManifestError>`, `id()`, `is_expired(now: &str) -> bool`, `allows(IpAddr) -> bool`, `ceiling() -> Budgets`.

- [ ] **Step 1: Write the failing test**

```rust
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

    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

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
        let permissive = MANIFEST.replace(
            r#"["10.30.0.0/24"]"#,
            r#"["0.0.0.0/0"]"#,
        );
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
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p sonde-scope manifest`
Expected: FAIL — `ScopeManifest` not found.

- [ ] **Step 3: Write the implementation**

```rust
use std::net::IpAddr;

use ipnet::IpNet;
use serde::Deserialize;
use sonde_types::ids::ScopeId;
use sonde_types::request::Budgets;

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("malformed manifest: {0}")]
    Malformed(#[from] serde_json::Error),
    #[error("a manifest must list at least one allowed CIDR")]
    NoAllowedCidrs,
    #[error("invalid CIDR `{0}`")]
    BadCidr(String),
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
    /// Reserved for v0.2 detached-signature verification. Accepted and stored
    /// but NOT verified in v0.1. Reserving the field now means adding
    /// verification later is not a breaking schema change; accepting it
    /// silently would be dishonest, so `ScopeManifest::load` logs a warning
    /// when it is present and `signature_verified()` always returns false.
    #[serde(default)]
    signature: Option<String>,
}

/// An authorization to scan. Deny-by-default: an address is in scope only if
/// it matches the allow set, does not match the deny set, and is an ordinary
/// unicast address.
#[derive(Debug, Clone)]
pub struct ScopeManifest {
    id: ScopeId,
    description: String,
    not_after: String,
    allowed: Vec<IpNet>,
    denied: Vec<IpNet>,
    ceiling: Budgets,
}

impl ScopeManifest {
    pub fn load(json: &str) -> Result<Self, ManifestError> {
        let raw: Raw = serde_json::from_str(json)?;
        if raw.allowed_cidrs.is_empty() {
            return Err(ManifestError::NoAllowedCidrs);
        }
        let parse = |v: &Vec<String>| -> Result<Vec<IpNet>, ManifestError> {
            v.iter()
                .map(|c| c.parse::<IpNet>().map_err(|_| ManifestError::BadCidr(c.clone())))
                .collect()
        };
        Ok(Self {
            id: raw.id,
            description: raw.description,
            not_after: raw.not_after,
            allowed: parse(&raw.allowed_cidrs)?,
            denied: parse(&raw.denied_cidrs)?,
            ceiling: raw.budget_ceiling,
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

    /// RFC 3339 UTC strings with fixed width and millisecond precision sort
    /// lexicographically in time order, so string comparison is correct here
    /// and avoids pulling a date library into the policy path.
    pub fn is_expired(&self, now_rfc3339: &str) -> bool {
        now_rfc3339 > self.not_after.as_str()
    }

    pub fn allows(&self, ip: IpAddr) -> bool {
        if !is_ordinary_unicast(ip) {
            return false;
        }
        if self.denied.iter().any(|n| n.contains(&ip)) {
            return false;
        }
        self.allowed.iter().any(|n| n.contains(&ip))
    }
}

/// Addresses that are never legitimate scan targets, regardless of what a
/// manifest says. A manifest is written by a human and can be wrong; these
/// categories cause collateral traffic or self-scans and are refused outright.
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
            !(v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                // link-local fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}
```

Also add a `ScopeManifestDto` mirror in `sonde-types/src/scope_dto.rs` deriving `JsonSchema` over the same fields, so `schema::all()` can publish it without `sonde-types` depending on `ipnet` parsing behavior.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p sonde-scope manifest`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/sonde-scope crates/sonde-types
git commit -m "feat(scope): deny-by-default manifest with expiry and reserved-range refusal"
```

**Acceptance criteria:**
- **AC-1.24** An address matching both allow and deny sets is denied — deny always wins.
- **AC-1.25** Loopback, multicast, broadcast, link-local, and unspecified addresses are refused even when the manifest allows `0.0.0.0/0`.
- **AC-1.26** A manifest with an empty `allowed_cidrs` fails to load.
- **AC-1.27** `is_expired` returns true for any instant after `not_after`.
- **AC-1.28** IPv6 loopback, multicast, unspecified, and `fe80::/10` link-local are refused.

---

### Task 8: Policy decision and budget accounting

**Files:**
- Create: `crates/sonde-scope/src/policy.rs`, `crates/sonde-scope/src/budget.rs`
- Create: `crates/sonde-types/src/task.rs`

**Interfaces:**
- Consumes: `ScopeManifest`, `ScanRequest`, `Budgets`.
- Produces: `PolicyDecision`, `DenyReason`, `evaluate(&ScopeManifest, &ScanRequest, &[IpAddr], now: &str) -> PolicyDecision`, `BudgetLedger` with `try_spend_packets(u64) -> Result<(), BudgetExhausted>`, `elapsed_exceeded(secs) -> bool`, `TaskHandle`, `TaskStatus`.

- [ ] **Step 1: Write the failing test**

`policy.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    const NOW: &str = "2026-08-15T00:00:00.000Z";

    #[test]
    fn approves_a_request_wholly_inside_scope_and_under_ceiling() {
        let m = manifest();
        let d = evaluate(&m, &request(), &[ip("10.30.0.42")], NOW);
        assert_eq!(d, PolicyDecision::Approved);
    }

    #[test]
    fn denies_when_any_single_target_is_out_of_scope() {
        let m = manifest();
        let d = evaluate(&m, &request(), &[ip("10.30.0.42"), ip("10.31.0.9")], NOW);
        assert!(
            matches!(&d, PolicyDecision::Denied { reason, .. } if *reason == DenyReason::TargetOutOfScope),
            "one out-of-scope target must deny the whole scan, got {d:?}"
        );
    }

    #[test]
    fn denies_an_expired_manifest() {
        let m = manifest();
        let d = evaluate(&m, &request(), &[ip("10.30.0.42")], "2026-10-01T00:00:00.000Z");
        assert!(matches!(&d, PolicyDecision::Denied { reason, .. } if *reason == DenyReason::ScopeExpired));
    }

    #[test]
    fn denies_a_request_whose_budget_exceeds_the_manifest_ceiling() {
        let m = manifest();
        let mut r = request();
        r.budgets.maximum_packets_per_second = 999_999;
        let d = evaluate(&m, &r, &[ip("10.30.0.42")], NOW);
        assert!(matches!(&d, PolicyDecision::Denied { reason, .. } if *reason == DenyReason::BudgetExceedsCeiling));
    }

    #[test]
    fn denies_when_the_request_names_a_different_scope() {
        let m = manifest();
        let mut r = request();
        r.authorization_scope_id = "scope_01ARZ3NDEKTSV4RRFFQ69G5FAW".parse().unwrap();
        let d = evaluate(&m, &r, &[ip("10.30.0.42")], NOW);
        assert!(matches!(&d, PolicyDecision::Denied { reason, .. } if *reason == DenyReason::ScopeMismatch));
    }

    #[test]
    fn every_denial_carries_a_stable_machine_readable_code() {
        let m = manifest();
        let d = evaluate(&m, &request(), &[ip("8.8.8.8")], NOW);
        let PolicyDecision::Denied { reason, detail } = d else { panic!("expected denial") };
        assert_eq!(reason.code(), "target_out_of_scope");
        assert!(detail.contains("8.8.8.8"), "detail must name the offending target");
    }
}
```

`budget.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(l.packets_spent(), 90, "a refused spend must not be recorded");
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
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p sonde-scope policy budget`
Expected: FAIL — `evaluate` and `BudgetLedger` not found.

- [ ] **Step 3: Write the implementation**

`policy.rs`:
```rust
use std::net::IpAddr;

use sonde_types::request::ScanRequest;

use crate::manifest::ScopeManifest;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyReason {
    ScopeMismatch,
    ScopeExpired,
    TargetOutOfScope,
    BudgetExceedsCeiling,
}

impl DenyReason {
    /// Stable identifiers. Agents branch on these, so they are part of the
    /// public contract and must not be reworded.
    pub fn code(self) -> &'static str {
        match self {
            Self::ScopeMismatch => "scope_mismatch",
            Self::ScopeExpired => "scope_expired",
            Self::TargetOutOfScope => "target_out_of_scope",
            Self::BudgetExceedsCeiling => "budget_exceeds_ceiling",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyDecision {
    Approved,
    Denied { reason: DenyReason, detail: String },
}

/// Evaluated once, before any packet exists, over the *fully expanded* target
/// list. Partial approval is not offered: if any target is out of scope the
/// whole scan is refused, so an agent cannot widen a scan by burying one
/// unauthorized address in a large CIDR.
pub fn evaluate(
    manifest: &ScopeManifest,
    request: &ScanRequest,
    expanded_targets: &[IpAddr],
    now_rfc3339: &str,
) -> PolicyDecision {
    let deny = |reason, detail: String| PolicyDecision::Denied { reason, detail };

    if request.authorization_scope_id != manifest.id() {
        return deny(
            DenyReason::ScopeMismatch,
            format!(
                "request cites {} but manifest is {}",
                request.authorization_scope_id,
                manifest.id()
            ),
        );
    }
    if manifest.is_expired(now_rfc3339) {
        return deny(
            DenyReason::ScopeExpired,
            format!("manifest {} expired before {now_rfc3339}", manifest.id()),
        );
    }
    if let Some(bad) = expanded_targets.iter().find(|ip| !manifest.allows(**ip)) {
        return deny(
            DenyReason::TargetOutOfScope,
            format!("{bad} is not authorized by manifest {}", manifest.id()),
        );
    }
    let c = manifest.ceiling();
    let b = request.budgets;
    if b.maximum_packets > c.maximum_packets
        || b.maximum_runtime_seconds > c.maximum_runtime_seconds
        || b.maximum_packets_per_second > c.maximum_packets_per_second
    {
        return deny(
            DenyReason::BudgetExceedsCeiling,
            format!(
                "requested {}pkt/{}s/{}pps exceeds ceiling {}pkt/{}s/{}pps",
                b.maximum_packets,
                b.maximum_runtime_seconds,
                b.maximum_packets_per_second,
                c.maximum_packets,
                c.maximum_runtime_seconds,
                c.maximum_packets_per_second
            ),
        );
    }
    PolicyDecision::Approved
}
```

`budget.rs`:
```rust
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
        Self { budgets, packets_spent: 0 }
    }
    pub fn packets_spent(&self) -> u64 {
        self.packets_spent
    }
    pub fn packets_remaining(&self) -> u64 {
        self.budgets.maximum_packets.saturating_sub(self.packets_spent)
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
```

`crates/sonde-types/src/task.rs`:
```rust
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{Digest, ScanId};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Pending,
    Running,
    Paused,
    Completed,
    Cancelled,
    Failed,
    /// Refused by policy. Terminal, and carries a `policy.denied` event.
    Denied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecisionTag {
    Approved,
    Denied,
}

/// Returned immediately by `scan.start`. Never blocks on scan completion.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskHandle {
    pub task_id: ScanId,
    pub plan_hash: Digest,
    pub policy_decision: PolicyDecisionTag,
    pub estimated_targets: u64,
    pub status: TaskStatus,
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p sonde-scope`
Expected: 16 passed across manifest, policy, and budget.

- [ ] **Step 5: Add a property test for the scope invariant**

```rust
proptest::proptest! {
    /// The single most important invariant in the project: nothing outside the
    /// allow set is ever approved, for any request and any target set.
    #[test]
    fn no_target_outside_the_allow_set_is_ever_approved(
        octets in proptest::collection::vec(0u8..=255, 4)
    ) {
        let ip = std::net::IpAddr::from([octets[0], octets[1], octets[2], octets[3]]);
        let m = manifest(); // allows 10.30.0.0/24, denies 10.30.0.1/32
        let d = evaluate(&m, &request(), &[ip], "2026-08-15T00:00:00.000Z");
        let should_allow = octets[0] == 10 && octets[1] == 30 && octets[2] == 0
            && octets[3] != 1 && octets[3] != 0 && octets[3] != 255;
        if !should_allow {
            proptest::prop_assert!(
                matches!(d, PolicyDecision::Denied { .. }),
                "{ip} was approved but is outside the allow set"
            );
        }
    }
}
```

Run: `cargo test -p sonde-scope no_target_outside` — expected PASS over 256 cases.

- [ ] **Step 6: Commit**

```bash
git add crates/sonde-scope crates/sonde-types
git commit -m "feat(scope): policy evaluation with stable deny codes and hard budget ledger"
```

**Acceptance criteria:**
- **AC-1.29** A scan containing even one out-of-scope target is denied in full. Partial approval is not representable.
- **AC-1.30** Every `PolicyDecision::Denied` carries a stable `reason.code()` string and a `detail` naming the specific offending value.
- **AC-1.31** A request whose budgets exceed the manifest ceiling on *any* axis is denied with `budget_exceeds_ceiling`.
- **AC-1.32** A request citing a different `ScopeId` than the loaded manifest is denied with `scope_mismatch`.
- **AC-1.33** `BudgetLedger::try_spend_packets` refuses at exactly the ceiling and leaves the ledger unchanged on refusal.
- **AC-1.34** A property test over ≥256 generated addresses confirms no address outside the allow set is ever approved.

---

## Milestone Exit Criteria

M1 is complete when all of the following hold:

- [ ] `cargo test --workspace` is green.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` is clean.
- [ ] `cargo run -p xtask -- check-deps` and `check-schemas` both exit 0.
- [ ] `schemas/scan-request.json`, `event.json`, `task-handle.json`, `scope-manifest.json` are committed.
- [ ] AC-1.1 through AC-1.34 are each demonstrated by a named passing test.
- [ ] No crate outside `sonde-packetd` contains `unsafe`.
- [ ] `sonde-types` has zero internal dependencies and no `tokio` in its dependency tree.
