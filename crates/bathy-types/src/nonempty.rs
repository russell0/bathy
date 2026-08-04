use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

/// A vector guaranteed to hold at least one element.
///
/// Used so that a `Finding` cannot be constructed without evidence. The
/// guarantee lives in the type system rather than in a validation pass,
/// because a validation pass can be forgotten.
// Rationale below is deliberately a `//` comment, not a `///` one:
// schemars copies doc comments on a wire type into `schemas/*.json` as
// `description`, and that file is the contract agents read. Notes about
// serde/schemars internals are for maintainers, not for a caller
// deciding what to put on the wire.
// `NonEmpty<T>` is instantiated at more than one `T` in this crate (e.g.
// `NonEmpty<String>` in `request.rs`, `NonEmpty<Digest>` in `event.rs`), so
// each instantiation needs its own name in the generated JSON Schema's
// `$defs`. Without `#[schemars(rename = ...)]`, schemars_derive 1.2.2 names
// every generic struct after its bare Rust identifier
// (`schemars_derive-1.2.2/src/lib.rs`'s `derive_json_schema`: `let name =
// cont.name();` is just the struct ident when no `rename` is set, with no
// reference to the type parameter) and disambiguates collisions by
// *declaration order* within a `SchemaGenerator` run, appending "2", "3",
// etc. That makes `$defs` key names depend on unrelated field-ordering
// decisions elsewhere in the crate -- reordering or adding a field renames
// them, producing spurious diffs against the schemas committed under
// `schemas/` (checked by `xtask check-schemas`).
//
// The fix uses the format-string form of `#[schemars(rename = "...")]`,
// which is schemars' own built-in mechanism for this: "If set on a struct
// or enum with generic type parameters, then the given name may contain
// them enclosed in curly braces (e.g. `{T}`) and they will be replaced with
// the concrete type names when the schema is generated"
// (`schemars_derive-1.2.2/attributes.md`, the `rename` section). This is
// also exactly the pattern schemars uses for its own builtin generic
// impls, e.g. `Vec<T>`'s `schema_name()` is
// `format!("Array_of_{}", T::schema_name())`
// (`schemars-1.2.2/src/json_schema_impls/sequences.rs`) -- `_of_`, not
// `_for_`. Confirmed empirically with a throwaway probe crate against this
// workspace's exact schemars 1.2.2: a struct holding `NonEmpty<String>` and
// `NonEmpty<u8>` emits `$defs` keys `NonEmpty_of_string` and
// `NonEmpty_of_uint8` regardless of the two fields' declaration order, each
// still carrying its own `minItems: 1`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent, rename = "NonEmpty_of_{T}")]
pub struct NonEmpty<T>(#[schemars(length(min = 1))] Vec<T>);

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
        if v.is_empty() {
            Err(EmptyError)
        } else {
            Ok(Self(v))
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for NonEmpty<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = Vec::<T>::deserialize(d)?;
        Self::try_from(v).map_err(serde::de::Error::custom)
    }
}

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

    // --- Additional coverage beyond the brief's minimal test list ---

    #[test]
    fn new_wraps_single_element() {
        let ne = NonEmpty::new(5u8);
        assert_eq!(ne.len(), 1);
        assert_eq!(*ne.first(), 5);
        assert!(!ne.is_empty());
    }

    #[test]
    fn iter_preserves_order() {
        let ne = NonEmpty::try_from(vec![1, 2, 3]).unwrap();
        assert_eq!(ne.iter().copied().collect::<Vec<_>>(), vec![1, 2, 3]);
    }

    #[test]
    fn push_appends_and_keeps_non_empty() {
        let mut ne = NonEmpty::new(1);
        ne.push(2);
        assert_eq!(ne.into_vec(), vec![1, 2]);
    }

    #[test]
    fn deserializing_populated_json_array_succeeds_and_preserves_order() {
        let ne: NonEmpty<u8> = serde_json::from_str("[3,1,2]").unwrap();
        assert_eq!(ne.into_vec(), vec![3, 1, 2]);
    }

    #[test]
    fn empty_error_message_is_stable() {
        let err = NonEmpty::<u8>::try_from(Vec::new()).unwrap_err();
        assert_eq!(err.to_string(), "value must contain at least one element");
    }

    // --- AC-1.9: JSON Schema exposes `minItems: 1` constraining the array ---
    // Proven concretely by generating the schema and asserting the exact
    // `minItems` value is present -- a JsonSchema impl that compiles,
    // satisfies the trait, and emits an unconstrained schema would
    // otherwise pass unnoticed (this is exactly the class of hole Task 2's
    // review found).

    #[test]
    fn non_empty_json_schema_has_min_items_one() {
        let schema = schemars::schema_for!(NonEmpty<u8>);
        let value = serde_json::to_value(&schema).unwrap();
        assert_eq!(
            value.get("minItems").and_then(|v| v.as_u64()),
            Some(1),
            "schema was {value:#}"
        );
        assert_eq!(value.get("type").and_then(|v| v.as_str()), Some("array"));
    }

    // --- Task 5a: `$defs` names for `NonEmpty<T>` must be deterministic and
    // independent of field declaration order, not assigned by schemars'
    // default first-seen-wins "NonEmpty" / "NonEmpty2" numbering. Two structs
    // below hold the *same two* `NonEmpty<T>` instantiations
    // (`NonEmpty<String>`, `NonEmpty<Digest>`) but declare their fields in
    // opposite order; the point of the second struct existing at all is to
    // prove the `$defs` keys don't move when declaration order changes --
    // asserting only the forward-order struct would not catch a regression
    // back to order-dependent naming, since first-seen-wins numbering also
    // produces *some* stable-looking name for a single struct in isolation.

    use crate::ids::Digest;

    // These two structs exist only to be handed to `schema_for!` below; no
    // value of either is ever constructed, so their fields are legitimately
    // unread.
    #[derive(JsonSchema)]
    #[allow(dead_code)]
    struct HoldsBothNonEmptyInstantiationsForwardOrder {
        strings: NonEmpty<String>,
        digests: NonEmpty<Digest>,
    }

    #[derive(JsonSchema)]
    #[allow(dead_code)]
    struct HoldsBothNonEmptyInstantiationsReversedOrder {
        digests: NonEmpty<Digest>,
        strings: NonEmpty<String>,
    }

    #[test]
    fn non_empty_defs_names_are_deterministic_and_order_independent() {
        let forward = serde_json::to_value(schemars::schema_for!(
            HoldsBothNonEmptyInstantiationsForwardOrder
        ))
        .unwrap();
        let reversed = serde_json::to_value(schemars::schema_for!(
            HoldsBothNonEmptyInstantiationsReversedOrder
        ))
        .unwrap();

        for (label, value) in [("forward", &forward), ("reversed", &reversed)] {
            let defs = value["$defs"].as_object().expect("$defs must be an object");
            // `$defs` also contains `Digest`'s own (unrelated) definition,
            // since `Digest` is itself a referenceable named type -- assert
            // the two `NonEmpty` keys are present, not that they're the only
            // keys.
            let mut keys: Vec<&str> = defs.keys().map(String::as_str).collect();
            keys.sort_unstable();
            for expected in ["NonEmpty_of_Digest", "NonEmpty_of_string"] {
                assert!(
                    keys.contains(&expected),
                    "{label} order: expected {expected} in $defs keys {keys:?}"
                );
            }
            for key in ["NonEmpty_of_Digest", "NonEmpty_of_string"] {
                assert_eq!(
                    defs[key]["minItems"].as_u64(),
                    Some(1),
                    "{label} order: {key} lost its minItems: 1 -- schema was {value:#}"
                );
                assert_eq!(defs[key]["type"].as_str(), Some("array"));
            }
        }

        // The actual point of this test: reversing field declaration order
        // must not rename anything.
        assert_eq!(
            forward["$defs"], reversed["$defs"],
            "reversing field order changed $defs -- names are still order-dependent"
        );
    }
}
