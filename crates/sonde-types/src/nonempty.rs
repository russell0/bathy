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
}
