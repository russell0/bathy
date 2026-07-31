use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

/// A probability in the closed interval [0.0, 1.0].
///
/// Confidence is reported, never inferred by a model at runtime: it comes from
/// how specifically a probe's response matched a rule in `sonde-interpret`.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct Confidence(#[schemars(range(min = 0.0, max = 1.0))] f64);

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

    // --- Additional coverage beyond the brief's minimal test list ---

    #[test]
    fn rejects_negative_infinity() {
        assert!(Confidence::new(f64::NEG_INFINITY).is_err());
    }

    #[test]
    fn get_returns_the_underlying_value() {
        assert_eq!(Confidence::new(0.42).unwrap().get(), 0.42);
    }

    #[test]
    fn certain_equals_one() {
        assert_eq!(Confidence::CERTAIN.get(), 1.0);
    }

    #[test]
    fn certain_is_usable_in_a_const_context() {
        const C: Confidence = Confidence::CERTAIN;
        assert_eq!(C.get(), 1.0);
    }

    #[test]
    fn deserializing_in_range_value_succeeds() {
        let c: Confidence = serde_json::from_str("0.73").unwrap();
        assert_eq!(c.get(), 0.73);
    }

    #[test]
    fn deserializing_negative_value_fails() {
        assert!(serde_json::from_str::<Confidence>("-0.01").is_err());
    }

    #[test]
    fn error_message_is_stable() {
        let err = Confidence::new(2.0).unwrap_err();
        assert_eq!(
            err.to_string(),
            "confidence must be a finite number in [0.0, 1.0]"
        );
    }

    // Note: JSON has no literal syntax for NaN/Infinity, so those values
    // cannot be expressed as JSON source text to exercise the
    // deserialize-time check the way `deserializing_out_of_range_fails`
    // exercises the finite-but-out-of-range case. The constructor tests
    // above (`rejects_out_of_range_and_nan`, `rejects_negative_infinity`)
    // cover them instead.

    // --- AC-1.10 (schema half): the published JSON Schema also carries
    // the `[0.0, 1.0]` bound via `minimum`/`maximum`, not just the
    // runtime construction/deserialization checks below. The brief's
    // literal Step 3 code block only annotated `NonEmpty` with
    // `#[schemars(length(min = 1))]`; `#[schemars(range(min = 0.0, max =
    // 1.0))]` was added here too, by analogy, so a schema consumer gets
    // the same guarantee a Rust caller gets. Proven concretely, per the
    // review guidance not to let an impl compile, satisfy the trait, and
    // emit an unconstrained schema unnoticed.

    #[test]
    fn confidence_json_schema_has_expected_range() {
        let schema = schemars::schema_for!(Confidence);
        let value = serde_json::to_value(&schema).unwrap();
        assert_eq!(value.get("type").and_then(|v| v.as_str()), Some("number"));
        assert_eq!(value.get("minimum").and_then(|v| v.as_f64()), Some(0.0));
        assert_eq!(value.get("maximum").and_then(|v| v.as_f64()), Some(1.0));
    }
}
