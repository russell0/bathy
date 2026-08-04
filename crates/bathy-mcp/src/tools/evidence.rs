//! `evidence.get`.

use bathy_types::tools::{EvidenceGetInput, EvidenceGetOutput};

use crate::engine::Runtime;
use crate::error::{ToolResult, evidence_error};

/// Lowercase hex, two characters per byte.
///
/// Hex rather than base64 for the same three reasons the command-line surface
/// chose it: no encoder dependency for one field, a human comparing a short
/// banner against a packet capture can read it, and the digest that names the
/// bytes is written the same way. The M5 plan's contract table said base64;
/// two encodings of one contract is worse than either encoding, and the
/// shipped surface already published this one.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub fn get(input: EvidenceGetInput, runtime: &Runtime) -> ToolResult<EvidenceGetOutput> {
    // `get` verifies the bytes against the digest that named them, so what
    // comes back is the evidence or it is an error, never something between.
    let bytes = runtime
        .evidence
        .get(&input.digest)
        .map_err(evidence_error)?;
    let length = bytes.len() as u64;

    let (returned, truncated) = match input.max_bytes {
        Some(max) if length > max => (&bytes[..max as usize], true),
        _ => (&bytes[..], false),
    };

    Ok(EvidenceGetOutput {
        digest: input.digest,
        length,
        truncated,
        bytes_hex: hex(returned),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_lowercase_and_two_characters_per_byte() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff, 0xa5]), "000fffa5");
        assert_eq!(hex(&[]), "");
    }

    #[test]
    fn a_cap_of_zero_returns_nothing_and_says_it_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = Runtime::open(dir.path()).unwrap();
        let digest = runtime.evidence.put(b"hello").unwrap();

        let all = get(
            EvidenceGetInput {
                digest,
                max_bytes: None,
            },
            &runtime,
        )
        .unwrap();
        assert_eq!(all.bytes_hex, "68656c6c6f");
        assert_eq!(all.length, 5);
        assert!(!all.truncated);

        let capped = get(
            EvidenceGetInput {
                digest,
                max_bytes: Some(0),
            },
            &runtime,
        )
        .unwrap();
        assert_eq!(capped.bytes_hex, "");
        assert!(capped.truncated);
        assert_eq!(
            capped.length, 5,
            "`length` is what is stored, not what was returned; an agent \
             deciding whether to ask again needs the former"
        );
    }

    #[test]
    fn a_cap_at_or_above_the_stored_length_does_not_claim_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = Runtime::open(dir.path()).unwrap();
        let digest = runtime.evidence.put(b"hello").unwrap();
        for max in [5, 6, 1000] {
            let out = get(
                EvidenceGetInput {
                    digest,
                    max_bytes: Some(max),
                },
                &runtime,
            )
            .unwrap();
            assert!(!out.truncated, "max_bytes={max}");
            assert_eq!(out.bytes_hex, "68656c6c6f");
        }
    }

    #[test]
    fn a_digest_that_names_nothing_is_a_typed_refusal_rather_than_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = Runtime::open(dir.path()).unwrap();
        let absent = format!("blake3:{}", "0".repeat(64)).parse().unwrap();
        assert_eq!(
            get(
                EvidenceGetInput {
                    digest: absent,
                    max_bytes: None
                },
                &runtime
            )
            .unwrap_err()
            .error,
            "no_such_evidence"
        );
    }
}
