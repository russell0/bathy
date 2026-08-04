//! `bathy evidence get`.

use std::io::Write;
use std::path::Path;

use bathy_evidence::EvidenceStore;
use bathy_types::ids::Digest;

use crate::emit::{Emitter, Mode};
use crate::exit::{CliError, ExitCode};

/// Lowercase hex, because evidence is arbitrary response bytes and JSON has
/// no byte string.
///
/// Hex rather than base64 so this crate needs no encoder dependency for one
/// field, and so a human comparing a short banner against a packet capture
/// can read it. `EvidenceStore::get` has already verified the bytes hash to
/// the digest that was asked for, so what is rendered here is the evidence
/// or it is an error -- never something in between.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn get(digest: &str, state_dir: &Path, emitter: &Emitter) -> Result<ExitCode, CliError> {
    let digest: Digest = digest
        .parse()
        .map_err(|e| CliError::operational("bad_digest", e))?;
    let store = EvidenceStore::open(state_dir)
        .map_err(|e| CliError::operational("evidence_unavailable", e))?;
    let bytes = store
        .get(&digest)
        .map_err(|e| CliError::operational("no_such_evidence", e))?;

    match emitter.mode() {
        Mode::Json => {
            emitter.result(
                serde_json::json!({
                    "digest": digest.to_string(),
                    "length": bytes.len(),
                    "bytes_hex": hex(&bytes),
                }),
                "",
            );
        }
        Mode::Human => {
            // The raw bytes, unmodified and with no trailing newline of our
            // own: this is the one command whose output a caller may want to
            // pipe into a file and hash.
            let mut out = std::io::stdout().lock();
            let _ = out.write_all(&bytes);
            let _ = out.flush();
        }
    }
    Ok(ExitCode::Success)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_lowercase_and_two_characters_per_byte() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff, 0xa5]), "000fffa5");
        assert_eq!(hex(&[]), "");
    }
}
