//! `bathy evidence get`.
//!
//! The `evidence.get` tool function, rendered. The truncation and the hex
//! encoding are its, not a second copy: `--max-bytes` is the flag that was
//! missing when the tool could cap a response and this command could not,
//! and `truncated` is the field an agent reads to know whether to ask again.

use std::io::Write;
use std::path::Path;

use bathy_mcp::engine::Runtime;
use bathy_mcp::tools;
use bathy_types::ids::Digest;
use bathy_types::tools::EvidenceGetInput;

use crate::cli::EvidenceGetArgs;
use crate::emit::{Emitter, Mode};
use crate::exit::{CliError, ExitCode};

/// Hex back to bytes, for the human mode that writes the evidence itself.
///
/// The round trip is deliberate: it keeps one implementation of "which bytes
/// does this digest name, and how many of them did you ask for" rather than
/// two that agree until one of them is changed.
fn unhex(text: &str) -> Result<Vec<u8>, CliError> {
    if !text.len().is_multiple_of(2) {
        return Err(CliError::operational(
            "evidence_unreadable",
            "the evidence tool returned an odd number of hex digits",
        ));
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&text[i..i + 2], 16)
                .map_err(|e| CliError::operational("evidence_unreadable", e))
        })
        .collect()
}

pub fn get(
    args: &EvidenceGetArgs,
    state_dir: &Path,
    emitter: &Emitter,
) -> Result<ExitCode, CliError> {
    let digest: Digest = args
        .digest
        .parse()
        .map_err(|e| CliError::operational("bad_digest", e))?;
    let runtime =
        Runtime::open(state_dir).map_err(|e| CliError::operational("state_unavailable", e))?;
    let out = tools::evidence::get(
        EvidenceGetInput {
            digest,
            max_bytes: args.max_bytes,
        },
        &runtime,
    )
    .map_err(CliError::from_tool)?;

    match emitter.mode() {
        Mode::Json => {
            let value = serde_json::to_value(&out)
                .map_err(|e| CliError::operational("encode_failed", e))?;
            emitter.result(value, "");
        }
        Mode::Human => {
            // The raw bytes, unmodified and with no trailing newline of our
            // own: this is the one command whose output a caller may want to
            // pipe into a file and hash. Under `--max-bytes` they are a
            // prefix, and the note on stderr is how a human knows -- stdout
            // stays exactly the bytes.
            let bytes = unhex(&out.bytes_hex)?;
            let mut stdout = std::io::stdout().lock();
            let _ = stdout.write_all(&bytes);
            let _ = stdout.flush();
            if out.truncated {
                emitter.note(format!(
                    "{} of {} byte(s); --max-bytes cut this short",
                    bytes.len(),
                    out.length
                ));
            }
        }
    }
    Ok(ExitCode::Success)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_refuses_a_half_byte() {
        assert_eq!(unhex("000fffa5").unwrap(), vec![0x00, 0x0f, 0xff, 0xa5]);
        assert_eq!(unhex("").unwrap(), Vec::<u8>::new());
        assert!(unhex("abc").is_err());
        assert!(unhex("zz").is_err());
    }
}
