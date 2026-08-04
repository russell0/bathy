//! Where a scan's durable state lives, and the small amount of cross-process
//! signalling the CLI needs on top of it.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use bathy_types::clock::{Clock, SystemClock};
use bathy_types::ids::ScanId;

use crate::exit::CliError;

/// Resolve `--state-dir`, `$BATHY_STATE_DIR`, then `$HOME/.local/share/bathy`.
///
/// The directory holds `state.sqlite` (`bathy-store`), one `<scan_id>.jsonl`
/// per scan (`bathy-evidence`'s log) and the content-addressed blob store,
/// all rooted at the same path so a scan's evidence, log and lifecycle
/// record cannot end up in three different places.
pub fn resolve_state_dir(explicit: Option<PathBuf>) -> Result<PathBuf, CliError> {
    if let Some(dir) = explicit {
        return Ok(dir);
    }
    if let Some(dir) = std::env::var_os("BATHY_STATE_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var_os("HOME").ok_or_else(|| {
        CliError::operational(
            "no_state_dir",
            "neither --state-dir nor $BATHY_STATE_DIR nor $HOME is set",
        )
    })?;
    Ok(PathBuf::from(home).join(".local/share/bathy"))
}

/// The one clock every component in a run shares.
///
/// C2/M2: `TaskStore` and `Scheduler` must be handed the *same*
/// `Arc<dyn Clock>`, never two independently constructed ones -- two clocks
/// means two ULID generators and identifier collisions, which has already
/// happened once in this repository.
pub fn clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock::default())
}

// The cancel-marker protocol moved to `bathy_engine::cancel` when the MCP
// server became a second surface that has to speak it. A scan started
// through one surface and cancelled through the other must actually stop,
// and that cannot be true of a protocol with two implementations. These are
// thin adapters onto the shared one, kept so the call sites below read the
// same as they did.

pub fn request_cancel(state_dir: &Path, scan_id: ScanId) -> Result<(), CliError> {
    bathy_engine::cancel::request(state_dir, scan_id)
        .map_err(|e| CliError::operational("state_dir_unwritable", e))
}

pub fn clear_cancel(state_dir: &Path, scan_id: ScanId) {
    bathy_engine::cancel::clear(state_dir, scan_id);
}

pub fn parse_scan_id(s: &str) -> Result<ScanId, CliError> {
    s.parse::<ScanId>()
        .map_err(|e| CliError::operational("bad_scan_id", e))
}
