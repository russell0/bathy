//! Asking a scan running in another process to stop.
//!
//! A running scan holds a [`CancellationToken`](tokio_util::sync::CancellationToken)
//! that only its own process can reach, so `bathy scan cancel` and the MCP
//! server's `scan.cancel` tool cannot cancel it directly. A marker file in the
//! state directory is the smallest thing that works across processes without a
//! daemon, a socket or a signal, and it degrades correctly: if no scan is
//! running the marker simply sits there, and a start or resume clears it
//! before beginning so it can never silently cancel a *later* scan.
//!
//! This lives here, beside the scheduler the marker exists to stop, rather
//! than in either adapter. Both the command-line surface and the tool surface
//! must agree on the path and on when it is cleared, and a protocol with two
//! implementations is a protocol that will eventually have two answers -- a
//! scan started through one surface and cancelled through the other would
//! keep running.

use std::path::{Path, PathBuf};
use std::time::Duration;

use bathy_types::ids::ScanId;
use tokio_util::sync::CancellationToken;

/// How often a running scan checks for the marker.
pub const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Path of the file a cancel request creates and a running scan polls.
pub fn marker_path(state_dir: &Path, scan_id: ScanId) -> PathBuf {
    state_dir.join("cancel").join(format!("{scan_id}.cancel"))
}

/// Ask the scan to stop. Idempotent.
pub fn request(state_dir: &Path, scan_id: ScanId) -> std::io::Result<()> {
    let path = marker_path(state_dir, scan_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, b"cancel\n")
}

/// Remove any standing request. Called before a scan begins, so a stale
/// marker cannot cancel a run that had not started when it was written.
pub fn clear(state_dir: &Path, scan_id: ScanId) {
    let _ = std::fs::remove_file(marker_path(state_dir, scan_id));
}

pub fn requested(state_dir: &Path, scan_id: ScanId) -> bool {
    marker_path(state_dir, scan_id).exists()
}

/// Spawn a task that cancels `token` as soon as a marker appears.
///
/// The returned handle must be aborted once the scan it watches has finished,
/// so the poller cannot outlive it.
pub fn spawn_watcher(
    state_dir: &Path,
    scan_id: ScanId,
    token: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    let dir = state_dir.to_path_buf();
    tokio::spawn(async move {
        loop {
            if requested(&dir, scan_id) {
                token.cancel();
                return;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan() -> ScanId {
        "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap()
    }

    #[test]
    fn a_request_is_visible_to_a_second_reader_and_clearing_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!requested(dir.path(), scan()));
        request(dir.path(), scan()).unwrap();
        assert!(requested(dir.path(), scan()));
        clear(dir.path(), scan());
        assert!(!requested(dir.path(), scan()));
    }

    #[test]
    fn the_marker_is_per_scan_not_per_directory() {
        let dir = tempfile::tempdir().unwrap();
        let other: ScanId = "scan_01ARZ3NDEKTSV4RRFFQ69G5FAW".parse().unwrap();
        request(dir.path(), scan()).unwrap();
        assert!(
            !requested(dir.path(), other),
            "cancelling one scan must not cancel every scan in the directory"
        );
    }

    #[test]
    fn clearing_a_marker_that_was_never_written_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        clear(dir.path(), scan());
    }

    #[tokio::test]
    async fn the_watcher_cancels_its_token_when_a_marker_appears() {
        let dir = tempfile::tempdir().unwrap();
        let token = CancellationToken::new();
        let handle = spawn_watcher(dir.path(), scan(), token.clone());
        assert!(!token.is_cancelled());
        request(dir.path(), scan()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), token.cancelled())
            .await
            .expect("the watcher must observe the marker");
        handle.abort();
    }
}
