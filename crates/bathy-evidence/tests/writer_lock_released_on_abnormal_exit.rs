//! C5: `EventLog::open`'s writer-exclusion lock must be released not only
//! when the holder drops cleanly (covered in-process by
//! `log::tests::the_writer_lock_is_released_once_the_first_handle_is_dropped`)
//! but also when the holder's process is killed abnormally -- a real crash,
//! not an orderly shutdown. That can't be simulated within one process (an
//! in-process `Drop` is by definition the orderly case), so this test spawns
//! a genuine child process that acquires the lock, SIGKILLs it, and confirms
//! this process can then open the same log.
//!
//! This relies on `fs4`'s advisory lock being backed by a real OS primitive
//! (`flock(2)` on Unix, `LockFileEx` on Windows), which the OS releases when
//! the holding process's file descriptor is closed for *any* reason,
//! including a kill signal -- not something this crate's own `Drop` impl
//! arranges, since a `SIGKILL`'d process never runs its destructors at all.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use bathy_evidence::EventLog;
use bathy_types::ids::ScanId;

fn scan_id() -> ScanId {
    "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap()
}

/// Not a normal test in its own right: does nothing unless
/// `BATHY_HOLD_LOCK_CHILD_DIR` is set, which only the test below ever sets,
/// on a child process it spawns of this very same test binary. Under a
/// plain `cargo test` run (the env var absent), this returns immediately
/// and passes trivially -- it exists to be re-invoked as a subprocess, not
/// to assert anything on its own.
#[test]
fn hold_lock_child() {
    let Ok(dir) = std::env::var("BATHY_HOLD_LOCK_CHILD_DIR") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let _log = EventLog::open(&dir, scan_id()).expect("child must acquire the lock");
    std::fs::write(dir.join("child-locked"), b"1").expect("child must signal it holds the lock");
    // Block "forever" -- the parent test SIGKILLs this process well before
    // this would ever elapse.
    std::thread::sleep(Duration::from_secs(3600));
}

#[test]
fn writer_lock_is_released_when_the_holder_is_killed_not_just_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let exe = std::env::current_exe().expect("test binary must know its own path");

    let mut child = Command::new(&exe)
        .arg("hold_lock_child")
        .arg("--exact")
        .arg("--nocapture")
        .env("BATHY_HOLD_LOCK_CHILD_DIR", dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn child process holding the lock");

    let sentinel = dir.path().join("child-locked");
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if sentinel.exists() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "child never signalled that it acquired the lock"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    // Sanity check: while the child holds the lock, a second open from THIS
    // process must fail -- otherwise the rest of this test would prove
    // nothing about the lock at all.
    assert!(
        EventLog::open(dir.path(), scan_id()).is_err(),
        "the log must be locked while the child holds it"
    );

    child.kill().expect("failed to SIGKILL the child process");
    child.wait().expect("failed to reap the killed child");

    let reopened = EventLog::open(dir.path(), scan_id());
    assert!(
        reopened.is_ok(),
        "the lock must be released after the holder is killed, not just \
         when it exits cleanly: {reopened:?}"
    );
}
