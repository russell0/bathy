//! AC-6.5 and AC-6.6, established against the real binary, from outside it.
//!
//! # Why not the self-check report
//!
//! The plan's test for AC-6.5 reads `--self-check`'s own
//! `first_input_read_after_drop` field and asserts it is `true`. That field
//! exists and is measured, but a process reporting on its own ordering can be
//! wrong about it in exactly the way that matters: the bookkeeping and the
//! behaviour are two things, and it is the behaviour the criterion is about.
//!
//! So [`the_capability_set_is_empty_before_a_single_byte_of_input_exists`]
//! does not ask the daemon anything. It **withholds every byte of the
//! daemon's input** -- the pipe is open and empty, and this test is the only
//! thing that can write to it -- and watches `/proc/<pid>/status` from the
//! parent until `CapEff` reads all zeros. Only then does it send the first
//! line. A byte of input therefore cannot exist until after the drop has been
//! observed by a process other than the one that performed it.
//!
//! **It fails when the order changes, not only when a step is deleted**,
//! which is what the Global Constraint on ordering guarantees requires and
//! what M3's durability inversion is the standing example of. Move
//! `drop_all_capabilities()` below the first read and the daemon blocks
//! forever on a pipe nobody will write to, `CapEff` never empties, and this
//! test fails on its deadline. Delete the drop and it fails the same way.
//! Move it *above* `acquire_raw_sockets()` and the daemon exits 69 before
//! reading anything, which the loop notices and reports.
//!
//! # What makes it non-vacuous
//!
//! A test that watched for "no capabilities" in an environment that never had
//! any would pass over nothing. Two things exclude that:
//!
//! 1. The harness asserts *its own* `CapEff` is non-zero before it starts.
//!    The child inherits that set across `fork`, so "empty" is a state the
//!    child had to reach rather than one it started in.
//! 2. The daemon answers `ready`. It can only get there through
//!    `acquire_raw_sockets`, which needs `CAP_NET_RAW` and exits 69 without
//!    it -- so a run that produces a response is a run that was privileged.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PACKETD: &str = env!("CARGO_BIN_EXE_bathy-packetd");

/// Set to `1` by `cargo run -p xtask -- packetd-privileged`, which runs this
/// file in a container holding `CAP_NET_RAW`.
///
/// Its only job is to turn a skip into a failure. A privileged test that
/// silently does nothing on an unprivileged machine is how a suite comes to
/// report coverage it does not have, and this whole file is about the one
/// property in the repository where that would matter most.
const DEMAND: &str = "BATHY_PACKETD_PRIVILEGED_TESTS";

const INIT_LINE: &str = concat!(
    r#"{"type":"init","allowed_cidrs":["10.30.0.0/24"],"denied_cidrs":[],"#,
    r#""packets_per_second":100,"max_packets":1000}"#,
    "\n"
);

/// The `CapEff:` line of a process's status, as text.
///
/// Deliberately not `bathy_packetd::privilege::parse_status`: the point of
/// this file is to observe the capability set with something other than the
/// code that dropped it. A mutated parser must not be able to make this test
/// agree with it.
fn cap_eff_of(pid: u32) -> Option<String> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = text.lines().find(|line| line.starts_with("CapEff:"))?;
    Some(line.split_whitespace().nth(1)?.to_string())
}

fn cap_eff_of_this_process() -> Option<String> {
    cap_eff_of(std::process::id())
}

fn all_zero(mask: &str) -> bool {
    !mask.is_empty() && mask.bytes().all(|b| b == b'0')
}

/// Announces a skipped precondition on the process's own stderr.
///
/// `write_all` and not a print macro: libtest captures the print macros and
/// throws the capture away for a test that *passes*, and a test that returns
/// early passes. A reason announced through `eprintln!` is a reason nobody
/// ever sees, which is strictly worse than no test, because the green is read
/// as coverage. (This repository has shipped that defect twice; the pattern
/// rule `captured-skip-message` exists because of it.)
fn announce(reason: &str) {
    let mut stderr = std::io::stderr();
    let _ = stderr.write_all(reason.as_bytes());
    let _ = stderr.write_all(b"\n");
    let _ = stderr.flush();
}

/// Whether this process holds a capability, and therefore whether the daemon
/// it spawns can. Returns `false` after announcing why -- unless the
/// privileged run was demanded, in which case an unprivileged environment is
/// a failure rather than a skip.
fn privileged_or_skip(test: &str) -> bool {
    let demanded = std::env::var(DEMAND).as_deref() == Ok("1");
    let mask = cap_eff_of_this_process();
    let privileged = mask.as_deref().is_some_and(|m| !all_zero(m));
    if privileged {
        return true;
    }
    assert!(
        !demanded,
        "{DEMAND}=1 was set, so {test} must run, but this process holds no capability \
         (CapEff={mask:?}). Run it under `cargo run -p xtask -- packetd-privileged`."
    );
    announce(&format!(
        "PRECONDITION ABSENT: {test} needs a process holding CAP_NET_RAW and this one has \
         CapEff={mask:?}. It did not run. `cargo run -p xtask -- packetd-privileged` runs \
         this file in a container that has it."
    ));
    false
}

struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// AC-6.5. See this module's header for what makes it an ordering test.
#[test]
fn the_capability_set_is_empty_before_a_single_byte_of_input_exists() {
    let name = "the_capability_set_is_empty_before_a_single_byte_of_input_exists";
    if !privileged_or_skip(name) {
        return;
    }
    let harness = cap_eff_of_this_process().unwrap_or_default();
    assert!(
        !all_zero(&harness),
        "the child inherits this process's capability set across fork, so a harness with an \
         empty CapEff would make `empty` a state the daemon started in rather than one it \
         reached: CapEff={harness}"
    );

    let child = Command::new(PACKETD)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning packetd");
    let pid = child.id();
    let mut guard = Guard(child);

    // Nothing is written to the pipe in this loop. The daemon's only source
    // of input is the handle held below, so until it is written to there is
    // no byte of input in existence for the daemon to have read.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(Some(status)) = guard.0.try_wait() {
            panic!(
                "packetd exited ({status}) before its capability set emptied. Exit 69 means it \
                 never held CAP_NET_RAW; anything else means it refused to run. Either way it \
                 did not reach the state this criterion is about."
            );
        }
        match cap_eff_of(pid) {
            Some(mask) if all_zero(&mask) => break,
            Some(_) | None => {}
        }
        assert!(
            Instant::now() < deadline,
            "packetd's CapEff was still {:?} after 15s with no input ever written to its \
             stdin. A daemon that drops capabilities before reading reaches all-zeros in \
             milliseconds without being sent anything; one that reads first waits here \
             forever, which is what moving the drop below the first read looks like from \
             outside.",
            cap_eff_of(pid)
        );
        std::thread::sleep(Duration::from_millis(2));
    }

    // The drop has now been observed by a process other than the one that
    // performed it. Only now does a byte of input exist.
    let mut stdin = guard.0.stdin.take().expect("stdin pipe");
    stdin.write_all(INIT_LINE.as_bytes()).expect("writing init");
    stdin.flush().expect("flushing init");

    let stdout = guard.0.stdout.take().expect("stdout pipe");
    let line = first_line_within(stdout, Duration::from_secs(15));

    assert!(
        line.contains(r#""type":"ready""#),
        "packetd answered a valid init with {line:?}"
    );
    // It answered, so it got past `acquire_raw_sockets`, so it held
    // CAP_NET_RAW when it started -- which is what makes the zeros above a
    // drop rather than an absence.
    assert!(
        line.contains(r#""dropped_capabilities":true"#),
        "the ready line must relay what the daemon measured after dropping: {line:?}"
    );

    drop(stdin);
    let status = guard.0.wait().expect("waiting for packetd");
    assert!(
        status.success(),
        "a session ended by closing the pipe is a clean end: {status}"
    );
}

/// Reads one line, or kills the test rather than hanging the suite.
fn first_line_within(stdout: std::process::ChildStdout, within: Duration) -> String {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let read = BufReader::new(stdout).read_line(&mut line);
        let _ = tx.send(read.map(|_| line));
    });
    match rx.recv_timeout(within) {
        Ok(Ok(line)) => line,
        Ok(Err(e)) => panic!("reading packetd's response: {e}"),
        Err(e) => panic!("packetd sent no response line within {within:?}: {e}"),
    }
}

/// AC-6.6 in the unprivileged direction and AC-6.5's negative in the
/// privileged one, in one test because the two are the *same run* under
/// different capabilities and each is the other's narrowing control.
///
/// Both branches assert. The plan's version of this test wrapped its
/// assertions in `if !out.status.success()`, so on any machine that *could*
/// open a raw socket it asserted nothing at all and passed -- which is the
/// shape of every test in this repository that turned out to be checking
/// nothing.
#[test]
fn the_self_check_either_reports_a_measured_drop_or_says_exactly_how_to_grant_the_capability() {
    let out = Command::new(PACKETD)
        .arg("--self-check")
        .stdin(Stdio::null())
        .output()
        .expect("running packetd --self-check");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

    if out.status.success() {
        let report: serde_json::Value =
            serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("{e}: {stdout:?}"));
        for claim in [
            "sockets_opened",
            "capabilities_dropped",
            "no_new_privs",
            "first_input_read_after_drop",
            "raw_socket_after_drop_denied",
        ] {
            assert_eq!(
                report.get(claim),
                Some(&serde_json::Value::Bool(true)),
                "{claim} in {stdout}"
            );
        }
        // The masks, read back as the strings `/proc/self/status` renders,
        // so this is not the same boolean twice.
        for mask in [
            "effective_capabilities",
            "permitted_capabilities",
            "inheritable_capabilities",
            "ambient_capabilities",
        ] {
            assert_eq!(
                report.get(mask).and_then(|v| v.as_str()),
                Some("0000000000000000"),
                "{mask} in {stdout}"
            );
        }
        assert!(
            !stderr.contains("setcap"),
            "a successful run must not tell the operator to grant anything: {stderr}"
        );
        // Independently: the process that just ran was able to open a raw
        // socket, so this one should be too. If it cannot, `sockets_opened`
        // above was true for some other reason than privilege.
        assert!(
            cap_eff_of_this_process().is_some_and(|m| !all_zero(&m)),
            "packetd opened raw sockets from an environment this harness measures as \
             holding no capability at all"
        );
    } else {
        assert!(
            !std::env::var(DEMAND).as_deref().is_ok_and(|v| v == "1"),
            "{DEMAND}=1 demands the privileged branch, and --self-check exited {:?}: {stderr}",
            out.status.code()
        );
        assert_eq!(
            out.status.code(),
            Some(69),
            "EX_UNAVAILABLE is what the engine branches on to fall back: {stderr}"
        );
        assert!(stderr.contains("CAP_NET_RAW"), "{stderr}");
        assert!(
            stderr.contains("sudo setcap cap_net_raw+ep $(which bathy-packetd)"),
            "the command has to be copy-pasteable, not described: {stderr}"
        );
        assert!(
            stderr.contains("bathy will fall back to connect scanning"),
            "{stderr}"
        );
    }
}

/// The daemon must not answer a probe -- or anything else -- before it has
/// been told its scope, and that has to be true of the *process*, not only of
/// the `Session` type M6 Task 1 unit-tests. This is the one assertion in this
/// file that needs no privilege, and it is here because the wiring between
/// `read_line`, `Session` and the exit status is Task 2's code.
#[test]
fn a_probe_before_init_kills_the_process_with_a_fatal_line() {
    if !privileged_or_skip("a_probe_before_init_kills_the_process_with_a_fatal_line") {
        return;
    }
    let mut child = Command::new(PACKETD)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning packetd");
    let mut stdin = child.stdin.take().expect("stdin pipe");
    let _ = stdin.write_all(br#"{"type":"probe","id":1,"target":"10.30.0.7","port":80}"#);
    let _ = stdin.write_all(b"\n");
    let _ = stdin.flush();
    drop(stdin);
    let out = child.wait_with_output().expect("waiting for packetd");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(stdout.contains(r#""type":"fatal""#), "{stdout}");
    assert_eq!(
        out.status.code(),
        Some(1),
        "a fatal session must end the process non-zero: {stdout}"
    );
}
