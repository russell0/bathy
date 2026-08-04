//! The eight clean-room protocol probes.
//!
//! Every submodule here documents, in its own `source:` doc comment, the
//! exact evidentiary basis for the bytes it sends: an RFC section, a
//! vendor's own protocol documentation, or a capture of software this
//! task's author ran themselves, locally, in a Docker container (with the
//! image and digest recorded) -- never anything read from, derived from,
//! or checked against Nmap's `nmap-service-probes` or `nmap-services`,
//! which are present on this development machine but out of bounds for
//! this milestone's clean-room requirement. See this task's report for the
//! full list of images, digests, and raw capture output.
//!
//! `no_probe_source_mentions_nmap` below is the structural half of that
//! promise: it does not just ask a reviewer to notice, it greps this
//! crate's own committed source text for the word and fails the build if
//! it ever appears.

pub mod dns;
pub mod http;
pub mod mysql;
pub mod postgres;
pub mod redis;
pub mod smtp;
pub mod ssh;
pub mod tls;

#[cfg(test)]
pub(crate) mod test_support;

use std::time::Instant;

use bathy_types::ProbeCapture;

use crate::framework::ProbeIo;

/// Assembles a [`ProbeCapture`] from the pieces every probe's `execute`
/// produces, so each probe file states only what differs (its id, its
/// request bytes if any, and how it drives `io`) rather than repeating the
/// same five-field struct literal eight times.
pub(crate) fn finish_capture(
    id: &'static str,
    io: &ProbeIo,
    request: Option<Vec<u8>>,
    start: Instant,
    response: Vec<u8>,
    truncated: bool,
) -> ProbeCapture {
    ProbeCapture {
        probe_id: id,
        transport: io.transport(),
        port: io.port(),
        request,
        response,
        elapsed_micros: start.elapsed().as_micros() as u64,
        truncated,
    }
}

#[cfg(test)]
mod tests {
    /// Every probe file's raw source text, gathered with `include_str!` so
    /// this check runs against exactly what is committed, not against a
    /// separately maintained list that could drift from it.
    const PROBE_FILES: &[(&str, &str)] = &[
        ("http.rs", include_str!("http.rs")),
        ("tls.rs", include_str!("tls.rs")),
        ("ssh.rs", include_str!("ssh.rs")),
        ("smtp.rs", include_str!("smtp.rs")),
        ("dns.rs", include_str!("dns.rs")),
        ("postgres.rs", include_str!("postgres.rs")),
        ("mysql.rs", include_str!("mysql.rs")),
        ("redis.rs", include_str!("redis.rs")),
    ];

    /// The register the two clean-room checks below iterate over must name
    /// **every** probe module, or those checks are a promise about whichever
    /// files somebody remembered.
    ///
    /// Not a hand-written count: the truth is the `pub mod` list at the top of
    /// this very file, read back through `include_str!`, so adding a probe
    /// without adding it here fails rather than quietly narrowing the scan.
    /// The M5 close-out review found this shape elsewhere in the tree
    /// (`FIELDS_ADDED_AFTER_THE_LOG_EXISTED`, emptied, and its test still
    /// passed); this file had the same hole with more riding on it -- an empty
    /// or short `PROBE_FILES` turns the structural half of the clean-room
    /// promise into a loop that runs zero times and reports `ok`.
    #[test]
    fn the_register_names_every_probe_module_or_the_two_checks_below_are_partial() {
        let declared: Vec<String> = include_str!("mod.rs")
            .lines()
            .filter_map(|line| line.strip_prefix("pub mod "))
            .filter_map(|rest| rest.strip_suffix(';'))
            .map(|name| format!("{name}.rs"))
            .collect();
        assert!(
            !declared.is_empty(),
            "no `pub mod` line was found in this file, so the comparison below is \
             vacuous in the other direction"
        );
        let mut registered: Vec<String> = PROBE_FILES
            .iter()
            .map(|(name, _)| (*name).to_owned())
            .collect();
        let mut declared_sorted = declared.clone();
        registered.sort();
        declared_sorted.sort();
        assert_eq!(
            registered, declared_sorted,
            "PROBE_FILES and this module's `pub mod` declarations disagree; a probe \
             missing from the register is a probe neither clean-room check reads"
        );
    }

    #[test]
    fn every_probe_file_documents_a_source() {
        for (name, text) in PROBE_FILES {
            assert!(
                text.contains("source:"),
                "{name} has no `source:` doc comment naming its evidentiary basis"
            );
        }
    }

    #[test]
    fn no_probe_source_mentions_nmap() {
        for (name, text) in PROBE_FILES {
            let lower = text.to_lowercase();
            assert!(
                !lower.contains("nmap"),
                "{name} mentions nmap; every probe's request bytes must be clean-room \
                 (an RFC, vendor documentation, or a capture run by this task's author \
                 against software they ran themselves)"
            );
        }
    }

    // --- `ProbeKind` gets a reader (M4 whole-branch review).
    //
    // The review's production-caller census found that every one of the
    // eight probes declares `ListenFirst`/`SendFirst` and **nothing ever
    // reads it** -- `select_probes` does not consult it, `detect_service`
    // does not consult it -- and asked for a decision: wire it or delete
    // it, because "a field with no reader is a claim nothing checks."
    //
    // Decision: KEEP it, and give it the reader it was missing. Deleting
    // was the tempting option (the behaviour is implemented in each
    // `execute` and already pinned at the wire level for SSH and MySQL),
    // but it is the wrong one. `Probe` is a PUBLIC trait: an out-of-tree
    // probe is expected to implement it, and `kind()` is the only place its
    // author declares this property at all. Deleting it would not remove
    // the concept, only the ability to state it -- and the failure it
    // guards against is real and silent. A probe that listens first when it
    // should speak first hangs until its deadline against every endpoint it
    // touches, producing `EmptyResponse` rather than an error, which is the
    // same shape of invisible false negative as CRITICAL-1's.
    //
    // So `kind()` stays, and the test below reads it -- for all eight
    // probes, against a real socket. That converts it from an unchecked
    // assertion into a specification checked against the implementation,
    // which is what the finding actually asks for. It is not a production
    // reader and is not claimed to be one; nothing in the scan path has a
    // decision to make from it. The claim being checked is the contract,
    // and this is where contracts get checked.
    //
    // Note `ListenFirst` means "reads before writing", NOT "never writes":
    // `smtp-banner-v1` is `ListenFirst` and does send `EHLO`, after the
    // greeting. The existing `ssh_probe_never_writes_to_the_socket_even_
    // when_it_would_be_read` and `mysql_probe_never_writes_to_the_socket`
    // assert the stronger never-writes property for the two probes where it
    // holds; this asserts the weaker one that holds for all eight, which is
    // exactly what `kind()` declares.

    use crate::framework::{ProbeIo, ProbeKind, ProbeRegistry};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn every_probe_speaks_or_listens_first_exactly_as_its_probe_kind_declares() {
        for probe in ProbeRegistry::standard().all() {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            // Set iff the peer sent us bytes BEFORE we sent it any.
            let wrote_first = Arc::new(AtomicBool::new(false));
            let observed = Arc::clone(&wrote_first);

            let server = tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let (mut sock, _) = listener.accept().await.unwrap();
                // Say nothing, and wait. A send-first probe writes its
                // request here; a listen-first probe is blocked waiting for
                // us, so this read times out at zero bytes.
                let mut buf = [0u8; 1024];
                let first =
                    tokio::time::timeout(Duration::from_millis(250), sock.read(&mut buf)).await;
                if matches!(first, Ok(Ok(n)) if n > 0) {
                    observed.store(true, Ordering::SeqCst);
                }
                // Now answer, so a listen-first probe can make progress and
                // `execute` returns instead of burning its whole deadline.
                let _ = sock.write_all(b"220 x\r\n").await;
                // Drain whatever it says next (e.g. SMTP's EHLO) so the
                // probe's own write cannot block on a full buffer.
                let mut sink = [0u8; 1024];
                let _ =
                    tokio::time::timeout(Duration::from_millis(250), sock.read(&mut sink)).await;
            });

            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut io = ProbeIo::new(stream, addr.port(), Duration::from_millis(300));
            let _ = probe.execute(&mut io).await;
            drop(io);
            server.await.unwrap();

            let observed_kind = if wrote_first.load(Ordering::SeqCst) {
                ProbeKind::SendFirst
            } else {
                ProbeKind::ListenFirst
            };
            assert_eq!(
                observed_kind,
                probe.kind(),
                "{} declares kind() == {:?} but on a real socket it behaved as {:?}. \
                 A send-first probe that actually listens first hangs until its deadline \
                 against every endpoint it touches and reports EmptyResponse rather than an \
                 error; a listen-first probe that actually speaks first can corrupt a \
                 server-greets-you protocol's session. Fix whichever of the two is wrong.",
                probe.id(),
                probe.kind(),
                observed_kind
            );
        }
    }
}
