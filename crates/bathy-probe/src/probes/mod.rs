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
}
