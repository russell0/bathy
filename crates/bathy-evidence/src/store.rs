use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use bathy_types::ids::Digest;

#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error("evidence io at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("no evidence stored for {0}")]
    NotFound(Digest),
    #[error("stored bytes for {digest} do not hash to their digest; store is corrupt")]
    Corrupt { digest: Digest },
}

/// Immutable, content-addressed blob store.
///
/// Evidence is always written *before* the event that references it, so an
/// `evidence_refs` entry can never dangle. Because the key is the hash,
/// writes are idempotent and identical responses across hosts cost one copy.
///
/// C1: "written before" is a durability claim, not just a program-order
/// claim -- `store.rs`'s own module doc and `put`'s doc below promise that
/// once `put` returns `Ok`, the digest is durably retrievable, and M4
/// depends on that ordering surviving a crash, not merely a bug. `durable`
/// (set by [`Self::open`] vs [`Self::open_without_durability_barrier`])
/// controls whether `put` actually pays for that guarantee with an
/// `fsync`, per the finding's requirement that any opt-out be explicit in
/// a named constructor, never a silent default.
pub struct EvidenceStore {
    root: PathBuf,
    durable: bool,
}

/// Where the bytes for `digest` live under `root`, if they exist.
///
/// `digest` is always a validated [`Digest`], never a raw string: its
/// `FromStr` accepts exactly `^blake3:[0-9a-f]{64}$` (see
/// `bathy_types::ids::Digest`) and `Display` renders the same shape back
/// out, so the hex segments joined below can never contain a path
/// separator, a `..`, or anything else that could walk the result outside
/// `root`. `blob_path_never_escapes_the_store_root` and the
/// `blob_path_is_always_confined_to_the_store_root` proptest in the test
/// module below verify this holds for every digest the type can produce,
/// rather than assuming it from the parser alone.
pub fn blob_path(root: &Path, digest: &Digest) -> PathBuf {
    let hex = digest.to_string();
    let hex = hex
        .strip_prefix("blake3:")
        .expect("digest renders with prefix");
    // Two-level fan-out keeps directory sizes manageable on ext4 and APFS.
    root.join("blobs")
        .join(&hex[0..2])
        .join(&hex[2..4])
        .join(hex)
}

/// Monotonic counter mixed into temp filenames alongside the pid.
///
/// A bare `.tmp-{pid}` (as originally drafted) is unique across processes
/// but *not* across threads within one process: two threads writing
/// different blobs whose digests share a two-byte prefix land in the same
/// fan-out directory (`root/blobs/xx/yy/`), and both would target the exact
/// same temp path. Whichever thread's `fs::write` and `fs::rename` interleave
/// last wins, silently discarding or corrupting the other's bytes -- see
/// `concurrent_puts_into_the_same_fan_out_directory_do_not_corrupt_either_blob`,
/// which forces exactly this collision and failed against the `{pid}`-only
/// name before this counter was added. A process-wide atomic counter makes
/// every call to `tmp_path`, from any thread, pick a distinct name, which is
/// all atomicity via rename requires: the temp name need not be
/// predictable or content-derived, only unique to the writer.
///
/// This still assumes distinct OS processes get distinct pids, which does
/// not hold if two separate containers each see themselves as pid 1 while
/// sharing one bind-mounted store directory. That is not a deployment shape
/// this project targets, so it is out of scope here rather than fixed.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn tmp_path(parent: &Path) -> PathBuf {
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    parent.join(format!(".tmp-{}-{seq}", std::process::id()))
}

/// Fsyncs a directory's own metadata (the entry pointing at a just-renamed
/// file), so the rename in [`EvidenceStore::put`] is itself durable, not
/// only the bytes underneath it.
///
/// Unix guarantees a directory can be opened read-only and `fsync`'d this
/// way (POSIX `open(2)`/`fsync(2)`; every mainstream Unix filesystem this
/// project targets -- ext4, APFS, XFS -- honors it). Windows has no
/// equivalent: `CreateFile` on a directory requires
/// `FILE_FLAG_BACKUP_SEMANTICS`, which `std::fs::File::open` does not set,
/// so attempting this on Windows would simply fail with "access denied" on
/// every call, and NTFS's own metadata journaling makes the hazard this
/// guards against far less likely there in the first place. Rather than
/// have every `put` on Windows pay for a syscall that only ever errors,
/// this degrades explicitly to a documented no-op on non-Unix platforms --
/// callers on Windows get the data-durability half of C1 (the temp file's
/// own `sync_all`) but not the directory-entry half.
#[cfg(unix)]
fn fsync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn fsync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

impl EvidenceStore {
    /// The default, durable constructor: `put` fsyncs the temp file before
    /// renaming it into place and fsyncs the containing directory after the
    /// rename (see [`fsync_dir`]), so a crash immediately after `put`
    /// returns `Ok` can never lose or corrupt the bytes it just wrote. See
    /// [`Self::open_without_durability_barrier`] for the explicit opt-out.
    pub fn open(root: &Path) -> Result<Self, EvidenceError> {
        Self::open_with_durability(root, true)
    }

    /// C1: the explicit, named opt-out. `put` on a store built this way
    /// skips both fsyncs -- cheaper, but a crash between `put` returning
    /// `Ok` and the OS actually flushing those pages can lose the blob
    /// while any event that already cited its digest survives, producing
    /// exactly the dangling `evidence_refs` entry `store.rs`'s module doc
    /// says can never happen. There is no way to reach this behavior except
    /// by naming it: [`Self::open`] (the type most callers should use) is
    /// always durable.
    pub fn open_without_durability_barrier(root: &Path) -> Result<Self, EvidenceError> {
        Self::open_with_durability(root, false)
    }

    fn open_with_durability(root: &Path, durable: bool) -> Result<Self, EvidenceError> {
        fs::create_dir_all(root.join("blobs")).map_err(|source| EvidenceError::Io {
            path: root.to_owned(),
            source,
        })?;
        Ok(Self {
            root: root.to_owned(),
            durable,
        })
    }

    pub fn put(&self, bytes: &[u8]) -> Result<Digest, EvidenceError> {
        let digest = Digest::of_bytes(bytes);
        let path = blob_path(&self.root, &digest);
        let parent = path.parent().expect("blob path has a parent");
        fs::create_dir_all(parent).map_err(|source| EvidenceError::Io {
            path: parent.to_owned(),
            source,
        })?;
        // Deliberately no `exists()` short-circuit: always write-then-rename,
        // even when a blob already appears to sit at `path`. `rename` onto an
        // existing file atomically replaces it (POSIX and Windows both
        // guarantee this), so for identical content this is a no-op in
        // substance -- same bytes hash to the same digest, so the
        // replacement writes back exactly what was already there -- while
        // also being self-healing if the existing blob was ever corrupted on
        // disk. An `exists()` short-circuit would trust that stale file
        // without checking it and return `Ok` for a digest `get` would then
        // refuse to serve, which is a correctness bug, not just a missed
        // optimization: M4's ordering rule treats `put`'s `Ok` as meaning the
        // digest is now durably retrievable. See
        // `put_heals_a_previously_corrupted_blob` and
        // `put_of_identical_bytes_still_deduplicates_without_the_exists_short_circuit`.
        //
        // The temp name is process- and call-unique (see `tmp_path`), so
        // concurrent writers never share one.
        let tmp = tmp_path(parent);
        // C1: `fs::write` alone (the previous shape here) opens, writes, and
        // closes the file with no way to fsync it first -- closing a file
        // does not imply the kernel has flushed its data to durable
        // storage. Go through a `File` handle instead, specifically so
        // `sync_all` can run on it before the file is renamed into place.
        {
            let mut f = File::create(&tmp).map_err(|source| EvidenceError::Io {
                path: tmp.clone(),
                source,
            })?;
            f.write_all(bytes).map_err(|source| EvidenceError::Io {
                path: tmp.clone(),
                source,
            })?;
            if self.durable {
                // Flushes both data and metadata (`sync_all`, not
                // `sync_data`): a freshly-created temp file's metadata
                // (e.g. its allocated extents) may not exist durably yet
                // either, and the subsequent `rename` depends on the file
                // actually existing on disk under this name.
                f.sync_all().map_err(|source| EvidenceError::Io {
                    path: tmp.clone(),
                    source,
                })?;
            }
            // `f` drops here, closing the descriptor before rename -- not
            // load-bearing for correctness (POSIX rename doesn't care
            // whether the source is still open), but avoids holding an fd
            // open a moment longer than necessary.
        }
        fs::rename(&tmp, &path).map_err(|source| EvidenceError::Io {
            path: path.clone(),
            source,
        })?;
        if self.durable {
            // The rename itself is only durable once the directory entry
            // change is flushed -- fsyncing the file's data says nothing
            // about the directory that now points to it under its final
            // name. Without this, a crash right after `rename` can leave
            // the *old* name (or no name at all) pointing at the bytes once
            // the filesystem's journal replays, even though the data itself
            // is safely on disk.
            fsync_dir(parent).map_err(|source| EvidenceError::Io {
                path: parent.to_owned(),
                source,
            })?;
        }
        Ok(digest)
    }

    pub fn put_capped(&self, bytes: &[u8], cap: usize) -> Result<(Digest, bool), EvidenceError> {
        let truncated = bytes.len() > cap;
        let slice = if truncated { &bytes[..cap] } else { bytes };
        Ok((self.put(slice)?, truncated))
    }

    /// Reports whether a blob is present at `digest`'s canonical path --
    /// **not** whether its bytes are intact. This is a cheap presence probe
    /// (one `Path::exists` syscall); it deliberately does not read or
    /// re-hash the blob, which would mean paying `get`'s full cost just to
    /// throw the bytes away. A corrupted blob therefore still reports
    /// `true` here. Callers that need a retrievability guarantee -- "these
    /// bytes are actually there and match their digest" -- must call
    /// [`Self::get`], the only method on this store that verifies on read.
    pub fn contains(&self, digest: &Digest) -> bool {
        blob_path(&self.root, digest).exists()
    }

    pub fn get(&self, digest: &Digest) -> Result<Vec<u8>, EvidenceError> {
        let path = blob_path(&self.root, digest);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(EvidenceError::NotFound(*digest));
            }
            Err(source) => return Err(EvidenceError::Io { path, source }),
        };
        // Verify on read. The whole provenance claim rests on this check.
        if Digest::of_bytes(&bytes) != *digest {
            return Err(EvidenceError::Corrupt { digest: *digest });
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, EvidenceStore) {
        let dir = tempfile::tempdir().unwrap();
        let s = EvidenceStore::open(dir.path()).unwrap();
        (dir, s)
    }

    /// Counts files under `blobs/` whose name does not start with `.tmp-`,
    /// i.e. finished, renamed-into-place blobs. Used to prove dedup and
    /// atomicity claims by inspecting the filesystem directly rather than
    /// trusting return values.
    fn walkdir_count_files(root: &Path) -> usize {
        walkdir::WalkDir::new(root.join("blobs"))
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| !e.file_name().to_string_lossy().starts_with(".tmp-"))
            .count()
    }

    #[test]
    fn round_trips_bytes_through_a_digest() {
        let (_d, s) = store();
        let digest = s.put(b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n").unwrap();
        assert_eq!(
            s.get(&digest).unwrap(),
            b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"
        );
    }

    #[test]
    fn identical_bytes_deduplicate_to_one_object() {
        let (dir, s) = store();
        let a = s.put(b"same").unwrap();
        let b = s.put(b"same").unwrap();
        assert_eq!(a, b);
        let count = walkdir_count_files(dir.path());
        assert_eq!(count, 1, "identical content must not be stored twice");
    }

    #[test]
    fn get_of_an_unknown_digest_is_an_error_not_a_panic() {
        let (_d, s) = store();
        let unknown = bathy_types::ids::Digest::of_bytes(b"never stored");
        // Pins the specific variant, not just `is_err()`: a bare `is_err()`
        // would still pass if `get` mistakenly reported `Corrupt` or `Io`
        // for a digest that was simply never stored, matching how the
        // tamper tests already pin `Corrupt` rather than accepting any
        // error.
        assert!(
            matches!(s.get(&unknown), Err(EvidenceError::NotFound(_))),
            "an unstored digest must report NotFound specifically"
        );
    }

    #[test]
    fn capped_put_truncates_and_reports_truncation() {
        let (_d, s) = store();
        let big = vec![b'x'; 100];
        let (digest, truncated) = s.put_capped(&big, 10).unwrap();
        assert!(truncated);
        assert_eq!(s.get(&digest).unwrap().len(), 10);
    }

    #[test]
    fn capped_put_under_the_cap_reports_no_truncation() {
        let (_d, s) = store();
        let (_, truncated) = s.put_capped(b"short", 4096).unwrap();
        assert!(!truncated);
    }

    #[test]
    fn stored_bytes_verify_against_their_digest_on_read() {
        let (dir, s) = store();
        let digest = s.put(b"authentic").unwrap();
        // Corrupt the blob on disk, simulating bit rot or tampering.
        let path = blob_path(dir.path(), &digest);
        std::fs::write(&path, b"tampered").unwrap();
        assert!(
            s.get(&digest).is_err(),
            "must detect content that does not match its digest"
        );
    }

    #[test]
    fn get_of_tampered_bytes_reports_corrupt_not_not_found() {
        // A sharper version of the tamper test above: distinguishes
        // "missing" from "present but wrong", which the brief's own test
        // does not (`is_err()` alone is satisfied by *either* variant).
        let (dir, s) = store();
        let digest = s.put(b"authentic").unwrap();
        let path = blob_path(dir.path(), &digest);
        std::fs::write(&path, b"tampered").unwrap();
        assert!(
            matches!(s.get(&digest), Err(EvidenceError::Corrupt { .. })),
            "tampering must surface as Corrupt, not any other error"
        );
    }

    // --- Review fix: `put` must not trust a stale `exists()` check ---
    //
    // The original brief's `put` short-circuited on `path.exists()` and
    // returned `Ok(digest)` without ever reading or verifying the file
    // already there. If that file had been corrupted on disk (bit rot,
    // tampering, a prior interrupted write from a different bug), `put`
    // still reported success for bytes it never actually wrote, and the
    // very next `get` for that digest would then fail with `Corrupt` --
    // silently breaking M4's ordering rule, which treats `put`'s `Ok` as
    // meaning the digest is now durably retrievable. `put` now always
    // writes-then-renames, which is self-healing (a `put` of the correct
    // bytes overwrites bad data with good) without regressing dedup (the
    // final path is still fully determined by content, so repeated puts of
    // identical bytes still converge on one file, they just each pay a
    // rename to get there instead of skipping it).

    #[test]
    fn put_heals_a_previously_corrupted_blob() {
        let (dir, s) = store();
        let digest = s.put(b"authentic").unwrap();
        let path = blob_path(dir.path(), &digest);
        // Corrupt it on disk, exactly as the tamper tests do above.
        fs::write(&path, b"tampered").unwrap();
        assert!(
            matches!(s.get(&digest), Err(EvidenceError::Corrupt { .. })),
            "setup: the blob must actually be corrupt before healing is exercised"
        );

        // Re-`put`-ting the correct bytes must heal the store.
        let healed = s.put(b"authentic").unwrap();
        assert_eq!(healed, digest);
        assert_eq!(
            s.get(&digest).unwrap(),
            b"authentic",
            "put() of the correct bytes must heal a previously corrupted blob"
        );
    }

    #[test]
    fn put_of_identical_bytes_still_deduplicates_without_the_exists_short_circuit() {
        // Guards the regression the fix above could plausibly introduce:
        // "always write-then-rename" must not silently become "always
        // create a new object". `blob_path` is a pure function of content,
        // so repeated puts of the same bytes must still land at the one
        // deterministic path -- this must keep holding even though `put`
        // no longer skips the write when that path already exists.
        let (dir, s) = store();
        let a = s.put(b"same-again").unwrap();
        let b = s.put(b"same-again").unwrap();
        let c = s.put(b"same-again").unwrap();
        assert_eq!(a, b);
        assert_eq!(b, c);
        assert_eq!(
            walkdir_count_files(dir.path()),
            1,
            "repeated puts of identical bytes must still yield exactly one on-disk object"
        );
    }

    // --- Beyond the brief: atomicity, proven rather than asserted ---
    //
    // `put`'s only write to the *final* path is the `fs::rename` call; the
    // preceding `fs::write` always targets a `.tmp-`-prefixed sibling. The
    // two tests below check the two consequences of that shape that matter
    // operationally: no leftover temp file survives a successful put, and a
    // write that stops short of `rename` (modeling a crash in that window)
    // leaves nothing readable under the digest. Neither test can literally
    // kill the process mid-syscall -- that is out of reach for a unit test
    // in-process -- so what's verified is the structural guarantee a real
    // crash would rely on, not the crash itself.

    #[test]
    fn put_leaves_no_stray_temp_file_after_success() {
        let (dir, s) = store();
        s.put(b"clean").unwrap();
        let total_files = walkdir::WalkDir::new(dir.path().join("blobs"))
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .count();
        assert_eq!(
            total_files, 1,
            "a successful put must leave exactly the renamed blob behind, no temp leftovers"
        );
    }

    #[test]
    fn a_write_that_never_reaches_rename_leaves_no_readable_blob() {
        let (dir, s) = store();
        let digest = Digest::of_bytes(b"never finished");
        let path = blob_path(dir.path(), &digest);
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        // Simulate the crash window: bytes landed at a temp name, but the
        // rename that would publish them under `digest` never ran.
        let stray_tmp = parent.join(".tmp-simulated-crash");
        fs::write(&stray_tmp, b"never finished").unwrap();

        assert!(
            !path.exists(),
            "the canonical path must never be created except by rename"
        );
        assert!(
            !s.contains(&digest),
            "a stray temp file must not count as stored evidence"
        );
        assert!(
            matches!(s.get(&digest), Err(EvidenceError::NotFound(_))),
            "a stray temp file must not be readable under its digest"
        );
    }

    #[test]
    fn temp_names_are_never_confused_with_final_blob_names() {
        // A final blob's filename is always exactly 64 lowercase hex
        // characters (`blob_path`'s last path component). Confirms
        // `tmp_path`'s output can never be mistaken for one -- i.e. a
        // half-written temp file could never accidentally satisfy a lookup
        // for some digest, even before considering that `get`/`contains`
        // only ever construct paths via `blob_path`, never `tmp_path`.
        let parent = Path::new("irrelevant-parent");
        for _ in 0..8 {
            let tmp = tmp_path(parent);
            let name = tmp.file_name().unwrap().to_str().unwrap().to_owned();
            assert!(
                name.starts_with(".tmp-"),
                "temp name must be unmistakably temp: {name}"
            );
            assert!(
                !(name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit())),
                "temp name must not have the shape of a final blob name: {name}"
            );
        }
    }

    // --- Beyond the brief: hostile paths ---
    //
    // `blob_path` builds a filesystem path out of a `Digest`'s hex
    // rendering. `Digest` can only be produced by `of_bytes` (always a
    // 32-byte BLAKE3 hash, hex-encoded) or by a `FromStr` that rejects
    // anything but exactly `blake3:` + 64 lowercase hex characters -- so
    // there is no path from attacker-controlled input to `blob_path` that
    // skips that validation. These tests check the consequence (no escape,
    // ever) rather than re-deriving that reasoning at the call site.

    #[test]
    fn blob_path_never_escapes_the_store_root() {
        let root = Path::new("store-root");
        for content in [
            &b""[..],
            b"a",
            b"the quick brown fox jumps",
            &[0u8; 4096][..],
        ] {
            let digest = Digest::of_bytes(content);
            let path = blob_path(root, &digest);
            assert!(
                path.starts_with(root),
                "path {path:?} escaped root {root:?}"
            );
            assert!(
                !path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir)),
                "path {path:?} contains a `..` component"
            );
        }
    }

    #[test]
    fn digest_parser_rejects_path_traversal_and_separator_payloads() {
        // The real gate: `blob_path` never sees these strings directly, only
        // a `Digest` that already parsed successfully. Confirms that gate
        // actually holds for the payloads an attacker would try.
        for attempt in [
            "blake3:../../../../etc/passwd",
            "blake3:/etc/passwd",
            "blake3:..",
            "blake3:....................................................................",
        ] {
            assert!(
                attempt.parse::<Digest>().is_err(),
                "{attempt:?} must not parse as a Digest"
            );
        }
    }

    proptest::proptest! {
        /// For every possible digest (i.e. every possible input to
        /// `Digest::of_bytes`), `blob_path` stays under `root`, contains no
        /// `..`, and has exactly the fan-out shape
        /// `root/blobs/<2 hex>/<2 hex>/<64 hex>`.
        #[test]
        fn blob_path_is_always_confined_to_the_store_root(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256)
        ) {
            let root = Path::new("store-root");
            let digest = Digest::of_bytes(&bytes);
            let path = blob_path(root, &digest);

            proptest::prop_assert!(path.starts_with(root));
            proptest::prop_assert!(
                !path.components().any(|c| matches!(c, std::path::Component::ParentDir))
            );

            let rel = path.strip_prefix(root).unwrap();
            let comps: Vec<String> = rel
                .components()
                .map(|c| c.as_os_str().to_str().unwrap().to_string())
                .collect();
            proptest::prop_assert_eq!(comps.len(), 4);
            proptest::prop_assert_eq!(&comps[0], "blobs");
            proptest::prop_assert_eq!(comps[1].len(), 2);
            proptest::prop_assert_eq!(comps[2].len(), 2);
            proptest::prop_assert_eq!(comps[3].len(), 64);
            proptest::prop_assert!(comps[3].bytes().all(|b| b.is_ascii_hexdigit()));
        }
    }

    // --- Beyond the brief: concurrency ---
    //
    // The brief's temp filename is `.tmp-{pid}`: unique per process, not
    // per thread. Two threads in the same process, writing distinct blobs
    // whose digests happen to share a fan-out directory
    // (`root/blobs/xx/yy/`), would collide on that exact temp path. This
    // finds a genuine such collision (rather than hoping a random one
    // shows up) and hammers it from two threads in lockstep.

    /// Brute-forces two distinct byte strings whose `Digest`s share their
    /// first two raw hash bytes (the four hex characters that select the
    /// fan-out directory), so `blob_path` places them in the very same
    /// `blobs/xx/yy/` directory. A 2-byte prefix match happens on average
    /// every 65536 tries, so this terminates quickly.
    fn colliding_content_pair() -> (Vec<u8>, Vec<u8>) {
        let a = b"evidence-a".to_vec();
        let target_prefix = Digest::of_bytes(&a).as_bytes()[0..2].to_owned();
        for i in 0u32.. {
            let b = format!("evidence-b-{i}").into_bytes();
            if Digest::of_bytes(&b).as_bytes()[0..2] == target_prefix[..] {
                return (a, b);
            }
        }
        unreachable!("2-byte prefix space is only 65536 wide; a match must appear")
    }

    #[test]
    fn concurrent_puts_into_the_same_fan_out_directory_do_not_corrupt_either_blob() {
        let (dir, s) = store();
        let (a, b) = colliding_content_pair();
        let digest_a = Digest::of_bytes(&a);
        let digest_b = Digest::of_bytes(&b);

        // Sanity: confirm this really is the hazard described above, i.e.
        // the two blobs' final directories coincide, before trusting the
        // rest of the test to exercise it.
        assert_eq!(
            blob_path(&s.root, &digest_a).parent(),
            blob_path(&s.root, &digest_b).parent(),
            "test setup must produce a genuine fan-out directory collision"
        );

        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for _ in 0..300 {
                    barrier.wait();
                    s.put(&a).unwrap();
                }
            });
            scope.spawn(|| {
                for _ in 0..300 {
                    barrier.wait();
                    s.put(&b).unwrap();
                }
            });
        });

        assert_eq!(
            s.get(&digest_a).unwrap(),
            a,
            "blob a must round-trip uncorrupted"
        );
        assert_eq!(
            s.get(&digest_b).unwrap(),
            b,
            "blob b must round-trip uncorrupted"
        );
        assert_eq!(
            walkdir_count_files(dir.path()),
            2,
            "exactly the two distinct blobs, neither lost nor duplicated"
        );
    }

    // --- C1: the durability barrier. A crash can't be simulated in-process,
    // so what's checked here is everything that IS observable from user
    // space: the default is durable, the opt-out is explicit and named (not
    // a flag that could default the wrong way), both still round-trip bytes
    // correctly, and `fsync_dir` itself succeeds against a real directory
    // and fails cleanly against a path that isn't one. The actual claim --
    // that `sync_all`/`fsync_dir` genuinely reach the OS, not just that the
    // code compiles -- is established differently: the fix wave report
    // measures wall-clock throughput with these calls present vs. removed,
    // which is the one thing that IS observable about an fsync from user
    // space. ---

    #[test]
    fn open_is_durable_by_default_and_still_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let s = EvidenceStore::open(dir.path()).unwrap();
        assert!(s.durable, "EvidenceStore::open must default to durable");
        let digest = s.put(b"durable by default").unwrap();
        assert_eq!(s.get(&digest).unwrap(), b"durable by default");
    }

    #[test]
    fn the_durability_opt_out_is_explicit_and_still_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let s = EvidenceStore::open_without_durability_barrier(dir.path()).unwrap();
        assert!(
            !s.durable,
            "the explicit opt-out constructor must actually disable the barrier"
        );
        let digest = s.put(b"no fsync here").unwrap();
        assert_eq!(
            s.get(&digest).unwrap(),
            b"no fsync here",
            "skipping the fsync must not affect correctness under normal \
             (non-crash) operation"
        );
        // Dedup, healing, and atomicity are all orthogonal to durability --
        // spot-check dedup still holds under the opt-out too.
        let again = s.put(b"no fsync here").unwrap();
        assert_eq!(digest, again);
    }

    #[cfg(unix)]
    #[test]
    fn fsync_dir_succeeds_against_a_real_directory() {
        let dir = tempfile::tempdir().unwrap();
        assert!(fsync_dir(dir.path()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn fsync_dir_fails_cleanly_against_a_path_that_does_not_exist() {
        // `File::open` doesn't distinguish "directory" from "regular file"
        // by itself -- opening either one read-only succeeds on Unix, so
        // `fsync_dir` is not, and does not claim to be, a type check.
        // What it must still do is propagate a real I/O failure cleanly
        // rather than panicking or silently reporting success.
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        assert!(
            fsync_dir(&missing).is_err(),
            "fsync_dir must report an error for a path that cannot be opened"
        );
    }

    #[cfg(not(unix))]
    #[test]
    fn fsync_dir_is_a_documented_no_op_off_unix() {
        // See `fsync_dir`'s doc comment: there is no portable directory-fsync
        // primitive on Windows via `std::fs::File::open`, so this degrades
        // explicitly rather than erroring on every `put`.
        let dir = tempfile::tempdir().unwrap();
        assert!(fsync_dir(dir.path()).is_ok());
    }
}
