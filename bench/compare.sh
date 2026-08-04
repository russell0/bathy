#!/usr/bin/env bash
#
# The cross-scanner comparison (AC-7.11 to AC-7.14), from a clean machine.
#
#   bench/compare.sh            run every installed scanner against the lab
#   bench/compare.sh --render   re-render docs/benchmarks.md from the last run
#
# What it does, in order: brings the lab up, works out where the lab is
# reachable from, builds `bathy` there, and runs `cargo run -p xtask --
# bench-compare`, which is where all the actual measuring and scoring lives.
# The script is the *driver*; it deliberately holds no rules about ports,
# timeouts or accuracy, because a shell script cannot be unit-tested and those
# rules are the ones that have to be right.
#
# ---------------------------------------------------------------------------
# Where this runs, and why it is not always the machine you typed it on
# ---------------------------------------------------------------------------
#
# `labnet` is a Docker bridge network. On Linux the host routes to it. On
# macOS it does not exist in the host's routing table at all -- Docker Desktop
# keeps the daemon in a VM whose bridges the Mac never learns -- so a scanner
# running on the Mac cannot see the lab, and neither can a Mac-built binary.
# This was established in M7 Task 1 and is not rediscovered here.
#
# So: if the lab is reachable from this host, everything runs here, against
# whatever is installed here. If it is not, everything runs inside one Linux
# container attached to `labnet` -- one container, one run, every tool, which
# is what AC-7.11 means by "on one machine in one run".
#
# ---------------------------------------------------------------------------
# Which tools take part
# ---------------------------------------------------------------------------
#
# Whatever is on `PATH` in the execution environment. A scanner that is not
# there produces a named "NOT RUN -- not installed" row in `docs/benchmarks.md`
# carrying the command that would make it present; it is never silently
# omitted, and never scored as though it had run badly.
#
# Two hooks, both free of code changes:
#
#   BENCH_APT_PACKAGES   packages installed in the runner container.
#                        Default `nmap`. Debian also packages `masscan`, so
#                        BENCH_APT_PACKAGES="nmap masscan" fills that row in.
#   bench/tools/         prepended to PATH inside the runner. `rustscan` has
#                        no Debian package; drop a Linux binary here and it
#                        joins the comparison.
#
# Nothing here installs `masscan` or `rustscan` on your machine. That is your
# decision, and a benchmark harness that quietly installs network scanners is
# not one anybody should run.
#
# ---------------------------------------------------------------------------
# Nmap, and the clean-room rule
# ---------------------------------------------------------------------------
#
# Running Nmap is legitimate here and only here: it is a benchmark subject.
# Its data files are never read, and its output is never used to author,
# correct or tune any rule, probe or port list in this repository. See
# `docs/benchmarks.md` for the full statement.

set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
root="$(dirname -- "$here")"
cd "$root"

# The image the runner uses when the host cannot route to the lab. The same
# image `xtask linux-gate` uses, for the same reason: it is one `docker run`
# away and tracks the toolchain CI tracks. Deliberately not digest-pinned --
# it is a tool, not part of the fixture. The lab's own images are what must
# not move, and they are pinned.
runner_image="${BENCH_RUNNER_IMAGE:-rust:1-bookworm}"
apt_packages="${BENCH_APT_PACKAGES:-nmap}"
lab_network="${BENCH_LAB_NETWORK:-bathy-lab_labnet}"

die() { printf 'bench/compare.sh: %s\n' "$*" >&2; exit 1; }

if [ "${1:-}" = "--render" ]; then
  exec cargo run -p xtask -- bench-compare --render-only
fi

command -v docker >/dev/null 2>&1 ||
  die "docker is not on PATH. The comparison runs against the lab, and the lab is a
     Docker Compose stack."

printf 'bench/compare.sh: bringing the lab up\n' >&2
"$root/lab/run.sh" up >/dev/null

# The first open port the ground truth records: if a TCP connect to it
# succeeds from here, this host routes to the lab.
probe_target="$(python3 -c '
import json, sys
truth = json.load(open("lab/ground-truth.json"))
for host in truth["hosts"]:
    if host["open"]:
        print(host["ip"], host["open"][0]["port"])
        sys.exit(0)
sys.exit("the ground truth records no open port")
')"
# shellcheck disable=SC2086
if python3 - $probe_target <<'PY'
import socket, sys
ip, port = sys.argv[1], int(sys.argv[2])
s = socket.socket()
s.settimeout(3)
try:
    s.connect((ip, port))
except OSError:
    sys.exit(1)
sys.exit(0)
PY
then
  reachable=yes
else
  reachable=no
fi

if [ "$reachable" = yes ]; then
  printf 'bench/compare.sh: the lab is reachable from this host; running here\n' >&2
  export PATH="$root/target/release:$root/bench/tools:$PATH"
  export BENCH_EXECUTED_IN="this host, which routes to $lab_network directly"
  cargo build --release -p bathy
  exec cargo run -p xtask -- bench-compare
fi

printf 'bench/compare.sh: this host cannot route to %s (expected on macOS);\n' "$lab_network" >&2
printf '                  running every scanner inside one container on that network\n' >&2

uid="$(id -u)"
gid="$(id -g)"
# Created on the host so they exist owned by the invoking user before the
# container writes into them, and separate from `target/linux-gate` so the two
# reproduction harnesses do not invalidate each other's caches.
mkdir -p target/bench target/bench-cargo target/bench-home bench/tools

# The container runs as root, which is not incidental: `apt-get` needs it, and
# so does every SYN-scanning variant in the comparison. `xtask bench-compare`
# records that it had CAP_NET_RAW, so a privileged Nmap run is never published
# as though it were the same operation as our unprivileged connect scan. The
# outputs are chowned back at the end -- a benchmark that leaves root-owned
# files in someone's working tree is a benchmark they run once.
docker run --rm \
  --network "$lab_network" \
  --volume "$root:/w" \
  --workdir /w \
  --env CARGO_TARGET_DIR=/w/target/bench \
  --env CARGO_HOME=/w/target/bench-cargo \
  --env HOME=/w/target/bench-home \
  ${BENCH_REPETITIONS:+--env BENCH_REPETITIONS="$BENCH_REPETITIONS"} \
  --env BENCH_EXECUTED_IN="a $runner_image container attached to $lab_network (this host cannot route to it)" \
  --env APT_PACKAGES="$apt_packages" \
  --env HOST_UID="$uid" \
  --env HOST_GID="$gid" \
  "$runner_image" \
  bash -euo pipefail -c '
    apt-get update -qq >/dev/null
    # shellcheck disable=SC2086
    apt-get install -y -qq $APT_PACKAGES >/dev/null
    export PATH="/w/target/bench/release:/w/bench/tools:$PATH"
    cargo build --release -p bathy
    status=0
    cargo run -p xtask -- bench-compare || status=$?
    chown -R "$HOST_UID:$HOST_GID" /w/target/bench /w/target/bench-cargo \
      /w/target/bench-home /w/bench /w/docs/benchmarks.md 2>/dev/null || true
    exit $status
  '
