#!/usr/bin/env bash
#
# The integration lab, from a clean machine.
#
#   lab/run.sh up       bring the lab up and wait for every service
#   lab/run.sh down     tear it down, including the TLS volume
#   lab/run.sh verify   re-derive the ground truth by sweeping all 65535 TCP
#                       ports on every lab address, from inside the lab
#                       network, with a program that shares no code with bathy
#   lab/run.sh test     up, run the conformance suite, down
#   lab/run.sh status   what is running
#
# Run from the repository root or from anywhere: paths are resolved relative
# to this script.
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
root="$(dirname -- "$here")"
compose="$here/docker-compose.yml"

die() { printf 'lab/run.sh: %s\n' "$*" >&2; exit 1; }

# Docker's absence is reported here, once, in words -- rather than as a
# `docker: command not found` in the middle of a test run, or (worse) as a
# suite that quietly passes having scanned nothing.
require_docker() {
  command -v docker >/dev/null 2>&1 ||
    die "docker is not on PATH. The lab is a Docker Compose stack; there is no
     other way to bring it up. On a machine without Docker, \`cargo test
     --workspace\` still runs the lab suite's fixture guards and lists the five
     conformance tests as ignored -- which is the honest result, not a pass."
  docker info >/dev/null 2>&1 ||
    die "the docker daemon is not responding. Start Docker and try again."
}

up() {
  require_docker
  docker compose -f "$compose" up -d --wait
  printf '\nlab is up. Addresses and expected open ports: %s\n' "$here/ground-truth.json"
}

down() {
  require_docker
  # `-v` so the generated TLS key does not survive a teardown. It is
  # regenerated on the next `up`, and a key that outlives the lab it was made
  # for is a key someone eventually finds.
  docker compose -f "$compose" down -v
}

status() {
  require_docker
  docker compose -f "$compose" ps -a
}

verify() {
  require_docker
  # Inside the lab network, because that is the only place the lab is
  # reachable from on every platform. `python:3.13-alpine` is deliberately NOT
  # pinned by digest the way the lab's own images are: it is a tool, not part
  # of the fixture, and nothing in the ground truth depends on which build of
  # it ran. The lab images are what must not move.
  docker run --rm --network bathy-lab_labnet \
    -v "$here:/lab:ro" python:3.13-alpine python /lab/verify-ground-truth.py
}

run_tests() {
  up
  # BATHY_LAB_REQUIRED turns the suite's "the lab is not reachable, skipping"
  # into a hard failure. Without it this command could report success on a
  # host that cannot route to `labnet` at all -- which is every macOS host,
  # where Docker Desktop keeps the daemon in a VM whose bridges the Mac's
  # routing table never learns. A command whose entire purpose is to test the
  # lab must not be able to pass without one.
  local status=0
  ( cd "$root" && BATHY_LAB_REQUIRED=1 cargo test --workspace -- --ignored ) || status=$?
  down
  return "$status"
}

case "${1:-up}" in
  up)     up ;;
  down)   down ;;
  status) status ;;
  verify) verify ;;
  test)   run_tests ;;
  *)      printf 'usage: %s {up|down|status|verify|test}\n' "$0" >&2; exit 64 ;;
esac
