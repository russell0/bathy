#!/usr/bin/env python3
"""Derive `lab/ground-truth.json` from what the lab containers actually expose.

This exists because a ground-truth file written by reading `docker-compose.yml`
is not a ground truth: it is the same assumption the scanner is being tested
for, written down twice. A wrong oracle is worse than no oracle -- it makes
every future disagreement look like our bug, or makes a real bug look like
agreement.

So this sweeps **every one of the 65535 TCP ports** on every lab address,
from inside `labnet`, using nothing but Python's standard-library socket
layer. It shares no code, no data and no fingerprint table with `bathy`, and
it does not consult Nmap or any of its data files (the clean-room rule in the
overview's Global Constraints applies to verification too).

Run it via `lab/run.sh verify`, which puts it in a container on `labnet`.
Output is written to stdout as JSON in the shape `lab/ground-truth.json` uses,
plus, on stderr, the banner bytes read from each open port so that the
`product` fields can be justified from observed evidence rather than from the
image name.
"""

from __future__ import annotations

import asyncio
import json
import sys

# Every address the lab defines, whether or not a container sits on it. The
# absent ones are swept too: "nothing is open here" is a claim that has to be
# measured like any other.
PRESENT = [f"10.30.0.{n}" for n in range(10, 19)]
ABSENT = ["10.30.0.200", "10.30.0.201"]

ALL_PORTS = range(1, 65536)
CONNECT_TIMEOUT = 2.0
BANNER_TIMEOUT = 4.0
CONCURRENCY = 800


async def is_open(ip: str, port: int, sem: asyncio.Semaphore) -> bool:
    async with sem:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), CONNECT_TIMEOUT
            )
        except (OSError, asyncio.TimeoutError):
            return False
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return True


async def sweep(ip: str) -> list[int]:
    sem = asyncio.Semaphore(CONCURRENCY)
    results = await asyncio.gather(*(is_open(ip, p, sem) for p in ALL_PORTS))
    return [p for p, ok in zip(ALL_PORTS, results) if ok]


async def banner(ip: str, port: int) -> str:
    """Read whatever the service volunteers, then nudge it once if it says
    nothing. Two shapes only -- a greeting-first protocol (SSH, SMTP, MySQL)
    and a request-first one (HTTP) -- because the point is to justify the
    `product` fields, not to reimplement service detection."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), CONNECT_TIMEOUT
        )
    except (OSError, asyncio.TimeoutError):
        return "<no connection>"
    try:
        try:
            data = await asyncio.wait_for(reader.read(512), BANNER_TIMEOUT)
        except asyncio.TimeoutError:
            data = b""
        if not data:
            writer.write(b"GET / HTTP/1.0\r\nHost: lab.invalid\r\n\r\n")
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(512), BANNER_TIMEOUT)
            except asyncio.TimeoutError:
                data = b""
        return repr(data[:200])
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def main() -> int:
    hosts = []
    for ip in PRESENT + ABSENT:
        open_ports = await sweep(ip)
        print(f"{ip}: {open_ports}", file=sys.stderr)
        for port in open_ports:
            print(f"    {ip}:{port} -> {await banner(ip, port)}", file=sys.stderr)
        hosts.append({"ip": ip, "open": open_ports})
    json.dump(hosts, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
