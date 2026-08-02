# Port datasets

## Provenance

Derived solely from the IANA Service Name and Transport Protocol Port Number
Registry. No Nmap data file was consulted in producing these lists.

Source: <https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv>

## What the ranking means, and what it does not

IANA records *assignments*, not *observed prevalence*. These lists are ordered
by a documented heuristic:

1. System ports (0–1023) with a TCP assignment, ascending.
2. User ports (1024–49151) with a TCP assignment, ascending.

A port counts as having "a TCP assignment" when the registry has a row for it
with `Transport Protocol` = `tcp` and a non-empty `Service Name` — ports the
registry marks `Reserved` or `Unassigned` (including port 0) are excluded.

This is a reasonable starting set. It is **not** a frequency ranking, and it
will scan some ports that are almost never open while missing some high
non-assigned ports that commonly are. A prevalence ranking requires our own
measurement study and is tracked as issue #1 for v0.2.

## Regenerating

    cargo run -p xtask -- gen-ports --registry path/to/service-names-port-numbers.csv

`--out-dir` overrides where the two files are written (default `data/ports`).
Fetch the registry CSV yourself from the URL above; `gen-ports` never fetches
it and never reads any Nmap data file.
