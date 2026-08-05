# Drop-in scanners for the comparison

`bench/compare.sh` prepends this directory to `PATH` in whatever environment
the comparison runs in. Put a **Linux** executable here and it joins the
comparison on the next run, with no code change and no edit to
`docs/benchmarks.md` — `xtask bench-compare` finds it with `command -v`, records
its `--version` output, and fills in the row that currently reads
"NOT RUN — not installed".

This exists for `rustscan`, which Debian does not package. For `masscan`, which
it does, the simpler route is:

```
BENCH_APT_PACKAGES="nmap masscan libpcap0.8" bench/compare.sh
```

`libpcap0.8` is in that list on purpose. Debian's `masscan` package declares
`Depends: libc6` and nothing else, while masscan loads libpcap with `dlopen` at
run time — so `masscan` on its own installs cleanly and then dies with `can't
open adapter: libpcap not loaded`. Co-installing `nmap` happens to satisfy it,
which is exactly why naming it is worth doing: an instruction that works only
because of another package on the same line stops working the moment somebody
edits the line.

A "Linux executable" here means the architecture the runner container is,
which is the architecture of the machine running Docker — `aarch64` on Apple
silicon, `x86_64` elsewhere. A macOS build of `rustscan` on the host's `PATH`
does not take part: the comparison runs inside a Linux container, because
that is the only place on macOS that can reach the lab at all.

**Nothing in this repository installs a network scanner on your machine.** That
is your decision. The rows for tools that are not installed stay in the
published table, named and empty, so nobody reads a two-scanner comparison as a
four-scanner one.

Binaries dropped here are ignored by git — see `bench/tools/.gitignore`. This
file is the only tracked thing in the directory, which is also what makes the
directory exist in a fresh clone.
