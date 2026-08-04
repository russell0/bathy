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
BENCH_APT_PACKAGES="nmap masscan" bench/compare.sh
```

**Nothing in this repository installs a network scanner on your machine.** That
is your decision. The rows for tools that are not installed stay in the
published table, named and empty, so nobody reads a two-scanner comparison as a
four-scanner one.

Binaries dropped here are ignored by git — see `bench/tools/.gitignore`. This
file is the only tracked thing in the directory, which is also what makes the
directory exist in a fresh clone.
