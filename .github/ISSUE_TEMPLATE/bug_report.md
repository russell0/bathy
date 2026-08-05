---
name: Bug report
about: Something behaved differently from what is documented
title: ''
labels: bug
assignees: ''
---

<!--
Not for vulnerabilities. If this is a way to emit a packet outside a scope
manifest, to forge an approval, or to crash or hang the scanner from bytes an
endpoint controls, close this and report it privately instead -- SECURITY.md
has the channel and the response times.

Do not paste scan output identifying a third party's hosts. Redact addresses to
RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
or use the lab.
-->

## What happened

## What the documentation says should happen

<!-- Quote it and name the file, so a wrong document is a possible outcome of
this issue rather than an assumption. Three consecutive milestone reviews of
this project found README.md asserting things the code did not do; "the
document is wrong" is a real bug and it gets fixed here too. -->

## Reproduction

<!-- The smallest thing that shows it. Include the scope manifest if the
behaviour depends on one -- with addresses redacted as above. -->

```
```

## Environment

- bathy version / commit:
- OS and version:
- Rust version (`rustc -V`), if building from source:
- Privileged (`packetd`) or unprivileged:

## Evidence

<!-- If a scan produced this, the evidence log and the plan hash say more than
a description does. `bathy --json ... result query --scan <id>` and the
relevant event log lines are ideal. Redact before pasting. -->
