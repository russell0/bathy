---
name: New interpretation rule or probe
about: A protocol bathy should recognize, or a service it should be able to name
title: ''
labels: interpretation-rule
assignees: ''
---

<!--
This template exists because the citation is the hard part, not the regex.

This repository has shipped TWO fabricated RFC quotations and one citation to a
PostgreSQL section number that does not exist. In every case the sentence was
plausible, the section number looked right, and nobody had opened the document.
So the fields below are not paperwork: a reviewer will open your citation and
search for your string.

CONTRIBUTING.md §2 is the full rule. The short form is: an RFC cited to the
section, or the vendor's own documentation cited to the section, or a capture
this project can reproduce -- and nothing else. Never another scanner's output,
never another scanner's data files, and never a fingerprint adapted from one.
-->

## Protocol and what the rule would identify

## Source

<!-- Exactly one of the three. Fill in the one that applies and delete the
others. -->

**An RFC.** Number, section, section title, and the URL:

> <!-- The verbatim text you are relying on. Copy and paste it. If it is not
> findable by searching the linked section, the rule is rejected on that ground
> alone. -->

**Vendor documentation.** Product, document title, section number and title,
URL, and the verbatim text:

> 

**A capture.** Image and its `sha256` digest, the service version, and the
observed bytes. The capture goes into `testdata/captures/` in the same pull
request, so the rule can be replayed without a network:

```
```

## What the source does NOT say

<!-- If the protocol makes no MUST-level promise about the thing the rule
relies on, write that here. This is not a formality: the RFC 5321 rule in this
tree matches a greeting shape defined in section 4.2 and NOT in 3.1, and the
first version of that rule claimed 3.1 said something it does not. -->

## Confidence rung

<!-- ProductAndVersion / ProductOnly / ProtocolOnly / Weak -- see
`bathy_interpret::rules::Specificity`. A rule that reads a self-identifying
banner is not the same claim as one that recognizes a byte layout, and the
ladder is what keeps scores comparable across protocols. -->

## What it must NOT match

<!-- The negative fixture. A rule tested only against bytes it should match is
untested: this project's standing rule is that a fixture must exclude something
the code is supposed to exclude. Name a plausible response that looks close and
must not fire. -->

## Clean-room confirmation

- [ ] This rule was written from the source cited above, and not from Nmap,
      `nmap-service-probes`, `nmap-os-db`, or any other incompatibly licensed
      project's data or output.
