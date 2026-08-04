# An authorized inventory in ten typed calls

The claim is ten or fewer; this run took nine. **The ten is not
unconditional, and here is what it depends on:** six of the nine are typed
calls that do not depend on anything -- two `scope.validate`s, `scan.preview`,
`scan.start`, `result.query`, `evidence.get` -- and the other three are
`scan.events` polls. There is no protocol-level way to be *told* a scan has
finished (a held response stream is what clients and intermediaries time out;
see `docs/protocol-notes.md`), so an agent asks, and asking costs a call. How
many times it has to ask is a function of how long the scan takes against a
fixed backoff, which is a property of the machine: re-paced six times slower,
this workflow takes eleven calls. The unconditional half of the claim is the
six. The test asserts the two halves separately and says which one gave way.

Otherwise it is a **verbatim capture** of one run of
`an_agent_completes_an_authorized_inventory_in_ten_typed_calls`
(`crates/bathy/tests/workflow.rs`), taken over a real stdio transport against
the shipped binary. Nothing here is hand-written: the test serializes its own
transcript when `BATHY_WORKFLOW_TRANSCRIPT` names a file, and this document is
rendered from that file.

```console
$ BATHY_WORKFLOW_TRANSCRIPT=/tmp/tx.json \
    cargo test -p bathy --test workflow an_agent_completes
```

The agent's whole vocabulary is the eleven advertised tools. It builds no
command line, parses no XML, and splits nothing on whitespace -- and it never
reads the JSON text mirror the specification asks servers to include for
Legacy clients. Every branch below is taken on a **typed field of
`structuredContent`**, which is why only that half of each result is shown:
the test's own client discards the mirror before the workflow can see it.

**What is real about this run, and what is local to the machine that made it.**
The scan is real: a real listener on this machine's own routable address
answered a real HTTP request, and the evidence bytes below are the ones it
sent. The address (`192.168.1.64`), the ephemeral port numbers, the manifest's
temporary path, the scan id and the timestamps are this run's. Re-running the
test produces a different scan id and different ports; everything else is the
same shape. One substitution is made and it is the only one: the platform's
temporary directory is written `$TMPDIR/`, because on macOS the real prefix
carries a token that is stable per user per machine. The RFC 1918 address and
the two-second ephemeral ports identify nothing and are left as they were.

The lab has three endpoints on purpose, because a filter with nothing to
exclude tests nothing:

| Endpoint | What it does | Filtered by |
|---|---|---|
| an HTTP port | answers `GET` with an nginx banner | kept |
| a silent port | accepts and closes without a word | dropped by `service` |
| a vacated port | nothing is listening | dropped by `state` |

---

## The transcript

### Call 1 — `scope.validate`

The brief names two hosts. The manifest authorizes one.

```json
{
  "name": "scope.validate",
  "arguments": {
    "manifest_path": "$TMPDIR/.tmpj58wJl/scope.json",
    "targets": [
      "192.168.1.64",
      "10.30.0.1"
    ]
  }
}
```

```json
{
  "isError": true,
  "structuredContent": {
    "budget_ceiling": {
      "maximum_packets": 1000000,
      "maximum_packets_per_second": 20000,
      "maximum_runtime_seconds": 3600
    },
    "decision": "denied",
    "description": "bathy MCP test fixture",
    "detail": "1 of 2 target(s) are not authorized by manifest scope_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    "expired": false,
    "in_scope_count": 1,
    "out_of_scope": [
      "10.30.0.1"
    ],
    "reason_code": "target_out_of_scope",
    "scope_id": "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    "signature_present": false,
    "signature_verified": false
  }
}
```

`decision` is `denied` and `reason_code` is a stable code, so the agent does not have to read the sentence in `detail` to know what happened. `out_of_scope` names exactly which target was refused, which is what the agent narrows its own request with. The result is flagged `isError`, so an agent cannot mistake a refusal for an empty success.

### Call 2 — `scope.validate`

The narrowed brief, confirmed rather than assumed.

```json
{
  "name": "scope.validate",
  "arguments": {
    "manifest_path": "$TMPDIR/.tmpj58wJl/scope.json",
    "targets": [
      "192.168.1.64"
    ]
  }
}
```

```json
{
  "structuredContent": {
    "budget_ceiling": {
      "maximum_packets": 1000000,
      "maximum_packets_per_second": 20000,
      "maximum_runtime_seconds": 3600
    },
    "decision": "approved",
    "description": "bathy MCP test fixture",
    "expired": false,
    "in_scope_count": 1,
    "out_of_scope": [],
    "scope_id": "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    "signature_present": false,
    "signature_verified": false
  }
}
```

`in_scope_count` and an empty `out_of_scope`, plus `expired: false` -- an unexpired manifest is a separate question from an in-scope target, and both are typed.

### Call 3 — `scan.preview`

What the scan would do, before it does it.

```json
{
  "name": "scan.preview",
  "arguments": {
    "manifest_path": "$TMPDIR/.tmpj58wJl/scope.json",
    "request": {
      "idempotency_key": "inventory-workflow",
      "max_packets_per_second": 6,
      "objective": "inventory_exposed_services",
      "ports": {
        "explicit": [
          "56160",
          "56161",
          "56159"
        ]
      },
      "service_detection": {
        "enabled": true,
        "intensity": 9
      },
      "targets": [
        "192.168.1.64"
      ]
    }
  }
}
```

```json
{
  "structuredContent": {
    "estimated_probes": 3,
    "estimated_runtime_seconds": 1,
    "estimated_targets": 1,
    "plan_hash": "blake3:39b9f7c9f70a0d514f8bfa9bf7388073bda01eb24cc734a25ac5cf824603e457",
    "policy_decision": "approved",
    "scope_id": "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV"
  }
}
```

No packet is emitted here. `plan_hash` is what the agent holds the run to; `estimated_probes` is three because the request named three ports.

### Call 4 — `scan.start`

Start it.

```json
{
  "name": "scan.start",
  "arguments": {
    "manifest_path": "$TMPDIR/.tmpj58wJl/scope.json",
    "request": {
      "idempotency_key": "inventory-workflow",
      "max_packets_per_second": 6,
      "objective": "inventory_exposed_services",
      "ports": {
        "explicit": [
          "56160",
          "56161",
          "56159"
        ]
      },
      "service_detection": {
        "enabled": true,
        "intensity": 9
      },
      "targets": [
        "192.168.1.64"
      ]
    }
  }
}
```

```json
{
  "structuredContent": {
    "handle": {
      "estimated_targets": 1,
      "plan_hash": "blake3:39b9f7c9f70a0d514f8bfa9bf7388073bda01eb24cc734a25ac5cf824603e457",
      "policy_decision": "approved",
      "status": "running",
      "task_id": "scan_01KZ69K3WPDSTXPDNTCYB7DM14"
    },
    "policy_decision": "approved",
    "reused": false
  }
}
```

The handle comes back while the work is still running -- the next call proves that, because the first page of the log is not terminal. `handle.plan_hash` equals the previewed hash: the plan that ran is the plan that was approved.

### Call 5 — `scan.events`

Poll the durable log, page one.

```json
{
  "name": "scan.events",
  "arguments": {
    "after_sequence": 0,
    "limit": 200,
    "scan_id": "scan_01KZ69K3WPDSTXPDNTCYB7DM14"
  }
}
```

```json
{
  "structuredContent": {
    "events": [
      {
        "engine_version": "0.1.0",
        "estimated_probes": 3,
        "estimated_targets": 1,
        "event_type": "scan.started",
        "plan_hash": "blake3:39b9f7c9f70a0d514f8bfa9bf7388073bda01eb24cc734a25ac5cf824603e457",
        "scan_id": "scan_01KZ69K3WPDSTXPDNTCYB7DM14",
        "sequence": 1,
        "timestamp": "2026-08-04T11:47:23.671Z"
      }
    ],
    "has_more": false,
    "next_cursor": 1
  }
}
```

`next_cursor` is a typed field of the page. The agent does not track an offset of its own, and the pages here do not overlap.

### Call 6 — `scan.events`

Poll, page two.

```json
{
  "name": "scan.events",
  "arguments": {
    "after_sequence": 1,
    "limit": 200,
    "scan_id": "scan_01KZ69K3WPDSTXPDNTCYB7DM14"
  }
}
```

```json
{
  "structuredContent": {
    "events": [
      {
        "endpoint": {
          "port": 56159,
          "transport": "tcp"
        },
        "engine_version": "0.1.0",
        "event_type": "port.state",
        "scan_id": "scan_01KZ69K3WPDSTXPDNTCYB7DM14",
        "sequence": 2,
        "state": "closed",
        "target": {
          "ip": "192.168.1.64"
        },
        "timestamp": "2026-08-04T11:47:23.672Z"
      },
      {
        "endpoint": {
          "port": 56160,
          "transport": "tcp"
        },
        "engine_version": "0.1.0",
        "event_type": "port.state",
        "scan_id": "scan_01KZ69K3WPDSTXPDNTCYB7DM14",
        "sequence": 3,
        "state": "open",
        "target": {
          "ip": "192.168.1.64"
        },
        "timestamp": "2026-08-04T11:47:23.672Z"
      },
      {
        "endpoint": {
          "port": 56160,
          "transport": "tcp"
        },
        "engine_version": "0.1.0",
        "event_type": "service.observed",
        "evidence_refs": [
          "blake3:05fa3b0bf868080a06d86246b9fc573b7581fe518fbb1668857272bce58f7345"
        ],
        "observation": {
          "confidence": 0.95,
          "product": "nginx",
          "service": "http",
          "version": "1.26.0"
        },
        "probe_id": "http-get-v1",
        "scan_id": "scan_01KZ69K3WPDSTXPDNTCYB7DM14",
        "sequence": 4,
        "target": {
          "ip": "192.168.1.64"
        },
        "timestamp": "2026-08-04T11:47:23.689Z"
      },
      {
        "endpoint": {
          "port": 56161,
          "transport": "tcp"
        },
        "engine_version": "0.1.0",
        "event_type": "port.state",
        "scan_id": "scan_01KZ69K3WPDSTXPDNTCYB7DM14",
        "sequence": 5,
        "state": "open",
        "target": {
          "ip": "192.168.1.64"
        },
        "timestamp": "2026-08-04T11:47:23.689Z"
      }
    ],
    "has_more": false,
    "next_cursor": 5
  }
}
```

### Call 7 — `scan.events`

Poll, page three: `scan.completed`.

```json
{
  "name": "scan.events",
  "arguments": {
    "after_sequence": 5,
    "limit": 200,
    "scan_id": "scan_01KZ69K3WPDSTXPDNTCYB7DM14"
  }
}
```

```json
{
  "structuredContent": {
    "events": [
      {
        "engine_version": "0.1.0",
        "event_type": "scan.completed",
        "findings": 2,
        "packets_spent": 12,
        "probes_sent": 3,
        "scan_id": "scan_01KZ69K3WPDSTXPDNTCYB7DM14",
        "sequence": 6,
        "timestamp": "2026-08-04T11:47:24.682Z"
      }
    ],
    "has_more": false,
    "next_cursor": 6
  }
}
```

The terminal event is read from a typed `event_type`, not from prose.

### Call 8 — `result.query`

The answer, filtered.

```json
{
  "name": "result.query",
  "arguments": {
    "filter": {
      "service": "http",
      "state": "open"
    },
    "scan_id": "scan_01KZ69K3WPDSTXPDNTCYB7DM14"
  }
}
```

```json
{
  "structuredContent": {
    "endpoints": [
      {
        "endpoint": {
          "port": 56160,
          "transport": "tcp"
        },
        "evidence_refs": [
          "blake3:05fa3b0bf868080a06d86246b9fc573b7581fe518fbb1668857272bce58f7345"
        ],
        "observation": {
          "confidence": 0.95,
          "product": "nginx",
          "service": "http",
          "version": "1.26.0"
        },
        "probe_id": "http-get-v1",
        "state": "open",
        "target": "192.168.1.64"
      }
    ],
    "hosts_up": [],
    "plan_hash": "blake3:39b9f7c9f70a0d514f8bfa9bf7388073bda01eb24cc734a25ac5cf824603e457",
    "terminal": {
      "findings": 2,
      "outcome": "completed",
      "packets_spent": 12,
      "probes_sent": 3
    },
    "total": 1,
    "total_before_filter": 3
  }
}
```

Three endpoints were folded (`total_before_filter`) and one matched (`total`): the closed port fails `state`, and the port that accepts but says nothing fails `service`. Every field the report needs -- state, service, product, version, confidence, the evidence digest -- is typed.

### Call 9 — `evidence.get`

The bytes the finding is standing on.

```json
{
  "name": "evidence.get",
  "arguments": {
    "digest": "blake3:05fa3b0bf868080a06d86246b9fc573b7581fe518fbb1668857272bce58f7345"
  }
}
```

```json
{
  "structuredContent": {
    "bytes_hex": "485454502f312e3120323030204f4b0d0a5365727665723a206e67696e782f312e32362e300d0a436f6e6e656374696f6e3a20636c6f73650d0a0d0a3c68746d6c3e3c2f68746d6c3e",
    "digest": "blake3:05fa3b0bf868080a06d86246b9fc573b7581fe518fbb1668857272bce58f7345",
    "length": 73,
    "truncated": false
  }
}
```

`bytes_hex` decodes to the exact response the listener sent. The digest that names the bytes is verified before they are returned, so this is the evidence or it is an error.

---

## What this demonstrates

- **Ten or fewer typed calls** (AC-5.24). This run took nine: one refused
  validation, one confirming the narrowed brief, a preview, a start, three
  polls, one filtered query and one evidence fetch. The number of polls is the
  only part that varies, and the test fails rather than exceeding the budget.
- **No string construction and no prose parsing** (AC-5.25), asserted at the
  source of the test itself so it cannot rot quietly.
- **A refusal in the middle of the workflow, not at the end of it.** Call 1 is
  denied, and the denial is what the agent acts on: it reads `out_of_scope` and
  narrows its own request. A prose error would have left it nothing to branch
  on, and a refusal an agent cannot act on is a refusal it retries.
- **Every finding is evidence-backed.** The endpoint in call 8 cites a
  digest; call 9 returns the bytes behind it, verified against that digest.

## Reproducing it

The test needs a routable IPv4 address on the machine (every shipped manifest
refuses loopback) and binds its own listeners; it authorizes nothing but this
machine, through a manifest it writes into a temporary directory.

```console
$ cargo test -p bathy --test workflow
```

The same eleven tools are reachable from a shell -- `bathy scope validate`,
`bathy scan preview`, `bathy scan start`, `bathy scan events`,
`bathy result query`, `bathy evidence get` -- and answer with the same
documents. That is what makes this surface auditable without an MCP client;
see `docs/protocol-notes.md`.
