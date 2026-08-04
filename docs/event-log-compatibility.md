# The event log's compatibility policy

The append-only JSONL event log is this project's source of truth. SQLite
state elsewhere is a derived index, rebuildable from the log and never the
other way around.

That sentence has been in `README.md` since M2. In M5 it stopped being true,
and nothing noticed for a milestone.

---

## What happened

`bd386e9` added a required `rule_id` field to `service.observed`. From that
commit, a log written by the *previous* commit could not be deserialized.
Because one unreadable line fails the whole read, the failure was total rather
than partial: a five-record log with one affected record became five
unreachable records.

| Surface | A log written one commit earlier |
|---|---|
| `bathy result query` | failed |
| `bathy result diff` | failed |
| `bathy scan events` | failed |
| MCP `result.query`, `scan.events` | failed |
| `bathy scan status`, MCP `scan.status` | **succeeded** — reads SQLite |

The derived index went on answering and the source of truth did not. That is
the precise inversion of the guarantee, demonstrated rather than risked.

There was no mechanism behind the guarantee at all: no defaults, no version
branch, no migration, and — the reason it went unnoticed — no test that any
older log loads. `bathy-store` has had `PRAGMA user_version` and a real
in-place migration since AC-3.34; the *derived index* had a versioning story
and the source of truth had none.

## The policy

**1. The record shape is append-only, like the log itself.**

- A field may be **added** to an event record. It must be optional in the
  Rust type (`Option<T>` with `#[serde(default)]`) and must stay optional
  forever, no matter how long every log in existence has carried it.
- A field may **never** be added as required, removed, renamed, retyped, or
  narrowed (a `String` becoming an enum is a narrowing). A new `event_type`
  variant is always allowed; readers already ignore nothing and reject
  unknown tags loudly, and old logs contain only old tags.
- A field that has existed since before the log did **stays required**. It is
  in no log's past, so relaxing it buys compatibility with nothing and costs
  a live guarantee. `probe_id` is the worked example: it has been in
  `service.observed` since `54f7b46`, the commit that created
  `crates/bathy-types/src/event.rs`, which is earlier than `b50763a`, the
  commit that created the log. `a_field_that_predates_the_log_is_still_required`
  fails if anyone relaxes it.

**2. Absent is a meaning, and it is not "empty".**

For `rule_id`, absent means **unattributed**: the build that wrote the record
did not write down which interpretation rule decided. It does not mean no rule
fired — a `service.observed` record exists *because* one did. Every current
build always writes the field, so absence dates a record rather than
describing it.

This is why the type is `Option<String>` and not `String` with a default. A
defaulted `String` would load an old record as `rule_id: ""` — a value its
writer never wrote, materialized on read and written back out on any
re-serialization. An append-only evidence log whose records change shape on the
way through a reader is not content-addressed evidence.
`reading_an_old_record_and_writing_it_back_invents_nothing` pins the round
trip byte for byte.

`Option` also reuses vocabulary that already exists: `bathy_query::EndpointState`
has published `rule_id: null` since M5 for an endpoint nothing identified. An
agent that already handles a null rule id handles an old log with no new code.
The empty string would have been a third state every consumer had to learn.

**3. Every addition is registered, and the register is tested.**

`FIELDS_ADDED_AFTER_THE_LOG_EXISTED` in `crates/bathy-types/src/event.rs`
lists every field added to a record shape after logs could exist.
`an_added_field_is_optional_in_every_direction` removes each registered field
from the canonical example and asserts the record still loads. One entry today
(`rule_id`), and the sweep that established that was run by execution:
`git show b50763a:crates/bathy-types/src/event.rs` is the file as it stood
when the log was created, and every other field of every variant is still
present and still required.

**4. A committed fixture, in the genuinely old shape.**

`crates/bathy-query/tests/fixtures/pre-rule-id-scan.jsonl` is a log from a
real scan — real listener, real TCP connect, real captured nginx banner — with
the one `rule_id` member removed. `old_log_compatibility.rs` reads it through
`EventLogReader` and folds it, and its first test fails if the fixture ever
acquires a `rule_id`. A compatibility guarantee with no fixture is a promise
nobody checks, and a fixture that satisfies every branch tests none of them.

## Why there is no log format version

There is no `log_version` or `schema_version` field on an event record, and
adding one would be worse than not having one.

A version field earns its place when something **branches** on it. Under the
policy above nothing ever does: the reader's behaviour for an old record and a
new one is identical, because the only permitted change is an addition that
defaults. A version nobody branches on is `engine_version` all over again —
written on every record, consulted nowhere — and this document exists partly
because that already happened once.

The day an incompatible change is genuinely unavoidable, the mechanism is a
new `event_type`, not a version gate on the existing ones: a new record shape
under a new tag leaves every old record readable by construction, which is the
outcome a version field would only have let us *detect*.

## What `engine_version` is for

Provenance, and exactly one thing more.

It records which build wrote each record, so a finding replayed years later can
be attributed to the code that produced it. It is deliberately **not** a
compatibility switch — nothing branches on it, and per the section above
nothing should.

Until the M5 blocker wave it had no reader anywhere in the workspace. It has
one now: `malformed_record` in `crates/bathy-evidence/src/log.rs` re-reads it
when a record fails to deserialize, so the error names the build that wrote the
record alongside the build that cannot read it, instead of reporting only the
missing field. Provenance nobody can read is decoration; this is the smallest
job that makes it real, and it is the job that matters — the one failure this
policy says must never happen is the one you want diagnosable when it does.

## Error codes

A log that is **absent** is `no_such_scan_log`. A log that is **present and
unreadable** is `log_unreadable`. `EventLogReader::open` validates every record
on the way in, so both conditions arrive through the same call, and until the
M5 blocker wave both were reported as `no_such_scan_log` — telling an agent
that a scan was gone when the truth was that its log had outlived a shape
change. The `detail` was accurate throughout and the code was not; an agent
branches on the code.
