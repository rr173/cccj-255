# scanflow — offline audited scanner-code reception

A batch of legacy handheld terminals emits **action codes** with no separator:
each action is a non-empty byte code, and a frame body is just the concatenation
of the codes for the actions in order. The receiving station wraps each body in an
outer frame that names the terminal configuration version and the body length.

This package does four jobs:

1. **Offline release audit.** Decide, exactly, whether a configuration can ever
   produce *the same body for two different action sequences*. If it can, the
   configuration is refused and the conflict is reported with everything needed to
   reproduce it.
2. **Streaming reception.** Parse a continuous byte stream of frames, feed each
   complete frame to the approved configuration its header names, and return the
   ordered actions with half-open body byte spans — or a whole-frame rejection.
3. **Pre-switch historical compatibility.** Before replacing the configuration,
   replay a captured history of frame bodies under both the current and the
   candidate configuration and report whether every record still names the same
   ordered actions. The candidate must pass the release audit first.
4. **Batch reconciliation.** After a picking batch, reconcile a plan manifest
   against one captured stream delivered as out-of-order, possibly duplicated
   or overlapping retransmission fragments, and report planned versus
   confirmed counts per `(wire, action sequence)`.

All four live in `scanflow/`. No third-party dependencies; Python 3.9+.

## The conflict rule

* Short codes are kept; shared prefixes (`0a` and `0a0b`) are **not** a violation
  by themselves.
* A **release conflict** is a *non-empty body* that is accepted by **two different
  complete legal action sequences** from the start state to an accept state.
* Only non-empty action sequences that run the whole flow from start to accept and
  consume the whole body count. A dead-end prefix is not a record.
* The audit has **no fixed frame length**: it searches the product of the flow
  automaton with itself over all lengths the finite flow admits, so "no conflict
  at N bytes" can never be mistaken for "releasable".

## Configuration file

```json
{
  "version": "v3",
  "wire": 3,
  "codes": { "start": "0a", "stop": "0b", "increment": "0a0b" },
  "flow": {
    "start": "idle",
    "accepts": ["done"],
    "transitions": [
      ["idle", "start", "running"],
      ["running", "increment", "running"],
      ["running", "stop", "done"]
    ]
  }
}
```

* `version` — non-empty string, the release identity. Hex codes are used because
  JSON strings cannot carry arbitrary bytes unambiguously.
* `wire` — optional 0..255 on-wire version byte for the receiver (two approved
  configs may not share one).
* `codes` — action name → non-empty byte code (hex string or `bytes`). Codes must
  be distinct; a shared code could not be attributed to one action.
* `flow` — one `start`, a set of `accepts`, and `[state, action, next]` edges.
  At most one destination per `(state, action)`; loops are fine; the same action
  may appear in many states.

## What the audit proves and reports

`scanflow.audit.audit(config)` models each code as a byte-level NFA over
`(in, flow_state)` / `(mid, flow_state, action, consumed)`, then explores the
product `(left, right, diverged)`. A state where both sides accept and `diverged`
is set is exactly a body with two distinct legal spellings. The search is
breadth-first over a finite graph, so it is a decision procedure, and the first
witness is a shortest one.

Each conflict reports:

| field          | content                                                     |
|----------------|-------------------------------------------------------------|
| `body_hex`     | the raw frame body bytes                                    |
| `sequences`    | both complete action sequences                              |
| `spans`        | half-open byte spans of each action for each sequence       |
| `state_traces` | replayable flow state path per sequence (start → … → accept)|

If a safety cap (`max_product_states`) is exceeded, `AuditIncomplete` is raised;
the caller treats that as **not releasable**, never as success.

## Duplicate versions

`scanflow.registry.Registry.register` audits first and commits only on success.
The same version string with *different* content raises `VersionConflict` and the
approved configuration is never overwritten. A rejected new configuration leaves
every approved version untouched, so an old version cannot start reading
differently because a new document was refused. Rejections are retained in
`Registry.rejections` for inspection.

## Reception

The receiver format and rules are in [`docs/frame-format.md`](docs/frame-format.md).
In short: magic `A5 5C`, 1-byte version, 2-byte big-endian body length, body,
CRC-16/CCITT-FALSE. The length field is authoritative, so a frame with an unknown
version, a bad body, or a length over the receiver's explicit limit is discarded
whole and scanning resumes at the next frame. Input may be split at any byte
boundary; the receiver buffers until a frame is complete.

Returned outcomes per region of the stream:

* `frame_accepted` — CRC valid, version approved, exactly one legal walk; carries
  the ordered actions and their half-open spans. Never emitted if any of those
  fail, so no partial result leaks.
* `frame_rejected` — complete frame with a known boundary that is not deliverable
  (`crc_mismatch`, `unknown_version`, `no_legal_sequence`, `body_too_large`).
* `noise` — inter-frame bytes skipped.
* `truncated` — end of stream with buffered incomplete bytes; reported once,
  separately from any bad complete frame.

An approved configuration is immutable for the life of the receiver, so a version
already in use keeps its reading even after a later configuration is refused.

## Pre-switch historical compatibility

The audit proves a candidate cannot spell one body two ways. It does **not** prove
that already-captured bodies still mean the same business actions after the switch.
`check-compat` adds that evidence check. Each history line is
`<record-id> <body-hex>`; every record is decoded completely under both
configurations. Same ordered action names on both sides = compatible. A candidate
that cannot decode the body, or names a different sequence, is incompatible. A
current-side failure (no unique reading), a malformed line, or a duplicate id is
invalid evidence — no verdict is issued.

The overall verdict is replaceable only when the candidate audits clean, the
history has at least one record, and every record is compatible. The history file
is streamed line by line and the JSON report replaces its destination atomically,
only after every record has been validated; on any error an existing report is
left untouched. Full format and schema: [`docs/compatibility-check.md`](docs/compatibility-check.md).

```bash
python3 -m scanflow.cli check-compat \
    --current examples/good.json --candidate examples/good_next.json \
    --history examples/history.txt --report compat-report.json
# exit 0 replaceable, 3 not replaceable, 2 invalid evidence, 1 report write failed
```

## Batch reconciliation

After a picking batch, `check-batch` reconciles the planned scans against one
captured stream. Terminals re-transmit from the original byte position after a
disconnect, so the capture arrives as fragments that may be out of order,
duplicated or partially overlapping; retransmitted bytes must be identical and
count once. Only the contiguous known prefix from offset zero is interpreted
(with the existing frame format) — never spliced across gaps. The evidence is
complete only when the whole declared stream arrived with no noise, rejection
or truncation; otherwise confirmed counts are lower bounds and no short/over
verdict is issued. Plan, capture and result rows are all streamed through an
on-disk store, so none of them is bounded by RAM. Full input and output
formats: [`docs/batch-reconciliation.md`](docs/batch-reconciliation.md).

```bash
python3 -m scanflow.cli check-batch \
    --config examples/good.json \
    --plan examples/plan.jsonl --fragments examples/fragments.jsonl \
    --stream-total 29 --report batch-report.json
# exit 0 batch matches, 3 counts disagree, 4 evidence incomplete,
#      2 invalid evidence, 1 report write failed
```

## Usage

```bash
# Audit one configuration (exit 0 releasable, 3 conflict, 2 malformed/incomplete)
PYTHONPATH=. python3 -m scanflow.cli audit examples/conflict.json

# Audit a directory and load the approved set
PYTHONPATH=. python3 -m scanflow.cli audit-dir examples/

# Receive a captured stream; chunk size only affects buffering, never parsing
PYTHONPATH=. python3 -m scanflow.cli receive --config examples/good.json \
    --chunks 7 --json < capture.bin

# Check captured history reads identically under a candidate before switching
PYTHONPATH=. python3 -m scanflow.cli check-compat \
    --current examples/good.json --candidate examples/good_next.json \
    --history examples/history.txt --report compat-report.json

# Reconcile a picking batch: plan versus captured retransmission fragments
PYTHONPATH=. python3 -m scanflow.cli check-batch \
    --config examples/good.json \
    --plan examples/plan.jsonl --fragments examples/fragments.jsonl \
    --stream-total 29 --report batch-report.json
```

Library:

```python
from scanflow import Registry, CodeConfig, Receiver, encode_frame

reg = Registry()
reg.register(CodeConfig.from_json_text(open("examples/good.json").read()))
rcv = Receiver(reg, max_body_len=4096)
for chunk in transport:
    for event in rcv.feed(chunk):
        handle(event)
for event in rcv.finish():
    handle(event)
```

## Tests

```bash
PYTHONPATH=. python3 -I -m unittest discover -s tests -v
```

The suite cross-checks the audit against exhaustive decoding on small random
configurations, exercises every rejection path, verifies that arbitrary chunk
boundaries produce identical events, and covers the compatibility check's and
the batch reconciliation's verdict rules, streaming, and atomic report
replacement — including fragment reordering and retransmission invariance.

## Limits worth knowing

* A body is decoded only under the single version named in its header. There is no
  fallback to another version.
* The receiver's default body cap is 65536 (the 16-bit field's maximum). The audit
  is not subject to it.
* The audit explores a finite product of size roughly `(|states| + codes)²`, so it
  is practical for realistic scanner flows but not intended for enormous alphabets.
