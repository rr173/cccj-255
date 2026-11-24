# Batch reconciliation: planned scans versus captured fragments

After a picking batch ends, the site reconciles the scans that were *planned*
against the scans the receiving station actually *received*. Terminals that
lose their link re-transmit from the original byte position, so the capture of
one stream arrives as **fragments** that may be out of order, duplicated or
partially overlapping. `scanflow.batch` / `scanflow.cli check-batch` delivers
one batch reconciliation result from three inputs:

1. the **approved configuration set** (the existing audited configurations;
   every referenced `wire` must belong to one),
2. the **plan manifest** (JSONL),
3. the **capture**: the declared total byte count of the original stream plus
   a **fragments file** (JSONL).

One run reconciles exactly one captured stream. Configurations and raw inputs
are never modified; the only file ever written is the optional report, which
replaces its destination atomically (same rules as the compatibility report).

## Command line

```bash
python3 -m scanflow.cli check-batch \
    [--config CONFIG.json ...] [--config-dir DIR] \
    --plan PLAN.jsonl --fragments FRAGMENTS.jsonl \
    --stream-total N [--report OUT.json] [--json] [--max-body N]
```

* `--config` — one approved configuration JSON; repeatable.
  `--config-dir` — a directory of configuration JSON files. At least one
  configuration is required, and every offered document must audit clean: any
  rejection in the configuration set aborts the run (exit 2).
* `--plan` — the plan manifest (below).
* `--fragments` — the captured fragments (below).
* `--stream-total` — the declared total byte count of the original stream, a
  non-negative integer.
* `--report` — write the JSON result here, atomically, on success.
* `--max-body` — the receiver's body-length limit for framed evidence
  (default 65536, as in `receive`).
* `--json` — print a one-object summary on stdout instead of text.

Exit codes:

| code | meaning                                                                 |
|------|-------------------------------------------------------------------------|
| 0    | evidence complete and every row matches — **batch matches**             |
| 3    | evidence complete, but at least one row is short or over                |
| 4    | evidence incomplete — confirmed counts are lower bounds, no conclusion  |
| 2    | invalid evidence: bad configuration, plan or fragment input, or a byte conflict between fragments |
| 1    | the report could not be written (existing report left untouched)        |

## Plan manifest (JSONL)

One JSON object per line, UTF-8, LF or CRLF, no blank lines:

```json
{"wire": 1, "actions": ["start", "increment", "stop"], "planned": 12}
```

| field      | content                                                                 |
|------------|-------------------------------------------------------------------------|
| `wire`     | integer 0..255; the on-wire version byte of an approved configuration   |
| `actions`  | non-empty array of non-empty action-name strings, in scan order         |
| `planned`  | positive integer: how many times this sequence was planned              |

Rules:

* Exactly these three fields are accepted; a missing or extra field, a
  duplicate JSON key, or a value of the wrong type is a format error.
* The sequence must be **legal**: walking the configuration for `wire` from
  its start state through `actions` must end in an accept state. An unknown
  action, a missing transition, or a sequence that stops short of an accept
  state is an illegal plan entry.
* The same `(wire, actions)` pair may not be declared twice. The same
  sequence under two different wires is two independent rows.

## Capture fragments (JSONL)

One JSON object per line:

```json
{"offset": 0, "data_hex": "a55c0100020a0b8b9d"}
```

| field      | content                                                                 |
|------------|-------------------------------------------------------------------------|
| `offset`   | zero-based byte position in the original stream, integer ≥ 0            |
| `data_hex` | non-empty hex string; at most 64 KiB (65536) decoded bytes              |

Rules:

* Exactly these two fields; format strictness matches the plan.
* A fragment must lie entirely inside the declared range:
  `offset + len(data) ≤ stream-total`.
* Retransmitted bytes must be **identical**: wherever two fragments cover the
  same position, the bytes must agree. Identical bytes count once. Any
  position with conflicting content is invalid evidence — no reconciliation
  conclusion is issued (exit 2), and the error names the first conflicting
  offset.

## How the evidence is interpreted

1. Fragments are merged by original byte position into a set of known
   intervals (order of arrival and retransmission count are irrelevant).
2. Only the **contiguous known prefix starting at offset 0** is interpreted,
   in original byte order, with the existing frame format
   (`docs/frame-format.md`). Bytes past the first gap are never spliced
   together, and frame boundaries are never re-guessed after a gap.
3. Frame header and body may span fragments. Frame identity comes from
   stream position: the same frame bytes at two positions count twice; a
   retransmission of one position counts once.
4. Every accepted frame increments the confirmed count of its
   `(wire, ordered action sequence)` by one.
5. The evidence is **complete** only when the whole declared range is
   received *and* the reception shows no `noise`, no `frame_rejected` and no
   `truncated` event. Otherwise confirmed counts are **lower bounds**.

## Result: JSON report

```json
{
  "kind": "scanflow.batch_reconciliation",
  "format_version": 1,
  "stream_total": 29,
  "coverage": {"received_bytes": 29, "complete": true,
               "first_missing_offset": null},
  "reception": {"parsed_prefix_bytes": 29, "frames_accepted": 3,
                "frames_rejected": 0, "noise_regions": 0, "noise_bytes": 0,
                "truncated": false, "clean": true},
  "evidence_complete": true,
  "counts_are_lower_bounds": false,
  "rows": [
    {"wire": 1, "actions": ["start", "increment", "stop"],
     "planned": 1, "confirmed": 1, "status": "match"},
    {"wire": 1, "actions": ["start", "stop"],
     "planned": 2, "confirmed": 2, "status": "match"}
  ],
  "counts": {"rows": 2, "match": 2, "short": 0, "over": 0},
  "batch_match": true
}
```

Top-level fields:

| field                     | content                                                              |
|---------------------------|----------------------------------------------------------------------|
| `stream_total`            | the declared total byte count                                        |
| `coverage.received_bytes` | distinct positions covered by the capture (duplicates counted once)  |
| `coverage.complete`       | true when every byte of `[0, stream_total)` arrived                  |
| `coverage.first_missing_offset` | first position not received, or `null` when coverage is complete |
| `reception.*`             | what the receiver saw in the parsed prefix: accepted/rejected frames, noise regions and bytes, truncation, and `clean` (none of those) |
| `evidence_complete`       | `coverage.complete and reception.clean`                              |
| `counts_are_lower_bounds` | `not evidence_complete`                                              |
| `rows`                    | one row per `(wire, actions)` seen on either side (below)            |
| `counts`                  | row tallies; `match`/`short`/`over` are `null` when incomplete       |
| `batch_match`             | `true` only when evidence is complete and every row matches; `false` on a confirmed disagreement; `null` when the evidence is incomplete |

Each row covers one `(wire, ordered action sequence)` that was planned or
confirmed (or both); a side that never saw it counts as zero:

| field       | content                                                                 |
|-------------|-------------------------------------------------------------------------|
| `wire`      | the on-wire version byte                                                |
| `actions`   | the ordered action-name sequence                                        |
| `planned`   | planned count (0 when the sequence was never planned)                   |
| `confirmed` | confirmed count from the parsed prefix (0 when never confirmed); a lower bound unless the evidence is complete |
| `status`    | `"match"` / `"short"` / `"over"` when the evidence is complete, else `null` — an incomplete capture never characterises a difference as short or over |

Rows are ordered by `wire` value, then by action-name sequence: sequences
compare element by element (names by Unicode code point) and a strict prefix
sorts first — e.g. `["A","B"]` before `["A","B","C"]` before `["AB"]` before
`["B"]`.

When the evidence is incomplete, `first_missing_offset` names the first byte
that never arrived (or `null` if everything arrived but the reception was not
clean), every row's `status` is `null`, and `batch_match` is `null`.

## Streaming and atomicity

The plan, the capture and the result rows may all exceed available memory.
Plan counts, confirmed counts and the merged fragment bytes live in a
temporary SQLite database on disk; both inputs are consumed line by line, the
known prefix is replayed segment by segment, and the report's rows are
streamed out. The report is written to a temporary file in the destination
directory and `os.replace`d over its target only after every input line has
been validated and the closing JSON flushed; on any error the temporary file
is removed and an existing report is left byte-for-byte untouched. The report
path may not coincide with the plan, the fragments, or any configuration
file. The report's existing permission bits are preserved (a new file gets
the process umask).

Because the merge is by position, **reordering the fragments or changing how
often any range was retransmitted never changes the result** — the report is
byte-for-byte identical.

## Library

```python
from scanflow import (
    Registry, CodeConfig, reconcile_batch, iter_plan, iter_fragments,
)

reg = Registry()
reg.register(CodeConfig.from_json_text(open("examples/good.json").read()))
summary = reconcile_batch(reg, "plan.jsonl", "fragments.jsonl", 29,
                          report_path="batch-report.json")
if summary.evidence_complete:
    print("batch matches" if summary.batch_match else "batch mismatch")
else:
    print("no conclusion; first missing byte:", summary.first_missing_offset)
```

`iter_plan(path, registry)` and `iter_fragments(path, stream_total)` stream
and validate the two inputs without writing a report. Errors raise
`BatchError` subclasses: `PlanFormatError`, `IllegalPlanSequence`,
`DuplicatePlanEntry`, `FragmentFormatError`, `FragmentRangeError`,
`FragmentConflictError`, and `BatchReportWriteError` for the report itself.
