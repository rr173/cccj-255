# Pre-switch historical compatibility check

The release audit proves that a **candidate** configuration cannot spell one body
in two different ways. It does not prove that bodies **already captured** under the
current configuration still read as the same business actions after the switch.
`scanflow.compat` / `scanflow.cli check-compat` supplies that evidence.

## Verdict rule

1. The candidate must pass the existing offline audit
   (`scanflow.audit.audit`, no release conflict). A conflict, or an audit stopped by
   its `--max-product-states` bound, means no switch verdict can be issued at all
   (exit 2); the history is not consulted and no report is written.
2. Every history record is decoded **completely** under both configurations. The
   record is **compatible** only when both sides yield the same ordered action-name
   sequence. A candidate with no complete legal walk, or with an ambiguous one,
   is incompatible.
3. The overall result is **replaceable** exactly when the candidate audited
   clean and the incompatible count is zero. (An empty history therefore yields
   `replaceable: true` with zero counts: the check reports what it was given and
   does not invent records.)

### Invalid evidence (no verdict)

These make the input unusable, so no replaceable/not-replaceable conclusion is
issued (exit 2):

* a malformed history line (blank line, wrong field count, odd-length hex, non-hex
  characters, invalid UTF-8), a read error, or a duplicate record id;
* a record the **current** configuration cannot read uniquely: no complete legal
  action sequence, or more than one (a released configuration should never be
  ambiguous, but if it is, the historical meaning itself is undefined);
* a missing or malformed configuration file, or a candidate that fails the audit.

A candidate-side decode failure is *not* invalid evidence: it is a concrete reason
the switch is not replaceable (exit 3).

## History input

One record per line, UTF-8, LF or CRLF:

```
<record-id> <body-hex>
```

* `<record-id>` — any non-empty token without whitespace; unique within the file.
* `<body-hex>` — the raw frame body as an even-length string of hex digits,
  `0-9a-fA-F`. No `0x` prefix, no separators. It is the body only; the outer frame
  (magic, version, length, CRC) is not part of the input.
* Fields are separated by one or more spaces or tabs. Exactly two fields are
  accepted; a trailing third field is an error, not silently ignored.
* Bodies are non-empty hex strings; the empty body cannot carry an action
  sequence, and a line without a body field is a format error.

Example (see `examples/history.txt`):

```
rec-0001 0a0b
rec-0002 0a0a0b0b
rec-0003 0a0a0b0a0b0b
```

Identical bodies under different ids are checked and reported independently; each
record appears once in the result, in input order. Order is the file order, so the
same inputs always produce the same output.

## Streaming and atomic report replacement

The history file is read line by line; it is never loaded whole. Decoding one body
is bounded by that body's length. Duplicate ids are tracked in a temporary SQLite
database on disk, so the id index does not grow with the file in RAM (the SQLite
module is part of the Python standard library).

When `--report PATH` is given, the JSON report is written to a temporary file in
the same directory and `os.replace`d over `PATH` only after the last line has been
validated and the closing JSON written and flushed. On any invalid input, decode
failure or write failure the temporary file is removed and an existing `PATH` is
left byte-for-byte unchanged. The report file's existing permission bits are
preserved (a new file gets the process umask). A report path equal to the history
file is refused. Without `--report` the check still runs and only the summary is
printed.

Only the record index is externalised; a single line (one record id plus one body)
must still fit in memory. Bodies up to the 65536-byte receiver limit are well
within that.

## Result: JSON report

```json
{
  "kind": "scanflow.compatibility",
  "format_version": 1,
  "current_version": "cur",
  "candidate_version": "cand",
  "records": [
    {
      "line": 1,
      "record_id": "rec-0001",
      "body_hex": "0a0b",
      "body_len": 2,
      "compatible": true,
      "current":   {"status": "unique", "actions": ["A", "B"],
                    "spans": [[0,1],[1,2]], "state_trace": ["s","s","ok"]},
      "candidate": {"status": "unique", "actions": ["A", "B"],
                    "spans": [[0,1],[1,2]], "state_trace": ["s","s","ok"]},
      "difference": {"kind": "none"}
    },
    {
      "line": 2,
      "record_id": "rec-0002",
      "body_hex": "0a0b",
      "body_len": 2,
      "compatible": false,
      "current":   {"status": "unique", "actions": ["A", "B"], "...": "..."},
      "candidate": {"status": "unique", "actions": ["A", "CHG"], "...": "..."},
      "difference": {
        "kind": "action_sequence_mismatch",
        "common_prefix": ["A"],
        "current_remainder": ["B"],
        "candidate_remainder": ["CHG"],
        "first_divergence": {"index": 1, "current": "B", "candidate": "CHG"}
      }
    }
  ],
  "counts": {"records": 2, "compatible": 1, "incompatible": 1},
  "replaceable": false,
  "complete": true
}
```

`difference.kind` is one of:

| kind                          | meaning                                                        |
|-------------------------------|----------------------------------------------------------------|
| `none`                        | both sides read the same ordered actions (compatible)          |
| `action_sequence_mismatch`    | both decode, but the action names differ at `first_divergence` |
| `candidate_no_legal_sequence` | candidate has no complete legal walk for the body              |
| `candidate_ambiguous`         | candidate has more than one legal walk (defensive; an audited candidate should not reach this) |

A side reading with `status: "unique"` carries `actions`, the half-open byte
`spans` of each action, and the replayable `state_trace` (start state followed by
the state after each action). A side with `no_legal_sequence` carries `actions:
null`, `furthest_pos` and `furthest_states` as a diagnostic; an `ambiguous` side
carries `actions: null`. Current-side non-unique readings abort the run and never
appear in a report.

Every record is its own entry even when bodies coincide: the `record_id` and
`line` distinguish them.

## Command line

```bash
python3 -m scanflow.cli check-compat \
    --current  examples/good.json \
    --candidate examples/good_next.json \
    --history  examples/history.txt \
    --report   compat-report.json [--json] [--max-product-states N]
```

Exit codes:

| code | meaning                                                              |
|------|----------------------------------------------------------------------|
| 0    | replaceable: candidate audited clean and every record matches        |
| 3    | not replaceable: at least one record differs                         |
| 2    | invalid evidence: bad configuration, candidate audit failure, bad history line, duplicate id, or current-side decode failure |
| 1    | the report could not be written (existing report left untouched)      |

`--json` prints a one-object summary (versions, verdict, counts, report path) on
stdout. Without `--report` the exit-code semantics are identical; no file is
touched.

## Library

```python
from scanflow import CodeConfig
from scanflow.compat import (
    CompatibilityError, check_compatibility, compare_history, iter_history,
)

summary = check_compatibility(current, candidate, "history.txt",
                              report_path="compat-report.json")
# Raises HistoryFormatError / DuplicateRecordId / CurrentDecodeError for invalid
# evidence, CandidateNotReleasable for a failed candidate audit, and
# ReportWriteError (an OSError subclass of CompatibilityError) on write failure.
if summary.replaceable:
    ...  # safe to switch
else:
    print(summary.compatible, summary.incompatible, "of", summary.total)

for record in iter_history("history.txt"):        # streaming, format-checked
    ...
for comparison in compare_history(current, candidate, "history.txt"):
    print(comparison.record_id, comparison.compatible, comparison.difference)
```

`iter_history` / `compare_history` stream and therefore do not write a report;
atomic replacement is provided by `check_compatibility` (or the CLI).
