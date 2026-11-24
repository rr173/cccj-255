"""Local batch reconciliation: planned scans versus captured stream fragments.

After a picking batch the site compares the scans that were *planned* against
the scans the receiving station actually *received*.  Terminals that lose
their link re-transmit from the original byte position, so the capture of one
stream arrives as fragments that may be out of order, duplicated or partially
overlapping.  One run reconciles exactly one captured stream; configurations
and raw inputs are never modified.

Inputs
------
* an approved-configuration set (the existing audited registry),
* a plan manifest (JSONL), one object per line::

      {"wire": 1, "actions": ["start", "increment", "stop"], "planned": 12}

  ``wire`` is the on-wire version byte of an approved configuration,
  ``actions`` a complete ordered action-name sequence that walks that
  configuration from its start state to an accept state, and ``planned`` a
  positive integer.  The same ``(wire, actions)`` pair may not be declared
  twice.
* the declared total byte count of the original stream, and
* a fragments file (JSONL), one object per line::

      {"offset": 0, "data_hex": "a55c0100020a0b0e1c"}

  ``offset`` is the zero-based position in the original stream and
  ``data_hex`` a non-empty hex string carrying at most 64 KiB of decoded
  bytes, lying entirely inside the declared range.  Bytes retransmitted for
  the same position must be identical; identical bytes count once.

Any conflicting byte position, malformed input line or illegal plan entry
means no reconciliation conclusion is issued at all.

Evidence rules
--------------
Only the contiguous known prefix starting at offset 0 is interpreted, in
original byte order, with the existing frame format.  Bytes past the first
gap are never spliced together and frame boundaries are never re-guessed
after a gap.  Frame identity comes from stream position: the same frame bytes
at two positions count twice; a retransmission of one position counts once.
The evidence is *complete* only when the whole declared range is received and
the reception shows no noise, no rejected frame and no truncation.  Otherwise
confirmed counts are lower bounds, the first missing byte offset is reported
(when there is one), and no row is characterised as short or over.

Memory
------
The plan, the capture and the result rows may all exceed RAM.  Plan counts,
confirmed counts and the merged fragment bytes live in a temporary SQLite
database on disk; inputs are consumed line by line and the JSON report is
streamed to a temporary file that replaces its destination atomically only
after a complete, valid run.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Tuple, Union

from .config import CodeConfig
from .receiver import (
    DEFAULT_MAX_BODY,
    FrameAccepted,
    FrameRejected,
    Noise,
    Receiver,
    Truncated,
)
from .registry import Registry

__all__ = [
    "BatchError",
    "BatchReportWriteError",
    "BatchSummary",
    "DuplicatePlanEntry",
    "Fragment",
    "FragmentConflictError",
    "FragmentError",
    "FragmentFormatError",
    "FragmentRangeError",
    "IllegalPlanSequence",
    "MAX_FRAGMENT_BYTES",
    "PlanEntry",
    "PlanError",
    "PlanFormatError",
    "check_plan_sequence",
    "iter_fragments",
    "iter_plan",
    "parse_fragment_line",
    "parse_plan_line",
    "reconcile_batch",
]

#: One fragment carries at most this many decoded bytes (64 KiB).
MAX_FRAGMENT_BYTES = 1 << 16

#: Counts and offsets are tracked in SQLite INTEGER columns (signed 64-bit).
_SQLITE_MAX_INT = (1 << 63) - 1

#: sqlite3.Error plus the OverflowError raised for integers beyond its range.
_STORE_FAILURES = (sqlite3.Error, OverflowError)

REPORT_KIND = "scanflow.batch_reconciliation"
SUMMARY_KIND = "scanflow.batch_reconciliation.summary"
FORMAT_VERSION = 1

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


# -- errors ------------------------------------------------------------------


class BatchError(Exception):
    """No batch reconciliation conclusion can be issued.

    Raised for invalid evidence: a malformed plan or fragment line, an
    illegal plan entry, a duplicate plan declaration, a byte-level conflict
    between overlapping fragments, or an unreadable input.  The batch is
    never characterised as matching or not matching on such input.
    """


class PlanError(BatchError):
    """The plan manifest is unusable."""


class PlanFormatError(PlanError):
    """One plan line is not a valid ``{"wire", "actions", "planned"}`` object."""

    def __init__(self, line_no: int, detail: str) -> None:
        super().__init__(f"plan line {line_no}: {detail}")
        self.line_no = line_no
        self.detail = detail


class IllegalPlanSequence(PlanError):
    """A planned action sequence does not walk its configuration start -> accept."""

    def __init__(self, line_no: int, detail: str) -> None:
        super().__init__(f"plan line {line_no}: {detail}")
        self.line_no = line_no
        self.detail = detail


class DuplicatePlanEntry(PlanError):
    """The same (wire, actions) sequence was declared twice in the plan."""

    def __init__(self, wire: int, actions: Tuple[str, ...], line_no: int,
                 first_line: int) -> None:
        super().__init__(
            f"plan line {line_no}: sequence {list(actions)!r} for wire {wire} "
            f"was already declared on line {first_line}"
        )
        self.wire = wire
        self.actions = tuple(actions)
        self.line_no = line_no
        self.first_line = first_line


class FragmentError(BatchError):
    """The captured fragments are unusable."""


class FragmentFormatError(FragmentError):
    """One fragment line is not a valid ``{"offset", "data_hex"}`` object."""

    def __init__(self, line_no: int, detail: str) -> None:
        super().__init__(f"fragments line {line_no}: {detail}")
        self.line_no = line_no
        self.detail = detail


class FragmentRangeError(FragmentError):
    """A fragment does not lie entirely inside the declared stream range."""

    def __init__(self, line_no: int, detail: str) -> None:
        super().__init__(f"fragments line {line_no}: {detail}")
        self.line_no = line_no
        self.detail = detail


class FragmentConflictError(FragmentError):
    """Two fragments carry different bytes for the same stream position."""

    def __init__(self, position: int, line_no: int) -> None:
        super().__init__(
            f"fragments line {line_no}: byte at stream offset {position} "
            f"conflicts with an earlier fragment"
        )
        self.position = position
        self.line_no = line_no


class BatchReportWriteError(BatchError, OSError):
    """The report could not be written; any existing report is still intact."""


# -- small shared helpers ------------------------------------------------------


class _DuplicateKey(ValueError):
    pass


def _object_without_duplicate_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise _DuplicateKey(f"duplicate object key {key!r}")
        obj[key] = value
    return obj


def _load_json_object(text: str, line_no: int, error_type) -> dict:
    if not text.strip():
        raise error_type(line_no, "blank line; expected a JSON object")
    try:
        obj = json.loads(text, object_pairs_hook=_object_without_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise error_type(line_no, f"invalid JSON: {exc}") from exc
    except _DuplicateKey as exc:
        raise error_type(line_no, str(exc)) from exc
    if not isinstance(obj, dict):
        raise error_type(line_no, "expected a JSON object")
    return obj


def _check_fields(obj: dict, required: Tuple[str, ...], line_no: int,
                  error_type) -> None:
    missing = [key for key in required if key not in obj]
    if missing:
        raise error_type(line_no, f"missing field(s): {', '.join(missing)}")
    extra = sorted(key for key in obj if key not in required)
    if extra:
        raise error_type(line_no, f"unexpected field(s): {', '.join(extra)}")


def _as_int(value: object, what: str, line_no: int, error_type) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise error_type(line_no, f"{what}: expected an integer")
    return value


def _brief(text: str, limit: int = 40) -> str:
    return text if len(text) <= limit else text[:limit] + "..."


def _iter_lines(path: Union[str, os.PathLike], what: str,
                error_type) -> Iterator[Tuple[int, str]]:
    """Yield ``(line_no, text)`` for one JSONL input, LF or CRLF, UTF-8 only."""
    try:
        with open(path, "rb") as handle:
            for line_no, raw in enumerate(handle, 1):
                if raw.endswith(b"\n"):
                    raw = raw[:-1]
                if raw.endswith(b"\r"):
                    raw = raw[:-1]
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise error_type(line_no, "not valid UTF-8") from exc
                yield line_no, text
    except OSError as exc:
        raise BatchError(
            f"could not read {what} file {os.fspath(path)!r}: {exc}") from exc


def _actions_key(actions) -> str:
    """Canonical, ASCII-safe, injective encoding of one action-name sequence."""
    return json.dumps(list(actions), ensure_ascii=True, separators=(",", ":"))


def _sequence_collate(left: str, right: str) -> int:
    """Order two ``_actions_key`` strings as action-name sequences.

    Sequences compare element by element (names by Unicode code point); a
    strict prefix sorts first.  This is *not* the byte order of the encoded
    key, so the final row ordering must go through this collation.
    """
    a = tuple(json.loads(left))
    b = tuple(json.loads(right))
    return (a > b) - (a < b)


# -- plan input ----------------------------------------------------------------


@dataclass(frozen=True)
class PlanEntry:
    wire: int
    actions: Tuple[str, ...]
    planned: int
    line_no: int


_PLAN_FIELDS = ("wire", "actions", "planned")


def parse_plan_line(text: str, line_no: int) -> Tuple[int, Tuple[str, ...], int]:
    """Format-check one plan line; return ``(wire, actions, planned)``.

    This checks the shape of the declaration only.  Wire resolution and the
    start-to-accept walk are checked separately by :func:`check_plan_sequence`
    (both are enforced by :func:`iter_plan`).
    """
    obj = _load_json_object(text, line_no, PlanFormatError)
    _check_fields(obj, _PLAN_FIELDS, line_no, PlanFormatError)
    wire = _as_int(obj["wire"], "wire", line_no, PlanFormatError)
    if not 0 <= wire <= 0xFF:
        raise PlanFormatError(line_no, f"wire: expected 0..255, got {wire}")
    actions = obj["actions"]
    if not isinstance(actions, list) or not actions:
        raise PlanFormatError(
            line_no, "actions: expected a non-empty array of action names")
    for action in actions:
        if not isinstance(action, str) or action == "":
            raise PlanFormatError(
                line_no, "actions: every action name must be a non-empty string")
    planned = _as_int(obj["planned"], "planned", line_no, PlanFormatError)
    if planned < 1:
        raise PlanFormatError(
            line_no, f"planned: expected a positive integer, got {planned}")
    return wire, tuple(actions), planned


def check_plan_sequence(config: CodeConfig, actions: Tuple[str, ...],
                        line_no: int) -> None:
    """Require *actions* to walk *config* from its start state to an accept state."""
    state = config.start
    for action in actions:
        if action not in config.codes:
            raise IllegalPlanSequence(
                line_no,
                f"action {action!r} has no code entry in configuration "
                f"{config.version!r}")
        nxt = config.transitions.get((state, action))
        if nxt is None:
            raise IllegalPlanSequence(
                line_no,
                f"configuration {config.version!r} has no transition from "
                f"state {state!r} on action {action!r}")
        state = nxt
    if state not in config.accepts:
        raise IllegalPlanSequence(
            line_no,
            f"sequence ends in state {state!r}, which is not an accept state "
            f"of configuration {config.version!r}")


class _PlanIndex:
    """Exact duplicate-key index on disk, so memory does not grow with the plan."""

    def __init__(self) -> None:
        self._dir = tempfile.mkdtemp(prefix="scanflow-batch-plan-")
        self._conn: Optional[sqlite3.Connection] = None
        try:
            self._conn = sqlite3.connect(
                os.path.join(self._dir, "plan-index.sqlite3"),
                isolation_level=None)
            # This database only indexes plan keys for the duration of one
            # run and is discarded afterwards, so crash durability is moot.
            self._conn.execute("PRAGMA journal_mode=OFF")
            self._conn.execute("PRAGMA synchronous=OFF")
            self._conn.execute(
                "CREATE TABLE seen (wire INTEGER NOT NULL, "
                "actions TEXT NOT NULL, line INTEGER NOT NULL, "
                "PRIMARY KEY (wire, actions)) WITHOUT ROWID"
            )
            self._conn.execute("BEGIN IMMEDIATE")
        except BaseException:
            self.close()
            raise

    def add(self, wire: int, actions: Tuple[str, ...],
            line_no: int) -> Optional[int]:
        """Record one key; return the first line declaring it, if any."""
        assert self._conn is not None
        key = _actions_key(actions)
        try:
            row = self._conn.execute(
                "SELECT line FROM seen WHERE wire = ? AND actions = ?",
                (wire, key)).fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO seen (wire, actions, line) VALUES (?, ?, ?)",
                    (wire, key, line_no))
                return None
        except _STORE_FAILURES as exc:
            raise BatchError(f"could not track plan entries: {exc}") from exc
        return int(row[0])

    def close(self) -> None:
        conn, self._conn = self._conn, None
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass
        shutil.rmtree(self._dir, ignore_errors=True)


def iter_plan(path: Union[str, os.PathLike],
              registry: Registry) -> Iterator[PlanEntry]:
    """Yield validated plan entries in file order.

    Every line is format-checked; its ``wire`` must name an approved
    configuration in *registry* and its action sequence must walk that
    configuration from the start state to an accept state.  Declaring the
    same ``(wire, actions)`` twice raises :class:`DuplicatePlanEntry`.  Any
    problem raises :class:`PlanError`; no conclusion may be drawn from a
    partially read plan.
    """
    index = _PlanIndex()
    try:
        for line_no, text in _iter_lines(path, "plan", PlanFormatError):
            wire, actions, planned = parse_plan_line(text, line_no)
            config = registry.get_wire(wire)
            if config is None:
                raise PlanFormatError(
                    line_no,
                    f"wire {wire} has no approved configuration")
            check_plan_sequence(config, actions, line_no)
            first_line = index.add(wire, actions, line_no)
            if first_line is not None:
                raise DuplicatePlanEntry(wire, actions, line_no, first_line)
            yield PlanEntry(wire, actions, planned, line_no)
    finally:
        index.close()


# -- fragment input ------------------------------------------------------------


@dataclass(frozen=True)
class Fragment:
    offset: int
    data: bytes
    line_no: int


_FRAGMENT_FIELDS = ("offset", "data_hex")


def parse_fragment_line(text: str, line_no: int, stream_total: int) -> Fragment:
    """Format- and range-check one fragment line against the declared range."""
    obj = _load_json_object(text, line_no, FragmentFormatError)
    _check_fields(obj, _FRAGMENT_FIELDS, line_no, FragmentFormatError)
    offset = _as_int(obj["offset"], "offset", line_no, FragmentFormatError)
    if offset < 0:
        raise FragmentFormatError(
            line_no, f"offset: expected a non-negative integer, got {offset}")
    data_hex = obj["data_hex"]
    if not isinstance(data_hex, str) or data_hex == "":
        raise FragmentFormatError(
            line_no, "data_hex: expected a non-empty hex string")
    if len(data_hex) % 2 != 0:
        raise FragmentFormatError(
            line_no,
            f"data_hex must have an even number of digits: {_brief(data_hex)!r}")
    if any(ch not in _HEX_DIGITS for ch in data_hex):
        raise FragmentFormatError(
            line_no,
            f"data_hex contains a non-hex character: {_brief(data_hex)!r}")
    data = bytes.fromhex(data_hex)
    if len(data) > MAX_FRAGMENT_BYTES:
        raise FragmentFormatError(
            line_no,
            f"fragment carries {len(data)} bytes; the limit is "
            f"{MAX_FRAGMENT_BYTES} (64 KiB)")
    if offset + len(data) > stream_total:
        raise FragmentRangeError(
            line_no,
            f"fragment [{offset}, {offset + len(data)}) exceeds the declared "
            f"stream size {stream_total}")
    return Fragment(offset, data, line_no)


def iter_fragments(path: Union[str, os.PathLike],
                   stream_total: int) -> Iterator[Fragment]:
    """Yield format- and range-checked fragments in file order.

    Byte-level conflicts between overlapping fragments are *not* decided here;
    they are detected when the fragments are merged (see
    :func:`reconcile_batch`).
    """
    for line_no, text in _iter_lines(path, "fragments", FragmentFormatError):
        yield parse_fragment_line(text, line_no, stream_total)


# -- on-disk merge and count store ----------------------------------------------


def _first_mismatch(mine: bytes, theirs: bytes, base: int) -> int:
    for i, (a, b) in enumerate(zip(mine, theirs)):
        if a != b:
            return base + i
    return base  # unreachable: equal-length slices that differ somewhere


class _Workspace:
    """On-disk merge/count store so inputs and results are not bounded by RAM.

    ``seg`` holds the captured bytes as non-overlapping ``[start, end)``
    segments; retransmitted bytes are checked for equality and stored once.
    ``plan`` and ``confirmed`` hold the two count sides keyed by
    ``(wire, actions)``.
    """

    def __init__(self) -> None:
        self._dir = tempfile.mkdtemp(prefix="scanflow-batch-")
        self._conn: Optional[sqlite3.Connection] = None
        try:
            self._conn = sqlite3.connect(
                os.path.join(self._dir, "batch.sqlite3"), isolation_level=None)
            self._conn.execute("PRAGMA journal_mode=OFF")
            self._conn.execute("PRAGMA synchronous=OFF")
            self._conn.execute(
                "CREATE TABLE seg (start INTEGER PRIMARY KEY, "
                "end INTEGER NOT NULL, data BLOB NOT NULL) WITHOUT ROWID")
            self._conn.execute(
                "CREATE TABLE plan (wire INTEGER NOT NULL, "
                "actions TEXT NOT NULL, planned INTEGER NOT NULL, "
                "line INTEGER NOT NULL, "
                "PRIMARY KEY (wire, actions)) WITHOUT ROWID")
            self._conn.execute(
                "CREATE TABLE confirmed (wire INTEGER NOT NULL, "
                "actions TEXT NOT NULL, n INTEGER NOT NULL, "
                "PRIMARY KEY (wire, actions)) WITHOUT ROWID")
            self._conn.create_collation("seqcmp", _sequence_collate)
            self._conn.execute("BEGIN IMMEDIATE")
        except BaseException:
            self.close()
            raise

    # -- plan side -------------------------------------------------------------

    def add_plan(self, entry: PlanEntry) -> None:
        try:
            self._conn.execute(
                "INSERT INTO plan (wire, actions, planned, line) "
                "VALUES (?, ?, ?, ?)",
                (entry.wire, _actions_key(entry.actions), entry.planned,
                 entry.line_no))
        except _STORE_FAILURES as exc:
            raise BatchError(f"could not record plan entries: {exc}") from exc

    # -- capture side ----------------------------------------------------------

    def add_fragment(self, fragment: Fragment) -> None:
        """Merge one fragment, refusing bytes that conflict with earlier ones."""
        offset = fragment.offset
        data = fragment.data
        end = offset + len(data)
        pieces: List[Tuple[int, bytes]] = []
        try:
            cursor = self._conn.execute(
                "SELECT start, end, data FROM seg "
                "WHERE start < ? AND end > ? ORDER BY start",
                (end, offset))
            position = offset
            for start, seg_end, seg_data in cursor:
                overlap_lo = max(offset, start)
                overlap_hi = min(end, seg_end)
                mine = data[overlap_lo - offset:overlap_hi - offset]
                theirs = seg_data[overlap_lo - start:overlap_hi - start]
                if mine != theirs:
                    raise FragmentConflictError(
                        _first_mismatch(mine, theirs, overlap_lo),
                        fragment.line_no)
                if start > position:
                    pieces.append(
                        (position, data[position - offset:start - offset]))
                if seg_end > position:
                    position = seg_end
            if position < end:
                pieces.append((position, data[position - offset:]))
            for piece_start, piece_data in pieces:
                self._conn.execute(
                    "INSERT INTO seg (start, end, data) VALUES (?, ?, ?)",
                    (piece_start, piece_start + len(piece_data), piece_data))
        except _STORE_FAILURES as exc:
            raise BatchError(f"could not merge captured fragments: {exc}") from exc

    def received_bytes(self) -> int:
        """Total distinct byte positions covered by the capture."""
        try:
            row = self._conn.execute(
                "SELECT COALESCE(SUM(end - start), 0) FROM seg").fetchone()
        except _STORE_FAILURES as exc:
            raise BatchError(f"could not measure captured coverage: {exc}") from exc
        return int(row[0])

    def iter_prefix_segments(self) -> Iterator[bytes]:
        """Yield the contiguous known prefix from offset 0, segment by segment.

        Stops at the first gap: bytes beyond it are never spliced in and frame
        boundaries are never re-guessed after a gap.
        """
        position = 0
        try:
            cursor = self._conn.execute(
                "SELECT start, end, data FROM seg ORDER BY start")
            for start, end, data in cursor:
                if start > position:
                    break
                yield data
                position = end
        except _STORE_FAILURES as exc:
            raise BatchError(f"could not read merged capture: {exc}") from exc

    # -- confirmed side ----------------------------------------------------------

    def add_confirmed(self, wire: int, actions: Tuple[str, ...]) -> None:
        key = _actions_key(actions)
        try:
            self._conn.execute(
                "INSERT OR IGNORE INTO confirmed (wire, actions, n) "
                "VALUES (?, ?, 0)", (wire, key))
            self._conn.execute(
                "UPDATE confirmed SET n = n + 1 "
                "WHERE wire = ? AND actions = ?", (wire, key))
        except _STORE_FAILURES as exc:
            raise BatchError(f"could not count confirmed frames: {exc}") from exc

    # -- tabulation --------------------------------------------------------------

    def iter_rows(self) -> Iterator[Tuple[int, List[str], int, int]]:
        """Yield ``(wire, actions, planned, confirmed)`` for the union of both sides.

        Rows are ordered by wire value, then by action-name sequence
        (element-wise, names by Unicode code point, strict prefix first).
        """
        sql = """
            SELECT wire, actions, SUM(p), SUM(c) FROM (
                SELECT wire, actions, planned AS p, 0 AS c FROM plan
                UNION ALL
                SELECT wire, actions, 0 AS p, n AS c FROM confirmed
            ) GROUP BY wire, actions
            ORDER BY wire, actions COLLATE seqcmp
        """
        try:
            cursor = self._conn.execute(sql)
            for wire, key, planned, confirmed in cursor:
                yield wire, list(json.loads(key)), int(planned), int(confirmed)
        except _STORE_FAILURES as exc:
            raise BatchError(
                f"could not tabulate reconciliation rows: {exc}") from exc

    def close(self) -> None:
        conn, self._conn = self._conn, None
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass
        shutil.rmtree(self._dir, ignore_errors=True)


# -- reception over the known prefix --------------------------------------------


@dataclass
class _Reception:
    parsed_prefix_bytes: int = 0
    frames_accepted: int = 0
    frames_rejected: int = 0
    noise_regions: int = 0
    noise_bytes: int = 0
    truncated: bool = False

    @property
    def clean(self) -> bool:
        return (self.frames_rejected == 0 and self.noise_regions == 0
                and not self.truncated)


def _absorb_events(events, reception: _Reception, workspace: _Workspace) -> None:
    for event in events:
        if isinstance(event, FrameAccepted):
            workspace.add_confirmed(
                event.version, tuple(a.name for a in event.actions))
            reception.frames_accepted += 1
        elif isinstance(event, FrameRejected):
            reception.frames_rejected += 1
        elif isinstance(event, Noise):
            reception.noise_regions += 1
            reception.noise_bytes += event.length
        elif isinstance(event, Truncated):
            reception.truncated = True


# -- summary ---------------------------------------------------------------------


@dataclass
class BatchSummary:
    """Aggregate outcome of one batch reconciliation run."""

    stream_total: int
    received_bytes: int
    first_missing_offset: Optional[int]
    parsed_prefix_bytes: int
    frames_accepted: int
    frames_rejected: int
    noise_regions: int
    noise_bytes: int
    truncated: bool
    rows: int
    matched: Optional[int]   # None unless the evidence is complete
    short: Optional[int]
    over: Optional[int]

    @property
    def coverage_complete(self) -> bool:
        return self.first_missing_offset is None

    @property
    def clean(self) -> bool:
        return (self.frames_rejected == 0 and self.noise_regions == 0
                and not self.truncated)

    @property
    def evidence_complete(self) -> bool:
        """Whole declared range received, with no noise, rejection or truncation."""
        return self.coverage_complete and self.clean

    @property
    def batch_match(self) -> Optional[bool]:
        """True only when the evidence is complete and every row matches."""
        if not self.evidence_complete:
            return None
        return self.matched == self.rows

    def coverage_json(self) -> dict:
        return {
            "received_bytes": self.received_bytes,
            "complete": self.coverage_complete,
            "first_missing_offset": self.first_missing_offset,
        }

    def reception_json(self) -> dict:
        return {
            "parsed_prefix_bytes": self.parsed_prefix_bytes,
            "frames_accepted": self.frames_accepted,
            "frames_rejected": self.frames_rejected,
            "noise_regions": self.noise_regions,
            "noise_bytes": self.noise_bytes,
            "truncated": self.truncated,
            "clean": self.clean,
        }

    def counts_json(self) -> dict:
        return {
            "rows": self.rows,
            "match": self.matched,
            "short": self.short,
            "over": self.over,
        }

    def to_json(self) -> dict:
        return {
            "kind": SUMMARY_KIND,
            "format_version": FORMAT_VERSION,
            "stream_total": self.stream_total,
            "coverage": self.coverage_json(),
            "reception": self.reception_json(),
            "evidence_complete": self.evidence_complete,
            "counts_are_lower_bounds": not self.evidence_complete,
            "counts": self.counts_json(),
            "batch_match": self.batch_match,
        }


# -- report ----------------------------------------------------------------------


class _BatchReportWriter:
    """Streams the JSON report; rows never accumulate in memory."""

    def __init__(self, handle, stream_total: int, coverage: dict,
                 reception: dict, evidence_complete: bool) -> None:
        self._handle = handle
        self._first = True
        handle.write("{\n")
        handle.write(f'  "kind": {json.dumps(REPORT_KIND)},\n')
        handle.write(f'  "format_version": {FORMAT_VERSION},\n')
        handle.write(f'  "stream_total": {json.dumps(stream_total)},\n')
        handle.write('  "coverage": '
                     + json.dumps(coverage, sort_keys=True) + ",\n")
        handle.write('  "reception": '
                     + json.dumps(reception, sort_keys=True) + ",\n")
        handle.write('  "evidence_complete": '
                     + json.dumps(evidence_complete) + ",\n")
        handle.write('  "counts_are_lower_bounds": '
                     + json.dumps(not evidence_complete) + ",\n")
        handle.write('  "rows": [\n')

    def row(self, wire: int, actions: List[str], planned: int, confirmed: int,
            status: Optional[str]) -> None:
        chunk = json.dumps(
            {"wire": wire, "actions": actions, "planned": planned,
             "confirmed": confirmed, "status": status},
            sort_keys=True, ensure_ascii=False)
        if not self._first:
            self._handle.write(",\n")
        self._handle.write("    " + chunk)
        self._first = False

    def finish(self, counts: dict, batch_match: Optional[bool]) -> None:
        if not self._first:
            self._handle.write("\n")
        self._handle.write("  ],\n")
        self._handle.write('  "counts": '
                           + json.dumps(counts, sort_keys=True) + ",\n")
        self._handle.write('  "batch_match": ' + json.dumps(batch_match) + "\n")
        self._handle.write("}\n")


def _fsync_dir(directory: Path) -> None:
    """Best-effort directory sync so a completed report survives a crash."""
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _default_mode() -> int:
    """Mode for a brand-new report, honouring the process umask."""
    umask = os.umask(0)
    os.umask(umask)
    return 0o666 & ~umask


def _report_mode(target: Path) -> int:
    """Preserve an existing report's permission bits; use the umask otherwise."""
    try:
        info = target.stat()
    except OSError:
        return _default_mode()
    if stat.S_ISREG(info.st_mode):
        return stat.S_IMODE(info.st_mode)
    return _default_mode()


def _check_report_target(target: Path, inputs: Iterable[Union[str, os.PathLike]]
                         ) -> None:
    """Refuse to overwrite any input; configurations and evidence stay read-only."""
    for source in inputs:
        try:
            same = os.path.realpath(target) == os.path.realpath(source)
        except OSError:
            same = (os.path.abspath(str(target))
                    == os.path.abspath(str(source)))
        if same:
            raise BatchReportWriteError(
                f"report path {os.fspath(target)!r} is the input file "
                f"{os.fspath(source)!r}; refusing to overwrite the evidence")


def _tabulate(workspace: _Workspace, evidence_complete: bool,
              writer: Optional[_BatchReportWriter]
              ) -> Tuple[int, int, int, int]:
    """Stream every row once, counting statuses and optionally writing them."""
    rows = matched = short = over = 0
    for wire, actions, planned, confirmed in workspace.iter_rows():
        status: Optional[str] = None
        if evidence_complete:
            if confirmed == planned:
                status = "match"
                matched += 1
            elif confirmed < planned:
                status = "short"
                short += 1
            else:
                status = "over"
                over += 1
        rows += 1
        if writer is not None:
            writer.row(wire, actions, planned, confirmed, status)
    return rows, matched, short, over


# -- top level ---------------------------------------------------------------------


def reconcile_batch(
    registry: Registry,
    plan_path: Union[str, os.PathLike],
    fragments_path: Union[str, os.PathLike],
    stream_total: int,
    *,
    report_path: Optional[Union[str, os.PathLike]] = None,
    max_body_len: int = DEFAULT_MAX_BODY,
    protected_paths: Iterable[Union[str, os.PathLike]] = (),
) -> BatchSummary:
    """Reconcile one captured stream against the plan.

    The plan and the fragments are streamed and merged on disk; only the
    contiguous known prefix of the declared stream is interpreted, in
    original byte order, with the existing frame format.  Any invalid input
    raises :class:`BatchError` and no conclusion is issued.

    When *report_path* is given, the JSON report is written to a sibling
    temporary file and atomically replaces the destination only after the
    whole run has been validated; on any error an existing report is left
    byte-for-byte untouched.  The report path may not coincide with the plan,
    the fragments or any *protected_paths* entry (the configurations).
    """
    if isinstance(stream_total, bool) or not isinstance(stream_total, int) \
            or stream_total < 0 or stream_total > _SQLITE_MAX_INT:
        raise BatchError(
            f"stream_total must be a non-negative integer below 2^63, "
            f"got {stream_total!r}")
    if max_body_len < 0:
        raise BatchError("max_body_len must be non-negative")

    workspace = _Workspace()
    try:
        for entry in iter_plan(plan_path, registry):
            workspace.add_plan(entry)
        for fragment in iter_fragments(fragments_path, stream_total):
            workspace.add_fragment(fragment)

        received = workspace.received_bytes()
        reception = _Reception()
        receiver = Receiver(registry, max_body_len=max_body_len)
        for data in workspace.iter_prefix_segments():
            reception.parsed_prefix_bytes += len(data)
            _absorb_events(receiver.feed(data), reception, workspace)
        _absorb_events(receiver.finish(), reception, workspace)

        coverage_complete = reception.parsed_prefix_bytes == stream_total
        first_missing = (None if coverage_complete
                         else reception.parsed_prefix_bytes)
        evidence_complete = coverage_complete and reception.clean

        coverage = {
            "received_bytes": received,
            "complete": coverage_complete,
            "first_missing_offset": first_missing,
        }
        reception_json = {
            "parsed_prefix_bytes": reception.parsed_prefix_bytes,
            "frames_accepted": reception.frames_accepted,
            "frames_rejected": reception.frames_rejected,
            "noise_regions": reception.noise_regions,
            "noise_bytes": reception.noise_bytes,
            "truncated": reception.truncated,
            "clean": reception.clean,
        }

        if report_path is None:
            rows, matched, short, over = _tabulate(
                workspace, evidence_complete, None)
        else:
            target = Path(report_path)
            _check_report_target(
                target, [plan_path, fragments_path, *protected_paths])
            try:
                mode = _report_mode(target)
                fd, temp_name = tempfile.mkstemp(
                    prefix=f".{target.name}.", suffix=".tmp",
                    dir=str(target.parent))
            except OSError as exc:
                raise BatchReportWriteError(
                    f"could not prepare report {os.fspath(target)!r}: {exc}"
                ) from exc
            try:
                with os.fdopen(fd, "w", encoding="utf-8",
                               newline="\n") as handle:
                    writer = _BatchReportWriter(
                        handle, stream_total, coverage, reception_json,
                        evidence_complete)
                    rows, matched, short, over = _tabulate(
                        workspace, evidence_complete, writer)
                    batch_match = (matched == rows) if evidence_complete else None
                    writer.finish(
                        {"rows": rows,
                         "match": matched if evidence_complete else None,
                         "short": short if evidence_complete else None,
                         "over": over if evidence_complete else None},
                        batch_match)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(temp_name, mode)
                os.replace(temp_name, target)
                temp_name = None
                _fsync_dir(target.parent)
            finally:
                if temp_name is not None:
                    try:
                        os.unlink(temp_name)
                    except OSError:
                        pass

        summary = BatchSummary(
            stream_total=stream_total,
            received_bytes=received,
            first_missing_offset=first_missing,
            parsed_prefix_bytes=reception.parsed_prefix_bytes,
            frames_accepted=reception.frames_accepted,
            frames_rejected=reception.frames_rejected,
            noise_regions=reception.noise_regions,
            noise_bytes=reception.noise_bytes,
            truncated=reception.truncated,
            rows=rows,
            matched=matched if evidence_complete else None,
            short=short if evidence_complete else None,
            over=over if evidence_complete else None,
        )
    finally:
        workspace.close()
    return summary
