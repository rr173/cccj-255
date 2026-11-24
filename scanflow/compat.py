"""Historical-record compatibility check for a configuration switch.

The release audit answers a language-level question: can one configuration spell
the same body in two different ways?  It says nothing about bodies that were
already captured under the *current* configuration.  This module adds the missing
evidence check: each historical body is decoded completely under the current and
the candidate configuration, and the switch is only considered safe when every
record reads as the *same ordered action names* on both sides.

Inputs
------
* a current :class:`~scanflow.config.CodeConfig`,
* a candidate :class:`~scanflow.config.CodeConfig` that must first pass the
  existing offline audit, and
* a line-oriented history file.

Every history line is ``<record-id> <body-hex>`` (two whitespace-separated
fields).  Record ids are unique across the file; bodies may repeat, and repeated
bodies are still one result row per record.  See ``docs/compatibility-check.md``
for the exact grammar and the JSON report schema.

Streaming and atomicity
-----------------------
The history file is read one line at a time and the JSON report is written to a
temporary file in the destination directory.  The destination is replaced with
:func:`os.replace` only after every line has been processed and the closing JSON
has been flushed; any invalid input, decode failure or write failure discards the
temporary file and leaves an existing report byte-for-byte untouched.

Duplicate ids are tracked in a temporary SQLite database rather than an
in-memory set, so the number of records is not bounded by RAM.  (A single record
line must still fit in memory; bodies and ids are not split across lines.)
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Optional, Tuple, Union

from .audit import AuditIncomplete, AuditReport, audit
from .config import CodeConfig
from .decoder import walk

__all__ = [
    "CandidateAuditIncomplete",
    "CandidateNotReleasable",
    "CompatibilityError",
    "CompatibilitySummary",
    "CurrentDecodeError",
    "DuplicateRecordId",
    "HistoryFormatError",
    "HistoryRecord",
    "RecordComparison",
    "ReportWriteError",
    "SideReading",
    "check_compatibility",
    "compare_history",
    "compare_record",
    "iter_history",
    "parse_history_line",
]

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_HISTORY_LINE_FORM = "<record-id> <body-hex>"


# -- errors -----------------------------------------------------------------


class CompatibilityError(Exception):
    """The compatibility check could not reach a replaceable/not-replaceable verdict.

    Raised for invalid evidence (bad input, current-side decode failure), a
    candidate that cannot be released, or a report that could not be written.
    Distinct subclasses let callers map each case to its own exit status.
    """


class HistoryFormatError(CompatibilityError):
    """One history line is not a valid ``<record-id> <body-hex>`` record."""

    def __init__(self, line_no: int, detail: str) -> None:
        super().__init__(f"history line {line_no}: {detail}")
        self.line_no = line_no
        self.detail = detail


class DuplicateRecordId(CompatibilityError):
    """A record id occurred more than once, so the evidence is not identifiable."""

    def __init__(self, record_id: str, line_no: int, first_line: int) -> None:
        super().__init__(
            f"history line {line_no}: duplicate record id {record_id!r} "
            f"(first seen on line {first_line})"
        )
        self.record_id = record_id
        self.line_no = line_no
        self.first_line = first_line


class CurrentDecodeError(CompatibilityError):
    """A record has no unique complete reading under the current configuration.

    The current configuration defines what the captured frames meant.  If it
    cannot give exactly one ordered action sequence for a record, the historical
    evidence is unusable and no switch verdict can be issued.
    """

    def __init__(self, record: "HistoryRecord", status: str,
                 furthest_pos: Optional[int] = None,
                 furthest_states: Optional[List[str]] = None) -> None:
        if status == "ambiguous":
            detail = ("current configuration produces more than one legal "
                      "action sequence; the historical reading is not unique")
        else:
            detail = "current configuration has no complete legal action sequence"
            if furthest_pos is not None:
                detail += (f" (reached body byte {furthest_pos}, "
                           f"state(s) {furthest_states})")
        super().__init__(
            f"history line {record.line_no} (record {record.record_id!r}, "
            f"body {record.body.hex()}): {detail}"
        )
        self.record = record
        self.status = status
        self.furthest_pos = furthest_pos
        self.furthest_states = furthest_states


class CandidateNotReleasable(CompatibilityError):
    """The candidate failed the existing offline release audit.

    This is invalid input to the switch decision, not a compatibility verdict:
    the candidate was never releasable in the first place.
    """

    def __init__(self, report: AuditReport) -> None:
        super().__init__(
            f"candidate version {report.version!r} failed the release audit: "
            f"{len(report.conflicts)} release conflict(s)"
        )
        self.report = report


class ReportWriteError(CompatibilityError, OSError):
    """The report could not be written; any existing report is still intact."""


class CandidateAuditIncomplete(CompatibilityError):
    """The candidate audit hit its explicit safety bound; it is never releasable."""


# -- history input ----------------------------------------------------------


@dataclass(frozen=True)
class HistoryRecord:
    record_id: str
    body: bytes
    line_no: int


def parse_history_line(text: str, line_no: int) -> HistoryRecord:
    """Parse one history line (without its newline).

    The first field is the record id, the second is the raw body as a contiguous
    even-length hex string.  Exactly two whitespace-separated fields are accepted;
    leading/trailing whitespace is ignored and extra fields are an error rather
    than silently discarded.
    """
    fields = text.split()
    if len(fields) != 2:
        if not fields:
            detail = f"blank line; expected {_HISTORY_LINE_FORM}"
        else:
            detail = (f"expected exactly {_HISTORY_LINE_FORM} "
                      f"({len(fields)} field(s) found)")
        raise HistoryFormatError(line_no, detail)
    record_id, body_hex = fields
    if len(body_hex) % 2 != 0:
        raise HistoryFormatError(
            line_no, f"body hex must have an even number of digits: {body_hex!r}")
    if any(ch not in _HEX_DIGITS for ch in body_hex):
        raise HistoryFormatError(
            line_no, f"body hex contains a non-hex character: {body_hex!r}")
    return HistoryRecord(record_id, bytes.fromhex(body_hex), line_no)


class _SeenIds:
    """Exact duplicate-id index on disk, so memory does not grow with the file."""

    def __init__(self) -> None:
        self._dir = tempfile.mkdtemp(prefix="scanflow-compat-ids-")
        self._conn: Optional[sqlite3.Connection] = None
        try:
            path = os.path.join(self._dir, "ids.sqlite3")
            self._conn = sqlite3.connect(path, isolation_level=None)
            # This database only indexes ids for the duration of one run; it is
            # discarded afterwards, so durability to an OS crash is irrelevant.
            self._conn.execute("PRAGMA journal_mode=OFF")
            self._conn.execute("PRAGMA synchronous=OFF")
            self._conn.execute(
                "CREATE TABLE seen (id BLOB PRIMARY KEY, line INTEGER NOT NULL) "
                "WITHOUT ROWID"
            )
            self._conn.execute("BEGIN IMMEDIATE")
        except BaseException:
            self.close()
            raise

    def add(self, record_id: str, line_no: int) -> Optional[int]:
        """Record *record_id*; return the first line number if it was seen before."""
        assert self._conn is not None
        key = record_id.encode("utf-8")
        try:
            row = self._conn.execute(
                "SELECT line FROM seen WHERE id = ?", (key,)
            ).fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO seen (id, line) VALUES (?, ?)", (key, line_no))
                return None
        except sqlite3.Error as exc:
            raise CompatibilityError(
                f"could not track historical record ids: {exc}") from exc
        return int(row[0])

    def close(self) -> None:
        conn, self._conn = self._conn, None
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass
        try:
            import shutil
            shutil.rmtree(self._dir, ignore_errors=True)
        except OSError:
            pass


def iter_history(path: Union[str, os.PathLike]) -> Iterator[HistoryRecord]:
    """Yield history records in file order, validating format and id uniqueness.

    The file is consumed line by line (LF or CRLF).  Any format problem, invalid
    UTF-8, duplicate id or read error raises :class:`CompatibilityError`; records
    already yielded are still valid, but the evidence as a whole is not.
    """
    index = _SeenIds()
    try:
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
                        raise HistoryFormatError(
                            line_no, "not valid UTF-8") from exc
                    record = parse_history_line(text, line_no)
                    first_line = index.add(record.record_id, line_no)
                    if first_line is not None:
                        raise DuplicateRecordId(record.record_id, line_no,
                                                first_line)
                    yield record
        except OSError as exc:
            raise CompatibilityError(
                f"could not read history file {os.fspath(path)!r}: {exc}"
            ) from exc
    finally:
        index.close()


# -- per-record comparison --------------------------------------------------


@dataclass
class SideReading:
    """How one configuration reads one body."""

    status: str  # "unique", "no_legal_sequence" or "ambiguous"
    actions: Optional[List[str]] = None
    spans: Optional[List[Tuple[int, int]]] = None
    state_trace: Optional[List[str]] = None
    furthest_pos: Optional[int] = None
    furthest_states: Optional[List[str]] = None

    @property
    def unique(self) -> bool:
        return self.status == "unique"

    def to_json(self) -> dict:
        if self.status == "unique":
            return {
                "status": "unique",
                "actions": list(self.actions or []),
                "spans": [list(span) for span in (self.spans or [])],
                "state_trace": list(self.state_trace or []),
            }
        if self.status == "no_legal_sequence":
            return {
                "status": "no_legal_sequence",
                "actions": None,
                "furthest_pos": self.furthest_pos,
                "furthest_states": list(self.furthest_states or []),
            }
        return {"status": "ambiguous", "actions": None}


def _reading(config: CodeConfig, body: bytes) -> SideReading:
    result = walk(config, body, max_matches=2)
    if not result.accepted:
        return SideReading(
            "no_legal_sequence",
            furthest_pos=result.furthest_pos,
            furthest_states=list(result.furthest_states),
        )
    if len(result.matches) > 1:
        return SideReading("ambiguous")
    match = result.matches[0]
    trace = [config.start]
    for action in match.actions:
        trace.append(config.transitions[(trace[-1], action)])
    return SideReading(
        "unique",
        actions=list(match.actions),
        spans=[tuple(span) for span in match.spans],
        state_trace=trace,
    )


@dataclass
class RecordComparison:
    record: HistoryRecord
    current: SideReading
    candidate: SideReading
    compatible: bool
    difference: dict

    def to_json(self) -> dict:
        return {
            "line": self.record.line_no,
            "record_id": self.record.record_id,
            "body_hex": self.record.body.hex(),
            "body_len": len(self.record.body),
            "compatible": self.compatible,
            "current": self.current.to_json(),
            "candidate": self.candidate.to_json(),
            "difference": self.difference,
        }


def _sequence_difference(current: List[str], candidate: List[str]) -> dict:
    common: List[str] = []
    for left, right in zip(current, candidate):
        if left != right:
            break
        common.append(left)
    index = len(common)
    return {
        "kind": "action_sequence_mismatch",
        "common_prefix": common,
        "current_remainder": current[index:],
        "candidate_remainder": candidate[index:],
        "first_divergence": {
            "index": index,
            "current": current[index] if index < len(current) else None,
            "candidate": candidate[index] if index < len(candidate) else None,
        },
    }


def _candidate_problem_kind(candidate: SideReading) -> dict:
    return {
        "kind": ("candidate_ambiguous" if candidate.status == "ambiguous"
                 else "candidate_no_legal_sequence"),
        "common_prefix": [],
        "current_remainder": None,
        "candidate_remainder": None,
        "first_divergence": None,
    }


def compare_record(current: CodeConfig, candidate: CodeConfig,
                   record: HistoryRecord) -> RecordComparison:
    """Decode one record under both configurations and compare the readings.

    A current-side failure (no complete walk, or an ambiguous one) raises
    :class:`CurrentDecodeError` -- it is invalid evidence, not an incompatibility.
    Candidate failures are ordinary incompatible results.
    """
    current_reading = _reading(current, record.body)
    if not current_reading.unique:
        raise CurrentDecodeError(record, current_reading.status,
                                 current_reading.furthest_pos,
                                 current_reading.furthest_states)

    candidate_reading = _reading(candidate, record.body)
    if candidate_reading.status != "unique":
        difference = _candidate_problem_kind(candidate_reading)
        difference["current_remainder"] = list(current_reading.actions or [])
        return RecordComparison(record, current_reading, candidate_reading,
                                False, difference)

    current_actions = list(current_reading.actions or [])
    candidate_actions = list(candidate_reading.actions or [])
    if current_actions == candidate_actions:
        difference = {"kind": "none"}
        compatible = True
    else:
        difference = _sequence_difference(current_actions, candidate_actions)
        compatible = False
    return RecordComparison(record, current_reading, candidate_reading,
                            compatible, difference)


def compare_history(current: CodeConfig, candidate: CodeConfig,
                    history_path: Union[str, os.PathLike]
                    ) -> Iterator[RecordComparison]:
    """Yield comparisons for every history record, in input order.

    Invalid evidence raises :class:`CompatibilityError` at the offending line.
    The candidate audit is *not* performed here; use :func:`check_compatibility`
    for the full pre-switch check.
    """
    for record in iter_history(history_path):
        yield compare_record(current, candidate, record)


# -- report -----------------------------------------------------------------


@dataclass
class CompatibilitySummary:
    current_version: str
    candidate_version: str
    total: int
    compatible: int
    incompatible: int

    @property
    def replaceable(self) -> bool:
        # Replaceable when no record disagrees.  An empty history is vacuously
        # compatible: the check reports the counts it was given, in the same way
        # the audit treats "no conflict found" as releasable.
        return self.incompatible == 0

    def counts_json(self) -> dict:
        return {
            "records": self.total,
            "compatible": self.compatible,
            "incompatible": self.incompatible,
        }

    def to_json(self) -> dict:
        return {
            "kind": "scanflow.compatibility.summary",
            "current_version": self.current_version,
            "candidate_version": self.candidate_version,
            "replaceable": self.replaceable,
            "counts": self.counts_json(),
        }


def _tally(comparisons, sink) -> Tuple[int, int, int]:
    """Consume comparisons, optionally forwarding each to *sink*.

    Returns ``(total, compatible, incompatible)``.  The whole history is consumed
    before the caller commits anything, so a late error cannot leave a partial
    result looking complete.
    """
    total = compatible = incompatible = 0
    for comparison in comparisons:
        if sink is not None:
            sink(comparison)
        total += 1
        if comparison.compatible:
            compatible += 1
        else:
            incompatible += 1
    return total, compatible, incompatible


class _JsonReportWriter:
    def __init__(self, handle, current: CodeConfig, candidate: CodeConfig) -> None:
        self._handle = handle
        self._first = True
        handle.write("{\n")
        handle.write('  "kind": "scanflow.compatibility",\n')
        handle.write('  "format_version": 1,\n')
        handle.write(f'  "current_version": '
                     f'{json.dumps(current.version, ensure_ascii=False)},\n')
        handle.write(f'  "candidate_version": '
                     f'{json.dumps(candidate.version, ensure_ascii=False)},\n')
        handle.write('  "records": [\n')

    def record(self, comparison: RecordComparison) -> None:
        chunk = json.dumps(comparison.to_json(), sort_keys=True,
                           ensure_ascii=False)
        if not self._first:
            self._handle.write(",\n")
        self._handle.write("    " + chunk)
        self._first = False

    def finish(self, summary: CompatibilitySummary) -> None:
        if not self._first:
            self._handle.write("\n")
        self._handle.write("  ],\n")
        self._handle.write('  "counts": '
                           + json.dumps(summary.counts_json(), sort_keys=True)
                           + ",\n")
        self._handle.write('  "replaceable": '
                           f'{str(summary.replaceable).lower()},\n')
        self._handle.write('  "complete": true\n')
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


def check_compatibility(
    current: CodeConfig,
    candidate: CodeConfig,
    history_path: Union[str, os.PathLike],
    *,
    report_path: Optional[Union[str, os.PathLike]] = None,
    max_product_states: Optional[int] = None,
    max_witnesses: int = 8,
) -> CompatibilitySummary:
    """Run the full pre-switch historical compatibility check.

    The candidate is audited first; a conflict or an incomplete audit raises
    :class:`CandidateNotReleasable` / :class:`CandidateAuditIncomplete` before
    any history is read.  The history is then streamed in input order.

    When *report_path* is given, the JSON report is written to a sibling temporary
    file and atomically replaces the destination only after the whole history has
    been validated and the report is complete.  Any error removes the temporary
    file and leaves an existing destination untouched.  With *report_path* left
    as ``None`` the check is still performed and only the summary is returned.
    """
    try:
        candidate_report = audit(
            candidate,
            max_witnesses=max_witnesses,
            max_product_states=max_product_states,
        )
    except AuditIncomplete as exc:
        raise CandidateAuditIncomplete(
            f"candidate version {candidate.version!r}: {exc}") from exc
    if not candidate_report.ok:
        raise CandidateNotReleasable(candidate_report)

    if report_path is None:
        comparison_iter = compare_history(current, candidate, history_path)
        try:
            counts = _tally(comparison_iter, sink=None)
        finally:
            comparison_iter.close()
        return CompatibilitySummary(current.version, candidate.version, *counts)

    target = Path(report_path)
    try:
        same = os.path.realpath(target) == os.path.realpath(history_path)
    except OSError:
        same = os.path.abspath(str(target)) == os.path.abspath(str(history_path))
    if same:
        raise ReportWriteError(
            f"report path {os.fspath(target)!r} is the history file; "
            f"refusing to overwrite the evidence")
    try:
        mode = _report_mode(target)
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
    except OSError as exc:
        raise ReportWriteError(
            f"could not prepare report {os.fspath(target)!r}: {exc}") from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            writer = _JsonReportWriter(handle, current, candidate)
            comparison_iter = compare_history(current, candidate, history_path)
            try:
                counts = _tally(comparison_iter, sink=writer.record)
            finally:
                comparison_iter.close()
            summary = CompatibilitySummary(current.version, candidate.version,
                                           *counts)
            writer.finish(summary)
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
    return summary
