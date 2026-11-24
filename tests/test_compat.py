"""Tests for the pre-switch historical compatibility check."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanflow import (  # noqa: E402
    CandidateAuditIncomplete,
    CandidateNotReleasable,
    CodeConfig,
    CompatibilityError,
    CurrentDecodeError,
    DuplicateRecordId,
    HistoryFormatError,
    check_compatibility,
    compare_history,
    compare_record,
    iter_history,
    parse_history_line,
)


def cfg(version="v1", codes=None, transitions=None, accepts=("ok",), wire=None):
    obj = {
        "version": version,
        "codes": codes or {},
        "flow": {"start": "s", "accepts": list(accepts),
                 "transitions": transitions or []},
    }
    if wire is not None:
        obj["wire"] = wire
    return CodeConfig.from_obj(obj)


def current_cfg(version="cur"):
    return cfg(version=version,
               codes={"A": "0a", "B": "0b", "C": "0c"},
               transitions=[["s", "A", "s"], ["s", "B", "ok"],
                            ["ok", "C", "ok"]])


def candidate_cfg(version="cand", c_code="0c"):
    return cfg(version=version,
               codes={"A": "0a", "B": "0b", "C": c_code},
               transitions=[["s", "A", "s"], ["s", "B", "ok"],
                            ["ok", "C", "ok"]])


def write_history(directory, lines, name="history.txt"):
    path = Path(directory) / name
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
    return path


class HistoryFormatTests(unittest.TestCase):
    def test_parses_id_and_body(self):
        rec = parse_history_line("  rec-1  0A0b\n", 7)
        self.assertEqual(rec.record_id, "rec-1")
        self.assertEqual(rec.body, b"\x0a\x0b")
        self.assertEqual(rec.line_no, 7)

    def test_rejects_wrong_field_counts(self):
        for text in ("", "   ", "only-id", "a b c"):
            with self.assertRaises(HistoryFormatError) as ctx:
                parse_history_line(text, 3)
            self.assertEqual(ctx.exception.line_no, 3)

    def test_rejects_bad_hex(self):
        for text in ("r 0a0", "r 0z", "r 0x0a", "r ----"):
            with self.assertRaises(HistoryFormatError):
                parse_history_line(text, 1)

    def test_tabs_and_multiple_spaces(self):
        rec = parse_history_line("rec\t 0a0b", 1)
        self.assertEqual((rec.record_id, rec.body), ("rec", b"\x0a\x0b"))

    def test_same_body_different_ids_both_yielded(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_history(tmp, ["a 0a0b", "b 0a0b"])
            records = list(iter_history(path))
        self.assertEqual([r.record_id for r in records], ["a", "b"])
        self.assertEqual([r.body for r in records], [b"\x0a\x0b", b"\x0a\x0b"])

    def test_duplicate_id_rejected_with_first_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_history(tmp, ["a 0a", "b 0b", "a 0c"])
            with self.assertRaises(DuplicateRecordId) as ctx:
                list(iter_history(path))
        self.assertEqual(ctx.exception.record_id, "a")
        self.assertEqual(ctx.exception.line_no, 3)
        self.assertEqual(ctx.exception.first_line, 1)

    def test_invalid_utf8_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "h.txt"
            path.write_bytes(b"a 0a\n\xff 0b\n")
            with self.assertRaises(HistoryFormatError):
                list(iter_history(path))

    def test_missing_file_is_compatibility_error(self):
        with self.assertRaises(CompatibilityError) as ctx:
            list(iter_history("/nonexistent/definitely/not/here.txt"))
        self.assertNotIsInstance(ctx.exception, FileNotFoundError)

    def test_crlf_and_no_final_newline(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "h.txt"
            path.write_bytes(b"a 0a\r\nb 0b")
            self.assertEqual([r.record_id for r in iter_history(path)], ["a", "b"])


class RecordComparisonTests(unittest.TestCase):
    def test_identical_reading_is_compatible(self):
        comp = compare_record(current_cfg(), candidate_cfg(),
                              parse_history_line("r 0a0b0c", 1))
        self.assertTrue(comp.compatible)
        self.assertEqual(comp.difference, {"kind": "none"})
        self.assertEqual(comp.current.actions, ["A", "B", "C"])
        self.assertEqual(comp.current.state_trace, ["s", "s", "ok", "ok"])

    def test_candidate_cannot_decode_is_incompatible(self):
        comp = compare_record(current_cfg(), candidate_cfg(c_code="0d"),
                              parse_history_line("r 0b0c", 1))
        self.assertFalse(comp.compatible)
        self.assertEqual(comp.current.actions, ["B", "C"])
        self.assertEqual(comp.candidate.status, "no_legal_sequence")
        self.assertEqual(comp.difference["kind"], "candidate_no_legal_sequence")

    def test_different_action_name_is_incompatible(self):
        cand = cfg(version="cand", codes={"A": "0a", "CHANGED": "0b"},
                   transitions=[["s", "A", "s"], ["s", "CHANGED", "ok"]])
        comp = compare_record(current_cfg(), cand,
                              parse_history_line("r 0a0b", 1))
        self.assertFalse(comp.compatible)
        self.assertEqual(comp.difference["kind"],
                         "action_sequence_mismatch")
        self.assertEqual(comp.difference["common_prefix"], ["A"])
        self.assertEqual(comp.difference["current_remainder"], ["B"])
        self.assertEqual(comp.difference["candidate_remainder"], ["CHANGED"])
        self.assertEqual(comp.difference["first_divergence"],
                         {"index": 1, "current": "B", "candidate": "CHANGED"})

    def test_current_side_failure_invalidates_evidence(self):
        with self.assertRaises(CurrentDecodeError) as ctx:
            compare_record(current_cfg(), candidate_cfg(),
                           parse_history_line("r 0c", 2))
        self.assertEqual(ctx.exception.record.line_no, 2)
        self.assertEqual(ctx.exception.status, "no_legal_sequence")

    def test_current_ambiguity_invalidates_evidence(self):
        ambiguous_current = cfg(
            codes={"A": "0a", "B": "0a0b", "C": "0b"},
            transitions=[["s", "A", "x"], ["x", "C", "ok"], ["s", "B", "ok"]])
        with self.assertRaises(CurrentDecodeError) as ctx:
            compare_record(ambiguous_current, candidate_cfg(),
                           parse_history_line("r 0a0b", 1))
        self.assertEqual(ctx.exception.status, "ambiguous")

    def test_same_body_records_are_independent(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_history(tmp, ["a 0a0b", "b 0a0b"])
            comps = list(compare_history(current_cfg(), candidate_cfg(), path))
        self.assertEqual([c.record.record_id for c in comps], ["a", "b"])
        self.assertEqual([c.record.line_no for c in comps], [1, 2])
        self.assertTrue(all(c.compatible for c in comps))


class CheckCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_replaceable_everything_matches(self):
        history = write_history(self.tmp, ["r1 0a0b", "r2 0a0a0b0c", "r3 0b0c"])
        summary = check_compatibility(current_cfg(), candidate_cfg(), history,
                                      report_path=self.tmp / "out.json")
        self.assertTrue(summary.replaceable)
        self.assertEqual((summary.total, summary.compatible,
                          summary.incompatible), (3, 3, 0))
        report = json.loads((self.tmp / "out.json").read_text(encoding="utf-8"))
        self.assertTrue(report["replaceable"])
        self.assertEqual(report["counts"],
                         {"records": 3, "compatible": 3, "incompatible": 0})
        self.assertTrue(report["complete"])
        self.assertEqual([r["record_id"] for r in report["records"]],
                         ["r1", "r2", "r3"])

    def test_one_incompatible_record_blocks_switch(self):
        history = write_history(self.tmp, ["r1 0a0b", "r2 0b0c"])
        summary = check_compatibility(current_cfg(), candidate_cfg(c_code="0d"),
                                      history,
                                      report_path=self.tmp / "out.json")
        self.assertFalse(summary.replaceable)
        self.assertEqual((summary.compatible, summary.incompatible), (1, 1))
        report = json.loads((self.tmp / "out.json").read_text(encoding="utf-8"))
        self.assertEqual([r["compatible"] for r in report["records"]],
                         [True, False])
        self.assertEqual(report["records"][1]["difference"]["kind"],
                         "candidate_no_legal_sequence")

    def test_empty_history_has_zero_counts(self):
        history = write_history(self.tmp, [])
        summary = check_compatibility(current_cfg(), candidate_cfg(), history,
                                      report_path=self.tmp / "out.json")
        self.assertEqual((summary.total, summary.compatible,
                          summary.incompatible), (0, 0, 0))
        self.assertTrue(summary.replaceable)
        report = json.loads((self.tmp / "out.json").read_text(encoding="utf-8"))
        self.assertTrue(report["replaceable"])
        self.assertEqual(report["records"], [])

    def test_candidate_with_release_conflict_is_refused(self):
        bad = cfg(version="bad",
                  codes={"A": "0a", "B": "0a0b", "C": "0b"},
                  transitions=[["s", "A", "x"], ["x", "C", "ok"],
                               ["s", "B", "ok"]])
        history = write_history(self.tmp, ["r1 0a0b"])
        with self.assertRaises(CandidateNotReleasable):
            check_compatibility(current_cfg(), bad, history,
                                report_path=self.tmp / "out.json")
        self.assertFalse((self.tmp / "out.json").exists())

    def test_candidate_audit_incomplete_is_refused(self):
        history = write_history(self.tmp, ["r1 0a0b"])
        with self.assertRaises(CandidateAuditIncomplete):
            check_compatibility(current_cfg(), candidate_cfg(), history,
                                report_path=self.tmp / "out.json",
                                max_product_states=1)
        self.assertFalse((self.tmp / "out.json").exists())

    def test_extra_field_is_a_format_error(self):
        history = write_history(self.tmp, ["r1 0a0b extra"])
        with self.assertRaises(HistoryFormatError):
            check_compatibility(current_cfg(), candidate_cfg(), history)

    def test_current_ambiguous_config_is_invalid_evidence(self):
        # A configuration that was somehow released despite an ambiguity cannot
        # define what the record meant; the check refuses rather than guessing.
        ambiguous_current = cfg(
            codes={"A": "0a", "B": "0a0b", "C": "0b"},
            transitions=[["s", "A", "x"], ["x", "C", "ok"], ["s", "B", "ok"]])
        history = write_history(self.tmp, ["r1 0a0b"])
        with self.assertRaises(CurrentDecodeError):
            check_compatibility(ambiguous_current, candidate_cfg(), history)

    def test_invalid_history_leaves_existing_report_untouched(self):
        target = self.tmp / "out.json"
        original = b'{"previous": "report"}\n'
        target.write_bytes(original)
        history = write_history(self.tmp, ["r1 0a0b", "oops"])
        with self.assertRaises(HistoryFormatError):
            check_compatibility(current_cfg(), candidate_cfg(), history,
                                report_path=target)
        self.assertEqual(target.read_bytes(), original)
        leftovers = [p for p in self.tmp.iterdir() if p.name != "out.json"
                     and p.name != "history.txt"]
        self.assertEqual(leftovers, [])

    def test_current_decode_failure_leaves_report_untouched(self):
        target = self.tmp / "out.json"
        target.write_text("KEEP", encoding="utf-8")
        history = write_history(self.tmp, ["r1 0a0b", "r2 0c"])
        with self.assertRaises(CurrentDecodeError):
            check_compatibility(current_cfg(), candidate_cfg(), history,
                                report_path=target)
        self.assertEqual(target.read_text(encoding="utf-8"), "KEEP")

    def test_not_replaceable_still_writes_complete_report(self):
        target = self.tmp / "out.json"
        target.write_text("STALE", encoding="utf-8")
        history = write_history(self.tmp, ["r1 0b0c"])
        summary = check_compatibility(current_cfg(), candidate_cfg(c_code="0d"),
                                      history, report_path=target)
        self.assertFalse(summary.replaceable)
        report = json.loads(target.read_text(encoding="utf-8"))
        self.assertTrue(report["complete"])
        self.assertFalse(report["replaceable"])

    def test_deterministic_output(self):
        history = write_history(self.tmp, ["r1 0a0b", "r2 0b0c", "r3 0a0b"])
        outputs = []
        for name in ("a.json", "b.json"):
            check_compatibility(current_cfg(), candidate_cfg(c_code="0d"),
                                history, report_path=self.tmp / name)
            outputs.append((self.tmp / name).read_bytes())
        self.assertEqual(outputs[0], outputs[1])

    def test_no_report_path_still_checks(self):
        history = write_history(self.tmp, ["r1 0a0b"])
        summary = check_compatibility(current_cfg(), candidate_cfg(), history)
        self.assertTrue(summary.replaceable)
        self.assertEqual(list(self.tmp.iterdir()), [history])

    def test_duplicate_id_is_invalid_evidence(self):
        history = write_history(self.tmp, ["r1 0a0b", "r1 0a0b"])
        with self.assertRaises(DuplicateRecordId):
            check_compatibility(current_cfg(), candidate_cfg(), history,
                                report_path=self.tmp / "out.json")
        self.assertFalse((self.tmp / "out.json").exists())

    def test_large_history_streams(self):
        # Many records, one body: exercises the on-disk id index and streaming.
        count = 5000
        history = self.tmp / "big.txt"
        with history.open("w", encoding="utf-8") as handle:
            for i in range(count):
                handle.write(f"r{i} 0a0b\n")
        summary = check_compatibility(current_cfg(), candidate_cfg(), history,
                                      report_path=self.tmp / "out.json")
        self.assertEqual(summary.total, count)
        self.assertTrue(summary.replaceable)
        report = json.loads((self.tmp / "out.json").read_text(encoding="utf-8"))
        self.assertEqual(len(report["records"]), count)
        self.assertEqual(report["records"][0]["record_id"], "r0")
        self.assertEqual(report["records"][-1]["record_id"], f"r{count - 1}")


class CheckCompatCliTests(unittest.TestCase):
    def run_cli(self, *args):
        bootstrap = ("import sys; sys.path.insert(0, %r); "
                     "from scanflow.cli import main; sys.exit(main(sys.argv[1:]))"
                     % str(ROOT))
        return subprocess.run([sys.executable, "-I", "-c", bootstrap, *args],
                              capture_output=True, cwd=str(ROOT))

    def make(self, tmp, cur, cand, lines):
        cur_path = Path(tmp) / "cur.json"
        cand_path = Path(tmp) / "cand.json"
        cur_path.write_text(json.dumps(CurJson), encoding="utf-8")
        cand_path.write_text(json.dumps(cand), encoding="utf-8")
        hist = Path(tmp) / "h.txt"
        hist.write_text("\n".join(lines) + ("\n" if lines else ""),
                        encoding="utf-8")
        return cur_path, cand_path, hist

    def test_exit_codes_and_atomic_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            cur = {"version": "cur", "wire": 1,
                   "codes": {"A": "0a", "B": "0b"},
                   "flow": {"start": "s", "accepts": ["ok"],
                            "transitions": [["s", "A", "s"],
                                            ["s", "B", "ok"]]}}
            cand = dict(cur, version="cand", wire=2)
            report = Path(tmp) / "out.json"
            cur_path, cand_path, hist = self.make(
                tmp, cur, cand, ["r1 0a0b"])
            result = self.run_cli("check-compat", "--current", str(cur_path),
                                  "--candidate", str(cand_path),
                                  "--history", str(hist),
                                  "--report", str(report), "--json")
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertTrue(payload["replaceable"])
            self.assertTrue(report.exists())

            # Incompatible candidate code: exit 3, report still written.
            cand_bad = dict(cand, codes={"A": "0a", "B": "0d"})
            cand_path.write_text(json.dumps(cand_bad), encoding="utf-8")
            report.write_text("STALE", encoding="utf-8")
            result = self.run_cli("check-compat", "--current", str(cur_path),
                                  "--candidate", str(cand_path),
                                  "--history", str(hist),
                                  "--report", str(report))
            self.assertEqual(result.returncode, 3, result.stderr)
            self.assertTrue(report.read_text(encoding="utf-8").startswith("{"))

            # Malformed history: exit 2 and report preserved.
            report.write_text("STALE", encoding="utf-8")
            hist.write_text("r1 0a0b\nnonsense\n", encoding="utf-8")
            result = self.run_cli("check-compat", "--current", str(cur_path),
                                  "--candidate", str(cand_path),
                                  "--history", str(hist),
                                  "--report", str(report))
            self.assertEqual(result.returncode, 2)
            self.assertEqual(report.read_text(encoding="utf-8"), "STALE")

    def test_empty_history_exits_0(self):
        with tempfile.TemporaryDirectory() as tmp:
            cur = dict(CurJson)
            cand = dict(cur, version="cand", wire=2)
            cur_path, cand_path, hist = self.make(tmp, cur, cand, [])
            result = self.run_cli("check-compat", "--current", str(cur_path),
                                  "--candidate", str(cand_path),
                                  "--history", str(hist))
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_report_may_not_be_the_history_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            cur = dict(CurJson)
            cand = dict(cur, version="cand", wire=2)
            cur_path, cand_path, hist = self.make(tmp, cur, cand, ["r1 0a0b"])
            before = hist.read_bytes()
            result = self.run_cli("check-compat", "--current", str(cur_path),
                                  "--candidate", str(cand_path),
                                  "--history", str(hist),
                                  "--report", str(hist))
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(hist.read_bytes(), before)

    def test_unwritable_report_exits_1_and_keeps_old(self):
        with tempfile.TemporaryDirectory() as tmp:
            cur = dict(CurJson)
            cand = dict(cur, version="cand", wire=2)
            cur_path, cand_path, hist = self.make(tmp, cur, cand, ["r1 0a0b"])
            missing_dir = Path(tmp) / "no-such-dir" / "out.json"
            result = self.run_cli("check-compat", "--current", str(cur_path),
                                  "--candidate", str(cand_path),
                                  "--history", str(hist),
                                  "--report", str(missing_dir))
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertFalse(missing_dir.exists())

    def test_bad_config_exits_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("{not json", encoding="utf-8")
            good = Path(tmp) / "good.json"
            good.write_text("{}", encoding="utf-8")
            hist = Path(tmp) / "h.txt"
            hist.write_text("r1 0a\n", encoding="utf-8")
            result = self.run_cli("check-compat", "--current", str(bad),
                                  "--candidate", str(good),
                                  "--history", str(hist))
            self.assertEqual(result.returncode, 2)


CurJson = {"version": "cur", "wire": 1,
           "codes": {"A": "0a", "B": "0b"},
           "flow": {"start": "s", "accepts": ["ok"],
                    "transitions": [["s", "A", "s"], ["s", "B", "ok"]]}}


if __name__ == "__main__":
    unittest.main()
