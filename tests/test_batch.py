"""Tests for local batch reconciliation (scanflow.batch / check-batch)."""

from __future__ import annotations

import json
import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanflow import (  # noqa: E402
    BatchError,
    BatchReportWriteError,
    CodeConfig,
    DuplicatePlanEntry,
    FragmentConflictError,
    FragmentFormatError,
    FragmentRangeError,
    IllegalPlanSequence,
    PlanFormatError,
    Registry,
    check_plan_sequence,
    encode_frame,
    iter_fragments,
    iter_plan,
    parse_fragment_line,
    parse_plan_line,
    reconcile_batch,
)

CODES = {"A": "0a", "B": "0b", "C": "0c", "X": "01", "Y": "02"}


def cfg(version="v1", wire=1):
    # Legal sequences: A* B C*
    return CodeConfig.from_obj({
        "version": version, "wire": wire,
        "codes": {"A": "0a", "B": "0b", "C": "0c"},
        "flow": {"start": "s", "accepts": ["ok"], "transitions": [
            ["s", "A", "s"], ["s", "B", "ok"], ["ok", "C", "ok"]]},
    })


def cfg2(version="v2", wire=2):
    # Legal sequences: X* Y
    return CodeConfig.from_obj({
        "version": version, "wire": wire,
        "codes": {"X": "01", "Y": "02"},
        "flow": {"start": "s", "accepts": ["ok"], "transitions": [
            ["s", "X", "s"], ["s", "Y", "ok"]]},
    })


def registry(*configs):
    reg = Registry()
    for config in configs:
        reg.register(config)
    return reg


def frame(wire, seq):
    return encode_frame(wire, bytes.fromhex("".join(CODES[a] for a in seq)))


def plan_line(wire, actions, planned):
    return json.dumps({"wire": wire, "actions": list(actions),
                       "planned": planned})


def fragment_line(offset, data):
    return json.dumps({"offset": offset, "data_hex": data.hex()})


def write_jsonl(directory, name, lines, trailing_newline=True):
    path = Path(directory) / name
    text = "\n".join(lines) + ("\n" if lines and trailing_newline else "")
    path.write_text(text, encoding="utf-8")
    return path


def slices(stream, ranges):
    return [fragment_line(start, stream[start:end]) for start, end in ranges]


class PlanParsingTests(unittest.TestCase):
    def test_valid_line(self):
        wire, actions, planned = parse_plan_line(
            '{"wire": 1, "actions": ["A", "B"], "planned": 3}', 1)
        self.assertEqual((wire, actions, planned), (1, ("A", "B"), 3))

    def test_rejects_malformed_lines(self):
        bad = [
            "",
            "   ",
            "not json",
            '["wire", 1]',
            '{"wire": 1, "actions": ["B"]}',                    # missing planned
            '{"wire": 1, "planned": 1, "actions": ["B"], "x": 0}',  # extra field
            '{"wire": 1, "wire": 1, "actions": ["B"], "planned": 1}',  # dup key
            '{"wire": true, "actions": ["B"], "planned": 1}',
            '{"wire": 256, "actions": ["B"], "planned": 1}',
            '{"wire": -1, "actions": ["B"], "planned": 1}',
            '{"wire": 1, "actions": [], "planned": 1}',
            '{"wire": 1, "actions": "B", "planned": 1}',
            '{"wire": 1, "actions": [""], "planned": 1}',
            '{"wire": 1, "actions": ["B", 2], "planned": 1}',
            '{"wire": 1, "actions": ["B"], "planned": 0}',
            '{"wire": 1, "actions": ["B"], "planned": -2}',
            '{"wire": 1, "actions": ["B"], "planned": "3"}',
            '{"wire": 1, "actions": ["B"], "planned": true}',
        ]
        for text in bad:
            with self.assertRaises(PlanFormatError, msg=text):
                parse_plan_line(text, 7)

    def test_legality_check(self):
        config = cfg()
        check_plan_sequence(config, ("A", "A", "B", "C"), 1)  # no raise
        check_plan_sequence(config, ("B",), 1)
        with self.assertRaises(IllegalPlanSequence):  # unknown action
            check_plan_sequence(config, ("Z",), 1)
        with self.assertRaises(IllegalPlanSequence):  # no transition from ok on A
            check_plan_sequence(config, ("B", "A"), 1)
        with self.assertRaises(IllegalPlanSequence):  # ends in non-accept state
            check_plan_sequence(config, ("A",), 1)

    def test_iter_plan_validates_and_dedups(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_jsonl(tmp, "plan.jsonl", [
                plan_line(1, ["A", "B"], 2),
                plan_line(1, ["B"], 1),
            ])
            entries = list(iter_plan(path, registry(cfg())))
        self.assertEqual([(e.wire, e.actions, e.planned, e.line_no)
                          for e in entries],
                         [(1, ("A", "B"), 2, 1), (1, ("B",), 1, 2)])

    def test_iter_plan_rejects_duplicate_sequence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_jsonl(tmp, "plan.jsonl", [
                plan_line(1, ["A", "B"], 2),
                plan_line(1, ["B"], 1),
                plan_line(1, ["A", "B"], 5),
            ])
            with self.assertRaises(DuplicatePlanEntry) as ctx:
                list(iter_plan(path, registry(cfg())))
        self.assertEqual(ctx.exception.line_no, 3)
        self.assertEqual(ctx.exception.first_line, 1)

    def test_same_sequence_on_two_wires_is_not_a_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_jsonl(tmp, "plan.jsonl", [
                plan_line(1, ["B"], 1),
                plan_line(2, ["B"], 1),
            ])
            reg = registry(cfg(), cfg2())
            # wire 2's config has no action "B": the failure must be legality,
            # not duplication.
            with self.assertRaises(IllegalPlanSequence):
                list(iter_plan(path, reg))

    def test_iter_plan_rejects_unknown_wire(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_jsonl(tmp, "plan.jsonl", [plan_line(9, ["B"], 1)])
            with self.assertRaises(PlanFormatError):
                list(iter_plan(path, registry(cfg())))

    def test_iter_plan_missing_file(self):
        with self.assertRaises(BatchError):
            list(iter_plan("/nonexistent/plan.jsonl", registry(cfg())))


class FragmentParsingTests(unittest.TestCase):
    def test_valid_line(self):
        frag = parse_fragment_line('{"offset": 3, "data_hex": "0a0B"}', 1, 10)
        self.assertEqual((frag.offset, frag.data), (3, b"\x0a\x0b"))

    def test_rejects_malformed_lines(self):
        bad = [
            "",
            "not json",
            '[1, "0a"]',
            '{"offset": 0}',                                # missing data_hex
            '{"offset": 0, "data_hex": "0a", "z": 1}',      # extra field
            '{"offset": 0, "offset": 0, "data_hex": "0a"}',  # dup key
            '{"offset": -1, "data_hex": "0a"}',
            '{"offset": true, "data_hex": "0a"}',
            '{"offset": 0, "data_hex": ""}',                # empty not allowed
            '{"offset": 0, "data_hex": "0a0"}',             # odd length
            '{"offset": 0, "data_hex": "0x0a"}',
            '{"offset": 0, "data_hex": 12}',
        ]
        for text in bad:
            with self.assertRaises(FragmentFormatError, msg=text):
                parse_fragment_line(text, 3, 100)

    def test_size_limit_is_64_kib(self):
        ok = parse_fragment_line(
            json.dumps({"offset": 0, "data_hex": "00" * 65536}), 1, 65536)
        self.assertEqual(len(ok.data), 65536)
        with self.assertRaises(FragmentFormatError):
            parse_fragment_line(
                json.dumps({"offset": 0, "data_hex": "00" * 65537}), 1, 70000)

    def test_must_lie_inside_declared_range(self):
        with self.assertRaises(FragmentRangeError):
            parse_fragment_line('{"offset": 9, "data_hex": "0a0b"}', 1, 10)
        with self.assertRaises(FragmentRangeError):
            parse_fragment_line('{"offset": 10, "data_hex": "0a"}', 1, 10)
        frag = parse_fragment_line('{"offset": 8, "data_hex": "0a0b"}', 1, 10)
        self.assertEqual(frag.offset, 8)

    def test_iter_fragments_streams(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_jsonl(tmp, "f.jsonl", [
                '{"offset": 0, "data_hex": "0a"}',
                '{"offset": 1, "data_hex": "0b"}',
            ])
            frags = list(iter_fragments(path, 2))
        self.assertEqual([(f.offset, f.data) for f in frags],
                         [(0, b"\x0a"), (1, b"\x0b")])

    def test_crlf_and_no_final_newline(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "f.jsonl"
            path.write_bytes(b'{"offset": 0, "data_hex": "0a"}\r\n'
                             b'{"offset": 1, "data_hex": "0b"}')
            frags = list(iter_fragments(path, 2))
        self.assertEqual([(f.offset, f.data) for f in frags],
                         [(0, b"\x0a"), (1, b"\x0b")])

    def test_oversized_integers_are_clean_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = write_jsonl(tmp, "plan.jsonl", [plan_line(1, ["B"], 1)])
            frags = write_jsonl(tmp, "fragments.jsonl", [])
            with self.assertRaises(BatchError):
                reconcile_batch(registry(cfg()), plan, frags, 1 << 70)
            huge_plan = write_jsonl(tmp, "huge.jsonl",
                                    [plan_line(1, ["B"], 1 << 70)])
            with self.assertRaises(BatchError):
                reconcile_batch(registry(cfg()), huge_plan, frags, 0)


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.reg = registry(cfg(), cfg2())

    def run_reconcile(self, stream, plan_lines, fragment_lines, **kwargs):
        plan = write_jsonl(self.tmp, "plan.jsonl", plan_lines)
        frags = write_jsonl(self.tmp, "fragments.jsonl", fragment_lines)
        return reconcile_batch(self.reg, plan, frags, len(stream), **kwargs)

    def test_complete_match(self):
        stream = frame(1, ["A", "B"]) + frame(1, ["B"]) + frame(1, ["A", "B"])
        summary = self.run_reconcile(
            stream,
            [plan_line(1, ["A", "B"], 2), plan_line(1, ["B"], 1)],
            slices(stream, [(0, len(stream))]))
        self.assertTrue(summary.evidence_complete)
        self.assertTrue(summary.batch_match)
        self.assertEqual((summary.rows, summary.matched, summary.short,
                          summary.over), (2, 2, 0, 0))
        self.assertEqual(summary.frames_accepted, 3)

    def test_short_and_over_rows(self):
        stream = frame(1, ["A", "B"]) + frame(1, ["B"])
        summary = self.run_reconcile(
            stream,
            [plan_line(1, ["A", "B"], 2),      # confirmed 1 -> short
             plan_line(1, ["A", "A", "B"], 1)],  # confirmed 0 -> short
            slices(stream, [(0, len(stream))]))
        self.assertTrue(summary.evidence_complete)
        self.assertFalse(summary.batch_match)
        # ["B"] confirmed but never planned -> over
        self.assertEqual((summary.matched, summary.short, summary.over),
                         (0, 2, 1))

    def test_rows_are_union_sorted_by_wire_then_sequence(self):
        stream = (frame(1, ["B"]) + frame(1, ["A", "B", "C"])
                  + frame(1, ["A", "A", "B"]) + frame(1, ["A", "B"])
                  + frame(2, ["X", "Y"]))
        plan = write_jsonl(self.tmp, "plan.jsonl", [])
        frags = write_jsonl(self.tmp, "fragments.jsonl",
                            slices(stream, [(0, len(stream))]))
        report = self.tmp / "out.json"
        reconcile_batch(self.reg, plan, frags, len(stream), report_path=report)
        rows = json.loads(report.read_text(encoding="utf-8"))["rows"]
        self.assertEqual(
            [(r["wire"], r["actions"], r["planned"], r["confirmed"])
             for r in rows],
            [(1, ["A", "A", "B"], 0, 1),
             (1, ["A", "B"], 0, 1),
             (1, ["A", "B", "C"], 0, 1),
             (1, ["B"], 0, 1),
             (2, ["X", "Y"], 0, 1)])

    def test_sequence_order_is_not_json_key_order(self):
        # "A\n" sorts before "A!" by code point; the JSON-encoded key would
        # order them the other way, so this exercises the sequence collation.
        weird = CodeConfig.from_obj({
            "version": "vw", "wire": 7,
            "codes": {"A\n": "01", "A!": "02"},
            "flow": {"start": "s", "accepts": ["ok"], "transitions": [
                ["s", "A\n", "ok"], ["s", "A!", "ok"]]},
        })
        reg = registry(weird)
        stream = encode_frame(7, b"\x02") + encode_frame(7, b"\x01")
        plan = write_jsonl(self.tmp, "plan.jsonl", [
            plan_line(7, ["A!"], 1),
            plan_line(7, ["A\n"], 1),
        ])
        frags = write_jsonl(self.tmp, "fragments.jsonl",
                            slices(stream, [(0, len(stream))]))
        report = self.tmp / "out.json"
        summary = reconcile_batch(reg, plan, frags, len(stream),
                                  report_path=report)
        self.assertTrue(summary.batch_match)
        rows = json.loads(report.read_text(encoding="utf-8"))["rows"]
        self.assertEqual([r["actions"] for r in rows], [["A\n"], ["A!"]])

    def test_retransmission_counts_once_and_positions_count_twice(self):
        one = frame(1, ["B"])
        stream = one + one  # same frame bytes at two positions -> counts twice
        summary = self.run_reconcile(
            stream,
            [plan_line(1, ["B"], 2)],
            # The second copy is additionally retransmitted, twice, overlapping.
            slices(stream, [(0, len(one)), (len(one), len(stream)),
                            (len(one), len(stream)), (0, len(stream))]))
        self.assertTrue(summary.batch_match)
        self.assertEqual(summary.frames_accepted, 2)
        self.assertEqual(summary.received_bytes, len(stream))

    def test_fragment_order_and_retransmit_count_do_not_matter(self):
        stream = (frame(1, ["A", "B"]) + frame(1, ["B", "C"])
                  + frame(2, ["X", "X", "Y"]) + frame(1, ["A", "A", "B"]))
        plan_lines = [plan_line(1, ["A", "B"], 1), plan_line(1, ["B", "C"], 1),
                      plan_line(1, ["A", "A", "B"], 1),
                      plan_line(2, ["X", "X", "Y"], 1)]
        base_ranges = [(0, 11), (9, 23), (20, 33), (30, len(stream))]
        rng = random.Random(2024)
        reports = []
        for trial in range(4):
            ranges = list(base_ranges)
            rng.shuffle(ranges)
            lines = slices(stream, ranges)
            # Sprinkle duplicates and an extra full retransmission.
            lines += slices(stream, [(0, len(stream))] + base_ranges[:2])
            rng.shuffle(lines)
            plan = write_jsonl(self.tmp, f"plan{trial}.jsonl", plan_lines)
            frags = write_jsonl(self.tmp, f"frag{trial}.jsonl", lines)
            report = self.tmp / f"out{trial}.json"
            summary = reconcile_batch(self.reg, plan, frags, len(stream),
                                      report_path=report)
            self.assertTrue(summary.batch_match)
            reports.append(report.read_bytes())
        self.assertEqual(len(set(reports)), 1)

    def test_conflicting_overlap_is_invalid_evidence(self):
        stream = frame(1, ["B"]) + b"\xde\xad\xbe\xef"  # 12 bytes
        plan = write_jsonl(self.tmp, "plan.jsonl", [plan_line(1, ["B"], 1)])
        # Overlap [9, 11): "ff ee" from the first fragment, "ff 00" from the
        # second -- the first conflicting byte is at stream offset 10.
        frags = write_jsonl(self.tmp, "fragments.jsonl", [
            '{"offset": 8, "data_hex": "c0ffee"}',
            '{"offset": 9, "data_hex": "ff00"}',
        ])
        with self.assertRaises(FragmentConflictError) as ctx:
            reconcile_batch(self.reg, plan, frags, len(stream))
        self.assertEqual(ctx.exception.position, 10)
        # Identical bytes in an overlap are fine and count once.
        good = write_jsonl(self.tmp, "good.jsonl",
                           slices(stream, [(0, 8), (6, 12), (6, 12)]))
        summary = reconcile_batch(self.reg, plan, good, len(stream))
        self.assertEqual(summary.received_bytes, 12)
        self.assertIsNone(summary.first_missing_offset)

    def test_gap_stops_counting_and_reports_first_missing(self):
        stream = frame(1, ["A", "B"]) + frame(1, ["B"])  # 9 + 8 = 17 bytes
        summary = self.run_reconcile(
            stream,
            [plan_line(1, ["A", "B"], 1), plan_line(1, ["B"], 1)],
            # Byte 9 (start of the second frame) is missing; bytes 10..16
            # arrived but lie past the gap and must not be spliced in.
            slices(stream, [(0, 9), (10, 17)]))
        self.assertFalse(summary.evidence_complete)
        self.assertIsNone(summary.batch_match)
        self.assertEqual(summary.first_missing_offset, 9)
        self.assertEqual(summary.parsed_prefix_bytes, 9)
        self.assertEqual(summary.frames_accepted, 1)  # the second frame is not counted
        self.assertEqual(summary.received_bytes, 16)
        self.assertEqual((summary.matched, summary.short, summary.over),
                         (None, None, None))

    def test_report_marks_lower_bounds_when_incomplete(self):
        stream = frame(1, ["A", "B"]) + frame(1, ["B"])
        plan = write_jsonl(self.tmp, "plan.jsonl",
                           [plan_line(1, ["A", "B"], 1), plan_line(1, ["B"], 1)])
        frags = write_jsonl(self.tmp, "fragments.jsonl",
                            slices(stream, [(0, 9), (10, 17)]))
        report = self.tmp / "out.json"
        reconcile_batch(self.reg, plan, frags, len(stream), report_path=report)
        payload = json.loads(report.read_text(encoding="utf-8"))
        self.assertFalse(payload["evidence_complete"])
        self.assertTrue(payload["counts_are_lower_bounds"])
        self.assertIsNone(payload["batch_match"])
        self.assertEqual(payload["coverage"]["first_missing_offset"], 9)
        self.assertTrue(all(row["status"] is None for row in payload["rows"]))
        self.assertEqual(payload["counts"],
                         {"rows": 2, "match": None, "short": None, "over": None})

    def test_noise_rejection_and_truncation_make_evidence_incomplete(self):
        # Leading noise byte.
        noisy = b"\xff" + frame(1, ["B"])
        summary = self.run_reconcile(noisy, [plan_line(1, ["B"], 1)],
                                     slices(noisy, [(0, len(noisy))]))
        self.assertFalse(summary.evidence_complete)
        self.assertIsNone(summary.first_missing_offset)  # fully received...
        self.assertEqual(summary.noise_bytes, 1)         # ...but not clean

        # Bad CRC -> rejected frame.
        bad = bytearray(frame(1, ["B"]))
        bad[-1] ^= 0xFF
        summary = self.run_reconcile(bytes(bad), [plan_line(1, ["B"], 1)],
                                     slices(bytes(bad), [(0, len(bad))]))
        self.assertFalse(summary.evidence_complete)
        self.assertEqual(summary.frames_rejected, 1)

        # Stream ends mid-frame -> truncated.
        cut = frame(1, ["B"])[:-1]
        summary = self.run_reconcile(cut, [plan_line(1, ["B"], 1)],
                                     slices(cut, [(0, len(cut))]))
        self.assertFalse(summary.evidence_complete)
        self.assertTrue(summary.truncated)

        # Unknown version byte -> rejected frame.
        foreign = encode_frame(9, b"\x00")
        summary = self.run_reconcile(foreign, [], slices(foreign, [(0, len(foreign))]))
        self.assertFalse(summary.evidence_complete)
        self.assertEqual(summary.frames_rejected, 1)

    def test_empty_plan_and_empty_stream_match_vacuously(self):
        summary = self.run_reconcile(b"", [], [])
        self.assertTrue(summary.evidence_complete)
        self.assertTrue(summary.batch_match)
        self.assertEqual(summary.rows, 0)

    def test_empty_stream_with_plan_is_short(self):
        summary = self.run_reconcile(b"", [plan_line(1, ["B"], 1)], [])
        self.assertTrue(summary.evidence_complete)
        self.assertFalse(summary.batch_match)
        self.assertEqual(summary.short, 1)

    def test_invalid_inputs_leave_report_and_inputs_untouched(self):
        stream = frame(1, ["B"])
        plan = write_jsonl(self.tmp, "plan.jsonl",
                           [plan_line(1, ["B"], 1), plan_line(1, ["B"], 2)])
        frags = write_jsonl(self.tmp, "fragments.jsonl",
                            slices(stream, [(0, len(stream))]))
        report = self.tmp / "out.json"
        report.write_text("KEEP", encoding="utf-8")
        before = (plan.read_bytes(), frags.read_bytes())
        with self.assertRaises(DuplicatePlanEntry):
            reconcile_batch(self.reg, plan, frags, len(stream),
                            report_path=report)
        self.assertEqual(report.read_text(encoding="utf-8"), "KEEP")
        self.assertEqual((plan.read_bytes(), frags.read_bytes()), before)
        leftovers = [p.name for p in self.tmp.iterdir()
                     if p.name not in {"plan.jsonl", "fragments.jsonl",
                                       "out.json"}]
        self.assertEqual(leftovers, [])

    def test_report_may_not_be_an_input(self):
        stream = frame(1, ["B"])
        plan = write_jsonl(self.tmp, "plan.jsonl", [plan_line(1, ["B"], 1)])
        frags = write_jsonl(self.tmp, "fragments.jsonl",
                            slices(stream, [(0, len(stream))]))
        for target in (plan, frags):
            with self.assertRaises(BatchReportWriteError):
                reconcile_batch(self.reg, plan, frags, len(stream),
                                report_path=target)

    def test_no_report_path_still_reconciles(self):
        stream = frame(1, ["B"])
        summary = self.run_reconcile(stream, [plan_line(1, ["B"], 1)],
                                     slices(stream, [(0, len(stream))]))
        self.assertTrue(summary.batch_match)
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir()),
                         ["fragments.jsonl", "plan.jsonl"])

    def test_large_stream_with_shuffled_fragments(self):
        rng = random.Random(7)
        sequences = [("B",), ("A", "B"), ("A", "A", "B"), ("B", "C"),
                     ("A", "B", "C", "C")]
        planned = {}
        frames = []
        for _ in range(3000):
            seq = rng.choice(sequences)
            planned[seq] = planned.get(seq, 0) + 1
            frames.append(frame(1, list(seq)))
        stream = b"".join(frames)
        # Cut into irregular overlapping fragments, duplicate some, shuffle.
        ranges = []
        pos = 0
        while pos < len(stream):
            end = min(len(stream), pos + rng.randrange(200, 700))
            ranges.append((pos, end))
            pos = end - rng.randrange(0, 50) if end < len(stream) else end
        lines = slices(stream, ranges)
        lines += [lines[i] for i in rng.sample(range(len(lines)), 20)]
        rng.shuffle(lines)
        plan_lines = [plan_line(1, list(seq), count)
                      for seq, count in planned.items()]
        summary = self.run_reconcile(stream, plan_lines, lines)
        self.assertTrue(summary.evidence_complete)
        self.assertTrue(summary.batch_match)
        self.assertEqual(summary.frames_accepted, 3000)
        self.assertEqual(summary.rows, len(planned))


class CheckBatchCliTests(unittest.TestCase):
    def run_cli(self, *args):
        bootstrap = ("import sys; sys.path.insert(0, %r); "
                     "from scanflow.cli import main; sys.exit(main(sys.argv[1:]))"
                     % str(ROOT))
        return subprocess.run([sys.executable, "-I", "-c", bootstrap, *args],
                              capture_output=True, cwd=str(ROOT))

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.config = self.tmp / "good.json"
        self.config.write_text(json.dumps({
            "version": "v1", "wire": 1,
            "codes": {"A": "0a", "B": "0b", "C": "0c"},
            "flow": {"start": "s", "accepts": ["ok"], "transitions": [
                ["s", "A", "s"], ["s", "B", "ok"], ["ok", "C", "ok"]]},
        }), encoding="utf-8")

    def write_inputs(self, stream, plan_lines, ranges):
        plan = write_jsonl(self.tmp, "plan.jsonl", plan_lines)
        frags = write_jsonl(self.tmp, "fragments.jsonl", slices(stream, ranges))
        return plan, frags

    def test_exit_0_on_match_and_report_written(self):
        stream = frame(1, ["A", "B"]) + frame(1, ["B"])
        plan, frags = self.write_inputs(
            stream, [plan_line(1, ["A", "B"], 1), plan_line(1, ["B"], 1)],
            [(0, len(stream))])
        report = self.tmp / "out.json"
        result = self.run_cli("check-batch", "--config", str(self.config),
                              "--plan", str(plan), "--fragments", str(frags),
                              "--stream-total", str(len(stream)),
                              "--report", str(report), "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["batch_match"])
        self.assertTrue(payload["evidence_complete"])
        self.assertEqual(payload["report"], str(report))
        written = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(written["kind"], "scanflow.batch_reconciliation")
        self.assertTrue(written["batch_match"])
        self.assertEqual([r["status"] for r in written["rows"]],
                         ["match", "match"])

    def test_exit_3_on_mismatch(self):
        stream = frame(1, ["B"])
        plan, frags = self.write_inputs(stream, [plan_line(1, ["B"], 2)],
                                        [(0, len(stream))])
        result = self.run_cli("check-batch", "--config", str(self.config),
                              "--plan", str(plan), "--fragments", str(frags),
                              "--stream-total", str(len(stream)))
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn(b"MISMATCH", result.stdout)

    def test_exit_4_on_incomplete_evidence(self):
        stream = frame(1, ["B"]) + frame(1, ["B"])
        plan, frags = self.write_inputs(stream, [plan_line(1, ["B"], 2)],
                                        [(0, 8)])  # second frame missing
        result = self.run_cli("check-batch", "--config", str(self.config),
                              "--plan", str(plan), "--fragments", str(frags),
                              "--stream-total", str(len(stream)), "--json")
        self.assertEqual(result.returncode, 4, result.stderr)
        payload = json.loads(result.stdout)
        self.assertFalse(payload["evidence_complete"])
        self.assertIsNone(payload["batch_match"])
        self.assertEqual(payload["coverage"]["first_missing_offset"], 8)

    def test_exit_2_on_invalid_evidence(self):
        stream = frame(1, ["B"])
        # Illegal plan: sequence does not reach an accept state.
        plan, frags = self.write_inputs(stream, [plan_line(1, ["A"], 1)],
                                        [(0, len(stream))])
        report = self.tmp / "out.json"
        report.write_text("STALE", encoding="utf-8")
        result = self.run_cli("check-batch", "--config", str(self.config),
                              "--plan", str(plan), "--fragments", str(frags),
                              "--stream-total", str(len(stream)),
                              "--report", str(report))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(report.read_text(encoding="utf-8"), "STALE")

        # Byte conflict between fragments.
        plan, _ = self.write_inputs(stream, [plan_line(1, ["B"], 1)],
                                    [(0, len(stream))])
        frags = write_jsonl(self.tmp, "fragments.jsonl",
                            ['{"offset": 0, "data_hex": "a55c"}',
                             '{"offset": 1, "data_hex": "00"}'])
        result = self.run_cli("check-batch", "--config", str(self.config),
                              "--plan", str(plan), "--fragments", str(frags),
                              "--stream-total", str(len(stream)))
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_exit_2_when_config_not_approved(self):
        bad_dir = self.tmp / "conf"
        bad_dir.mkdir()
        (bad_dir / "conflict.json").write_text(json.dumps({
            "version": "bad", "wire": 1,
            "codes": {"A": "0a", "B": "0a0b", "C": "0b"},
            "flow": {"start": "s", "accepts": ["ok"], "transitions": [
                ["s", "A", "x"], ["x", "C", "ok"], ["s", "B", "ok"]]},
        }), encoding="utf-8")
        stream = frame(1, ["B"])
        plan, frags = self.write_inputs(stream, [plan_line(1, ["B"], 1)],
                                        [(0, len(stream))])
        result = self.run_cli("check-batch", "--config-dir", str(bad_dir),
                              "--plan", str(plan), "--fragments", str(frags),
                              "--stream-total", str(len(stream)))
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_exit_1_when_report_unwritable_or_is_an_input(self):
        stream = frame(1, ["B"])
        plan, frags = self.write_inputs(stream, [plan_line(1, ["B"], 1)],
                                        [(0, len(stream))])
        missing_dir = self.tmp / "no-such-dir" / "out.json"
        result = self.run_cli("check-batch", "--config", str(self.config),
                              "--plan", str(plan), "--fragments", str(frags),
                              "--stream-total", str(len(stream)),
                              "--report", str(missing_dir))
        self.assertEqual(result.returncode, 1, result.stderr)

        before = frags.read_bytes()
        result = self.run_cli("check-batch", "--config", str(self.config),
                              "--plan", str(plan), "--fragments", str(frags),
                              "--stream-total", str(len(stream)),
                              "--report", str(frags))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(frags.read_bytes(), before)

    def test_config_dir_and_text_output(self):
        stream = frame(1, ["B"])
        plan, frags = self.write_inputs(stream, [plan_line(1, ["B"], 1)],
                                        [(0, len(stream))])
        result = self.run_cli("check-batch", "--config-dir", str(self.tmp),
                              "--plan", str(plan), "--fragments", str(frags),
                              "--stream-total", str(len(stream)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"batch: MATCH", result.stdout)

    def test_no_config_is_an_error(self):
        stream = frame(1, ["B"])
        plan, frags = self.write_inputs(stream, [plan_line(1, ["B"], 1)],
                                        [(0, len(stream))])
        result = self.run_cli("check-batch",
                              "--plan", str(plan), "--fragments", str(frags),
                              "--stream-total", str(len(stream)))
        self.assertEqual(result.returncode, 2, result.stderr)


if __name__ == "__main__":
    unittest.main()
