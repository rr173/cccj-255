"""Minimal, dependency-free test suite.

Run with:  PYTHONPATH=. python3 -I -m unittest discover -s tests -v
"""

from __future__ import annotations

import itertools
import json
import os
import random
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanflow import (  # noqa: E402
    AuditIncomplete,
    CodeConfig,
    ConfigError,
    ConfigRejected,
    Receiver,
    Registry,
    VersionConflict,
    audit,
    decodes,
    encode_frame,
    feed_chunks,
    walk,
)


def cfg(version="v1", codes=None, start="s", accepts=("ok",), transitions=None,
        wire=None):
    obj = {
        "version": version,
        "codes": codes or {},
        "flow": {"start": start, "accepts": list(accepts),
                 "transitions": transitions or []},
    }
    if wire is not None:
        obj["wire"] = wire
    return CodeConfig.from_obj(obj)


def strings_over(alphabet, max_len):
    for n in range(1, max_len + 1):
        for tup in itertools.product(alphabet, repeat=n):
            yield "".join(tup)


# -- config validation ------------------------------------------------------


class ConfigValidationTests(unittest.TestCase):
    def test_rejects_empty_code(self):
        with self.assertRaises(ConfigError):
            cfg(codes={"A": b""})

    def test_rejects_duplicate_code(self):
        with self.assertRaises(ConfigError):
            cfg(codes={"A": b"\x01", "B": b"\x01"})

    def test_rejects_nondeterministic_transition(self):
        with self.assertRaises(ConfigError):
            cfg(codes={"A": b"\x01"},
                transitions=[["s", "A", "x"], ["s", "A", "y"]])

    def test_rejects_transition_for_unknown_action(self):
        with self.assertRaises(ConfigError):
            cfg(codes={"A": b"\x01"}, transitions=[["s", "Z", "x"]])

    def test_allows_loop_and_action_in_many_states(self):
        c = cfg(codes={"A": b"\x01", "B": b"\x02"},
                transitions=[["s", "A", "s"], ["s", "B", "x"], ["x", "A", "x"],
                             ["x", "B", "ok"]])
        self.assertTrue(decodes(c, b"\x01\x01\x02\x02"))
        self.assertTrue(decodes(c, b"\x01\x02\x01\x02"))

    def test_wire_range(self):
        with self.assertRaises(ConfigError):
            cfg(codes={"A": b"\x01"}, wire=256)


# -- decoder ----------------------------------------------------------------


class DecoderTests(unittest.TestCase):
    def c(self):
        return cfg(codes={"A": b"\x0a", "B": b"\x0a\x0b", "C": b"\x0b"},
                   transitions=[["s", "A", "x"], ["x", "C", "ok"], ["s", "B", "ok"]])

    def test_ambiguous_body_reports_both(self):
        result = walk(self.c(), bytes.fromhex("0a0b"), max_matches=2)
        self.assertEqual(len(result.matches), 2)
        self.assertEqual(sorted(m.actions for m in result.matches),
                         [["A", "C"], ["B"]])

    def test_spans_are_half_open_and_contiguous(self):
        for match in walk(self.c(), bytes.fromhex("0a0b"), max_matches=2).matches:
            pos = 0
            for action, (lo, hi) in zip(match.actions, match.spans):
                self.assertEqual(lo, pos)
                self.assertEqual(hi - lo, len(self.c().codes[action]))
                pos = hi
            self.assertEqual(pos, 2)

    def test_rejects_partial_walk(self):
        result = walk(self.c(), bytes.fromhex("0a"), max_matches=2)
        self.assertFalse(result.accepted)
        self.assertEqual(result.furthest_pos, 1)
        self.assertEqual(result.furthest_states, ["x"])

    def test_empty_body_never_accepted(self):
        c = cfg(codes={"A": b"\x01"}, start="s", accepts=("s",),
                transitions=[["s", "A", "s"]])
        self.assertFalse(decodes(c, b""))

    def test_trailing_bytes_reject(self):
        c = cfg(codes={"A": b"\x01"}, transitions=[["s", "A", "ok"]])
        self.assertTrue(decodes(c, b"\x01"))
        self.assertFalse(decodes(c, b"\x01\x01"))

    def test_long_body_iterative(self):
        # 4000 repetitions would blow a recursive descent; iterative walk is fine.
        c = cfg(codes={"A": b"\x07"}, accepts=("ok",),
                transitions=[["s", "A", "s"]])
        # add a way to reach accept after a loop
        c = cfg(codes={"A": b"\x07", "Z": b"\x09"}, accepts=("ok",),
                transitions=[["s", "A", "s"], ["s", "Z", "ok"]])
        body = b"\x07" * 4000 + b"\x09"
        self.assertTrue(decodes(c, body))


# -- audit ------------------------------------------------------------------


class AuditTests(unittest.TestCase):
    def test_detects_ambiguity_with_witness(self):
        c = cfg(codes={"A": b"\x0a", "B": b"\x0a\x0b", "C": b"\x0b"},
                transitions=[["s", "A", "x"], ["x", "C", "ok"], ["s", "B", "ok"]])
        report = audit(c)
        self.assertFalse(report.ok)
        conflict = report.conflicts[0]
        self.assertEqual(conflict.body, bytes.fromhex("0a0b"))
        self.assertEqual(sorted(conflict.sequences), [["A", "C"], ["B"]])
        # Every witness must replay in the decoder.
        for seq, spans in zip(conflict.sequences, conflict.spans):
            self.assertEqual(b"".join(c.codes[a] for a in seq), conflict.body)

    def test_shared_prefix_alone_is_not_conflict(self):
        c = cfg(codes={"A": b"\x0a", "B": b"\x0a\x0b"},
                transitions=[["s", "A", "ok"], ["s", "B", "ok"]])
        self.assertTrue(audit(c).ok)

    def test_unreachable_action_not_a_conflict(self):
        # Same prefix, but the short action is unreachable => no ambiguous body.
        c = cfg(codes={"A": b"\x0a", "B": b"\x0a\x0b"},
                transitions=[["s", "B", "ok"]])
        self.assertTrue(audit(c).ok)

    def test_loop_creates_ambiguity(self):
        # One two-byte action versus the same bytes read as two one-byte actions
        # reached through a distinct state.
        c = cfg(codes={"A": b"\x01", "AB": b"\x01\x01"},
                transitions=[["s", "A", "m"], ["m", "A", "ok"], ["s", "AB", "ok"]])
        report = audit(c)
        self.assertFalse(report.ok)
        self.assertEqual(report.conflicts[0].body, b"\x01\x01")

    def test_exhaustive_cross_check_small(self):
        # Compare the product audit against brute force over all bodies up to a
        # length that covers every code, for a grid of random small configs.
        rng = random.Random(1234)
        alphabet = [b"\x01", b"\x02", b"\x01\x02", b"\x02\x01"]
        names = ["p", "q", "r", "s1"]
        for _ in range(60):
            codes = {}
            for name in names:
                if rng.random() < 0.7:
                    codes[name] = rng.choice(alphabet)
            if not codes:
                continue
            states = ["a", "b", "c"]
            transitions = []
            for st in states:
                for name in codes:
                    if rng.random() < 0.5:
                        transitions.append([st, name, rng.choice(states)])
            try:
                c = cfg(codes=codes, start="a", accepts=tuple(
                    s for s in states if rng.random() < 0.5) or ("c",),
                    transitions=transitions)
            except ConfigError:
                continue
            report = audit(c)
            if report.ok:
                # Audit says clean: brute force over bodies up to 8 bytes must
                # agree (soundness in the other direction).
                self.assertFalse(_any_ambiguous(c, 8),
                                 msg=f"audit missed: {codes} {transitions}")
            else:
                # Audit says conflict: every witness replays, and brute force
                # reaches it at the witness length or shorter.
                for conflict in report.conflicts:
                    self.assertEqual(
                        b"".join(c.codes[a] for a in conflict.sequences[0]),
                        conflict.body)
                    self.assertTrue(_any_ambiguous(c, len(conflict.body)),
                                    msg=f"witness not reproducible: {codes}")

    def test_audit_has_no_fixed_frame_limit(self):
        # Conflict only appears at length 21, beyond any "probe a short frame" idea.
        codes = {"A": b"\x01" * 20, "B": b"\x02",
                 "Z": b"\x01" * 20 + b"\x02"}
        c = cfg(codes=codes, accepts=("ok",),
                transitions=[["s", "A", "q"], ["q", "B", "ok"], ["s", "Z", "ok"]])
        report = audit(c)
        self.assertFalse(report.ok)
        self.assertEqual(report.conflicts[0].body, b"\x01" * 20 + b"\x02")

    def test_incomplete_audit_cannot_pass(self):
        c = cfg(codes={"A": b"\x01", "B": b"\x02"},
                transitions=[["s", "A", "ok"], ["s", "B", "ok"]])
        with self.assertRaises(AuditIncomplete):
            audit(c, max_product_states=1)


def _bodies(c, maxlen):
    letters = sorted({b for code in c.codes.values() for b in code})
    for n in range(1, maxlen + 1):
        for tup in itertools.product(letters, repeat=n):
            yield bytes(tup)


def _any_ambiguous(c, maxlen):
    return any(len(walk(c, body, max_matches=2).matches) >= 2
               for body in _bodies(c, maxlen))


# -- registry ---------------------------------------------------------------


class RegistryTests(unittest.TestCase):
    def base(self, version="v1", extra=b"\x03"):
        return cfg(version=version, codes={"A": b"\x01", "B": extra},
                   transitions=[["s", "A", "ok"], ["s", "B", "ok"]])

    def test_duplicate_version_cannot_overwrite(self):
        reg = Registry()
        reg.register(self.base())
        with self.assertRaises(VersionConflict):
            reg.register(self.base(extra=b"\x04"))
        self.assertEqual(reg.get("v1").codes["B"], b"\x03")

    def test_rejected_config_does_not_disturb_old(self):
        reg = Registry()
        reg.register(self.base())
        bad = cfg(version="v2", codes={"A": b"\x0a", "B": b"\x0a\x0b", "C": b"\x0b"},
                  transitions=[["s", "A", "x"], ["x", "C", "ok"], ["s", "B", "ok"]])
        with self.assertRaises(ConfigRejected) as ctx:
            reg.register(bad)
        self.assertFalse(ctx.exception.report.ok)
        self.assertNotIn("v2", reg)
        self.assertEqual(reg.get("v1").codes["B"], b"\x03")
        self.assertTrue(reg.rejections)

    def test_wire_collision_rejected(self):
        reg = Registry()
        reg.register(self.base(version="v1").__class__(
            **{**self.base(version="v1").__dict__, "wire": 7}))
        other = self.base(version="v2")
        other.wire = 7
        with self.assertRaises(VersionConflict):
            reg.register(other)


# -- receiver ---------------------------------------------------------------


def approved_registry():
    reg = Registry()
    reg.register(CodeConfig.from_obj({
        "version": "v1", "wire": 1,
        "codes": {"A": "0a", "B": "0b", "C": "0c"},
        "flow": {"start": "s", "accepts": ["ok"], "transitions": [
            ["s", "A", "s"], ["s", "B", "ok"], ["ok", "C", "ok"]]},
    }))
    return reg


class ReceiverTests(unittest.TestCase):
    def test_basic_accept(self):
        reg = approved_registry()
        frame = encode_frame(1, bytes.fromhex("0a0b0c"))
        events = feed_chunks(Receiver(reg), [frame])
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev.kind, "frame_accepted")
        self.assertEqual([a.name for a in ev.actions], ["A", "B", "C"])
        self.assertEqual([a.span for a in ev.actions], [(0, 1), (1, 2), (2, 3)])

    def test_any_chunk_boundary(self):
        reg = approved_registry()
        frames = (encode_frame(1, bytes.fromhex("0a0b"))
                  + encode_frame(1, bytes.fromhex("0a0a0b0c")))
        expected = feed_chunks(Receiver(reg), [frames])
        for size in range(1, len(frames) + 1):
            got = feed_chunks(Receiver(reg), [frames[i:i + size]
                                              for i in range(0, len(frames), size)])
            self.assertEqual([e.to_json() for e in got],
                             [e.to_json() for e in expected], msg=f"chunk={size}")

    def test_body_may_contain_magic_and_arbitrary_bytes(self):
        reg = approved_registry()
        c = reg.get("v1")
        # Build a body containing 0xA5 0x5C and 0x00 through free action codes.
        c2 = CodeConfig.from_obj({
            "version": "v2", "wire": 2,
            "codes": {"X": "a55c00ff"},
            "flow": {"start": "s", "accepts": ["ok"],
                     "transitions": [["s", "X", "ok"]]}})
        reg.register(c2)
        body = bytes.fromhex("a55c00ff")
        events = feed_chunks(Receiver(reg), [encode_frame(2, body)])
        self.assertEqual(events[0].kind, "frame_accepted")
        self.assertEqual(events[0].body_hex, "a55c00ff")

    def test_unknown_version_rejected_but_frame_consumed(self):
        reg = approved_registry()
        good = encode_frame(1, bytes.fromhex("0a0b"))
        stream = encode_frame(9, b"\x00\x01") + good
        events = feed_chunks(Receiver(reg), [stream])
        self.assertEqual([e.kind for e in events],
                         ["frame_rejected", "frame_accepted"])
        self.assertEqual(events[0].reason, "unknown_version")
        self.assertEqual(events[1].body_hex, "0a0b")

    def test_no_legal_sequence_gives_no_partial(self):
        reg = approved_registry()
        events = feed_chunks(Receiver(reg), [encode_frame(1, bytes.fromhex("0b0a"))])
        self.assertEqual(events[0].kind, "frame_rejected")
        self.assertEqual(events[0].reason, "no_legal_sequence")
        self.assertFalse(hasattr(events[0], "actions"))

    def test_crc_mismatch(self):
        reg = approved_registry()
        frame = bytearray(encode_frame(1, bytes.fromhex("0a0b")))
        frame[-1] ^= 0xFF
        events = feed_chunks(Receiver(reg), [bytes(frame)])
        self.assertEqual(events[0].reason, "crc_mismatch")

    def test_bad_frame_does_not_block_following(self):
        reg = approved_registry()
        bad = encode_frame(9, b"\x00")  # unknown version
        good = encode_frame(1, bytes.fromhex("0a0b"))
        events = feed_chunks(Receiver(reg), [b"\x99\x88" + bad + b"junk" + good])
        kinds = [e.kind for e in events]
        self.assertIn("frame_accepted", kinds)
        self.assertEqual(events[-1].body_hex, "0a0b")

    def test_over_limit_frame_skipped_with_known_boundary(self):
        reg = approved_registry()
        big = encode_frame(1, b"\x0a" * 20)
        good = encode_frame(1, bytes.fromhex("0a0b"))
        r = Receiver(reg, max_body_len=10)
        events = feed_chunks(r, [big + good])
        self.assertEqual(events[0].reason, "body_too_large")
        self.assertTrue(any(e.kind == "frame_accepted" and e.body_hex == "0a0b"
                            for e in events))

    def test_truncation_is_separate(self):
        reg = approved_registry()
        frame = encode_frame(1, bytes.fromhex("0a0b"))
        events = feed_chunks(Receiver(reg), [frame[:-1]])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].kind, "truncated")
        self.assertEqual(events[0].pending_bytes, len(frame) - 1)

    def test_trailing_magic_is_truncation_not_noise(self):
        reg = approved_registry()
        events = feed_chunks(Receiver(reg), [b"\x00\xa5"])
        self.assertEqual(events[0].kind, "noise")
        self.assertEqual(events[1].kind, "truncated")

    def test_nonzero_frame_offsets(self):
        reg = approved_registry()
        stream = b"\x00\x01" + encode_frame(1, bytes.fromhex("0a0b"))
        events = feed_chunks(Receiver(reg), [stream])
        accepted = [e for e in events if e.kind == "frame_accepted"][0]
        self.assertEqual(accepted.frame_offset, 2)

    def test_approved_version_reads_same_after_rejected_update(self):
        reg = approved_registry()
        before = feed_chunks(Receiver(reg), [encode_frame(1, bytes.fromhex("0a0b"))])
        bad = cfg(version="v2", wire=2,
                  codes={"A": b"\x0a", "B": b"\x0a\x0b", "C": b"\x0b"},
                  transitions=[["s", "A", "x"], ["x", "C", "ok"], ["s", "B", "ok"]])
        with self.assertRaises(ConfigRejected):
            reg.register(bad)
        after = feed_chunks(Receiver(reg), [encode_frame(1, bytes.fromhex("0a0b"))])
        self.assertEqual([e.to_json() for e in before], [e.to_json() for e in after])


# -- CLI --------------------------------------------------------------------


class CliTests(unittest.TestCase):
    def run_cli(self, *args, stdin=None):
        bootstrap = ("import sys; sys.path.insert(0, %r); "
                     "from scanflow.cli import main; sys.exit(main(sys.argv[1:]))"
                     % str(ROOT))
        return subprocess.run([sys.executable, "-I", "-c", bootstrap, *args],
                              input=stdin, capture_output=True, cwd=str(ROOT))

    def test_audit_exit_codes(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp) / "good.json"
            good.write_text(json.dumps({
                "version": "g", "wire": 1, "codes": {"A": "0a", "B": "0b"},
                "flow": {"start": "s", "accepts": ["ok"],
                         "transitions": [["s", "A", "ok"], ["s", "B", "ok"]]}}))
            bad = Path(tmp) / "bad.json"
            bad.write_text(json.dumps({
                "version": "b", "wire": 2,
                "codes": {"A": "0a", "B": "0a0b", "C": "0b"},
                "flow": {"start": "s", "accepts": ["ok"],
                         "transitions": [["s", "A", "x"], ["x", "C", "ok"],
                                         ["s", "B", "ok"]]}}))
            self.assertEqual(self.run_cli("audit", str(good)).returncode, 0)
            result = self.run_cli("audit", str(bad), "--json")
            self.assertEqual(result.returncode, 3)
            self.assertIn(b"0a0b", result.stdout)


if __name__ == "__main__":
    unittest.main()


class AdditionalEdgeTests(unittest.TestCase):
    def test_accepting_start_still_requires_nonempty(self):
        c = cfg(codes={"A": b"\x01"}, start="s", accepts=("s",),
                transitions=[["s", "A", "s"]])
        self.assertFalse(walk(c, b"").accepted)
        self.assertTrue(walk(c, b"\x01").accepted)
        self.assertTrue(audit(c).ok)

    def test_three_way_ambiguity_is_reported(self):
        c = cfg(codes={"X": b"\x01\x02", "Y": b"\x01", "Z": b"\x02"},
                transitions=[["s", "X", "ok"], ["s", "Y", "m"], ["m", "Z", "ok"]])
        report = audit(c)
        self.assertFalse(report.ok)
        self.assertEqual(report.conflicts[0].body, b"\x01\x02")
        seqs = sorted(report.conflicts[0].sequences)
        self.assertIn(["X"], seqs)
        self.assertIn(["Y", "Z"], seqs)

    def test_audit_and_decoder_agree_on_random_bodies(self):
        c = cfg(codes={"A": b"\x01", "B": b"\x01\x02", "C": b"\x02", "D": b"\x03"},
                transitions=[["s", "A", "m"], ["s", "B", "ok"], ["s", "D", "m"],
                             ["m", "C", "ok"], ["m", "A", "m"]])
        rng = random.Random(7)
        for _ in range(500):
            body = bytes(rng.choice([1, 2, 3, 4]) for _ in range(rng.randrange(0, 8)))
            result = walk(c, body, max_matches=2)
            self.assertLessEqual(len(result.matches), 2)

    def test_receiver_fuzz_chunking_equivalence(self):
        reg = approved_registry()
        rng = random.Random(99)
        frames = []
        for _ in range(12):
            version = rng.choice([1, 9])
            body = bytes(rng.choice([0x0A, 0x0B, 0x0C, 0xA5, 0x5C])
                         for _ in range(rng.randrange(0, 6)))
            frames.append(encode_frame(version, body))
        stream = b"\x00".join(frames)
        baseline = feed_chunks(Receiver(reg), [stream])
        for _ in range(30):
            cuts = sorted(rng.sample(range(1, len(stream)), min(5, len(stream) - 1)))
            chunks = [stream[a:b] for a, b in zip([0] + cuts, cuts + [len(stream)])]
            got = feed_chunks(Receiver(reg), chunks)
            self.assertEqual([e.to_json() for e in got],
                             [e.to_json() for e in baseline])
