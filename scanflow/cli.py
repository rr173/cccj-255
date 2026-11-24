"""Command-line entry points.

    python3 -m scanflow.cli audit  CONFIG.json [--witnesses K] [--json]
    python3 -m scanflow.cli audit-dir CONFIG_DIR [--json]
    python3 -m scanflow.cli receive --config CONFIG.json [--max-body N] \
                                     [--chunks N] [--json] < stream.bin
    python3 -m scanflow.cli check-compat --current CUR.json \
                                     --candidate CAND.json --history FILE \
                                     [--report OUT.json] [--json]
    python3 -m scanflow.cli check-batch [--config CONFIG.json ...] \
                                     [--config-dir DIR] --plan PLAN.jsonl \
                                     --fragments FRAGMENTS.jsonl \
                                     --stream-total N [--report OUT.json] [--json]

``audit`` exits 0 when the configuration is releasable, 3 when a release conflict
is found, and 2 on a malformed configuration or an incomplete audit.  ``receive``
reads the whole byte stream, feeds it to the streaming receiver in chunks of the
given size, and prints one JSON line per event.

``check-compat`` audits the candidate, then decodes every ``<record-id> <body-hex>``
line of the history under both configurations.  Exit codes: 0 = replaceable,
3 = not replaceable (candidate or records incompatible), 2 = invalid evidence or
evidence too large to check exhaustively (missing/malformed configuration,
candidate audit failure, malformed history line, duplicate id, current-side decode
failure), 1 = the report could not be written.  The report is only replaced after
every record has been validated; see ``docs/compatibility-check.md``.

``check-batch`` reconciles one captured stream (delivered as out-of-order,
possibly duplicated or overlapping retransmission fragments) against a JSONL
plan manifest, interpreting only the contiguous known prefix from offset zero
with the existing frame format.  Exit codes: 0 = batch matches, 3 = evidence
complete but planned and confirmed counts disagree, 4 = evidence incomplete
(confirmed counts are lower bounds only), 2 = invalid evidence (bad
configuration, plan or fragment input, byte conflict between fragments),
1 = the report could not be written.  See ``docs/batch-reconciliation.md``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from .audit import AuditIncomplete, audit
from .batch import BatchError, BatchReportWriteError, reconcile_batch
from .compat import (
    CandidateAuditIncomplete,
    CandidateNotReleasable,
    CompatibilityError,
    ReportWriteError,
    check_compatibility,
)
from .config import CodeConfig, ConfigError
from .receiver import DEFAULT_MAX_BODY, Receiver
from .registry import (
    ConfigRejected,
    Registry,
    RegistryError,
    VersionConflict,
    load_registry,
    load_registry_dir,
)


def _cmd_audit(args: argparse.Namespace) -> int:
    try:
        config = CodeConfig.from_json_text(Path(args.config).read_text(encoding="utf-8"))
    except (ConfigError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        report = audit(config, max_witnesses=args.witnesses)
    except AuditIncomplete as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report.to_json(), indent=2, sort_keys=True))
    else:
        state = "RELEASABLE" if report.ok else "BLOCKED"
        print(f"version {report.version}: {state}")
        for i, conflict in enumerate(report.conflicts, 1):
            print(f"\nconflict {i}: body {conflict.body.hex()} "
                  f"({len(conflict.body)} bytes)")
            for side in range(2):
                print(f"  sequence {side + 1}: {' '.join(conflict.sequences[side])}")
                print(f"    spans:  {conflict.spans[side]}")
                print(f"    states: {' -> '.join(conflict.state_traces[side])}")
    return 0 if report.ok else 3


def _cmd_audit_dir(args: argparse.Namespace) -> int:
    registry = load_registry_dir(Path(args.config_dir),
                                 max_witnesses=args.witnesses)
    if args.json:
        print(json.dumps({
            "approved": [r.to_json() for r in registry.reports()],
            "rejected": registry.rejections,
        }, indent=2, sort_keys=True))
    else:
        print("approved: " + (", ".join(registry.versions()) or "(none)"))
        for entry in registry.rejections:
            src = entry.get("source", "?")
            if entry.get("error"):
                print(f"rejected: {src}: {entry['error']}")
            else:
                print(f"rejected: {src}: {len(entry.get('conflicts', []))} "
                      f"release conflict(s)")
    for entry in registry.rejections:
        if entry.get("conflicts"):
            return 3
        if entry.get("error"):
            return 2
    return 0


def _cmd_receive(args: argparse.Namespace) -> int:
    registry = Registry()
    try:
        config = CodeConfig.from_json_text(Path(args.config).read_text(encoding="utf-8"))
        registry.register(config)
    except (ConfigError, OSError, ConfigRejected, VersionConflict) as exc:
        print(f"error: {exc}", file=sys.stderr)
        if hasattr(exc, "report"):
            print(json.dumps(exc.report.to_json(), indent=2, sort_keys=True),
                  file=sys.stderr)
        return 2

    receiver = Receiver(registry, max_body_len=args.max_body)
    chunk = max(1, args.chunks)
    data = sys.stdin.buffer.read()
    events = []
    for start in range(0, len(data), chunk):
        events.extend(receiver.feed(data[start:start + chunk]))
    events.extend(receiver.finish())

    if args.json:
        for event in events:
            print(json.dumps(event.to_json(), sort_keys=True))
    else:
        for event in events:
            if event.kind == "frame_accepted":
                print(f"[{event.frame_offset}] accepted v{event.version}: "
                      f"{' '.join(a.name for a in event.actions)}")
            else:
                print(f"[{event.to_json().get('frame_offset', event.to_json().get('offset'))}] "
                      f"{event.kind}: {event.to_json()}")
    return 0


def _read_config(path: str) -> CodeConfig:
    return CodeConfig.from_json_text(Path(path).read_text(encoding="utf-8"))


def _cmd_check_compat(args: argparse.Namespace) -> int:
    try:
        current = _read_config(args.current)
        candidate = _read_config(args.candidate)
    except (ConfigError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        summary = check_compatibility(
            current,
            candidate,
            args.history,
            report_path=args.report,
            max_product_states=args.max_product_states,
        )
    except (CandidateNotReleasable, CandidateAuditIncomplete) as exc:
        print(f"error: {exc}", file=sys.stderr)
        if hasattr(exc, "report"):
            print(json.dumps(exc.report.to_json(), indent=2, sort_keys=True),
                  file=sys.stderr)
        return 2
    except ReportWriteError as exc:
        print(f"error: could not write report: {exc}", file=sys.stderr)
        return 1
    except CompatibilityError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: could not write report: {exc}", file=sys.stderr)
        return 1

    if args.json:
        out = summary.to_json()
        out["report"] = None if args.report is None else str(args.report)
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        verdict = "REPLACEABLE" if summary.replaceable else "NOT REPLACEABLE"
        print(f"current {summary.current_version!r} -> candidate "
              f"{summary.candidate_version!r}: {verdict}")
        print(f"records: {summary.total}, compatible: {summary.compatible}, "
              f"incompatible: {summary.incompatible}")
        if not summary.replaceable:
            print("some historical records read differently under the candidate")
        if args.report is not None:
            print(f"report: {args.report}")
    if not summary.replaceable:
        return 3
    return 0


def _cmd_check_batch(args: argparse.Namespace) -> int:
    config_paths = [Path(p) for p in args.config]
    if args.config_dir is not None:
        config_paths.extend(Path(args.config_dir).glob("*.json"))
    if not config_paths:
        print("error: at least one --config or --config-dir is required",
              file=sys.stderr)
        return 2
    try:
        registry = load_registry(config_paths)
    except RegistryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if registry.rejections:
        # Fail closed: the offered configuration set is not fully approved,
        # so the premise "existing audited configurations" does not hold.
        for entry in registry.rejections:
            source = entry.get("source", entry.get("version", "?"))
            detail = entry.get("error") or (
                f"{len(entry.get('conflicts', []))} release conflict(s)")
            print(f"error: configuration not approved: {source}: {detail}",
                  file=sys.stderr)
        return 2
    if args.stream_total < 0:
        print("error: --stream-total must be a non-negative integer",
              file=sys.stderr)
        return 2

    try:
        summary = reconcile_batch(
            registry,
            args.plan,
            args.fragments,
            args.stream_total,
            report_path=args.report,
            max_body_len=args.max_body,
            protected_paths=config_paths,
        )
    except BatchReportWriteError as exc:
        print(f"error: could not write report: {exc}", file=sys.stderr)
        return 1
    except BatchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: could not write report: {exc}", file=sys.stderr)
        return 1

    if args.json:
        out = summary.to_json()
        out["report"] = None if args.report is None else str(args.report)
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        print(f"stream: {summary.received_bytes}/{summary.stream_total} "
              f"bytes received")
        if summary.first_missing_offset is not None:
            print(f"first missing byte: {summary.first_missing_offset}")
        print(f"reception: {summary.frames_accepted} accepted, "
              f"{summary.frames_rejected} rejected, "
              f"{summary.noise_bytes} noise byte(s) in "
              f"{summary.noise_regions} region(s), "
              f"truncated: {str(summary.truncated).lower()}")
        if summary.evidence_complete:
            print(f"rows: {summary.rows} (match {summary.matched}, "
                  f"short {summary.short}, over {summary.over})")
            print(f"batch: {'MATCH' if summary.batch_match else 'MISMATCH'}")
        else:
            print(f"rows: {summary.rows} "
                  f"(confirmed counts are lower bounds)")
            print("batch: NO CONCLUSION (evidence incomplete)")
        if args.report is not None:
            print(f"report: {args.report}")
    if not summary.evidence_complete:
        return 4
    return 0 if summary.batch_match else 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scanflow")
    sub = parser.add_subparsers(dest="command", required=True)

    p_audit = sub.add_parser("audit", help="audit one configuration file")
    p_audit.add_argument("config")
    p_audit.add_argument("--witnesses", type=int, default=8)
    p_audit.add_argument("--json", action="store_true")
    p_audit.set_defaults(func=_cmd_audit)

    p_dir = sub.add_parser("audit-dir", help="audit and load a directory of configs")
    p_dir.add_argument("config_dir")
    p_dir.add_argument("--witnesses", type=int, default=8)
    p_dir.add_argument("--json", action="store_true")
    p_dir.set_defaults(func=_cmd_audit_dir)

    p_recv = sub.add_parser("receive", help="receive frames from stdin")
    p_recv.add_argument("--config", required=True,
                        help="approved configuration JSON for the version used")
    p_recv.add_argument("--max-body", type=int, default=DEFAULT_MAX_BODY)
    p_recv.add_argument("--chunks", type=int, default=4096,
                        help="input split size in bytes (any value is legal)")
    p_recv.add_argument("--json", action="store_true")
    p_recv.set_defaults(func=_cmd_receive)

    p_compat = sub.add_parser(
        "check-compat",
        help="check captured history reads the same under a candidate config")
    p_compat.add_argument("--current", required=True,
                          help="approved configuration currently in use")
    p_compat.add_argument("--candidate", required=True,
                          help="configuration proposed as the replacement")
    p_compat.add_argument("--history", required=True,
                          help="line-oriented file: <record-id> <body-hex>")
    p_compat.add_argument("--report",
                          help="replace this report file atomically on success")
    p_compat.add_argument("--max-product-states", type=int, default=None,
                          help="fail-closed bound for the candidate audit")
    p_compat.add_argument("--json", action="store_true",
                          help="print a JSON summary instead of text")
    p_compat.set_defaults(func=_cmd_check_compat)

    p_batch = sub.add_parser(
        "check-batch",
        help="reconcile planned scans against captured stream fragments")
    p_batch.add_argument("--config", action="append", default=[],
                         help="approved configuration JSON (repeatable)")
    p_batch.add_argument("--config-dir",
                         help="directory of approved configuration JSON files")
    p_batch.add_argument("--plan", required=True,
                         help="plan manifest JSONL: one "
                         '{"wire": N, "actions": [...], "planned": N} per line')
    p_batch.add_argument("--fragments", required=True,
                         help="captured fragments JSONL: one "
                         '{"offset": N, "data_hex": "..."} per line')
    p_batch.add_argument("--stream-total", type=int, required=True,
                         help="declared total byte count of the original stream")
    p_batch.add_argument("--report",
                         help="replace this report file atomically on success")
    p_batch.add_argument("--max-body", type=int, default=DEFAULT_MAX_BODY,
                         help="receiver body-length limit for framed evidence")
    p_batch.add_argument("--json", action="store_true",
                         help="print a JSON summary instead of text")
    p_batch.set_defaults(func=_cmd_check_batch)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
