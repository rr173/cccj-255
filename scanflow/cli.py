"""Command-line entry points.

    python3 -m scanflow.cli audit  CONFIG.json [--witnesses K] [--json]
    python3 -m scanflow.cli audit-dir CONFIG_DIR [--json]
    python3 -m scanflow.cli receive --config CONFIG.json [--max-body N] \
                                     [--chunks N] [--json] < stream.bin

``audit`` exits 0 when the configuration is releasable, 3 when a release conflict
is found, and 2 on a malformed configuration or an incomplete audit.  ``receive``
reads the whole byte stream, feeds it to the streaming receiver in chunks of the
given size, and prints one JSON line per event.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from .audit import AuditIncomplete, audit
from .config import CodeConfig, ConfigError
from .receiver import DEFAULT_MAX_BODY, Receiver
from .registry import ConfigRejected, Registry, VersionConflict, load_registry_dir


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
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
