"""Offline release audit: does a configuration ever admit an ambiguous body?

A *conflict* is a non-empty body that has two distinct complete legal action
sequences under one configuration.  Shared code prefixes (``0a`` vs ``0a0b``) are
not by themselves a conflict; only an actually accepted, actually ambiguous body is.

Method
------
Each action code is spliced into a byte-level NFA that remembers the flow state
and the position inside the current code::

    (in, q) --c[0]--> (mid,q,a,1) --c[1]--> ... --c[-1]--> (in, q')

Accepting states are ``(in, q)`` with ``q`` in the flow's accept set.  A byte string
has a legal action sequence exactly when this NFA accepts it, and distinct
accepting runs are in bijection with distinct action sequences (codes are unique
per action and have fixed lengths).

The product automaton ``(u, v, diverged)`` reads one byte at a time from both
copies.  ``diverged`` latches when the two runs ever take different edges; a
product state with both components accepting and ``diverged`` set is exactly a
witness of two different legal sequences spelling the same bytes.  Breadth-first
search over this finite product therefore *decides* the question and returns a
shortest witness.  There is no "try bodies up to length N" step, so the audit can
never be passed merely because a fixed probe length happened to be clean.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from .config import CodeConfig

BState = Tuple  # ('in', q) or ('mid', q, action, consumed)
Edge = Tuple[BState, Optional[str]]  # (next state, action started at this byte)


class AuditIncomplete(RuntimeError):
    """The product search was stopped by an explicit safety bound.

    Callers must treat this as a refusal to release, never as success.
    """


@dataclass
class Conflict:
    body: bytes
    sequences: List[List[str]]
    spans: List[List[Tuple[int, int]]]
    state_traces: List[List[str]]

    def to_json(self) -> dict:
        return {
            "body_hex": self.body.hex(),
            "body_len": len(self.body),
            "sequences": self.sequences,
            "spans": [[list(span) for span in side] for side in self.spans],
            "state_traces": self.state_traces,
        }


@dataclass
class AuditReport:
    version: str
    conflicts: List[Conflict]
    nfa_states: int
    letters: int
    product_states: int

    @property
    def ok(self) -> bool:
        return not self.conflicts

    def to_json(self) -> dict:
        return {
            "version": self.version,
            "ok": self.ok,
            "conflicts": [c.to_json() for c in self.conflicts],
            "stats": {
                "nfa_states": self.nfa_states,
                "alphabet_bytes": self.letters,
                "product_states": self.product_states,
            },
        }


def build_byte_nfa(config: CodeConfig):
    trans: Dict[BState, Dict[int, List[Edge]]] = {}
    actions = sorted(config.codes)

    def add(src: BState, byte: int, dst: BState, started: Optional[str]) -> None:
        trans.setdefault(src, {}).setdefault(byte, []).append((dst, started))

    for q in sorted(config.states):
        for action in actions:
            dst = config.transitions.get((q, action))
            if dst is None:
                continue
            code = config.codes[action]
            if len(code) == 1:
                add(("in", q), code[0], ("in", dst), action)
                continue
            add(("in", q), code[0], ("mid", q, action, 1), action)
            for consumed in range(1, len(code) - 1):
                add(("mid", q, action, consumed), code[consumed],
                    ("mid", q, action, consumed + 1), None)
            add(("mid", q, action, len(code) - 1), code[-1], ("in", dst), None)

    accepts = {("in", q) for q in config.accepts}
    letters = sorted({b for edges in trans.values() for b in edges})
    return trans, accepts, letters


def _reconstruct(config: CodeConfig, trans, accepts, parent, goal) -> Conflict:
    steps: List[Tuple[int, Edge, Edge]] = []
    node = goal
    while node in parent:
        prev, byte, e1, e2 = parent[node]
        steps.append((byte, e1, e2))
        node = prev
    steps.reverse()

    body = bytes(step[0] for step in steps)
    sequences: List[List[str]] = []
    spans: List[List[Tuple[int, int]]] = []
    traces: List[List[str]] = []

    for which in (1, 2):
        cur: BState = ("in", config.start)
        pos = 0
        actions: List[str] = []
        starts: List[int] = []
        for byte, e1, e2 in steps:
            edge = e1 if which == 1 else e2
            if edge not in trans.get(cur, {}).get(byte, ()):
                raise AssertionError("product witness does not replay")
            nxt, started = edge
            if started is not None:
                actions.append(started)
                starts.append(pos)
            cur = nxt
            pos += 1
        if not actions or cur not in accepts:
            raise AssertionError("product witness does not end accepting")
        trace: List[str] = [config.start]
        for action in actions:
            trace.append(config.transitions[(trace[-1], action)])
        if trace[-1] not in config.accepts:
            raise AssertionError("witness state trace does not end accepting")
        side_spans = [(start, start + len(config.codes[a]))
                      for a, start in zip(actions, starts)]
        if side_spans[-1][1] != len(body):
            raise AssertionError("witness span does not cover the body")
        sequences.append(actions)
        spans.append(side_spans)
        traces.append(trace)

    if sequences[0] == sequences[1]:
        raise AssertionError("product witness is not actually ambiguous")
    return Conflict(body=body, sequences=sequences, spans=spans,
                    state_traces=traces)


def audit(config: CodeConfig, *,
          max_witnesses: int = 8,
          max_product_states: Optional[int] = None) -> AuditReport:
    """Decide whether *config* has any release conflict.

    ``max_product_states`` is a fail-closed guard for pathological sizes: if it is
    exceeded, :class:`AuditIncomplete` is raised and the configuration must not be
    released.  The default ``None`` explores the whole finite product.
    """
    trans, accepts, letters = build_byte_nfa(config)
    start: BState = ("in", config.start)

    start_node = (start, start, False)
    parent: Dict[tuple, tuple] = {}
    depth: Dict[tuple, int] = {start_node: 0}
    queue = deque([start_node])
    product_states = 1

    goals: List[tuple] = []
    found_depth: Optional[int] = None
    while queue:
        node = queue.popleft()
        d = depth[node]
        if found_depth is not None and d > found_depth:
            break
        u, v, diverged = node
        is_goal = d > 0 and diverged and u in accepts and v in accepts
        if is_goal:
            goals.append(node)
            if found_depth is None:
                found_depth = d
            if len(goals) >= max_witnesses:
                break
            # Do not expand below the shortest witness level.
            continue
        if found_depth is not None:
            continue
        u_edges = trans.get(u, {})
        v_edges = trans.get(v, {})
        for byte in sorted(set(u_edges) | set(v_edges)):
            for e1 in u_edges.get(byte, ()):
                for e2 in v_edges.get(byte, ()):
                    ndiv = diverged or (u != v) or (e1 != e2)
                    child = (e1[0], e2[0], ndiv)
                    if child not in depth:
                        depth[child] = d + 1
                        parent[child] = (node, byte, e1, e2)
                        queue.append(child)
                        product_states += 1
                        if max_product_states is not None and \
                                product_states > max_product_states:
                            raise AuditIncomplete(
                                f"product exploration exceeded "
                                f"{max_product_states} states; refusing release"
                            )

    conflicts: List[Conflict] = []
    seen = set()
    for goal in goals:
        conflict = _reconstruct(config, trans, accepts, parent, goal)
        key = (conflict.body, tuple(conflict.sequences[0]))
        if key in seen:
            continue
        seen.add(key)
        conflicts.append(conflict)
        if len(conflicts) >= max_witnesses:
            break

    return AuditReport(
        version=config.version,
        conflicts=conflicts,
        nfa_states=len(trans),
        letters=len(letters),
        product_states=product_states,
    )

