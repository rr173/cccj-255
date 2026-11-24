"""Exact, bounded exploration of the scanner flow against a body byte string.

The walk is a path search over ``(flow_state, byte_position)`` nodes.  Positions
strictly increase (every code is non-empty), so the graph is a DAG.  We first
discover the reachable nodes, then count accepting continuations bottom-up with a
hard cap.  ``count >= 2`` therefore means, exactly, that two distinct legal action
sequences spell the same body -- not a heuristic "two paths happened to start
alike".  ``count == 0`` means no legal complete walk exists.

Distinct paths in this graph are in one-to-one correspondence with distinct action
sequences: codes are unique per action and have fixed lengths, so a sequence fixes
its token boundaries and hence its path, and a path fixes its actions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .config import CodeConfig

Node = Tuple[str, int]


@dataclass
class Match:
    """One concrete, complete action walk over a body."""

    actions: List[str]
    states: List[str]        # states[i] is the state *before* actions[i]
    spans: List[Tuple[int, int]]  # half-open body byte span of each action
    body: bytes = b""

    @property
    def end_state(self) -> str:
        return self.states[-1]

    def full_states(self) -> List[str]:
        """start state, state after each action (len(actions)+1 entries)."""
        return list(self.states) + [self.end_state]


@dataclass
class Walk:
    matches: List[Match]
    furthest_pos: int = 0
    furthest_states: List[str] = None  # type: ignore[assignment]
    total_matches_capped: int = 0

    def __post_init__(self) -> None:
        if self.furthest_states is None:
            self.furthest_states = []

    @property
    def accepted(self) -> bool:
        return bool(self.matches)


def _positive(value: Optional[int], name: str) -> Optional[int]:
    if value is None:
        return None
    if not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer or None")
    return value


def _build_graph(config: CodeConfig, body: bytes):
    """Return reachable nodes, outgoing edges and furthest reachable position."""
    n = len(body)
    # Deterministic action order keeps witnesses reproducible.
    actions = sorted(config.codes)
    out: Dict[Node, List[Tuple[Node, str, int]]] = {}
    nodes = set()
    start = (config.start, 0)
    nodes.add(start)
    stack = [start]
    furthest = 0
    while stack:
        node = stack.pop()
        state, pos = node
        if pos > furthest:
            furthest = pos
        edges: List[Tuple[Node, str, int]] = []
        for action in actions:
            nxt = config.transitions.get((state, action))
            if nxt is None:
                continue
            code = config.codes[action]
            end = pos + len(code)
            if end <= n and body.startswith(code, pos):
                child = (nxt, end)
                edges.append((child, action, pos))
                if child not in nodes:
                    nodes.add(child)
                    stack.append(child)
        out[node] = edges
    return nodes, out, furthest


def walk(config: CodeConfig, body: bytes, *, max_matches: int = 1) -> Walk:
    """Explore legal walks of *body* from the configured start state.

    ``max_matches`` caps how many complete matches are materialised; the internal
    counting cap is the same, so ``accepted`` is exact and a returned list of
    length 2 is an exact proof of ambiguity.
    """
    cap = _positive(max_matches, "max_matches")
    assert cap is not None
    n = len(body)
    nodes, out, furthest = _build_graph(config, body)

    # Bottom-up counting on the position DAG.  count[node] = number of complete
    # accepting walks from node onward, capped at `cap`.
    count: Dict[Node, int] = {}
    for state, pos in sorted(nodes, key=lambda np: -np[1]):
        node = (state, pos)
        if pos == n:
            # A sequence must be non-empty: the zero-byte body at the start
            # node is not an accepted action sequence even if start accepts.
            count[node] = 1 if (pos > 0 and state in config.accepts) else 0
            continue
        total = 0
        for child, _action, _start in out.get(node, ()):
            total += count.get(child, 0)
            if total >= cap:
                total = cap
                break
        count[node] = total

    total_from_start = count.get((config.start, 0), 0)
    if total_from_start == 0:
        # No complete walk.  Report the furthest offset any prefix reached, for
        # a diagnostic only -- it never turns a rejection into an acceptance.
        fstates = sorted({s for (s, p) in nodes if p == furthest})
        return Walk([], furthest, fstates, 0)

    # Materialise up to `cap` distinct matches iteratively (no recursion depth
    # dependency on body length).
    matches: List[Match] = []
    frames: List[Tuple[Node, List[Tuple[Node, str, int]], int]] = [
        ((config.start, 0), out.get((config.start, 0), []), 0)
    ]
    path_actions: List[str] = []
    path_starts: List[int] = []
    while frames:
        node, edges, idx = frames[-1]
        state, pos = node
        if pos == n and pos > 0 and state in config.accepts:
            actions = list(path_actions)
            spans = [(path_starts[i], path_starts[i] + len(config.codes[actions[i]]))
                     for i in range(len(actions))]
            states: List[str] = [config.start]
            for action in actions:
                states.append(config.transitions[(states[-1], action)])
            matches.append(Match(actions, states[:-1], spans, body))
            if len(matches) >= cap:
                break
            frames.pop()
            if frames:
                path_actions.pop()
                path_starts.pop()
            continue
        if idx >= len(edges):
            frames.pop()
            if frames:
                path_actions.pop()
                path_starts.pop()
            continue
        frames[-1] = (node, edges, idx + 1)
        child, action, start = edges[idx]
        if count.get(child, 0) <= 0:
            continue
        frames.append((child, out.get(child, []), 0))
        path_actions.append(action)
        path_starts.append(start)

    return Walk(matches, furthest, [], total_from_start)


def decodes(config: CodeConfig, body: bytes) -> bool:
    return walk(config, body, max_matches=1).accepted


def ambiguous(config: CodeConfig, body: bytes) -> bool:
    """True iff *body* has two or more distinct legal action sequences."""
    return len(walk(config, body, max_matches=2).matches) >= 2
