"""Configuration model for the action-code decoder.

A configuration is intentionally small and offline-auditable:

* ``version``  -- the terminal configuration version stamped into the outer frame
                  header.  Version strings are non-empty and are never reused.
* ``codes``    -- action name -> non-empty byte code.
* ``flow``     -- finite scanner flow: one start state, a set of accept states,
                  and transitions ``(state, action) -> next_state``.  At most one
                  destination per (state, action); loops are allowed and the same
                  action may appear in several states.

The model never sees the wire framing.  It only answers: "given a body byte string
and a known version, can the body be segmented into a complete, legal action walk,
and if so, how?"  That separation is what lets the audit use unbounded bodies while
the receiver enforces its own explicit length cap.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Sequence, Set, Tuple


class ConfigError(ValueError):
    """Raised when a configuration document is malformed."""


def as_bytes(value: object, what: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        # A JSON string is a sequence of Unicode code points.  A byte code is a
        # sequence of bytes; the only unambiguous textual spelling is hex.
        try:
            return bytes.fromhex(value)
        except ValueError as exc:
            raise ConfigError(f"{what}: string codes must be hex (e.g. '1a0f')") from exc
    raise ConfigError(f"{what}: expected bytes or a hex string")


@dataclass
class CodeConfig:
    version: str
    codes: Dict[str, bytes]
    start: str
    accepts: Set[str]
    transitions: Dict[Tuple[str, str], str]
    # One-byte on-wire version.  Optional for pure offline auditing; mandatory for
    # the receiver, which carries it in the frame header.
    wire: Optional[int] = None
    # Derived for auditing.
    owned: Dict[bytes, str] = field(default_factory=dict)
    states: Set[str] = field(default_factory=set)

    # -- construction -------------------------------------------------------

    @staticmethod
    def from_obj(obj: Mapping[str, object]) -> "CodeConfig":
        if not isinstance(obj, Mapping):
            raise ConfigError("configuration must be a JSON object")

        version = obj.get("version")
        if not isinstance(version, str) or version == "":
            raise ConfigError("version: expected a non-empty string")

        wire = obj.get("wire")
        if wire is not None:
            if not isinstance(wire, int) or isinstance(wire, bool) or not 0 <= wire <= 0xFF:
                raise ConfigError("wire: expected an integer 0..255")

        raw_codes = obj.get("codes")
        if not isinstance(raw_codes, Mapping):
            raise ConfigError("codes: expected an object of name -> byte code")
        codes: Dict[str, bytes] = {}
        owned: Dict[bytes, str] = {}
        for name, raw in raw_codes.items():
            if not isinstance(name, str) or name == "":
                raise ConfigError("codes: action names must be non-empty strings")
            code = as_bytes(raw, f"codes[{name!r}]")
            if not code:
                raise ConfigError(f"codes[{name!r}]: byte code must be non-empty")
            if code in owned:
                raise ConfigError(
                    f"codes: actions {owned[code]!r} and {name!r} share the same byte "
                    f"code {code.hex()} -- a token could not be attributed"
                )
            owned[code] = name
            codes[name] = code
        if not codes:
            raise ConfigError("codes: at least one action is required")

        flow = obj.get("flow")
        if not isinstance(flow, Mapping):
            raise ConfigError("flow: expected an object with start/accepts/transitions")
        start = flow.get("start")
        if not isinstance(start, str) or start == "":
            raise ConfigError("flow.start: expected a non-empty state name")

        raw_accepts = flow.get("accepts")
        if not isinstance(raw_accepts, Sequence) or isinstance(raw_accepts, (str, bytes)):
            raise ConfigError("flow.accepts: expected a list of state names")
        accepts: Set[str] = set()
        for state in raw_accepts:
            if not isinstance(state, str) or state == "":
                raise ConfigError("flow.accepts: state names must be non-empty strings")
            accepts.add(state)

        raw_transitions = flow.get("transitions")
        if not isinstance(raw_transitions, Sequence) or isinstance(raw_transitions, (str, bytes)):
            raise ConfigError("flow.transitions: expected a list")

        transitions: Dict[Tuple[str, str], str] = {}
        states: Set[str] = {start} | set(accepts)
        for index, item in enumerate(raw_transitions):
            if isinstance(item, Mapping):
                src = item.get("state")
                action = item.get("action")
                dst = item.get("next")
            elif isinstance(item, Sequence) and not isinstance(item, (str, bytes)):
                if len(item) != 3:
                    raise ConfigError(
                        f"flow.transitions[{index}]: expected [state, action, next]"
                    )
                src, action, dst = item
            else:
                raise ConfigError(f"flow.transitions[{index}]: expected a list or object")
            if not isinstance(src, str) or src == "":
                raise ConfigError(f"flow.transitions[{index}]: bad state name")
            if not isinstance(action, str):
                raise ConfigError(f"flow.transitions[{index}]: action must be a string")
            if action not in codes:
                raise ConfigError(
                    f"flow.transitions[{index}]: action {action!r} has no code entry"
                )
            if not isinstance(dst, str) or dst == "":
                raise ConfigError(f"flow.transitions[{index}]: bad next state")
            key = (src, action)
            if key in transitions:
                raise ConfigError(
                    f"flow.transitions[{index}]: more than one destination for "
                    f"state {src!r} and action {action!r} "
                    f"({transitions[key]!r} and {dst!r})"
                )
            transitions[key] = dst
            states.add(src)
            states.add(dst)

        return CodeConfig(
            version=version,
            codes=dict(codes),
            start=start,
            accepts=set(accepts),
            transitions=dict(transitions),
            wire=wire,
            owned=dict(owned),
            states=states,
        )

    @staticmethod
    def from_json_text(text: str) -> "CodeConfig":
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"invalid JSON: {exc}") from exc
        return CodeConfig.from_obj(obj)

    # -- helpers ------------------------------------------------------------

    def action_for(self, code: bytes) -> Tuple[str, bytes]:
        """Return the action owning *code*, along with the bytes it consumes."""
        if code in self.owned:
            return self.owned[code], code
        for candidate, name in self.owned.items():
            if code.startswith(candidate):
                return name, candidate
        raise KeyError(code)

    def code_prefix_hits(self) -> int:
        """Number of distinct code-prefix matches -- the decoder's fan-out bound."""
        return len(self.owned)
