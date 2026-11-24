"""Streaming receiver for the outer frame format.

Frame format (this is the "simple frame format" the programme adopts; it is also
written down in ``docs/frame-format.md``)::

    offset  size  field
    0       2     magic           0xA5 0x5C
    2       1     version byte    approved configuration version (unsigned)
    3       2     body length     big-endian unsigned 16-bit, N
    5       N     body            arbitrary bytes, may contain anything
    5+N     2     CRC-16/CCITT-FALSE over bytes [2, 5+N)
                                 poly 0x1021, init 0xFFFF, refin/refout false,
                                 xorout 0x0000

A frame is complete only when all ``N + 2`` trailing bytes have arrived.  The
length field is the sole authority for where a frame ends, so a frame with an
otherwise bad payload, unknown version or over-limit length still has a *known*
boundary: it is discarded whole and scanning resumes at the next magic.  The
receiver never emits a partial action list for any frame it refuses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple, Union

from .config import CodeConfig
from .decoder import walk
from .registry import Registry

MAGIC = b"\xa5\x5c"
HEADER_SIZE = 5
CRC_SIZE = 2
DEFAULT_MAX_BODY = 1 << 16  # one 64 KiB frame body


def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


# -- events ----------------------------------------------------------------


@dataclass
class ActionOut:
    name: str
    code_hex: str
    span: Tuple[int, int]

    def to_json(self) -> dict:
        return {"name": self.name, "code_hex": self.code_hex,
                "span": list(self.span)}


@dataclass
class FrameAccepted:
    frame_offset: int
    version: int
    version_label: str
    body_len: int
    body_hex: str
    actions: List[ActionOut]

    kind = "frame_accepted"

    def to_json(self) -> dict:
        return {
            "kind": self.kind,
            "frame_offset": self.frame_offset,
            "version": self.version,
            "version_label": self.version_label,
            "body_len": self.body_len,
            "body_hex": self.body_hex,
            "actions": [a.to_json() for a in self.actions],
        }


@dataclass
class FrameRejected:
    frame_offset: int
    version: Optional[int]
    reason: str
    detail: str = ""
    body_len: Optional[int] = None
    body_hex: Optional[str] = None
    furthest_pos: Optional[int] = None
    furthest_states: List[str] = field(default_factory=list)

    kind = "frame_rejected"

    def to_json(self) -> dict:
        out = {
            "kind": self.kind,
            "frame_offset": self.frame_offset,
            "version": self.version,
            "reason": self.reason,
            "detail": self.detail,
        }
        if self.body_len is not None:
            out["body_len"] = self.body_len
        if self.body_hex is not None:
            out["body_hex"] = self.body_hex
        if self.furthest_pos is not None:
            out["furthest_pos"] = self.furthest_pos
            out["furthest_states"] = self.furthest_states
        return out


@dataclass
class Noise:
    offset: int
    length: int
    prefix_hex: str

    kind = "noise"

    def to_json(self) -> dict:
        return {"kind": self.kind, "offset": self.offset,
                "length": self.length, "prefix_hex": self.prefix_hex}


@dataclass
class Truncated:
    offset: int
    pending_bytes: int
    pending_hex: str
    in_progress_hex: Optional[str] = None

    kind = "truncated"

    def to_json(self) -> dict:
        out = {"kind": self.kind, "offset": self.offset,
               "pending_bytes": self.pending_bytes,
               "pending_hex": self.pending_hex}
        if self.in_progress_hex is not None:
            out["in_progress_hex"] = self.in_progress_hex
        return out


Event = Union[FrameAccepted, FrameRejected, Noise, Truncated]


# -- receiver --------------------------------------------------------------


class Receiver:
    def __init__(self, registry: Registry,
                 max_body_len: int = DEFAULT_MAX_BODY) -> None:
        if max_body_len < 0:
            raise ValueError("max_body_len must be non-negative")
        self.registry = registry
        self.max_body_len = max_body_len
        self._pending = bytearray()
        # Absolute stream offset of pending[0].
        self._pending_abs = 0
        # None => hunting for magic; otherwise bytes still to skip to reach the
        # next frame boundary.
        self._skip = 0
        self._skipping_from: Optional[int] = None
        self._finished = False

    # -- public API ---------------------------------------------------------

    def feed(self, data: bytes) -> List[Event]:
        if self._finished:
            raise RuntimeError("feed() called after finish()")
        self._pending.extend(data)
        return self._parse()

    def finish(self) -> List[Event]:
        if self._finished:
            return []
        self._finished = True
        events = self._parse(final=True)
        if self._pending:
            offset = self._pending_abs
            in_progress = None
            if self._skipping_from is not None:
                in_progress = f"skipped-frame@{self._skipping_from}"
            events.append(Truncated(
                offset=offset,
                pending_bytes=len(self._pending),
                pending_hex=bytes(self._pending[:64]).hex(),
                in_progress_hex=in_progress,
            ))
            self._pending.clear()
            self._pending_abs += 0  # offset already represents the buffer start
        return events

    # -- internals ----------------------------------------------------------

    def _discard(self, count: int) -> None:
        del self._pending[:count]
        self._pending_abs += count

    def _parse(self, final: bool = False) -> List[Event]:
        events: List[Event] = []
        while True:
            if self._skip:
                take = min(self._skip, len(self._pending))
                self._discard(take)
                self._skip -= take
                if self._skip:
                    return events  # need more bytes
                self._skipping_from = None
                continue

            # Hunting: locate magic.
            idx = self._pending.find(MAGIC)
            if idx < 0:
                # Emit noise for anything that cannot be part of a magic prefix.
                keep = len(MAGIC) - 1
                cut = len(self._pending) - keep
                if cut > 0:
                    events.append(self._noise(cut))
                    self._discard(cut)
                return events
            if idx > 0:
                events.append(self._noise(idx))
                self._discard(idx)
            # Magic is at the front, or we still need bytes after it.
            if len(self._pending) < HEADER_SIZE:
                return events
            version = self._pending[2]
            body_len = int.from_bytes(self._pending[3:5], "big")

            if body_len > self.max_body_len:
                # Explicit, documented limit.  Boundary is still known from the
                # length field, so skip body + CRC and keep scanning.
                frame_offset = self._pending_abs
                self._discard(HEADER_SIZE)
                self._skip = body_len + CRC_SIZE
                self._skipping_from = frame_offset
                events.append(FrameRejected(
                    frame_offset=frame_offset,
                    version=version,
                    reason="body_too_large",
                    detail=(f"frame declares {body_len} body bytes; receiver "
                            f"limit is {self.max_body_len}"),
                    body_len=body_len,
                ))
                if self._skip == 0:
                    self._skip = 0
                    self._skipping_from = None
                continue

            total = HEADER_SIZE + body_len + CRC_SIZE
            if len(self._pending) < total:
                if final:
                    # finish() will report the truncation with the pending bytes.
                    return events
                return events

            frame = bytes(self._pending[:total])
            self._discard(total)
            events.append(self._resolve(frame, body_len))
        return events

    def _noise(self, count: int) -> Noise:
        offset = self._pending_abs
        prefix = bytes(self._pending[:min(count, 16)]).hex()
        return Noise(offset=offset, length=count, prefix_hex=prefix)

    def _resolve(self, frame: bytes, body_len: int) -> Event:
        frame_offset = self._pending_abs - len(frame)
        version = frame[2]
        body = frame[HEADER_SIZE:HEADER_SIZE + body_len]
        want_crc = int.from_bytes(
            frame[HEADER_SIZE + body_len:HEADER_SIZE + body_len + CRC_SIZE], "big")
        got_crc = crc16_ccitt_false(frame[2:HEADER_SIZE + body_len])

        if got_crc != want_crc:
            return FrameRejected(
                frame_offset=frame_offset, version=version, reason="crc_mismatch",
                detail=f"computed {got_crc:#06x}, frame carries {want_crc:#06x}",
                body_len=body_len, body_hex=body.hex(),
            )

        config = self.registry.get_wire(version)
        if config is None:
            return FrameRejected(
                frame_offset=frame_offset, version=version,
                reason="unknown_version",
                detail=f"version byte {version} has no approved configuration",
                body_len=body_len, body_hex=body.hex(),
            )

        result = walk(config, body, max_matches=2)
        if not result.accepted:
            return FrameRejected(
                frame_offset=frame_offset, version=version,
                reason="no_legal_sequence",
                detail=(f"no complete legal action sequence from state "
                        f"{config.start!r} to an accept state"),
                body_len=body_len, body_hex=body.hex(),
                furthest_pos=result.furthest_pos,
                furthest_states=result.furthest_states,
            )
        if len(result.matches) > 1:
            # Cannot happen for an audited configuration; fail closed rather than
            # invent a reading.
            return FrameRejected(
                frame_offset=frame_offset, version=version,
                reason="ambiguous_under_version",
                detail="body has more than one legal sequence; configuration "
                       "should not have been released",
                body_len=body_len, body_hex=body.hex(),
            )

        match = result.matches[0]
        actions = [
            ActionOut(name=name, code_hex=config.codes[name].hex(), span=span)
            for name, span in zip(match.actions, match.spans)
        ]
        return FrameAccepted(
            frame_offset=frame_offset,
            version=version,
            version_label=config.version,
            body_len=body_len,
            body_hex=body.hex(),
            actions=actions,
        )


def feed_chunks(receiver: Receiver, chunks: Sequence[bytes]) -> List[Event]:
    events: List[Event] = []
    for chunk in chunks:
        events.extend(receiver.feed(chunk))
    events.extend(receiver.finish())
    return events


def encode_frame(version: int, body: bytes) -> bytes:
    """Encode one frame; used by the demo CLI and tests."""
    if not 0 <= version <= 0xFF:
        raise ValueError("version byte must be 0..255")
    header = MAGIC + bytes([version]) + len(body).to_bytes(2, "big")
    crc = crc16_ccitt_false(header[2:] + body)
    return header + body + crc.to_bytes(2, "big")
