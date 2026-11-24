# Frame format adopted by this receiver

This is the "simple frame format" required by the receiving station. It is the
sole description; the physical serial layer is out of scope and any byte stream
carrying these frames is accepted.

```
offset  size  field
0       2     magic          fixed 0xA5 0x5C
2       1     version        approved configuration version, 0..255
3       2     body length N  big-endian unsigned 16-bit
5       N     body           arbitrary bytes (may contain 0xA5 0x5C)
5+N     2     CRC-16/CCITT-FALSE over bytes [2, 5+N)
```

CRC parameters: polynomial `0x1021`, initial value `0xFFFF`, no input/output
reflection, no final XOR. A reference implementation is
`scanflow.receiver.crc16_ccitt_false`.

## Framing rules

* The **length field is authoritative**. A frame ends exactly `N + 2` bytes after
  the header. Body bytes, including anything that looks like the magic, are never
  inspected while locating the frame end.
* A frame is complete only when every one of its `N + 2` trailing bytes has
  arrived. Until then the receiver buffers and emits nothing for it.
* A complete frame whose body is bad (CRC, unknown version, no legal action
  sequence, or `N` above the receiver's limit) is **discarded whole**. The next
  frame is sought immediately after its known boundary.
* Bytes between frames that do not start with the magic are reported as `noise`
  and skipped; a trailing partial magic is held until more bytes disambiguate it.
* At end of stream, any buffered bytes are reported **once** as a `truncated`
  event. A frame cut short this way is never reported as `accepted` or as an
  ordinary bad frame; truncation is its own outcome.

## Receiver length limit

The receiver has an explicit `max_body_len` (default 65536, i.e. the largest body
the 16-bit length field can describe). A frame declaring a larger `N` is rejected
as `body_too_large` without being buffered. The audit used to approve
configurations has **no** such limit; it searches for conflicts at every length
that the configuration's finite flow allows.

## Event vocabulary

| kind             | meaning                                                        |
|------------------|----------------------------------------------------------------|
| `frame_accepted` | CRC and version valid, body has exactly one legal walk; carries ordered actions with half-open body byte spans |
| `frame_rejected` | complete frame with a known boundary that is not deliverable   |
| `noise`          | inter-frame bytes skipped                                      |
| `truncated`      | end of stream with buffered, incomplete bytes                  |

A rejected or truncated frame never yields a partial action list.
