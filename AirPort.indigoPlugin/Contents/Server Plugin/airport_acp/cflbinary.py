"""CFB0 ("CFL binary plist") encoder/decoder used by AirPort ACP.

Format: b"CFB0" + one packed object + b"END!".
Object markers (high nibble = type, low nibble = info):
  0x00 null (also used as array/dict terminator), 0x08 false, 0x09 true
  0x1n big-endian unsigned int of 2**n bytes
  0x2n big-endian real of 2**n bytes
  0x4n data, n = length (0xF -> length follows as packed int)
  0x70 null-terminated UTF-8 string
  0xA0 array, elements until null
  0xD0 dict, key/value pairs until null key

Ints and reals decode to SizedInt / SizedFloat, which remember their encoded
width, so decode -> encode reproduces the device's original bytes exactly.
Ported from node-acp (MIT, (c) Samuel Elliott).
"""

import struct

HEADER = b"CFB0"
FOOTER = b"END!"
MAX_DEPTH = 32


class CFBError(ValueError):
    pass


class SizedInt(int):
    """int that remembers its encoded width in bytes (1, 2, 4 or 8)."""

    def __new__(cls, value, width=None):
        obj = int.__new__(cls, value)
        obj.width = width
        return obj

    def __repr__(self):
        return int.__repr__(self)


class SizedFloat(float):
    def __new__(cls, value, width=8):
        obj = float.__new__(cls, value)
        obj.width = width
        return obj


# ---------------------------------------------------------------- decoding

def parse(data):
    data = bytes(data)
    if len(data) < len(HEADER) + len(FOOTER) + 1:
        raise CFBError("not enough data")
    if data[:4] != HEADER:
        raise CFBError("bad header magic")
    obj, pos = _unpack(data, 4, 1)
    if data[pos:] != FOOTER:
        raise CFBError("bad footer / trailing data: %r" % data[pos:pos + 16])
    return obj


def _unpack(data, pos, depth):
    if depth > MAX_DEPTH:
        raise CFBError("max depth reached")
    if pos >= len(data):
        raise CFBError("truncated data")
    marker = data[pos]
    pos += 1
    otype, info = marker & 0xF0, marker & 0x0F

    if otype == 0x00:
        if info == 0x00:
            return None, pos
        if info == 0x08:
            return False, pos
        if info == 0x09:
            return True, pos
        raise CFBError("bad null/bool marker 0x%02x" % marker)
    if otype == 0x10:
        width = 2 ** info
        if width not in (1, 2, 4, 8):
            raise CFBError("bad int width %d" % width)
        return SizedInt(int.from_bytes(data[pos:pos + width], "big"), width), pos + width
    if otype == 0x20:
        width = 2 ** info
        if width == 4:
            return SizedFloat(struct.unpack(">f", data[pos:pos + 4])[0], 4), pos + 4
        if width == 8:
            return SizedFloat(struct.unpack(">d", data[pos:pos + 8])[0], 8), pos + 8
        raise CFBError("bad real width %d" % width)
    if otype == 0x40:
        if info == 0x0F:
            count, pos = _unpack(data, pos, depth + 1)
            if not isinstance(count, int) or isinstance(count, bool):
                raise CFBError("data length is not an int")
        else:
            count = info
        if pos + count > len(data):
            raise CFBError("truncated data object")
        return bytes(data[pos:pos + count]), pos + count
    if otype == 0x70:
        end = data.index(b"\x00", pos)
        return data[pos:end].decode("utf-8", "surrogateescape"), end + 1
    if otype == 0xA0:
        items = []
        while True:
            if pos >= len(data):
                raise CFBError("unterminated array")
            if data[pos] == 0x00:
                return items, pos + 1
            item, pos = _unpack(data, pos, depth + 1)
            items.append(item)
    if otype == 0xD0:
        result = {}
        while True:
            if pos >= len(data):
                raise CFBError("unterminated dict")
            if data[pos] == 0x00:
                return result, pos + 1
            key, pos = _unpack(data, pos, depth + 1)
            value, pos = _unpack(data, pos, depth + 1)
            result[key] = value
    raise CFBError("unsupported object type 0x%02x at offset %d" % (otype, pos - 1))


# ---------------------------------------------------------------- encoding

def compose(obj):
    return HEADER + _pack(obj, 1) + FOOTER


def _int_width(value):
    for width in (1, 2, 4, 8):
        if value < 256 ** width:
            return width
    raise CFBError("int too large: %r" % value)


_WIDTH_CODE = {1: 0, 2: 1, 4: 2, 8: 3}


def _pack(obj, depth):
    if depth > MAX_DEPTH:
        raise CFBError("max depth reached")
    if obj is None:
        return b"\x00"
    if obj is True:
        return b"\x09"
    if obj is False:
        return b"\x08"
    if isinstance(obj, float):
        if getattr(obj, "width", 8) == 4:
            return b"\x22" + struct.pack(">f", obj)
        return b"\x23" + struct.pack(">d", obj)
    if isinstance(obj, int):
        if obj < 0:
            raise CFBError("negative ints are not supported: %r" % obj)
        width = getattr(obj, "width", None) or _int_width(obj)
        if obj >= 256 ** width:
            width = _int_width(obj)
        return bytes([0x10 + _WIDTH_CODE[width]]) + int(obj).to_bytes(width, "big")
    if isinstance(obj, (bytes, bytearray)):
        n = len(obj)
        head = bytes([0x40 + n]) if n < 0x0F else b"\x4f" + _pack(n, depth + 1)
        return head + bytes(obj)
    if isinstance(obj, str):
        raw = obj.encode("utf-8", "surrogateescape")
        if b"\x00" in raw:
            raise CFBError("strings may not contain NUL")
        return b"\x70" + raw + b"\x00"
    if isinstance(obj, (list, tuple)):
        return b"\xa0" + b"".join(_pack(i, depth + 1) for i in obj) + b"\x00"
    if isinstance(obj, dict):
        parts = [b"\xd0"]
        for key, value in obj.items():
            parts.append(_pack(key, depth + 1))
            parts.append(_pack(value, depth + 1))
        parts.append(b"\x00")
        return b"".join(parts)
    raise CFBError("unsupported type for CFB encoding: %s" % type(obj).__name__)
