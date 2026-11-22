"""ACP message framing (port 5009).

Every message starts with a 128-byte header:
  0   4s  magic "acpp"
  4   i   version (0x00030001)
  8   I   header checksum (adler32 of the header with this field zeroed)
  12  I   body checksum (adler32 of body, 1 if no body)
  16  i   body size (-1 = streamed body, e.g. property elements)
  20  i   flags
  24  i   unused
  28  i   command
  32  i   error code
  36  12s padding
  48  32s key (obfuscated password, or a fixed key / zeros)
  80  48s padding
Property elements: 4s name, I flags (bit 0 = error), I size, then value.
Ported from node-acp (MIT, (c) Samuel Elliott).
"""

import struct
import zlib

MAGIC = b"acpp"
VERSION = 0x00030001
HEADER_SIZE = 128
ELEMENT_HEADER_SIZE = 12
_HEADER = struct.Struct(">4siIIiiiii12s32s48s")
_ELEMENT = struct.Struct(">4sII")

CMD_ECHO = 0x01
CMD_GET_PROPERTY = 0x14
CMD_SET_PROPERTY = 0x15
CMD_PERFORM = 0x16
CMD_MONITOR = 0x18
CMD_RPC = 0x19
CMD_AUTHENTICATE = 0x1A
CMD_GET_FEATURES = 0x1B

ERRORS = {
    -10: "NOT_AVAILABLE",
    -16: "INVALID_KEY",
    -6754: "INCORRECT_PASSWORD",
    -6772: "UNKNOWN_FFFFE58C",
}

_STATIC_KEY = bytes.fromhex("5b6faf5d9d5b0e1351f2da1de7e8d673")


def keystream(length):
    return bytes(((i + 0x55) & 0xFF) ^ _STATIC_KEY[i % len(_STATIC_KEY)] for i in range(length))


def header_key(password):
    """Old-style obfuscated password for the header key field.

    Only used with an empty password (authentication/feature messages); the
    plugin never sends a real password this way, as it is trivially reversible.
    """
    raw = password.encode("utf-8")[:32].ljust(32, b"\x00")
    return bytes(a ^ b for a, b in zip(keystream(32), raw))


ZERO_KEY = bytes(32)


def adler32(data):
    return zlib.adler32(data) & 0xFFFFFFFF


class Header:
    __slots__ = ("version", "body_checksum", "body_size", "flags", "unused",
                 "command", "error_code", "key")

    def __init__(self, command, flags=0, key=ZERO_KEY, body_size=-1,
                 body_checksum=1, error_code=0, version=VERSION, unused=0):
        self.version = version
        self.body_checksum = body_checksum
        self.body_size = body_size
        self.flags = flags
        self.unused = unused
        self.command = command
        self.error_code = error_code
        self.key = key

    def _pack(self, checksum):
        return _HEADER.pack(MAGIC, self.version, checksum, self.body_checksum,
                            self.body_size, self.flags, self.unused, self.command,
                            self.error_code, bytes(12), self.key, bytes(48))

    def pack(self):
        return self._pack(adler32(self._pack(0)))

    @classmethod
    def unpack(cls, raw):
        if len(raw) != HEADER_SIZE:
            raise ValueError("header must be %d bytes" % HEADER_SIZE)
        (magic, version, checksum, body_checksum, body_size, flags, unused,
         command, error_code, pad1, key, pad2) = _HEADER.unpack(raw)
        if magic != MAGIC:
            raise ValueError("bad header magic %r" % magic)
        zeroed = raw[:8] + b"\x00\x00\x00\x00" + raw[12:]
        if adler32(zeroed) != checksum:
            raise ValueError("header checksum mismatch")
        return cls(command, flags, key, body_size, body_checksum, error_code, version, unused)

    @property
    def error_name(self):
        return ERRORS.get(self.error_code, "ERROR_%d" % self.error_code)


def compose(command, flags=0, key=ZERO_KEY, body=None):
    if body is None:
        return Header(command, flags, key, -1, 1).pack()
    body = bytes(body)
    return Header(command, flags, key, len(body), adler32(body)).pack() + body


def pack_element(name, value=b"\x00\x00\x00\x00", flags=0):
    name_b = name.encode("latin-1") if isinstance(name, str) else name
    if len(name_b) != 4:
        raise ValueError("property names are 4 characters: %r" % name)
    return _ELEMENT.pack(name_b, flags, len(value)) + bytes(value)


def unpack_element_header(raw):
    name, flags, size = _ELEMENT.unpack(raw)
    return name, flags, size
