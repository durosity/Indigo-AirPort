"""Turn raw ACP property bytes into typed Python values."""

import ipaddress
import plistlib
import uuid

from . import cflbinary
from .catalogue import PROPERTIES


def _str(v):
    return v.decode("utf-8", "replace").rstrip("\x00")


DECODERS = {
    "str": _str,
    "boo": lambda v: bool(v[0]) if v else False,
    "ui8": lambda v: v[0],
    "u16": lambda v: int.from_bytes(v[:2], "big"),
    "u32": lambda v: int.from_bytes(v[:4], "big"),
    "dec": lambda v: int.from_bytes(v, "big"),
    "hex": lambda v: "0x" + v.hex(),
    "mac": lambda v: ":".join("%02x" % b for b in v[:6]),
    "ip4": lambda v: str(ipaddress.IPv4Address(bytes(v[:4]))),
    "ip6": lambda v: str(ipaddress.IPv6Address(bytes(v[:16]))),
    "uid": lambda v: str(uuid.UUID(bytes=bytes(v[:16]))),
    "cfb": cflbinary.parse,
    "bpl": lambda v: plistlib.loads(bytes(v)),
    "log": lambda v: "\n".join(line.strip() for line in v.decode("latin-1").split("\x00") if line.strip()),
    "bin": bytes,
}


def type_of(name):
    entry = PROPERTIES.get(name)
    return entry[0] if entry else "bin"


def decode(name, raw):
    """Decode one property value; falls back to raw bytes if decoding fails."""
    kind = type_of(name)
    try:
        return DECODERS.get(kind, bytes)(raw)
    except Exception:
        return bytes(raw)
