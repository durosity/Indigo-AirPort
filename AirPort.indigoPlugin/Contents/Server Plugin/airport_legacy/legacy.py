"""Original AirPort base stations (Graphite and Snow), administered over SNMPv1.

What's known about these units (from Jon Sevy's published reverse-engineering
of the AirPort Admin protocol; this is an independent implementation):

* The base station password is the SNMP community string.
* The configuration is a 17,408-byte block, read as 68 OCTET STRINGs of 256
  bytes from 1.3.6.1.4.1.762.2.2.1.1.<1..68>.  17,336 bytes are significant,
  the last two of which are a 16-bit little-endian byte-sum checksum.
* Fields are laid out in a 16-byte-wide grid: a field of R rows x C columns
  starting at offset O covers bytes O + r*16 + c.
* Associated wireless clients: count at 1.3.6.1.4.1.762.2.5.1.0, MAC of
  client n at 1.3.6.1.4.1.762.2.5.2.1.11.n.
* Discovery: a 116-byte UDP packet (first byte 0x01) to port 192; the reply
  carries MAC (0x24), IP (0x2C), name (0x30, 32 bytes), uptime (0x50) and a
  device description (0x54, 32 bytes).

Read-only for now. Writing a configuration requires re-sending all blocks
with checksums and makes the unit burn its flash and restart.
"""

import socket

from .snmp import SNMPClient, SNMPError, SNMPErrorStatus, SNMPTimeout

ENTERPRISE = "1.3.6.1.4.1.762"
CONFIG_READ_OID = ENTERPRISE + ".2.2.1.1."
CLIENT_COUNT_OID = ENTERPRISE + ".2.5.1.0"
CLIENT_MAC_OID = ENTERPRISE + ".2.5.2.1.11."
CONFIG_BLOCKS = 68
BLOCK_SIZE = 256
CONFIG_SIGNIFICANT = 17336
DISCOVERY_PORT = 192

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"


class LegacyError(Exception):
    pass


# ------------------------------------------------------------------ field table
# key, offset, rows, cols, kind, mask, secret
#   kind: str (NUL-padded text), uint (big-endian), le (little-endian),
#         ip (4 bytes), flag (bool from mask), byte (masked byte value), hex
FIELDS = [
    ("baseStationName",  0x4CC, 1, 64, "str", None, False),
    ("contact",          0x48C, 1, 64, "str", None, False),
    ("location",         0x50C, 1, 64, "str", None, False),
    ("networkName",      0x1C8, 16, 2, "str", None, False),
    ("channel",          0x178, 1, 1, "uint", None, False),
    ("closedNetwork",    0x168, 1, 1, "flag", 0x40, False),
    ("encryption",       0x158, 1, 1, "flag", 0x08, False),
    ("denyUnencrypted",  0x168, 1, 1, "flag", 0x80, False),
    ("rtsCts",           0x168, 1, 1, "flag", 0x20, False),
    ("rtsThreshold",     0x1A8, 1, 2, "le", None, False),
    ("distanceRate",     0x169, 1, 1, "byte", 0x0F, False),
    ("configuredIP",     0x46A, 1, 4, "ip", None, False),
    ("configuredRouter", 0x470, 1, 4, "ip", None, False),
    ("configuredMask",   0x474, 1, 4, "ip", None, False),
    ("dhcpClient",       0x117, 1, 1, "flag", 0x20, False),
    ("dhcpOnEthernet",   0x117, 1, 1, "flag", 0x40, False),
    ("bridging",         0x448, 1, 1, "flag", 0x01, False),
    ("accessControl",    0x448, 1, 1, "flag", 0x80, False),
    ("dhcpServer",       0x449, 1, 1, "flag", 0x80, False),
    ("nat",              0x449, 1, 1, "flag", 0x02, False),
    ("portMapping",      0x449, 1, 1, "flag", 0x04, False),
    ("wanInterface",     0x460, 1, 1, "uint", None, False),
    ("syslogHost",       0x478, 1, 4, "ip", None, False),
    ("trapHost",         0x47C, 1, 4, "ip", None, False),
    ("dhcpRangeStart",   0xCF2, 1, 4, "ip", None, False),
    ("dhcpRangeEnd",     0xCF6, 1, 4, "ip", None, False),
    ("domainName",       0xD0A, 1, 32, "str", None, False),
    ("portMapCount",     0xD62, 1, 2, "le", None, False),
    ("accessControlCount", 0xF87, 1, 2, "uint", None, False),
    ("storedChecksum",   0x43B6, 1, 2, "le", None, False),
    # secrets: decoded only for internal use, never returned by decode_config()
    ("readWriteCommunity", 0x096, 1, 16, "str", None, True),
    ("readCommunity",    0x076, 1, 16, "str", None, True),
    ("trapCommunity",    0x056, 1, 16, "str", None, True),
    ("encryptionKey1",   0x376, 1, 13, "hex", None, True),
    ("pppoeClientId",    0x3ED3, 1, 128, "str", None, True),
]

WAN_INTERFACES = {0: "Ethernet", 1: "PPPoE", 3: "modem"}


def window(raw, offset, rows, cols):
    return bytes(raw[offset + r * 16 + c] for r in range(rows) for c in range(cols))


def _decode(kind, data, mask):
    if kind == "str":
        return data.split(b"\x00", 1)[0].decode("mac_roman", "replace")
    if kind == "uint":
        return int.from_bytes(data, "big")
    if kind == "le":
        return int.from_bytes(data, "little")
    if kind == "ip":
        return socket.inet_ntoa(data[:4])
    if kind == "flag":
        return bool(data[0] & mask)
    if kind == "byte":
        return data[0] & mask
    return data.hex()


def decode_config(raw, include_secrets=False):
    if len(raw) < CONFIG_SIGNIFICANT:
        raise LegacyError("configuration block too short (%d bytes)" % len(raw))
    out = {}
    for key, offset, rows, cols, kind, mask, secret in FIELDS:
        if secret and not include_secrets:
            continue
        out[key] = _decode(kind, window(raw, offset, rows, cols), mask)
    return out


def checksum(raw, length=CONFIG_SIGNIFICANT - 2):
    return sum(raw[:length]) & 0xFFFF


# ------------------------------------------------------------------ network

def discover(host="255.255.255.255", timeout=2.0):
    """Ask base stations on UDP 192 to identify themselves (no password)."""
    request = b"\x01" + bytes(115)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)
    found = {}
    try:
        sock.sendto(request, (host, DISCOVERY_PORT))
        while True:
            try:
                data, (address, _) = sock.recvfrom(1024)
            except socket.timeout:
                break
            if len(data) < 0x74 or data[0] == 0x01 and data[1:] == bytes(len(data) - 1):
                continue
            found[address] = {
                "mac": ":".join("%02x" % b for b in data[0x24:0x2A]),
                "ip": socket.inet_ntoa(data[0x2C:0x30]),
                "name": data[0x30:0x50].split(b"\x00", 1)[0].decode("mac_roman", "replace"),
                "uptimeRaw": int.from_bytes(data[0x50:0x54], "big"),
                "description": data[0x54:0x74].split(b"\x00", 1)[0].decode("mac_roman", "replace"),
            }
    finally:
        sock.close()
    return found


class LegacyBaseStation:
    """Read access to a Graphite/Snow base station."""

    def __init__(self, host, password, timeout=3.0, retries=2):
        self.host = host
        self._snmp = SNMPClient(host, password, timeout=timeout, retries=retries)

    def __repr__(self):
        return "<LegacyBaseStation %s>" % self.host

    def system(self):
        values = dict(self._snmp.get(SYS_DESCR, SYS_UPTIME, SYS_CONTACT, SYS_NAME, SYS_LOCATION))
        text = lambda v: v.decode("mac_roman", "replace").rstrip("\x00") if isinstance(v, bytes) else (v or "")
        return {
            "description": text(values.get(SYS_DESCR)),
            "uptimeSeconds": int(values.get(SYS_UPTIME) or 0) // 100,
            "contact": text(values.get(SYS_CONTACT)),
            "name": text(values.get(SYS_NAME)),
            "location": text(values.get(SYS_LOCATION)),
        }

    def read_config(self):
        blocks = []
        for k in range(1, CONFIG_BLOCKS + 1):
            value = self._snmp.get_one(CONFIG_READ_OID + str(k))
            if not isinstance(value, bytes):
                raise LegacyError("block %d: unexpected value type" % k)
            blocks.append(value.ljust(BLOCK_SIZE, b"\x00")[:BLOCK_SIZE])
        return b"".join(blocks)

    def clients(self):
        try:
            count = int(self._snmp.get_one(CLIENT_COUNT_OID) or 0)
        except SNMPErrorStatus:
            return None
        macs = []
        for n in range(1, count + 1):
            try:
                value = self._snmp.get_one(CLIENT_MAC_OID + str(n))
            except SNMPErrorStatus:
                continue
            if isinstance(value, bytes) and len(value) >= 6:
                macs.append(":".join("%02x" % b for b in value[:6]))
        return macs

    def walk(self, prefix):
        return self._snmp.walk(prefix)


def read_states(station):
    """Flat states for the plugin (no secrets)."""
    s = {}
    system = station.system()
    s["description"] = system["description"]
    s["uptimeSeconds"] = system["uptimeSeconds"]
    raw = station.read_config()
    cfg = decode_config(raw)
    s["name"] = cfg["baseStationName"] or system["name"]
    s["networkName"] = cfg["networkName"]
    s["channel"] = cfg["channel"]
    s["closedNetwork"] = cfg["closedNetwork"]
    s["encryption"] = cfg["encryption"]
    s["ipAddress"] = cfg["configuredIP"]
    s["router"] = cfg["configuredRouter"]
    s["subnetMask"] = cfg["configuredMask"]
    s["natEnabled"] = cfg["nat"]
    s["dhcpServerEnabled"] = cfg["dhcpServer"]
    s["bridging"] = cfg["bridging"]
    s["wanInterface"] = WAN_INTERFACES.get(cfg["wanInterface"], "type %d" % cfg["wanInterface"])
    s["contact"] = cfg["contact"]
    s["location"] = cfg["location"]
    clients = station.clients()
    if clients is not None:
        s["clientCount"] = len(clients)
    return s, raw
