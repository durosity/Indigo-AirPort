"""ACP version 1: the original protocol, as spoken by the AirPort Snow (and,
it appears, the 802.11g generation).

Differences from the current protocol (see client.py):
  * No login: the admin password travels in every request header, obfuscated
    with the same fixed keystream as message.header_key(). It is trivially
    reversible, so treat it as clear text on the wire (as Apple's own AirPort
    Admin Utility did).
  * One request per TCP connection; the base station closes the connection
    after replying.
  * Header version field is 1.
  * Request elements carry no value (size 0). In responses, an element flag of
    2 means the value is XOR-ed with the same keystream; flag 1 is an error.

Facts from Jon Sevy's published reverse-engineering (airport2config); this is
an independent implementation.
"""

import socket

from . import message
from .client import ACPError, AuthenticationError, PropertyError

VERSION_1 = 0x00000001

# tag: (kind, value is encrypted on the wire, description)
TAGS = {
    "syNm": ("str", True, "Base station name"),
    "syCt": ("str", True, "Contact"),
    "syLo": ("str", True, "Location"),
    "syPW": ("str", True, "Admin password"),
    "syPR": ("str", True, "Read community"),
    "waCV": ("hex", False, "Configuration mode"),
    "waIn": ("hex", False, "WAN interface (Ethernet/modem)"),
    "waIP": ("ip", True, "Base station IP address"),
    "waRA": ("ip", True, "Router"),
    "waSM": ("ip", True, "Subnet mask"),
    "waD1": ("ip", True, "Primary DNS"),
    "waD2": ("ip", True, "Secondary DNS"),
    "waDN": ("str", True, "Domain name"),
    "waDS": ("uint", True, "WAN DHCP client"),
    "raNm": ("str", True, "Network name"),
    "raCh": ("uint", False, "Channel"),
    "raCl": ("uint", False, "Closed network"),
    "raRo": ("uint", False, "Interference robustness"),
    "raDe": ("hex", False, "Access point density"),
    "raMu": ("hex", False, "Multicast rate"),
    "raWM": ("hex", False, "Encryption switch"),
    "raWE": ("hex", True, "WEP key"),
    "raWB": ("uint", False, "Wireless to Ethernet bridging"),
    "raDS": ("uint", True, "DHCP server"),
    "raNA": ("uint", False, "NAT"),
    "laIP": ("ip", True, "Private LAN address"),
    "laSM": ("ip", True, "Private LAN subnet mask"),
    "laDS": ("uint", False, "DHCP on LAN Ethernet"),
    "dhBg": ("ip", True, "DHCP range start"),
    "dhEn": ("ip", True, "DHCP range end"),
    "dhLe": ("uint", True, "DHCP lease time"),
    "acEn": ("uint", False, "Access control"),
    "acTa": ("hex", True, "Access control table"),
    "pmTa": ("hex", True, "Port mappings"),
    "peID": ("uint", False, "PPPoE idle timeout"),
    "peAC": ("uint", False, "PPPoE auto connect"),
    "peSC": ("uint", False, "PPPoE stay connected"),
    "moID": ("uint", False, "Modem timeout"),
    "moPD": ("uint", False, "Pulse dialling"),
    "moAD": ("uint", False, "Automatic dial"),
    "moCC": ("uint", False, "Phone country code"),
    "moPN": ("str", True, "Primary phone number"),
    "syVs": ("str", False, "Firmware version"),
    "syDs": ("str", False, "System description"),
    "syAP": ("uint", False, "Product ID"),
    "waMA": ("mac", False, "WAN (Ethernet) MAC address"),
    "laMA": ("mac", False, "LAN MAC address"),
    "raMA": ("mac", False, "Wi-Fi MAC address"),
    "leAc": ("uint", False, "Status light mode"),
    "raSt": ("uint", False, "Radio mode (0 = on, 3 = off on newer models)"),
    "raVs": ("str", False, "Radio firmware version"),
    "moAP": ("str", True, "Secondary phone number"),
}
SECRET_TAGS = frozenset({"syPW", "syPR", "syGP", "raWE", "raCr", "moPN", "moAP", "moPW", "pePW", "pdPW", "auNP"})


def _xor(data):
    return bytes(a ^ b for a, b in zip(data, message.keystream(len(data))))


def decode(tag, raw):
    kind = TAGS.get(tag, ("hex", False, ""))[0]
    try:
        if kind == "str":
            return raw.split(b"\x00", 1)[0].decode("mac_roman", "replace")
        if kind == "ip":
            return socket.inet_ntoa(raw[:4])
        if kind == "mac":
            return ":".join("%02x" % b for b in raw[:6])
        if kind == "uint":
            return int.from_bytes(raw, "big") if raw else 0
    except (ValueError, OSError):
        pass
    return raw.hex()


class ACPv1Client:
    def __init__(self, host, password, port=5009, timeout=10.0):
        self.host, self.port, self.timeout = host, port, timeout
        self.__password = password or ""

    def __repr__(self):
        return "<ACPv1Client %s:%d password=%s>" % (self.host, self.port, "set" if self.__password else "not set")

    def _exchange(self, command, body):
        header = message.Header(command, 0, message.header_key(self.__password), len(body),
                                message.adler32(body), version=VERSION_1).pack()
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        try:
            sock.sendall(header + body)
            chunks = []
            while True:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            sock.close()
        data = b"".join(chunks)
        if len(data) < message.HEADER_SIZE:
            raise ACPError("no reply from base station")
        return message.Header.unpack(data[:message.HEADER_SIZE]), data[message.HEADER_SIZE:]

    def get_raw(self, names, include_secret=False):
        names = [n for n in names if include_secret or n not in SECRET_TAGS]
        if not names:
            return {}
        body = b"".join(message.pack_element(n, b"", 2 if TAGS.get(n, ("", True))[1] else 0)
                        for n in names)
        header, payload = self._exchange(message.CMD_GET_PROPERTY, body)
        if header.error_code:
            if header.error_code in (-6754, -16):
                raise AuthenticationError("password rejected (%s)" % header.error_name)
            raise ACPError("get properties failed: %s" % header.error_name)
        results, pos = {}, 0
        while pos + message.ELEMENT_HEADER_SIZE <= len(payload):
            name, flags, size = message.unpack_element_header(payload[pos:pos + message.ELEMENT_HEADER_SIZE])
            pos += message.ELEMENT_HEADER_SIZE
            value = payload[pos:pos + size]
            pos += size
            key = name.decode("latin-1")
            if name == b"\x00\x00\x00\x00":
                break
            if flags & 1:
                results[key] = PropertyError(key, int.from_bytes(value[:4], "big", signed=True))
                continue
            results[key] = _xor(value) if flags & 2 else value
        return results

    def set_raw(self, values, reboot=False):
        """Write properties ({tag: bytes}); with reboot=True append the reboot flag.

        Request format per Sevy's airport2config: a WRITE header with a streamed
        body, then elements of tag, flag (2 = value obfuscated), length, value.
        """
        body = b""
        for tag, value in values.items():
            encrypted = TAGS.get(tag, ("", False))[1]
            body += message.pack_element(tag, _xor(value) if encrypted else bytes(value), 2 if encrypted else 0)
        if reboot:
            body += message.pack_element("acRB", b"", 0)
        if not body:
            return
        header = message.Header(message.CMD_SET_PROPERTY, 0, message.header_key(self.__password), -1, 1,
                                version=VERSION_1).pack()
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        try:
            sock.sendall(header + body)
            reply = b""
            try:
                while len(reply) < message.HEADER_SIZE:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    reply += chunk
            except socket.timeout:
                pass
        finally:
            sock.close()
        if len(reply) >= message.HEADER_SIZE:
            header = message.Header.unpack(reply[:message.HEADER_SIZE])
            if header.error_code in (-6754, -16):
                raise AuthenticationError("password rejected (%s)" % header.error_name)
            if header.error_code:
                raise ACPError("set properties failed: %s" % header.error_name)
        elif not reboot:
            raise ACPError("no reply to write")

    def password_matches_device(self):
        value = self.get_raw(["syPW"], include_secret=True).get("syPW")
        if not isinstance(value, bytes):
            return None
        return value.split(b"\x00", 1)[0] == self.__password.encode("utf-8")


def read_states(client):
    raw = client.get_raw([t for t in TAGS if t not in SECRET_TAGS])
    v = {t: decode(t, r) for t, r in raw.items() if isinstance(r, bytes)}
    s = {
        "name": v.get("syNm", ""),
        "contact": v.get("syCt", ""),
        "location": v.get("syLo", ""),
        "networkName": v.get("raNm", ""),
        "channel": v.get("raCh", 0) if isinstance(v.get("raCh"), int) else 0,
        "closedNetwork": bool(v.get("raCl")) if isinstance(v.get("raCl"), int) else False,
        "ipAddress": v.get("waIP", ""),
        "router": v.get("waRA", ""),
        "subnetMask": v.get("waSM", ""),
        "natEnabled": bool(v.get("raNA")) if isinstance(v.get("raNA"), int) else False,
        "dhcpServerEnabled": bool(v.get("raDS")) if isinstance(v.get("raDS"), int) else False,
        "bridging": bool(v.get("raWB")) if isinstance(v.get("raWB"), int) else False,
        "domainName": v.get("waDN", ""),
        "firmware": v.get("syVs", ""),
        "description": v.get("syDs", ""),
        "macAddress": v.get("waMA", ""),
        "wifiMacAddress": v.get("raMA", ""),
    }
    wm = v.get("raWM")
    if isinstance(wm, str):
        s["encryption"] = any(c not in "0" for c in wm)
    return s, v


# Known not to switch the radio despite storing raSt (tested: Snow, firmware 4.0.9).
RADIO_IGNORES_RASTATE = {1}


def set_wifi(client, enable, state_dir, host_id, reboot=True):
    """Experimental Wi-Fi on/off via a top-level raSt (0 on, 3 off) on ACP v1 units.

    Snapshot every non-secret setting, back it up (0600), write raSt alone,
    re-read and require that only raSt changed (else write the changed
    settings back), then restart. Returns a result dict like wifi.set_wifi().
    """
    import json, os, time
    watch = [t for t in TAGS if t not in SECRET_TAGS]

    def snapshot():
        return {k: v for k, v in client.get_raw(watch).items() if isinstance(v, bytes)}

    before = snapshot()
    if "raSt" not in before:
        raise ACPError("this unit does not report raSt")
    product = int.from_bytes(before.get("syAP", b"\x00"), "big")
    current = int.from_bytes(before["raSt"], "big")
    target = 0 if enable else 3
    result = {"changed": [], "written": False, "rebooted": False, "backup": None,
              "radio_may_ignore": product in RADIO_IGNORES_RASTATE}
    if current == target:
        result["note"] = "already %s" % ("on" if enable else "off")
        return result
    os.makedirs(state_dir, exist_ok=True)
    backup = os.path.join(state_dir, "%s-v1-%s.json" % (host_id, time.strftime("%Y%m%d-%H%M%S")))
    fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump({k: v.hex() for k, v in before.items()}, fh, indent=1)
    result["backup"] = backup
    new = target.to_bytes(len(before["raSt"]), "big")
    client.set_raw({"raSt": new})
    time.sleep(1)
    after = snapshot()
    others = sorted(k for k in set(before) | set(after) if k != "raSt" and before.get(k) != after.get(k))
    if after.get("raSt") != new or others:
        client.set_raw({k: before[k] for k in others + ["raSt"] if k in before})
        raise ACPError("read-back check failed (other changes: %s); original written back" % (others or "none"))
    result["changed"] = [".raSt"]
    result["written"] = True
    if reboot:
        client.set_raw({}, reboot=True)
        result["rebooted"] = True
    return result
