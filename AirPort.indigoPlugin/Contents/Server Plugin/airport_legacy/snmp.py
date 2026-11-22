"""Minimal SNMPv1 client (get, get-next, walk, set) over UDP. No dependencies.

Enough for the original AirPort base stations (Graphite / Snow), which are
administered over SNMPv1 with the base station password as the community.
"""

import os
import socket

# ASN.1 / SNMP tags
INTEGER, OCTET_STRING, NULL, OID, SEQUENCE = 0x02, 0x04, 0x05, 0x06, 0x30
IP_ADDRESS, COUNTER32, GAUGE32, TIMETICKS, OPAQUE, COUNTER64 = 0x40, 0x41, 0x42, 0x43, 0x44, 0x46
GET, GET_NEXT, RESPONSE, SET = 0xA0, 0xA1, 0xA2, 0xA3

ERRORS = {1: "tooBig", 2: "noSuchName", 3: "badValue", 4: "readOnly", 5: "genErr"}


class SNMPError(Exception):
    pass


class SNMPTimeout(SNMPError):
    """No reply. With SNMPv1 a wrong community also looks like this."""


class SNMPErrorStatus(SNMPError):
    def __init__(self, status, index):
        self.status, self.index = status, index
        super().__init__("%s (index %d)" % (ERRORS.get(status, "error %d" % status), index))


# ------------------------------------------------------------------ BER encoding

def _len(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag, body):
    return bytes([tag]) + _len(len(body)) + body


def enc_int(value, tag=INTEGER):
    length = max(1, (value.bit_length() + 8) // 8)
    return tlv(tag, value.to_bytes(length, "big", signed=True))


def enc_uint(value, tag):
    body = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return tlv(tag, body)


def enc_oid(oid):
    parts = [int(p) for p in str(oid).strip(".").split(".")]
    body = bytearray([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.insert(0, 0x80 | (part & 0x7F))
            part >>= 7
        body += bytes(chunk)
    return tlv(OID, bytes(body))


def encode_value(value):
    """value: None (NULL), int (INTEGER), bytes/str (OCTET STRING) or (tag, payload)."""
    if value is None:
        return tlv(NULL, b"")
    if isinstance(value, tuple):
        tag, payload = value
        if tag in (COUNTER32, GAUGE32, TIMETICKS, COUNTER64):
            return enc_uint(payload, tag)
        if tag == IP_ADDRESS:
            return tlv(IP_ADDRESS, socket.inet_aton(payload) if isinstance(payload, str) else bytes(payload))
        return tlv(tag, bytes(payload))
    if isinstance(value, bool):
        raise SNMPError("booleans are not an SNMP type")
    if isinstance(value, int):
        return enc_int(value)
    if isinstance(value, str):
        value = value.encode("latin-1")
    return tlv(OCTET_STRING, bytes(value))


# ------------------------------------------------------------------ BER decoding

def _read_tlv(data, pos):
    tag = data[pos]
    pos += 1
    length = data[pos]
    pos += 1
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    end = pos + length
    if end > len(data):
        raise SNMPError("truncated packet")
    return tag, data[pos:end], end


def dec_oid(body):
    parts = [body[0] // 40, body[0] % 40]
    value = 0
    for b in body[1:]:
        value = (value << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


def decode_value(tag, body):
    if tag == INTEGER:
        return int.from_bytes(body, "big", signed=True) if body else 0
    if tag in (COUNTER32, GAUGE32, TIMETICKS, COUNTER64):
        return int.from_bytes(body, "big") if body else 0
    if tag == OCTET_STRING:
        return bytes(body)
    if tag == NULL:
        return None
    if tag == OID:
        return dec_oid(body)
    if tag == IP_ADDRESS:
        return socket.inet_ntoa(bytes(body[:4]))
    return (tag, bytes(body))


def _children(body):
    pos, out = 0, []
    while pos < len(body):
        tag, value, pos = _read_tlv(body, pos)
        out.append((tag, value))
    return out


def build_message(community, pdu_type, request_id, varbinds):
    vbs = b"".join(tlv(SEQUENCE, enc_oid(oid) + encode_value(value)) for oid, value in varbinds)
    pdu = tlv(pdu_type, enc_int(request_id) + enc_int(0) + enc_int(0) + tlv(SEQUENCE, vbs))
    if isinstance(community, str):
        community = community.encode("latin-1")
    return tlv(SEQUENCE, enc_int(0) + tlv(OCTET_STRING, community) + pdu)


def parse_message(data):
    tag, body, _ = _read_tlv(data, 0)
    if tag != SEQUENCE:
        raise SNMPError("not an SNMP message")
    parts = _children(body)
    if len(parts) < 3:
        raise SNMPError("malformed SNMP message")
    pdu_tag, pdu = parts[2]
    fields = _children(pdu)
    request_id = decode_value(INTEGER, fields[0][1])
    status = decode_value(INTEGER, fields[1][1])
    index = decode_value(INTEGER, fields[2][1])
    varbinds = []
    for _, vb in _children(fields[3][1]):
        (_, oid_body), (vtag, vbody) = _children(vb)[:2]
        varbinds.append((dec_oid(oid_body), decode_value(vtag, vbody)))
    return pdu_tag, request_id, status, index, varbinds


# ------------------------------------------------------------------ client

class SNMPClient:
    def __init__(self, host, community, port=161, timeout=3.0, retries=2):
        self.host, self.port, self.timeout, self.retries = host, port, timeout, retries
        self.__community = community or ""
        self._request_id = int.from_bytes(os.urandom(3), "big")

    def __repr__(self):
        return "<SNMPClient %s:%d community=%s>" % (self.host, self.port, "set" if self.__community else "not set")

    def _request(self, pdu_type, varbinds):
        self._request_id = (self._request_id + 1) & 0x7FFFFFFF
        packet = build_message(self.__community, pdu_type, self._request_id, varbinds)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            for _ in range(self.retries + 1):
                sock.sendto(packet, (self.host, self.port))
                try:
                    while True:
                        data, _ = sock.recvfrom(65535)
                        try:
                            tag, rid, status, index, result = parse_message(data)
                        except (SNMPError, IndexError, ValueError):
                            continue
                        if tag == RESPONSE and rid == self._request_id:
                            if status:
                                raise SNMPErrorStatus(status, index)
                            return result
                except socket.timeout:
                    continue
        finally:
            sock.close()
        raise SNMPTimeout("no response from %s (wrong password, or not reachable)" % self.host)

    def get(self, *oids):
        return self._request(GET, [(o, None) for o in oids])

    def get_one(self, oid):
        return self.get(oid)[0][1]

    def get_next(self, oid):
        return self._request(GET_NEXT, [(oid, None)])[0]

    def walk(self, prefix, limit=1000):
        prefix = str(prefix).strip(".")
        oid, out = prefix, []
        for _ in range(limit):
            try:
                oid, value = self.get_next(oid)
            except SNMPErrorStatus as err:
                if err.status == 2:   # v1 end of MIB
                    break
                raise
            if not (oid == prefix or oid.startswith(prefix + ".")):
                break
            out.append((oid, value))
        return out

    def set(self, oid, value):
        return self._request(SET, [(oid, value)])
