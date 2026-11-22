"""Offline test of the Graphite/Snow backend against a simulated SNMPv1 base station."""
import os, socket, sys, threading
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "AirPort.indigoPlugin", "Contents", "Server Plugin"))
from airport_legacy import snmp, legacy

def put(raw, offset, rows, cols, data):
    data = data.ljust(rows * cols, b"\x00")
    for i, b in enumerate(data[:rows * cols]):
        r, c = divmod(i, cols)
        raw[offset + r * 16 + c] = b

raw = bytearray(68 * 256)
put(raw, 0x4CC, 1, 64, b"Graphite Test")
put(raw, 0x1C8, 16, 2, b"Vintage Net")
raw[0x178] = 6
raw[0x168] |= 0x40          # closed network
raw[0x449] |= 0x82          # DHCP + NAT
put(raw, 0x46A, 1, 4, socket.inet_aton("10.9.8.7"))
put(raw, 0x096, 1, 16, b"secretpw")
cs = legacy.checksum(raw); raw[0x43B6] = cs & 0xFF; raw[0x43B7] = cs >> 8
COMMUNITY = b"secretpw"
values = {legacy.CONFIG_READ_OID + str(k): bytes(raw[(k - 1) * 256:k * 256]) for k in range(1, 69)}
values.update({legacy.SYS_DESCR: b"Base Station V4.0.9", legacy.SYS_UPTIME: ("tt", 123456),
               legacy.SYS_CONTACT: b"", legacy.SYS_NAME: b"Graphite Test", legacy.SYS_LOCATION: b"",
               legacy.CLIENT_COUNT_OID: 2, legacy.CLIENT_MAC_OID + "1": bytes.fromhex("0003930a0b0c"),
               legacy.CLIENT_MAC_OID + "2": bytes.fromhex("0003930d0e0f")})

def agent(sock):
    while True:
        try:
            data, addr = sock.recvfrom(65535)
        except OSError:
            return
        tag, body, _ = snmp._read_tlv(data, 0)
        parts = snmp._children(body)
        if parts[1][1] != COMMUNITY:
            continue  # SNMPv1: silently drop wrong community
        pdu_tag, pdu = parts[2]
        fields = snmp._children(pdu)
        rid = snmp.decode_value(snmp.INTEGER, fields[0][1])
        oids = [snmp.dec_oid(snmp._children(vb)[0][1]) for _, vb in snmp._children(fields[3][1])]
        out, status = [], 0
        for oid in oids:
            if oid not in values:
                status = 2; out.append((oid, None)); continue
            v = values[oid]
            out.append((oid, (snmp.TIMETICKS, v[1]) if isinstance(v, tuple) else v))
        vbs = b"".join(snmp.tlv(snmp.SEQUENCE, snmp.enc_oid(o) + snmp.encode_value(v)) for o, v in out)
        pdu = snmp.tlv(snmp.RESPONSE, snmp.enc_int(rid) + snmp.enc_int(status) + snmp.enc_int(1 if status else 0) + snmp.tlv(snmp.SEQUENCE, vbs))
        sock.sendto(snmp.tlv(snmp.SEQUENCE, snmp.enc_int(0) + snmp.tlv(snmp.OCTET_STRING, COMMUNITY) + pdu), addr)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]
threading.Thread(target=agent, args=(sock,), daemon=True).start()

ok = True
station = legacy.LegacyBaseStation("127.0.0.1", "secretpw"); station._snmp.port = port
states, got = legacy.read_states(station)
print("states:", states)
ok &= got == bytes(raw) and states["name"] == "Graphite Test" and states["networkName"] == "Vintage Net"
ok &= states["channel"] == 6 and states["closedNetwork"] and states["natEnabled"] and states["dhcpServerEnabled"]
ok &= states["ipAddress"] == "10.9.8.7" and states["clientCount"] == 2 and states["uptimeSeconds"] == 1234
cfg = legacy.decode_config(got)
ok &= "readWriteCommunity" not in cfg and "secretpw" not in repr(cfg) and "secretpw" not in repr(states)
ok &= cfg["storedChecksum"] == legacy.checksum(got)
wrong = legacy.LegacyBaseStation("127.0.0.1", "nope", timeout=0.5, retries=0); wrong._snmp.port = port
try:
    wrong.system(); ok = False
except snmp.SNMPTimeout:
    print("wrong password -> timeout (as on real SNMPv1 units)")
print("LEGACY PASSED" if ok else "LEGACY FAILED")
sock.close()
