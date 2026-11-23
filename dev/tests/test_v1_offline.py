"""Offline test of the ACP v1 client (AirPort Snow) against a simulated base station."""
import os, socket, sys, threading
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "AirPort.indigoPlugin", "Contents", "Server Plugin"))
from airport_acp import message
from airport_acp.v1 import ACPv1Client, read_states, _xor
from airport_acp.client import AuthenticationError

PASSWORD = "snowpw"
STORE = {"syNm": b"Snow Test\x00", "raNm": b"Vintage\x00", "raCh": (11).to_bytes(4, "big"), "raCl": b"\x01",
         "waIP": socket.inet_aton("10.9.8.6"), "waRA": socket.inet_aton("10.9.8.1"), "waSM": socket.inet_aton("255.255.255.0"),
         "raNA": b"\x00", "raDS": b"\x00", "raWB": b"\x01", "raWM": b"\x00\x00\x00\x01", "syPW": b"snowpw\x00", "raSt": b"\x00\x00\x00\x00"}
REBOOTS = []
ENC = {"syNm", "raNm", "waIP", "waRA", "waSM", "raDS", "syPW"}
seen = []

def serve(srv):
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        data = b""
        while len(data) < 128:
            data += conn.recv(4096)
        hdr = message.Header.unpack(data[:128])
        if hdr.body_size < 0:            # streamed (writes): read until the client pauses
            conn.settimeout(0.3)
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except socket.timeout:
                pass
            body = data[128:]
        else:
            while len(data) < 128 + hdr.body_size:
                data += conn.recv(4096)
            body = data[128:128 + hdr.body_size]
        seen.append((hdr.version, hdr.key))
        if hdr.key != message.header_key(PASSWORD):
            conn.sendall(message.Header(hdr.command, 1, message.ZERO_KEY, -1, 1, error_code=-16, version=1).pack()); conn.close(); continue
        if hdr.command == message.CMD_SET_PROPERTY:
            pos = 0
            while pos < len(body):
                name, flags, size = message.unpack_element_header(body[pos:pos + 12])
                value = body[pos + 12:pos + 12 + size]; pos += 12 + size
                tag = name.decode()
                if tag == "acRB":
                    REBOOTS.append(1)
                else:
                    STORE[tag] = _xor(value) if flags & 2 else value
            conn.sendall(message.Header(hdr.command, 1, message.ZERO_KEY, -1, 1, version=1).pack()); conn.close(); continue
        out, pos = b"", 0
        while pos < len(body):
            name, flags, size = message.unpack_element_header(body[pos:pos + 12]); pos += 12 + size
            tag = name.decode()
            if tag in STORE:
                v = STORE[tag]
                out += message.pack_element(tag, _xor(v) if tag in ENC else v, 2 if tag in ENC else 0)
            else:
                out += message.pack_element(tag, (-10 & 0xFFFFFFFF).to_bytes(4, "big"), 1)
        conn.sendall(message.Header(hdr.command, 1, message.ZERO_KEY, -1, 1, version=1).pack() + out)
        conn.close()

srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(5); port = srv.getsockname()[1]
threading.Thread(target=serve, args=(srv,), daemon=True).start()
ok = True
c = ACPv1Client("127.0.0.1", PASSWORD, port=port)
states, values = read_states(c)
print("states:", states)
ok &= states["name"] == "Snow Test" and states["networkName"] == "Vintage" and states["channel"] == 11
ok &= states["closedNetwork"] and states["bridging"] and states["ipAddress"] == "10.9.8.6" and states.get("encryption") is True
ok &= "syPW" not in values and PASSWORD not in repr(states) + repr(values)
ok &= c.password_matches_device() is True
ok &= all(v == 1 for v, _ in seen)
try:
    ACPv1Client("127.0.0.1", "wrong", port=port).get_raw(["syNm"]); ok = False
except AuthenticationError as e:
    print("wrong password ->", e)
c.set_raw({"raSt": (3).to_bytes(4, "big"), "raNm": b"Renamed\x00"})
ok &= STORE["raSt"] == (3).to_bytes(4, "big") and STORE["raNm"] == b"Renamed\x00"
c.set_raw({}, reboot=True); ok &= REBOOTS == [1]
print("write: raSt ->", STORE["raSt"].hex(), "| raNm ->", STORE["raNm"], "| reboots", len(REBOOTS))
print("V1 PASSED" if ok else "V1 FAILED")
srv.close()
