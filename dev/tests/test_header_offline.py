"""Offline test: current-protocol units without the encrypted login (e.g. 802.11g firmware),
using the header-password method, the 'auto' fallback, and the top-level raSt Wi-Fi path."""
import os, socket, sys, tempfile, threading
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "AirPort.indigoPlugin", "Contents", "Server Plugin"))
from airport_acp import message, ACPClient, AuthenticationError, AUTH_AUTO, AUTH_SRP, AuthenticationUnsupported
from airport_acp import wifi
from airport_acp.device import read_states

PASSWORD = "saucer"
STORE = {"syNm": b"Saucer", "syAP": (3).to_bytes(4, "big"), "syVs": b"5.7", "raSt": (0).to_bytes(4, "big"),
         "raCh": (11).to_bytes(4, "big"), "raNm": b"OldNet", "waIP": socket.inet_aton("10.9.8.3"), "syPW": b"saucer"}
REBOOTS = []

def recv_exact(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise EOFError
        data += chunk
    return data

def handle(conn):
    try:
        while True:
            hdr = message.Header.unpack(recv_exact(conn, 128))
            body = recv_exact(conn, hdr.body_size) if hdr.body_size > 0 else b""
            if hdr.command == message.CMD_AUTHENTICATE:      # no SRP on this firmware
                conn.sendall(message.Header(hdr.command, 1, message.ZERO_KEY, -1, 1, error_code=-10).pack()); continue
            if hdr.key != message.header_key(PASSWORD):
                conn.sendall(message.Header(hdr.command, 1, message.ZERO_KEY, -1, 1, error_code=-16).pack()); continue
            out, pos = b"", 0
            while pos < len(body):
                name, flags, size = message.unpack_element_header(body[pos:pos + 12])
                value = body[pos + 12:pos + 12 + size]; pos += 12 + size
                tag = name.decode()
                if hdr.command == message.CMD_SET_PROPERTY:
                    if tag == "acRB":
                        REBOOTS.append(1)
                    else:
                        STORE[tag] = value
                    out += message.pack_element(tag, b"\x00\x00\x00\x00")
                elif tag in STORE:
                    out += message.pack_element(tag, STORE[tag])
                else:
                    out += message.pack_element(tag, (-10 & 0xFFFFFFFF).to_bytes(4, "big"), 1)
            out += message.pack_element(b"\x00\x00\x00\x00", b"\x00\x00\x00\x00")
            conn.sendall(message.Header(hdr.command, 1, message.ZERO_KEY, -1, 1).pack() + out)
    except (EOFError, OSError):
        conn.close()

def serve(srv):
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        threading.Thread(target=handle, args=(conn,), daemon=True).start()

srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(5); port = srv.getsockname()[1]
threading.Thread(target=serve, args=(srv,), daemon=True).start()
ok = True
try:
    with ACPClient("127.0.0.1", PASSWORD, port=port, auth=AUTH_SRP) as c:
        pass
    ok = False
except AuthenticationUnsupported:
    print("encrypted-only: refused as expected")
with ACPClient("127.0.0.1", PASSWORD, port=port, auth=AUTH_AUTO) as c:
    print("auto ->", c.auth_used)
    ok &= c.auth_used == "header"
    states = read_states(c)
    print("states:", {k: states[k] for k in ("name", "firmware", "radioCount", "radio1_state", "radio1_channel", "radio1_network", "wifiEnabled")})
    ok &= states["radio1_state"] == "on" and states["radio1_channel"] == 11 and states["name"] == "Saucer"
    ok &= c.password_matches_device() is True
    with tempfile.TemporaryDirectory() as tmp:
        r = wifi.set_wifi(c, False, tmp, "saucer")
        print("wifi off ->", r["changed"], "written", r["written"], "rebooted", r["rebooted"])
        ok &= STORE["raSt"] == (3).to_bytes(4, "big") and REBOOTS == [1]
try:
    with ACPClient("127.0.0.1", "wrong", port=port, auth=AUTH_AUTO) as c:
        c.get_raw(["syNm"])
    ok = False
except AuthenticationError as e:
    print("wrong password ->", e)
print("HEADER PASSED" if ok else "HEADER FAILED")
srv.close()
