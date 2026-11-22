"""Offline tests of the Wi-Fi toggle against a fake base station seeded with the Express's real WiFi bytes."""
import json, os, re, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "AirPort.indigoPlugin", "Contents", "Server Plugin"))
from airport_acp import cflbinary, wifi, device

def express_wifi_raw():
    for line in open(os.path.expanduser("~/acp-test/survey/all.txt")):
        m = re.match(r"^Prop WiFi value: (\{.*\})\s*$", line)
        if m:
            return bytes(json.loads(m.group(1))["data"])

class FakeStation:
    def __init__(self, raw):
        self.store = {"WiFi": raw}; self.writes = []; self.reboots = 0
    def get_raw(self, names, include_secret=False):
        return {n: self.store[n] for n in names if n in self.store}
    def set_raw(self, values):
        self.writes.append(dict(values)); self.store.update(values)
    def reboot(self):
        self.reboots += 1

def main():
    raw = express_wifi_raw()
    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        st = FakeStation(raw)
        r = wifi.set_wifi(st, False, tmp, "garden", dry_run=True)
        print("dry run off ->", r["changed"], r.get("note")); ok &= not st.writes and len(r["changed"]) == 4
        r = wifi.set_wifi(st, False, tmp, "garden")
        off = cflbinary.parse(st.store["WiFi"])
        print("off ->", r["changed"], "reboots", st.reboots, "backup mode", oct(os.stat(r["backup"]).st_mode & 0o777))
        ok &= [x["raSt"] for x in off["radios"]] == [3, 3] and [x["dWDS"] for x in off["radios"]] == [False, False]
        r = wifi.set_wifi(st, False, tmp, "garden")
        print("off again ->", r.get("note")); ok &= not r["written"]
        r = wifi.set_wifi(st, True, tmp, "garden")
        print("on ->", r["changed"], "restored original bytes:", st.store["WiFi"] == raw); ok &= st.store["WiFi"] == raw
        r = wifi.set_wifi(st, False, tmp, "garden", radios=[1])
        two = cflbinary.parse(st.store["WiFi"])
        print("radio 2 only off ->", [x["raSt"] for x in two["radios"]]); ok &= [x["raSt"] for x in two["radios"]] == [0, 3]
        try:
            wifi.set_wifi(st, False, tmp, "garden", radios=[5]); ok = False
        except wifi.WiFiChangeError as e:
            print("bad radio rejected:", e)
    # device states from the surveyed values
    import glob
    for path in sorted(glob.glob("survey/*.json")):
        host = os.path.basename(path)[:-5]
        props = json.load(open(path))["properties"]
        vals = {n: e["value"] for n, e in props.items()}
        s = device.states_from(vals)
        print(host, {k: v for k, v in s.items() if k.startswith(("name", "model", "wifi", "radio1", "temperature", "sensor", "disk1", "problems", "airplay", "clientCount", "uptime"))})
    print("ALL PASSED" if ok else "FAILURES")

main()

# A station that stores the write and then hangs up (AirPort5,105 behaviour)
from airport_acp.client import ACPError
class HangUpStation(FakeStation):
    reconnects = 0
    def set_raw(self, values):
        self.store.update(values); raise ACPError("connection closed by base station")
    def reconnect(self):
        self.reconnects += 1
with tempfile.TemporaryDirectory() as tmp:
    st = HangUpStation(express_wifi_raw())
    r = wifi.set_wifi(st, False, tmp, "x")
    print("hang-up station: written", r["written"], "reconnected", r.get("reconnected"), "reboots", st.reboots)
    print("HANGUP PASSED" if r["written"] and st.reconnects == 1 and st.reboots == 1 else "HANGUP FAILED")

class AckThenCloseStation(FakeStation):
    """Acknowledges the write, then the next request fails (AirPort5,105 behaviour)."""
    reconnects = 0; closed = False
    def set_raw(self, values):
        self.store.update(values); self.closed = True
    def get_raw(self, names, include_secret=False):
        if self.closed:
            raise ACPError("connection closed by base station")
        return FakeStation.get_raw(self, names)
    def reconnect(self):
        self.reconnects += 1; self.closed = False
with tempfile.TemporaryDirectory() as tmp:
    st = AckThenCloseStation(express_wifi_raw())
    r = wifi.set_wifi(st, False, tmp, "x")
    print("ack-then-close: written", r["written"], "reconnects", st.reconnects, "reboots", st.reboots)
    print("ACKCLOSE PASSED" if r["written"] and st.reconnects == 1 and st.reboots == 1 else "ACKCLOSE FAILED")
