"""Experimental: Wi-Fi on/off for ACP version 1 units via a top-level raSt.

  python3 tools/v1_wifi.py HOST status
  python3 tools/v1_wifi.py HOST off [--no-reboot]
  python3 tools/v1_wifi.py HOST on  [--no-reboot]

Tested on the AirPort Snow (4.0.9): the setting is stored but the radio
ignores it. Kept for the 802.11g generation, which may honour it.
Safety: snapshot + backup (0600), write raSt only, verify nothing else
changed (else write back), then restart.
"""
import getpass, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "AirPort.indigoPlugin", "Contents", "Server Plugin"))
from airport_acp import ACPError, AuthenticationError
from airport_acp.v1 import ACPv1Client, set_wifi

if len(sys.argv) < 3 or sys.argv[2] not in ("status", "on", "off"):
    sys.exit(__doc__)
host, action = sys.argv[1], sys.argv[2]
client = ACPv1Client(host, getpass.getpass("Admin password: "))
state_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "state")
try:
    if action == "status":
        raw = client.get_raw(["raSt"]).get("raSt")
        print("raSt is", int.from_bytes(raw, "big") if isinstance(raw, bytes) else "not reported")
        sys.exit(0)
    r = set_wifi(client, action == "on", state_dir, host, reboot="--no-reboot" not in sys.argv)
    if r.get("note"):
        print(r["note"])
    if r["backup"]:
        print("backup:", r["backup"])
    if r["written"]:
        print("verified: raSt changed and nothing else;", "restart requested" if r["rebooted"] else "not restarted")
    if r["radio_may_ignore"]:
        print("note: this model is known to ignore raSt (the radio stays as it was)")
except AuthenticationError as err:
    sys.exit("login failed: %s" % err)
except (ACPError, OSError) as err:
    sys.exit("error: %s" % err)
