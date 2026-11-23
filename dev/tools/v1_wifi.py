"""Experimental: Wi-Fi on/off for ACP version 1 units (AirPort Snow) via raSt.

  python3 tools/v1_wifi.py HOST status
  python3 tools/v1_wifi.py HOST off [--no-reboot]
  python3 tools/v1_wifi.py HOST on  [--no-reboot]

The Snow reports a top-level raSt (0 here, like the newer models' "on").
Whether 3 really switches its radio off is what this tests. Safety steps:
  1. read every known setting (the "before" snapshot) and save it (mode 0600)
  2. write only raSt, without restarting
  3. read everything again: raSt must be the new value and nothing else may
     have changed, otherwise the changed settings are written back
  4. then restart (unless --no-reboot) so the change takes effect
"""
import getpass, json, os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "AirPort.indigoPlugin", "Contents", "Server Plugin"))
from airport_acp import ACPError, AuthenticationError
from airport_acp.v1 import ACPv1Client, TAGS, SECRET_TAGS

if len(sys.argv) < 3 or sys.argv[2] not in ("status", "on", "off"):
    sys.exit(__doc__)
host, action = sys.argv[1], sys.argv[2]
reboot = "--no-reboot" not in sys.argv
WATCH = [t for t in TAGS if t not in SECRET_TAGS]   # includes raSt

client = ACPv1Client(host, getpass.getpass("Admin password: "))


def snapshot():
    return {k: v for k, v in client.get_raw(WATCH).items() if isinstance(v, bytes)}


try:
    before = snapshot()
    if "raSt" not in before:
        sys.exit("this unit did not return raSt")
    current = int.from_bytes(before["raSt"], "big")
    print("raSt is %d (%d bytes)" % (current, len(before["raSt"])))
    if action == "status":
        sys.exit(0)
    target = 0 if action == "on" else 3
    if current == target:
        sys.exit("already %d; nothing to do (restart the unit if the radio hasn't followed)" % target)

    state_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "state")
    os.makedirs(state_dir, exist_ok=True)
    backup = os.path.join(state_dir, "v1-%s-%s.json" % (host, time.strftime("%Y%m%d-%H%M%S")))
    fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump({k: v.hex() for k, v in before.items()}, fh, indent=1)
    print("backup:", backup)

    new = target.to_bytes(len(before["raSt"]), "big")
    client.set_raw({"raSt": new})
    time.sleep(1)
    after = snapshot()
    changed = sorted(k for k in set(before) | set(after) if k != "raSt" and before.get(k) != after.get(k))
    if after.get("raSt") != new or changed:
        print("verification FAILED: raSt=%s, other changes: %s" % (after.get("raSt", b"").hex(), changed or "none"))
        restore = {k: before[k] for k in changed + ["raSt"] if k in before}
        client.set_raw(restore)
        print("wrote back:", ", ".join(restore))
        sys.exit(1)
    print("verified: raSt now %d, no other setting changed" % target)
    if reboot:
        client.set_raw({}, reboot=True)
        print("restart requested; allow a couple of minutes, then check whether the network is visible")
    else:
        print("not restarted; the change applies at the next restart")
except AuthenticationError as err:
    sys.exit("login failed: %s" % err)
except (ACPError, OSError) as err:
    sys.exit("error: %s" % err)
