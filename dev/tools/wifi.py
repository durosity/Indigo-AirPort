"""Turn Wi-Fi on/off with the verified write path.

  python3 tools/wifi.py HOST status
  python3 tools/wifi.py HOST off  [--radio N] [--dry-run] [--no-reboot]
  python3 tools/wifi.py HOST on   [--radio N] [--dry-run] [--no-reboot]
  python3 tools/wifi.py HOST restart
  python3 tools/wifi.py HOST restore BACKUP.cfb

Backups and the remembered dWDS values go in ~/airport-lib/state/ (mode 0600;
backups contain the unit's Wi-Fi password).
"""
import argparse, getpass, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "AirPort.indigoPlugin", "Contents", "Server Plugin"))
from airport_acp import ACPClient, AuthenticationError, ACPError, wifi

STATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "state")

ap = argparse.ArgumentParser()
ap.add_argument("host"); ap.add_argument("action", choices=["status", "on", "off", "restore", "restart"])
ap.add_argument("backup", nargs="?"); ap.add_argument("--radio", type=int, action="append")
ap.add_argument("--dry-run", action="store_true"); ap.add_argument("--no-reboot", action="store_true")
args = ap.parse_args()
if os.environ.get("AIRPORT_DEBUG"):
    import logging
    logging.basicConfig(level=logging.DEBUG, format="      %(message)s")

password = getpass.getpass("Admin password for %s: " % args.host)
names = {0: "on", 3: "off"}
try:
    with ACPClient(args.host, password) as client:
        if args.action == "status":
            print("radios:", ", ".join("%d: %s" % (i, names.get(s, "mode %s" % s))
                                       for i, s in enumerate(wifi.wifi_status(client), 1)))
        elif args.action == "restart":
            client.reboot()
            print("restart requested (allow ~1 minute)")
        elif args.action == "restore":
            if not args.backup:
                sys.exit("restore needs a backup file")
            wifi.restore(client, args.backup, reboot=not args.no_reboot)
            print("restored from", args.backup, "" if args.no_reboot else "and restarting")
        else:
            radios = [r - 1 for r in args.radio] if args.radio else None
            r = wifi.set_wifi(client, args.action == "on", STATE_DIR, args.host.replace(":", "_"),
                              radios=radios, reboot=not args.no_reboot, dry_run=args.dry_run)
            print("fields to change:" if args.dry_run else "fields changed:", ", ".join(r["changed"]) or "none")
            if r.get("note"):
                print(r["note"], "(stored setting; if the radio hasn't changed yet, run: restart)"
                      if r["note"].startswith("already") else "")
            if r["backup"]:
                print("backup:", r["backup"])
            if r.get("reconnected"):
                print("note: the unit dropped the connection during the write; reconnected and verified")
            if r["written"]:
                print("written and verified by read-back;", "restarting now (allow ~1 minute)" if r["rebooted"] else "not restarted (change applies at next restart)")
except AuthenticationError as err:
    sys.exit("login failed: %s" % err)
except (ACPError, OSError) as err:
    sys.exit("error: %s" % err)
