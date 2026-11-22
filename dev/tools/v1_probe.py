"""Probe a base station speaking ACP version 1 (AirPort Snow, 802.11g models).

  python3 tools/v1_probe.py HOST           read the known settings
  python3 tools/v1_probe.py HOST --survey  also try every known property code

Secrets (admin password, read community, WEP key, phone numbers) are never requested.
"""
import getpass, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "AirPort.indigoPlugin", "Contents", "Server Plugin"))
from airport_acp import ACPError, AuthenticationError, PropertyError, PROPERTIES
from airport_acp.v1 import ACPv1Client, TAGS, SECRET_TAGS, decode, read_states
from airport_acp.redact import SECRET_TOP_LEVEL

if len(sys.argv) < 2:
    sys.exit(__doc__)
client = ACPv1Client(sys.argv[1], getpass.getpass("Admin password: "))
try:
    states, values = read_states(client)
except AuthenticationError as err:
    sys.exit("login failed: %s" % err)
except (ACPError, OSError) as err:
    sys.exit("error: %s" % err)

print("== states")
for k, v in states.items():
    print("   %-18s %s" % (k, v))
print("== known settings")
for tag in TAGS:
    if tag in values:
        print("   %s  %-32s %s" % (tag, TAGS[tag][2], values[tag]))
missing = [t for t in TAGS if t not in values and t not in SECRET_TAGS]
print("   not returned:", " ".join(missing) or "none")
print("== stored password matches:", {True: "yes", False: "NO", None: "n/a"}[client.password_matches_device()])

if "--survey" in sys.argv:
    codes = sorted(set(PROPERTIES) - set(TAGS) - SECRET_TOP_LEVEL - {"usrd"})
    found = {}
    for i in range(0, len(codes), 25):
        try:
            for name, value in client.get_raw(codes[i:i + 25]).items():
                if isinstance(value, bytes):
                    found[name] = value
        except ACPError as err:
            print("   batch %s.. failed: %s" % (codes[i], err))
    print("== other readable properties (%d of %d tried)" % (len(found), len(codes)))
    for name in sorted(found):
        print("   %s  %-28s %s" % (name, PROPERTIES[name][1][:28], found[name][:48].hex()))
