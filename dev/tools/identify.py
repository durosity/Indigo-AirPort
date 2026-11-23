"""Work out how an AirPort base station must be talked to, then survey it.

  python3 tools/identify.py HOST

Without a password: UDP 192 discovery (Graphite), TCP 5009 and the reply
version to a features request (Snow-era v1 vs current ACP).
With the password (prompted): tries, in order, the encrypted login (SRP),
the older header-password login on the current protocol, ACP v1, and SNMP,
then reads the identity and saves a redacted survey of every known property
to survey/HOST.json for whichever method worked.
"""
import getpass, json, os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "AirPort.indigoPlugin", "Contents", "Server Plugin"))
from airport_acp import (ACPClient, ACPError, AuthenticationError, AuthenticationUnsupported, PropertyError,
                         PROPERTIES, AUTH_SRP, AUTH_HEADER, decode)
from airport_acp.redact import redact, REDACTED, SECRET_TOP_LEVEL
from airport_acp.scan import probe, GEN_V1, GEN_CURRENT, GEN_SNMP
from airport_acp import v1
from airport_legacy import LegacyBaseStation, SNMPError

if len(sys.argv) < 2:
    sys.exit(__doc__)
host = sys.argv[1]
HERE = os.path.dirname(os.path.abspath(__file__))

print("== without a password")
found = probe(host, timeout=2)
if not found:
    sys.exit("   nothing answered on TCP 5009 or UDP 192")
print("   generation:", found["generation"])
for k in ("name", "description"):
    if found.get(k):
        print("   %s: %s" % (k, found[k]))
if found["macs"]:
    print("   MACs:", ", ".join("%s %s" % kv for kv in found["macs"].items()))

password = getpass.getpass("Admin password: ")
codes = set(PROPERTIES)
extra = os.path.expanduser("~/acp-test/props.txt")
if os.path.exists(extra):
    codes.update(c for c in open(extra).read().split("\n") if len(c) == 4)
codes = sorted(codes - SECRET_TOP_LEVEL - v1.SECRET_TAGS - {"usrd"})


def survey(get):
    out, errors = {}, {}
    for i in range(0, len(codes), 25):
        try:
            for name, value in get(codes[i:i + 25]).items():
                if isinstance(value, PropertyError):
                    errors[name] = value.code
                elif isinstance(value, bytes):
                    out[name] = value
        except (ACPError, OSError) as err:
            print("   batch from %s failed: %s" % (codes[i], err))
    return out, errors


method = values = None
if found["generation"] == GEN_CURRENT:
    for auth in (AUTH_SRP, AUTH_HEADER):
        print("== trying current ACP, %s login" % ("encrypted (SRP)" if auth == AUTH_SRP else "header-password"))
        try:
            with ACPClient(host, password, auth=auth) as client:
                values, errors = survey(client.get_raw)
            method = "current ACP, %s" % auth
            break
        except AuthenticationUnsupported as err:
            print("   not supported:", err)
        except AuthenticationError as err:
            print("   password rejected:", err)
            break
        except (ACPError, OSError) as err:
            print("   failed:", err)
elif found["generation"] == GEN_V1:
    print("== trying ACP v1")
    client = v1.ACPv1Client(host, password)
    try:
        values, errors = survey(client.get_raw)
        method = "ACP v1"
    except AuthenticationError as err:
        print("   password rejected:", err)
elif found["generation"] == GEN_SNMP:
    print("== trying SNMP")
    try:
        station = LegacyBaseStation(host, password)
        print("   system:", station.system())
        method, values, errors = "SNMP", {}, {}
        print("   SNMP works: use tools/legacy_probe.py %s --login for the configuration block" % host)
    except SNMPError as err:
        print("   failed:", err)

if not method:
    sys.exit("no method worked")
print("== method that works:", method)
if values:
    show = ["syNm", "syAM", "syAP", "syVs", "syDs", "sySN", "syUT", "raSt", "raNm", "raCh", "WiFi"]
    for name in show:
        if name in values:
            text = decode(name, values[name]) if method.startswith("current") else v1.decode(name, values[name])
            print("   %-5s %s" % (name, str(redact(name, text))[:100]))
    print("   %d readable properties, %d refused" % (len(values), len(errors)))
    os.makedirs(os.path.join(HERE, "..", "survey"), exist_ok=True)
    path = os.path.join(HERE, "..", "survey", "%s.json" % host)
    record = {"host": host, "method": method, "generation": found["generation"],
              "read_at": time.strftime("%Y-%m-%d %H:%M:%S"),
              "properties": {n: (REDACTED if redact(n, decode(n, v)) != decode(n, v) else v.hex())
                             for n, v in sorted(values.items())},
              "errors": dict(sorted(errors.items()))}
    with open(path, "w") as fh:
        json.dump(record, fh, indent=1)
    print("   survey saved to", path)
