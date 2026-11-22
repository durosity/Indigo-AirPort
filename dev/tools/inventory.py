"""Read-only inventory of one or more ACP base stations.

Usage:  python3 tools/inventory.py HOST [HOST...]
Prompts once for the admin password (used for every host). For each host it
logs in, tries every known property code, and saves the results to
survey/<host>.json (raw hex + decoded value; syPW is never requested).
"""
import getpass, json, os, re, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "AirPort.indigoPlugin", "Contents", "Server Plugin"))
from airport_acp.redact import redact, REDACTED
from airport_acp import ACPClient, AuthenticationError, ACPError, PropertyError, SECRET_PROPERTIES, decode, PROPERTIES

HERE = os.path.join(os.path.dirname(__file__), "..")
OUT_DIR = os.path.join(HERE, "survey")
CODES_FILE = os.path.expanduser("~/acp-test/props.txt")


def all_codes():
    codes = set(PROPERTIES)
    if os.path.exists(CODES_FILE):
        codes.update(c for c in open(CODES_FILE).read().split("\n") if len(c) == 4)
    return sorted(codes - SECRET_PROPERTIES)


def jsonable(value):
    if isinstance(value, bytes):
        return {"hex": value.hex()}
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [jsonable(v) for v in value]
    if isinstance(value, float):
        return float(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return int(value)
    return value


def survey(host, password, codes):
    found, errors, start = {}, {}, time.time()
    with ACPClient(host, password) as client:
        for i in range(0, len(codes), 25):
            for name, value in client.get_raw(codes[i:i + 25]).items():
                if isinstance(value, PropertyError):
                    errors[name] = value.code
                else:
                    found[name] = value
        credential = client.password_matches_device()
    return found, errors, credential, time.time() - start


def radios(wifi):
    out = []
    for r in (wifi or {}).get("radios", []):
        out.append("ch%s %s" % (r.get("raCh"), {0: "on", 3: "off"}.get(r.get("raSt"), "raSt=%s" % r.get("raSt"))))
    return ", ".join(out) or "?"


def main():
    hosts = sys.argv[1:]
    if not hosts:
        sys.exit(__doc__)
    password = getpass.getpass("Admin password (used for all hosts): ")
    codes = all_codes()
    os.makedirs(OUT_DIR, exist_ok=True)
    print("Trying %d property codes on each host\n" % len(codes))
    for host in hosts:
        try:
            found, errors, credential, secs = survey(host, password, codes)
        except AuthenticationError as err:
            print("%-12s login failed: %s" % (host, err))
            continue
        except (ACPError, OSError) as err:
            print("%-12s error: %s" % (host, err))
            continue
        dec = {n: decode(n, v) for n, v in found.items()}
        record = {
            "host": host, "read_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "properties": {n: ({"hex": found[n].hex(), "value": jsonable(dec[n])}
                           if redact(n, dec[n]) == dec[n] else
                           {"hex": REDACTED, "value": jsonable(redact(n, dec[n]))}) for n in sorted(found)},
            "errors": dict(sorted(errors.items())),
        }
        path = os.path.join(OUT_DIR, "%s.json" % host)
        with open(path, "w") as fh:
            json.dump(record, fh, indent=1)
        status = [p.get("code") for p in (dec.get("sySt") or {}).get("problems", [])]
        clients = sum(len(v) for v in (dec.get("raSL") or {}).values()) if isinstance(dec.get("raSL"), dict) else "?"
        print("%-12s %-22s %-16s syAP %-4s fw %-7s up %6ss  radios: %s  clients: %s  problems: %s  credential: %s"
              % (host, dec.get("syNm"), dec.get("syAM"), dec.get("syAP"), dec.get("syVs"), dec.get("syUT"),
                 radios(dec.get("WiFi")), clients, ",".join(status) or "none",
                 {True: "ok", False: "MISMATCH", None: "n/a"}[credential]))
        print("%-12s %d readable, %d unavailable, %.1fs -> %s" % ("", len(found), len(errors), secs, path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
