"""Live check: read every surveyed property with airport_acp and with node-acp, compare.

Usage (from ~/airport-lib, Node 20 on PATH for the node-acp half):
    python3 tools/compare_live.py HOST
The password is prompted for, never echoed, logged or written to disk.
"""
import getpass, json, os, re, subprocess, sys, tempfile, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "AirPort.indigoPlugin", "Contents", "Server Plugin"))
from airport_acp import ACPClient, AuthenticationError, PropertyError, SECRET_PROPERTIES, decode

NODE_DIR = os.path.expanduser("~/acp-test")
SURVEY = os.path.join(NODE_DIR, "survey", "all.txt")
DYNAMIC = {"syUT", "time", "ctim", "logm", "raSR", "CLTM", "sySI", "tmpC", "DynS", "waDI",
           "rteI", "raSL", "sySt", "syIg", "sPLL", "fe01", "cks1", "cks2", "raLF", "raII", "USBi"}


def surveyed_names():
    names = re.findall(r"^Prop (.{4}) value", open(SURVEY).read(), re.M)
    return [n for n in dict.fromkeys(names) if n not in SECRET_PROPERTIES]


def read_python(host, password, names):
    out, start = {}, time.time()
    with ACPClient(host, password) as client:
        for i in range(0, len(names), 25):
            batch = names[i:i + 25]
            t = time.time()
            print("   reading %s..%s (%d)" % (batch[0], batch[-1], len(batch)), end="", flush=True)
            out.update(client.get_raw(batch))
            print("  %.1fs" % (time.time() - t))
        match = client.password_matches_device()
    return out, match, time.time() - start


def read_node(host, password, names):
    out = {}
    with tempfile.TemporaryDirectory() as tmp:
        for i in range(0, len(names), 50):
            lst = os.path.join(tmp, "batch%d" % i)
            open(lst, "w").write("\n".join(names[i:i + 50]))
            res = subprocess.run(["npx", "acp", "--host", host, "--password", password,
                                  "dumpprops", lst, "--all", "--json"],
                                 cwd=NODE_DIR, capture_output=True, text=True)
            for m in re.finditer(r"^Prop (.{4}) value: (\{.*\})\s*$", res.stdout, re.M):
                out[m.group(1)] = bytes(json.loads(m.group(2))["data"])
    return out


def main():
    if os.environ.get("AIRPORT_DEBUG"):
        import logging
        logging.basicConfig(level=logging.DEBUG, format="      %(message)s")
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    host = sys.argv[1]
    password = getpass.getpass("Admin password for %s: " % host)
    names = surveyed_names()
    try:
        py, match, secs = read_python(host, password, names)
    except AuthenticationError as err:
        print("airport_acp: authentication failed (%s)" % err)
        return 1
    errors = {n: v for n, v in py.items() if isinstance(v, PropertyError)}
    values = {n: v for n, v in py.items() if isinstance(v, bytes)}
    print("airport_acp: %d properties read in %.1fs, %d errors, credential check: %s"
          % (len(values), secs, len(errors), {True: "ok", False: "MISMATCH", None: "unavailable"}[match]))
    for n, e in errors.items():
        print("   error:", e)

    nd = read_node(host, password, names)
    print("node-acp:    %d properties read" % len(nd))
    same = [n for n in values if nd.get(n) == values[n]]
    dyn = [n for n in values if n in nd and nd[n] != values[n] and n in DYNAMIC]
    diff = [n for n in values if n in nd and nd[n] != values[n] and n not in DYNAMIC]
    missing = [n for n in values if n not in nd] + [n for n in nd if n not in values]
    print("identical: %d   changed (expected, live values): %d   UNEXPECTED differences: %d   missing: %d"
          % (len(same), len(dyn), len(diff), len(missing)))
    if dyn:
        print("   live values:", " ".join(dyn))
    if diff:
        print("   UNEXPECTED:", " ".join(diff))
    if missing:
        print("   missing on one side:", " ".join(missing))

    print("\nDecoded sample:")
    for n in ["syNm", "syAM", "syAP", "syVs", "sySN", "syUT", "tmpC", "sySt", "raSL", "waIP", "LEDc"]:
        if n in values:
            print("   %s = %s" % (n, decode(n, values[n])))
    return 0 if not diff and not missing and not errors else 2


if __name__ == "__main__":
    sys.exit(main())
