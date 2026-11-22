"""Probe an original AirPort (Graphite / Snow): discovery, SNMP system info, config block.

  python3 tools/legacy_probe.py HOST            discovery only (no password)
  python3 tools/legacy_probe.py HOST --login    also read over SNMP (prompts for password)

With --login the raw configuration block is saved to state/legacy-HOST.bin
(mode 0600: it contains the base station password and WEP keys).
"""
import getpass, os, socket, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "AirPort.indigoPlugin", "Contents", "Server Plugin"))
from airport_legacy import discover, LegacyBaseStation, SNMPError, SNMPTimeout, decode_config
from airport_legacy.legacy import checksum

if len(sys.argv) < 2:
    sys.exit(__doc__)
host = sys.argv[1]

print("== discovery (UDP 192)")
found = discover(host, timeout=3)
if not found:
    print("   no reply on UDP 192")
for address, info in found.items():
    for k, v in info.items():
        print("   %-12s %s" % (k, v))

print("== ports")
for port, label in [(5009, "ACP (TCP 5009)")]:
    s = socket.socket(); s.settimeout(2)
    print("   %-16s %s" % (label, "open" if s.connect_ex((host, port)) == 0 else "closed"))
    s.close()

if "--login" not in sys.argv:
    sys.exit(0)

station = LegacyBaseStation(host, getpass.getpass("Base station password: "))
try:
    print("== SNMP system")
    for k, v in station.system().items():
        print("   %-14s %s" % (k, v))
except SNMPTimeout:
    sys.exit("   no SNMP reply: wrong password, SNMP disabled, or not reachable")

print("== configuration block")
raw = station.read_config()
state_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "state")
os.makedirs(state_dir, exist_ok=True)
path = os.path.join(state_dir, "legacy-%s.bin" % host)
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "wb") as fh:
    fh.write(raw)
cfg = decode_config(raw)
for k, v in cfg.items():
    print("   %-20s %s" % (k, v))
print("   computed checksum    %d (stored %d; Sevy notes the read-back copy may not match)" % (checksum(raw), cfg["storedChecksum"]))
print("   saved %d bytes to %s" % (len(raw), path))

print("== wireless clients")
clients = station.clients()
print("   " + ("not available" if clients is None else "%d: %s" % (len(clients), ", ".join(clients) or "none")))

print("== enterprise MIB (1.3.6.1.4.1.762.2.5)")
try:
    for oid, value in station.walk("1.3.6.1.4.1.762.2.5")[:60]:
        print("   %s = %r" % (oid, value if not isinstance(value, bytes) else value.hex()))
except SNMPError as err:
    print("   walk failed:", err)
