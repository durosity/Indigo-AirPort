"""Show the device states the plugin would display.  Usage: python3 tools/states.py HOST [HOST...]"""
import getpass, os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "AirPort.indigoPlugin", "Contents", "Server Plugin"))
from airport_acp import ACPClient, AuthenticationError, ACPError
from airport_acp.device import read_states

password = getpass.getpass("Admin password (used for all hosts): ")
if len(sys.argv) < 2:
    sys.exit(__doc__)
for host in sys.argv[1:]:
    try:
        start = time.time()
        with ACPClient(host, password) as client:
            states = read_states(client)
        print("\n== %s  (%.1fs)" % (host, time.time() - start))
        for key in sorted(states):
            print("   %-22s %s" % (key, states[key]))
    except AuthenticationError as err:
        print("\n== %s  login failed: %s" % (host, err))
    except (ACPError, OSError) as err:
        print("\n== %s  error: %s" % (host, err))
