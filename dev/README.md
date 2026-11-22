# Development tools

Command-line tools and tests for the `airport_acp` library that ships inside the plugin
(`AirPort.indigoPlugin/Contents/Server Plugin/airport_acp`). They use the library in place,
so run them from this folder with `python3 tools/...`. Requires `cryptography`.

All tools prompt for the admin password (never echoed, logged or saved).

| Tool | What it does |
|---|---|
| `tools/states.py HOST [HOST...]` | Prints the device states the plugin would show |
| `tools/inventory.py HOST [HOST...]` | Tries every known property code and saves the results (secrets redacted) to `survey/HOST.json` |
| `tools/wifi.py HOST status\|on\|off\|restart\|restore FILE` | Wi-Fi control with the verified write path; `--radio N`, `--dry-run`, `--no-reboot` |
| `tools/legacy_probe.py HOST [--login]` | Graphite/Snow: UDP 192 discovery, then SNMP system info and the config block (raw block saved to `state/`) |
| `tools/compare_live.py HOST` | Reads properties with both this library and node-acp and compares them (needs node-acp installed in `~/acp-test`) |

Set `AIRPORT_DEBUG=1` to see the protocol trace.

`survey/` and `state/` are git-ignored: survey files describe your network and Wi-Fi backups contain Wi-Fi passwords.

## Tests

- `tests/test_offline.py` checks the CFB0 plist codec, SRP, message framing and session encryption against node-acp (needs node-acp and a survey from `~/acp-test`).
- `tests/test_wifi_offline.py` runs the Wi-Fi change logic against simulated base stations, including ones that drop the connection after a write (needs survey data).
- `tests/test_legacy_offline.py` runs the Graphite/Snow SNMP backend against a simulated base station.
