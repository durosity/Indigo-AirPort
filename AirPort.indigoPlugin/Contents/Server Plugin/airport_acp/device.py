"""Read-only device model: turn ACP properties into flat, display-ready states.

read_states(client) returns a dict suitable for Indigo device states. Common
states exist for every ACP (802.11n/ac era) unit; model extras (sensors, fan,
disks, AirPlay name) appear only when the unit reports them. Nothing secret
is ever included.
"""

import re

from .client import PropertyError
from .values import decode

COMMON = ["syNm", "syAM", "syAP", "syVs", "sySN", "syUT", "tmpC", "sySt", "WiFi", "raSL", "raSt", "raCh", "raNm",
          "waIP", "waMA", "waRA", "waSM", "raNA", "raDS", "LEDc", "timz", "ntSV"]
EXTRAS = ["sySI", "MaSt", "auNN"]

RADIO_MODES = {0: "on", 3: "off"}

# Known sySt problem codes (from the AirPort Utility "status" list); unknown
# codes are passed through as-is.
PROBLEMS = {
    "opNW": "open wireless network (no security)",
}


def _signed64(n):
    n = int(n)
    return n - (1 << 64) if n >= 1 << 63 else n


def _slug(text):
    return re.sub(r"[^a-z0-9]+", "_", str(text).lower()).strip("_")


def _uptime_text(seconds):
    seconds = int(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    return ("%dd " % days if days else "") + "%02d:%02d" % (hours, minutes)


def sensors(value):
    """sySI -> {slug: float}; absent sensors (negative sentinels) are skipped."""
    out = {}
    for entry in value or []:
        if not isinstance(entry, dict) or "name" not in entry:
            continue
        whole = _signed64(entry.get("value", 0))
        if whole < 0:
            continue
        out[_slug(entry["name"])] = round(whole + int(entry.get("thousandths", 0)) / 1000.0, 3)
    return out


def states_from(values):
    """Build states from {name: decoded value}."""
    s = {}
    g = values.get
    s["name"] = g("syNm") or ""
    s["model"] = g("syAM") or ""
    s["productId"] = int(g("syAP") or 0)
    s["firmware"] = g("syVs") or ""
    s["serialNumber"] = g("sySN") or ""
    if g("syUT") is not None:
        s["uptimeSeconds"] = int(g("syUT"))
        s["uptime"] = _uptime_text(g("syUT"))
    if g("tmpC"):  # 0 = unit has no temperature sensor
        s["temperatureC"] = round(int(g("tmpC")) / 10.0, 1)

    problems = [p.get("code", "?") for p in (g("sySt") or {}).get("problems", []) if isinstance(p, dict)]
    s["problemCount"] = len(problems)
    s["problems"] = ", ".join(PROBLEMS.get(c, c) for c in problems) or "none"

    radios = (g("WiFi") or {}).get("radios", []) if isinstance(g("WiFi"), dict) else []
    if not radios and g("raSt") is not None:
        # Older firmware (no WiFi blob): single radio described by top-level codes
        radios = [{"raSt": g("raSt"), "raCh": g("raCh"), "raNm": g("raNm")}]
    s["radioCount"] = len(radios)
    s["wifiEnabled"] = any(r.get("raSt") == 0 for r in radios)
    for i, radio in enumerate(radios, 1):
        mode = radio.get("raSt")
        s["radio%d_state" % i] = RADIO_MODES.get(mode, "mode %s" % mode)
        s["radio%d_channel" % i] = int(radio.get("raCh") or 0)
        s["radio%d_network" % i] = radio.get("raNm") or ""
    clients = g("raSL")
    s["clientCount"] = sum(len(v) for v in clients.values() if isinstance(v, list)) if isinstance(clients, dict) else 0

    s["ipAddress"] = g("waIP") or ""
    s["macAddress"] = g("waMA") or ""
    s["router"] = g("waRA") or ""
    s["subnetMask"] = g("waSM") or ""
    s["natEnabled"] = bool(g("raNA"))
    s["dhcpServerEnabled"] = bool(g("raDS"))
    if g("LEDc") is not None:
        s["ledMode"] = int(g("LEDc"))
    s["timeZone"] = (g("timz") or {}).get("zoneName", "") if isinstance(g("timz"), dict) else ""
    s["ntpServer"] = g("ntSV") or ""

    # Model extras
    for key, reading in sensors(g("sySI")).items():
        s[key if key.startswith("sensor_") else "sensor_" + key] = reading
    disks = g("MaSt")
    if isinstance(disks, list):
        s["diskCount"] = len(disks)
        for i, disk in enumerate(disks, 1):
            s["disk%d_name" % i] = (disk.get("vendor") or "").strip()
            s["disk%d_smart" % i] = disk.get("smartStatus", "")
            parts = disk.get("partitions") or []
            size = sum(int(p.get("size", 0)) for p in parts)
            used = sum(int(p.get("sizeUsed", 0)) for p in parts)
            s["disk%d_sizeMB" % i] = size
            s["disk%d_usedMB" % i] = used
            s["disk%d_freeMB" % i] = sum(int(p.get("sizeFree", 0)) for p in parts)
            s["disk%d_usedPercent" % i] = round(100.0 * used / size, 1) if size else 0.0
    if g("auNN"):
        s["airplayName"] = g("auNN")
    return s


def read_states(client):
    wanted = COMMON + EXTRAS
    raw = client.get_raw(wanted)
    values = {n: decode(n, v) for n, v in raw.items() if not isinstance(v, PropertyError)}
    return states_from(values)
