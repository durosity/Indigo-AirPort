"""Verified Wi-Fi on/off for ACP base stations.

Turning a radio off sets raSt=3 and dWDS=False on that radio in the WiFi
property (exactly what AirPort Utility writes). Turning it on sets raSt=0 and
restores dWDS to the value it had before it was turned off.

Every change follows the same safety sequence:
  1. read WiFi and check the encoder reproduces it byte-for-byte
  2. save a backup of the original bytes (contains Wi-Fi keys: mode 0600)
  3. build the new value and check it differs only in the intended fields
  4. write it, read it back, and require an exact match (else restore)
  5. restart the base station so the change takes effect
"""

import copy
import json
import os
import logging
import time

from . import cflbinary
from .client import ACPError, PropertyError
from .cflbinary import SizedInt

ON, OFF = 0, 3
log = logging.getLogger("airport_acp")


class WiFiChangeError(ACPError):
    pass


def _changed_paths(before, after, path=""):
    if isinstance(before, dict) and isinstance(after, dict):
        out = []
        for k in set(before) | set(after):
            out += _changed_paths(before.get(k), after.get(k), "%s.%s" % (path, k))
        return out
    if isinstance(before, list) and isinstance(after, list) and len(before) == len(after):
        out = []
        for i, (b, a) in enumerate(zip(before, after)):
            out += _changed_paths(b, a, "%s[%d]" % (path, i))
        return out
    return [] if before == after and type(before) is type(after) else [path]


def _with_width(template, value):
    return SizedInt(value, getattr(template, "width", None))


def _read_wifi(client):
    raw = client.get_raw(["WiFi"]).get("WiFi")
    if not isinstance(raw, bytes):
        raise WiFiChangeError("could not read WiFi: %s" % raw)
    obj = cflbinary.parse(raw)
    if cflbinary.compose(obj) != raw:
        raise WiFiChangeError("encoder cannot reproduce this unit's WiFi bytes; refusing to write")
    if not isinstance(obj, dict) or not isinstance(obj.get("radios"), list) or not obj["radios"]:
        raise WiFiChangeError("unexpected WiFi layout")
    return raw, obj


def _has_wifi_blob(client):
    return isinstance(client.get_raw(["WiFi"]).get("WiFi"), bytes)


def wifi_status(client):
    if not _has_wifi_blob(client):
        raw = client.get_raw(["raSt"]).get("raSt")
        if not isinstance(raw, bytes):
            raise WiFiChangeError("this unit reports neither WiFi nor raSt")
        return [int.from_bytes(raw, "big")]
    _, obj = _read_wifi(client)
    return [r.get("raSt") for r in obj["radios"]]


TOP_LEVEL_WATCH = ["raSt", "raNm", "raCh", "raMd", "raPo", "raNA", "raDS", "waIP", "waRA", "waSM", "syNm"]


def _set_wifi_top_level(client, enable, state_dir, host_id, radios, reboot, dry_run):
    """Older firmware without the WiFi blob (e.g. 802.11g units): a top-level raSt.

    Untested on real hardware: the snapshot check refuses to call a write
    successful unless raSt changed and nothing else did.
    """
    if radios not in (None, [0]):
        raise WiFiChangeError("this unit has a single radio setting")
    before = {k: v for k, v in client.get_raw(TOP_LEVEL_WATCH).items() if isinstance(v, bytes)}
    if "raSt" not in before:
        raise WiFiChangeError("this unit reports neither WiFi nor raSt")
    current = int.from_bytes(before["raSt"], "big")
    target = ON if enable else OFF
    result = {"changed": [], "written": False, "rebooted": False, "backup": None, "method": "raSt"}
    if current == target:
        result["note"] = "already %s" % ("on" if enable else "off")
        return result
    result["changed"] = [".raSt"]
    if dry_run:
        result["note"] = "dry run: nothing written"
        return result
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup = os.path.join(state_dir, "%s-raSt-%s.json" % (host_id, stamp))
    fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump({k: v.hex() for k, v in before.items()}, fh)
    result["backup"] = backup
    new = target.to_bytes(len(before["raSt"]), "big")
    try:
        client.set_raw({"raSt": new})
    except PropertyError:
        raise
    except (ACPError, OSError) as err:
        log.debug("connection lost during write (%s); reconnecting to verify", err)
        result["reconnected"] = True
        client.reconnect()
    try:
        after = {k: v for k, v in client.get_raw(TOP_LEVEL_WATCH).items() if isinstance(v, bytes)}
    except (ACPError, OSError):
        result["reconnected"] = True
        client.reconnect()
        after = {k: v for k, v in client.get_raw(TOP_LEVEL_WATCH).items() if isinstance(v, bytes)}
    others = [k for k in set(before) | set(after) if k != "raSt" and before.get(k) != after.get(k)]
    if after.get("raSt") != new or others:
        restore = {k: before[k] for k in others + ["raSt"] if k in before}
        client.set_raw(restore)
        raise WiFiChangeError("read-back check failed (raSt %s, other changes %s); original written back"
                              % (after.get("raSt", b"").hex(), others or "none"))
    result["written"] = True
    if reboot:
        client.reboot()
        result["rebooted"] = True
    return result


def plan(obj, enable, radios=None, memory=None):
    """Return (new_obj, changed_paths, memory) without touching the device."""
    memory = dict(memory or {})
    new = copy.deepcopy(obj)
    indexes = range(len(new["radios"])) if radios is None else radios
    for i in indexes:
        if i >= len(new["radios"]):
            raise WiFiChangeError("unit has %d radio(s); no radio %d" % (len(new["radios"]), i + 1))
        radio = new["radios"][i]
        if "raSt" not in radio:
            raise WiFiChangeError("radio %d has no raSt field" % (i + 1))
        if enable and radio["raSt"] == OFF:
            radio["raSt"] = _with_width(radio["raSt"], ON)
            if "dWDS" in radio:
                radio["dWDS"] = bool(memory.get(str(i), True))
        elif not enable and radio["raSt"] == ON:
            if "dWDS" in radio:
                memory[str(i)] = bool(radio["dWDS"])
                radio["dWDS"] = False
            radio["raSt"] = _with_width(radio["raSt"], OFF)
    changed = sorted(_changed_paths(obj, new))
    allowed = {".radios[%d].%s" % (i, f) for i in range(len(new["radios"])) for f in ("raSt", "dWDS")}
    unexpected = [p for p in changed if p not in allowed]
    if unexpected:
        raise WiFiChangeError("plan would change unexpected fields: %s" % unexpected)
    return new, changed, memory


def set_wifi(client, enable, state_dir, host_id, radios=None, reboot=True, dry_run=False):
    """Turn Wi-Fi on/off. Returns a dict describing what happened."""
    os.makedirs(state_dir, exist_ok=True)
    mem_path = os.path.join(state_dir, "%s-wifi-memory.json" % host_id)
    memory = json.load(open(mem_path)) if os.path.exists(mem_path) else {}

    if not _has_wifi_blob(client):
        return _set_wifi_top_level(client, enable, state_dir, host_id, radios, reboot, dry_run)
    raw, obj = _read_wifi(client)
    new, changed, memory = plan(obj, enable, radios, memory)
    result = {"changed": changed, "written": False, "rebooted": False, "backup": None}
    if not changed:
        result["note"] = "already %s" % ("on" if enable else "off")
        return result
    new_raw = cflbinary.compose(new)
    if cflbinary.parse(new_raw) != new:
        raise WiFiChangeError("new WiFi value does not survive a parse round-trip")
    if dry_run:
        result["note"] = "dry run: nothing written"
        return result

    stamp = time.strftime("%Y%m%d-%H%M%S")
    for n in range(1000):
        backup = os.path.join(state_dir, "%s-WiFi-%s%s.cfb" % (host_id, stamp, "-%d" % n if n else ""))
        try:
            fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            break
        except FileExistsError:
            continue
    else:
        raise WiFiChangeError("could not create a backup file")
    with os.fdopen(fd, "wb") as fh:
        fh.write(raw)
    result["backup"] = backup

    log.debug("writing WiFi (%d bytes, was %d)", len(new_raw), len(raw))
    try:
        client.set_raw({"WiFi": new_raw})
        log.debug("write acknowledged, reading back")
    except PropertyError:
        raise
    except (ACPError, OSError) as err:
        # Some models (seen on AirPort5,105) store the value and then drop the
        # connection without replying. Log in again and let the read-back decide.
        log.debug("connection lost during write (%s); reconnecting to verify", err)
        result["reconnected"] = True
        client.reconnect()
    try:
        check = client.get_raw(["WiFi"]).get("WiFi")
    except PropertyError:
        raise
    except (ACPError, OSError) as err:
        # AirPort5,105 acknowledges the write, then closes the session.
        log.debug("connection lost before read-back (%s); reconnecting to verify", err)
        result["reconnected"] = True
        client.reconnect()
        check = client.get_raw(["WiFi"]).get("WiFi")
    if check != new_raw:
        try:
            client.set_raw({"WiFi": raw})
        finally:
            raise WiFiChangeError("read-back did not match what was written; original restored")
    result["written"] = True
    with open(mem_path, "w") as fh:
        json.dump(memory, fh)
    if reboot:
        client.reboot()
        result["rebooted"] = True
    return result


def restore(client, backup_path, reboot=True):
    raw = open(backup_path, "rb").read()
    cflbinary.parse(raw)  # must be a valid WiFi value
    client.set_raw({"WiFi": raw})
    if client.get_raw(["WiFi"]).get("WiFi") != raw:
        raise WiFiChangeError("restore read-back did not match")
    if reboot:
        client.reboot()
