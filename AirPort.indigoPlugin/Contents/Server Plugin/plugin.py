#! /usr/bin/env python
# -*- coding: utf-8 -*-
# AirPort - Indigo plugin for Apple AirPort base stations and Time Capsules
# Author: Durosity
# ACP protocol support ported in part from node-acp (MIT, (c) Samuel Elliott).

import json
import logging
import os
import queue
import threading
import time
import xml.etree.ElementTree as ET

import indigo

from airport_acp import ACPClient, ACPError, AuthenticationError
from airport_acp import wifi as wifi_ops
from airport_acp.device import read_states, _uptime_text
from airport_acp.v1 import ACPv1Client, read_states as v1_read_states, decode as v1_decode
from airport_acp.scan import scan as acp_scan, GEN_V1, GEN_CURRENT, GEN_SNMP
from airport_acp.values import decode as acp_decode
from airport_legacy import (LegacyBaseStation, LegacyError, SNMPError, SNMPTimeout,
                            discover as legacy_discover, read_states as legacy_read_states)

try:
    from zeroconf import Zeroconf, ServiceBrowser, ServiceStateChange
except ImportError:  # plugin still works by IP address without Bonjour
    Zeroconf = None

PLUGIN_ID = "com.durosity.indigoplugin.airport"
DEVICE_TYPE = "airportBaseStation"
LEGACY_TYPE = "legacyBaseStation"
V1_TYPE = "acpV1BaseStation"
BONJOUR_SERVICE = "_airport._tcp.local."
RESTART_GRACE = 300     # seconds a unit may stay unreachable after we restart it
RESTART_POLL = 15       # poll interval while waiting for a restart to finish
MIN_POLL = 30


def _norm_mac(text):
    return str(text or "").replace("-", ":").lower()


def _usable_ipv4(addresses):
    for address in addresses or []:
        if address.count(".") == 3 and not address.startswith("169.254."):
            return address
    return ""


def _parse_txt(raw):
    """AirPort TXT records hold comma-separated key=value pairs."""
    out, i = {}, 0
    raw = raw or b""
    while i < len(raw):
        length = raw[i]
        entry = raw[i + 1:i + 1 + length].decode("utf-8", "replace")
        i += 1 + length
        for part in entry.split(","):
            if "=" in part:
                key, value = part.split("=", 1)
                out[key.strip()] = value.strip()
    return out


class Plugin(indigo.PluginBase):

    def __init__(self, plugin_id, plugin_display_name, plugin_version, plugin_prefs, **kwargs):
        super().__init__(plugin_id, plugin_display_name, plugin_version, plugin_prefs, **kwargs)
        self.debug = bool(plugin_prefs.get("showDebugInfo", False))
        self.locks = {}
        self.next_poll = {}
        self.restarting = {}        # dev.id -> deadline
        self.restart_started = {}   # dev.id -> time the restart was requested
        self.pending = {}           # dev.id -> True while a stored change awaits restart
        self.last_uptime = {}
        self.bonjour = {}           # service name -> {"txt": {...}, "addresses": [...]}
        self.bonjour_queue = queue.Queue()
        self.zeroconf = None
        self.browser = None
        self.static_states = self._load_static_states()
        self.recheck_create = False

    # ------------------------------------------------------------------ lifecycle
    def startup(self):
        self._apply_logging()
        if self.pluginPrefs.get("bonjourEnabled", True):
            self._start_bonjour()
        self.logger.info("AirPort plugin started")

    def shutdown(self):
        self._stop_bonjour()

    def closedPrefsConfigUi(self, values_dict, user_cancelled):
        if user_cancelled:
            return
        self.debug = bool(values_dict.get("showDebugInfo", False))
        self.pluginPrefs["traceProtocol"] = bool(values_dict.get("traceProtocol", False))
        self._apply_logging()
        if values_dict.get("bonjourEnabled", True):
            self._start_bonjour()
        else:
            self._stop_bonjour()
        if values_dict.get("autoCreate", False):
            self.recheck_create = True   # handled on the main loop

    def _apply_logging(self):
        level = logging.DEBUG if self.debug else logging.INFO
        self.indigo_log_handler.setLevel(level)
        lib = logging.getLogger("airport_acp")
        if self.indigo_log_handler not in lib.handlers:
            lib.addHandler(self.indigo_log_handler)
        lib.propagate = False
        trace = self.debug and bool(self.pluginPrefs.get("traceProtocol", False))
        lib.setLevel(logging.DEBUG if trace else logging.INFO)

    def _load_static_states(self):
        # Indigo runs plugin.py without __file__; the working directory is
        # the bundle's "Server Plugin" folder, and pluginFolderPath is the bundle.
        candidates = [os.path.join(os.getcwd(), "Devices.xml")]
        folder = getattr(self, "pluginFolderPath", None)
        if folder:
            candidates.insert(0, os.path.join(folder, "Contents", "Server Plugin", "Devices.xml"))
        for path in candidates:
            try:
                root = ET.parse(path).getroot()
                return {s.get("id") for s in root.iter("State")}
            except Exception:
                continue
        self.logger.warning("could not read Devices.xml; model-specific states may be duplicated")
        return set()

    # ------------------------------------------------------------------ devices
    def deviceStartComm(self, dev):
        self.locks.setdefault(dev.id, threading.Lock())
        self.next_poll[dev.id] = 0
        dev.stateListOrDisplayStateIdChanged()
        if not dev.pluginProps.get("password"):
            self._set_status(dev, "no password", "not set", error=True)

    def deviceStopComm(self, dev):
        self.next_poll.pop(dev.id, None)

    def validateDeviceConfigUi(self, values_dict, type_id, dev_id):
        errors = indigo.Dict()
        if not values_dict.get("address", "").strip():
            errors["address"] = "Enter the base station's IP address or hostname."
        try:
            if int(values_dict.get("pollInterval", 300)) < MIN_POLL:
                errors["pollInterval"] = "Use at least %d seconds." % MIN_POLL
        except ValueError:
            errors["pollInterval"] = "Enter a number of seconds."
        if errors:
            return False, values_dict, errors
        values_dict["address"] = values_dict["address"].strip()
        return True, values_dict

    def getDeviceStateList(self, dev):
        state_list = indigo.PluginBase.getDeviceStateList(self, dev)
        try:
            extras = json.loads(dev.pluginProps.get("extraStates", "[]"))
        except ValueError:
            extras = []
        for key, kind in extras:
            label = key.replace("_", " ")
            if kind == "Number":
                state_list.append(self.getDeviceStateDictForNumberType(key, label, label))
            elif kind == "Boolean":
                state_list.append(self.getDeviceStateDictForBoolTrueFalseType(key, label, label))
            else:
                state_list.append(self.getDeviceStateDictForStringType(key, label, label))
        return state_list

    # ------------------------------------------------------------------ main loop
    def runConcurrentThread(self):
        try:
            while True:
                self._drain_bonjour()
                if self.recheck_create:
                    self.recheck_create = False
                    for name, entry in sorted(self.bonjour.items()):
                        self._create_for(name, entry, respect_history=True)
                now = time.time()
                for dev in indigo.devices.iter("self"):
                    if dev.enabled and dev.configured and now >= self.next_poll.get(dev.id, now + 1):
                        self._poll(dev)
                self.sleep(1)
        except self.StopThread:
            pass

    def _interval(self, dev):
        try:
            return max(MIN_POLL, int(dev.pluginProps.get("pollInterval", 300)))
        except ValueError:
            return 300

    def _client(self, dev):
        props = dev.pluginProps
        return ACPClient(props.get("address", ""), props.get("password", ""))

    # ------------------------------------------------------------------ polling
    def _poll(self, dev):
        lock = self.locks.setdefault(dev.id, threading.Lock())
        if not lock.acquire(blocking=False):
            return
        try:
            self._poll_locked(dev)
        finally:
            lock.release()

    def _poll_locked(self, dev):
        if dev.deviceTypeId == LEGACY_TYPE:
            self._poll_legacy(dev)
            return
        if dev.deviceTypeId == V1_TYPE:
            self._poll_v1(dev)
            return
        now = time.time()
        if not dev.pluginProps.get("password"):
            self._set_status(dev, "no password", "not set", error=True)
            self.next_poll[dev.id] = now + self._interval(dev)
            return
        restarting = self.restarting.get(dev.id)
        try:
            with self._client(dev) as client:
                states = read_states(client)
                matches = client.password_matches_device()
        except AuthenticationError:
            self.logger.error('"%s": the base station rejected the stored password' % dev.name)
            self._set_status(dev, "password rejected", "password rejected", error=True)
            self.next_poll[dev.id] = now + self._interval(dev)
            return
        except (ACPError, OSError) as err:
            if restarting and now < restarting:
                self._set_status(dev, "restarting")
                self.next_poll[dev.id] = now + RESTART_POLL
                self.logger.debug('"%s": still restarting (%s)' % (dev.name, err))
            else:
                self.restarting.pop(dev.id, None)
                if dev.states.get("status") != "offline":
                    self.logger.warning('"%s": not reachable (%s)' % (dev.name, err))
                self._set_status(dev, "offline", error=True)
                self.next_poll[dev.id] = now + self._interval(dev)
            return

        uptime = states.get("uptimeSeconds")
        previous = self.last_uptime.get(dev.id)
        started = self.restart_started.get(dev.id)
        if uptime is not None:
            self.last_uptime[dev.id] = uptime
        if restarting is not None and uptime is not None and started is not None:
            if uptime > (now - started) + 30 and now < restarting:
                # Still the pre-restart session: older units take a while to go down.
                self._set_status(dev, "restarting")
                self.next_poll[dev.id] = now + RESTART_POLL
                return
        restarted = (restarting is not None) or (previous is not None and uptime is not None and uptime < previous)
        if restarted:
            self.pending.pop(dev.id, None)
            if restarting is not None:
                self.logger.info('"%s": back online after restart' % dev.name)
        self.restarting.pop(dev.id, None)
        self.restart_started.pop(dev.id, None)

        credential = {True: "ok", False: "password changed on device", None: "ok"}[matches]
        self._update_states(dev, states, credential)
        self.next_poll[dev.id] = now + self._interval(dev)

    def _update_states(self, dev, states, credential):
        extras = []
        for key, value in states.items():
            if key in self.static_states:
                continue
            kind = "Boolean" if isinstance(value, bool) else "Number" if isinstance(value, (int, float)) else "String"
            extras.append([key, kind])
        extras.sort()
        if json.dumps(extras) != dev.pluginProps.get("extraStates", "[]"):
            props = dev.pluginProps
            props["extraStates"] = json.dumps(extras)
            dev.replacePluginPropsOnServer(props)
            dev.stateListOrDisplayStateIdChanged()
            dev = indigo.devices[dev.id]

        for i in range(states.get("radioCount", 0) + 1, 3):
            states.setdefault("radio%d_state" % i, "n/a")
            states.setdefault("radio%d_channel" % i, 0)
            states.setdefault("radio%d_network" % i, "")

        live = self._bonjour_live(dev, states)
        setting_on = bool(states.get("wifiEnabled"))
        pending = bool(self.pending.get(dev.id)) or (live in ("on", "off") and (live == "on") != setting_on)

        updates = [{"key": k, "value": v} for k, v in states.items() if k != "temperatureC"]
        updates += [
            {"key": "onOffState", "value": setting_on, "uiValue": self._on_off_ui(setting_on, pending)},
            {"key": "status", "value": "online"},
            {"key": "credentialStatus", "value": credential},
            {"key": "wifiLive", "value": live},
            {"key": "wifiPending", "value": pending},
            {"key": "lastUpdate", "value": time.strftime("%Y-%m-%d %H:%M:%S")},
        ]
        if "temperatureC" in states:
            updates.append({"key": "temperatureC", "value": states["temperatureC"],
                            "uiValue": "%.1f °C" % states["temperatureC"]})
        dev.updateStatesOnServer(updates)
        dev.setErrorStateOnServer(None)

    def _set_status(self, dev, status, credential=None, error=False):
        updates = [{"key": "status", "value": status}]
        if credential is not None and "credentialStatus" in dev.states:
            updates.append({"key": "credentialStatus", "value": credential})
        if status == "restarting" and dev.deviceTypeId == DEVICE_TYPE:
            # Keep the on/off value (HomeKit still sees the setting) but show
            # "restarting" in the State column.
            updates.append({"key": "onOffState", "value": dev.onState, "uiValue": "restarting"})
        dev.updateStatesOnServer(updates)
        dev.setErrorStateOnServer(status if error else None)

    @staticmethod
    def _on_off_ui(on, pending):
        return ("on" if on else "off") + (" (pending)" if pending else "")

    # ------------------------------------------------------------------ Graphite / Snow
    def _poll_legacy(self, dev):
        now = time.time()
        self.next_poll[dev.id] = now + self._interval(dev)
        address = dev.pluginProps.get("address", "")
        if not dev.pluginProps.get("password"):
            self._set_status(dev, "no password", error=True)
            return
        try:
            states, _raw = legacy_read_states(LegacyBaseStation(address, dev.pluginProps.get("password")))
        except SNMPTimeout:
            # SNMPv1 ignores a wrong community, so tell "wrong password" apart
            # from "unreachable" by asking the unit to identify itself.
            try:
                answered = bool(legacy_discover(address, timeout=1.5))
            except OSError:
                answered = False
            status = "no SNMP reply (check password)" if answered else "offline"
            if dev.states.get("status") != status:
                self.logger.warning('"%s": %s' % (dev.name, status))
            self._set_status(dev, status, error=True)
            return
        except (SNMPError, LegacyError, OSError) as err:
            self.logger.warning('"%s": read failed: %s' % (dev.name, err))
            self._set_status(dev, "error", error=True)
            return
        states["uptime"] = _uptime_text(states.get("uptimeSeconds", 0))
        updates = [{"key": k, "value": v} for k, v in states.items() if k in dev.states]
        updates += [{"key": "status", "value": "online"},
                    {"key": "lastUpdate", "value": time.strftime("%Y-%m-%d %H:%M:%S")}]
        dev.updateStatesOnServer(updates)
        dev.setErrorStateOnServer(None)

    # ------------------------------------------------------------------ Snow (ACP v1)
    def _poll_v1(self, dev):
        self.next_poll[dev.id] = time.time() + self._interval(dev)
        if not dev.pluginProps.get("password"):
            self._set_status(dev, "no password", "not set", error=True)
            return
        client = ACPv1Client(dev.pluginProps.get("address", ""), dev.pluginProps.get("password"))
        try:
            states, _values = v1_read_states(client)
            matches = client.password_matches_device()
        except AuthenticationError:
            if dev.states.get("status") != "password rejected":
                self.logger.error('"%s": the base station rejected the stored password' % dev.name)
            self._set_status(dev, "password rejected", "password rejected", error=True)
            return
        except (ACPError, OSError) as err:
            if dev.states.get("status") != "offline":
                self.logger.warning('"%s": not reachable (%s)' % (dev.name, err))
            self._set_status(dev, "offline", error=True)
            return
        updates = [{"key": k, "value": v} for k, v in states.items() if k in dev.states]
        updates += [{"key": "status", "value": "online"},
                    {"key": "credentialStatus", "value": "password changed on device" if matches is False else "ok"},
                    {"key": "lastUpdate", "value": time.strftime("%Y-%m-%d %H:%M:%S")}]
        dev.updateStatesOnServer(updates)
        dev.setErrorStateOnServer(None)

    # ------------------------------------------------------------------ Wi-Fi changes
    def _backup_dir(self):
        return os.path.join(indigo.server.getInstallFolderPath(), "Preferences", "Plugins",
                            self.pluginId, "wifi-backups")

    def _change_wifi(self, dev, enable, radios=None):
        if not dev.pluginProps.get("password"):
            self.logger.error('"%s": no admin password set' % dev.name)
            return
        reboot = bool(dev.pluginProps.get("restartAfterChange", True))
        what = "Wi-Fi" if radios is None else "radio %s" % ", ".join(str(r + 1) for r in radios)
        with self.locks.setdefault(dev.id, threading.Lock()):
            try:
                with self._client(dev) as client:
                    result = wifi_ops.set_wifi(client, enable, self._backup_dir(), str(dev.id),
                                               radios=radios, reboot=reboot)
            except AuthenticationError:
                self.logger.error('"%s": the base station rejected the stored password' % dev.name)
                self._set_status(dev, "password rejected", "password rejected", error=True)
                return
            except (ACPError, OSError) as err:
                self.logger.error('"%s": could not change %s: %s' % (dev.name, what, err))
                return

        if not result["written"]:
            self.logger.info('"%s": %s is already %s' % (dev.name, what, "on" if enable else "off"))
            self.next_poll[dev.id] = 0
            return
        self.logger.info('"%s": %s turned %s (verified)%s' % (
            dev.name, what, "on" if enable else "off",
            "; restarting to apply" if result["rebooted"] else "; applies at next restart"))
        self.pending[dev.id] = True
        updates = [{"key": "wifiPending", "value": True}]
        if radios is None:
            updates.append({"key": "onOffState", "value": enable, "uiValue": self._on_off_ui(enable, True)})
        dev.updateStatesOnServer(updates)
        if result["rebooted"]:
            self._mark_restarting(dev)
        else:
            self.next_poll[dev.id] = time.time() + 5

    def _mark_restarting(self, dev):
        self.restart_started[dev.id] = time.time()
        self.restarting[dev.id] = time.time() + RESTART_GRACE
        self.next_poll[dev.id] = time.time() + 45
        self._set_status(dev, "restarting")

    # ------------------------------------------------------------------ actions
    def actionControlDevice(self, action, dev):
        if action.deviceAction == indigo.kDeviceAction.TurnOn:
            self._change_wifi(dev, True)
        elif action.deviceAction == indigo.kDeviceAction.TurnOff:
            self._change_wifi(dev, False)
        elif action.deviceAction == indigo.kDeviceAction.Toggle:
            self._change_wifi(dev, not dev.onState)
        elif action.deviceAction == indigo.kDeviceAction.RequestStatus:
            self.next_poll[dev.id] = 0

    def actionControlUniversal(self, action, dev):
        if action.deviceAction == indigo.kUniversalAction.RequestStatus:
            self.next_poll[dev.id] = 0

    def action_set_radio(self, plugin_action, dev):
        radio = plugin_action.props.get("radio", "all")
        radios = None if radio == "all" else [int(radio) - 1]
        self._change_wifi(dev, plugin_action.props.get("state", "on") == "on", radios)

    def action_restart(self, plugin_action, dev):
        with self.locks.setdefault(dev.id, threading.Lock()):
            try:
                with self._client(dev) as client:
                    client.reboot()
            except AuthenticationError:
                self.logger.error('"%s": the base station rejected the stored password' % dev.name)
                return
            except (ACPError, OSError) as err:
                self.logger.error('"%s": restart failed: %s' % (dev.name, err))
                return
        self.logger.info('"%s": restarting' % dev.name)
        self._mark_restarting(dev)

    def action_refresh(self, plugin_action, dev):
        self.next_poll[dev.id] = 0

    # ------------------------------------------------------------------ Bonjour
    def _start_bonjour(self):
        if self.zeroconf or Zeroconf is None:
            if Zeroconf is None:
                self.logger.warning("zeroconf is not available; live Wi-Fi state disabled")
            return
        try:
            self.zeroconf = Zeroconf()
            self.browser = ServiceBrowser(self.zeroconf, BONJOUR_SERVICE, handlers=[self._on_bonjour])
            self.logger.debug("watching Bonjour for AirPort base stations")
        except Exception as err:
            self.logger.warning("could not start Bonjour browsing: %s" % err)
            self.zeroconf = None

    def _stop_bonjour(self):
        if self.zeroconf:
            try:
                self.zeroconf.close()
            except Exception:
                pass
        self.zeroconf = self.browser = None
        self.bonjour = {}

    def _on_bonjour(self, zeroconf=None, service_type=None, name=None, state_change=None, **kwargs):
        # Called on zeroconf's thread; hand off so lookups happen in runConcurrentThread.
        self.bonjour_queue.put((name, state_change))

    def _drain_bonjour(self):
        while True:
            try:
                name, change = self.bonjour_queue.get_nowait()
            except queue.Empty:
                return
            if change == ServiceStateChange.Removed:
                self.bonjour.pop(name, None)
                continue
            if not self.zeroconf:
                continue
            try:
                info = self.zeroconf.get_service_info(BONJOUR_SERVICE, name, timeout=2000)
            except Exception as err:
                self.logger.debug("Bonjour lookup failed for %s: %s" % (name, err))
                continue
            if not info:
                continue
            entry = {"txt": _parse_txt(info.text), "addresses": info.parsed_addresses()}
            self.bonjour[name] = entry
            self.logger.debug("Bonjour: %s %s raSt=%s" % (name, entry["addresses"], entry["txt"].get("raSt")))
            self._apply_bonjour(entry)
            if self.pluginPrefs.get("autoCreate", False):
                self._create_for(name, entry, respect_history=True)

    def _match_bonjour(self, dev, states=None):
        address = dev.pluginProps.get("address", "")
        mac = _norm_mac((states or {}).get("macAddress") or dev.states.get("macAddress")
                        or dev.pluginProps.get("macAddress"))
        for entry in self.bonjour.values():
            if address in entry["addresses"] or (mac and _norm_mac(entry["txt"].get("waMA")) == mac):
                return entry
        return None

    @staticmethod
    def _live_from(entry):
        if not entry:
            return "unknown"
        return {"0": "on", "3": "off"}.get(entry["txt"].get("raSt"), "mode %s" % entry["txt"].get("raSt"))

    def _bonjour_live(self, dev, states=None):
        return self._live_from(self._match_bonjour(dev, states))

    def _apply_bonjour(self, entry):
        """A base station (re)announced itself: update live state straight away."""
        for dev in indigo.devices.iter("self"):
            if not dev.enabled or self._match_bonjour(dev) is not entry:
                continue
            live = self._live_from(entry)
            setting_on = bool(dev.states.get("wifiEnabled"))
            pending = bool(self.pending.get(dev.id)) or (live in ("on", "off") and (live == "on") != setting_on)
            if dev.states.get("wifiLive") != live or dev.states.get("wifiPending") != pending:
                updates = [{"key": "wifiLive", "value": live}, {"key": "wifiPending", "value": pending}]
                if dev.id not in self.restarting:
                    updates.append({"key": "onOffState", "value": setting_on,
                                    "uiValue": self._on_off_ui(setting_on, pending)})
                dev.updateStatesOnServer(updates)
            if dev.id in self.restarting:
                self.next_poll[dev.id] = 0   # it is back: poll now

    # ------------------------------------------------------------------ auto-create
    def _device_for_entry(self, entry):
        mac = _norm_mac(entry["txt"].get("waMA"))
        for dev in indigo.devices.iter("self"):
            dev_mac = _norm_mac(dev.pluginProps.get("macAddress") or dev.states.get("macAddress"))
            if (mac and dev_mac == mac) or dev.pluginProps.get("address", "") in entry["addresses"]:
                return dev
        return None

    def _unique_name(self, base):
        name, n = base, 1
        while name in indigo.devices:
            n += 1
            name = "%s (AirPort)" % base if n == 2 else "%s (AirPort %d)" % (base, n - 1)
        return name

    def _folder_id(self):
        folder = (self.pluginPrefs.get("deviceFolder") or "").strip()
        if not folder:
            return 0
        if folder not in indigo.devices.folders:
            indigo.devices.folder.create(folder)
        return indigo.devices.folders[folder].id

    def _create_for(self, service_name, entry, respect_history):
        """Create a device for a discovered base station unless one exists.

        respect_history: skip units this plugin auto-created before (so a device
        the user deleted is not recreated behind their back).
        """
        mac = _norm_mac(entry["txt"].get("waMA"))
        address = _usable_ipv4(entry["addresses"])
        if not mac or not address or self._device_for_entry(entry):
            return None
        history = set(json.loads(self.pluginPrefs.get("autoCreatedMacs", "[]")))
        if respect_history and mac in history:
            return None
        base = service_name.replace("." + BONJOUR_SERVICE, "") or "AirPort %s" % address
        props = {
            "address": address,
            "password": self.pluginPrefs.get("defaultPassword", ""),
            "pollInterval": "300",
            "restartAfterChange": True,
            "macAddress": mac,
            "SupportsOnState": True,
            "SupportsStatusRequest": True,
        }
        try:
            dev = indigo.device.create(protocol=indigo.kProtocol.Plugin, address=address,
                                       name=self._unique_name(base), pluginId=self.pluginId,
                                       deviceTypeId=DEVICE_TYPE, props=props, folder=self._folder_id())
        except Exception as err:
            self.logger.error('could not create a device for "%s": %s' % (base, err))
            return None
        history.add(mac)
        self.pluginPrefs["autoCreatedMacs"] = json.dumps(sorted(history))
        self.logger.info('created device "%s" for %s (model %s)%s' % (
            dev.name, address, entry["txt"].get("syAP", "?"),
            "" if props["password"] else "; enter its admin password in the device settings"))
        return dev

    # ------------------------------------------------------------------ network scan
    def menu_scan_network(self, values_dict, menu_id):
        network = (values_dict.get("network") or "").strip()
        try:
            import ipaddress
            ipaddress.ip_network(network, strict=False)
        except ValueError:
            errors = indigo.Dict()
            errors["network"] = "Enter a network such as 10.0.9.0/24."
            return False, values_dict, errors
        create = bool(values_dict.get("createDevices", True))
        threading.Thread(target=self._scan_network, args=(network, create), daemon=True).start()
        return True

    def _scan_network(self, network, create):
        self.logger.info("scanning %s for AirPort base stations..." % network)
        try:
            found = acp_scan(network)
        except Exception as err:
            self.logger.error("scan of %s failed: %s" % (network, err))
            return
        if not found:
            self.logger.info("no AirPort base stations found on %s" % network)
            return
        for result in found:
            host, gen = result["host"], result["generation"]
            label = {GEN_V1: "early model (AirPort Snow era)", GEN_CURRENT: "802.11n/ac",
                     GEN_SNMP: "original AirPort (Graphite)"}.get(gen, gen)
            existing = self._device_for_address(host, result["macs"])
            self.logger.info("found %s at %s%s" % (label, host,
                             ' (device "%s")' % existing.name if existing else ""))
            if create and not existing and gen in (GEN_V1, GEN_CURRENT, GEN_SNMP):
                self._create_scanned(host, gen, result["macs"], result.get("name", ""))

    def _device_for_address(self, host, macs=None):
        wanted = {_norm_mac(m) for m in (macs or {}).values()}
        for dev in indigo.devices.iter("self"):
            if dev.pluginProps.get("address", "") == host:
                return dev
            dev_mac = _norm_mac(dev.pluginProps.get("macAddress") or dev.states.get("macAddress"))
            if dev_mac and dev_mac in wanted:
                return dev
        return None

    def _create_scanned(self, host, gen, macs, reported_name=""):
        password = self.pluginPrefs.get("defaultPassword", "")
        name = reported_name   # the Graphite gives its name without a password
        if password and not name:   # best effort: use the unit's own name
            try:
                if gen == GEN_V1:
                    raw = ACPv1Client(host, password, timeout=5).get_raw(["syNm"]).get("syNm")
                    name = v1_decode("syNm", raw) if isinstance(raw, bytes) else ""
                else:
                    with ACPClient(host, password, timeout=5) as client:
                        raw = client.get_raw(["syNm"]).get("syNm")
                    name = acp_decode("syNm", raw) if isinstance(raw, bytes) else ""
            except Exception:
                name = ""
        type_id = {GEN_V1: V1_TYPE, GEN_SNMP: LEGACY_TYPE}.get(gen, DEVICE_TYPE)
        base = name or {GEN_V1: "AirPort Snow %s", GEN_SNMP: "AirPort Graphite %s"}.get(gen, "AirPort %s") % host
        props = {"address": host, "password": password, "pollInterval": "300"}
        if gen == GEN_CURRENT:
            props.update({"restartAfterChange": True, "SupportsOnState": True, "SupportsStatusRequest": True,
                          "macAddress": _norm_mac(macs.get("waMA") or macs.get("laMA") or "")})
        try:
            dev = indigo.device.create(protocol=indigo.kProtocol.Plugin, address=host,
                                       name=self._unique_name(base), pluginId=self.pluginId,
                                       deviceTypeId=type_id, props=props, folder=self._folder_id())
        except Exception as err:
            self.logger.error('could not create a device for %s: %s' % (host, err))
            return
        self.logger.info('created device "%s" for %s%s' % (
            dev.name, host, "" if password else "; enter its admin password in the device settings"))

    def menu_create_discovered(self):
        if not self.bonjour:
            self.logger.info("No AirPort base stations seen over Bonjour yet")
            return
        created = [d for name, entry in sorted(self.bonjour.items())
                   if (d := self._create_for(name, entry, respect_history=False))]
        if not created:
            self.logger.info("Every discovered base station already has a device")

    # ------------------------------------------------------------------ menu
    def menu_list_discovered(self):
        if not self.bonjour:
            self.logger.info("No AirPort base stations seen over Bonjour yet")
            return
        for name, entry in sorted(self.bonjour.items()):
            txt = entry["txt"]
            self.logger.info("%s: %s  model %s  firmware %s  Wi-Fi %s" % (
                name.replace("." + BONJOUR_SERVICE, ""), ", ".join(entry["addresses"]),
                txt.get("syAP", "?"), txt.get("syVs", "?"), self._live_from(entry)))

    def menu_refresh_all(self):
        for dev in indigo.devices.iter("self"):
            self.next_poll[dev.id] = 0
