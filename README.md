# Indigo-AirPort

Indigo plugin for Apple AirPort base stations and Time Capsules.

Apple stopped making AirPorts in 2018 and AirPort Utility hasn't moved since, but plenty of them are still running. This plugin talks to them directly over Apple's own admin protocol (ACP, TCP port 5009), so you can monitor them and switch their Wi-Fi on and off from Indigo, HomeKit or anything else that can control an Indigo device.

The long-term aim is a replacement for AirPort Utility that covers every model Apple made. It currently monitors and controls the 802.11n/ac generation, and monitors the original Graphite and Snow base stations.

## Features

- Reads model, firmware, serial number, uptime, temperature and Apple's own status/problem list (the reasons the light goes amber)
- Wi-Fi radio state, channel and network name per radio, plus the number of wireless clients
- Network details: IP, MAC, router, NAT and DHCP status, time zone, NTP server
- Model extras where the unit has them: sensors (temperatures, voltage, fan speed), Time Capsule disk usage and SMART status, AirPlay name on the Express
- Wi-Fi on/off: the device is a relay, so it works as a switch in HomeKit and Indigo
- Turn individual radios on or off (for example just the 5 GHz radio)
- Restart action
- Live Wi-Fi state from Bonjour without logging in, with changes picked up the moment a base station re-announces itself
- Optional auto-creation of devices for base stations found on the network
- Network scan that also finds the older units Bonjour can't see (Graphite and Snow)
- Graphite and Snow devices: name, firmware, network name, channel, closed network, WEP, IP settings, NAT/DHCP/bridging, plus uptime and wireless clients on the Graphite
- Shows "restarting" and "on (pending)" / "off (pending)" while changes take effect

## Supported models

| Model | Status |
|---|---|
| AirPort Extreme 802.11n (e.g. AirPort5,105) | Tested |
| AirPort Express 802.11n, 2nd gen (AirPort10,115) | Tested |
| Time Capsule 802.11n (e.g. TimeCapsule6,113) | Tested |
| Other 802.11n Extremes, Expresses and Time Capsules on 7.x firmware | Expected to work |
| AirPort Extreme / Time Capsule 802.11ac (7.9.x firmware) | Expected to work, untested |
| AirPort Snow (firmware 4.0.9) | Tested: monitoring (uses the original ACP protocol, version 1) |
| AirPort Graphite (firmware 3.84) | Tested: monitoring (uses SNMP) |
| 802.11g "flying saucer" Extreme and original Express | Not yet tested; probably the same protocol as the Snow |

If you try it on a model not marked as tested, please open an issue with the result.

## Installation

1. Download `AirPort.indigoPlugin.zip` from the [latest release](https://github.com/durosity/Indigo-AirPort/releases/latest), unzip it and double-click the plugin to install it in Indigo.
2. Indigo installs the Python dependencies (`cryptography`, `zeroconf`) from `requirements.txt` on first start.
3. Either create an **AirPort Base Station** device and enter the base station's IP address and admin password, or tick **Auto-create devices for discovered base stations** in the plugin's configuration.

## How Wi-Fi on/off works

Turning Wi-Fi off does exactly what AirPort Utility's "Network Mode: Off" does: it changes the radio mode and the "allow this network to be extended" flag, and nothing else. Your network name, security, password and channels stay stored on the base station, so turning Wi-Fi back on brings the same network back.

AirPorts only apply configuration changes when they restart, which takes one to two minutes. With **Restart after Wi-Fi changes** ticked (the default) the plugin restarts the base station for you and shows "restarting" until it's back. Untick it and the change shows as pending until the next restart.

Every change is made carefully:

1. The current Wi-Fi configuration is read and the plugin checks it can reproduce it byte-for-byte before going any further.
2. A backup of the original is saved (in Indigo's Preferences folder, readable only by your user account).
3. Only the intended fields are changed; anything else changing aborts the write.
4. After writing, the configuration is read back and must match exactly; if it doesn't, the original is written back.
5. Then the base station is restarted.

## Devices

### AirPort Base Station

A relay device: on/off is the Wi-Fi setting.

| State | Description |
|---|---|
| `status` | online, restarting, offline, password rejected, no password |
| `credentialStatus` | ok, password rejected, not set, password changed on device |
| `name`, `model`, `productId`, `firmware`, `serialNumber` | Identity |
| `uptime`, `uptimeSeconds` | Time since last restart |
| `temperatureC` | Internal temperature, where the unit has a sensor |
| `problems`, `problemCount` | Apple's status list, e.g. "open wireless network (no security)" |
| `wifiEnabled` | Wi-Fi setting stored on the base station |
| `wifiLive` | What the radio is actually doing, from Bonjour (on, off, unknown) |
| `wifiPending` | A stored change is waiting for a restart |
| `radioCount`, `radio1_state`, `radio1_channel`, `radio1_network` (and `radio2_…`) | Per-radio details |
| `clientCount` | Wireless clients connected |
| `ipAddress`, `macAddress`, `router`, `subnetMask`, `natEnabled`, `dhcpServerEnabled` | Network |
| `ledMode`, `timeZone`, `ntpServer`, `lastUpdate` | Other |

Extra states are added automatically for whatever the unit reports: `sensor_…` readings, `disk1_…` (name, SMART status, size, used, free, percent used) and `airplayName`.

## Actions

- **Turn On / Turn Off / Toggle**: Wi-Fi on all radios
- **Set Wi-Fi Radio On/Off**: one radio or all
- **Restart Base Station**
- **Refresh Now**

## Menu items

- **Log Discovered Base Stations**: everything seen over Bonjour, with model, firmware and Wi-Fi state
- **Create Devices for Discovered Base Stations**: creates devices for any discovered unit that doesn't have one
- **Scan Network for Base Stations...**: checks every address on one or more networks (pre-filled with the ones your devices are on) and finds units Bonjour misses, including the Graphite and Snow; optionally creates devices
- **Refresh All Base Stations**

### AirPort Base Station (Graphite) and AirPort Base Station (Snow)

Custom devices whose State column shows `status` (online, offline, password rejected, no SNMP reply). States: `name`, `firmware`, `description`, `networkName`, `channel`, `closedNetwork`, `encryption`, `ipAddress`, `router`, `subnetMask`, `natEnabled`, `dhcpServerEnabled`, `bridging`, `contact`, `location`, `lastUpdate`. The Graphite adds `uptime`, `uptimeSeconds`, `clientCount` and `wanInterface`; the Snow adds `credentialStatus`, `domainName` and its MAC addresses.

These models predate encrypted admin connections: the Graphite uses SNMPv1 (the password is the community string) and the Snow sends an obfuscated password with every request. That's how Apple's own AirPort Admin Utility worked too; keep them on a network you trust.

## Bonjour and VLANs

Base stations announce themselves over Bonjour, which doesn't cross VLANs or subnets on its own. If yours are on a different network from the Indigo server, enable an mDNS proxy/reflector on your router (UniFi calls it Gateway mDNS Proxy) with both networks selected. Without it, devices still work by IP address; you just lose discovery and the live Wi-Fi state.

A base station in router (NAT) mode only announces itself on its LAN side, so it won't be discovered from its WAN side.

## Security notes

- Device passwords are stored in the Indigo database, unencrypted, and are never written to the log, even with debug logging on.
- Once logged in, base stations hand back several secrets (the admin password, Wi-Fi passwords, Time Capsule file-sharing passwords). The plugin never shows, stores or logs these.
- All communication uses the base station's encrypted session (SRP login, AES-128-CTR), the same as AirPort Utility. The old unencrypted password scheme is never used.
- Wi-Fi backups contain your Wi-Fi password and are saved with permissions that only your user account can read.

## Debugging

Turn on **Enable debug logging** in the plugin configuration. **Include ACP protocol trace** adds a line for every property sent and received (names and sizes only, never values).

The `dev` folder has the command-line tools and tests used to develop the protocol library; see `dev/README.md`.

## Credits

The ACP protocol implementation is a Python port of parts of [node-acp](https://github.com/samuelthomas2774/node-acp) by Samuel Elliott (MIT licence), whose reverse-engineering work, building on [airpyrt-tools](https://github.com/x56/airpyrt-tools), made this possible.

## Licence

MIT. See `LICENSE`.
