"""Find AirPort base stations by scanning a subnet on TCP 5009 (no password needed).

Bonjour finds the 802.11n/ac units, but the Snow and other early models don't
advertise themselves. Every ACP base station answers a "get features" request
without logging in, and the reply's header version tells the generations apart:
  version 1           ACP v1 (AirPort Snow, likely 802.11g models)
  version 0x00030001  current ACP (802.11n/ac); the reply also carries MACs
"""

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

from . import cflbinary, message
from .client import PORT

GEN_V1 = "v1"
GEN_CURRENT = "current"


def _recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            break
        data += chunk
    return data


def probe(host, timeout=1.0):
    """Return {"host", "generation", "macs"} or None if nothing ACP-like answers."""
    try:
        sock = socket.create_connection((host, PORT), timeout=timeout)
    except OSError:
        return None
    try:
        sock.settimeout(timeout + 2)
        sock.sendall(message.compose(message.CMD_GET_FEATURES, 0, message.header_key("")))
        raw = _recv_exact(sock, message.HEADER_SIZE)
        if len(raw) < message.HEADER_SIZE:
            return None
        header = message.Header.unpack(raw)
        result = {"host": host, "macs": {}}
        if header.version == 1:
            result["generation"] = GEN_V1
        elif header.version == message.VERSION:
            result["generation"] = GEN_CURRENT
            if header.body_size > 0 and not header.error_code:
                try:
                    features = cflbinary.parse(_recv_exact(sock, header.body_size))
                    props = features.get("acpProperties", {}) if isinstance(features, dict) else {}
                    for key, value in props.items():
                        if isinstance(value, bytes) and len(value) == 6:
                            value = ":".join("%02x" % b for b in value)
                        if isinstance(value, str):
                            result["macs"][key] = value.lower()
                except (ValueError, OSError):
                    pass
        else:
            result["generation"] = "version %d" % header.version
        return result
    except (OSError, ValueError):
        return None
    finally:
        sock.close()


def scan(network, timeout=1.0, workers=64):
    """Scan e.g. "10.0.9.0/24". Returns a list of probe() results, by address."""
    net = ipaddress.ip_network(network, strict=False)
    if net.num_addresses > 4096:
        raise ValueError("network too large to scan (use /20 or smaller)")
    hosts = [str(h) for h in (net.hosts() if net.num_addresses > 2 else net)]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        found = [r for r in pool.map(lambda h: probe(h, timeout), hosts) if r]
    return sorted(found, key=lambda r: ipaddress.ip_address(r["host"]))
