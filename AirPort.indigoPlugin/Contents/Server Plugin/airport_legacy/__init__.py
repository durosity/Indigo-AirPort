"""airport_legacy - original AirPort base stations (Graphite, Snow) over SNMPv1."""

from .snmp import SNMPClient, SNMPError, SNMPTimeout, SNMPErrorStatus
from .legacy import LegacyBaseStation, LegacyError, decode_config, discover, read_states

__all__ = ["SNMPClient", "SNMPError", "SNMPTimeout", "SNMPErrorStatus",
           "LegacyBaseStation", "LegacyError", "decode_config", "discover", "read_states"]
