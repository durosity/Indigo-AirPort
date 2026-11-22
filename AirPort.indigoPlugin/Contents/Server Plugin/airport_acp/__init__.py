"""airport_acp - read (and later write) Apple AirPort base stations over ACP.

Portions ported from node-acp (MIT, (c) 2018-2020 Samuel Elliott).
"""

from .client import ACPClient, ACPError, AuthenticationError, PropertyError, SECRET_PROPERTIES
from .catalogue import PROPERTIES
from .values import decode

__version__ = "0.0.1"
__all__ = ["ACPClient", "ACPError", "AuthenticationError", "PropertyError",
           "SECRET_PROPERTIES", "PROPERTIES", "decode"]
