"""Remove secrets from decoded property values before they are shown, stored or logged.

Base stations hand back several secrets once you are logged in:
  syPW            admin password
  raCr / raWE     Wi-Fi password / WEP key (top level on single-radio units,
                  and inside WiFi and Prof radio entries)
  usrd            Time Capsule file-sharing users, including their passwords
The library still reads WiFi (it has to, to change it) but anything leaving the
library for display passes through redact().
"""

REDACTED = "<redacted>"
SECRET_KEYS = frozenset({"raCr", "raWE", "password", "syPW"})
SECRET_TOP_LEVEL = frozenset({"syPW", "raCr", "raWE"})


def redact_value(value):
    if isinstance(value, dict):
        return {k: (REDACTED if k in SECRET_KEYS and value[k] not in (b"", "", None) else redact_value(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    return value


def redact(name, value):
    if name in SECRET_TOP_LEVEL:
        return REDACTED
    return redact_value(value)
