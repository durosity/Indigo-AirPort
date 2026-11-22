"""ACP client: connect, authenticate (SRP + session encryption), get properties.

Credentials are never logged: the password is only held privately on the
client object, its repr is redacted, and the admin-password property (syPW)
is never returned to callers.
"""

import hashlib
import hmac
import logging
import secrets
import socket

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import cflbinary, message
from .srp import SRPClient, SRPError

log = logging.getLogger("airport_acp")

PORT = 5009
_PBKDF_SALT_CLIENT = bytes.fromhex("F072FA3F66B410A135FAE8E6D1D43D5F")
_PBKDF_SALT_SERVER = bytes.fromhex("BD0682C9FE79325BC73655F4174B996C")

# Properties that are never handed back to callers.
SECRET_PROPERTIES = frozenset({"syPW"})


class ACPError(Exception):
    pass


class AuthenticationError(ACPError):
    """Wrong password, or the base station failed SRP verification."""


class PropertyError(ACPError):
    def __init__(self, name, code):
        self.name, self.code = name, code
        super().__init__("%s: %s (%d)" % (name, message.ERRORS.get(code, "error"), code))


class _StreamCipher:
    def __init__(self, session_key, client_iv, server_iv):
        ckey = hashlib.pbkdf2_hmac("sha1", session_key, _PBKDF_SALT_CLIENT, 5, 16)
        skey = hashlib.pbkdf2_hmac("sha1", session_key, _PBKDF_SALT_SERVER, 7, 16)
        self._enc = Cipher(algorithms.AES(ckey), modes.CTR(client_iv)).encryptor()
        self._dec = Cipher(algorithms.AES(skey), modes.CTR(server_iv)).decryptor()

    def encrypt(self, data):
        return self._enc.update(data)

    def decrypt(self, data):
        return self._dec.update(data)


class ACPClient:
    def __init__(self, host, password, port=PORT, timeout=10.0):
        self.host, self.port, self.timeout = host, port, timeout
        self.__password = password or ""
        self._sock = None
        self._cipher = None
        self._buffer = b""

    def __repr__(self):
        return "<ACPClient %s:%d password=%s>" % (
            self.host, self.port, "set" if self.__password else "not set")

    # ------------------------------------------------------------ transport
    def connect(self):
        self.close()
        self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._sock.settimeout(self.timeout)

    def close(self):
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None
        self._cipher = None
        self._buffer = b""

    def reconnect(self):
        """Open a fresh connection and log in again (e.g. after the unit hung up)."""
        self.connect()
        self.authenticate()

    def __enter__(self):
        self.connect()
        self.authenticate()
        return self

    def __exit__(self, *exc):
        self.close()

    def _send(self, data):
        if self._cipher:
            data = self._cipher.encrypt(data)
        self._sock.sendall(data)

    def _recv(self, size):
        while len(self._buffer) < size:
            chunk = self._sock.recv(65536)
            if not chunk:
                log.debug("connection closed with %d of %d bytes received", len(self._buffer), size)
                raise ACPError("connection closed by base station")
            if self._cipher:
                chunk = self._cipher.decrypt(chunk)
            self._buffer += chunk
        data, self._buffer = self._buffer[:size], self._buffer[size:]
        return data

    def _recv_message(self):
        header = message.Header.unpack(self._recv(message.HEADER_SIZE))
        body = self._recv(header.body_size) if header.body_size > 0 else b""
        if body and message.adler32(body) != header.body_checksum:
            raise ACPError("body checksum mismatch")
        return header, body

    # ------------------------------------------------------------ auth
    def authenticate(self):
        if not self.__password:
            raise AuthenticationError("no password set")
        auth_key = message.header_key("")
        self._send(message.compose(message.CMD_AUTHENTICATE, 4, auth_key,
                                   cflbinary.compose({"state": 1, "username": "admin"})))
        header, body = self._recv_message()
        if header.error_code:
            raise ACPError("authentication stage 2 failed: %s" % header.error_name)
        params = cflbinary.parse(body)

        try:
            srp = SRPClient(self.__password, params["salt"], params["generator"],
                            params["modulus"], params["publicKey"])
        except (KeyError, SRPError) as err:
            raise ACPError("unexpected authentication parameters: %s" % err) from None

        client_iv = secrets.token_bytes(16)
        self._send(message.compose(message.CMD_AUTHENTICATE, 4, auth_key, cflbinary.compose({
            "iv": client_iv, "publicKey": srp.public, "state": 3, "response": srp.proof})))
        header, body = self._recv_message()
        if header.error_code == -6754:
            raise AuthenticationError("password rejected")
        if header.error_code:
            raise ACPError("authentication stage 4 failed: %s" % header.error_name)
        reply = cflbinary.parse(body)
        try:
            srp.verify_server(reply["response"])
        except (KeyError, SRPError):
            raise AuthenticationError("base station could not be verified") from None
        self._cipher = _StreamCipher(srp.session_key, client_iv, reply["iv"])
        log.debug("authenticated to %s, session encryption enabled", self.host)

    # ------------------------------------------------------------ properties
    def get_raw(self, names, include_secret=False, timeout=90.0):
        """Fetch properties. Returns {name: bytes | PropertyError}.

        Some properties (e.g. raSR, the Wi-Fi scan) make the base station do
        work before replying, so reads use a longer timeout than connecting.
        """
        if not self._cipher:
            raise ACPError("not authenticated")
        names = [n for n in names if include_secret or n not in SECRET_PROPERTIES]
        if not names:
            return {}
        body = b"".join(message.pack_element(n) for n in names)
        self._send(message.compose(message.CMD_GET_PROPERTY, 4, message.ZERO_KEY, body))
        self._sock.settimeout(timeout)
        try:
            return self._read_properties()
        finally:
            if self._sock is not None:
                self._sock.settimeout(self.timeout)

    def _read_properties(self):
        header = message.Header.unpack(self._recv(message.HEADER_SIZE))
        log.debug("get reply: command=%d flags=%d body_size=%d error=%d",
                  header.command, header.flags, header.body_size, header.error_code)
        if header.error_code:
            raise ACPError("get properties failed: %s" % header.error_name)
        results = {}
        while True:
            name, flags, size = message.unpack_element_header(self._recv(message.ELEMENT_HEADER_SIZE))
            value = self._recv(size) if size else b""
            key = name.decode("latin-1")
            log.debug("element %r flags=%d size=%d", key, flags, size)
            if flags & 1:
                results[key] = PropertyError(key, int.from_bytes(value[:4], "big", signed=True))
                continue
            if name == b"\x00\x00\x00\x00":
                break
            results[key] = value
        return results

    def set_raw(self, values, timeout=30.0):
        """Write properties: {name: bytes}. Raises PropertyError on a rejected value.

        Callers are responsible for the value bytes; see wifi.py for the
        verified read-modify-write used for configuration changes.
        """
        if not self._cipher:
            raise ACPError("not authenticated")
        body = b"".join(message.pack_element(n, v) for n, v in values.items())
        log.debug("set %s (%d bytes)", ", ".join("%s=%d bytes" % (n, len(v)) for n, v in values.items()), len(body))
        self._send(message.compose(message.CMD_SET_PROPERTY, 0, message.ZERO_KEY, body))
        self._sock.settimeout(timeout)
        try:
            header = message.Header.unpack(self._recv(message.HEADER_SIZE))
            log.debug("set reply: command=%d flags=%d body_size=%d error=%d",
                      header.command, header.flags, header.body_size, header.error_code)
            if header.error_code:
                raise ACPError("set properties failed: %s" % header.error_name)
            while True:
                name, flags, size = message.unpack_element_header(self._recv(message.ELEMENT_HEADER_SIZE))
                value = self._recv(size) if size else b""
                key = name.decode("latin-1")
                log.debug("set reply %r flags=%d size=%d", key, flags, size)
                if flags & 1:
                    raise PropertyError(key, int.from_bytes(value[:4], "big", signed=True))
                if name == b"\x00\x00\x00\x00":
                    return
        finally:
            if self._sock is not None:
                self._sock.settimeout(self.timeout)

    def reboot(self):
        """Ask the base station to restart (applies stored configuration)."""
        try:
            self.set_raw({"acRB": b"\x00\x00\x00\x00"})
        except (ACPError, OSError):
            # The base station may drop the connection as it restarts.
            pass
        self.close()

    def password_matches_device(self):
        """True if the stored password equals the device's admin password (syPW)."""
        value = self.get_raw(["syPW"], include_secret=True).get("syPW")
        if not isinstance(value, bytes):
            return None
        return hmac.compare_digest(value, self.__password.encode("utf-8"))
