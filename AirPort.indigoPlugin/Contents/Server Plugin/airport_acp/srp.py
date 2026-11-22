"""SRP-6a client as used by AirPort ACP (SHA-1, 1536-bit group, user "admin").

Matches fast-srp-hap's behaviour, which node-acp uses successfully:
  k  = H(PAD(N) | PAD(g))
  x  = H(s | H(I | ":" | P))
  u  = H(PAD(A) | PAD(B))
  S  = (B - k*g^x) ^ (a + u*x) mod N
  K  = H(S | 00000000) | H(S | 00000001)        (40 bytes, SHA-1 interleave)
  M1 = H(H(N) xor H(g) | H(I) | s | A | B | K)
  M2 = H(A | M1 | K)
Numbers are big-endian, minimal length unless PAD() (to N's byte length).
"""

import hashlib
import hmac
import secrets

USERNAME = b"admin"


def _h(*parts):
    digest = hashlib.sha1()
    for part in parts:
        digest.update(part)
    return digest.digest()


def _to_bytes(n):
    return n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")


def _from_bytes(b):
    return int.from_bytes(b, "big")


class SRPError(Exception):
    pass


class SRPClient:
    def __init__(self, password, salt, generator, modulus, server_public, n_bits=1536, _secret=None):
        self._pad_len = n_bits // 8
        N = _from_bytes(modulus)
        g = _from_bytes(generator)
        B = _from_bytes(server_public)
        if not 0 < B % N:
            raise SRPError("invalid server public key")

        pad = lambda b: b.rjust(self._pad_len, b"\x00")
        k = _from_bytes(_h(pad(_to_bytes(N)), pad(_to_bytes(g))))
        x = _from_bytes(_h(salt, _h(USERNAME + b":" + password.encode("utf-8"))))

        a = _from_bytes(_secret if _secret is not None else secrets.token_bytes(32))
        A = pow(g, a, N)
        self.public = _to_bytes(A)
        B_buf = bytes(server_public)

        u = _from_bytes(_h(pad(self.public), pad(B_buf)))
        if u == 0:
            raise SRPError("invalid scrambling parameter")
        S = pow((B - k * pow(g, x, N)) % N, a + u * x, N)
        S_buf = _to_bytes(S)
        self.session_key = _h(S_buf, b"\x00\x00\x00\x00") + _h(S_buf, b"\x00\x00\x00\x01")

        hN, hg = _h(_to_bytes(N)), _h(_to_bytes(g))
        self.proof = _h(bytes(p ^ q for p, q in zip(hN, hg)), _h(USERNAME), bytes(salt),
                        self.public, B_buf, self.session_key)
        self._expected_server_proof = _h(self.public, self.proof, self.session_key)

    def verify_server(self, server_proof):
        if not hmac.compare_digest(self._expected_server_proof, bytes(server_proof)):
            raise SRPError("base station failed to prove it knows the password")
