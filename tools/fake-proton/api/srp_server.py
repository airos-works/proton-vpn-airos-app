"""Server side of Proton's SRP-6a (auth version 4).

Mirrors the client in python-proton-core (proton/session/srp/_pysrp.py and
util.py): every number travels as a 256-byte little-endian string, the hash is
PMHash (SHA-512 of the input followed by 0, 1, 2 and 3, concatenated), g = 2,
k = H(g || N) and x = H(bcrypt(password, salt) || N).
"""
from __future__ import annotations

import base64
import hashlib
import secrets

import bcrypt

SRP_LEN = 256
SALT_LEN = 10
GENERATOR = 2


def pmhash(data: bytes) -> bytes:
    return b"".join(hashlib.sha512(data + bytes([i])).digest() for i in range(4))


def to_le(number: int) -> bytes:
    return number.to_bytes(SRP_LEN, "little")


def from_le(data: bytes) -> int:
    return int.from_bytes(data, "little")


def bcrypt_b64(data: bytes) -> bytes:
    std = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    bcr = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return base64.b64encode(data).translate(bytes.maketrans(std, bcr))


def hash_password(password: bytes, salt: bytes, modulus_le: bytes) -> bytes:
    bcrypt_salt = bcrypt_b64((salt + b"proton")[:16])[:22]
    hashed = bcrypt.hashpw(password[:72], b"$2y$10$" + bcrypt_salt)
    return pmhash(hashed + modulus_le)


def modulus_from_armored(armored: str) -> int:
    """Extracts N from the PGP clear-signed modulus (the signature is not checked)."""
    lines = armored.replace("\r\n", "\n").split("\n")
    start = lines.index("") + 1           # the blank line ends the armor headers
    end = lines.index("-----BEGIN PGP SIGNATURE-----")
    data = base64.b64decode("".join(lines[start:end]).strip())
    if len(data) != SRP_LEN:
        raise ValueError(f"modulus is {len(data)} bytes, expected {SRP_LEN}")
    return from_le(data)


class SrpGroup:
    def __init__(self, modulus: int):
        self.N = modulus
        self.g = GENERATOR
        self.N_le = to_le(modulus)
        self.k = from_le(pmhash(to_le(self.g) + self.N_le))

    def verifier(self, password: str, salt: bytes) -> int:
        x = from_le(hash_password(password.encode(), salt, self.N_le))
        return pow(self.g, x, self.N)


class SrpServerSession:
    """One /auth/info challenge, answered by one /auth call."""

    def __init__(self, group: SrpGroup, verifier: int):
        self.group = group
        self.v = verifier
        N = group.N
        while True:
            self.b = from_le(secrets.token_bytes(SRP_LEN)) % N
            self.B = (group.k * self.v + pow(group.g, self.b, N)) % N
            if self.b > 1 and self.B != 0:
                break

    @property
    def server_ephemeral(self) -> bytes:
        return to_le(self.B)

    def verify(self, client_ephemeral: bytes, client_proof: bytes) -> bytes | None:
        """Returns the server proof, or None when the client proof is wrong."""
        N = self.group.N
        if len(client_ephemeral) != SRP_LEN:
            return None
        A = from_le(client_ephemeral)
        if A % N == 0:
            return None
        A_le, B_le = to_le(A), to_le(self.B)
        u = from_le(pmhash(A_le + B_le))
        if u == 0:
            return None
        S = pow(A * pow(self.v, u, N) % N, self.b, N)
        K = to_le(S)
        expected = pmhash(A_le + B_le + K)
        if not secrets.compare_digest(expected, client_proof):
            return None
        return pmhash(A_le + expected + K)
