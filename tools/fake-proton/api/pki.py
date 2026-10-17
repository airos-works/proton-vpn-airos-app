"""Generates and loads the fake Proton stack's keys and certificates.

Everything lives in tools/fake-proton/state/ (gitignored) and is created on
first start. Existing files are kept, so clients that already trust a CA keep
working across restarts; delete the state directory to start over.

Files (PEM unless noted):
  api-ca.pem / .key            CA of the fake REST API's HTTPS certificate
  api-server.pem / .key        HTTPS certificate (localhost, 127.0.0.1, 10.0.2.2, ...)
  openvpn-ca.pem / .key        CA of the OpenVPN server certificate (the client's <ca>)
  openvpn-server.pem / .key    OpenVPN server certificate, CN = SAN = the server domain
  agent-ca.pem / .key          CA of the local agent's TLS certificate
  agent-server.pem / .key      local agent certificate, SAN = the server domain
  vpn-client-ca.pem / .key     Ed25519 "ProtonVPN test CA" that signs the client
                               certificates of /vpn/v1/certificate; OpenVPN and the
                               local agent require client certificates from it
  wg-server.key / .pub         WireGuard server key pair (base64)
  meta.json                    domain and SANs the certificates were made for
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, x25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DEFAULT_DOMAIN = "node-fake-01.protonvpn.net"
CLIENT_CA_NAME = "ProtonVPN test CA"

# Default names/addresses in the API's HTTPS certificate. 10.0.2.2 is the host
# as seen from a QEMU user-networking guest, 172.17.0.1 the docker0 bridge.
DEFAULT_API_DNS = ["localhost", "vpn-api.proton.me", "fake-proton-api", "host.docker.internal"]
DEFAULT_API_IPS = ["127.0.0.1", "10.0.2.2", "172.17.0.1"]


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _write(path: Path, data: bytes, private: bool = False) -> None:
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if private else 0o644)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    os.replace(tmp, path)


def _key_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _sign_hash(key):
    return None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()


def _name(common_name: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CH"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fake Proton (test only)"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def make_ca(common_name: str, key=None, days: int = 3650):
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = (x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
            if isinstance(key, ed25519.Ed25519PrivateKey) else _name(common_name))
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, _sign_hash(key))
    )
    return key, cert


def issue_server_cert(ca_key, ca_cert: x509.Certificate, common_name: str,
                      dns_names: list[str], ip_addresses: list[str], days: int = 825):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = _now()
    sans = [x509.DNSName(name) for name in dns_names]
    sans += [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ip_addresses]
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                       critical=False)
        .sign(ca_key, _sign_hash(ca_key))
    )
    return key, cert


def spki_pin(cert: x509.Certificate) -> str:
    """base64(SHA-256(SubjectPublicKeyInfo)), the format of Proton's TLS pins."""
    der = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(hashlib.sha256(der).digest()).decode()


class State:
    """Paths and lazily generated material in the state directory."""

    def __init__(self, directory: Path, domain: str = DEFAULT_DOMAIN,
                 api_dns: list[str] | None = None, api_ips: list[str] | None = None):
        self.dir = Path(directory)
        self.domain = domain
        self.api_dns = list(api_dns or DEFAULT_API_DNS)
        self.api_ips = list(api_ips or DEFAULT_API_IPS)

    def path(self, name: str) -> Path:
        return self.dir / name

    # -- helpers -------------------------------------------------------------
    def _load_key(self, name: str):
        return serialization.load_pem_private_key(self.path(name).read_bytes(), None)

    def _load_cert(self, name: str) -> x509.Certificate:
        return x509.load_pem_x509_certificate(self.path(name).read_bytes())

    def _ensure_ca(self, stem: str, common_name: str, key_factory=None) -> bool:
        if self.path(f"{stem}.pem").exists() and self.path(f"{stem}.key").exists():
            return False
        key, cert = make_ca(common_name, key_factory() if key_factory else None)
        _write(self.path(f"{stem}.key"), _key_pem(key), private=True)
        _write(self.path(f"{stem}.pem"), _cert_pem(cert))
        return True

    def _issue(self, ca_stem: str, stem: str, common_name: str, dns: list[str], ips: list[str]):
        ca_key = self._load_key(f"{ca_stem}.key")
        ca_cert = self._load_cert(f"{ca_stem}.pem")
        key, cert = issue_server_cert(ca_key, ca_cert, common_name, dns, ips)
        _write(self.path(f"{stem}.key"), _key_pem(key), private=True)
        # Leaf followed by its CA, so servers send the whole chain.
        _write(self.path(f"{stem}.pem"), _cert_pem(cert) + _cert_pem(ca_cert))

    # -- public --------------------------------------------------------------
    def ensure(self) -> list[str]:
        """Creates whatever is missing or outdated. Returns what was (re)made."""
        self.dir.mkdir(parents=True, exist_ok=True)
        made = []
        meta_path = self.path("meta.json")
        meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}

        if self._ensure_ca("api-ca", "Fake Proton API test CA"):
            made.append("api-ca")
        if self._ensure_ca("openvpn-ca", "Fake ProtonVPN OpenVPN test CA"):
            made.append("openvpn-ca")
        if self._ensure_ca("agent-ca", "Fake ProtonVPN local agent test CA"):
            made.append("agent-ca")
        if self._ensure_ca("vpn-client-ca", CLIENT_CA_NAME, ed25519.Ed25519PrivateKey.generate):
            made.append("vpn-client-ca")

        api_sans = {"dns": self.api_dns, "ips": self.api_ips}
        if ("api-ca" in made or not self.path("api-server.pem").exists()
                or meta.get("api_sans") != api_sans):
            self._issue("api-ca", "api-server", self.api_dns[0], self.api_dns, self.api_ips)
            made.append("api-server")

        server_dns = [self.domain, "*.protonvpn.net"] if self.domain.endswith(".protonvpn.net") \
            else [self.domain]
        if ("openvpn-ca" in made or not self.path("openvpn-server.pem").exists()
                or meta.get("domain") != self.domain):
            self._issue("openvpn-ca", "openvpn-server", self.domain, server_dns, [])
            made.append("openvpn-server")
        if ("agent-ca" in made or not self.path("agent-server.pem").exists()
                or meta.get("domain") != self.domain):
            self._issue("agent-ca", "agent-server", self.domain, server_dns, ["10.2.0.1"])
            made.append("agent-server")

        if not self.path("wg-server.key").exists() or not self.path("wg-server.pub").exists():
            key = x25519.X25519PrivateKey.generate()
            raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                    serialization.NoEncryption())
            pub = key.public_key().public_bytes(serialization.Encoding.Raw,
                                                serialization.PublicFormat.Raw)
            _write(self.path("wg-server.key"), base64.b64encode(raw) + b"\n", private=True)
            _write(self.path("wg-server.pub"), base64.b64encode(pub) + b"\n")
            made.append("wg-server")

        meta.update({"domain": self.domain, "api_sans": api_sans})
        _write(meta_path, json.dumps(meta, indent=2).encode() + b"\n")
        return made

    @property
    def wg_public_key(self) -> str:
        return self.path("wg-server.pub").read_text().strip()

    @property
    def client_ca(self):
        return self._load_key("vpn-client-ca.key"), self._load_cert("vpn-client-ca.pem")

    @property
    def api_pin(self) -> str:
        return spki_pin(self._load_cert("api-server.pem"))
