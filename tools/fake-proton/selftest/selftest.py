#!/usr/bin/env python3
"""End-to-end self-test of the fake Proton stack (run via tools/fake-proton.sh test).

1. REST API: SRP login with python-proton-core's own SRP client
   (.upstream/python-proton-core/proton/session/srp/_pysrp.py), 2FA, token
   refresh/expiry, every endpoint, error shapes and the test controls.
2. Certificates: a fresh Ed25519 key gets a certificate; its chain, fingerprint,
   Proton extensions and the WireGuard peer registration are checked.
3. WireGuard: a throwaway client container brings up wg0 with the X25519 form
   of that key and probes 10.2.0.1 (DNS, HTTP, local agent over TLS, NAT-PMP).
4. OpenVPN UDP and TCP: the same container connects with the exact client
   template of python-proton-vpn-api-core (openvpn.py), Proton's tls-crypt key,
   the issued certificate and its Ed25519 key, and runs the same probes.

The client container reaches the server through the host's published ports
(docker bridge gateway, like a QEMU guest reaching 10.0.2.2), never touching
the host's own routing table.
"""
from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import hmac
import importlib.util
import json
import os
import shutil
import struct
import subprocess
import sys
import time
import types
from pathlib import Path

import nacl.bindings
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID

HERE = Path(__file__).resolve().parent
FAKE = HERE.parent
REPO = FAKE.parent.parent
UPSTREAM = REPO / ".upstream"
STATE = Path(os.environ.get("FAKE_PROTON_STATE", FAKE / "state"))
WORK = STATE / "selftest"
IMAGE = os.environ.get("FAKE_PROTON_IMAGE", "fake-proton-vpn:latest")
SERVER_CONTAINER = os.environ.get("FAKE_PROTON_CONTAINER", "fake-proton-vpn")
CLIENT_CONTAINER = f"fake-proton-selftest-{os.getpid()}"
HTTP_PORT = int(os.environ.get("FAKE_PROTON_HTTP_PORT", "18080"))
HTTPS_PORT = int(os.environ.get("FAKE_PROTON_HTTPS_PORT", "18443"))
OVPN_UDP_PORT = int(os.environ.get("FAKE_PROTON_OVPN_UDP_PORT", "11940"))
OVPN_TCP_PORT = int(os.environ.get("FAKE_PROTON_OVPN_TCP_PORT", "11941"))
WG_PORT = int(os.environ.get("FAKE_PROTON_WG_PORT", "51830"))
ENTRY_IP = os.environ.get("FAKE_PROTON_ENTRY_IP", "10.0.2.2")
DOMAIN = os.environ.get("FAKE_PROTON_DOMAIN", "node-fake-01.protonvpn.net")
APP_VERSION = "linux-vpn@4.99.0+fake-selftest"
PROTON_OID = "1.3.6.1.4.1.56809.1."

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok, detail="") -> bool:
    RESULTS.append((name, bool(ok), str(detail)))
    status = "PASS" if ok else "FAIL"
    text = f"  [{status}] {name}"
    if detail and not ok:
        text += f"\n         {str(detail)[:600]}"
    print(text, flush=True)
    return bool(ok)


def section(title: str):
    print(f"\n== {title}", flush=True)


# -- upstream SRP client ------------------------------------------------------------

def load_upstream_srp():
    """Imports python-proton-core's pure-Python SRP client without the rest of
    the package (which would need gnupg, the keyring, etc.)."""
    base = UPSTREAM / "python-proton-core" / "proton"
    for name, path in (("proton", base), ("proton.session", base / "session"),
                       ("proton.session.srp", base / "session" / "srp")):
        if name not in sys.modules:
            module = types.ModuleType(name)
            module.__path__ = [str(path)]
            sys.modules[name] = module

    def load(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module

    load("proton.session.exceptions", base / "session" / "exceptions.py")
    return load("proton.session.srp._pysrp", base / "session" / "srp" / "_pysrp.py").User


SrpUser = load_upstream_srp()


def modulus_from_signed_message(armored: str) -> bytes:
    """What python-proton-core gets from gnupg after verifying the signature
    (the self-test skips the signature check itself)."""
    body = armored.split("\n\n", 1)[1].split("\n-----BEGIN PGP SIGNATURE-----", 1)[0]
    return base64.b64decode(body.strip())


def totp(secret: str, at: float) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", int(at // 30)), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    return f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


# -- API client -----------------------------------------------------------------------

class Api:
    created: list["Api"] = []      # every client, logged out when the self-test ends

    def __init__(self, base: str, verify=True):
        Api.created.append(self)
        self.base = base
        self.http = requests.Session()
        self.http.verify = verify
        self.uid = self.access = self.refresh_token = None
        self.scopes = []

    def call(self, method: str, path: str, body=None, headers=None, auth=True,
             appversion=True, **kwargs) -> requests.Response:
        sent = {"User-Agent": "fake-proton-selftest"}
        if appversion:
            sent["x-pm-appversion"] = APP_VERSION
        if auth and self.uid:
            sent["x-pm-uid"] = self.uid
            sent["Authorization"] = f"Bearer {self.access}"
        sent.update(headers or {})
        return self.http.request(method, self.base + path, json=body, headers=sent,
                                 timeout=30, **kwargs)

    def login(self, username: str, password: str):
        """SRP login with the upstream client. Returns (auth response, info reply)."""
        info = self.call("POST", "/auth/info", {"Username": username}, auth=False).json()
        user = SrpUser(password, modulus_from_signed_message(info["Modulus"]))
        client_ephemeral = user.get_challenge()
        proof = user.process_challenge(base64.b64decode(info["Salt"]),
                                       base64.b64decode(info["ServerEphemeral"]),
                                       info["Version"])
        response = self.call("POST", "/auth", {
            "Username": username,
            "ClientEphemeral": base64.b64encode(client_ephemeral).decode(),
            "ClientProof": base64.b64encode(proof).decode(),
            "SRPSession": info["SRPSession"],
        }, auth=False)
        if response.status_code == 200:
            data = response.json()
            user.verify_session(base64.b64decode(data["ServerProof"]))
            response.srp_verified = user.authenticated()
            self.uid, self.access = data["UID"], data["AccessToken"]
            self.refresh_token, self.scopes = data["RefreshToken"], data["Scopes"]
        return response, info

    def refresh(self) -> requests.Response:
        response = self.call("POST", "/auth/refresh", {
            "ResponseType": "token", "GrantType": "refresh_token",
            "RefreshToken": self.refresh_token, "RedirectURI": "http://protonmail.ch"},
            auth=False, headers={"x-pm-uid": self.uid})
        if response.status_code == 200:
            data = response.json()
            self.access, self.refresh_token = data["AccessToken"], data["RefreshToken"]
            self.scopes = data["Scopes"]
        return response

    def request_with_refresh(self, method: str, path: str, body=None) -> requests.Response:
        """The client's 401 -> refresh -> retry path."""
        response = self.call(method, path, body)
        if response.status_code == 401 and self.refresh().status_code == 200:
            response = self.call(method, path, body)
            response.refreshed = True
        return response

    def control(self, **body):
        response = self.http.post(self.base + "/fake/control", json=body, timeout=10)
        response.raise_for_status()
        return response.json()


def is_error(response: requests.Response, status: int, code: int) -> bool:
    try:
        data = response.json()
    except ValueError:
        return False
    return (response.status_code == status and data.get("Code") == code
            and isinstance(data.get("Error"), str) and isinstance(data.get("Details"), dict))


# -- docker helpers -----------------------------------------------------------------------

def docker(*args, check_rc=True, timeout=120) -> subprocess.CompletedProcess:
    result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    if check_rc and result.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args)} failed: {result.stdout}{result.stderr}")
    return result


def in_client(command: str, timeout=60, check_rc=False) -> subprocess.CompletedProcess:
    return docker("exec", CLIENT_CONTAINER, "sh", "-c", command, check_rc=check_rc,
                  timeout=timeout)


def bridge_gateway() -> str:
    result = docker("network", "inspect", "bridge", "--format",
                    "{{(index .IPAM.Config 0).Gateway}}", check_rc=False)
    return result.stdout.strip() or "172.17.0.1"


def wait_for(predicate, timeout: float, interval: float = 0.5) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


# -- certificate helpers ----------------------------------------------------------------

def new_key():
    key = ed25519.Ed25519PrivateKey.generate()
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return key, public_pem


def x25519_keys(key: ed25519.Ed25519PrivateKey) -> tuple[str, str]:
    """WireGuard keys derived from the Ed25519 key, as python-proton-vpn-api-core does."""
    seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.Raw,
                                           serialization.PublicFormat.Raw)
    secret = nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(seed + public)
    x_public = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(public)
    return base64.b64encode(secret).decode(), base64.b64encode(x_public).decode()


def proton_extensions(cert: x509.Certificate) -> dict:
    found = {}
    for extension in cert.extensions:
        oid = extension.oid.dotted_string
        if oid.startswith(PROTON_OID):
            found[oid[len(PROTON_OID):]] = extension.value.value
    return found


def write_client_material(key, certificate_pem: str, stem: str):
    WORK.mkdir(parents=True, exist_ok=True)
    (WORK / f"{stem}.key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    (WORK / f"{stem}.pem").write_text(certificate_pem)


def upstream_openvpn_template() -> str:
    path = (UPSTREAM / "python-proton-vpn-api-core" / "proton" / "vpn" / "backend" /
            "networkmanager" / "protocol" / "openvpn" / "openvpn.py")
    for node in ast.parse(path.read_text()).body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == \
                "OPENVPN_V2_TEMPLATE":
            return node.value.value
    raise RuntimeError("OPENVPN_V2_TEMPLATE not found in openvpn.py")


def render_openvpn(protocol: str, server: str, port: int, cert_pem: str, key_pem: str) -> str:
    from jinja2 import BaseLoader, Environment
    template = Environment(loader=BaseLoader, autoescape=True).from_string(
        upstream_openvpn_template())
    config = template.render({
        "enable_ipv6_support": False,
        "openvpn_protocol": protocol,
        "serverlist": [server],
        "openvpn_ports": [port],
        "ca_certificate": (STATE / "openvpn-ca.pem").read_text().strip(),
        "cert": cert_pem.strip(),
        "priv_key": key_pem.strip(),
    })
    # NetworkManager adds this from the server's Domain (openvpn.py
    # _set_server_certificate_check: verify-x509-name "name:<domain>").
    return config + f"\nverify-x509-name {DOMAIN} name\n"


# -- test phases -----------------------------------------------------------------------------

def test_api(api: Api, tls_api: Api) -> dict:
    section("REST API basics")
    response = api.call("GET", "/tests/ping", auth=False)
    check("GET /tests/ping -> 1000", response.status_code == 200
          and response.json() == {"Code": 1000})
    check("Content-Type is exactly application/json (python-proton-core compares it)",
          response.headers.get("Content-Type") == "application/json",
          response.headers.get("Content-Type"))
    response = api.call("GET", "/tests/ping", auth=False, appversion=False)
    check("missing x-pm-appversion -> HTTP 400 Code 5001", is_error(response, 400, 5001),
          response.text)
    try:
        response = tls_api.call("GET", "/tests/ping", auth=False)
        check(f"HTTPS on {HTTPS_PORT} verifies against state/api-ca.pem",
              response.status_code == 200)
    except requests.RequestException as exc:
        check(f"HTTPS on {HTTPS_PORT} verifies against state/api-ca.pem", False, exc)
    server_cert = x509.load_pem_x509_certificate((STATE / "api-server.pem").read_bytes())
    sans = server_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    check("API certificate covers 10.0.2.2 (QEMU guest view of the host)",
          "10.0.2.2" in [str(ip) for ip in sans.get_values_for_type(x509.IPAddress)])
    response = api.call("GET", "/does/not/exist", auth=False)
    check("unknown route -> JSON error shape", is_error(response, 404, 2501), response.text)

    section("SRP login (python-proton-core SRP client)")
    info = api.call("POST", "/auth/info", {"Username": "demo"}, auth=False).json()
    reference = json.loads((REPO / "tests" / "data" / "auth-info.json").read_text())
    check("/auth/info Modulus is byte-identical to tests/data/auth-info.json",
          info.get("Modulus") == reference["Modulus"])
    check("/auth/info Version 4, 10-byte Salt, 256-byte ServerEphemeral, hex SRPSession",
          info.get("Version") == 4 and len(base64.b64decode(info["Salt"])) == 10
          and len(base64.b64decode(info["ServerEphemeral"])) == 256
          and all(c in "0123456789abcdef" for c in info["SRPSession"]), info)
    wrong = Api(api.base)
    response, _ = wrong.login("demo", "not-the-password")
    check("wrong password -> HTTP 422 Code 8002", is_error(response, 422, 8002)
          and response.json()["Error"] == "Incorrect login credentials. Please try again.",
          response.text)
    response, _ = Api(api.base).login("nobody", "demo")
    check("unknown user -> HTTP 422 Code 8002", is_error(response, 422, 8002), response.text)

    response, _ = api.login("demo", "demo")
    data = response.json()
    check("demo/demo login succeeds", response.status_code == 200, response.text)
    check("server proof verified by the upstream client", getattr(response, "srp_verified", False))
    check("/auth reply shape (UID, tokens, Scopes, 2FA, PasswordMode)",
          all(k in data for k in ("UID", "AccessToken", "RefreshToken", "Scopes", "ServerProof",
                                  "2FA", "PasswordMode"))
          and data["2FA"] == {"Enabled": 0, "FIDO2": {"AuthenticationOptions": None,
                                                     "RegisteredKeys": []}, "TOTP": 0}
          and "vpn" in data["Scopes"] and data["PasswordMode"] == 1, data)

    section("Account and server endpoints")
    response = api.call("GET", "/vpn/v2")
    vpn = response.json()
    check("GET /vpn/v2 (VPNSettings shape, Plus)", response.status_code == 200
          and vpn["VPN"]["MaxTier"] == 2 and vpn["VPN"]["PlanTitle"] == "VPN Plus"
          and vpn["VPN"]["PlanName"] == "vpn2022" and vpn["VPN"]["MaxConnect"] == 10
          and all(k in vpn for k in ("Services", "Subscribed", "Delinquent", "HasPaymentMethod",
                                     "Credit", "Currency", "Warnings")), vpn)
    location = api.call("GET", "/vpn/v1/location").json()
    check("GET /vpn/v1/location", location == {"Code": 1000, "IP": "203.0.113.7", "Lat": -42.88,
                                               "Long": 147.33, "Country": "AU",
                                               "ISP": "Fake ISP"}, location)
    config = api.call("GET", "/vpn/v2/clientconfig").json()
    ports = config.get("DefaultPorts", {})
    check("GET /vpn/v2/clientconfig points at the published ports",
          ports.get("OpenVPN") == {"UDP": [OVPN_UDP_PORT], "TCP": [OVPN_TCP_PORT]}
          and ports.get("WireGuard", {}).get("UDP") == [WG_PORT]
          and all(k in config for k in ("HolesIPs", "ServerRefreshInterval", "FeatureFlags",
                                        "SmartProtocol", "ChangeServerAttemptLimit")), ports)
    flags = api.call("GET", "/feature/v2/frontend").json()
    check("GET /feature/v2/frontend -> no toggles", flags == {"Code": 1000, "toggles": []}, flags)
    sessions = api.call("GET", "/vpn/v1/sessions").json()
    check("GET /vpn/v1/sessions", sessions == {"Code": 1000, "Sessions": []}, sessions)
    for path in ("/users", "/auth/scopes", "/core/v4/notifications", "/vpn/v1/cities/names"):
        response = api.call("GET", path)
        check(f"GET {path}", response.status_code == 200 and response.json()["Code"] == 1000,
              response.text[:200])
    response = api.call("POST", "/core/v4/reports/bug", files={
        "OS": (None, "air/OS"), "Description": (None, "self-test report"),
        "Attachment": ("log.txt", b"log line\n", "text/plain")})
    check("POST /core/v4/reports/bug (multipart)", response.status_code == 200
          and response.json()["Code"] == 1000, response.text)

    section("Server list")
    epoch = "Thu, 01 Jan 1970 00:00:00 GMT"
    response = api.call("GET", "/vpn/v1/logicals?SecureCoreFilter=all&WithState=true",
                        headers={"If-Modified-Since": epoch, "X-PM-netzone": "203.0.113.0"})
    logicals = response.json().get("LogicalServers", [])
    last_modified = response.headers.get("Last-Modified")
    check("GET /vpn/v1/logicals -> 200 with Last-Modified", response.status_code == 200
          and bool(last_modified), response.status_code)
    countries = {s["ExitCountry"] for s in logicals}
    physicals = [p for s in logicals for p in s["Servers"]]
    wg_public = (STATE / "wg-server.pub").read_text().strip()
    check(f"~150 logicals across >= 25 countries ({len(logicals)} / {len(countries)})",
          len(logicals) >= 140 and len(countries) >= 25)
    check("UK (not GB) is the United Kingdom", "UK" in countries and "GB" not in countries)
    check("free servers in JP, NL, US, PL, RO, NO, MX, CA, SG",
          {"JP", "NL", "US", "PL", "RO", "NO", "MX", "CA", "SG"} <=
          {s["ExitCountry"] for s in logicals if s["Tier"] == 0})
    check("Secure Core servers enter via CH/SE/IS",
          {s["EntryCountry"] for s in logicals if s["Features"] & 1} == {"CH", "SE", "IS"})
    check("Tor and P2P servers present", any(s["Features"] & 2 and s["Name"].endswith("-TOR")
                                             for s in logicals)
          and any(s["Features"] & 4 for s in logicals))
    check("smart routing servers (HostCountry set)", any(s["HostCountry"] for s in logicals))
    check("US servers carry a State", all(s["State"] for s in logicals
                                         if s["ExitCountry"] == "US"))
    check("servers in maintenance, and PT entirely",
          any(s["Status"] == 0 and s["ExitCountry"] != "PT" for s in logicals)
          and all(s["Status"] == 0 for s in logicals if s["ExitCountry"] == "PT"))
    check(f"every physical server: EntryIP {ENTRY_IP}, Domain {DOMAIN}, X25519 = wg-server.pub",
          all(p["EntryIP"] == ENTRY_IP and p["Domain"] == DOMAIN
              and p["X25519PublicKey"] == wg_public for p in physicals))
    required = {"ID", "Name", "EntryCountry", "ExitCountry", "HostCountry", "Domain", "Tier",
                "Features", "City", "State", "Region", "Score", "Load", "Status", "Location",
                "Servers"}
    check("logical server fields", all(required <= set(s) for s in logicals))
    response = api.call("GET", "/vpn/v1/logicals?SecureCoreFilter=all&WithState=true",
                        headers={"If-Modified-Since": last_modified})
    check("If-Modified-Since: <Last-Modified> -> 304", response.status_code == 304,
          response.status_code)
    response = api.call("GET", "/vpn/logicals", headers={"If-Modified-Since": epoch})
    check("/vpn/logicals alias", response.status_code == 200
          and len(response.json()["LogicalServers"]) == len(logicals))
    loads1 = api.call("GET", "/vpn/v1/loads").json()["LogicalServers"]
    loads2 = api.call("GET", "/vpn/v1/loads").json()["LogicalServers"]
    check("GET /vpn/v1/loads covers every logical, loads change between calls",
          {s["ID"] for s in logicals} <= {s["ID"] for s in loads1}
          and [s["Load"] for s in loads1] != [s["Load"] for s in loads2]
          and set(loads1[0]) == {"ID", "Load", "Score", "Status"})

    api.control(action="set_maintenance", servers=["CH#1"], status=0)
    response = api.call("GET", "/vpn/v1/logicals", headers={"If-Modified-Since": last_modified})
    changed = [s for s in response.json().get("LogicalServers", []) if s["Name"] == "CH#1"] \
        if response.status_code == 200 else []
    check("control set_maintenance -> new Last-Modified and CH#1 Status 0",
          response.status_code == 200 and changed and changed[0]["Status"] == 0,
          response.status_code)
    api.control(action="reset_maintenance")
    return {"logicals": logicals}


def test_tokens_and_2fa(api: Api):
    section("Tokens: refresh, expiry, logout")
    old_access = api.access
    response = api.refresh()
    check("POST /auth/refresh -> new tokens", response.status_code == 200
          and api.access != old_access and "vpn" in api.scopes, response.text)
    stale = Api(api.base)
    stale.uid, stale.access = api.uid, old_access
    check("old access token -> HTTP 401 Code 401", is_error(stale.call("GET", "/vpn/v2"), 401, 401))
    api.control(action="expire_tokens", uid=api.uid)
    response = api.request_with_refresh("GET", "/vpn/v2")
    check("expire_tokens: 401 -> /auth/refresh -> retry succeeds", response.status_code == 200
          and getattr(response, "refreshed", False), response.text)
    bogus = Api(api.base)
    bogus.uid, bogus.refresh_token = api.uid, "0" * 32
    check("unknown refresh token -> HTTP 422", bogus.refresh().status_code == 422)

    section("Two-factor authentication")
    twofa = Api(api.base)
    response, _ = twofa.login("twofa", "twofa")
    data = response.json()
    check("twofa/twofa login: Scopes [twofactor], 2FA Enabled 1 / TOTP 1",
          response.status_code == 200 and data["Scopes"] == ["twofactor"]
          and data["2FA"]["Enabled"] == 1 and data["2FA"]["TOTP"] == 1, data)
    check("before 2FA: GET /vpn/v2 -> 403", twofa.call("GET", "/vpn/v2").status_code == 403)
    response = twofa.call("POST", "/auth/2fa", {"TwoFactorCode": "000000"})
    check("wrong 2FA code -> HTTP 422 Code 2028", is_error(response, 422, 2028), response.text)
    response = twofa.call("POST", "/auth/2fa", {"TwoFactorCode": "123456"})
    check("static code 123456 -> full scopes", response.status_code == 200
          and "vpn" in response.json().get("Scopes", []), response.text)
    check("after 2FA: GET /vpn/v2 -> 200", twofa.call("GET", "/vpn/v2").status_code == 200)

    users = json.loads((FAKE / "users.json").read_text())
    second = Api(api.base)
    second.login("twofa", "twofa")
    response = second.call("POST", "/auth/2fa",
                           {"TwoFactorCode": totp(users["totp_secret"], time.time())})
    check("TOTP code of the documented secret is accepted", response.status_code == 200,
          response.text)
    third = Api(api.base)
    third.login("twofa", "twofa")
    codes = [third.call("POST", "/auth/2fa", {"TwoFactorCode": "999999"})
             for _ in range(users.get("twofa_max_attempts", 3))]
    check("too many wrong codes -> HTTP 422 Code 8002 and the session is revoked",
          is_error(codes[-1], 422, 8002) and third.call("GET", "/auth/scopes").status_code == 401,
          [c.text for c in codes])
    second.call("DELETE", "/auth")
    twofa.call("DELETE", "/auth")

    section("Free account and error injection")
    free = Api(api.base)
    response, _ = free.login("free", "free")
    vpn = free.call("GET", "/vpn/v2").json().get("VPN", {})
    check("free/free: MaxTier 0, PlanTitle Proton Free, PlanName free",
          response.status_code == 200 and vpn.get("MaxTier") == 0
          and vpn.get("PlanTitle") == "Proton Free" and vpn.get("PlanName") == "free", vpn)
    api.control(action="human_verification", path="/vpn/v2", count=1)
    response = free.call("GET", "/vpn/v2")
    check("control human_verification -> HTTP 422 Code 9001 with methods",
          is_error(response, 422, 9001)
          and "HumanVerificationMethods" in response.json()["Details"], response.text)
    api.control(action="fail_next", path="/vpn/v1/loads", status=503, code=503,
                headers={"Retry-After": "1"})
    response = free.call("GET", "/vpn/v1/loads")
    check("control fail_next -> HTTP 503 with Retry-After", response.status_code == 503
          and response.headers.get("Retry-After") == "1")
    check("injected failures are one-shot", free.call("GET", "/vpn/v1/loads").status_code == 200)
    return free


def issue_certificate(api: Api, features: dict | None, stem: str, tier: int):
    key, public_pem = new_key()
    body = {"ClientPublicKey": public_pem, "Duration": "10080 min"}
    if features is not None:
        body["Features"] = features
    started = time.time()
    response = api.call("POST", "/vpn/v1/certificate", body)
    data = response.json()
    label = f"POST /vpn/v1/certificate ({stem})"
    if not check(label, response.status_code == 200, response.text):
        raise SystemExit(1)
    cert = x509.load_pem_x509_certificate(data["Certificate"].encode())
    ca = x509.load_pem_x509_certificate((STATE / "vpn-client-ca.pem").read_bytes())
    _, wg_public = x25519_keys(key)
    x_raw = base64.b64decode(wg_public)
    try:
        ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes)
        signed = True
    except Exception:  # noqa: BLE001
        signed = False
    check(f"  {stem}: signed by vpn-client-ca (ProtonVPN test CA, Ed25519)",
          signed and cert.issuer == ca.subject)
    check(f"  {stem}: certificate key is the requested Ed25519 key",
          cert.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()
          == public_pem and data["ClientKey"] == public_pem)
    check(f"  {stem}: ClientKeyFingerprint = base64(SHA-512(X25519 public key))",
          data["ClientKeyFingerprint"] == base64.b64encode(hashlib.sha512(x_raw).digest()).decode())
    check(f"  {stem}: ExpirationTime/RefreshTime match Duration 10080 min",
          abs(data["ExpirationTime"] - started - 10080 * 60) < 30
          and abs(data["RefreshTime"] - started - 10080 * 60 * 3 / 4) < 30, data)
    check(f"  {stem}: reply fields (Mode, ServerPublicKeyMode, SerialNumber)",
          data["Mode"] == "persistent" and data["ServerPublicKeyMode"] == "EC"
          and data["DeviceName"] == "" and data["SerialNumber"] == str(cert.serial_number))
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    extensions = proton_extensions(cert)
    check(f"  {stem}: clientAuth EKU and Proton tier extension",
          ExtendedKeyUsageOID.CLIENT_AUTH in eku and extensions.get("0.0.1") == bytes(
              [2, 1, tier]), extensions)
    if features:
        check(f"  {stem}: requested Features embedded (NetShield {features.get('NetShieldLevel')})",
              extensions.get("0.1.0") == bytes([2, 1, features.get("NetShieldLevel", 0)]),
              extensions)
    peers = docker("exec", SERVER_CONTAINER, "wg", "show", "wg0", "peers",
                   check_rc=False).stdout.split()
    check(f"  {stem}: X25519 key registered as the only WireGuard peer", peers == [wg_public],
          peers)
    write_client_material(key, data["Certificate"], stem)
    return key, data


def run_probe(label: str, stem: str, expect_ip: str | None, protocol: str | None, tier: int,
              netshield: int, extra: str = "") -> bool:
    api = f"http://{bridge_gateway()}:{HTTP_PORT}"
    command = (f"python3 /selftest/tunnel_probe.py --label {label} --domain {DOMAIN} "
               f"--cert /work/{stem}.pem --key /work/{stem}.key --agent-ca /work/agent-ca.pem "
               f"--tier {tier} --expect-netshield {netshield} --api {api} {extra}")
    if expect_ip:
        command += f" --expect-ip {expect_ip}"
    if protocol:
        command += f" --expect-protocol {protocol}"
    if os.environ.get("FAKE_PROTON_TEST_INTERNET"):
        command += f" --internet {os.environ['FAKE_PROTON_TEST_INTERNET']}"
    result = in_client(command, timeout=120)
    try:
        report = json.loads(result.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return check(f"{label}: probe ran", False, result.stdout + result.stderr)
    for item in report["checks"]:
        check(f"{label}: {item['name']}", item["ok"], item["detail"])
    return report["ok"]


def wireguard_handshake(client_secret_b64: str, server_public_b64: str, host: str, port: int,
                        timeout: float = 5.0) -> bool:
    """Sends a WireGuard handshake initiation (Noise_IKpsk2, as in the WireGuard
    paper) and returns True when the server answers with a handshake response.
    Used from the host against 127.0.0.1, the path QEMU's slirp takes for a
    guest talking to 10.0.2.2."""
    import socket
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    def blake(data: bytes) -> bytes:
        return hashlib.blake2s(data).digest()

    def hmac_b(key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, hashlib.blake2s).digest()

    def kdf2(key: bytes, data: bytes) -> tuple[bytes, bytes]:
        prk = hmac_b(key, data)
        first = hmac_b(prk, b"\x01")
        return first, hmac_b(prk, first + b"\x02")

    def raw_public(private_key) -> bytes:
        return private_key.public_key().public_bytes(serialization.Encoding.Raw,
                                                     serialization.PublicFormat.Raw)

    static = X25519PrivateKey.from_private_bytes(base64.b64decode(client_secret_b64))
    server_raw = base64.b64decode(server_public_b64)
    server = X25519PublicKey.from_public_bytes(server_raw)
    ephemeral = X25519PrivateKey.generate()
    chain = blake(b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")
    hashed = blake(blake(chain + b"WireGuard v1 zx2c4 Jason@zx2c4.com") + server_raw)
    e_pub = raw_public(ephemeral)
    chain = hmac_b(hmac_b(chain, e_pub), b"\x01")
    hashed = blake(hashed + e_pub)
    chain, key = kdf2(chain, ephemeral.exchange(server))
    encrypted_static = ChaCha20Poly1305(key).encrypt(b"\0" * 12, raw_public(static), hashed)
    hashed = blake(hashed + encrypted_static)
    chain, key = kdf2(chain, static.exchange(server))
    now = time.time()
    tai64n = struct.pack(">QI", 0x400000000000000A + int(now), int((now % 1) * 1e9))
    encrypted_time = ChaCha20Poly1305(key).encrypt(b"\0" * 12, tai64n, hashed)
    sender = int.from_bytes(os.urandom(4), "little")
    message = struct.pack("<I", 1) + struct.pack("<I", sender) + e_pub + encrypted_static \
        + encrypted_time
    mac_key = blake(b"mac1----" + server_raw)
    message += hashlib.blake2s(message, digest_size=16, key=mac_key).digest() + b"\0" * 16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(message, (host, port))
        try:
            answer, _ = sock.recvfrom(256)
        except socket.timeout:
            return False
    return len(answer) == 92 and answer[0] == 2 and \
        struct.unpack("<I", answer[8:12])[0] == sender


def test_loopback_path(key):
    section("Published ports on 127.0.0.1 (the path of a QEMU guest's 10.0.2.2)")
    secret, _ = x25519_keys(key)
    server_public = (STATE / "wg-server.pub").read_text().strip()
    check(f"WireGuard handshake via 127.0.0.1:{WG_PORT}/udp",
          wireguard_handshake(secret, server_public, "127.0.0.1", WG_PORT))
    import socket
    try:
        socket.create_connection(("127.0.0.1", OVPN_TCP_PORT), timeout=5).close()
        reachable = True
    except OSError:
        reachable = False
    check(f"OpenVPN TCP port 127.0.0.1:{OVPN_TCP_PORT} accepts connections", reachable)


def start_client_container():
    WORK.mkdir(parents=True, exist_ok=True)
    shutil.copy(STATE / "agent-ca.pem", WORK / "agent-ca.pem")
    docker("rm", "-f", CLIENT_CONTAINER, check_rc=False)
    docker("run", "-d", "--name", CLIENT_CONTAINER, "--label", "fake-proton=selftest",
           "--dns", "1.1.1.1", "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
           "-v", f"{WORK}:/work:ro", "-v", f"{HERE}:/selftest:ro",
           IMAGE, "sleep", "3600")


def test_wireguard(key, stem: str):
    section("WireGuard tunnel (throwaway client container)")
    gateway = bridge_gateway()
    secret, _ = x25519_keys(key)
    server_public = (STATE / "wg-server.pub").read_text().strip()
    (WORK / "wg-client.key").write_text(secret + "\n")
    setup = (
        "ip link del wg0 2>/dev/null; ip link add wg0 type wireguard && "
        f"wg set wg0 private-key /work/wg-client.key peer {server_public} "
        f"endpoint {gateway}:{WG_PORT} allowed-ips 0.0.0.0/0 persistent-keepalive 5 && "
        "ip address add 10.2.0.2/32 dev wg0 && ip link set wg0 mtu 1420 up && "
        "ip route add 0.0.0.0/1 dev wg0 && ip route add 128.0.0.0/1 dev wg0"
    )
    result = in_client(setup)
    if not check(f"wg0 up in the client container (endpoint {gateway}:{WG_PORT}, 10.2.0.2/32)",
                 result.returncode == 0, result.stdout + result.stderr):
        return
    route = in_client("ip route get 10.2.0.1").stdout
    check("10.2.0.1 is routed through wg0 inside the container", "dev wg0" in route, route)
    run_probe("wireguard", stem, "10.2.0.2", "wireguard", 2, 1,
              "--jail-test --no-cert-check")
    shown = in_client("wg show wg0").stdout
    check("WireGuard handshake completed", "latest handshake" in shown, shown)
    in_client("ip link del wg0")


def test_openvpn(protocol: str, stem: str, free_stem: str | None):
    port = OVPN_UDP_PORT if protocol == "udp" else OVPN_TCP_PORT
    section(f"OpenVPN {protocol.upper()} tunnel (upstream client template)")
    gateway = bridge_gateway()
    config = render_openvpn(protocol, gateway, port, (WORK / f"{stem}.pem").read_text(),
                            (WORK / f"{stem}.key").read_text())
    name = f"client-{protocol}.ovpn"
    (WORK / name).write_text(config)
    log = f"/tmp/openvpn-{protocol}.log"
    in_client(f"rm -f {log}; openvpn --config /work/{name} --log {log} "
              f"--writepid /tmp/openvpn-{protocol}.pid --daemon")
    up = wait_for(lambda: "Initialization Sequence Completed" in
                  in_client(f"cat {log} 2>/dev/null").stdout, 40)
    text = in_client(f"cat {log}").stdout
    if not check(f"OpenVPN {protocol.upper()} connects to {gateway}:{port}", up, text[-3000:]):
        in_client(f"kill $(cat /tmp/openvpn-{protocol}.pid) 2>/dev/null")
        return
    x509_line = next((line for line in text.splitlines() if "VERIFY X509NAME OK" in line), "")
    check("TLS: server certificate passes verify-x509-name and remote-cert-tls server",
          f"CN={DOMAIN}" in x509_line and "VERIFY EKU OK" in text, x509_line)
    push = next((line for line in text.splitlines() if "PUSH_REPLY" in line), "")
    check("pushed redirect-gateway def1, DNS 10.2.0.1 and a route to 10.2.0.1",
          "redirect-gateway def1" in push and "dhcp-option DNS 10.2.0.1" in push
          and "route 10.2.0.1 255.255.255.255" in push, push)
    check("data channel cipher AES-256-GCM", "AES-256-GCM" in text)
    address = in_client("ip -4 -o address show dev tun0 | awk '{print $4}' | cut -d/ -f1"
                        ).stdout.strip()
    route = in_client("ip route get 10.2.0.1").stdout
    check(f"tun0 has {address}; 10.2.0.1 routed through tun0", "dev tun0" in route
          and address.startswith("10.96." if protocol == "udp" else "10.97."), route)
    run_probe(f"openvpn-{protocol}", stem, address, f"openvpn-{protocol}", 2, 1)
    if free_stem:
        run_probe(f"openvpn-{protocol}/free-cert", free_stem, None, None, 0, 0, "--agent-only")
    in_client(f"kill $(cat /tmp/openvpn-{protocol}.pid) 2>/dev/null")
    wait_for(lambda: in_client("ip link show tun0").returncode != 0, 15)


def main():
    parser = argparse.ArgumentParser(description="fake Proton self-test")
    parser.add_argument("--api-only", action="store_true", help="skip the tunnel tests")
    parser.add_argument("--keep", action="store_true", help="keep the client container")
    args = parser.parse_args()

    api = Api(f"http://127.0.0.1:{HTTP_PORT}")
    tls_api = Api(f"https://127.0.0.1:{HTTPS_PORT}", verify=str(STATE / "api-ca.pem"))
    try:
        api.control(action="reset")
    except requests.RequestException as exc:
        print(f"fake API not reachable on port {HTTP_PORT}: {exc}\n"
              "start it with: tools/fake-proton.sh start")
        return 2

    try:
        test_api(api, tls_api)
        free = test_tokens_and_2fa(api)
        section("VPN certificates")
        key, _ = issue_certificate(free, None, "free-client", 0)
        key, _ = issue_certificate(api, {"NetShieldLevel": 1, "RandomNAT": False}, "client", 2)
        if not args.api_only:
            if docker("inspect", SERVER_CONTAINER, check_rc=False).returncode != 0:
                check(f"server container {SERVER_CONTAINER} is running", False)
            else:
                test_loopback_path(key)
                start_client_container()
                test_wireguard(key, "client")
                test_openvpn("udp", "client", None)
                test_openvpn("tcp", "client", "free-client")
        section("Logout")
        response = api.call("DELETE", "/auth")
        check("DELETE /auth -> 1000", response.status_code == 200
              and response.json()["Code"] == 1000)
        check("after logout: GET /vpn/v2 -> 401", api.call("GET", "/vpn/v2").status_code == 401)
        free.call("DELETE", "/auth")
    finally:
        for client in Api.created:
            if client.uid and client.access:
                try:
                    client.call("DELETE", "/auth")
                except requests.RequestException:
                    pass
        try:
            api.control(action="reset")
        except requests.RequestException:
            pass
        if not args.keep:
            docker("rm", "-f", CLIENT_CONTAINER, check_rc=False)

    failed = [name for name, ok, _ in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    if failed:
        print("FAILED:\n  " + "\n  ".join(failed))
        return 1
    print("fake Proton self-test PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
