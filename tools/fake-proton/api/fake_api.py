#!/usr/bin/env python3
"""Fake Proton VPN REST API for end-to-end testing without a Proton account.

Serves plain HTTP (default 0.0.0.0:18080) and HTTPS (default 0.0.0.0:18443,
certificate from state/api-ca.pem). See tools/fake-proton/README.md.

    python3 fake_api.py              # run the servers
    python3 fake_api.py --init-only  # just create tools/fake-proton/state/
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import datetime
import email.utils
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import ssl
import struct
import sys
import time
import traceback
from pathlib import Path

import nacl.bindings
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import pki  # noqa: E402
import servers  # noqa: E402
import srp_server  # noqa: E402


def env(name: str, default: str) -> str:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


STATE_DIR = Path(env("FAKE_PROTON_STATE", str(ROOT / "state")))
USERS_FILE = Path(env("FAKE_PROTON_USERS", str(ROOT / "users.json")))
MODULUS_FILE = HERE / "srp-modulus.asc"
BIND = env("FAKE_PROTON_BIND", "0.0.0.0")
HTTP_PORT = int(env("FAKE_PROTON_HTTP_PORT", "18080"))
HTTPS_PORT = int(env("FAKE_PROTON_HTTPS_PORT", "18443"))
ENTRY_IP = env("FAKE_PROTON_ENTRY_IP", "10.0.2.2")
DOMAIN = env("FAKE_PROTON_DOMAIN", pki.DEFAULT_DOMAIN)
CONTAINER = env("FAKE_PROTON_CONTAINER", "fake-proton-vpn")
OVPN_UDP_PORT = int(env("FAKE_PROTON_OVPN_UDP_PORT", "11940"))
OVPN_TCP_PORT = int(env("FAKE_PROTON_OVPN_TCP_PORT", "11941"))
WG_PORT = int(env("FAKE_PROTON_WG_PORT", "51830"))
TOKEN_TTL = int(env("FAKE_PROTON_TOKEN_TTL", "1800"))
CERT_TTL = env("FAKE_PROTON_CERT_TTL", "")          # seconds; overrides Duration
CERT_BACKDATE = int(env("FAKE_PROTON_CERT_BACKDATE", "60"))
NO_DOCKER = env("FAKE_PROTON_NO_DOCKER", "0") == "1"
WG_CLIENT_ADDRESS = "10.2.0.2/32"

FULL_SCOPES = ["full", "self", "payments", "keys", "parent", "user", "loggedin",
               "nondelinquent", "verified", "settings", "vpn"]
TWOFA_SCOPES = ["twofactor"]

PROTON_OID = "1.3.6.1.4.1.56809.1"      # Proton's certificate extension arc
CERT_FEATURE_OIDS = {                    # /vpn/v1/certificate "Features" -> extension
    "NetShieldLevel": "0.1.0",
    "PortForwarding": "0.1.3",
    "Jail": "0.1.5",
    "SplitTCP": "0.1.6",
    "RandomNAT": "0.1.7",
    "Bouncing": "0.1.8",
    "SafeMode": "0.1.9",
}

DEFAULT_LOCATION = {"IP": "203.0.113.7", "Lat": -42.88, "Long": 147.33, "Country": "AU",
                    "ISP": "Fake ISP"}
DEFAULT_AGENT = {
    "mode": "connected",            # connected | hard-jailed | error | drop | silent
    "reason": None,                 # for hard-jailed
    "error": None,                  # for error
    "push_on_connect": True,
    "server_ipv4": "198.51.100.1",
    "natpmp_mode": "ok",            # ok | refuse | silent
    "natpmp_port": 61234,
}

CLIENT_CONFIG = {
    "DefaultPorts": {
        "OpenVPN": {"UDP": [OVPN_UDP_PORT], "TCP": [OVPN_TCP_PORT]},
        "WireGuard": {"UDP": [WG_PORT], "TCP": [], "TLS": []},
    },
    "HolesIPs": ["62.112.9.168", "104.245.144.186"],
    "ServerRefreshInterval": 10,
    "FeatureFlags": {
        "NetShield": True, "GuestHoles": False, "ServerRefresh": True,
        "StreamingServicesLogos": True, "PortForwarding": True, "ModerateNAT": True,
        "SafeMode": False, "StartConnectOnBoot": True, "PollNotificationAPI": True,
        "VpnAccelerator": True, "SmartReconnect": True, "PromoCode": False,
        "WireGuardTls": False, "Telemetry": False, "NetShieldStats": True,
    },
    "SmartProtocol": {"OpenVPN": True, "IKEv2": False, "WireGuard": True,
                      "WireGuardTCP": False, "WireGuardTLS": False},
    "RatingSettings": {"EligiblePlans": [], "SuccessConnections": 3,
                       "DaysLastReviewPassed": 100, "DaysConnected": 3,
                       "DaysFromFirstConnection": 14},
    "ChangeServerAttemptLimit": 4,
    "ChangeServerShortDelayInSeconds": 90,
    "ChangeServerLongDelayInSeconds": 1200,
}


# -- small helpers ------------------------------------------------------------

def log(message: str) -> None:
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{stamp} {message}", flush=True)


def reply(data: dict | None = None, status: int = 200, headers: dict | None = None) -> web.Response:
    body = {"Code": 1000}
    body.update(data or {})
    # Exactly "application/json" (no charset): python-proton-core compares it verbatim.
    return web.Response(body=json.dumps(body).encode(), status=status,
                        content_type="application/json", headers=headers)


def error(status: int, code: int, message: str, details: dict | None = None,
          headers: dict | None = None) -> web.Response:
    body = {"Code": code, "Error": message, "Details": details or {}}
    return web.Response(body=json.dumps(body).encode(), status=status,
                        content_type="application/json", headers=headers)


def http_date(timestamp: float) -> str:
    return email.utils.formatdate(timestamp, usegmt=True)


def totp(secret: str, at: float, step: int = 30, digits: int = 6) -> str:
    key = base64.b32decode(secret.upper().replace(" ", "") + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", int(at // step)), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 10 ** digits
    return f"{value:0{digits}d}"


def der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def der_int(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big", signed=True)
    return b"\x02" + der_length(len(raw)) + raw


def der_octets(text: str) -> bytes:
    raw = text.encode()
    return b"\x04" + der_length(len(raw)) + raw


def der_sequence(items: list[bytes]) -> bytes:
    raw = b"".join(items)
    return b"\x30" + der_length(len(raw)) + raw


def parse_duration(value) -> int | None:
    """'10080 min' -> seconds."""
    if value is None:
        return 24 * 3600
    match = re.fullmatch(r"\s*(\d+)\s*([a-zA-Z]*)\s*", str(value))
    if not match:
        return None
    number, unit = int(match.group(1)), match.group(2).lower()
    scale = {"": 60, "m": 60, "min": 60, "mins": 60, "minute": 60, "minutes": 60,
             "s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1,
             "h": 3600, "hour": 3600, "hours": 3600, "d": 86400, "day": 86400,
             "days": 86400}.get(unit)
    return number * scale if scale else None


def api_sans() -> tuple[list[str], list[str]]:
    dns, ips = list(pki.DEFAULT_API_DNS), list(pki.DEFAULT_API_IPS)
    hostname = socket.gethostname()
    if hostname and hostname not in dns:
        dns.append(hostname)
    for item in filter(None, (s.strip() for s in env("FAKE_PROTON_API_SANS", "").split(","))):
        try:
            socket.inet_aton(item)
            if item not in ips:
                ips.append(item)
        except OSError:
            if item not in dns:
                dns.append(item)
    return dns, ips


# -- the fake service -----------------------------------------------------------

class FakeProton:
    def __init__(self):
        dns, ips = api_sans()
        self.state = pki.State(STATE_DIR, DOMAIN, dns, ips)
        made = self.state.ensure()
        if made:
            log(f"state: generated {', '.join(made)} in {STATE_DIR}")
        self.modulus_armored = MODULUS_FILE.read_text()
        self.group = srp_server.SrpGroup(srp_server.modulus_from_armored(self.modulus_armored))
        self.load_users()
        self.srp_sessions: dict[str, dict] = {}
        self.sessions: dict[str, dict] = {}
        self.load_sessions()
        self.server_list = servers.ServerList(ENTRY_IP, DOMAIN, self.state.wg_public_key)
        self.reset_controls()
        self.last_peer: str | None = None
        self.peer_lock = asyncio.Lock()

    # -- configuration --------------------------------------------------------
    def load_users(self):
        config = json.loads(USERS_FILE.read_text())
        self.totp_secret = config.get("totp_secret", "JBSWY3DPEHPK3PXP")
        self.static_code = str(config.get("static_twofa_code", "123456"))
        self.twofa_max_attempts = int(config.get("twofa_max_attempts", 3))
        self.users = {}
        for name, user in config["users"].items():
            # A stable per-user salt keeps /auth/info replies identical across restarts.
            salt = hashlib.sha256(b"fake-proton-salt:" + name.lower().encode()).digest()[:10]
            user = dict(user)
            user["name"] = name
            user["salt"] = salt
            user["verifier"] = self.group.verifier(user["password"], salt)
            user["id"] = base64.urlsafe_b64encode(
                hashlib.sha512(b"user:" + name.encode()).digest()).decode()
            self.users[name.lower()] = user
        log(f"users: {', '.join(sorted(self.users))} (2FA secret {self.totp_secret})")

    def reset_controls(self):
        self.token_ttl = TOKEN_TTL
        self.cert_ttl = int(CERT_TTL) if CERT_TTL else None
        self.failures: list[dict] = []
        self.location = dict(DEFAULT_LOCATION)
        self.feature_toggles: list[dict] = []
        self.agent = dict(DEFAULT_AGENT)
        self.server_list.reset_status()
        self.update_last_modified()
        self.write_agent_config()

    # -- persistence ----------------------------------------------------------
    def load_sessions(self):
        path = STATE_DIR / "api-sessions.json"
        if path.exists():
            try:
                self.sessions = json.loads(path.read_text())
            except ValueError:
                self.sessions = {}

    def save_sessions(self):
        path = STATE_DIR / "api-sessions.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.sessions, indent=1))
        os.replace(tmp, path)

    def update_last_modified(self, force: bool = False):
        path = STATE_DIR / "logicals-meta.json"
        meta = json.loads(path.read_text()) if path.exists() else {}
        digest = self.server_list.structure_hash()
        if force or meta.get("hash") != digest or "last_modified" not in meta:
            meta = {"hash": digest, "last_modified": int(time.time())}
            path.write_text(json.dumps(meta))
        self.last_modified = int(meta["last_modified"])

    def write_agent_config(self):
        config = dict(self.agent)
        config.update({"device_ip": self.location["IP"],
                       "device_country": self.location["Country"]})
        path = STATE_DIR / "agent-config.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(config, indent=1))
        os.replace(tmp, path)

    # -- sessions -------------------------------------------------------------
    def new_tokens(self, session: dict):
        session["AccessToken"] = secrets.token_hex(16)
        session["RefreshToken"] = secrets.token_hex(16)
        session["AccessExpires"] = time.time() + self.token_ttl

    def authenticate(self, request: web.Request, mode: str):
        """mode: optional | any (2FA-pending sessions allowed) | full."""
        header = request.headers.get("Authorization", "")
        if not header:
            if mode == "optional":
                return None, None
            request["note"] = "no Authorization header"
            return None, error(401, 401, "Invalid access token")
        token = header[7:].strip() if header.lower().startswith("bearer ") else ""
        uid = request.headers.get("x-pm-uid", "")
        session = self.sessions.get(uid)
        if not uid:
            request["note"] = "Authorization without x-pm-uid"
        elif session is None:
            request["note"] = "unknown UID"
        elif not hmac.compare_digest(session["AccessToken"], token):
            request["note"] = "wrong access token"
        elif time.time() >= session["AccessExpires"]:
            request["note"] = "access token expired"
        else:
            request["user"] = session["Username"]
            if mode == "full" and session["Pending2FA"]:
                request["note"] = "2FA pending"
                return None, error(403, 9101, "Access token does not have sufficient scope")
            return session, None
        return None, error(401, 401, "Invalid access token")

    # -- WireGuard peers ------------------------------------------------------
    async def register_peer(self, x25519_public: str):
        (STATE_DIR / "wg-peers.txt").write_text(f"{x25519_public} {WG_CLIENT_ADDRESS}\n")
        self.last_peer = x25519_public
        if NO_DOCKER:
            return True, "docker disabled"
        async with self.peer_lock:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "docker", "exec", CONTAINER, "/opt/fake-proton/set-peer.sh",
                    x25519_public, WG_CLIENT_ADDRESS,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
                out, _ = await asyncio.wait_for(proc.communicate(), 15)
            except (OSError, asyncio.TimeoutError) as exc:
                return False, str(exc)
            return proc.returncode == 0, out.decode(errors="replace").strip()

    # -- certificates ---------------------------------------------------------
    def issue_certificate(self, public_key: ed25519.Ed25519PublicKey, duration: int,
                          features: dict, user: dict) -> tuple[x509.Certificate, int, int]:
        ca_key, ca_cert = self.state.client_ca
        serial = secrets.randbelow(2 ** 31 - 2) + 1
        now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        not_after = now + datetime.timedelta(seconds=duration)

        def proton_ext(suffix: str, value: bytes):
            return x509.UnrecognizedExtension(x509.ObjectIdentifier(f"{PROTON_OID}.{suffix}"),
                                              value)

        ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, str(serial))]))
            .issuer_name(ca_cert.subject)
            .public_key(public_key)
            .serial_number(serial)
            .not_valid_before(now - datetime.timedelta(seconds=CERT_BACKDATE))
            .not_valid_after(not_after)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .add_extension(proton_ext("0.0.0", der_int(0)), critical=False)
            .add_extension(proton_ext("0.0.1", der_int(int(user["vpn"]["MaxTier"]))),
                           critical=False)
            .add_extension(proton_ext("0.0.2", der_sequence(
                [der_octets(g) for g in user["vpn"].get("Groups", [])])), critical=False)
        )
        for name, suffix in CERT_FEATURE_OIDS.items():
            if name not in features:
                continue
            value = features[name]
            encoded = der_octets(str(value)) if isinstance(value, str) else der_int(int(value))
            builder = builder.add_extension(proton_ext(suffix, encoded), critical=False)
        builder = (
            builder
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                           critical=False)
            .add_extension(x509.AuthorityKeyIdentifier(
                key_identifier=ca_ski.digest,
                authority_cert_issuer=[x509.DirectoryName(ca_cert.subject)],
                authority_cert_serial_number=ca_cert.serial_number), critical=False)
        )
        cert = builder.sign(ca_key, None)
        return cert, serial, int(now.timestamp())

    # -- server list ----------------------------------------------------------
    def not_modified(self, request: web.Request) -> bool:
        value = request.headers.get("If-Modified-Since")
        if not value:
            return False
        try:
            since = email.utils.parsedate_to_datetime(value).timestamp()
        except (TypeError, ValueError):
            return False
        return since >= self.last_modified

    # -- failure injection ------------------------------------------------------
    def injected_failure(self, request: web.Request) -> web.Response | None:
        for rule in list(self.failures):
            path = rule.get("path", "*")
            if path != "*" and not request.path.startswith(path):
                continue
            if rule.get("method") and rule["method"].upper() != request.method:
                continue
            if rule.get("count", 1) > 0:
                rule["count"] = rule.get("count", 1) - 1
                if rule["count"] == 0:
                    self.failures.remove(rule)
            request["note"] = "injected failure"
            return error(int(rule.get("status", 503)), int(rule.get("code", 503)),
                         rule.get("error", "Injected failure"), rule.get("details"),
                         rule.get("headers"))
        return None


# -- request handlers -----------------------------------------------------------

def endpoint(auth: str = "none"):
    def wrap(handler):
        async def run(request: web.Request):
            fake: FakeProton = request.app["fake"]
            session = None
            if auth != "none":
                session, failure = fake.authenticate(request, auth)
                if failure is not None:
                    return failure
            return await handler(fake, request, session)
        run.__name__ = handler.__name__
        return run
    return wrap


async def json_body(request: web.Request) -> dict:
    if not request.can_read_body:
        return {}
    try:
        data = await request.json()
    except ValueError:
        raise web.HTTPBadRequest(reason="Invalid JSON body")
    return data if isinstance(data, dict) else {}


@endpoint()
async def ping(fake, request, session):
    return reply()


@endpoint()
async def auth_info(fake: FakeProton, request, session):
    body = await json_body(request)
    username = str(body.get("Username", "")).strip()
    if not username:
        return error(422, 2000, "Username is required")
    now = time.time()
    for key in [k for k, v in fake.srp_sessions.items() if now - v["created"] > 300]:
        del fake.srp_sessions[key]
    user = fake.users.get(username.lower())
    if user is not None:
        salt, verifier = user["salt"], user["verifier"]
    else:
        # Unknown users get a random verifier, so /auth fails with 8002 like a
        # wrong password and the reply does not reveal whether the user exists.
        salt = secrets.token_bytes(srp_server.SALT_LEN)
        verifier = pow(2, int.from_bytes(secrets.token_bytes(64), "little"), fake.group.N)
    challenge = srp_server.SrpServerSession(fake.group, verifier)
    srp_id = secrets.token_hex(16)
    fake.srp_sessions[srp_id] = {"username": username.lower(), "srp": challenge, "created": now}
    request["user"] = username
    return reply({
        "Modulus": fake.modulus_armored,
        "ServerEphemeral": base64.b64encode(challenge.server_ephemeral).decode(),
        "Version": 4,
        "Salt": base64.b64encode(salt).decode(),
        "SRPSession": srp_id,
        "Username": username,
        "ClaimedAddresses": [],
    })


def twofa_info(user: dict) -> dict:
    enabled = 1 if user.get("twofa") else 0
    return {"Enabled": enabled,
            "FIDO2": {"AuthenticationOptions": None, "RegisteredKeys": []},
            "TOTP": enabled}


@endpoint()
async def auth(fake: FakeProton, request, session):
    body = await json_body(request)
    username = str(body.get("Username", "")).strip().lower()
    request["user"] = username
    pending = fake.srp_sessions.pop(str(body.get("SRPSession", "")), None)
    if pending is None or pending["username"] != username:
        request["note"] = "unknown/expired SRPSession"
        return error(422, 2001, "Invalid SRPSession, please restart the login")
    try:
        client_ephemeral = base64.b64decode(body.get("ClientEphemeral", ""), validate=True)
        client_proof = base64.b64decode(body.get("ClientProof", ""), validate=True)
    except (ValueError, TypeError):
        return error(422, 2001, "Invalid ClientEphemeral or ClientProof")
    server_proof = pending["srp"].verify(client_ephemeral, client_proof)
    user = fake.users.get(username)
    if server_proof is None or user is None:
        request["note"] = "wrong password"
        return error(422, 8002, "Incorrect login credentials. Please try again.")

    uid = secrets.token_hex(16)
    new = {"UID": uid, "Username": user["name"], "Pending2FA": bool(user.get("twofa")),
           "TwoFactorFailures": 0, "Created": time.time()}
    fake.new_tokens(new)
    fake.sessions[uid] = new
    fake.save_sessions()
    scopes = TWOFA_SCOPES if new["Pending2FA"] else FULL_SCOPES
    return reply({
        "UID": uid,
        "UserID": user["id"],
        "AccessToken": new["AccessToken"],
        "RefreshToken": new["RefreshToken"],
        "TokenType": "Bearer",
        "ExpiresIn": fake.token_ttl,
        "Scopes": scopes,
        "Scope": " ".join(scopes),
        "ServerProof": base64.b64encode(server_proof).decode(),
        "EventID": secrets.token_hex(16),
        "PasswordMode": 1,
        "TemporaryPassword": 0,
        "TwoFactor": 1 if new["Pending2FA"] else 0,
        "2FA": twofa_info(user),
    })


@endpoint("any")
async def auth_2fa(fake: FakeProton, request, session):
    body = await json_body(request)
    if not session["Pending2FA"]:
        return reply({"Scopes": FULL_SCOPES})
    code = re.sub(r"\s+", "", str(body.get("TwoFactorCode", "")))
    now = time.time()
    valid = bool(code) and (code == fake.static_code or any(
        hmac.compare_digest(code, totp(fake.totp_secret, now + drift))
        for drift in (-30, 0, 30)))
    if valid:
        session["Pending2FA"] = False
        session["TwoFactorFailures"] = 0
        fake.save_sessions()
        return reply({"Scopes": FULL_SCOPES})
    session["TwoFactorFailures"] += 1
    if fake.twofa_max_attempts and session["TwoFactorFailures"] >= fake.twofa_max_attempts:
        del fake.sessions[session["UID"]]
        fake.save_sessions()
        request["note"] = "too many 2FA failures, session revoked"
        return error(422, 8002, "Too many failed attempts. Please log in again.")
    fake.save_sessions()
    request["note"] = f"wrong 2FA code ({session['TwoFactorFailures']})"
    return error(422, 2028, "Incorrect code")


@endpoint()
async def auth_refresh(fake: FakeProton, request, session):
    body = await json_body(request)
    token = str(body.get("RefreshToken", ""))
    uid = request.headers.get("x-pm-uid", "")
    found = None
    for candidate in fake.sessions.values():
        if token and hmac.compare_digest(candidate["RefreshToken"], token):
            found = candidate
            break
    if found is None or (uid and uid != found["UID"]):
        request["note"] = "unknown refresh token" if found is None else "UID mismatch"
        return error(422, 10013, "Invalid refresh token")
    fake.new_tokens(found)
    fake.save_sessions()
    request["user"] = found["Username"]
    scopes = TWOFA_SCOPES if found["Pending2FA"] else FULL_SCOPES
    return reply({"UID": found["UID"], "AccessToken": found["AccessToken"],
                  "RefreshToken": found["RefreshToken"], "TokenType": "Bearer",
                  "ExpiresIn": fake.token_ttl, "Scopes": scopes, "Scope": " ".join(scopes)})


@endpoint("any")
async def auth_logout(fake: FakeProton, request, session):
    fake.sessions.pop(session["UID"], None)
    fake.save_sessions()
    return reply()


@endpoint("any")
async def auth_scopes(fake, request, session):
    return reply({"Scopes": TWOFA_SCOPES if session["Pending2FA"] else FULL_SCOPES})


@endpoint("full")
async def users(fake: FakeProton, request, session):
    user = fake.users[session["Username"].lower()]
    account = user.get("account", {})
    return reply({"User": {
        "ID": user["id"], "Name": user["name"], "DisplayName": user["name"],
        "Email": user.get("email", f"{user['name']}@proton.test"), "Currency": "EUR",
        "Credit": 0, "Type": 1, "CreateTime": 1577836800, "MaxSpace": 1073741824,
        "UsedSpace": 0, "Role": 2 if account.get("Subscribed") else 0, "Private": 1,
        "Subscribed": account.get("Subscribed", 0), "Services": account.get("Services", 4),
        "Delinquent": account.get("Delinquent", 0), "Keys": [],
    }})


@endpoint("full")
async def vpn_settings(fake: FakeProton, request, session):
    user = fake.users[session["Username"].lower()]
    data = {"VPN": dict(user["vpn"])}
    data.update(user.get("account", {}))
    return reply(data)


@endpoint("full")
async def vpn_certificate(fake: FakeProton, request, session):
    body = await json_body(request)
    user = fake.users[session["Username"].lower()]
    pem = str(body.get("ClientPublicKey", ""))
    try:
        public_key = serialization.load_pem_public_key(pem.encode())
    except (ValueError, TypeError):
        public_key = None
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        return error(422, 2001, "Invalid ClientPublicKey: an Ed25519 public key in PEM "
                                "(SubjectPublicKeyInfo) format is required")
    duration = parse_duration(body.get("Duration"))
    if duration is None or duration <= 0:
        return error(422, 2001, "Invalid Duration")
    if fake.cert_ttl:
        duration = fake.cert_ttl
    features = body.get("Features") or {}
    if not isinstance(features, dict):
        return error(422, 2001, "Invalid Features")

    cert, serial, issued = fake.issue_certificate(public_key, duration, features, user)
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    x25519_public = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(raw)
    fingerprint = base64.b64encode(hashlib.sha512(x25519_public).digest()).decode()
    wg_public = base64.b64encode(x25519_public).decode()
    ok, output = await fake.register_peer(wg_public)
    request["note"] = (f"serial {serial}, {duration}s, features {features}, "
                       f"wg peer {wg_public} {'registered' if ok else 'NOT registered: ' + output}")
    return reply({
        "SerialNumber": str(serial),
        "ClientKeyFingerprint": fingerprint,
        "ClientKey": pem,
        "Certificate": cert.public_bytes(serialization.Encoding.PEM).decode(),
        "ExpirationTime": issued + duration,
        "RefreshTime": issued + duration * 3 // 4,
        "Mode": "persistent",
        "DeviceName": "",
        "ServerPublicKeyMode": "EC",
        "ServerPublicKey": "",
    })


@endpoint("optional")
async def vpn_location(fake: FakeProton, request, session):
    return reply(fake.location)


@endpoint("optional")
async def vpn_clientconfig(fake, request, session):
    return reply(json.loads(json.dumps(CLIENT_CONFIG)))


@endpoint("optional")
async def feature_flags(fake: FakeProton, request, session):
    return reply({"toggles": fake.feature_toggles})


@endpoint("optional")
async def vpn_logicals(fake: FakeProton, request, session):
    headers = {"Last-Modified": http_date(fake.last_modified)}
    if fake.not_modified(request):
        return web.Response(status=304, headers=headers)
    return reply({"LogicalServers": fake.server_list.logicals()}, headers=headers)


@endpoint("optional")
async def vpn_loads(fake: FakeProton, request, session):
    return reply({"LogicalServers": fake.server_list.loads()})


@endpoint("full")
async def vpn_sessions(fake, request, session):
    return reply({"Sessions": []})


@endpoint("optional")
async def bug_report(fake, request, session):
    report = {"time": time.time(), "user": session["Username"] if session else None,
              "fields": {}, "files": {}}
    directory = STATE_DIR / "bug-reports"
    directory.mkdir(exist_ok=True)
    stem = time.strftime("%Y%m%d-%H%M%S") + f"-{secrets.token_hex(2)}"
    if request.content_type.startswith("multipart/"):
        reader = await request.multipart()
        while (part := await reader.next()) is not None:
            data = await part.read(decode=False)
            if part.filename:
                safe = re.sub(r"[^A-Za-z0-9._-]", "_", part.filename)
                (directory / f"{stem}-{safe}").write_bytes(data)
                report["files"][part.name] = {"filename": part.filename, "size": len(data)}
            else:
                report["fields"][part.name] = data.decode(errors="replace")
    else:
        body = await request.post()
        report["fields"] = {k: str(v) for k, v in body.items()}
    (directory / f"{stem}.json").write_text(json.dumps(report, indent=1))
    request["note"] = f"saved bug-reports/{stem}.json"
    return reply()


@endpoint("optional")
async def notifications(fake, request, session):
    return reply({"Notifications": []})


@endpoint("optional")
async def city_names(fake, request, session):
    return reply({"Cities": {}, "States": {}})


@endpoint("full")
async def nps(fake, request, session):
    return reply()


# -- test control ---------------------------------------------------------------

async def fake_control(request: web.Request):
    fake: FakeProton = request.app["fake"]
    body = await json_body(request)
    action = body.get("action", "")
    request["note"] = f"action {action}"
    result = None
    if action in ("expire_tokens", "revoke_sessions"):
        # Optional filters: "username" and/or "uid"; without them every session.
        selected = [uid for uid, s in fake.sessions.items()
                    if body.get("username") in (None, s["Username"])
                    and body.get("uid") in (None, uid)]
        for uid in selected:
            if action == "expire_tokens":
                fake.sessions[uid]["AccessExpires"] = 0
            else:
                del fake.sessions[uid]
        fake.save_sessions()
        result = selected
    elif action == "set_token_ttl":
        fake.token_ttl = int(body.get("seconds", TOKEN_TTL))
    elif action == "set_cert_ttl":
        fake.cert_ttl = int(body["seconds"]) if body.get("seconds") else None
    elif action == "set_maintenance":
        result = fake.server_list.set_status(set(body.get("servers", [])),
                                             set(body.get("countries", [])),
                                             int(body.get("status", 0)))
        fake.update_last_modified()
    elif action == "reset_maintenance":
        fake.server_list.reset_status()
        fake.update_last_modified()
    elif action == "bump_server_list":
        fake.update_last_modified(force=True)
    elif action == "fail_next":
        rule = {k: body[k] for k in ("path", "method", "status", "code", "error", "details",
                                     "headers", "count") if k in body}
        fake.failures.append(rule)
    elif action == "human_verification":
        fake.failures.append({
            "path": body.get("path", "*"), "count": int(body.get("count", 1)), "status": 422,
            "code": 9001, "error": "Human verification required",
            "details": {"HumanVerificationMethods": ["captcha", "email"],
                        "HumanVerificationToken": "fake-hv-token",
                        "Title": "Human Verification", "Direct": 1}})
    elif action == "clear_failures":
        fake.failures.clear()
    elif action == "agent_mode":
        mode = body.get("mode", "connected")
        if mode not in ("connected", "hard-jailed", "error", "drop", "silent"):
            return error(422, 2001, f"unknown agent mode {mode}")
        fake.agent["mode"] = mode
        fake.agent["reason"] = None
        fake.agent["error"] = None
        if mode == "hard-jailed":
            fake.agent["reason"] = {"code": int(body.get("code", 86111)),
                                    "final": bool(body.get("final", True)),
                                    "description": body.get("description",
                                                            "Max sessions reached")}
        elif mode == "error":
            fake.agent["error"] = {"code": int(body.get("code", 86203)),
                                   "description": body.get("description",
                                                           "session has no fingerprint")}
        if "push_on_connect" in body:
            fake.agent["push_on_connect"] = bool(body["push_on_connect"])
        fake.write_agent_config()
    elif action == "natpmp_mode":
        fake.agent["natpmp_mode"] = body.get("mode", "ok")
        fake.agent["natpmp_port"] = int(body.get("port", fake.agent["natpmp_port"]))
        fake.write_agent_config()
    elif action == "set_location":
        fake.location.update({k: body[k] for k in ("IP", "Lat", "Long", "Country", "ISP")
                              if k in body})
        fake.write_agent_config()
    elif action == "set_feature_flags":
        if "toggles" in body:
            fake.feature_toggles = list(body["toggles"])
        else:
            fake.feature_toggles = [
                {"name": name, "enabled": True, "impressionData": False,
                 "variant": {"name": "disabled", "enabled": False}}
                for name in body.get("enable", [])]
    elif action == "reset":
        fake.reset_controls()
    else:
        return error(422, 2001, f"unknown action {action!r}", {"Actions": [
            "expire_tokens", "revoke_sessions", "set_token_ttl", "set_cert_ttl",
            "set_maintenance", "reset_maintenance", "bump_server_list", "fail_next",
            "human_verification", "clear_failures", "agent_mode", "natpmp_mode",
            "set_location", "set_feature_flags", "reset"]})
    return reply({"Result": result})


async def fake_state(request: web.Request):
    fake: FakeProton = request.app["fake"]
    now = time.time()
    return reply({
        "Sessions": [{"Username": s["Username"], "UID": s["UID"], "Pending2FA": s["Pending2FA"],
                      "AccessExpiresIn": int(s["AccessExpires"] - now)}
                     for s in fake.sessions.values()],
        "TokenTTL": fake.token_ttl, "CertTTL": fake.cert_ttl,
        "Agent": fake.agent, "Location": fake.location, "Failures": fake.failures,
        "Maintenance": fake.server_list.status_override,
        "LastModified": http_date(fake.last_modified),
        "WireGuardServerPublicKey": fake.state.wg_public_key,
        "WireGuardPeer": fake.last_peer, "Domain": DOMAIN, "EntryIP": ENTRY_IP,
        "ApiPin": fake.state.api_pin,
    })


FAKE_FILES = {"api-ca.pem", "openvpn-ca.pem", "agent-ca.pem", "vpn-client-ca.pem",
              "wg-server.pub"}


async def fake_file(request: web.Request):
    name = request.match_info["name"]
    if name not in FAKE_FILES:
        return error(404, 2501, "No such file")
    return web.Response(body=(STATE_DIR / name).read_bytes(), content_type="text/plain")


# -- application --------------------------------------------------------------------

@web.middleware
async def middleware(request: web.Request, handler):
    started = time.monotonic()
    fake: FakeProton = request.app["fake"]
    try:
        if request.path.startswith("/fake/"):
            response = await handler(request)
        elif not request.headers.get("x-pm-appversion"):
            request["note"] = "missing x-pm-appversion"
            response = error(400, 5001, "Missing x-pm-appversion header")
        else:
            # (aiohttp responses are falsy, so no "or" here)
            response = fake.injected_failure(request)
            if response is None:
                response = await handler(request)
    except web.HTTPException as exc:
        code = {404: 2501, 405: 2501}.get(exc.status, 2001)
        response = error(exc.status, code, exc.reason or "Error")
    except Exception as exc:  # noqa: BLE001
        traceback.print_exc()
        response = error(500, 500, f"Internal error in the fake API: {exc}")
    elapsed = (time.monotonic() - started) * 1000
    extra = []
    if request.get("user"):
        extra.append(f"user={request['user']}")
    if request.get("note"):
        extra.append(request["note"])
    scheme = "https" if request.secure else "http"
    log(f"{request.remote} {scheme} {request.method} {request.path_qs} -> {response.status} "
        f"({elapsed:.1f} ms){' ' + '; '.join(extra) if extra else ''}")
    return response


def build_app(fake: FakeProton) -> web.Application:
    app = web.Application(middlewares=[middleware], client_max_size=32 * 1024 * 1024)
    app["fake"] = fake
    routes = [
        ("GET", ["/tests/ping"], ping),
        ("POST", ["/auth/info", "/core/v4/auth/info", "/auth/v4/info"], auth_info),
        ("POST", ["/auth", "/core/v4/auth", "/auth/v4"], auth),
        ("POST", ["/auth/2fa", "/core/v4/auth/2fa", "/auth/v4/2fa"], auth_2fa),
        ("POST", ["/auth/refresh", "/core/v4/auth/refresh", "/auth/v4/refresh"], auth_refresh),
        ("DELETE", ["/auth", "/core/v4/auth", "/auth/v4"], auth_logout),
        ("GET", ["/auth/scopes", "/core/v4/auth/scopes", "/auth/v4/scopes"], auth_scopes),
        ("GET", ["/users", "/core/v4/users"], users),
        ("GET", ["/vpn/v2", "/vpn"], vpn_settings),
        ("POST", ["/vpn/v1/certificate", "/vpn/certificate"], vpn_certificate),
        ("GET", ["/vpn/v1/location", "/vpn/location"], vpn_location),
        ("GET", ["/vpn/v2/clientconfig", "/vpn/clientconfig"], vpn_clientconfig),
        ("GET", ["/feature/v2/frontend"], feature_flags),
        ("GET", ["/vpn/v1/logicals", "/vpn/logicals"], vpn_logicals),
        ("GET", ["/vpn/v1/loads", "/vpn/loads"], vpn_loads),
        ("GET", ["/vpn/v1/sessions", "/vpn/sessions"], vpn_sessions),
        ("POST", ["/core/v4/reports/bug", "/reports/bug"], bug_report),
        ("GET", ["/core/v4/notifications"], notifications),
        ("GET", ["/vpn/v1/cities/names"], city_names),
        ("POST", ["/vpn/v1/nps/submit", "/vpn/v1/nps/dismiss"], nps),
        ("POST", ["/fake/control"], fake_control),
        ("GET", ["/fake/state"], fake_state),
        ("GET", ["/fake/files/{name}"], fake_file),
    ]
    for method, paths, handler in routes:
        for path in paths:
            app.router.add_route(method, path, handler)
    return app


async def serve(fake: FakeProton):
    runner = web.AppRunner(build_app(fake), access_log=None)
    await runner.setup()
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(STATE_DIR / "api-server.pem", STATE_DIR / "api-server.key")
    await web.TCPSite(runner, BIND, HTTP_PORT).start()
    await web.TCPSite(runner, BIND, HTTPS_PORT, ssl_context=context).start()
    log(f"fake Proton API on http://{BIND}:{HTTP_PORT} and https://{BIND}:{HTTPS_PORT} "
        f"(entry IP {ENTRY_IP}, domain {DOMAIN}, token TTL {fake.token_ttl}s, "
        f"{len(fake.server_list.base)} logical servers)")
    log(f"WireGuard server key {fake.state.wg_public_key}; API SPKI pin {fake.state.api_pin}")
    await asyncio.Event().wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--init-only", action="store_true",
                        help="create the state directory (keys, CAs) and exit")
    args = parser.parse_args()
    if args.init_only:
        dns, ips = api_sans()
        made = pki.State(STATE_DIR, DOMAIN, dns, ips).ensure()
        print(f"state ready in {STATE_DIR}" + (f" (generated {', '.join(made)})" if made else ""))
        return

    async def run():
        await serve(FakeProton())

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
