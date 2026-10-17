#!/usr/bin/env python3
"""Services the fake VPN server offers inside the tunnel, on 10.2.0.1.

* Local agent stand-in, TLS on 10.2.0.1:65432. Speaks the protocol of
  local-agent-rs (transport_stream.rs, message.rs): every message is a 4-byte
  big-endian length followed by JSON with kebab-case keys. The server
  certificate is for the server domain (signed by state/agent-ca.pem) and a
  client certificate from the fake API (state/vpn-client-ca.pem) is required.
  The initial features come from the certificate's Proton extensions
  (1.3.6.1.4.1.56809.1.*), as requested in POST /vpn/v1/certificate.
* NAT-PMP responder on 10.2.0.1:5351/udp (see local-agent-rs port_forwarding.rs).
* "whoami" HTTP server on 10.2.0.1:80: GET / returns the caller's tunnel IP,
  GET /json a JSON description.

Behaviour switches are read from state/agent-config.json, which the fake API
writes (POST /fake/control {"action": "agent_mode", ...}); a change is pushed
to the agent connections that are open.
"""
from __future__ import annotations

import asyncio
import datetime
import ipaddress
import json
import os
import socket
import ssl
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import serialization

STATE = os.environ.get("FAKE_PROTON_STATE", "/state")
ADDRESS = os.environ.get("FAKE_PROTON_SERVICE_ADDRESS", "10.2.0.1")
AGENT_PORT = 65432
NATPMP_PORT = 5351
HTTP_PORT = 80
PROTON_OID = "1.3.6.1.4.1.56809.1."
X509_V_FLAG_NO_CHECK_TIME = 0x200000   # expiry is reported as hard-jailed 86101 instead
STARTED = time.time()
MAX_MESSAGE = 1 << 20

DEFAULT_CONFIG = {
    "mode": "connected", "reason": None, "error": None, "push_on_connect": True,
    "device_ip": "203.0.113.7", "device_country": "AU", "server_ipv4": "198.51.100.1",
    "natpmp_mode": "ok", "natpmp_port": 61234,
}


def log(message: str) -> None:
    print(time.strftime("%Y-%m-%d %H:%M:%S"), message, flush=True)


def protocol_of(ip: str) -> str:
    address = ipaddress.ip_address(ip)
    for network, name in (("10.2.0.0/24", "wireguard"), ("10.96.0.0/16", "openvpn-udp"),
                          ("10.97.0.0/16", "openvpn-tcp")):
        if address in ipaddress.ip_network(network):
            return name
    return "unknown"


class Config:
    """state/agent-config.json, re-read when it changes."""

    def __init__(self):
        self.path = os.path.join(STATE, "agent-config.json")
        self.mtime = None
        self.data = dict(DEFAULT_CONFIG)

    def get(self) -> dict:
        try:
            mtime = os.stat(self.path).st_mtime_ns
        except OSError:
            return self.data
        if mtime != self.mtime:
            try:
                with open(self.path) as handle:
                    data = dict(DEFAULT_CONFIG)
                    data.update(json.load(handle))
                self.data, self.mtime = data, mtime
                log(f"config: agent mode {data['mode']}, NAT-PMP {data['natpmp_mode']}")
            except (OSError, ValueError) as exc:
                log(f"config: cannot read {self.path}: {exc}")
        return self.data


CONFIG = Config()


# -- certificate parsing --------------------------------------------------------

def der_value(raw: bytes, pos: int = 0):
    """Decodes one DER INTEGER / OCTET STRING / SEQUENCE. Returns (value, end)."""
    tag = raw[pos]
    length = raw[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(raw[pos:pos + count], "big")
        pos += count
    body = raw[pos:pos + length]
    end = pos + length
    if tag == 0x02:
        return int.from_bytes(body, "big", signed=True), end
    if tag == 0x04:
        return body.decode(errors="replace"), end
    if tag == 0x30:
        items, inner = [], 0
        while inner < len(body):
            value, inner = der_value(body, inner)
            items.append(value)
        return items, end
    return body, end


def certificate_info(der: bytes) -> dict:
    cert = x509.load_der_x509_certificate(der)
    ext = {}
    for extension in cert.extensions:
        oid = extension.oid.dotted_string
        if oid.startswith(PROTON_OID):
            try:
                ext[oid[len(PROTON_OID):]] = der_value(extension.value.value)[0]
            except (IndexError, ValueError):
                pass
    not_after = getattr(cert, "not_valid_after_utc", None) or \
        cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    key = cert.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)
    return {
        "serial": cert.serial_number,
        "key": key.hex(),
        "tier": int(ext.get("0.0.1", 0)),
        "groups": ext.get("0.0.2", []),
        "not_after": not_after.timestamp(),
        "features": {
            "netshield-level": int(ext.get("0.1.0", 0)),
            "split-tcp": bool(ext.get("0.1.6", 1)),
            "randomized-nat": bool(ext.get("0.1.7", 1)),
            "port-forwarding": bool(ext.get("0.1.3", 0)),
            "jail": bool(ext.get("0.1.5", 0)),
            "bouncing": str(ext.get("0.1.8", "0")),
        },
    }


# -- local agent ------------------------------------------------------------------

FEATURE_KEYS = {"netshield-level": int, "split-tcp": bool, "randomized-nat": bool,
                "port-forwarding": bool, "jail": bool, "bouncing": str}
CONNECTIONS: set["AgentConnection"] = set()


class AgentConnection:
    def __init__(self, reader, writer, info: dict, peer: str):
        self.reader, self.writer = reader, writer
        self.info, self.peer = info, peer
        self.lock = asyncio.Lock()
        # Every connection starts from the certificate's features (clients
        # send features-set again after reconnecting, as LocalAgentMixin does).
        self.features = dict(info["features"])
        self.statistics = {"DNSBL/1b": 0, "DNSBL/2a": 0, "DNSBL/2b": 0}
        self.name = f"{peer} ({protocol_of(peer)}, serial {info['serial']}, tier {info['tier']})"

    def status(self, config: dict, statistics: bool = False) -> dict:
        if config["mode"] == "error" and config.get("error"):
            return {"error": config["error"]}
        if config["mode"] == "hard-jailed":
            return {"status": {"state": "hard-jailed", "reason": config.get("reason") or {
                "code": 86111, "final": True, "description": "Max sessions reached"}}}
        if time.time() > self.info["not_after"]:
            return {"status": {"state": "hard-jailed", "reason": {
                "code": 86101, "final": False, "description": "Certificate expired"}}}
        status = {
            "state": "connected",
            "features": dict(self.features),
            "connection-details": {
                "device-ip": config["device_ip"],
                "device-country": config["device_country"],
                "server-ipv4": config["server_ipv4"],
            },
        }
        if statistics and self.features.get("netshield-level", 0) > 0:
            for key in self.statistics:
                self.statistics[key] += 1
            status["features-statistics"] = {"netshield-level": dict(self.statistics)}
        return {"status": status}

    async def send(self, message: dict) -> None:
        payload = json.dumps(message).encode()
        async with self.lock:
            self.writer.write(struct.pack(">I", len(payload)) + payload)
            await self.writer.drain()
        log(f"agent {self.name}: sent {payload.decode()}")

    async def receive(self) -> dict | None:
        try:
            length = struct.unpack(">I", await self.reader.readexactly(4))[0]
            if length > MAX_MESSAGE:
                raise ValueError(f"message of {length} bytes")
            data = await self.reader.readexactly(length)
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
            return None
        log(f"agent {self.name}: received {data.decode(errors='replace')}")
        try:
            message = json.loads(data)
            return message if isinstance(message, dict) else {"invalid": True}
        except ValueError:
            return {"invalid": True}

    def apply_features(self, requested: dict) -> dict | None:
        """Returns an error message, or None when the features were applied."""
        if self.info["tier"] == 0:
            return {"error": {"code": 86201, "description":
                              "features cannot be changed on the free plan"}}
        for key, kind in FEATURE_KEYS.items():
            if key in requested and requested[key] is not None:
                try:
                    self.features[key] = kind(requested[key])
                except (TypeError, ValueError):
                    return {"error": {"code": 86202, "description": f"invalid value for {key}"}}
        return None

    async def run(self) -> None:
        config = CONFIG.get()
        if config["mode"] == "drop":
            log(f"agent {self.name}: dropping the connection (mode drop)")
            return
        if config.get("push_on_connect", True) and config["mode"] != "silent":
            await self.send(self.status(config))
        while True:
            message = await self.receive()
            if message is None:
                return
            config = CONFIG.get()
            if config["mode"] == "drop":
                return
            if config["mode"] == "silent":
                continue
            if "features-set" in message and isinstance(message["features-set"], dict):
                failure = self.apply_features(message["features-set"])
                await self.send(failure or self.status(config))
            elif "status-get" in message:
                options = message["status-get"] if isinstance(message["status-get"], dict) else {}
                await self.send(self.status(config, bool(options.get("features-statistics"))))
            else:
                await self.send({"error": {"code": 86202, "description": "unknown request"}})


async def handle_agent(reader, writer):
    peer = (writer.get_extra_info("peername") or ("?",))[0]
    der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
    try:
        connection = AgentConnection(reader, writer, certificate_info(der), peer)
    except Exception as exc:  # noqa: BLE001
        log(f"agent {peer}: unusable client certificate: {exc}")
        writer.close()
        return
    log(f"agent {connection.name}: connected, features {connection.features}")
    CONNECTIONS.add(connection)
    try:
        await connection.run()
    except (ConnectionError, ssl.SSLError) as exc:
        log(f"agent {connection.name}: {exc}")
    finally:
        CONNECTIONS.discard(connection)
        writer.close()
        log(f"agent {connection.name}: closed")


async def watch_config():
    """Pushes the new status to open connections when the agent mode changes."""
    previous = json.dumps(CONFIG.get(), sort_keys=True)
    while True:
        await asyncio.sleep(1)
        config = CONFIG.get()
        current = json.dumps(config, sort_keys=True)
        if current == previous:
            continue
        previous = current
        for connection in list(CONNECTIONS):
            try:
                if config["mode"] == "drop":
                    connection.writer.close()
                elif config["mode"] != "silent":
                    await connection.send(connection.status(config))
            except (ConnectionError, ssl.SSLError, RuntimeError) as exc:
                log(f"agent {connection.name}: push failed: {exc}")


def agent_ssl_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(os.path.join(STATE, "agent-server.pem"),
                            os.path.join(STATE, "agent-server.key"))
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(os.path.join(STATE, "vpn-client-ca.pem"))
    context.verify_flags |= X509_V_FLAG_NO_CHECK_TIME
    return context


# -- NAT-PMP ------------------------------------------------------------------------

class NatPmp(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        config = CONFIG.get()
        if len(data) < 2 or config["natpmp_mode"] == "silent":
            return
        version, op = data[0], data[1]
        epoch = int(time.time() - STARTED)
        if version != 0:
            reply = struct.pack(">BBHI", 0, 128 + op, 1, epoch)            # unsupported version
        elif op == 0:
            reply = struct.pack(">BBHI", 0, 128, 0, epoch) + socket.inet_aton(config["server_ipv4"])
        elif op in (1, 2) and len(data) >= 12:
            internal, external, lifetime = struct.unpack(">HHI", data[4:12])
            if config["natpmp_mode"] == "refuse":
                reply = struct.pack(">BBHIHHI", 0, 128 + op, 2, epoch, internal, 0, 0)
            else:
                port = int(config["natpmp_port"])
                reply = struct.pack(">BBHIHHI", 0, 128 + op, 0, epoch, port, port, lifetime)
        else:
            reply = struct.pack(">BBHI", 0, 128 + op, 5, epoch)            # unsupported opcode
        self.transport.sendto(reply, addr)
        log(f"natpmp {addr[0]}:{addr[1]} op {op} -> {reply.hex()}")


# -- whoami HTTP --------------------------------------------------------------------

class WhoAmI(BaseHTTPRequestHandler):
    server_version = "fake-proton-whoami/1"

    def do_GET(self):  # noqa: N802
        ip = self.client_address[0]
        if self.path in ("/", "/ip"):
            body, kind = f"{ip}\n".encode(), "text/plain"
        elif self.path == "/json":
            body = json.dumps({"ip": ip, "protocol": protocol_of(ip), "time": int(time.time()),
                               "host": self.headers.get("Host")}).encode()
            kind = "application/json"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        log(f"http {self.client_address[0]} {fmt % args}")


# -- main -----------------------------------------------------------------------------

async def main():
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(lambda _loop, ctx: log(
        f"asyncio: {ctx.get('message')} {ctx.get('exception') or ''}"))
    http = ThreadingHTTPServer((ADDRESS, HTTP_PORT), WhoAmI)
    threading.Thread(target=http.serve_forever, daemon=True).start()
    await loop.create_datagram_endpoint(NatPmp, local_addr=(ADDRESS, NATPMP_PORT))
    server = await asyncio.start_server(handle_agent, ADDRESS, AGENT_PORT,
                                        ssl=agent_ssl_context())
    CONFIG.get()
    log(f"services on {ADDRESS}: local agent tcp/{AGENT_PORT} (TLS), NAT-PMP udp/{NATPMP_PORT}, "
        f"whoami http/{HTTP_PORT}")
    asyncio.create_task(watch_config())
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
