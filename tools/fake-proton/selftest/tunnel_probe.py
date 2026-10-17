#!/usr/bin/env python3
"""Checks the services on 10.2.0.1 from inside a VPN tunnel (stdlib only).

Run by selftest.py inside a throwaway client container once the WireGuard or
OpenVPN tunnel is up. Prints one JSON object and exits 0 when every check passed.
"""
from __future__ import annotations

import argparse
import http.client
import json
import random
import socket
import ssl
import struct
import sys
import urllib.request

SERVICE_IP = "10.2.0.1"
RESULTS = []


def check(name: str, ok: bool, detail="") -> bool:
    RESULTS.append({"name": name, "ok": bool(ok), "detail": detail})
    return ok


# -- DNS ------------------------------------------------------------------------

def dns_a(name: str, server: str, timeout: float = 3.0) -> list[str]:
    tid = random.randint(0, 0xFFFF)
    question = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    packet = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + question + struct.pack(">HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(4096)
    rid, flags, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
    if rid != tid:
        raise ValueError("DNS transaction id mismatch")
    if flags & 0xF:
        raise ValueError(f"DNS rcode {flags & 0xF}")

    def skip_name(pos: int) -> int:
        while True:
            length = data[pos]
            if length & 0xC0 == 0xC0:
                return pos + 2
            if length == 0:
                return pos + 1
            pos += length + 1

    pos = 12
    for _ in range(qd):
        pos = skip_name(pos) + 4
    addresses = []
    for _ in range(an):
        pos = skip_name(pos)
        rtype, _, _, rdlength = struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        if rtype == 1 and rdlength == 4:
            addresses.append(socket.inet_ntoa(data[pos:pos + 4]))
        pos += rdlength
    return addresses


# -- local agent -----------------------------------------------------------------

class Agent:
    def __init__(self, domain: str, ca: str, cert: str | None, key: str | None):
        context = ssl.create_default_context(cafile=ca)
        if cert:
            context.load_cert_chain(cert, key)
        raw = socket.create_connection((SERVICE_IP, 65432), timeout=10)
        self.sock = context.wrap_socket(raw, server_hostname=domain)
        self.version = self.sock.version()

    def send(self, message: dict):
        payload = json.dumps(message).encode()
        self.sock.sendall(struct.pack(">I", len(payload)) + payload)

    def _exact(self, count: int) -> bytes:
        data = b""
        while len(data) < count:
            chunk = self.sock.recv(count - len(data))
            if not chunk:
                raise ConnectionError("agent closed the connection")
            data += chunk
        return data

    def recv(self, timeout: float = 8.0) -> dict:
        self.sock.settimeout(timeout)
        length = struct.unpack(">I", self._exact(4))[0]
        return json.loads(self._exact(length))

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def control(api: str, body: dict):
    request = urllib.request.Request(api + "/fake/control", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def agent_checks(args):
    tag = f"agent[{args.label}]"
    try:
        agent = Agent(args.domain, args.agent_ca, args.cert, args.key)
    except (OSError, ssl.SSLError) as exc:
        check(f"{tag} TLS connection with the client certificate", False, repr(exc))
        return
    check(f"{tag} TLS connection with the client certificate", True, agent.version)
    try:
        pushed = agent.recv()
        check(f"{tag} status pushed on connect", "status" in pushed, pushed)
        agent.send({"status-get": {}})
        status = agent.recv().get("status", {})
        check(f"{tag} status-get -> connected", status.get("state") == "connected", status)
        details = status.get("connection-details", {})
        check(f"{tag} connection-details", bool(details.get("device-ip"))
              and bool(details.get("server-ipv4")), details)
        features = status.get("features", {})
        check(f"{tag} features reflect the certificate request",
              features.get("netshield-level") == args.expect_netshield, features)

        agent.send({"features-set": {"port-forwarding": True, "netshield-level": 2}})
        answer = agent.recv()
        if args.tier == 0:
            check(f"{tag} features-set refused on the free plan",
                  answer.get("error", {}).get("code") == 86201, answer)
        else:
            features = answer.get("status", {}).get("features", {})
            check(f"{tag} features-set port-forwarding -> port-forwarding true",
                  features.get("port-forwarding") is True and features.get("netshield-level") == 2,
                  answer)
            agent.send({"status-get": {"features-statistics": True}})
            answer = agent.recv()
            check(f"{tag} status-get with features-statistics",
                  "features-statistics" in answer.get("status", {}), answer)

        if args.api and args.jail_test:
            control(args.api, {"action": "agent_mode", "mode": "hard-jailed", "code": 86111,
                               "description": "Max sessions reached"})
            try:
                jailed = agent.recv(timeout=10).get("status", {})
            finally:
                control(args.api, {"action": "agent_mode", "mode": "connected"})
            check(f"{tag} hard-jailed status pushed after /fake/control agent_mode",
                  jailed.get("state") == "hard-jailed"
                  and jailed.get("reason", {}).get("code") == 86111, jailed)
            back = agent.recv(timeout=10).get("status", {})
            check(f"{tag} connected status pushed after reset", back.get("state") == "connected",
                  back)
    except (OSError, ssl.SSLError, ValueError) as exc:
        check(f"{tag} protocol exchange", False, repr(exc))
    finally:
        agent.close()

    if args.no_cert_check:
        try:
            bare = Agent(args.domain, args.agent_ca, None, None)
            try:
                got = bare.recv(timeout=5)
                check(f"{tag} connection without a client certificate is refused", False, got)
            except (OSError, ssl.SSLError, ConnectionError, ValueError) as exc:
                check(f"{tag} connection without a client certificate is refused", True,
                      type(exc).__name__)
            bare.close()
        except (OSError, ssl.SSLError) as exc:
            check(f"{tag} connection without a client certificate is refused", True,
                  type(exc).__name__)


# -- NAT-PMP -----------------------------------------------------------------------

def natpmp(op: int, lifetime: int = 60) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.connect((SERVICE_IP, 5351))
        if op == 0:
            sock.send(struct.pack(">BB", 0, 0))
        else:
            sock.send(struct.pack(">BBHHHI", 0, op, 0, 0, 0, lifetime))
        return sock.recv(64)


def natpmp_checks(expected_port: int):
    try:
        reply = natpmp(2)
        version, op, code, _, internal, external, lifetime = struct.unpack(">BBHIHHI", reply)
        check("NAT-PMP TCP mapping", len(reply) == 16 and op == 130 and code == 0
              and internal == expected_port and external == expected_port,
              {"internal": internal, "external": external, "lifetime": lifetime})
        reply = natpmp(1)
        _, op, code, _, internal, _, _ = struct.unpack(">BBHIHHI", reply)
        check("NAT-PMP UDP mapping", op == 129 and code == 0 and internal == expected_port,
              {"internal": internal})
        reply = natpmp(0)
        check("NAT-PMP external address", len(reply) == 12 and reply[1] == 128,
              socket.inet_ntoa(reply[8:12]))
    except (OSError, struct.error) as exc:
        check("NAT-PMP", False, repr(exc))


# -- main ----------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", default="tunnel")
    parser.add_argument("--domain", required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--agent-ca", required=True)
    parser.add_argument("--expect-ip")
    parser.add_argument("--expect-protocol")
    parser.add_argument("--expect-netshield", type=int, default=0)
    parser.add_argument("--tier", type=int, default=2)
    parser.add_argument("--api", help="fake API base URL, for the agent jail push test")
    parser.add_argument("--jail-test", action="store_true")
    parser.add_argument("--no-cert-check", action="store_true")
    parser.add_argument("--agent-only", action="store_true")
    parser.add_argument("--natpmp-port", type=int, default=61234)
    parser.add_argument("--internet", help="URL fetched through the tunnel (optional)")
    args = parser.parse_args()

    if not args.agent_only:
        try:
            addresses = dns_a("whoami.fake.proton", SERVICE_IP)
            check("DNS whoami.fake.proton via 10.2.0.1", addresses == [SERVICE_IP], addresses)
        except (OSError, ValueError) as exc:
            check("DNS whoami.fake.proton via 10.2.0.1", False, repr(exc))
        try:
            connection = http.client.HTTPConnection(SERVICE_IP, 80, timeout=5)
            connection.request("GET", "/", headers={"Host": "whoami.fake.proton"})
            body = connection.getresponse().read().decode().strip()
            check("HTTP whoami returns the tunnel IP", body == args.expect_ip,
                  {"got": body, "expected": args.expect_ip})
            connection.request("GET", "/json", headers={"Host": "whoami.fake.proton"})
            info = json.loads(connection.getresponse().read())
            if args.expect_protocol:
                check("HTTP whoami sees the expected protocol",
                      info.get("protocol") == args.expect_protocol, info)
        except (OSError, ValueError) as exc:
            check("HTTP whoami", False, repr(exc))
        natpmp_checks(args.natpmp_port)
        if args.internet:
            try:
                host = args.internet.split("/")[2]
                addresses = dns_a(host, SERVICE_IP, timeout=5)
                with urllib.request.urlopen(args.internet, timeout=10) as response:
                    check("internet through the tunnel", response.status == 200,
                          {"dns": addresses, "status": response.status})
            except (OSError, ValueError) as exc:
                check("internet through the tunnel", False, repr(exc))
    agent_checks(args)

    ok = all(item["ok"] for item in RESULTS)
    print(json.dumps({"ok": ok, "checks": RESULTS}))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
