# Fake Proton: test servers for the air/OS Proton VPN client

This directory stands in for Proton's infrastructure, so the whole client can be
tested end to end without a Proton account:

- **Fake REST API** (`api/`, a Python/aiohttp process on the host). It does real
  Proton SRP (auth version 4, with Proton's real PGP-signed modulus), 2FA, tokens,
  VPN settings, client certificates, the server list, loads and client config.
- **Fake VPN server** (`vpn/`, one Docker container). It runs WireGuard, OpenVPN
  UDP and TCP (Proton's client template, tls-crypt key and Ed25519 client
  certificates), plus DNS, an HTTP "whoami", a local agent and a NAT-PMP
  responder on `10.2.0.1` inside the tunnel.

```sh
tools/fake-proton.sh start     # build the image if needed, start both, print the client env
tools/fake-proton.sh test      # end-to-end self-test (starts things if needed)
tools/fake-proton.sh status    # what runs, WireGuard peer and handshake, API sessions
tools/fake-proton.sh logs [api|vpn|openvpn-udp|openvpn-tcp|dnsmasq|services|container] [-f]
tools/fake-proton.sh env [--https] [--host]   # client environment (guest or host view)
tools/fake-proton.sh ctl ACTION [key=value ...]   # test controls, see below
tools/fake-proton.sh totp      # current 2FA code for the twofa user
tools/fake-proton.sh stop
```

The first `start` creates every key and CA in `tools/fake-proton/state/`
(gitignored), and later starts reuse them. Delete `state/` to start over; clients
must then reload the CA files.

## Ports and addresses

The QEMU guest reaches the host as `10.0.2.2` (slirp maps it to the host's
127.0.0.1). Everything is published on host ports (bind address
`FAKE_PROTON_BIND`, default `0.0.0.0`):

| Service | Host port | Notes |
| --- | --- | --- |
| REST API, HTTP | 18080/tcp | `http://10.0.2.2:18080` from the guest |
| REST API, HTTPS | 18443/tcp | certificate from `state/api-ca.pem`, SANs include `10.0.2.2`, `127.0.0.1`, `localhost`, `vpn-api.proton.me` |
| OpenVPN UDP | 11940/udp | container port 1194 |
| OpenVPN TCP | 11941/tcp | container port 443 |
| WireGuard | 51830/udp | container port 51820 |

Inside the tunnel (both protocols):

| Address | Service |
| --- | --- |
| `10.2.0.1:53` | DNS (dnsmasq). `whoami.fake.proton`, and anything under `fake.proton`, resolves to 10.2.0.1. Other names are forwarded to 1.1.1.1 (see "No internet" below). |
| `10.2.0.1:80` | whoami HTTP: `GET /` returns the caller's tunnel IP as text, `GET /json` returns `{"ip", "protocol", ...}` |
| `10.2.0.1:65432` | local agent (TLS, client certificate required) |
| `10.2.0.1:5351/udp` | NAT-PMP |

Every logical server in the list points at this single server: `EntryIP`
`10.0.2.2` (`FAKE_PROTON_ENTRY_IP`), `Domain` `node-fake-01.protonvpn.net`
(`FAKE_PROTON_DOMAIN`) and `X25519PublicKey` = `state/wg-server.pub`.

### How 10.2.0.1 works for both protocols

- **WireGuard**: the server's `wg0` is `10.2.0.1/24`. Every client uses
  `10.2.0.2/32`, like real Proton (DNS `10.2.0.1`, allowed IPs `0.0.0.0/0`).
- **OpenVPN** gives clients addresses from a separate pool, so the two protocols never
  collide: UDP gets `10.96.0.0/16` (server `10.96.0.1`) and TCP gets `10.97.0.0/16`
  (server `10.97.0.1`), with `topology subnet`. The server pushes
  `redirect-gateway def1`, `dhcp-option DNS 10.2.0.1` and an explicit
  `route 10.2.0.1 255.255.255.255`. 10.2.0.1 is a local address of the server, so
  it answers packets for 10.2.0.1 that arrive on its tun interface, and replies go
  back through the tunnel.

The whoami `/json` reply names the protocol from the source address
(`wireguard`, `openvpn-udp`, `openvpn-tcp`).

## What the client needs (test mode)

`tools/fake-proton.sh start` (or `env`) prints this:

```sh
export PROTON_VPN_API_URL=http://10.0.2.2:18080     # or https://10.0.2.2:18443
export PROTON_VPN_API_PINS=none                      # or the printed SPKI pin of the fake API cert
export PROTON_VPN_CA_FILE=<path>/api-ca.pem          # needed for the HTTPS URL
export PROTON_VPN_OPENVPN_CA_FILE=<path>/openvpn-ca.pem   # suggested name: replaces CA_CERT as <ca>
export PROTON_VPN_AGENT_CA_FILE=<path>/agent-ca.pem       # suggested name: replaces the agent's root+intermediate
```

The guest cannot read host paths. Fetch the files over plain HTTP (no headers
needed):

```sh
for f in api-ca.pem openvpn-ca.pem agent-ca.pem wg-server.pub; do
    curl -o $f http://10.0.2.2:18080/fake/files/$f
done
```

The client does not need any other changes. The `/auth/info` modulus is Proton's
real signed modulus, so the modulus signature check runs as in production. The
certificates and the WireGuard key come from the API as in production.

## Test users

Defined in `users.json` (username, password, plan, and the `VPN` member of
`/vpn/v2` verbatim). Edit the file and restart to change them.

| User / password | Plan | `MaxTier` | `PlanTitle` | 2FA |
| --- | --- | --- | --- | --- |
| `demo` / `demo` | `vpn2022` | 2 | VPN Plus | no |
| `free` / `free` | `free` | 0 | Proton Free | no |
| `twofa` / `twofa` | `vpn2022` | 2 | VPN Plus | TOTP |

`twofa` accepts the fixed code **`123456`**, or a real TOTP (RFC 6238: SHA-1,
30 s, 6 digits, ±1 step) of the base32 secret **`JBSWY3DPEHPK3PXP`**. Add that
secret to any authenticator app, or run `tools/fake-proton.sh totp`.
After 3 wrong codes (`twofa_max_attempts`) the session is revoked.

## REST API

Every JSON reply has `"Code": 1000` on success, with `Content-Type` exactly
`application/json` (python-proton-core compares it verbatim). Errors have the real
API's shape, `{"Code": c, "Error": "...", "Details": {}}`. Every request except
`/fake/*` needs an `x-pm-appversion` header; without it the reply is HTTP 400 with
Code 5001. Each request is logged to `state/api.log` as method, path, status and
duration, with notes such as the user, why a token was rejected, and the
certificate serial and WireGuard peer.

Authenticated calls need `x-pm-uid` and `Authorization: Bearer <AccessToken>`.

| Endpoint | Auth | Notes |
| --- | --- | --- |
| `GET /tests/ping` | – | `{"Code":1000}` |
| `POST /auth/info` | – | `Modulus` (byte-identical to `tests/data/auth-info.json`), `ServerEphemeral`, `Version` 4, `Salt` (10 bytes, stable per user), `SRPSession` |
| `POST /auth` | – | SRP-6a server side, matching `proton/session/srp/_pysrp.py`. Reply: `UID`, `AccessToken`, `RefreshToken`, `Scopes`, `ServerProof`, `2FA`, `PasswordMode` 1. While 2FA is pending, `Scopes` is `["twofactor"]` |
| `POST /auth/2fa` | pending session | `{"TwoFactorCode"}` → `{"Scopes":[full]}` |
| `POST /auth/refresh` | `x-pm-uid` | new access and refresh tokens (the old ones stop working) |
| `DELETE /auth` | session | revokes the session |
| `GET /auth/scopes`, `GET /users` | session | |
| `GET /vpn/v2` (also `/vpn`) | full | VPNSettings from `users.json` |
| `POST /vpn/v1/certificate` | full | see below |
| `GET /vpn/v1/location` | optional | `203.0.113.7`, Hobart, AU, "Fake ISP" |
| `GET /vpn/v2/clientconfig` | optional | `DEFAULT_CLIENT_CONFIG` shape. Ports: OpenVPN UDP [11940], TCP [11941]; WireGuard UDP [51830], TCP [], TLS [] |
| `GET /feature/v2/frontend` | optional | `{"toggles": []}` (all flags off; see `set_feature_flags`) |
| `GET /vpn/v1/logicals?SecureCoreFilter=all&WithState=true` (also `/vpn/logicals`) | optional | 156 logicals, 32 countries. Sends `Last-Modified`, and returns 304 when `If-Modified-Since` ≥ it. Load/Score change slightly on every call |
| `GET /vpn/v1/loads` (also `/vpn/loads`) | optional | `ID, Load, Score, Status`, different each call. Like the real API, it lists 2 IDs that are not in `/logicals` |
| `GET /vpn/v1/sessions` | full | `{"Sessions": []}` |
| `POST /core/v4/reports/bug` | optional | multipart, saved to `state/bug-reports/` |
| `GET /core/v4/notifications`, `GET /vpn/v1/cities/names`, `POST /vpn/v1/nps/*` | | empty replies |

"optional" means no token is needed, but a token that is sent must be valid.
`/core/v4/auth*` and `/auth/v4*` are accepted as aliases of `/auth*`.

### Errors the client should handle

| Situation | HTTP | Code | Error |
| --- | --- | --- | --- |
| no `x-pm-appversion` | 400 | 5001 | Missing x-pm-appversion header |
| wrong password / unknown user | 422 | 8002 | Incorrect login credentials. Please try again. |
| unknown or reused `SRPSession` | 422 | 2001 | Invalid SRPSession, please restart the login |
| wrong 2FA code | 422 | 2028 | Incorrect code |
| 3rd wrong 2FA code (session revoked) | 422 | 8002 | Too many failed attempts. Please log in again. |
| missing, expired or unknown access token, or no `x-pm-uid` | 401 | 401 | Invalid access token |
| 2FA still pending | 403 | 9101 | Access token does not have sufficient scope |
| unknown refresh token | 422 | 10013 | Invalid refresh token |
| bad `ClientPublicKey` / `Duration` | 422 | 2001 | … |
| unknown route (e.g. `/vpn/v2/logicals`, the binary status API) | 404 | 2501 | Not Found |

Access tokens expire after `FAKE_PROTON_TOKEN_TTL` seconds (default 1800).
Refresh tokens do not expire. Sessions are kept in `state/api-sessions.json`,
so restarting the API does not log the client out.

### Server list contents

- Plus servers (`Tier` 2), such as `CH#1` and `US-CA#3`. US servers are named by
  state and carry `State` ("California", "New York", …); other countries have
  `State` null.
- Free servers (`Tier` 0), such as `JP-FREE#1`, in JP, NL, US, PL, RO, NO, MX, CA
  and SG.
- Secure Core (`Features & 1`), such as `CH-US#1`, `SE-NL#1` and `IS-UK#1`, with
  `EntryCountry` CH, SE or IS.
- Tor (`Features` 2): `CH#9-TOR`, `CH#10-TOR`, `SE#6-TOR`, `NL#6-TOR`.
- P2P (4), streaming (8) and IPv6 (16) flags spread over the Plus servers.
- Smart routing (`HostCountry` set): `IN#1`/`IN#2` (hosted in SG), `TR#1` (RO),
  `AR#1` (US).
- The United Kingdom is `UK`, as in Proton's API (not `GB`).
- Maintenance: `DE#4` and `US-NY#3` have `Status` 0, and the whole of Portugal
  (`PT#1`–`PT#3`) is down. `SE#2` has two physical servers, one of them down.

IDs are stable 88-character base64url strings, so the list is identical across
restarts and `Last-Modified` only changes when the list does.

### Certificates (`POST /vpn/v1/certificate`)

Request: `{"ClientPublicKey": "<PEM SPKI Ed25519>", "Duration": "10080 min",
"Features": {"NetShieldLevel": 1, "RandomNAT": false, "SplitTCP": false,
"PortForwarding": true}}`. `Duration` accepts `min`, `s`, `h` and `day` units.

The certificate is X.509v3 for that Ed25519 key, signed by the Ed25519
**"ProtonVPN test CA"** (`state/vpn-client-ca.pem`). It is shaped like a real Proton
certificate:

- `CN` is the serial number.
- `KeyUsage` digitalSignature (critical) and `ExtendedKeyUsage` clientAuth.
- Proton's private extensions under `1.3.6.1.4.1.56809.1`: `0.0.0` (2FA, INTEGER 0),
  `0.0.1` (tier), `0.0.2` (groups), and each requested feature (`0.1.0` NetShield,
  `0.1.3` port forwarding, `0.1.6` split TCP, `0.1.7` random NAT, as DER INTEGERs).
  The fake local agent reads its initial features from these.

The reply has `SerialNumber`, `ClientKeyFingerprint` (base64 SHA-512 of the
X25519 form of the key), `ClientKey`, `Certificate`, `ExpirationTime`,
`RefreshTime` (now + ¾ of the duration), `Mode` `persistent`, `DeviceName` "",
`ServerPublicKeyMode` `EC` and `ServerPublicKey` "". The validity starts 60 s in
the past (`FAKE_PROTON_CERT_BACKDATE`) to absorb clock skew in the guest.

On the same call, the X25519 form of the key becomes the **only** WireGuard peer
of the server (`docker exec fake-proton-vpn /opt/fake-proton/set-peer.sh`),
with allowed IPs `10.2.0.2/32`, and is saved to `state/wg-peers.txt` so a
container restart restores it. The last certificate wins: one client at a time
over WireGuard. OpenVPN accepts any number of clients.

## VPN server details

- **OpenVPN 2.6** (Alpine). Server side of `OPENVPN_V2_TEMPLATE` in
  `openvpn.py`: `tls-crypt` with Proton's static key (`vpn/proton-tls-crypt.key`),
  AES-256-GCM, `dh none`, `verify-client-cert require`, `remote-cert-tls client`,
  with client certificates from `vpn-client-ca.pem`. Ed25519 client keys work
  over TLS 1.3. The server certificate (`state/openvpn-server.pem`, signed by
  `state/openvpn-ca.pem`) has CN and SAN `node-fake-01.protonvpn.net` and EKU
  serverAuth, so the client's `remote-cert-tls server` and
  `verify-x509-name node-fake-01.protonvpn.net name` both pass.
- **WireGuard**: kernel `wg0` in the container, private key `state/wg-server.key`.
- **Local agent** (`vpn/services.py`). The protocol is from local-agent-rs:
  4-byte big-endian length, then JSON with kebab-case keys.
  - TLS server certificate for the domain (SAN, as rustls requires), signed by
    `state/agent-ca.pem`. It requires a client certificate from the fake API.
  - It pushes a status on connect. The upstream client sends nothing for free
    users and waits for that push.
  - It answers every `status-get` and `features-set`:
    `{"status":{"state":"connected","features":{"netshield-level":N,"split-tcp":true,"randomized-nat":true,"port-forwarding":false,"jail":false,"bouncing":"0"},"connection-details":{"device-ip":"203.0.113.7","device-country":"AU","server-ipv4":"198.51.100.1"}}}`.
  - Features start from the certificate and `features-set` overrides them, so
    `"port-forwarding": true` is reflected back.
  - `status-get {"features-statistics": true}` adds NetShield counters when
    NetShield is on.
  - Free-tier certificates get `{"error":{"code":86201,…}}` for any
    `features-set`, because the real agent refuses feature requests from free users.
  - An expired certificate gets `hard-jailed` with code 86101 rather than a TLS
    failure.
  - When the agent mode changes, the new status is pushed to open connections.
- **NAT-PMP** on 10.2.0.1:5351. TCP (op 2) and UDP (op 1) mapping requests get a
  16-byte reply with internal = external port **61234** and the requested
  lifetime; op 0 returns the external address.

### No internet through the tunnel on this host

The container NATs tunnel traffic out of `eth0` (MASQUERADE for 10.2.0.0/24,
10.96.0.0/16 and 10.97.0.0/16). This host runs with `net.ipv4.ip_forward=0`,
though, so bridge containers have no egress. Browsing through the tunnel and
DNS for real names therefore time out, while everything on 10.2.0.1 works.
Published ports still work for inbound traffic: the host's userland
`docker-proxy` carries it, and the self-test checks this. On a host that forwards,
set `FAKE_PROTON_TEST_INTERNET=http://example.com/` to make the self-test check
browsing too.

## Test controls

`POST /fake/control` with `{"action": …}` needs no headers or auth; `/fake/*` is
for tests only. Use `tools/fake-proton.sh ctl ACTION key=value …` (values are
parsed as JSON when possible). `GET /fake/state` shows sessions, controls and
the WireGuard peer.

| Action | Parameters | Effect |
| --- | --- | --- |
| `expire_tokens` | `username`, `uid` (optional) | access tokens expire now: the next call gets 401, then refresh and retry |
| `revoke_sessions` | `username`, `uid` (optional) | sessions deleted: refresh fails (422), so the client must log in again |
| `set_token_ttl` | `seconds` | TTL of new access tokens |
| `set_cert_ttl` | `seconds` (null = as requested) | forces the certificate validity, e.g. 120 to test certificate refresh |
| `set_maintenance` | `servers` (names), `countries`, `status` 0/1 | changes `Status` and bumps `Last-Modified` |
| `reset_maintenance` / `bump_server_list` | | undo / force a new `Last-Modified` |
| `fail_next` | `path` (prefix or `*`), `method`, `status`, `code`, `error`, `details`, `headers`, `count` (-1 = forever) | the next matching requests fail, e.g. `ctl fail_next path=/vpn/v2 status=503 code=503 'headers={"Retry-After":"5"}'` or `status=429` |
| `human_verification` | `path`, `count` | 422 / Code 9001 with `HumanVerificationMethods` (the token is not checked, so this only tests the error path) |
| `clear_failures` | | |
| `agent_mode` | `mode`: `connected`, `hard-jailed` (`code` default 86111, `final`, `description`), `error` (`code` default 86203, `description`), `drop` (close connections), `silent` (never answer); `push_on_connect` | local agent behaviour, pushed to open connections |
| `natpmp_mode` | `mode`: `ok`, `refuse` (result code 2), `silent`; `port` | NAT-PMP behaviour |
| `set_location` | `IP`, `Country`, `Lat`, `Long`, `ISP` | `/vpn/v1/location`, and the agent's `device-ip` and `device-country` |
| `set_feature_flags` | `enable: ["Name", …]` or `toggles: [...]` | `/feature/v2/frontend` |
| `reset` | | all controls back to their defaults (sessions are kept) |

Examples:

```sh
tools/fake-proton.sh ctl agent_mode mode=hard-jailed code=86111 description="Max sessions reached"
tools/fake-proton.sh ctl agent_mode mode=hard-jailed code=86101 final=false description="Certificate expired"
tools/fake-proton.sh ctl agent_mode mode=hard-jailed code=86120 description="2FA required"
tools/fake-proton.sh ctl set_maintenance 'servers=["CH#1","CH#2"]' status=0
tools/fake-proton.sh ctl set_maintenance 'countries=["JP"]' status=0
tools/fake-proton.sh ctl expire_tokens
tools/fake-proton.sh ctl set_cert_ttl seconds=300
tools/fake-proton.sh ctl reset
```

## Configuration (environment of `tools/fake-proton.sh` / `fake_api.py`)

| Variable | Default | Meaning |
| --- | --- | --- |
| `FAKE_PROTON_BIND` | `0.0.0.0` | bind address of the API and the published container ports |
| `FAKE_PROTON_HTTP_PORT` / `FAKE_PROTON_HTTPS_PORT` | 18080 / 18443 | API ports |
| `FAKE_PROTON_OVPN_UDP_PORT` / `_OVPN_TCP_PORT` / `_WG_PORT` | 11940 / 11941 / 51830 | published VPN ports (also in clientconfig) |
| `FAKE_PROTON_ENTRY_IP` | `10.0.2.2` | `EntryIP` of every server |
| `FAKE_PROTON_DOMAIN` | `node-fake-01.protonvpn.net` | server `Domain`; changing it reissues the server certificates |
| `FAKE_PROTON_TOKEN_TTL` | 1800 | access token lifetime (s) |
| `FAKE_PROTON_CERT_TTL` | (as requested) | force the certificate validity (s) |
| `FAKE_PROTON_CERT_BACKDATE` | 60 | seconds subtracted from `notBefore` |
| `FAKE_PROTON_API_SANS` | | extra names or IPs for the API certificate (comma separated) |
| `FAKE_PROTON_DNS_UPSTREAM` | `1.1.1.1` | dnsmasq upstreams (comma separated, `none` for local names only) |
| `FAKE_PROTON_USERS` | `users.json` | users file |
| `FAKE_PROTON_STATE` | `tools/fake-proton/state` | state directory |
| `FAKE_PROTON_CONTAINER` / `FAKE_PROTON_IMAGE` | `fake-proton-vpn` / `fake-proton-vpn:latest` | Docker names |
| `FAKE_PROTON_NO_DOCKER` | 0 | 1 = API only, without WireGuard peer registration |

## Self-test

`tools/fake-proton.sh test` (or `--api-only`, or `--keep` to keep the client
container). It resets the test controls at the start and at the end. It checks:

1. The REST API against **python-proton-core's own SRP client**
   (`.upstream/python-proton-core/proton/session/srp/_pysrp.py`, loaded directly;
   the gnupg modulus check is skipped). That covers the modulus bytes, wrong
   password, 2FA (static code, TOTP, lock-out), refresh and expiry
   (401 → refresh → retry), every endpoint, `If-Modified-Since`/304,
   maintenance, error injection and logout.
2. Certificates for fresh Ed25519 keys (free and Plus). It verifies the signature
   by the test CA, the fingerprint, the Proton extensions, the expiry and refresh
   times, and the WireGuard peer registration.
3. A WireGuard handshake sent from the host to `127.0.0.1:51830`. This is the path
   a QEMU guest's `10.0.2.2` takes, and it uses a Noise IK handshake written in
   Python.
4. A **WireGuard tunnel** in a throwaway client container (never the host's
   routing table), using the X25519 form of the key and the published port via the
   docker bridge gateway. Over it: DNS `whoami.fake.proton`, HTTP whoami
   (= 10.2.0.2), NAT-PMP, and the local agent over TLS with the client certificate
   (pushed status, `status-get`, `features-set` port-forwarding, statistics, a
   hard-jail push via `/fake/control`, and refusal without a client certificate).
5. **OpenVPN UDP and TCP** from the same container. The config is rendered from the
   upstream `OPENVPN_V2_TEMPLATE` (jinja2, as `openvpn.py` does) with
   `openvpn-ca.pem`, the certificate and the Ed25519 key, plus `verify-x509-name`.
   The test checks the pushed options, then repeats the in-tunnel probes, and a
   free-tier certificate's agent refusal.

## Differences from the real Proton service

- **One physical server.** Every logical server leads to the same container,
  domain and WireGuard key, and the exit IPs are TEST-NET addresses that are
  never actually used. WireGuard accepts one peer at a time (the last certificate
  issued).
- **Custom CAs.** The client must take its trust anchors from files in test mode:
  the OpenVPN `<ca>` (`openvpn-ca.pem` instead of the built-in ProtonVPN Root CA),
  the local agent CA (`agent-ca.pem` instead of root + intermediate) and the API
  CA/pins (`api-ca.pem`, `PROTON_VPN_API_PINS=none` or the printed pin). The real
  service uses one root for OpenVPN and the agent; the fake uses two separate CAs.
- **The API host is the VPN entry IP.** Both are `10.0.2.2`, so API calls made while
  connected leave outside the tunnel, through the host route to the VPN
  endpoint. A kill switch that only allows the endpoint's VPN port blocks the API.
- **No WireGuard TCP/TLS (Stealth) and no IKEv2.** clientconfig lists no ports
  for them and `SmartProtocol` has them off. There is no `/vpn/v2/logicals` or
  binary status API (404), so use v1.
- **No internet egress through the tunnel on this host** (see above).
- **Agent and NAT-PMP specifics.** The agent's free-tier refusal code 86201 is
  the fake's choice. NAT-PMP grants port 61234 even when port forwarding was not
  requested (use `natpmp_mode refuse` to test failures). The location does not
  change after connecting (use `set_location`).
- **Certificate request and reply.** Any `Duration` is accepted (Proton enforces
  minimums). `ServerPublicKey` is "" and `Mode` is "persistent"; Proton's sample
  reply has an Ed25519 PEM and "session".
- **Human verification** only produces the error; no token is ever validated.
- `x-pm-appversion` is required but its format is not validated.
