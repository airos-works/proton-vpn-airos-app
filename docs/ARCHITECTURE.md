# Architecture

Proton VPN for air/OS is a C++ re-implementation of the Proton VPN Linux app:
[proton-vpn-gtk-app](https://github.com/ProtonVPN/proton-vpn-gtk-app) (UI, 4.18.7),
[python-proton-vpn-api-core](https://github.com/ProtonVPN/python-proton-vpn-api-core)
(session, server list, connections, 5.8.7), [python-proton-core](https://github.com/ProtonVPN/python-proton-core)
(SRP sign-in, API transport) and [local-agent-rs](https://github.com/ProtonVPN/local-agent-rs)
(the VPN servers' local agent). The Linux app drives NetworkManager; on Haiku the app runs
the tunnels itself. `docs/GTK-UI-SPEC.md` records the GTK app's screens, texts and
behaviour that the Haiku UI follows.

## Pieces

| Part | Where | Notes |
| --- | --- | --- |
| App | `src/ui` | BApplication (`App`), main window with menu bar and login/2FA/loading/VPN screens, server list (`ServerListView`), status block (`StatusView`), Settings, bug report, Deskbar tray icon (`DeskbarView`, loaded by Deskbar from the executable, which is linked with `--export-dynamic`), key store session storage. |
| Core | `src/core` | Plain C++17 + OpenSSL + libcurl, no Haiku API: builds and is tested on Linux too. |
| `proton-wireguard` | `src/wg`, `src/core/WireGuard.cpp` | Userspace WireGuard on Haiku's tunnel driver. |
| `proton-openvpn` | `openvpn/` | OpenVPN 2.6.13 + HaikuPorts patches + Burrow's Haiku tunnel/route patch. |
| `proton-vpn-cli` | `src/cli` | The core without a window, for scripts and tests. |
| Test servers | `tools/fake-proton` | Stand-in Proton API, VPN server (WireGuard + OpenVPN), local agent and NAT-PMP in Docker. |

### Core modules

| File | Ported from | What |
| --- | --- | --- |
| `Api` | `proton/session/api.py`, transports | Session tokens, `/auth/info` + SRP + `/auth`, `/auth/2fa`, `/auth/refresh`, `DELETE /auth`; request retries (401 → refresh → retry, 408/502 again, 429/503 after Retry-After), `x-pm-appversion: linux-vpn-gui@5.8.7+<arch>`, multipart bug reports |
| `Srp`, `Modulus` | `proton/session/srp/*`, `_verify_modulus` | Proton's SRP-6a (PMHash = 4×SHA-512, bcrypt `$2y$10$` over salt + "proton", little-endian numbers); the modulus's OpenPGP cleartext signature checked against Proton's Ed25519 key (no GnuPG) |
| `Http` | aiohttp transport | libcurl, with Proton's leaf SPKI pins (`CURLOPT_PINNEDPUBLICKEY`) plus normal CA verification |
| `Crypto` | `session/key_mgr.py`, `certificates.py` | Ed25519 client key, its X25519 form (WireGuard), PEMs, Proton fingerprint, certificate parsing |
| `Account`, `Settings` | `session/dataclasses/*`, `core/settings/*`, `client_config.py`, `feature_flags_fetcher.py` | `/vpn/v2`, `/vpn/v1/certificate`, `/vpn/v1/location`, `/vpn/v2/clientconfig`, `/feature/v2/frontend`; settings.json / app-config.json |
| `ServerList`, `Countries` | `session/servers/*`, `dataclasses/servers/country.py`, GTK `city_view` | `/vpn/v1/logicals` (with `If-Modified-Since`, `X-PM-netzone`) and `/vpn/v1/loads`; fastest-server rules; grouping by country, city/state and Secure Core |
| `Client` | `core/api.py`, `session/session.py`, refreshers, reconnector | Sign-in, session store, `LoadSessionData` (fetch_session_data), background refresh (server list 3 h ± 22 %, loads 15 min, client config 3 h, feature flags 2 h, certificate at its refresh time with exponential back-off, location after disconnecting), reconnection (2ⁿ s back-off, network monitor) and the notices the UI turns into dialogs |
| `Connector` | `connection/states.py`, `core/vpnconnector.py`, `localagent_mixin.py` | The state machine (Disconnected, Connecting, Connected, Disconnecting, Error; reconnections go through Disconnecting), DNS, kill switch, local agent thread, port forwarding |
| `Tunnel` | `backend/networkmanager/protocol/*` | OpenVPN (OPENVPN_V2_TEMPLATE + management interface, after Burrow) and WireGuard (the helper); failure classification |
| `LocalAgent` | `local-agent-rs` | TLS to 10.2.0.1:65432 with the API certificate, 4-byte length + JSON, status and features (NetShield, split TCP, randomized NAT, port forwarding); NAT-PMP at 10.2.0.1:5351 |
| `WireGuard` | the WireGuard protocol | Noise_IKpsk2 initiator and responder, cookies (XChaCha20 via HChaCha20), transport data, replay window, timers; BLAKE2s/HMAC/KDF in code, ChaCha20-Poly1305 and X25519 from OpenSSL |
| `Network`, `KillSwitch`, `ResolvConf` | — | Tunnel devices, addresses and routes through the stack's ioctls; the route-based kill switch; resolv.conf editing (from Burrow) |

## Signing in

1. `POST /auth/info {Username}` returns the SRP salt, the server ephemeral and the
   modulus as an OpenPGP cleartext-signed message. `Modulus.cpp` verifies its v4 EdDSA
   signature (type 0x01, canonical text) with Proton's modulus key
   (fingerprint `248097092b458509c508dac0350585c4e9518f26`).
2. `Srp.cpp` computes the client proof; `POST /auth` returns the tokens and the server
   proof, which is checked. Scopes containing `twofactor` mean a code is needed:
   `POST /auth/2fa {TwoFactorCode}` (6-digit TOTP or an 8-character recovery code).
3. `LoadSessionData` generates (or reuses) the Ed25519 key, requests a 7-day certificate
   for it with the VPN features, and fetches the account, location, client config,
   feature flags and server list. Tokens and account (with the key) go to the Haiku key
   store (keyring "Proton VPN"); caches to `~/config/cache/Proton VPN`.

## A connection

- **WireGuard:** `proton-wireguard` reads its configuration from stdin (the X25519 private
  key derived from the Ed25519 key, the physical server's `X25519PublicKey`, entry IP and
  the first WireGuard UDP port from the client config), creates `tun/<n>`, sets
  10.2.0.2/32 (and 2a07:b944::2:2 with IPv6), adds a host route to the server through the
  current default gateway and routes the four quarters of the address space
  (`0.0.0.0/2` … `192.0.0.0/2`, `::/2` …) through the tunnel. It reports `handshake`,
  `stats`, `timeout` and `error` events on stdout and removes everything on stop or when
  the app goes away. The connection is Connected when the local agent says "connected".
- **OpenVPN:** Proton's template (AES-256-GCM, tls-crypt with Proton's static key,
  `remote-cert-tls server`, `verify-x509-name <domain> name`) with the API certificate and
  key. The pushed `redirect-gateway` is filtered and replaced by the same quarter routes
  plus a `net_gateway` host route to the server. Connected on `>STATE:CONNECTED`; the agent
  then adds details and features.
- **DNS:** custom DNS when enabled, otherwise 10.2.0.1 for WireGuard or the pushed servers
  for OpenVPN, written above net_server's `# Dynamic DNS entries` marker and removed on
  disconnect (and at start-up after a crash).
- **Local agent:** features requested for paid plans (free plans only ask for the status);
  hard-jailed reasons become ExpiredCertificate (refresh the certificate, the agent
  reconnects with it), TwoFARequired, MaximumSessionsReached or UnexpectedError. With port
  forwarding the app renews a NAT-PMP TCP mapping every minute.

## Kill switch

Haiku has no packet filter, so the kill switch uses routes: a "blackhole" tunnel
interface that nobody reads (`10.255.255.254/32`) carries `0.0.0.0/1` and `128.0.0.0/1`
(and the IPv6 halves when there is an IPv6 default route), which beat the default route.
The VPN server keeps a host route through the real gateway. Tunnels route quarters,
which beat the halves, so the blackhole can stay in place while connected and catches
everything the moment a tunnel drops. Standard: active while connecting, connected and in
error, removed on a deliberate disconnect. Advanced (permanent): also while disconnected;
the state file `~/config/settings/Proton VPN/killswitch` makes the next start restore it,
and the interface outlives a crashed app.

## Haiku notes

- **Tunnel units:** adding an interface `tun/<n>` makes the driver publish `/dev/tun/<n>`;
  the helper adds the first free unit and removes it when done. Units whose interface is
  gone but whose sockets linger are skipped (see Burrow). The driver's `read()` blocks
  even in non-blocking mode, so the helper polls first. Packets are raw IP.
- **Routes:** one route per destination system-wide; a new helper takes over routes a
  killed helper left behind, and the app removes a dead helper's interface.
- **`route(8)`** turns `0.0.0.0/1` into a default route (fixed in the fork on branch
  `route-zero-network`); the app and its OpenVPN use ioctls.
- **Resolver caching:** programs that already resolved names keep their name servers until
  they restart (libnetwork's `res_check()` is compiled out; see Burrow's notes).
- **Key store:** the first access from each executable path asks the user to allow it.

## Testing

- `make BUILD=build-host check-host` (Linux) / `make check` (Haiku): SRP against vectors
  from python-proton-core, the modulus signature of a real `/auth/info` reply, key
  derivation against libsodium, WireGuard handshakes, rekeying, replay protection and
  retransmission.
- `tests/wg-interop.sh`: the WireGuard engine against Linux's kernel WireGuard in Docker
  (handshake and ICMP echo, small and near-MTU packets).
- `tools/fake-proton.sh start`: stand-in Proton API (real SRP, certificates, logicals with
  free, Secure Core, Tor, P2P, smart-routing and maintenance servers), WireGuard and
  OpenVPN server, local agent and NAT-PMP; `ctl` switches error modes (expired tokens,
  maintenance, jailed agent, ...). See `tools/fake-proton/README.md`.
- In the air/OS VM (`docs/VM.md`) with the fake servers: `proton-vpn-cli` sign-in,
  WireGuard, OpenVPN UDP/TCP, port forwarding, standard kill switch with a killed helper
  and reconnection; the app's login, 2FA, server list, search, settings, tray menu,
  sign-out and quit flows, max sessions and expired certificate recovery.
