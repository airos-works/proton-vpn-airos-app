# Proton VPN for air/OS

A native port of the [Proton VPN](https://protonvpn.com) Linux app
([proton-vpn-gtk-app](https://github.com/ProtonVPN/proton-vpn-gtk-app) and
[python-proton-vpn-api-core](https://github.com/ProtonVPN/python-proton-vpn-api-core))
to air/OS and Haiku, with a native Haiku user interface instead of GTK.

- **Sign in** with your Proton account, including two-factor codes (authenticator app or
  recovery code). The session lives in the Haiku key store; sign out from the menu.
- **Server list** of countries, cities/states and Secure Core routes, with flags, P2P,
  Tor and smart routing badges, loads and maintenance; search by country, city or server.
  Free plans see the free countries first and "Upgrade" on paid ones.
- **Connect** to the fastest server, a country, a city, a Secure Core route or a server.
  Change server for free plans, auto connect at start-up, and pinned connections in the
  Deskbar tray menu.
- **Protocols:** WireGuard (a built-in userspace implementation on Haiku's tunnel driver)
  and OpenVPN over UDP or TCP (`proton-openvpn`, OpenVPN 2.6.13 for Haiku), both with
  Proton's certificate authentication.
- **Features** through the server's local agent: NetShield, VPN Accelerator, moderate NAT
  and port forwarding (the forwarded port is shown, click to copy).
- **Kill switch** (standard and advanced), custom DNS servers, IPv6.
- Server list and loads, client configuration, feature flags and the certificate are
  refreshed in the background as the Linux app does; dropped connections reconnect.

## Status

Alpha. Tested end to end in an air/OS x86_64 VM against stand-in Proton servers
(`tools/fake-proton`) and against the real Proton API for sign-in.

## Build

On air/OS or Haiku with `gcc`, `make`, `curl_devel`, `openssl3_devel`, `autoconf`,
`automake`, `libtool`, `patch` and `pkgconfig`:

```sh
make                 # build-haiku/ProtonVPN, proton-wireguard, proton-vpn-cli
make openvpn         # build-haiku/openvpn/proton-openvpn
make check           # core tests
make package         # artifacts/proton_vpn-<version>-x86_64.hpkg
```

The core (`src/core`, no Haiku API) also builds on Linux: `make BUILD=build-host check-host`.
`tests/wg-interop.sh` checks the WireGuard implementation against Linux's kernel WireGuard.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/VM.md](docs/VM.md) and
[docs/TESTING.md](docs/TESTING.md) (checklist for a real Proton account).

## License

GNU GPL version 3 or later, like the Proton VPN Linux app it is ported from (see
[LICENSE](LICENSE)). `proton-openvpn` is OpenVPN, GNU GPL v2; its patches and build script
ship in the package's documentation folder. crypt_blowfish is public domain,
nlohmann/json is MIT. Proton VPN is a trademark of Proton AG; this is an unofficial port.
