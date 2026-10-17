# Source of proton-openvpn

`proton-openvpn` is OpenVPN 2.6.13 (GNU GPL v2), built by `build.sh` from the
upstream release plus the patches in `patches/`, applied in order:

| Patch | From | Purpose |
| --- | --- | --- |
| `0001-haikuports-openvpn-2.6.13.patchset` | HaikuPorts `net-vpn/openvpn` | Haiku platform, tunnel and routing support |
| `0004-burrow-haiku-tunnel-routes.patch` | Burrow (the author's AWS Client VPN app for Haiku) | Creates and removes tunnel units, routes VPN traffic through the tunnel with route ioctls (Haiku's `route(8)` turns `0.0.0.0/1` into a default route), point-to-point peers and IPv6 |

Burrow's AWS Client VPN patches are not used: Proton's servers are stock OpenVPN.
OpenVPN is configured without LZO and LZ4, which Proton does not use.

Upstream source: https://github.com/OpenVPN/openvpn/archive/refs/tags/v2.6.13.tar.gz
(SHA-256 `730ad13ab0d8efda24b7e8e0df660e4c358ad89105aca47f2bf26da44d8ab020`).
