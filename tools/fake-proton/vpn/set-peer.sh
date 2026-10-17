#!/bin/sh
# Makes <public key> the only WireGuard peer of wg0. The fake API runs this
# with `docker exec` whenever it issues a certificate (POST /vpn/v1/certificate).
set -eu
pub=$1
ips=${2:-10.2.0.2/32}
for peer in $(wg show wg0 peers); do
	[ "$peer" = "$pub" ] || wg set wg0 peer "$peer" remove
done
wg set wg0 peer "$pub" allowed-ips "$ips"
echo "wg0 peer is now $pub ($ips)"
