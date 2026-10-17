#!/usr/bin/env bash
# Checks the userspace WireGuard engine against Linux's kernel WireGuard in a
# throwaway Docker container (needs the wireguard module on the host).
# Usage: tests/wg-interop.sh   (after make BUILD=build-host build-host/wg_interop)
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BIN=$ROOT/build-host/wg_interop
NAME=pvpn-wg-interop
PORT=${WG_INTEROP_PORT:-51999}
[[ -x $BIN ]] || { echo "build $BIN first" >&2; exit 1; }
docker image inspect pvpn-wgtest:1 >/dev/null 2>&1 || printf "FROM alpine:3.20\nRUN apk add --no-cache wireguard-tools-wg iproute2\n" | docker build -q --network host -t pvpn-wgtest:1 - >/dev/null
docker rm -f "$NAME" >/dev/null 2>&1 || true
CLIENT_KEY=$(python3 -c 'import base64,os;k=bytearray(os.urandom(32));k[0]&=248;k[31]&=127;k[31]|=64;print(base64.b64encode(bytes(k)).decode())')
CLIENT_PUB=$(python3 -c 'import base64,sys;from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey as K;from cryptography.hazmat.primitives import serialization as s;k=K.from_private_bytes(base64.b64decode(sys.argv[1]));print(base64.b64encode(k.public_key().public_bytes(s.Encoding.Raw,s.PublicFormat.Raw)).decode())' "$CLIENT_KEY")
docker run -d --name "$NAME" --dns 1.1.1.1 --cap-add NET_ADMIN -p 127.0.0.1:$PORT:51820/udp pvpn-wgtest:1 sleep 600 >/dev/null
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
# wg comes with the image (tools/../tests/wg-interop.sh builds it with host networking)
SERVER_PUB=$(docker exec -e CLIENT_PUB="$CLIENT_PUB" "$NAME" sh -c '
	umask 077
	wg genkey > /server.key
	ip link add wg0 type wireguard
	wg set wg0 listen-port 51820 private-key /server.key peer "$CLIENT_PUB" allowed-ips 10.2.0.2/32
	ip addr add 10.2.0.1/24 dev wg0
	ip link set wg0 mtu 1420 up
	wg pubkey < /server.key')
"$BIN" "$CLIENT_KEY" "$SERVER_PUB" 127.0.0.1 "$PORT" 10
docker exec "$NAME" wg show wg0 | sed -n '1,20p'
