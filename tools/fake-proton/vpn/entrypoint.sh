#!/bin/sh
# Fake ProtonVPN server: WireGuard (wg0, 10.2.0.1/24), OpenVPN over UDP
# (10.96.0.0/16) and TCP (10.97.0.0/16), dnsmasq and the local agent /
# NAT-PMP / whoami services, all on 10.2.0.1. Keys and certificates come
# from the state directory mounted at /state (made by the fake API).
set -u

STATE=${FAKE_PROTON_STATE:-/state}
DNS_UPSTREAM=${FAKE_PROTON_DNS_UPSTREAM:-1.1.1.1}
RUN=/run/fake-proton
OPT=/opt/fake-proton
mkdir -p "$RUN"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [entrypoint] $*"; }
die() { log "FATAL: $*"; exit 1; }
own() { [ -n "${HOST_UID:-}" ] && chown "$HOST_UID:${HOST_GID:-$HOST_UID}" "$@" 2>/dev/null; true; }

for f in wg-server.key openvpn-server.pem openvpn-server.key vpn-client-ca.pem \
         agent-server.pem agent-server.key; do
	[ -s "$STATE/$f" ] || die "missing $STATE/$f (run tools/fake-proton.sh start)"
done
for name in openvpn-udp openvpn-tcp dnsmasq services; do
	: > "$STATE/vpn-$name.log"
	own "$STATE/vpn-$name.log"
done

# -- WireGuard ------------------------------------------------------------------
ip link del wg0 2>/dev/null
ip link add wg0 type wireguard || die "cannot create wg0 (wireguard kernel module missing on the host?)"
wg set wg0 listen-port 51820 private-key "$STATE/wg-server.key" || die "wg set failed"
ip address add 10.2.0.1/24 dev wg0
ip link set wg0 mtu 1420 up
if [ -s "$STATE/wg-peers.txt" ]; then
	while read -r pub ips; do
		[ -n "$pub" ] && wg set wg0 peer "$pub" allowed-ips "${ips:-10.2.0.2/32}" \
			&& log "restored WireGuard peer $pub"
	done < "$STATE/wg-peers.txt"
fi
log "WireGuard wg0 up, public key $(wg show wg0 public-key), listening on udp/51820"

# -- NAT (only effective when the host forwards traffic) -----------------------------
for net in 10.2.0.0/24 10.96.0.0/16 10.97.0.0/16; do
	iptables -t nat -A POSTROUTING -s "$net" -o eth0 -j MASQUERADE 2>/dev/null \
		|| log "warning: cannot add MASQUERADE for $net"
done
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu \
	2>/dev/null || true

# -- OpenVPN --------------------------------------------------------------------------
write_openvpn() { # name proto port device network
	cat > "$RUN/$1.conf" <<EOF
# Server side of the client template in python-proton-vpn-api-core
# (openvpn.py OPENVPN_V2_TEMPLATE): AES-256-GCM, Proton's tls-crypt key,
# certificate-only authentication with Ed25519 client certificates.
mode server
tls-server
proto $2
port $3
dev $4
dev-type tun
topology subnet
server $5 255.255.0.0
disable-dco
ca $STATE/vpn-client-ca.pem
cert $STATE/openvpn-server.pem
key $STATE/openvpn-server.key
dh none
tls-crypt $OPT/proton-tls-crypt.key
verify-client-cert require
remote-cert-tls client
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
tun-mtu 1500
mssfix 1400
keepalive 10 60
reneg-sec 0
persist-key
persist-tun
duplicate-cn
push "redirect-gateway def1"
push "dhcp-option DNS 10.2.0.1"
push "route 10.2.0.1 255.255.255.255"
status $RUN/$1.status 10
writepid $RUN/$1.pid
log-append $STATE/vpn-$1.log
verb 3
EOF
	[ "$2" = udp4 ] && echo "explicit-exit-notify 1" >> "$RUN/$1.conf"
}
write_openvpn openvpn-udp udp4 1194 tun-udp 10.96.0.0
write_openvpn openvpn-tcp tcp4-server 443 tun-tcp 10.97.0.0

# -- daemons -----------------------------------------------------------------------
DNS_SERVERS=""
for server in $(echo "$DNS_UPSTREAM" | tr ',' ' '); do
	[ "$server" = none ] || DNS_SERVERS="$DNS_SERVERS --server=$server"
done

start_openvpn_udp() { openvpn --config "$RUN/openvpn-udp.conf" >/dev/null 2>&1 & echo $! > "$RUN/openvpn-udp.pid"; }
start_openvpn_tcp() { openvpn --config "$RUN/openvpn-tcp.conf" >/dev/null 2>&1 & echo $! > "$RUN/openvpn-tcp.pid"; }
start_dnsmasq() {
	# shellcheck disable=SC2086
	dnsmasq --keep-in-foreground --user=root --no-resolv --no-hosts --no-poll \
		--listen-address=10.2.0.1 --bind-interfaces \
		--address=/fake.proton/10.2.0.1 --address=/whoami.fake.proton/10.2.0.1 \
		--log-queries --log-facility="$STATE/vpn-dnsmasq.log" $DNS_SERVERS &
	echo $! > "$RUN/dnsmasq.pid"
}
start_services() { python3 -u "$OPT/services.py" >> "$STATE/vpn-services.log" 2>&1 & echo $! > "$RUN/services.pid"; }

stop_all() {
	log "stopping"
	for pidfile in "$RUN"/*.pid; do kill "$(cat "$pidfile")" 2>/dev/null; done
	exit 0
}
trap stop_all TERM INT

for daemon in openvpn_udp openvpn_tcp dnsmasq services; do "start_$daemon"; done
log "OpenVPN udp/1194 (10.96.0.0/16) and tcp/443 (10.97.0.0/16), dnsmasq, services on 10.2.0.1 started"

while true; do
	sleep 3 &
	wait $!
	for daemon in openvpn_udp openvpn_tcp dnsmasq services; do
		pidfile="$RUN/$(echo "$daemon" | tr _ -).pid"
		pid=$(cat "$pidfile" 2>/dev/null)
		if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
			log "$daemon is not running, restarting"
			"start_$daemon"
		fi
	done
done
