#!/usr/bin/env bash
# Fake Proton servers for end-to-end tests of the air/OS Proton VPN client:
# the REST API (a host process) and the VPN server (a Docker container).
# See tools/fake-proton/README.md.
#
#   tools/fake-proton.sh start            build the image if needed, start both, print the env
#   tools/fake-proton.sh stop             stop both
#   tools/fake-proton.sh restart          stop + start (picks up code changes)
#   tools/fake-proton.sh status           what is running, WireGuard peers, API sessions
#   tools/fake-proton.sh logs [NAME] [-f] api | vpn | openvpn-udp | openvpn-tcp | dnsmasq |
#                                         services | container | all (default all)
#   tools/fake-proton.sh env [--https] [--host]
#                                         client environment (guest view, or host view)
#   tools/fake-proton.sh ctl ACTION [key=value ...]
#                                         POST /fake/control, e.g. ctl agent_mode mode=hard-jailed
#   tools/fake-proton.sh test [--api-only] [--keep]
#                                         end-to-end self-test (starts things if needed)
#   tools/fake-proton.sh totp             current 2FA code of the twofa user's TOTP secret
#   tools/fake-proton.sh build            (re)build the Docker image
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FAKE=$REPO/tools/fake-proton
export FAKE_PROTON_STATE=${FAKE_PROTON_STATE:-$FAKE/state}
STATE=$FAKE_PROTON_STATE
IMAGE=${FAKE_PROTON_IMAGE:-fake-proton-vpn:latest}
export FAKE_PROTON_CONTAINER=${FAKE_PROTON_CONTAINER:-fake-proton-vpn}
CONTAINER=$FAKE_PROTON_CONTAINER
export FAKE_PROTON_BIND=${FAKE_PROTON_BIND:-0.0.0.0}
export FAKE_PROTON_HTTP_PORT=${FAKE_PROTON_HTTP_PORT:-18080}
export FAKE_PROTON_HTTPS_PORT=${FAKE_PROTON_HTTPS_PORT:-18443}
export FAKE_PROTON_OVPN_UDP_PORT=${FAKE_PROTON_OVPN_UDP_PORT:-11940}
export FAKE_PROTON_OVPN_TCP_PORT=${FAKE_PROTON_OVPN_TCP_PORT:-11941}
export FAKE_PROTON_WG_PORT=${FAKE_PROTON_WG_PORT:-51830}
export FAKE_PROTON_ENTRY_IP=${FAKE_PROTON_ENTRY_IP:-10.0.2.2}
export FAKE_PROTON_DOMAIN=${FAKE_PROTON_DOMAIN:-node-fake-01.protonvpn.net}
DNS_UPSTREAM=${FAKE_PROTON_DNS_UPSTREAM:-1.1.1.1}
PIDFILE=$STATE/api.pid
API=http://127.0.0.1:$FAKE_PROTON_HTTP_PORT

say() { printf '%s\n' "$*"; }
die() { printf 'fake-proton: %s\n' "$*" >&2; exit 1; }

image_hash() { cat "$FAKE"/vpn/* | sha256sum | cut -c1-16; }

build_image() {
	local want have
	want=$(image_hash)
	have=$(docker image inspect -f '{{index .Config.Labels "fake-proton.hash"}}' "$IMAGE" 2>/dev/null || true)
	if [[ "$want" != "$have" || "${1:-}" == force ]]; then
		say "building $IMAGE"
		docker build -q --network host --label "fake-proton.hash=$want" -t "$IMAGE" "$FAKE/vpn" >/dev/null
	fi
}

api_running() { [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }
container_running() { [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" == true ]]; }

ping_api() {
	python3 - "$API" <<'EOF' 2>/dev/null
import sys, urllib.request
req = urllib.request.Request(sys.argv[1] + "/tests/ping", headers={"x-pm-appversion": "fake-proton.sh"})
sys.exit(0 if urllib.request.urlopen(req, timeout=2).status == 200 else 1)
EOF
}

init_state() {
	mkdir -p "$STATE"
	python3 "$FAKE/api/fake_api.py" --init-only
}

start_container() {
	if container_running; then
		if [[ "$(docker inspect -f '{{.Image}}' "$CONTAINER")" == "$(docker image inspect -f '{{.Id}}' "$IMAGE")" ]]; then
			return
		fi
		say "image changed, recreating $CONTAINER"
	fi
	docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
	: > "$STATE/vpn-container.log"
	docker run -d --name "$CONTAINER" --hostname node-fake-01 --label fake-proton=server \
		--dns 1.1.1.1 --cap-add NET_ADMIN --device /dev/net/tun \
		--sysctl net.ipv4.ip_forward=1 \
		-p "$FAKE_PROTON_BIND:$FAKE_PROTON_OVPN_UDP_PORT:1194/udp" \
		-p "$FAKE_PROTON_BIND:$FAKE_PROTON_OVPN_TCP_PORT:443/tcp" \
		-p "$FAKE_PROTON_BIND:$FAKE_PROTON_WG_PORT:51820/udp" \
		-v "$STATE:/state" -e "HOST_UID=$(id -u)" -e "HOST_GID=$(id -g)" \
		-e "FAKE_PROTON_DNS_UPSTREAM=$DNS_UPSTREAM" "$IMAGE" >/dev/null
	nohup docker logs -f "$CONTAINER" >> "$STATE/vpn-container.log" 2>&1 &
	local i
	for i in $(seq 1 40); do
		grep -q "services on 10.2.0.1" "$STATE/vpn-services.log" 2>/dev/null && return
		container_running || break
		sleep 0.5
	done
	cat "$STATE/vpn-container.log" >&2
	die "the VPN server container did not come up (see $STATE/vpn-*.log)"
}

start_api() {
	if api_running; then
		return
	fi
	if ping_api; then
		die "something else answers on port $FAKE_PROTON_HTTP_PORT (another fake API?)"
	fi
	nohup python3 "$FAKE/api/fake_api.py" >> "$STATE/api.log" 2>&1 &
	echo $! > "$PIDFILE"
	local i
	for i in $(seq 1 40); do
		ping_api && return
		api_running || break
		sleep 0.25
	done
	tail -n 30 "$STATE/api.log" >&2
	die "the fake API did not start (see $STATE/api.log)"
}

stop_all() {
	if api_running; then
		kill "$(cat "$PIDFILE")" 2>/dev/null || true
		say "stopped the fake API"
	fi
	rm -f "$PIDFILE"
	if docker inspect "$CONTAINER" >/dev/null 2>&1; then
		docker rm -f "$CONTAINER" >/dev/null
		say "removed container $CONTAINER"
	fi
	local leftovers
	leftovers=$(docker ps -aq --filter label=fake-proton=selftest)
	[[ -n "$leftovers" ]] && docker rm -f $leftovers >/dev/null
	return 0
}

print_env() {
	local scheme=http port=$FAKE_PROTON_HTTP_PORT host=10.0.2.2 view="QEMU guest"
	local arg
	for arg in "$@"; do
		case $arg in
			--https) scheme=https; port=$FAKE_PROTON_HTTPS_PORT ;;
			--host) host=127.0.0.1; view="this host" ;;
		esac
	done
	local pin wg
	pin=$(python3 -c "import sys; sys.path.insert(0, sys.argv[1]); import pki; print(pki.State(sys.argv[2]).api_pin)" "$FAKE/api" "$STATE")
	wg=$(cat "$STATE/wg-server.pub")
	cat <<EOF
# Client environment ($view). Copy the CA files into the guest first, e.g.
#   curl -o api-ca.pem http://10.0.2.2:$FAKE_PROTON_HTTP_PORT/fake/files/api-ca.pem   (also openvpn-ca.pem, agent-ca.pem)
export PROTON_VPN_API_URL=$scheme://$host:$port
export PROTON_VPN_API_PINS=none          # or: $pin  (SPKI pin of the fake API certificate)
export PROTON_VPN_CA_FILE=$STATE/api-ca.pem
export PROTON_VPN_OPENVPN_CA_FILE=$STATE/openvpn-ca.pem
export PROTON_VPN_AGENT_CA_FILE=$STATE/agent-ca.pem
# VPN server: entry IP $FAKE_PROTON_ENTRY_IP, domain $FAKE_PROTON_DOMAIN,
#   OpenVPN udp/$FAKE_PROTON_OVPN_UDP_PORT tcp/$FAKE_PROTON_OVPN_TCP_PORT, WireGuard udp/$FAKE_PROTON_WG_PORT
#   WireGuard server public key $wg ($STATE/wg-server.pub)
# In the tunnel: DNS/HTTP/local agent (tcp/65432)/NAT-PMP (udp/5351) on 10.2.0.1, whoami.fake.proton
# Users: demo/demo (Plus), free/free (Free), twofa/twofa (Plus, 2FA code 123456 or TOTP of JBSWY3DPEHPK3PXP)
EOF
}

control() {
	local action=$1
	shift
	python3 - "$API" "$action" "$@" <<'EOF'
import json, sys, urllib.request, urllib.error
api, action, pairs = sys.argv[1], sys.argv[2], sys.argv[3:]
body = {"action": action}
for pair in pairs:
    key, _, value = pair.partition("=")
    try:
        body[key] = json.loads(value)
    except ValueError:
        body[key] = value
req = urllib.request.Request(api + "/fake/control", data=json.dumps(body).encode(),
                             headers={"Content-Type": "application/json"})
try:
    print(urllib.request.urlopen(req, timeout=10).read().decode())
except urllib.error.HTTPError as exc:
    print(exc.read().decode())
    sys.exit(1)
EOF
}

show_status() {
	if api_running; then
		say "API: running (pid $(cat "$PIDFILE")) on http://$FAKE_PROTON_BIND:$FAKE_PROTON_HTTP_PORT and https://$FAKE_PROTON_BIND:$FAKE_PROTON_HTTPS_PORT"
		python3 - "$API" <<'EOF' || true
import json, sys, urllib.request
state = json.load(urllib.request.urlopen(sys.argv[1] + "/fake/state", timeout=5))
for s in state["Sessions"]:
    left = s["AccessExpiresIn"]
    expiry = f"expires in {left} s" if left > 0 else "expired (refreshable)"
    print(f"  session {s['Username']:<8} UID {s['UID']} access token {expiry}"
          f"{' (2FA pending)' if s['Pending2FA'] else ''}")
print(f"  agent mode {state['Agent']['mode']}, NAT-PMP {state['Agent']['natpmp_mode']}, "
      f"token TTL {state['TokenTTL']} s, cert TTL {state['CertTTL'] or 'as requested'}")
EOF
	else
		say "API: not running"
	fi
	if container_running; then
		say "VPN server: container $CONTAINER running ($(docker port "$CONTAINER" | tr '\n' ' '))"
		docker exec "$CONTAINER" wg show wg0 | sed 's/^/  /'
	else
		say "VPN server: not running"
	fi
}

show_logs() {
	local name=all follow=0 arg files=()
	for arg in "$@"; do
		case $arg in
			-f|--follow) follow=1 ;;
			*) name=$arg ;;
		esac
	done
	case $name in
		all) files=("$STATE/api.log" "$STATE"/vpn-*.log) ;;
		api) files=("$STATE/api.log") ;;
		vpn) files=("$STATE"/vpn-*.log) ;;
		openvpn-udp|openvpn-tcp|dnsmasq|services|container) files=("$STATE/vpn-$name.log") ;;
		*) die "unknown log $name" ;;
	esac
	if (( follow )); then
		tail -n 20 -F "${files[@]}"
	else
		tail -n 40 "${files[@]}"
	fi
}

cmd=${1:-help}
shift || true
case $cmd in
	start)
		command -v docker >/dev/null || die "docker is required"
		init_state
		build_image
		start_container
		start_api
		say "fake Proton is up (logs: $STATE/*.log)"
		say ""
		print_env "$@"
		;;
	stop) stop_all ;;
	restart) stop_all; exec "$0" start "$@" ;;
	status) show_status ;;
	logs) show_logs "$@" ;;
	env) print_env "$@" ;;
	ctl|control) [[ $# -ge 1 ]] || die "usage: ctl ACTION [key=value ...]"; control "$@" ;;
	build) build_image force ;;
	totp)
		python3 - "$FAKE/users.json" <<'EOF'
import base64, hashlib, hmac, json, struct, sys, time
secret = json.load(open(sys.argv[1]))["totp_secret"]
key = base64.b32decode(secret + "=" * (-len(secret) % 8))
digest = hmac.new(key, struct.pack(">Q", int(time.time() // 30)), hashlib.sha1).digest()
offset = digest[-1] & 0x0F
print(f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000:06d}")
EOF
		;;
	test)
		if ! api_running || ! container_running; then
			"$0" start >/dev/null
		fi
		exec python3 "$FAKE/selftest/selftest.py" "$@"
		;;
	help|-h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0" ;;
	*) die "unknown command $cmd (try: $0 help)" ;;
esac
