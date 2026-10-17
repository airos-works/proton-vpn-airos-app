#!/usr/bin/env bash
# Runs a command inside the air/OS test VM over SSH (port 2229).
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
exec ssh -i "$ROOT/.vm/id_ed25519" -p 2229 \
	-o IdentitiesOnly=yes -o BatchMode=yes \
	-o UserKnownHostsFile="$ROOT/.vm/known_hosts" -o StrictHostKeyChecking=accept-new \
	-o ConnectTimeout=10 -o ServerAliveInterval=30 user@127.0.0.1 "$@"
