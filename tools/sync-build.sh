#!/usr/bin/env bash
# Sync sources to the test VM (/Data/proton-vpn) and build there, printing
# compiler errors only. Usage: tools/sync-build.sh [make-target] [max-lines]
set -uo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
TARGET=${1:-all}
tar -czf - --exclude=__pycache__ --exclude='tools/fake-proton/state' Makefile README.md LICENSE docs \
	src tests tools resources openvpn third_party 2>/dev/null |
	bash tools/haiku.sh "mkdir -p /Data/proton-vpn && tar xzf - --warning=no-timestamp -C /Data/proton-vpn 2>/dev/null; cd /Data/proton-vpn && make -j6 $TARGET 2>&1 | grep -E -B1 -A4 'error|Error|undefined|warning: unused' | head -${2:-80}; echo \"exit: \${PIPESTATUS[0]}\""
