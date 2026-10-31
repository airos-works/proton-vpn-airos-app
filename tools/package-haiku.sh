#!/usr/bin/env bash
# Builds the Haiku package (.hpkg) on Haiku. Run from the repository root.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
NAME=$(awk '$1 == "name" { print $2; exit }' resources/ProtonVPN.PackageInfo)
VERSION=$(awk '$1 == "version" { print $2; exit }' resources/ProtonVPN.PackageInfo)
ARCH=$(awk '$1 == "architecture" { print $2; exit }' resources/ProtonVPN.PackageInfo)
FILE="$ROOT/artifacts/$NAME-$VERSION-$ARCH.hpkg"
make -j6
sh openvpn/build.sh
STAGE=$(mktemp -d /tmp/proton-vpn-package-XXXXXX)
trap 'rm -rf -- "$STAGE"' EXIT
APP="$STAGE/apps/Proton VPN"
DOCS="$STAGE/documentation/packages/proton_vpn"
mkdir -p "$APP/helpers" "$STAGE/bin" "$DOCS/openvpn" "$STAGE/data/deskbar/menu/Applications" \
    "$STAGE/data/launch" \
    "$ROOT/artifacts"
cp build-haiku/ProtonVPN "$APP/Proton VPN"
strip --strip-debug "$APP/Proton VPN"
# GNU strip drops the appended Haiku resources; put them back.
xres -o "$APP/Proton VPN" build-haiku/ProtonVPN.rsrc
cp build-haiku/proton-wireguard "$APP/helpers/proton-wireguard"
cp build-haiku/openvpn/proton-openvpn "$APP/helpers/proton-openvpn"
strip "$APP/helpers/proton-wireguard"
cp build-haiku/proton-vpn-cli "$STAGE/bin/proton-vpn-cli"
strip "$STAGE/bin/proton-vpn-cli"
# At boot, drop name servers a connection left behind (shutdown while connected).
cp resources/launch/proton_vpn "$STAGE/data/launch/proton_vpn"
cp resources/ProtonVPN.PackageInfo "$STAGE/.PackageInfo"
cp README.md LICENSE "$DOCS/"
cp -R docs "$DOCS/"
# OpenVPN is GPL 2: ship how proton-openvpn was made next to the binary.
cp -R openvpn/patches openvpn/build.sh openvpn/SOURCE.md "$DOCS/openvpn/"
ln -s "../../../../apps/Proton VPN/Proton VPN" "$STAGE/data/deskbar/menu/Applications/Proton VPN"
( cd "$STAGE" && mimeset --all -f --mimedb data/mime_db --mimedb /boot/system/data/mime_db "apps/Proton VPN/Proton VPN" )
package create -C "$STAGE" "$FILE"
printf '%s\n' "$FILE"
