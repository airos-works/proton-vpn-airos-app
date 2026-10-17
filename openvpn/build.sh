#!/bin/sh
# Builds the app's OpenVPN in Haiku: OpenVPN 2.6.13 with the HaikuPorts
# platform patches and Burrow's Haiku tunnel/route patch (no AWS patch: Proton
# servers are stock OpenVPN). Output: build-haiku/openvpn/proton-openvpn.
# Usage (from the checkout root, in Haiku): sh openvpn/build.sh
set -e
VERSION=2.6.13
SHA256=730ad13ab0d8efda24b7e8e0df660e4c358ad89105aca47f2bf26da44d8ab020
ROOT=$(pwd)
OUT=$ROOT/build-haiku/openvpn
TARBALL=$OUT/openvpn-$VERSION.tar.gz
SRC=$OUT/openvpn-$VERSION

mkdir -p "$OUT"
if [ ! -f "$TARBALL" ]; then
	curl -sSfL -o "$TARBALL.part" \
		"https://github.com/OpenVPN/openvpn/archive/refs/tags/v$VERSION.tar.gz"
	mv "$TARBALL.part" "$TARBALL"
fi
echo "$SHA256  $TARBALL" | sha256sum -c - >/dev/null

# Always start from pristine sources so patch changes take effect.
patches=$(ls "$ROOT"/openvpn/patches/0*.patch* | sort)
stamp=$(cat $patches | sha256sum | cut -d' ' -f1)
if [ ! -f "$SRC/.proton-patches" ] || [ "$(cat "$SRC/.proton-patches")" != "$stamp" ]; then
	rm -rf "$SRC"
	mkdir -p "$SRC"
	tar xzf "$TARBALL" -C "$SRC" --strip-components=1
	for patch in $patches; do
		echo "applying $(basename "$patch")"
		patch -d "$SRC" -p1 -s < "$patch"
	done
	(cd "$SRC" && autoreconf -fi >/dev/null 2>&1)
	# Proton's servers use no compression, so neither LZO nor LZ4 is needed.
	(cd "$SRC" && LDFLAGS="-lnetwork" ./configure -q \
		--disable-lzo --disable-lz4 \
		--disable-plugin-auth-pam --disable-plugin-down-root \
		--disable-pkcs11 --disable-debug >/dev/null)
	echo "$stamp" > "$SRC/.proton-patches"
fi
make -C "$SRC" -j"$(nproc 2>/dev/null || echo 4)" >/dev/null
cp "$SRC/src/openvpn/openvpn" "$OUT/proton-openvpn"
strip "$OUT/proton-openvpn"
"$OUT/proton-openvpn" --version | head -1
