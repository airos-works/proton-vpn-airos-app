#!/usr/bin/env bash
# Builds the test VM disk (.vm/disk.img) from an air/OS x86_64 anyboot ISO,
# entirely on Linux with the Haiku host tools (bfs_shell, package):
#   1. copies the ISO's MBR and BFS partition into a larger sparse image and
#      adds a second BFS volume, "Data", on the rest of the disk,
#   2. adds the development tools needed to build the app and OpenVPN
#      (gcc, binutils, make, autotools, openssl3_devel, curl_devel, python3),
#   3. installs .vm/id_ed25519.pub for SSH and starts sshd at boot.
# Usage: tools/make-vm-disk.sh [ISO]   (PVPN_VM_DISK_GB sets the disk size)
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
ISO=${1:-${PVPN_VM_ISO:-/mnt/HaikuWork/apps/summit/.vm/airos-x86_64/airos-x86_64.iso}}
SIZE_GB=${PVPN_VM_DISK_GB:-24}
HAIKU_BUILD=${HAIKU_BUILD:-/mnt/HaikuWork/x399/build/x86_64}
TOOLS=$HAIKU_BUILD/objects/linux/x86_64/release/tools
BFS=$TOOLS/bfs_shell/bfs_shell
PACKAGE=$TOOLS/package/package
PACKAGE_REPO=$TOOLS/package_repo/package_repo
DEVEL=${PVPN_HAIKU_DEVEL:-/mnt/HaikuWork/build/master-x86_64/objects/haiku/x86_64/packaging/packages/haiku_devel.hpkg}
REPO_URL=https://eu.hpkg.haiku-os.org/haikuports/master/x86_64/current
CACHE=.vm/packages
DISK=.vm/disk.img
mkdir -p .vm "$CACHE"

if [[ -f .vm/qemu.pid ]] && kill -0 "$(cat .vm/qemu.pid)" 2>/dev/null; then
	echo 'Stop the VM first (bash tools/haiku.sh shutdown -q).' >&2
	exit 1
fi
[[ -f .vm/id_ed25519 ]] || ssh-keygen -q -t ed25519 -N '' -C proton-vpn-vm -f .vm/id_ed25519

# --- 1. Disk image: the ISO's system partition plus a data partition ---------
# BFS cannot grow the system volume (its block bitmap is sized at creation), so
# the rest of the disk becomes a second BFS volume, "Data", for builds.
read -r START SECTORS < <(python3 - "$ISO" <<'EOF'
import struct, sys
mbr = open(sys.argv[1], 'rb').read(512)
for i in range(4):
	entry = mbr[446 + 16 * i:462 + 16 * i]
	if entry[4] == 0xeb:  # BeOS/Haiku BFS
		start, count = struct.unpack('<II', entry[8:16])
		print(start, count)
		break
else:
	sys.exit('no BFS partition in ' + sys.argv[1])
EOF
)
echo "BFS partition: sector $START, $SECTORS sectors"
rm -f "$DISK"
truncate -s "${SIZE_GB}G" "$DISK"
dd if="$ISO" of="$DISK" bs=512 count="$START" conv=notrunc,sparse status=none
dd if="$ISO" of="$DISK" bs=512 skip="$START" seek="$START" count="$SECTORS" conv=notrunc,sparse status=none
TOTAL=$(( SIZE_GB * 1024 * 1024 * 2 ))
DATA_START=$(( (START + SECTORS + 2047) / 2048 * 2048 ))
DATA_SECTORS=$(( (TOTAL - DATA_START) / 2048 * 2048 ))
python3 - "$DISK" "$START" "$SECTORS" "$DATA_START" "$DATA_SECTORS" <<'EOF'
import struct, sys
path = sys.argv[1]
start, count, data_start, data_count = map(int, sys.argv[2:])
def entry(active, start, count):
	# CHS fields are unused by Haiku and SeaBIOS; mark them as LBA-only.
	return bytes([0x80 if active else 0, 0xfe, 0xff, 0xff, 0xeb, 0xfe, 0xff, 0xff]) + struct.pack('<II', start, count)
with open(path, 'r+b') as f:
	mbr = bytearray(f.read(512))
	keep = mbr[446:462] if mbr[446 + 4] == 0xeb else None
	mbr[446:510] = bytes(64)
	mbr[446:462] = keep if keep else entry(True, start, count)
	mbr[446] = 0x80
	# the ISO's EFI partition is dropped: the VM boots through the BIOS
	mbr[462:478] = entry(False, data_start, data_count)
	f.seek(0)
	f.write(mbr)
EOF
OFFSETS=(--start-offset $(( START * 512 )) --end-offset $(( (START + SECTORS) * 512 )))
DATA_OFFSETS=(--start-offset $(( DATA_START * 512 )) --end-offset $(( (DATA_START + DATA_SECTORS) * 512 )))
"$BFS" "${DATA_OFFSETS[@]}" --initialize "$DISK" Data >/dev/null

# --- 2. Development packages ----------------------------------------------------
printf 'ls /myfs/system/packages\nquit\n' | "$BFS" "${OFFSETS[@]}" "$DISK" 2>/dev/null |
	awk '{print $NF}' | grep '\.hpkg$' > .vm/installed-packages.txt
if [[ ! -f $CACHE/repo-verbose.txt || -n $(find "$CACHE/repo-verbose.txt" -mmin +1440) ]]; then
	curl -sSfL -o "$CACHE/repo" "$REPO_URL/repo"
	"$PACKAGE_REPO" list -v "$CACHE/repo" > "$CACHE/repo-verbose.txt"
fi
# curl_devel must match curl exactly, so the image's curl is replaced by the
# repository's. openssl3_devel is taken from the Haiku build's downloads, which
# match the image's openssl3.
grep -v '^curl-' .vm/installed-packages.txt > .vm/installed-minus-curl.txt
mapfile -t WANT < <(python3 tools/resolve-packages.py "$CACHE/repo-verbose.txt" .vm/installed-minus-curl.txt \
	gcc binutils make autoconf automake libtool m4 pkgconfig curl curl_devel python3.10 | grep -v '^openssl3_devel-')
OPENSSL_VERSION=$(grep '^openssl3-' .vm/installed-packages.txt | cut -d- -f2)
OPENSSL_DEVEL=$(ls "$HAIKU_BUILD"/download/openssl3_devel-"$OPENSSL_VERSION"-*.hpkg | head -1)
for pkg in "${WANT[@]}"; do
	[[ -f $CACHE/$pkg ]] || { echo "downloading $pkg"; curl -sSfL -o "$CACHE/$pkg.part" "$REPO_URL/packages/$pkg" && mv "$CACHE/$pkg.part" "$CACHE/$pkg"; }
done

# haiku_devel has to match the haiku package exactly; repackage a build's
# haiku_devel with the image's version requirement relaxed.
HAIKU_VERSION=$(grep '^haiku-r1' .vm/installed-packages.txt | sed -E 's/^haiku-(.*)-x86_64\.hpkg$/\1/')
WORK=$(mktemp -d /mnt/HaikuWork/tmp/pvpn-devel.XXXXXX)
trap 'rm -rf "$WORK"' EXIT
(cd "$WORK" && "$PACKAGE" extract "$DEVEL" >/dev/null)
sed -i -E "s/haiku==r1~[^ ]+/haiku>=$HAIKU_VERSION/" "$WORK/.PackageInfo"
(cd "$WORK" && "$PACKAGE" create -q -C . "$ROOT/$CACHE/haiku_devel.hpkg" 2>/dev/null || "$PACKAGE" create -C . "$ROOT/$CACHE/haiku_devel.hpkg")
"$PACKAGE" list -i "$CACHE/haiku_devel.hpkg" | grep -E 'version:|requires:' | head -3

# --- 3. SSH and boot script -------------------------------------------------------
cat > .vm/UserBootscript <<'EOF'
#!/bin/sh
# Test VM: start sshd (host keys are generated on the first boot).
/boot/system/bin/ssh-keygen -A >/dev/null 2>&1
/boot/system/bin/sshd
mountvolume Data >/dev/null 2>&1
EOF
cp .vm/id_ed25519.pub .vm/authorized_keys

{
	echo "rm /myfs/system/packages/$(grep '^curl-' .vm/installed-packages.txt)"
	for pkg in "${WANT[@]}"; do echo "cp :$ROOT/$CACHE/$pkg /myfs/system/packages/$pkg"; done
	echo "cp :$OPENSSL_DEVEL /myfs/system/packages/$(basename "$OPENSSL_DEVEL")"
	echo "cp :$ROOT/$CACHE/haiku_devel.hpkg /myfs/system/packages/haiku_devel.hpkg"
	echo "mkdir -p /myfs/home/config/settings/ssh"
	echo "cp :$ROOT/.vm/authorized_keys /myfs/home/config/settings/ssh/authorized_keys"
	echo "chmod 700 /myfs/home/config/settings/ssh"
	echo "chmod 600 /myfs/home/config/settings/ssh/authorized_keys"
	echo "mkdir -p /myfs/home/config/settings/boot"
	echo "cp :$ROOT/.vm/UserBootscript /myfs/home/config/settings/boot/UserBootscript"
	echo "chmod 755 /myfs/home/config/settings/boot/UserBootscript"
	echo "sync"
	echo "quit"
} | "$BFS" "${OFFSETS[@]}" "$DISK" 2>&1 | grep -i -E 'error|fail|cannot' || true
printf 'info\nquit\n' | "$BFS" "${OFFSETS[@]}" "$DISK" 2>/dev/null | grep -i -E 'free size'
printf 'info\nquit\n' | "$BFS" "${DATA_OFFSETS[@]}" "$DISK" 2>/dev/null | grep -i -E 'total size|free size'
echo "disk ready: $DISK ($(du -h "$DISK" | cut -f1) used)"
