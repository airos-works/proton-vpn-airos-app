#!/usr/bin/env bash
# Starts the air/OS test VM (VNC 127.0.0.1:5909, SSH 127.0.0.1:2229).
# The disk comes from tools/make-vm-disk.sh; see docs/VM.md.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
if [[ -S .vm/qmp.sock ]] && python3 tools/vm.py status >/dev/null 2>&1; then
	echo 'The VM is already running.'
	exit 0
fi
if [[ -f .vm/qemu.pid ]] && kill -0 "$(cat .vm/qemu.pid)" 2>/dev/null; then
	echo 'A VM process exists but QMP does not answer; inspect it first.' >&2
	exit 1
fi
[[ -f .vm/disk.img ]] || { echo 'No .vm/disk.img: run tools/make-vm-disk.sh first.' >&2; exit 1; }
rm -f .vm/qmp.sock
exec qemu-system-x86_64 -enable-kvm -cpu host -m "${PVPN_VM_MEMORY:-4096}" -smp "${PVPN_VM_CPUS:-6}" \
	-drive file=.vm/disk.img,format=raw,if=ide,index=0 \
	-nic user,model=e1000,hostfwd=tcp:127.0.0.1:2229-:22 \
	-device qemu-xhci -device usb-tablet -vga std -display none \
	-audiodev none,id=snd0 -device intel-hda -device hda-duplex,audiodev=snd0 \
	-vnc 127.0.0.1:9 -qmp unix:.vm/qmp.sock,server=on,wait=off \
	-pidfile .vm/qemu.pid -serial file:.vm/serial.log -daemonize
