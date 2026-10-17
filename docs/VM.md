# Test VM (air/OS x86_64)

| Item | Value |
| --- | --- |
| Guest | air/OS x86_64 anyboot (hrev60206_1145) + development tools |
| VNC | `127.0.0.1:5909` (display `:9`), loopback only |
| SSH | `127.0.0.1:2229`, user `user`, key `.vm/id_ed25519` (`bash tools/haiku.sh`) |
| QMP | `.vm/qmp.sock` (`python3 tools/vm.py status|screenshot|click|type|key`) |
| Disk | `.vm/disk.img`, raw, sparse 24 GiB: `airOS` system volume (3 GiB) and `Data` (21 GiB, `/Data`) |
| Resources | 6 vCPUs, 4 GiB RAM (`PVPN_VM_CPUS`, `PVPN_VM_MEMORY`) |

## Creating the disk

`bash tools/make-vm-disk.sh [ISO]` builds the disk on Linux with the Haiku host tools
from the x399 build (`bfs_shell`, `package`, `package_repo`), without booting an
installer:

1. The ISO's MBR and BFS system partition are copied into a sparse image. BFS cannot
   grow that volume (its block bitmap is sized when it is created), so the rest of
   the disk becomes a second BFS volume, `Data`.
2. gcc, binutils, make, autotools, pkgconfig, curl/curl_devel, openssl3_devel and
   python3.10 are added to `/system/packages` (resolved from the current HaikuPorts
   index by `tools/resolve-packages.py`). `curl_devel` must match `curl` exactly, so
   the image's curl is replaced; `openssl3_devel` comes from the Haiku build's
   downloads, which match the image's openssl3. `haiku_devel` comes from the
   master-x86_64 build, repackaged with its `haiku==` requirement relaxed to the
   image's version.
3. `.vm/id_ed25519.pub` becomes `~/config/settings/ssh/authorized_keys` and a
   `UserBootscript` generates the host keys, starts sshd and mounts `Data`.

The first boot shows the "Welcome to air/OS" prompt: click **Try air/OS**
(`python3 tools/vm.py click 902 582 1280 800`).

## Everyday commands

```sh
bash tools/run-vm.sh                 # start
bash tools/sync-build.sh             # sync sources to /Data/proton-vpn and build
bash tools/haiku.sh 'shutdown -q'    # stop
python3 tools/vm.py screenshot       # .vm/screen.png
```

The guest reaches the host as `10.0.2.2` (QEMU user networking).

## Testing against the stand-in Proton servers

```sh
bash tools/fake-proton.sh start          # API on 18080/18443, VPN server in Docker
bash tools/haiku.sh '. /Data/fakeenv.sh; $CLI login demo'   # see below
```

`/Data/fakeenv.sh` in the guest downloads the fake CAs and sets `PROTON_VPN_API_URL`,
`PROTON_VPN_API_PINS=none`, `PROTON_VPN_OPENVPN_CA_FILE`, `PROTON_VPN_AGENT_CA_FILE` and
`CLI` (proton-vpn-cli with its own state directory). Start the app with the same
environment to test the UI against the fake servers:

```sh
bash tools/haiku.sh '. /Data/fakeenv.sh; cd /Data/proton-vpn; nohup build-haiku/ProtonVPN >/Data/app.out 2>&1 &'
```

The app logs to `~/config/settings/Proton VPN/proton-vpn.log`. `hey application/x-vnd.ProtonVPN qcon`
quick-connects, `dcon` disconnects, `rfsv` refreshes the server list.

The package needed `patch` for the OpenVPN build; on the first activation the package
daemon also updated xz_utils, sqlite and expat (a dialog on the guest's screen).
