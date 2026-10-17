# Testing with a real Proton account

Everything below has been exercised against the stand-in servers in `tools/fake-proton`
(see `docs/VM.md`); with the real service only the sign-in exchange has been checked so
far. A free Proton account is enough for most of it; Plus features need a paid plan.

The app logs to `~/config/settings/Proton VPN/proton-vpn.log`; OpenVPN's own log for the
last attempt is in `/boot/system/cache/tmp/proton-vpn/connection-*/openvpn.log` while it
runs. `proton-vpn-cli -v ...` (in `/boot/system/bin`) runs the same core from Terminal
with its own state directory.

## Checklist

1. **Sign in.** Wrong password → "Incorrect credentials." Correct one → the server list.
   With two-factor authentication: the 6-digit code screen, a wrong code → "Incorrect 2FA
   code.", "Use recovery code" takes 8 characters. The first start asks the key store for
   access (Allow always).
2. **Server list.** Countries with flags, cities/states, "Via Secure Core" (Plus), feature
   badges (P2P, Tor, smart routing), loads. Free plan: free countries first, "Upgrade" on
   paid rows. Search "zur", "ch#", a country name. Connection › Refresh server list.
3. **Connect (WireGuard, the default).** Quick Connect → "Protected", country and
   "City - XX#N". `curl https://ipinfo.io` (or a browser) shows the VPN's address; DNS
   resolves through 10.2.0.1 (`cat /boot/system/settings/network/resolv.conf`).
   Disconnect → "Unprotected", routes and DNS restored (`route list` has no `tun` lines).
4. **OpenVPN.** Settings › Protocol › OpenVPN (UDP), connect, check as above; then
   OpenVPN (TCP).
5. **Features (Plus).** NetShield "Block ads, trackers and malware" while connected
   (applies live); port forwarding shows "Active port" (click copies it); Secure Core
   route; a P2P server.
6. **Kill switch.** Standard: connect, then `kill` the `proton-wireguard` team →
   internet blocked until the app reconnects (a second or two). Advanced: blocks while
   disconnected, survives quitting and restarting the app; turning it off restores the
   network.
7. **Tray.** Deskbar icon (grey / green check / red), its menu: Connect, Disconnect,
   pinned connections (Settings › Pinned tray connections, e.g. `NL, CH#1`), Show/Hide,
   Quit. Closing the window keeps the app in the tray.
8. **Session.** Quit and start again: still signed in, no password. Sign out while
   connected → confirmation, disconnects, back to the login screen.
9. **Long run.** Leave it connected for more than 15 minutes (loads refresh) and over
   an hour; the certificate refreshes weekly, the server list every 3 hours.

## Things to watch for

- The API rejecting the client (`x-pm-appversion` is `linux-vpn-gui@5.8.7+x86_64`, the
  Linux app's): the error text appears in the login notification bar.
- Human verification (CAPTCHA, code 9001): like the Linux app, the port cannot show the
  CAPTCHA; the API's message is shown. Signing in once on the web usually clears it.
- Programs that were running before connecting keep their old name servers (Haiku's
  resolver reads resolv.conf once per process); restart the browser if names do not
  resolve.
