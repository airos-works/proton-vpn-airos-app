# Proton VPN GTK app: UI and behaviour spec for the Haiku port

Everything below was read from source in `proton-vpn-gtk-app` (release notes say 4.18.7) and `python-proton-vpn-api-core`. Quoted strings are the exact English text. `_X` in a button label is a GTK mnemonic (an underscore before the access-key letter). Strings containing `\n` have line breaks at those points.

**Some things you asked about do not exist in this app:**
- There is no "Forgot password" link.
- No IP address and no protocol are shown anywhere in the main window.
- Auto connect has no "last server" option.
- No streaming icon is shown on server rows (the icon class exists but is never used).
- Help links are limited to the URLs listed below.

---

## 0. Global conventions

- **Theme.** Dark theme is forced. Main palette:
  - Accent/primary: #6D4AFF (hover #7C5CFF; the `primary` colour is #8A6EFF).
  - Danger: #F7607E. Warning: #FFAD33. Success: #4BB99D.
  - Background: #16141C. Weak background: #292733.
  - Text: #FFFFFF. Weak text: white at 70% opacity.
  - Link: #AC99FF.
- **Button styles.**
  - "primary": filled with the accent colour.
  - "danger": red, used for Disconnect, Cancel and Yes-to-destructive.
  - "secondary": neutral/outlined.
- **Notification bar.** A strip that slides in at the top of the main window (and of the Settings window, which has its own). It holds one centred, wrapping label and has three styles: error (red), info, success. It hides itself after **10 s**; the bug-report "sending" message uses 60 s. A new message replaces the old one and restarts the timer.
- **Error dialog.** A modal message box with a bold primary text (the title), a secondary text (the message, which may contain links) and one "OK" button unless other buttons are specified. Only one error dialog exists at a time; a new one replaces the old.
- **Confirmation dialog.** A modal dialog with the window title set to the dialog title, a wrapped message (about 50 characters wide) and two buttons:
  - "_Yes" (danger style)
  - "_No" (primary style)

  Callers can rename the buttons. A variant shows a question line plus a dimmed clarification line (used for setting conflicts).
- **Loading overlay.** Covers the whole main content with the window background colour. Shows a centred wrapping label above a 50 px spinner. Messages used: "Signing in...", "Signing out...", "Loading app...".
- **Desktop notification.** Used only for port forwarding (see 2.4). App name "Proton VPN", proton-vpn-sign icon.

---

## 1. Screens and windows

### 1.1 Main window frame

- Title "Proton VPN". Fixed size **450×700**, not resizable. Single instance (app id `proton.vpn.app.gtk`).
- **Header bar.** A hamburger menu button on the left (the window decoration layout is menu-left; minimize and close on the right). Menu contents are in 2.1.
- **Close (X) button.**
  - If a tray icon is available, X only hides the window.
  - Otherwise X behaves exactly like the menu's Quit, including the confirmation.
- **Command-line options.**
  - `--start-minimized` ("Start minimized in the system tray")
  - `-v/--version` ("Display the application's version"; prints the version and exits)
- **Start minimized.** Applies when the CLI flag is given or the "Start app minimized" setting is on, and **only if a tray exists**. The window is hidden after first presentation.
- **Content area.** Vertical, 20 px padding: notification bar first, then either the Login widget or the VPN widget. The loading overlay sits on top.
- **Background gradient.** Behind the VPN widget there is a 160 px top-down gradient that fades over 2 s:
  - Connected: rgba(30,168,133,0.2) fading to transparent (green).
  - Disconnected: rgba(245,56,90,0.2) (red).
  - Connecting, Disconnecting and Error: rgba(255,255,255,0.1).
  - The gradient is cleared on the login screen.

**Startup sequence:**
1. Create the window.
2. If logged in: show the VPN widget behind the overlay "Loading app...". Start the data refresher, which ensures the session data (server list, client config, certificate, etc.) is loaded. Build the server list. When the list is built: hide the overlay, push the current connection state to all widgets, enable the reconnector, then run the auto-connect action.
3. If not logged in: show the Login widget.
4. If no VPN backend is available, show a blocking error dialog (no title) with this text, where the link points to https://protonvpn.com/support/linux-gui-setup:
   "Some required components were not detected on your system. The app may not work as expected.\n{Learn more} about requirements and alternative installation methods."

### 1.2 Login form (top to bottom, 30 px spacing)

1. Proton VPN wordmark logo, 320 px wide, centred.
2. Text entry, placeholder "Username".
3. Password entry, placeholder "Password". Text is hidden; an eye icon at the right end toggles visibility (icon switches between show and hide).
4. Button "Sign in" (primary, centred). Disabled until both fields are non-empty after trimming. Enter in either field triggers it when enabled.
5. Bottom row, pinned to the bottom of the form:
   - Left link "Create Account" → https://account.protonvpn.com/signup?ref=linux
   - Right link "Need Help?" → https://protonvpn.com/support

**On submit:** show the overlay "Signing in...". Results:
- Invalid username (ValueError from the backend): notification-bar error "Invalid username."
- Credentials rejected (API code 8002, not authenticated): error "Incorrect credentials."
- Authenticated and 2FA required: switch to the 2FA screen.
- Authenticated, no 2FA: go to the VPN widget.
- Other failures are handled by the global exception handler (section 6). For example, an unreachable API shows "Our servers are not reachable. Please check your internet connection." in the bar, and other API errors show the API's own error text.

**Permanent kill switch banner.** When the stored kill switch setting is Advanced/permanent and the user is on the login screen:
- A slide-down row appears at the bottom with the left-aligned wrapping label "Kill switch is blocking any outgoing connections." and a secondary button "Disable".
- The whole login form is insensitive (greyed out) while the banner is shown.
- "Disable" opens a confirmation dialog titled "Kill Switch Enabled" with the message "Permanent Kill Switch is blocking any outgoing connections and preventing your IP to be exposed.\n\nDo you want to disable Kill Switch?"
- Yes: save kill switch Off, hide the banner, re-enable the form.

**Reset on showing the login screen:** clear both fields, hide the notification, focus Username.

### 1.3 Two-factor screen (20 px spacing)

1. Smaller logo, 200 px.
2. Heading "Two-factor authentication".
3. Tab switcher filling the width:
   - If FIDO2 is available: tabs "Security key" (first, selected by default) and "Authenticator app".
   - Otherwise only "Authenticator app".
4. The selected form.

**Authenticator app form:**
- Label "6-digit authentication code".
- Entry with placeholder "123456".
- An empty, dimmed clarification label.
- Buttons, stacked and full width:
  - "Authenticate" (primary). Enabled only when the trimmed text is **exactly 6** characters. Digits are not enforced.
  - Toggle button (secondary) "Use recovery code". In recovery mode:
    - The label becomes "Recovery code".
    - The placeholder becomes "y5d6132f".
    - The clarification becomes "Each code can only be used once".
    - Exactly **8** characters are required.
    - The toggle reads "Use 6-digit authentication code".
    - Toggling focuses the entry.
  - "Cancel" (danger).
- Enter in the entry submits. This upstream code submits even if the length is wrong; you may want to guard it.
- On submit: overlay "Signing in...". Failure: error "Incorrect 2FA code." The field is reset after every attempt.

**Security key form:**
- Wrapping description "Insert the U2F or FIDO key linked to your Proton Account. Learn more". The link goes to https://protonvpn.com/support/#.
- Security-key illustration, 400 px wide.
- At the bottom:
  - Hidden "PIN code" label and password field (slides down when needed).
  - "Authenticate" button.
  - "Cancel" (danger).

Flow:
- Clicking Authenticate starts key discovery. The overlay shows:
  - "Multiple security keys were found. Tap one to select it." when several keys are present.
  - "If your security key has a button or a gold disc, tap it now." when touch is needed.
- If the key needs a PIN: the overlay hides, the PIN field slides in and gets focus, and Authenticate is enabled while the PIN is non-empty. A second click (or Enter in the PIN field) submits it.
- On a successful assertion: overlay "Signing in..." and submit.

Errors (notification bar):
- "Two-factor authentication failed: No security key detected"
- "Two-factor authentication failed: The security key you used is not linked to your Proton Account."
- "Two-factor authentication failed. Security key 2FA is not enabled for your account."
- "Two-factor authentication failed: Your security key has no PIN set"
- "Two-factor authentication failed: Incorrect PIN"
- "An unknown error occurred" (any other key error, or the server rejecting the assertion)

**Cancel on either form:** abort any assertion, show the overlay "Signing out...", call logout, then return to the login form.

### 1.4 Other windows

- **About** (standard about box). Title "About". Program "Proton VPN Linux Client", the app version, © "Proton AG 2026", GPL-3.0, website https://protonvpn.com labelled "Proton VPN", author "Proton AG", 80 px sign logo.
- **Release notes.** Title "Release notes", 450×500, modal, scrollable. Parsed from `release_notes.md`: `## ` lines become bold headings (for example "What's new (4.18.7)", "4.18.6"); `- ` lines become selectable, wrapping bullet lines; a blank line ends an entry. 25 px between entries.
- **Report an Issue.**
  - Title "Report an Issue", 400×300, modal.
  - Its own notification bar at the top.
  - Fields: "Username" entry, "Email" entry, "Description (minimum 50 characters)" multi-line text area (minimum height 100).
  - Checkbox "Send error logs", checked by default.
  - Buttons "_Cancel" (danger) and "_Submit" (primary). Submit is enabled only when the username is non-empty, the email matches `[^@\s]+@[^@\s]{2,}\.[^@\s\.-]{2,}`, and the description is **more than** 50 characters.
  - On submit: info "Reporting your issue..." (60 s); the form is disabled. The report is sent with title "Report from Linux app", client "Linux GUI" and the app version. With logs on, it attaches the app log plus system logs (the NetworkManager journal on Linux; use the Haiku syslog instead).
  - Success: close the dialog; the main window shows a success message "Your issue has been reported".
  - API unreachable: "Proton services could not be reached.\nPlease try again."
  - API error: the server's error text.
  - Other errors: "Something went wrong. Please try submitting your report at:\nhttps://protonvpn.com/support-form"
- **NPS survey modal.** Shown when the main window becomes visible, the user is logged in, and there is an unseen active survey notification (it is marked seen immediately).
  - 450×595.
  - Title "How likely are you to recommend Proton VPN to a friend?"
  - Score buttons 0–10, with captions "0 is very unlikely" and "10 is very likely".
  - "Please let us know why you gave that rating" with "Optional", a text box limited to 250 characters and a counter "n/250".
  - Button "Share anonymously". After submitting: "Thanks for your feedback" / "Your feedback helps us improve Proton VPN."
  - Closing the window sends a "dismiss" response.

---

## 2. Main window (logged in)

### 2.1 Header menu (in this order)

1. "About": opens the About box.
2. "Settings": opens the Settings window. Disabled on the login screen.
3. "Release notes": opens the dialog.
4. "Report an issue": opens the bug report dialog.
5. "Sign out": disabled on the login screen. Flow:
   - Disable the item during the flow.
   - **If a VPN connection is not in the Disconnected state:** confirmation titled "Active connection found":
     - Kill switch Off: "Signing out will cancel the current VPN connection.\n\nDo you want to continue?"
     - Kill switch Standard or Advanced: "Signing out will cancel the current VPN connection and disable the kill switch.\n\nDo you want to continue?"
   - **Else, if the kill switch is Advanced/permanent:** confirmation titled "Kill Switch enabled": "Signing out will disable the kill switch, potentially exposing your internet traffic. \n\nDo you want to continue?"
   - **Else:** sign out immediately.
   - On Yes: overlay "Signing out...". If the kill switch is not Off, save it as Off first. Then log out. The backend stops the refreshers, revokes the session, **deletes the settings file** (so settings return to defaults on the next login) and disconnects the VPN.
   - On success: show the login screen, clear the gradient, and close the Settings window if it is open.
   - If the API is unreachable: error "Unable to sign out, please ensure you have internet access." and re-enable the item.
   - No or closing the dialog: re-enable the item.
6. "Quit":
   - If Disconnected: quit at once.
   - Otherwise confirmation titled "Active connection found":
     - Kill switch not permanent: "Quitting the application will cancel the current VPN connection.\n\nDo you want to continue?"
     - Permanent: "Quitting the application will keep the kill switch active, but your current VPN connection will be terminated.\n\nDo you want to continue?"
   - On Yes: disconnect, wait for the Disconnected state, then close the window and exit.

Keyboard shortcut: **Ctrl+F** focuses the search entry.

### 2.2 VPN widget layout (vertical, 10 px spacing)

1. Connection status block.
2. Quick-connect block.
3. Search entry.
4. Search results panel (slides in under the search entry).
5. Server list (scrolls and takes the rest of the window).

### 2.3 Connection status block (left-padded 8 px)

**Status row** (centred): a 24×24 icon or a spinner, then a title in heading style.

| State | Icon | Title | Colour |
|---|---|---|---|
| Connecting, or Disconnecting as part of a reconnect | spinner | "Connecting..." | default |
| Connected | protected shield | "Protected" | success green |
| Disconnecting (user-initiated) | spinner | "Disconnecting..." | default |
| Error | none | "Connection error" | default |
| Disconnected | unprotected shield | "Unprotected" | danger red |

The Disconnected state reached during a reconnect also shows "Unprotected" briefly. The details lines below are not reset in that case.

**Error detail line** (centred, under the title, Error state only), chosen by the last connection event:
- "Tunnel setup failed"
- "Authentication denied"
- "Timeout"
- "Device disconnected"
- "Session limit reached". This also opens an error dialog titled "Connection error: session limit reached" with the message "You've reached your maximum device limit. To reconnect to VPN, please disconnect from another device."

**Details grid** (left-aligned): an icon column (36×24) and a text column. The text column has a title (heading style), a subtitle, an optional free-countries summary row and an optional port-forward row.

**When Disconnected (and not reconnecting):** the icon is the "fastest" lightning/flag graphic.
- Paid user: title "Fastest country"; subtitle empty.
- Free user, legacy mode (feature flag `FreeRescope` off): title "Fastest free server"; subtitle "Auto-selected from free locations".
- Free user, rescope mode (`FreeRescope` on). The app calls this condition `server_selection_requires_upgrade`, used throughout this spec:
  - Title "Fastest free server".
  - The subtitle is replaced by a summary row: "Auto-selected from", a 56×16 three-flag graphic, "+{count}" (shown only if there are more than 3 free countries; count = total − 3), and a 20 px info button.
  - The info button's tooltip and accessible name are "Free server locations". It opens a popover:
    - Header "Free connections" with a round close button (tooltip "Close").
    - Description "Proton Free automatically connects you to the fastest free server available. This is usually the closest server to your location."
    - "Free server locations ({count})".
    - A grid with **3 per row** of flag (24×16) plus localized country name. The list holds every country that has at least one tier-0 server, sorted by localized name.

**When Connecting, Connected or Error** (the target or current server):
- Icon: country flag (24×16). For Secure Core it is a composite double flag: the exit flag larger at top-right, the entry flag smaller at bottom-left.
- Title: localized exit country name.
- Subtitle: "{location} - {server_name}" (for example "Zurich - CH#12"). For Secure Core: "Via {entry country}" (for example "Via Switzerland").

**Port-forward row** (only when Connected and the backend reports a forwarded port):
- A flat clickable row: small active-port icon, dim "Active port:", the port number, and a copy icon.
- Click copies the number to the clipboard and shows a "Copied!" popover for 1.5 s.
- When the forwarded port changes to a new value while the main window is not focused, show a desktop notification titled "Port forwarding" with body "Active port is {new_port}".

**On entering Connected,** info messages in the bar:
- If split tunneling is on: "Split tunneling enabled. Remember to restart affected apps."
- If the user is free and feature flag `LinuxProtunOnly` is on: "Free-tier launches default to a Proton protocol. Any WireGuard or OpenVPN selection lasts only until the next application restart."

### 2.4 Quick connect block

The main full-width action button changes with the state:

| State | Label | Style | Action |
|---|---|---|---|
| Disconnected (not reconnecting) | "Connect" | primary | connect to the fastest server |
| Connecting | "Cancel Connection" | danger | disconnect |
| Connected | "Disconnect" | danger | disconnect |
| Error | "Cancel Connection" | danger | disconnect |
| Disconnecting | unchanged | | |

"Fastest server" means: enabled servers whose tier is at most the user's tier, excluding Secure Core and Tor, choosing the lowest `score`.

**"Change server" (only in rescope free mode).** A secondary button below the action button.
- It slides in when Connected.
- It is enabled when Connected and no cooldown is running. It is also enabled (and revealed) if a connection attempt is still Connecting after **8 s**; this unlock bypasses the cooldown and does not count against the limit.
- Click: connect to a random server. If the last connection was made at country level, the pick comes from that country; otherwise from any country. The pick excludes Secure Core, Tor and the current server (unless it is the only one).
- When a change-server connection completes, a cooldown starts. Each change starts a short cooldown (ChangeServerShortDelayInSeconds, default 90 s). The Nth change, where N is ChangeServerAttemptLimit (default 4), starts the long one instead (ChangeServerLongDelayInSeconds, default 1200 s) and resets the counter. All three values come from the client config.
- While the cooldown runs:
  - The button shows a countdown "MM:SS", rounded up, next to its label.
  - A card under the button shows "Get unlimited server changes with VPN Plus." (dim).
  - During the long cooldown only, the card also shows the heading "You've reached the maximum number of free server changes for now".
- Accessibility announcement only: "Change server is now available".
- Change-server state is hidden on Disconnected and Error, and when a reconnect is started by anything other than this button. It is not touched during automatic reconnector retries.

### 2.5 Search

- Search entry with placeholder "Press Ctrl+F to search".
- While the text is non-empty, a 200 px results panel slides open below it. The panel is a two-column list (name and grey load) with up to three section headers:
  - "Countries ({n})". Matching servers not under maintenance, by **localized entry-country** name. Note this means Secure Core entry countries match too.
  - "Locations ({n})". Matching location (city/state) names, sorted alphabetically.
  - "Servers ({n})". The section header shows "Server load" in the load column. Includes server names the user's tier allows and not under maintenance, sorted by country name then natural server number; each row shows "{load}%". **This section is omitted in rescope free mode.**
- Matching is substring, case-insensitive and accent-insensitive ("zur" matches "Zürich").
- At most 100 rows per section, followed by a "..." row.
- A single click on a row:
  - Name contains "#": connect directly to that server and refocus the search entry.
  - Country: scroll to and focus that country row.
  - Location: expand its country and focus the location row.
- After any click, the search text is cleared and the panel closes.

### 2.6 Server list

**Header row:**
- Dim "All countries ({count})" on the left.
- An info icon on the right opening a "Features" legend popover with a close button (tooltip "Close"). Each legend entry has an icon, a bold heading, a dim description and a "Learn more" link:
  - "Smart routing": "This technology allows Proton VPN to provide higher speed and security in difficult-to-reach countries." → https://protonvpn.com/support/how-smart-routing-works
  - "Secure Core": "Connect to your destination server through a second, maximum security VPN server. Slower, but more private." → https://protonvpn.com/support/secure-core-vpn
  - "P2P/BitTorrent": "These servers give the best performance for BitTorrent and file sharing." → https://protonvpn.com/features/p2p-support
  - "Tor": "Connect to a Tor server to access hidden services and onion sites using any browser." → https://protonvpn.com/support/tor-vpn

**Grouping and sorting:**
- Servers are grouped by exit country.
- Countries are sorted by localized name. For **free** users, countries with any free (tier-0) server come first, then the rest; each group is sorted by name.
- Inside a country, rows are grouped by **location** (the city/state name the API provides). Secure Core servers are not part of locations.
- Free (tier-0) servers are **excluded from location rows for paid users**. They still count towards the country's "free" flag.

**Row anatomy.** This applies to every row type: country, location, Secure Core group and server.

- Resting state, left to right:
  1. Icon: flag for a country, pin icon for a location, Secure Core icon for the group, double flag for a Secure Core server, empty 24 px space for a normal server.
  2. Name.
  3. Feature icons, right-aligned. Visual order left to right: Tor, P2P, Smart routing, Secure Core. Each is shown if any server in the group has it; Smart routing only if *all* servers use it.
  4. Load (server rows only).
  5. Expand/collapse chevron (down arrow when collapsed, up when expanded). On server rows the chevron is invisible but still takes up space.
- Feature icon tooltips: "Tor supported", "P2P/BitTorrent supported", "Smart routing is used", "Secure Core supported". A Secure Core server icon's tooltip reads "Secure Core server that connects to {exit_country} through {entry_country}." instead.
- Load: a 36 px level bar plus "NN%". Colour: red if >90, orange if >75, otherwise green. Tooltip "Server load is at {load}%".
- On mouse hover or keyboard focus, the resting content crossfades (70 ms) into one full-width flat button: icon + name on the left, action text on the right. The action is "Connect", or "Upgrade" when the user's plan doesn't include that row.
  - "Upgrade" rows are drawn dimmed. Clicking opens https://account.protonvpn.com/ in the browser.
  - Tooltips on the action button:
    - Country: "Connect to {country_name}" / "Upgrade to connect to {country_name}".
    - Location and server: "Connect to {name}" / "Upgrade to connect to {name}".
    - Secure Core group: "Connect to {country} via Secure Core" / "Upgrade to connect to {country} via Secure Core".
    - Secure Core server: "Connect to {exit_country} via {entry_country}" / "Upgrade to connect to {exit_country} via {entry_country}".
  - Chevron tooltips:
    - Country: "Show all locations from {country_name}" / "Hide all locations from {country_name}".
    - Location: "Show all servers from {name}" / "Hide all servers from {name}".
    - Secure Core group: "Show all Secure Core servers\nto connect to {country}" / "Hide all Secure Core servers\nto connect to {country}".
- **Maintenance.** A group is under maintenance when *all* its servers are disabled.
  - The row is dimmed and shows a maintenance (wrench) icon at the right with tooltip "{name} is under maintenance".
  - It has no hover/connect button and load is hidden.
  - The chevron still works.
  - When "Upgrade" applies, it takes priority over maintenance.

**What each row's Connect does:**
- Country row: fastest server in that country (tier-allowed, enabled, excluding Secure Core and Tor).
- Location row: fastest tier-allowed, enabled server in that location.
- "Via Secure Core" row: fastest tier-allowed, enabled Secure Core server for that exit country.
- Server row: that exact server.

**Expanded country contents:**
1. Location rows, sorted by name. For a free user in a free country: free locations first, then paid, each sorted.
2. If the country has Secure Core servers, one extra expandable row "Via Secure Core" (Secure Core icon, 24 px). Its children are rows named "Via {entry country}" with a double flag and load.

Expanding a location shows its servers in order:
- Free user in a free location: free servers first, then paid.
- Otherwise: paid servers first, then free.
- Within each group: enabled before disabled, then by load ascending.

Expansion state (countries, locations and the Secure Core group) is preserved across list refreshes.

**Tier rules ("Upgrade" vs "Connect"):**
- Paid users: always Connect.
- Free users, legacy mode: Upgrade on any row that has no free server; free countries, locations and servers are connectable.
- Free users, rescope mode: **only country rows** can be connected, and only free countries. Every location, Secure Core group and server row shows Upgrade, even free ones.

**Clicking Connect while already connected or connecting:** there is no confirmation. The state machine moves to Disconnecting (as a reconnect), then Disconnected (reconnect), then Connecting, then Connected. The status block shows "Connecting..." throughout.

---

## 3. Settings window

- Title "Settings", 600×500, modal over the main window. Scrollable (minimum 400×300).
- Notification bar at the top.
- Four sections, each with a bold heading, in this order: **Account, Features, Connection, General**.
- Every setting row has the name on the left, the control right-aligned, and a dim wrapping description below.
- **Paid-only rows** (when the user's tier is below 1) replace the control with a "VPN Plus" pill button that opens https://protonvpn.com/pricing.
- Any change is saved immediately. Settings changed elsewhere (for example a conflict resolution) update the open window live.
- **Reconnect message** (info, Settings bar): "Please establish a new VPN connection for changes to take effect." It appears when:
  - IPv6 is toggled (always).
  - A custom DNS change is made while connected.
  - Custom DNS is enabled over NetShield while connected with a protocol that can't apply changes live. WireGuard and Proton protocols apply live; OpenVPN does not.

### 3.1 Account

- Bold title: the account username.
- Description: "VPN plan: {plan}". The plan title comes from the API, or "Free".
- Button "Manage Account" → https://account.protonvpn.com/account
- Refresh icon button, tooltip "Refresh account details". Re-fetches VPN info (one request at a time).
  - Success: info "Account info refreshed, restart the app to see changes", and the plan line updates.
  - Failure: error "Account info refresh failed, check your connection and try again".

### 3.2 Features

**NetShield** (combobox, paid only):
- Options: "Off" (0), "Block Malware" (1), "Block ads, trackers and malware" (2).
- Default: Off for free users, Block Malware for paid users.
- Description: "Protect yourself from ads, malware, and trackers on websites and apps."
- If custom DNS is on and NetShield is set to anything but Off, a dialog appears:
  - Title "Enable Netshield".
  - Content "Enable Netshield ?" / "This will disable custom DNS." / "Learn more" → https://protonvpn.com/support/custom-dns#netshield
  - Buttons "_Enable" / "_Cancel".
  - Enable turns custom DNS off. Cancel sets NetShield back to Off.

**Kill switch** (switch, all tiers, default Off):
- Description: "Protects your IP address by disconnecting you from the internet if you lose your VPN connection. Learn more \n\nKill switch can only be changed when VPN is disconnected." The link goes to https://protonvpn.com/support/what-is-kill-switch/
- The row is insensitive unless Disconnected.
- When the switch is on, two radio options slide in. Turning the switch on selects Standard.
  - "Standard" (value 1): "Automatically disconnect from the internet if VPN connection is lost."
  - "Advanced" (value 2, permanent): "Only allow internet access when connected to Proton VPN. Advanced kill switch will remain active even when you restart your device."
- Conflict: if split tunneling is on, a dialog asks "Enable kill switch?" with "•  This will disable split tunneling." and buttons "_Yes" / "_Cancel". Cancel turns the switch back off.

**Port forwarding** (switch, paid only, default Off):
- Description: "Bypass firewalls to connect to P2P servers and devices on your local network. Learn more" → https://protonvpn.com/support/port-forwarding/#linux

**Split tunneling** (shown only if the backend supports it; probably not applicable on Haiku; switch, paid only):
- Description: "Customize your connection by deciding which apps are protected by VPN."
- Insensitive while connected, with tooltip "To change split tunneling settings, please disconnect the VPN first."
- Enabling may need confirmation, title "Enable split tunneling?", with the applicable bullets:
  - "•  This will automatically set your protocol to WireGuard." (if the current protocol is not WireGuard or a Proton protocol)
  - "•  This will disable kill switch." (if the kill switch is on)
- When on, a panel slides in:
  - Radio "Exclude mode" (default): "Allow selected apps to connect without VPN protection."
  - Radio "Include mode": "Only selected apps connect with VPN protection. All other traffic is unprotected."
  - "Excluded apps (N)" or "Included apps (N)".
  - A list of chosen apps with remove buttons; up to 6 rows visible before scrolling.
  - An "Add" button opens "Add excluded apps" / "Add included apps" (600×500): installed apps with checkboxes and a "Done" button.
  - Each mode keeps its own app list.

### 3.3 Connection

**Protocol** (combobox, all tiers):
- Description: "Protocol can only be changed when VPN is disconnected." The row is insensitive while not disconnected.
- Standard list, in priority order: "WireGuard" (`wireguard`, the default), "OpenVPN (UDP)", "OpenVPN (TCP)".
- If feature flag `ProTunV1` is on, a checkbox "Use Proton protocols" with a purple-bordered "BETA" tag appears under the row. Checked, the list becomes "Smart", "Wireguard UDP", "Wireguard TCP", "Stealth" (`protun-smart`, `protun-udp`, `protun-tcp`, `protun-tls`) and the first option is selected.
- Conflict: choosing OpenVPN while split tunneling is on asks "Disable WireGuard?" with "•  This will disable split tunneling.". Cancel reverts the choice to WireGuard.

**VPN Accelerator** (switch, paid only, default On):
- "Increase your connection speed by up to 400% with performance enhancing technologies."

**Moderate NAT** (switch, paid only, default Off):
- "Disables randomization of the local addresses mapping. This can slightly reduce connection security, but should allow direct connections for online gaming and similar purposes."

**IPv6** (switch, all tiers, default On):
- "Tunnels IPv6 traffic through the VPN. Can enhance compatibility with IPv6 networks."
- Always shows the reconnect message after a change.

**Custom DNS servers** (switch, paid only, default Off):
- "Connect to Proton VPN using your own domain name servers (DNS)."
- When on, a panel slides in:
  - Label "Add new server".
  - An entry plus an "Add" button. Input is validated as IPv4 or IPv6; invalid input shows the red error "Enter a valid IPv4 or IPv6 address".
  - A list of IPs, each with a trash button.
- Enabling while NetShield is not Off asks:
  - Title "Enable Custom DNS".
  - Content "Enable Custom DNS?" / "This will disable NetShield." / "Learn more" → https://protonvpn.com/support/custom-dns#netshield
  - Buttons "_Enable" / "_Cancel".
  - Enable sets NetShield Off and may show the reconnect message. Cancel turns custom DNS back off.

### 3.4 General

**Auto connect** (free-text entry, not a dropdown):
- Description: "You will be connected to a server as soon as Proton VPN app starts. Replace it with a country ISO code (e.g.: US for United States), a server (e.g.: NL#42) or Fastest for quick connection. Default value: Off."
- Shows "Off" when unset. Saved on every keystroke, trimmed and upper-cased; "OFF" means unset.
- Shows the "VPN Plus" pill in rescope free mode, and is ignored in that mode.

**Start app minimized** (switch, only if a tray exists, default Off):
- "When enabled, the app starts minimized to the tray."

**Pinned tray connections** (entry, only if a tray exists):
- "Access preferred connections from system tray. Enter country or server codes, separated by commas, to quickly connect (e.g.: NL#42, JP, US, IT#01)."
- Saved as an upper-case list; the tray menu reloads.
- Shows the "VPN Plus" pill in rescope free mode.

**Share anonymous usage statistics** (switch, only if feature flag `LinuxTelemetry` is on, default On):
- "Usage data helps us overcome VPN blocks and improve app performance.\n\nThese statistics do not contain your IP address, and they cannot be used to identify you. We'll never share them with third parties."

**Share anonymous crash reports** (switch, default On):
- "Crash reports help us fix bugs, detect firewalls, and avoid VPN blocks.\n\nThese statistics do not contain your IP address, and they cannot be used to identify you. We'll never share them with third parties."

**Create a troubleshooting file** (only for protocols that support packet capture):
- Description "Captures a specific issue you're facing when using Proton VPN to get help from our customer support team.\n\nWarning: This file is a recording of all your internet activity during the capture session."
- A "Start"/"Stop" button (Stop is red), enabled only while Connected.
- A directory entry plus "Browse..." (dialog "Select packet capture directory", accept button "_Select").

**Beta access** (Linux package-manager specific; skip on Haiku):
- "Get early access and help us test new versions of Proton VPN."

---

## 4. Tray icon

- Title "Proton VPN". Icons and accessible descriptions:
  - state-disconnected, "VPN disconnected"
  - state-connected, "VPN connected"
  - state-error, "VPN error"
- No action on left-click; menu only.

**Menu, rebuilt on every state change:**
1. Connection entries:
   - "Connect" (connects to the fastest server). Shown when logged in and Disconnected or Error. Shown but **disabled** while Connecting.
   - "Disconnect". Shown when Connected. Disabled while Disconnecting.
   - Neither entry is shown when logged out.
2. Separator, if any of the above were shown.
3. If logged in and pins exist: one entry per pinned code (label = the upper-case code). A code containing "#" connects to that server; otherwise it connects to the fastest server in that country. Then a separator.
4. "Show" or "Hide", toggling main window visibility.
5. Separator.
6. "Quit": the same flow as the menu Quit, with confirmation.

---

## 5. Background behaviour

**Refresh schedule.** The refresher starts when the VPN widget loads and stops on logout or unload. Every interval below has ±22% random jitter unless noted.

- **Server list:** the full list every **3 h**; loads every **15 min**. The next run happens at whichever expires first. On a 429 response or an unreachable API, retry after one loads interval.
- Each update triggers a UI refresh:
  - Full list update: rebuild the country rows, keeping expansion state.
  - Loads update: the same re-display.
  - Updated location names (refreshed **weekly**): the same re-display.
- **Client config:** every **3 h**, or at the API-provided expiry. Holds ports and change-server limits; no UI refresh.
- **Feature flags:** every **2 h**. Read when widgets are built; no live UI refresh.
- **Pull notifications** (NPS): every **24 h**.
- **Session location** data expires after **15 min** and is updated on refresher start. It is not displayed.
- **Certificate:** requested with a 7-day duration and refreshed at the API's RefreshTime. On failure, back off exponentially (1 s × 2^n with jitter), capped at 7 days. After a refresh, a Connected or Error connection gets its credentials updated in place.
- **Telemetry** publishes every 15 min.

**Reconnector** (enabled after the VPN widget is ready, disabled on logout):
- **VPN drop** (state becomes Error), by event:
  - ExpiredCertificate: force a certificate refresh. No UI message.
  - MaximumSessionsReached: nothing; the status block shows its dialog.
  - TwoFARequired: dialog "2FA Required" (text in section 6).
  - NotYetValidCertificate: dialog "Update system clock".
  - AuthDenied (fatal): reset, then dialog "VPN connection error".
  - Anything else: schedule a reconnect.
- **Backoff:** 2^retry × U(0.9, 1.1) seconds (1, 2, 4, 8 s and so on, with no cap).
- **Each attempt:**
  - If the network is down or the user session is locked: increment the counter and reschedule.
  - Otherwise reconnect to the **same server id** with the same protocol. If that server is gone from the list, give up quietly.
- **Network monitor:** polls every **5 s** (Linux uses `ip route get 192.0.2.1`; on Haiku, check for a default route). When the network comes back up: reset the counter, and if the VPN is in a recoverable Error, schedule a reconnect.
- **Session unlock** (logind "Unlock" signal; this is the wake-from-lock trigger): same as the network coming up. There is no separate suspend/resume handling.
- Counter resets on Connected and on a user-initiated Disconnected.

**Auto connect at startup:** runs once after the VPN widget is ready, if logged in and the value is set. The value is "FASTEST", a server name containing "#", or a country code; anything else is treated as a country code. There is no "last server" option.

**Session expiry** (API reports authentication is needed, at any time):
- Error dialog titled "Invalid Session": "Your session has expired. Please sign in again."
- Switch to the login screen and close Settings.

**Missing VPN permission** (account has no VPN connections assigned):
- Sign out, then show an info dialog using the API's Title, Body and Hint.
- Buttons: an API-provided action button (opens https://protonvpn.com/support/assign-vpn-connection) and "Sign in again".

---

## 6. Error and notification texts

**Notification bar:**
- Login and 2FA: "Invalid username.", "Incorrect credentials.", "Incorrect 2FA code.", plus the security-key errors in 1.3.
- API unreachable: "Our servers are not reachable. Please check your internet connection."
- Other API error with a message: the server's message verbatim. This covers wrong credentials beyond 8002, human-verification required and similar cases.
- Logout failure: "Unable to sign out, please ensure you have internet access."

**Dialogs** (title / message):
- "Something went wrong" / "We're sorry, an unexpected error occurred. Please try again." (any unhandled error, which is also sent to crash reporting)
- "Unable to find server" / the backend text, for example "No server available in the current tier" or "The server with name='XX#1' was not found". Triggered by a bad auto-connect or pin code, or by no server being available for the tier.
- "VPN connection error" / "Proton VPN could not connect to the VPN and blocked access to Internet to protect your IP.\n\nClick \"Cancel Connection\" to restore your Internet connection. If the issue persists please try to sign out and in."
- "2FA Required" / "You are connected to the VPN, but all traffic is blocked.\nYou need to go to the authentication page provided by security and authenticate with your hardware key.\nAfter that, the traffic will be enabled."
- "Update system clock" / "Looks like your system clock is out of sync.\nThis may cause issues when connecting to VPN.\nUpdate your system time and try to connect again."
- "No space left on device" / "There is not enough space left on your device."
- "Connection error: session limit reached" / "You've reached your maximum device limit. To reconnect to VPN, please disconnect from another device."
- "Invalid Session" / "Your session has expired. Please sign in again."

**In the status block** (Error state detail): "Tunnel setup failed", "Authentication denied", "Timeout", "Device disconnected", "Session limit reached".

The server-under-maintenance state is only a dimmed row with tooltip "{name} is under maintenance". Such rows can't be connected, and they're excluded from search.

---

## Key source files

Base path: `/mnt/HaikuWork/apps/proton-vpn-airos-app/.upstream/proton-vpn-gtk-app/proton/vpn/app/gtk/`

- `app.py`, `controller.py`, `conflicts.py`, `config.py`, `utils/exception_handler.py`, `utils/change_server_cooldown.py`
- `widgets/login/` (`login_form.py`, `disable_killswitch.py`, `two_factor_auth/*.py`)
- `widgets/main/` (`main_window.py`, `main_widget.py`, `notification_bar.py`, `notifications.py`, `confirmation_dialog.py`, `loading_widget.py`, `tray_indicator.py`, `tray_icon.py`)
- `widgets/headerbar/menu/` (`menu.py`, `about_dialog.py`, `bug_report_dialog.py`, `release_notes_dialog.py`, `settings/*.py`)
- `widgets/vpn/` (`connection_status_widget.py`, `quick_connect_widget.py`, `free_countries_summary.py`, `port_forward_widget.py`, `search_entry.py`, `search_results.py`, `serverlist/icons.py`, `serverlist/city_view/*.py`)
- `services/reconnector/*.py`
- `assets/style/_dark_palette.css`, `assets/style/main_widget.css`, `assets/release_notes.md`

Backend: `/mnt/HaikuWork/apps/proton-vpn-airos-app/.upstream/python-proton-vpn-api-core/proton/vpn/`

- `session/servers/logicals.py` (refresh intervals, fastest-server selection, grouping)
- `session/dataclasses/servers/country.py` (free and maintenance rules)
- `core/settings/settings.py` and `core/settings/features.py` (defaults)
- `session/client_config.py` (change-server defaults)
- `core/refresher/*.py`
- `connection/states.py` and `connection/events.py`
- `backend/networkmanager/protocol/*` (protocol names and priorities)
