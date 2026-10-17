// User settings: the VPN settings of python-proton-vpn-api-core
// (core/settings/settings.py, deleted when signing out) and the GTK app's own
// configuration (auto connect, tray pins, start minimized).
#pragma once
#include "Json.h"
#include <string>
#include <vector>

namespace pvpn {

extern const char* const kProtocolWireGuard;     // "wireguard"
extern const char* const kProtocolOpenVpnUdp;    // "openvpn-udp"
extern const char* const kProtocolOpenVpnTcp;    // "openvpn-tcp"

enum KillSwitchSetting {
    kKillSwitchOff = 0,
    kKillSwitchStandard = 1,
    kKillSwitchAdvanced = 2,    // permanent
};

enum NetShieldLevel {
    kNetShieldOff = 0,
    kNetShieldMalware = 1,
    kNetShieldAdsTrackersMalware = 2,
};

struct Features {
    int netshield = kNetShieldOff;
    bool moderateNat = false;
    bool vpnAccelerator = true;
    bool portForwarding = false;

    static Features Default(int userTier);
    bool operator==(const Features& other) const;
};

struct Settings {
    std::string protocol = kProtocolWireGuard;
    int killSwitch = kKillSwitchOff;
    bool customDnsEnabled = false;
    std::vector<std::string> customDns;
    bool ipv6 = true;
    bool anonymousCrashReports = true;
    Features features;

    static Settings Default(int userTier);
    static Settings FromJson(const Json& json, int userTier);
    Json ToJson() const;
};

struct AppConfig {
    // "" (off), "FASTEST", a server name ("NL#42") or a country code ("US").
    std::string connectAtStartup;
    bool startMinimized = false;
    std::vector<std::string> trayPinnedServers;

    static AppConfig FromJson(const Json& json);
    Json ToJson() const;
};

bool IsValidIpAddress(const std::string& text);
const char* ProtocolTitle(const std::string& protocol);

}  // namespace pvpn
