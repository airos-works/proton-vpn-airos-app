#include "Settings.h"
#include "Util.h"
#include <arpa/inet.h>

namespace pvpn {

const char* const kProtocolWireGuard = "wireguard";
const char* const kProtocolOpenVpnUdp = "openvpn-udp";
const char* const kProtocolOpenVpnTcp = "openvpn-tcp";


Features Features::Default(int userTier)
{
    Features features;
    features.netshield = userTier < 1 ? kNetShieldOff : kNetShieldMalware;
    return features;
}


bool Features::operator==(const Features& other) const
{
    return netshield == other.netshield && moderateNat == other.moderateNat
        && vpnAccelerator == other.vpnAccelerator && portForwarding == other.portForwarding;
}


Settings Settings::Default(int userTier)
{
    Settings settings;
    settings.features = Features::Default(userTier);
    return settings;
}


Settings Settings::FromJson(const Json& json, int userTier)
{
    Settings settings = Default(userTier);
    if (!json.is_object())
        return settings;
    std::string protocol = JsonString(json, "protocol", settings.protocol);
    if (protocol == kProtocolWireGuard || protocol == kProtocolOpenVpnUdp
        || protocol == kProtocolOpenVpnTcp)
        settings.protocol = protocol;
    settings.killSwitch = (int)JsonInt(json, "killswitch", settings.killSwitch);
    if (settings.killSwitch < kKillSwitchOff || settings.killSwitch > kKillSwitchAdvanced)
        settings.killSwitch = kKillSwitchOff;
    const Json& dns = JsonObject(json, "custom_dns");
    settings.customDnsEnabled = JsonBool(dns, "enabled", false);
    for (const Json& entry : JsonArray(dns, "ip_list")) {
        std::string ip = entry.is_string() ? entry.get<std::string>() : JsonString(entry, "ip");
        if (IsValidIpAddress(ip))
            settings.customDns.push_back(ip);
    }
    settings.ipv6 = JsonBool(json, "ipv6", settings.ipv6);
    settings.anonymousCrashReports = JsonBool(json, "anonymous_crash_reports",
        settings.anonymousCrashReports);
    const Json& features = JsonObject(json, "features");
    settings.features.netshield = (int)JsonInt(features, "netshield", settings.features.netshield);
    settings.features.moderateNat = JsonBool(features, "moderate_nat", settings.features.moderateNat);
    settings.features.vpnAccelerator = JsonBool(features, "vpn_accelerator",
        settings.features.vpnAccelerator);
    settings.features.portForwarding = JsonBool(features, "port_forwarding",
        settings.features.portForwarding);
    return settings;
}


Json Settings::ToJson() const
{
    Json dns = Json::array();
    for (const std::string& ip : customDns)
        dns.push_back({{"ip", ip}, {"enabled", true}});
    return Json{{"protocol", protocol}, {"killswitch", killSwitch},
        {"custom_dns", {{"enabled", customDnsEnabled}, {"ip_list", dns}}}, {"ipv6", ipv6},
        {"anonymous_crash_reports", anonymousCrashReports},
        {"features", {{"netshield", features.netshield}, {"moderate_nat", features.moderateNat},
            {"vpn_accelerator", features.vpnAccelerator},
            {"port_forwarding", features.portForwarding}}}};
}


AppConfig AppConfig::FromJson(const Json& json)
{
    AppConfig config;
    config.connectAtStartup = ToUpper(Trim(JsonString(json, "connect_at_app_startup")));
    if (config.connectAtStartup == "OFF")
        config.connectAtStartup.clear();
    config.startMinimized = JsonBool(json, "start_app_minimized");
    for (const Json& pin : JsonArray(json, "tray_pinned_servers")) {
        if (pin.is_string() && !Trim(pin.get<std::string>()).empty())
            config.trayPinnedServers.push_back(ToUpper(Trim(pin.get<std::string>())));
    }
    return config;
}


Json AppConfig::ToJson() const
{
    return Json{{"connect_at_app_startup", connectAtStartup.empty() ? Json() : Json(connectAtStartup)},
        {"start_app_minimized", startMinimized}, {"tray_pinned_servers", trayPinnedServers}};
}


bool IsValidIpAddress(const std::string& text)
{
    unsigned char buffer[16];
    return inet_pton(AF_INET, text.c_str(), buffer) == 1
        || inet_pton(AF_INET6, text.c_str(), buffer) == 1;
}


const char* ProtocolTitle(const std::string& protocol)
{
    if (protocol == kProtocolOpenVpnUdp)
        return "OpenVPN (UDP)";
    if (protocol == kProtocolOpenVpnTcp)
        return "OpenVPN (TCP)";
    return "WireGuard";
}

}  // namespace pvpn
