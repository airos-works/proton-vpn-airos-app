#include "Account.h"
#include "Util.h"
#include <cstdlib>

namespace pvpn {

namespace {

std::vector<int> IntList(const Json& json, const char* key)
{
    std::vector<int> out;
    for (const Json& item : JsonArray(json, key)) {
        if (item.is_number_integer())
            out.push_back(item.get<int>());
    }
    return out;
}

PortList Ports(const Json& json)
{
    PortList ports;
    ports.udp = IntList(json, "UDP");
    ports.tcp = IntList(json, "TCP");
    ports.tls = IntList(json, "TLS");
    return ports;
}

Json PortsJson(const PortList& ports)
{
    return Json{{"UDP", ports.udp}, {"TCP", ports.tcp}, {"TLS", ports.tls}};
}

}  // namespace


bool VpnInfo::FromJson(const Json& reply, VpnInfo& info)
{
    const Json& vpn = JsonObject(reply, "VPN");
    if (vpn.empty())
        return false;
    info.name = JsonString(vpn, "Name");
    info.password = JsonString(vpn, "Password");
    info.planName = JsonString(vpn, "PlanName");
    info.planTitle = JsonString(vpn, "PlanTitle");
    info.maxTier = (int)JsonInt(vpn, "MaxTier");
    info.maxConnect = (int)JsonInt(vpn, "MaxConnect");
    info.status = (int)JsonInt(vpn, "Status");
    info.delinquent = (int)JsonInt(reply, "Delinquent");
    info.groups.clear();
    for (const Json& group : JsonArray(vpn, "Groups")) {
        if (group.is_string())
            info.groups.push_back(group.get<std::string>());
    }
    info.raw = reply;
    info.raw.erase("Code");
    return true;
}


bool VpnCertificate::FromJson(const Json& reply, VpnCertificate& certificate)
{
    certificate.certificate = JsonString(reply, "Certificate");
    if (certificate.certificate.empty())
        return false;
    certificate.serialNumber = JsonString(reply, "SerialNumber");
    certificate.clientKeyFingerprint = JsonString(reply, "ClientKeyFingerprint");
    certificate.clientKey = JsonString(reply, "ClientKey");
    certificate.expirationTime = JsonInt(reply, "ExpirationTime");
    certificate.refreshTime = JsonInt(reply, "RefreshTime");
    certificate.raw = reply;
    certificate.raw.erase("Code");
    return true;
}


bool VpnLocation::Expired() const
{
    return Now() > expirationTime;
}


Json VpnLocation::ToJson() const
{
    Json json = {{"IP", ip}, {"Country", country}, {"ISP", isp}, {"ExpirationTime", expirationTime}};
    if (hasCoordinates) {
        json["Lat"] = latitude;
        json["Long"] = longitude;
    }
    return json;
}


VpnLocation VpnLocation::FromJson(const Json& json)
{
    VpnLocation location;
    location.ip = JsonString(json, "IP");
    location.country = JsonString(json, "Country");
    location.isp = JsonString(json, "ISP");
    location.hasCoordinates = JsonMember(json, "Lat") != nullptr && JsonMember(json, "Long") != nullptr;
    location.latitude = JsonDouble(json, "Lat");
    location.longitude = JsonDouble(json, "Long");
    location.expirationTime = JsonDouble(json, "ExpirationTime", Now() + kRefreshSeconds);
    return location;
}


ClientConfig ClientConfig::Default()
{
    // DEFAULT_CLIENT_CONFIG in proton/vpn/session/client_config.py.
    ClientConfig config;
    config.openvpn.udp = {80, 51820, 4569, 1194, 5060};
    config.openvpn.tcp = {443, 7770, 8443};
    config.wireguard.udp = {443, 88, 1224, 51820, 500, 4500};
    config.wireguard.tcp = {443};
    config.holesIps = {"62.112.9.168", "104.245.144.186"};
    config.expirationTime = 0;
    return config;
}


bool ClientConfig::FromJson(const Json& json, ClientConfig& config)
{
    const Json& ports = JsonObject(json, "DefaultPorts");
    if (ports.empty())
        return false;
    config.openvpn = Ports(JsonObject(ports, "OpenVPN"));
    config.wireguard = Ports(JsonObject(ports, "WireGuard"));
    config.holesIps.clear();
    for (const Json& ip : JsonArray(json, "HolesIPs")) {
        if (ip.is_string())
            config.holesIps.push_back(ip.get<std::string>());
    }
    config.serverRefreshInterval = (int)JsonInt(json, "ServerRefreshInterval", 10);
    config.changeServerAttemptLimit = (int)JsonInt(json, "ChangeServerAttemptLimit", 4);
    config.changeServerShortDelay = (int)JsonInt(json, "ChangeServerShortDelayInSeconds", 90);
    config.changeServerLongDelay = (int)JsonInt(json, "ChangeServerLongDelayInSeconds", 1200);
    config.expirationTime = JsonDouble(json, "ExpirationTime",
        Now() + kRefreshSeconds * Jitter(0.22));
    return true;
}


Json ClientConfig::ToJson() const
{
    return Json{{"DefaultPorts", {{"OpenVPN", PortsJson(openvpn)}, {"WireGuard", PortsJson(wireguard)}}},
        {"HolesIPs", holesIps}, {"ServerRefreshInterval", serverRefreshInterval},
        {"ChangeServerAttemptLimit", changeServerAttemptLimit},
        {"ChangeServerShortDelayInSeconds", changeServerShortDelay},
        {"ChangeServerLongDelayInSeconds", changeServerLongDelay},
        {"ExpirationTime", expirationTime}};
}


bool ClientConfig::Expired() const
{
    return Now() > expirationTime;
}


FeatureFlags::FeatureFlags(const Json& reply)
    :
    fData(reply.is_object() ? reply : Json::object())
{
    fExpiration = JsonDouble(fData, "ExpirationTime", Now() + kRefreshSeconds * Jitter(0.22));
    fData["ExpirationTime"] = fExpiration;
    fData.erase("Code");
}


bool FeatureFlags::Get(const std::string& name) const
{
    if (getenv(("PROTON_VPN_FEATURE_FLAG_" + name).c_str()) != NULL)
        return true;
    for (const Json& toggle : JsonArray(fData, "toggles")) {
        if (JsonString(toggle, "name") == name)
            return JsonBool(toggle, "enabled");
    }
    return false;
}


Json VpnAccount::ToJson() const
{
    return Json{{"vpninfo", info.raw}, {"certificate", certificate.raw},
        {"secrets", {{"ed25519_privatekey", key.SeedBase64()}}}, {"location", location.ToJson()}};
}


bool VpnAccount::FromJson(const Json& json, VpnAccount& account)
{
    if (!VpnInfo::FromJson(JsonObject(json, "vpninfo"), account.info))
        return false;
    if (!VpnCertificate::FromJson(JsonObject(json, "certificate"), account.certificate))
        return false;
    if (!Ed25519Key::FromSeed(Base64Decode(JsonString(JsonObject(json, "secrets"),
            "ed25519_privatekey")), account.key))
        return false;
    account.location = VpnLocation::FromJson(JsonObject(json, "location"));
    return true;
}

}  // namespace pvpn
