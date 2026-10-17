// The VPN account data the API provides after sign-in: plan and limits
// (/vpn/v2), the client certificate (/vpn/v1/certificate), the user's
// location (/vpn/v1/location), connection ports (/vpn/v2/clientconfig) and
// feature flags (/feature/v2/frontend).
#pragma once
#include "Crypto.h"
#include "Json.h"
#include <string>
#include <vector>

namespace pvpn {

struct VpnInfo {
    std::string name;           // OpenVPN user name (unused with certificates)
    std::string password;
    std::string planName;
    std::string planTitle;
    int maxTier = 0;
    int maxConnect = 0;
    int status = 0;
    int delinquent = 0;
    std::vector<std::string> groups;
    Json raw;

    bool Delinquent() const { return delinquent > 2; }
    static bool FromJson(const Json& reply, VpnInfo& info);
};

struct VpnCertificate {
    std::string serialNumber;
    std::string clientKeyFingerprint;
    std::string clientKey;
    std::string certificate;    // PEM
    int64_t expirationTime = 0;
    int64_t refreshTime = 0;
    Json raw;

    static bool FromJson(const Json& reply, VpnCertificate& certificate);
};

struct VpnLocation {
    std::string ip;
    std::string country;
    std::string isp;
    double latitude = 0;
    double longitude = 0;
    bool hasCoordinates = false;
    double expirationTime = 0;

    static const int kRefreshSeconds = 15 * 60;
    bool Expired() const;
    Json ToJson() const;
    static VpnLocation FromJson(const Json& json);
};

struct PortList {
    std::vector<int> udp;
    std::vector<int> tcp;
    std::vector<int> tls;
};

struct ClientConfig {
    PortList openvpn;
    PortList wireguard;
    std::vector<std::string> holesIps;
    int serverRefreshInterval = 10;
    int changeServerAttemptLimit = 4;
    int changeServerShortDelay = 90;
    int changeServerLongDelay = 1200;
    double expirationTime = 0;

    static const int kRefreshSeconds = 3 * 60 * 60;
    static ClientConfig Default();
    static bool FromJson(const Json& json, ClientConfig& config);
    Json ToJson() const;
    bool Expired() const;
};

class FeatureFlags {
public:
    static const int kRefreshSeconds = 2 * 60 * 60;

    FeatureFlags() {}
    explicit FeatureFlags(const Json& reply);
    // False for unknown flags; PROTON_VPN_FEATURE_FLAG_<name> in the
    // environment turns a flag on, as in the Linux app.
    bool Get(const std::string& name) const;
    Json ToJson() const { return fData; }
    double ExpirationTime() const { return fExpiration; }

private:
    Json fData = Json::object();
    double fExpiration = 0;
};

// Everything the app keeps about the signed-in account, stored with the
// session tokens (the GTK app keeps it in the keyring).
struct VpnAccount {
    VpnInfo info;
    VpnCertificate certificate;
    Ed25519Key key;
    VpnLocation location;

    bool Valid() const { return key.IsValid() && !certificate.certificate.empty(); }
    Json ToJson() const;
    static bool FromJson(const Json& json, VpnAccount& account);
};

}  // namespace pvpn
