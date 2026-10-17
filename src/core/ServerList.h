// The VPN server list (/vpn/v1/logicals, loads from /vpn/v1/loads), with the
// selection and grouping rules of python-proton-vpn-api-core's ServerList and
// the GTK app's server list widget.
#pragma once
#include "Json.h"
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace pvpn {

enum ServerFeature : uint32_t {
    kFeatureSecureCore = 1 << 0,
    kFeatureTor = 1 << 1,
    kFeatureP2P = 1 << 2,
    kFeatureStreaming = 1 << 3,
    kFeatureIPv6 = 1 << 4,
};

enum Tier {
    kTierFree = 0,
    kTierPlus = 2,
    kTierProton = 3,
};

struct PhysicalServer {
    std::string id;
    std::string entryIp;
    std::string exitIp;
    std::string domain;
    std::string label;
    std::string x25519PublicKey;   // base64
    bool enabled = false;
};

struct LogicalServer {
    std::string id;
    std::string name;
    std::string entryCountry;
    std::string exitCountry;
    std::string hostCountry;
    std::string city;
    std::string state;
    int tier = 0;
    uint32_t features = 0;
    double score = 0;
    int load = 0;
    int status = 0;
    double latitude = 0;
    double longitude = 0;
    std::vector<PhysicalServer> servers;

    bool Enabled() const;
    bool UnderMaintenance() const { return !Enabled(); }
    bool Free() const { return tier == kTierFree; }
    bool Has(uint32_t feature) const { return (features & feature) == feature; }
    bool SmartRouting() const { return !hostCountry.empty(); }
    // State if there is one, the city otherwise (what the list groups by).
    std::string Location() const { return !state.empty() ? state : city; }
    // A random enabled physical server, or NULL.
    const PhysicalServer* PickPhysical() const;

    static bool FromJson(const Json& json, LogicalServer& server);
};

// Summary of a group of servers, as ServerAnalysis computes it.
struct GroupSummary {
    bool free = false;              // at least one free server
    bool underMaintenance = true;   // every server disabled
    bool smartRouting = true;       // every server smart-routed
    uint32_t features = 0;          // union of the servers' features

    static GroupSummary Of(const std::vector<const LogicalServer*>& servers);
};

struct LocationGroup {
    std::string name;
    std::vector<const LogicalServer*> servers;
    GroupSummary summary;
};

struct CountryGroup {
    std::string code;
    std::string name;
    std::vector<const LogicalServer*> servers;      // all servers of the country
    std::vector<LocationGroup> locations;           // Secure Core servers excluded
    std::vector<const LogicalServer*> secureCore;   // "Via Secure Core"
    GroupSummary summary;
    GroupSummary secureCoreSummary;
};

class ServerList {
public:
    static const int kLogicalsRefreshSeconds = 3 * 60 * 60;
    static const int kLoadsRefreshSeconds = 15 * 60;

    ServerList() {}

    // From an API reply ({"LogicalServers": [...]}).
    bool LoadApiReply(const Json& reply, int userTier, const std::string& lastModified);
    // Applies /vpn/v1/loads.
    void UpdateLoads(const Json& reply);
    bool LoadCache(const Json& cache);
    Json ToCache() const;

    int UserTier() const { return fUserTier; }
    void SetUserTier(int tier) { fUserTier = tier; }
    size_t Size() const { return fServers.size(); }
    bool Empty() const { return fServers.empty(); }
    const std::vector<LogicalServer>& Servers() const { return fServers; }
    const std::string& LastModified() const { return fLastModified; }
    double ExpirationTime() const { return fExpiration; }
    double LoadsExpirationTime() const { return fLoadsExpiration; }
    void ResetExpiration();
    void ResetLoadsExpiration();

    const LogicalServer* ById(const std::string& id) const;
    const LogicalServer* ByName(const std::string& name) const;

    // Lowest score among enabled servers the tier allows, without Secure Core
    // and Tor (ServerList.get_fastest*). NULL if there is none.
    const LogicalServer* Fastest(int tier) const;
    const LogicalServer* FastestInCountry(const std::string& code, int tier) const;
    const LogicalServer* FastestInLocation(const std::string& code, const std::string& location,
        int tier) const;
    const LogicalServer* FastestSecureCore(const std::string& exitCountry, int tier) const;
    static const LogicalServer* FastestOf(const std::vector<const LogicalServer*>& servers,
        int tier);

    // Countries for the list: sorted by name, free countries first for free
    // users; locations sorted by name (free locations first for free users in
    // free countries) and their servers ordered as the GTK app shows them.
    // Paid users do not see free servers inside locations.
    std::vector<CountryGroup> GroupByCountry(int userTier) const;
    // Codes of countries that have a free server, sorted by name.
    std::vector<std::string> FreeCountries() const;

private:
    void Index();

    std::vector<LogicalServer> fServers;
    std::map<std::string, size_t> fById;
    std::map<std::string, size_t> fByName;   // upper case
    int fUserTier = 0;
    double fExpiration = 0;
    double fLoadsExpiration = 0;
    std::string fLastModified;
};

}  // namespace pvpn
