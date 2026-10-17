#include "ServerList.h"
#include "Countries.h"
#include "Crypto.h"
#include "Util.h"
#include <algorithm>
#include <set>

namespace pvpn {

namespace {

const double kRefreshRandomness = 0.22;

bool Excluded(const LogicalServer& server)
{
    return (server.features & (kFeatureSecureCore | kFeatureTor)) != 0;
}

bool Available(const LogicalServer& server, int tier)
{
    return server.Enabled() && server.tier <= tier;
}

// Servers inside a location: free first for free users in free locations,
// otherwise paid first; then enabled before disabled and by load.
void SortLocationServers(std::vector<const LogicalServer*>& servers, bool freeFirst)
{
    std::stable_sort(servers.begin(), servers.end(),
        [freeFirst](const LogicalServer* a, const LogicalServer* b) {
            bool aFirst = freeFirst ? a->Free() : !a->Free();
            bool bFirst = freeFirst ? b->Free() : !b->Free();
            if (aFirst != bFirst)
                return aFirst;
            if (a->Enabled() != b->Enabled())
                return a->Enabled();
            return a->load < b->load;
        });
}

}  // namespace


bool LogicalServer::Enabled() const
{
    if (status != 1)
        return false;
    for (const PhysicalServer& physical : servers) {
        if (physical.enabled)
            return true;
    }
    return false;
}


const PhysicalServer* LogicalServer::PickPhysical() const
{
    std::vector<const PhysicalServer*> enabled;
    for (const PhysicalServer& physical : servers) {
        if (physical.enabled)
            enabled.push_back(&physical);
    }
    if (enabled.empty())
        return NULL;
    size_t index = (size_t)(RandomUnit() * enabled.size());
    return enabled[std::min(index, enabled.size() - 1)];
}


bool LogicalServer::FromJson(const Json& json, LogicalServer& server)
{
    server.id = JsonString(json, "ID");
    server.name = JsonString(json, "Name");
    if (server.id.empty() || server.name.empty())
        return false;
    server.entryCountry = JsonString(json, "EntryCountry");
    server.exitCountry = JsonString(json, "ExitCountry");
    server.hostCountry = JsonString(json, "HostCountry");
    server.city = JsonString(json, "City");
    server.state = JsonString(json, "State");
    server.tier = (int)JsonInt(json, "Tier");
    server.features = (uint32_t)JsonInt(json, "Features");
    server.score = JsonDouble(json, "Score", (double)JsonInt(json, "Score"));
    server.load = (int)JsonInt(json, "Load");
    server.status = (int)JsonInt(json, "Status");
    const Json& location = JsonObject(json, "Location");
    server.latitude = JsonDouble(location, "Lat");
    server.longitude = JsonDouble(location, "Long");
    server.servers.clear();
    for (const Json& item : JsonArray(json, "Servers")) {
        PhysicalServer physical;
        physical.id = JsonString(item, "ID");
        physical.entryIp = JsonString(item, "EntryIP");
        physical.exitIp = JsonString(item, "ExitIP");
        physical.domain = JsonString(item, "Domain");
        physical.label = JsonString(item, "Label");
        physical.x25519PublicKey = JsonString(item, "X25519PublicKey");
        physical.enabled = JsonInt(item, "Status") == 1;
        server.servers.push_back(physical);
    }
    return true;
}


GroupSummary GroupSummary::Of(const std::vector<const LogicalServer*>& servers)
{
    GroupSummary summary;
    for (const LogicalServer* server : servers) {
        summary.features |= server->features;
        summary.free = summary.free || server->Free();
        summary.underMaintenance = summary.underMaintenance && !server->Enabled();
        summary.smartRouting = summary.smartRouting && server->SmartRouting();
    }
    if (servers.empty())
        summary.smartRouting = false;
    return summary;
}


bool ServerList::LoadApiReply(const Json& reply, int userTier, const std::string& lastModified)
{
    const Json& logicals = JsonArray(reply, "LogicalServers");
    if (logicals.empty())
        return false;
    std::vector<LogicalServer> servers;
    servers.reserve(logicals.size());
    for (const Json& item : logicals) {
        LogicalServer server;
        if (LogicalServer::FromJson(item, server))
            servers.push_back(std::move(server));
    }
    fServers.swap(servers);
    fUserTier = userTier;
    fLastModified = lastModified.empty() ? "Thu, 01 Jan 1970 00:00:00 GMT" : lastModified;
    ResetExpiration();
    ResetLoadsExpiration();
    Index();
    return true;
}


void ServerList::UpdateLoads(const Json& reply)
{
    for (const Json& item : JsonArray(reply, "LogicalServers")) {
        auto it = fById.find(JsonString(item, "ID"));
        // /vpn/loads lists a few servers /vpn/logicals does not.
        if (it == fById.end())
            continue;
        LogicalServer& server = fServers[it->second];
        server.load = (int)JsonInt(item, "Load", server.load);
        server.score = JsonDouble(item, "Score", server.score);
        server.status = (int)JsonInt(item, "Status", server.status);
    }
    ResetLoadsExpiration();
}


void ServerList::ResetExpiration()
{
    fExpiration = Now() + kLogicalsRefreshSeconds * Jitter(kRefreshRandomness);
}


void ServerList::ResetLoadsExpiration()
{
    fLoadsExpiration = Now() + kLoadsRefreshSeconds * Jitter(kRefreshRandomness);
}


bool ServerList::LoadCache(const Json& cache)
{
    if (!LoadApiReply(cache, (int)JsonInt(cache, "MaxTier"), JsonString(cache, "LastModifiedTime")))
        return false;
    fExpiration = JsonDouble(cache, "ExpirationTime", fExpiration);
    fLoadsExpiration = JsonDouble(cache, "LoadsExpirationTime", fLoadsExpiration);
    return true;
}


Json ServerList::ToCache() const
{
    Json logicals = Json::array();
    for (const LogicalServer& server : fServers) {
        Json physical = Json::array();
        for (const PhysicalServer& item : server.servers) {
            physical.push_back({{"ID", item.id}, {"EntryIP", item.entryIp}, {"ExitIP", item.exitIp},
                {"Domain", item.domain}, {"Label", item.label},
                {"X25519PublicKey", item.x25519PublicKey}, {"Status", item.enabled ? 1 : 0}});
        }
        Json json = {{"ID", server.id}, {"Name", server.name}, {"EntryCountry", server.entryCountry},
            {"ExitCountry", server.exitCountry}, {"City", server.city}, {"Tier", server.tier},
            {"Features", server.features}, {"Score", server.score}, {"Load", server.load},
            {"Status", server.status},
            {"Location", {{"Lat", server.latitude}, {"Long", server.longitude}}},
            {"Servers", physical}};
        json["HostCountry"] = server.hostCountry.empty() ? Json() : Json(server.hostCountry);
        json["State"] = server.state.empty() ? Json() : Json(server.state);
        logicals.push_back(json);
    }
    return Json{{"LogicalServers", logicals}, {"MaxTier", fUserTier},
        {"ExpirationTime", fExpiration}, {"LoadsExpirationTime", fLoadsExpiration},
        {"LastModifiedTime", fLastModified}};
}


void ServerList::Index()
{
    fById.clear();
    fByName.clear();
    for (size_t i = 0; i < fServers.size(); i++) {
        fById[fServers[i].id] = i;
        fByName[ToUpper(fServers[i].name)] = i;
    }
}


const LogicalServer* ServerList::ById(const std::string& id) const
{
    auto it = fById.find(id);
    return it == fById.end() ? NULL : &fServers[it->second];
}


const LogicalServer* ServerList::ByName(const std::string& name) const
{
    auto it = fByName.find(ToUpper(name));
    return it == fByName.end() ? NULL : &fServers[it->second];
}


const LogicalServer* ServerList::FastestOf(const std::vector<const LogicalServer*>& servers,
    int tier)
{
    const LogicalServer* best = NULL;
    for (const LogicalServer* server : servers) {
        if (Available(*server, tier) && (best == NULL || server->score < best->score))
            best = server;
    }
    return best;
}


const LogicalServer* ServerList::Fastest(int tier) const
{
    std::vector<const LogicalServer*> candidates;
    for (const LogicalServer& server : fServers) {
        if (!Excluded(server))
            candidates.push_back(&server);
    }
    return FastestOf(candidates, tier);
}


const LogicalServer* ServerList::FastestInCountry(const std::string& code, int tier) const
{
    std::vector<const LogicalServer*> candidates;
    std::string lower = ToLower(code);
    for (const LogicalServer& server : fServers) {
        if (!Excluded(server) && ToLower(server.exitCountry) == lower)
            candidates.push_back(&server);
    }
    return FastestOf(candidates, tier);
}


const LogicalServer* ServerList::FastestInLocation(const std::string& code,
    const std::string& location, int tier) const
{
    std::vector<const LogicalServer*> candidates;
    std::string lower = ToLower(code);
    for (const LogicalServer& server : fServers) {
        if (!server.Has(kFeatureSecureCore) && ToLower(server.exitCountry) == lower
            && server.Location() == location)
            candidates.push_back(&server);
    }
    return FastestOf(candidates, tier);
}


const LogicalServer* ServerList::FastestSecureCore(const std::string& exitCountry, int tier) const
{
    std::vector<const LogicalServer*> candidates;
    std::string lower = ToLower(exitCountry);
    for (const LogicalServer& server : fServers) {
        if (server.Has(kFeatureSecureCore) && ToLower(server.exitCountry) == lower)
            candidates.push_back(&server);
    }
    return FastestOf(candidates, tier);
}


std::vector<CountryGroup> ServerList::GroupByCountry(int userTier) const
{
    bool freeUser = userTier == kTierFree;
    std::map<std::string, CountryGroup> byCode;
    for (const LogicalServer& server : fServers) {
        std::string code = ToUpper(server.exitCountry);
        CountryGroup& country = byCode[code];
        country.code = code;
        country.servers.push_back(&server);
    }
    std::vector<CountryGroup> countries;
    for (auto& entry : byCode) {
        CountryGroup& country = entry.second;
        country.name = CountryName(country.code);
        country.summary = GroupSummary::Of(country.servers);
        std::map<std::string, LocationGroup> locations;
        for (const LogicalServer* server : country.servers) {
            if (server->Has(kFeatureSecureCore)) {
                country.secureCore.push_back(server);
                continue;
            }
            if (server->Free() && !freeUser)
                continue;
            LocationGroup& location = locations[server->Location()];
            location.name = server->Location();
            location.servers.push_back(server);
        }
        for (auto& item : locations) {
            LocationGroup& location = item.second;
            location.summary = GroupSummary::Of(location.servers);
            SortLocationServers(location.servers, freeUser && location.summary.free);
            country.locations.push_back(location);
        }
        bool freeLocationsFirst = freeUser && country.summary.free;
        std::stable_sort(country.locations.begin(), country.locations.end(),
            [freeLocationsFirst](const LocationGroup& a, const LocationGroup& b) {
                if (freeLocationsFirst && a.summary.free != b.summary.free)
                    return a.summary.free;
                return FoldForSearch(a.name) < FoldForSearch(b.name);
            });
        std::stable_sort(country.secureCore.begin(), country.secureCore.end(),
            [](const LogicalServer* a, const LogicalServer* b) {
                std::string nameA = CountryName(a->entryCountry);
                std::string nameB = CountryName(b->entryCountry);
                if (nameA != nameB)
                    return nameA < nameB;
                return NaturalLess(a->name, b->name);
            });
        country.secureCoreSummary = GroupSummary::Of(country.secureCore);
        countries.push_back(std::move(country));
    }
    std::stable_sort(countries.begin(), countries.end(),
        [freeUser](const CountryGroup& a, const CountryGroup& b) {
            if (freeUser && a.summary.free != b.summary.free)
                return a.summary.free;
            return FoldForSearch(a.name) < FoldForSearch(b.name);
        });
    return countries;
}


std::vector<std::string> ServerList::FreeCountries() const
{
    std::set<std::string> codes;
    for (const LogicalServer& server : fServers) {
        if (server.Free())
            codes.insert(ToUpper(server.exitCountry));
    }
    std::vector<std::string> result(codes.begin(), codes.end());
    std::sort(result.begin(), result.end(), [](const std::string& a, const std::string& b) {
        return FoldForSearch(CountryName(a)) < FoldForSearch(CountryName(b));
    });
    return result;
}

}  // namespace pvpn
