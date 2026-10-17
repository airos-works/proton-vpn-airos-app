#include "KillSwitch.h"
#include "Network.h"
#include "Util.h"
#include <unistd.h>
#include <vector>

namespace pvpn {

namespace {

const char* const kHalves[] = {"0.0.0.0/1", "128.0.0.0/1"};
const char* const kHalves6[] = {"::/1", "8000::/1"};

}  // namespace


struct RouteKillSwitch::Private {
    TunDevice blackhole;
    std::vector<Route> routes;
    Route bypass;
    bool haveBypass = false;
};


RouteKillSwitch::RouteKillSwitch(const std::string& stateFile)
    :
    fStateFile(stateFile),
    fPrivate(new Private)
{
}


namespace {

// The state file: "permanent" or "standard", then the blackhole interface.
bool ReadState(const std::string& path, bool& permanent, std::string& interface)
{
    std::string contents;
    if (!ReadFile(path, contents))
        return false;
    std::vector<std::string> lines = Split(contents, '\n');
    permanent = Trim(lines[0]) == "permanent";
    interface = lines.size() > 1 ? Trim(lines[1]) : "";
    return true;
}

}  // namespace


RouteKillSwitch::~RouteKillSwitch()
{
    // A permanent kill switch outlives the app: its routes stay on the
    // blackhole interface, which keeps existing once our descriptor closes.
    bool permanent = false;
    std::string interface;
    if (!ReadState(fStateFile, permanent, interface) || !permanent)
        Disable();
    delete fPrivate;
}


bool RouteKillSwitch::Enable(const std::string& serverIp, bool permanent)
{
    std::string error;
    if (!fEnabled) {
        bool wasPermanent;
        std::string previous;
        // Take over the interface a previous run left behind.
        if (!ReadState(fStateFile, wasPermanent, previous) || previous.empty()
            || !fPrivate->blackhole.OpenExisting(previous, error)) {
            if (!fPrivate->blackhole.Open(error))
                return false;
        }
        // Routes need an addressed interface; nothing is ever read from it,
        // so whatever is routed there is dropped.
        fPrivate->blackhole.SetAddress("10.255.255.254", 32, "", error);
        fPrivate->blackhole.Up(error);
        for (const char* half : kHalves) {
            Route route;
            route.interface = fPrivate->blackhole.Name();
            ParseCidr(half, route.destination, route.prefix);
            if (AddRoute(route, error))
                fPrivate->routes.push_back(route);
        }
        Route default6;
        if (FindDefaultRoute6(default6)) {
            for (const char* half : kHalves6) {
                Route route;
                route.interface = fPrivate->blackhole.Name();
                ParseCidr(half, route.destination, route.prefix);
                if (AddRoute(route, error))
                    fPrivate->routes.push_back(route);
            }
        }
        fEnabled = true;
    }
    // Only the VPN server stays reachable through the real gateway.
    if (serverIp != fServerIp) {
        if (fPrivate->haveBypass) {
            DeleteRoute(fPrivate->bypass, error);
            fPrivate->haveBypass = false;
        }
        Route original;
        if (!serverIp.empty() && FindDefaultRoute(original)) {
            Route bypass;
            bypass.interface = original.interface;
            bypass.destination = serverIp;
            bypass.prefix = 32;
            if (original.gateway != serverIp)
                bypass.gateway = original.gateway;
            if (AddRoute(bypass, error)) {
                fPrivate->bypass = bypass;
                fPrivate->haveBypass = true;
            }
        }
        fServerIp = serverIp;
    }
    WriteFile(fStateFile, std::string(permanent ? "permanent" : "standard") + "\n"
        + fPrivate->blackhole.Name() + "\n", 0644);
    return true;
}


void RouteKillSwitch::RemoveRoutes()
{
    std::string error;
    for (auto it = fPrivate->routes.rbegin(); it != fPrivate->routes.rend(); ++it)
        DeleteRoute(*it, error);
    fPrivate->routes.clear();
    if (fPrivate->haveBypass) {
        DeleteRoute(fPrivate->bypass, error);
        fPrivate->haveBypass = false;
    }
}


void RouteKillSwitch::Disable()
{
    unlink(fStateFile.c_str());
    if (!fEnabled)
        return;
    RemoveRoutes();
    fPrivate->blackhole.Close();
    fEnabled = false;
    fServerIp.clear();
}


void RouteKillSwitch::Restore()
{
    bool permanent = false;
    std::string interface;
    if (!ReadState(fStateFile, permanent, interface))
        return;
    if (permanent) {
        Enable("", true);
        return;
    }
    // A standard kill switch left over from a crash: remove its interface.
    std::string error;
    if (!interface.empty() && fPrivate->blackhole.OpenExisting(interface, error))
        fPrivate->blackhole.Close();
    unlink(fStateFile.c_str());
}

}  // namespace pvpn
