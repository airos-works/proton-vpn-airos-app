// Network plumbing for the WireGuard helper and the kill switch: tunnel
// devices, interface addresses and routes. On Haiku through the stack's
// ioctls (route(8) mangles 0.0.0.0/1, see Burrow's notes); on Linux through
// /dev/net/tun and ip(8), which is only used by tests in containers.
#pragma once
#include <string>
#include <vector>

namespace pvpn {

struct Route {
    std::string interface;
    std::string destination;   // "0.0.0.0", "::"
    int prefix = 0;
    std::string gateway;       // empty for directly connected routes
    bool isDefault = false;
};

// The IPv4 default route (gateway and interface), or false.
bool FindDefaultRoute(Route& route);
bool FindDefaultRoute6(Route& route);
bool ListRoutes(std::vector<Route>& routes, int family);
bool HasDefaultRoute();

bool AddRoute(const Route& route, std::string& error);
bool DeleteRoute(const Route& route, std::string& error);

class TunDevice {
public:
    TunDevice();
    ~TunDevice();

    // Creates (Haiku: adds the first free tun/<n> interface) and opens a
    // tunnel device.
    bool Open(std::string& error);
    // Takes over an existing tunnel interface (removed again by Close()).
    bool OpenExisting(const std::string& name, std::string& error);
    void Close();
    // Closes the descriptor but leaves the interface (and its routes) in
    // place, for a kill switch that outlives the app.
    void Release();
    int Fd() const { return fFd; }
    const std::string& Name() const { return fName; }

    bool SetAddress(const std::string& address, int prefix, const std::string& peer,
        std::string& error);
    bool SetAddress6(const std::string& address, int prefix, std::string& error);
    bool SetMtu(int mtu, std::string& error);
    bool Up(std::string& error);

private:
    int fFd = -1;
    std::string fName;
    bool fCreated = false;
};

// Removes a tunnel interface someone else created (e.g. a helper that was
// killed); its routes go with it.
bool RemoveTunnelInterface(const std::string& name);

// Parses "10.2.0.2/32" into address and prefix.
bool ParseCidr(const std::string& text, std::string& address, int& prefix);

}  // namespace pvpn
