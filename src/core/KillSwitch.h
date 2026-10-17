// The kill switch keeps traffic from leaving outside the VPN. Haiku has no
// packet filter, so it works with routes: a "blackhole" tunnel interface
// that nobody reads gets 0.0.0.0/1 and 128.0.0.0/1 (and the IPv6 halves),
// which win over the default route; only the VPN server keeps a host route
// through the real gateway. The VPN's own routes replace them while it is up.
#pragma once
#include <string>

namespace pvpn {

class KillSwitch {
public:
    virtual ~KillSwitch() {}
    // Blocks everything except the VPN server (when given). permanent: keep
    // blocking after the app quits, and block again when it starts.
    virtual bool Enable(const std::string& serverIp, bool permanent) = 0;
    virtual void Disable() = 0;
    virtual bool Enabled() const = 0;
};

// The route-based kill switch (Haiku). stateFile remembers a permanent kill
// switch across restarts of the app.
class RouteKillSwitch : public KillSwitch {
public:
    explicit RouteKillSwitch(const std::string& stateFile);
    ~RouteKillSwitch() override;

    bool Enable(const std::string& serverIp, bool permanent) override;
    void Disable() override;
    bool Enabled() const override { return fEnabled; }
    // Re-applies a permanent kill switch recorded in the state file.
    void Restore();

private:
    void RemoveRoutes();

    std::string fStateFile;
    bool fEnabled = false;
    std::string fServerIp;
    struct Private;
    Private* fPrivate;
};

}  // namespace pvpn
