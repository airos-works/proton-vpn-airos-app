// The VPN connection state machine (python-proton-vpn-api-core's
// connection/states.py and core/vpnconnector.py): Disconnected, Connecting,
// Connected, Disconnecting and Error, with reconnections going through
// Disconnecting. It owns the tunnel of the current connection, talks to the
// server's local agent once the tunnel is up, applies the VPN's name servers
// and drives the kill switch. Everything runs on the connector's thread;
// status changes are reported to a ConnectorListener on that thread.
#pragma once
#include "LocalAgent.h"
#include "ServerList.h"
#include "Settings.h"
#include "Tunnel.h"
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace pvpn {

class KillSwitch;

enum class VpnState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Error,
};

// What led to the current state (connection/events.py).
enum class VpnEvent {
    Initialized,
    Up,
    Down,
    Connected,
    Disconnected,
    Timeout,
    AuthDenied,
    ExpiredCertificate,
    NotYetValidCertificate,
    MaximumSessionsReached,
    TwoFactorRequired,
    TunnelSetupFailed,
    DeviceDisconnected,
    UnexpectedError,
};

bool IsErrorEvent(VpnEvent event);
const char* VpnStateName(VpnState state);
const char* VpnEventName(VpnEvent event);

struct ServerTarget {
    LogicalServer logical;
    PhysicalServer physical;
    std::string protocol;
};

struct VpnStatus {
    VpnState state = VpnState::Disconnected;
    VpnEvent event = VpnEvent::Initialized;
    // Disconnecting/Disconnected on the way to another connection.
    bool reconnecting = false;
    bool hasServer = false;
    ServerTarget server;
    std::string message;          // details of an error
    int forwardedPort = 0;
    std::string deviceIp;         // the exit IP the agent reports
    std::string deviceCountry;
    std::string device;           // tun/0
    std::string localAddress;
    uint64_t received = 0;
    uint64_t sent = 0;
    double connectedSince = 0;
    int connectionId = 0;
};

class ConnectorListener {
public:
    virtual ~ConnectorListener() {}
    virtual void VpnStatusChanged(const VpnStatus& status) = 0;
    virtual void VpnLog(const std::string& line) = 0;
};

struct ConnectionRequest {
    ServerTarget target;
    TunnelConfig tunnel;       // filled by the caller: credentials, paths, ports
    Settings settings;
    int userTier = 0;
};

class Connector {
public:
    explicit Connector(ConnectorListener* listener);
    ~Connector();

    void SetKillSwitch(KillSwitch* killSwitch);
    void SetResolvConfPath(const std::string& path) { fResolvConf = path; }

    void Connect(const ConnectionRequest& request);
    void Disconnect();
    // Settings changed: VPN features go to the agent at once; the rest
    // (protocol, kill switch mode, DNS) applies to the next connection,
    // except the kill switch mode which also applies when disconnected.
    void ApplySettings(const Settings& settings, int userTier);
    // A new certificate: the agent connection is restarted with it.
    void UpdateCredentials(const std::string& certificatePem, const std::string& keyPem);
    // Blocks until the state is Disconnected (or the timeout passes).
    bool WaitForDisconnected(double timeoutSeconds);

    VpnStatus Status() const;
    bool Active() const;   // anything but Disconnected or Error

private:
    struct Connection;
    struct Event;
    class TunnelSink;

    void Post(Event event);
    void Run();
    void Process(Event& event);
    void Transition(VpnState state, VpnEvent event, const std::string& message = "");
    void EnterConnecting();
    void EnterConnected();
    void EnterDisconnecting();
    void EnterDisconnected();
    void EnterError();
    void StartTunnel(Connection& connection);
    void StartAgent(Connection& connection);
    void StopAgent(Connection& connection);
    void AgentLoop(std::shared_ptr<Connection> connection);
    AgentFeatures FeaturesFor(const Settings& settings, const Connection& connection) const;
    void ApplyDns(Connection& connection);
    void RestoreDns();
    void Notify();
    void Log(const std::string& line);

    ConnectorListener* fListener;
    KillSwitch* fKillSwitch = nullptr;
    std::string fResolvConf;

    mutable std::mutex fLock;
    std::condition_variable fCondition;
    std::condition_variable fStateCondition;
    std::deque<Event> fEvents;
    bool fQuit = false;
    std::thread fThread;

    // Only touched on the connector thread (fStatus also under fLock).
    VpnStatus fStatus;
    std::shared_ptr<Connection> fCurrent;
    std::shared_ptr<Connection> fReconnection;
    std::vector<std::shared_ptr<Connection>> fRetired;
    int fNextId = 1;
    Settings fSettings;
    int fUserTier = 0;
    bool fDnsApplied = false;
};

}  // namespace pvpn
