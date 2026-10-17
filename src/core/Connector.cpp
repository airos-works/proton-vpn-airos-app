#include "Connector.h"
#include "KillSwitch.h"
#include "ResolvConf.h"
#include "Util.h"
#include <atomic>
#include <chrono>
#include <unistd.h>

namespace pvpn {

namespace {

const double kConnectTimeout = 60;
const double kAgentReadTimeoutMs = 1000;
const double kPortForwardingRefresh = 60;

}  // namespace


bool IsErrorEvent(VpnEvent event)
{
    switch (event) {
        case VpnEvent::Timeout:
        case VpnEvent::AuthDenied:
        case VpnEvent::ExpiredCertificate:
        case VpnEvent::NotYetValidCertificate:
        case VpnEvent::MaximumSessionsReached:
        case VpnEvent::TwoFactorRequired:
        case VpnEvent::TunnelSetupFailed:
        case VpnEvent::DeviceDisconnected:
        case VpnEvent::UnexpectedError:
            return true;
        default:
            return false;
    }
}


const char* VpnStateName(VpnState state)
{
    switch (state) {
        case VpnState::Disconnected: return "Disconnected";
        case VpnState::Connecting: return "Connecting";
        case VpnState::Connected: return "Connected";
        case VpnState::Disconnecting: return "Disconnecting";
        case VpnState::Error: return "Error";
    }
    return "";
}


const char* VpnEventName(VpnEvent event)
{
    switch (event) {
        case VpnEvent::Initialized: return "Initialized";
        case VpnEvent::Up: return "Up";
        case VpnEvent::Down: return "Down";
        case VpnEvent::Connected: return "Connected";
        case VpnEvent::Disconnected: return "Disconnected";
        case VpnEvent::Timeout: return "Timeout";
        case VpnEvent::AuthDenied: return "AuthDenied";
        case VpnEvent::ExpiredCertificate: return "ExpiredCertificate";
        case VpnEvent::NotYetValidCertificate: return "NotYetValidCertificate";
        case VpnEvent::MaximumSessionsReached: return "MaximumSessionsReached";
        case VpnEvent::TwoFactorRequired: return "TwoFARequired";
        case VpnEvent::TunnelSetupFailed: return "TunnelSetupFailed";
        case VpnEvent::DeviceDisconnected: return "DeviceDisconnected";
        case VpnEvent::UnexpectedError: return "UnexpectedError";
    }
    return "";
}


struct Connector::Event {
    enum Kind {
        Up, Down, TunnelUp, TunnelReconnecting, TunnelFailed, TunnelStopped, TunnelStats,
        AgentStatus, AgentFailure, Tick, Settings, Credentials, Log,
    } kind;
    int connectionId = 0;
    std::shared_ptr<Connection> connection;
    TunnelFailure failure = TunnelFailure::None;
    VpnEvent errorEvent = VpnEvent::UnexpectedError;
    std::string message;
    std::string device;
    std::string localAddress;
    std::vector<std::string> dns;
    uint64_t received = 0;
    uint64_t sent = 0;
    pvpn::AgentStatus agent;
    pvpn::Settings settings;
    int userTier = 0;
    std::string certificate;
    std::string key;

    explicit Event(Kind kind_) : kind(kind_) {}
};


class Connector::TunnelSink : public TunnelListener {
public:
    TunnelSink(Connector* connector, int id) : fConnector(connector), fId(id) {}

    void TunnelUp(const std::string& device, const std::string& localAddress,
        const std::vector<std::string>& dns) override
    {
        Event event(Event::TunnelUp);
        event.connectionId = fId;
        event.device = device;
        event.localAddress = localAddress;
        event.dns = dns;
        fConnector->Post(event);
    }

    void TunnelReconnecting(const std::string& reason) override
    {
        Event event(Event::TunnelReconnecting);
        event.connectionId = fId;
        event.message = reason;
        fConnector->Post(event);
    }

    void TunnelFailed(TunnelFailure failure, const std::string& message) override
    {
        Event event(Event::TunnelFailed);
        event.connectionId = fId;
        event.failure = failure;
        event.message = message;
        fConnector->Post(event);
    }

    void TunnelStopped() override
    {
        Event event(Event::TunnelStopped);
        event.connectionId = fId;
        fConnector->Post(event);
    }

    void TunnelStats(uint64_t received, uint64_t sent) override
    {
        Event event(Event::TunnelStats);
        event.connectionId = fId;
        event.received = received;
        event.sent = sent;
        fConnector->Post(event);
    }

    void TunnelLog(const std::string& line) override
    {
        Event event(Event::Log);
        event.message = line;
        fConnector->Post(event);
    }

private:
    Connector* fConnector;
    int fId;
};


struct Connector::Connection {
    int id = 0;
    ConnectionRequest request;
    std::unique_ptr<TunnelSink> sink;
    std::unique_ptr<Tunnel> tunnel;
    bool tunnelStopped = true;    // no tunnel process alive
    bool tunnelUp = false;
    std::vector<std::string> pushedDns;
    std::string device;
    std::string localAddress;
    double startedAt = 0;

    std::thread agentThread;
    std::atomic<bool> agentStop{false};
    std::atomic<bool> agentDone{false};
    std::mutex agentLock;           // guards the fields below
    bool featuresPending = false;
    AgentFeatures pendingFeatures;
    bool credentialsChanged = false;
    std::string certificatePem;
    std::string keyPem;

    ~Connection()
    {
        agentStop = true;
        if (agentThread.joinable()) {
            // The agent thread may hold the last reference itself.
            if (agentThread.get_id() == std::this_thread::get_id())
                agentThread.detach();
            else
                agentThread.join();
        }
        tunnel.reset();
    }
};


Connector::Connector(ConnectorListener* listener)
    :
    fListener(listener),
    fResolvConf(kResolvConfPath)
{
    fThread = std::thread(&Connector::Run, this);
}


Connector::~Connector()
{
    {
        std::lock_guard<std::mutex> lock(fLock);
        fQuit = true;
    }
    fCondition.notify_all();
    if (fThread.joinable())
        fThread.join();
    if (fCurrent) {
        StopAgent(*fCurrent);
        if (fCurrent->tunnel)
            fCurrent->tunnel->Stop();
    }
    fCurrent.reset();
    fReconnection.reset();
    fRetired.clear();
    RestoreDns();
}


void Connector::SetKillSwitch(KillSwitch* killSwitch)
{
    fKillSwitch = killSwitch;
}


void Connector::Post(Event event)
{
    {
        std::lock_guard<std::mutex> lock(fLock);
        fEvents.push_back(std::move(event));
    }
    fCondition.notify_all();
}


void Connector::Connect(const ConnectionRequest& request)
{
    Event event(Event::Up);
    event.connection = std::make_shared<Connection>();
    event.connection->request = request;
    event.connection->certificatePem = request.tunnel.certificatePem;
    event.connection->keyPem = request.tunnel.privateKeyPem;
    Post(event);
}


void Connector::Disconnect()
{
    Post(Event(Event::Down));
}


void Connector::ApplySettings(const Settings& settings, int userTier)
{
    Event event(Event::Settings);
    event.settings = settings;
    event.userTier = userTier;
    Post(event);
}


void Connector::UpdateCredentials(const std::string& certificatePem, const std::string& keyPem)
{
    Event event(Event::Credentials);
    event.certificate = certificatePem;
    event.key = keyPem;
    Post(event);
}


VpnStatus Connector::Status() const
{
    std::lock_guard<std::mutex> lock(fLock);
    return fStatus;
}


bool Connector::Active() const
{
    VpnState state = Status().state;
    return state != VpnState::Disconnected && state != VpnState::Error;
}


bool Connector::WaitForDisconnected(double timeoutSeconds)
{
    std::unique_lock<std::mutex> lock(fLock);
    return fStateCondition.wait_for(lock,
        std::chrono::milliseconds((long)(timeoutSeconds * 1000)),
        [this] { return fStatus.state == VpnState::Disconnected && !fStatus.reconnecting; });
}


void Connector::Log(const std::string& line)
{
    fListener->VpnLog(line);
}


void Connector::Notify()
{
    VpnStatus status;
    {
        std::lock_guard<std::mutex> lock(fLock);
        status = fStatus;
    }
    fStateCondition.notify_all();
    fListener->VpnStatusChanged(status);
}


void Connector::Run()
{
    while (true) {
        Event event(Event::Tick);
        {
            std::unique_lock<std::mutex> lock(fLock);
            fCondition.wait_for(lock, std::chrono::milliseconds(500),
                [this] { return fQuit || !fEvents.empty(); });
            if (fQuit)
                return;
            if (!fEvents.empty()) {
                event = std::move(fEvents.front());
                fEvents.pop_front();
            }
        }
        Process(event);
        // Connections whose tunnel and agent are finished can go.
        for (auto it = fRetired.begin(); it != fRetired.end();) {
            if ((*it)->tunnelStopped && *it != fCurrent && *it != fReconnection
                && ((*it)->agentDone || !(*it)->agentThread.joinable()))
                it = fRetired.erase(it);
            else
                ++it;
        }
    }
}


void Connector::Transition(VpnState state, VpnEvent event, const std::string& message)
{
    {
        std::lock_guard<std::mutex> lock(fLock);
        VpnState previous = fStatus.state;
        fStatus.state = state;
        fStatus.event = event;
        fStatus.message = message;
        fStatus.reconnecting = fReconnection != nullptr
            && (state == VpnState::Disconnecting || state == VpnState::Disconnected);
        if (state == VpnState::Connected && previous != VpnState::Connected)
            fStatus.connectedSince = Now();
        if (fCurrent) {
            fStatus.hasServer = true;
            fStatus.server = fCurrent->request.target;
            fStatus.connectionId = fCurrent->id;
        }
    }
    Log(std::string("State: ") + VpnStateName(state) + " (" + VpnEventName(event) + ")"
        + (message.empty() ? "" : ": " + message));
}


void Connector::Process(Event& event)
{
    VpnState state = Status().state;
    bool current = fCurrent && event.connectionId == fCurrent->id;
    switch (event.kind) {
        case Event::Log:
            Log(event.message);
            return;

        case Event::Up: {
            std::shared_ptr<Connection> connection = event.connection;
            connection->id = fNextId++;
            fSettings = connection->request.settings;
            fUserTier = connection->request.userTier;
            if (state == VpnState::Disconnected) {
                fCurrent = connection;
                {
                    std::lock_guard<std::mutex> lock(fLock);
                    fStatus = VpnStatus();
                }
                Transition(VpnState::Connecting, VpnEvent::Up);
                EnterConnecting();
            } else if (state == VpnState::Disconnecting) {
                fReconnection = connection;
                Transition(VpnState::Disconnecting, VpnEvent::Up);
                Notify();
            } else {
                // Connecting, Connected or Error: stop the current one first.
                fReconnection = connection;
                Transition(VpnState::Disconnecting, VpnEvent::Up);
                EnterDisconnecting();
            }
            return;
        }

        case Event::Down:
            fReconnection.reset();
            if (state == VpnState::Connecting || state == VpnState::Connected
                || state == VpnState::Error) {
                Transition(VpnState::Disconnecting, VpnEvent::Down);
                EnterDisconnecting();
            } else if (state == VpnState::Disconnecting) {
                Transition(VpnState::Disconnecting, VpnEvent::Down);
                Notify();
            }
            return;

        case Event::Settings: {
            bool featuresChanged = !(event.settings.features == fSettings.features);
            fSettings = event.settings;
            fUserTier = event.userTier;
            if (state == VpnState::Disconnected && fKillSwitch != nullptr) {
                if (fSettings.killSwitch == kKillSwitchAdvanced)
                    fKillSwitch->Enable("", true);
                else
                    fKillSwitch->Disable();
            }
            if (featuresChanged && fCurrent && fUserTier > kTierFree) {
                std::lock_guard<std::mutex> lock(fCurrent->agentLock);
                fCurrent->pendingFeatures = FeaturesFor(fSettings, *fCurrent);
                fCurrent->featuresPending = true;
            }
            return;
        }

        case Event::Credentials:
            if (fCurrent) {
                {
                    std::lock_guard<std::mutex> lock(fCurrent->agentLock);
                    fCurrent->certificatePem = event.certificate;
                    fCurrent->keyPem = event.key;
                    fCurrent->credentialsChanged = true;
                }
                // An agent that gave up on the old certificate starts again.
                if (fCurrent->tunnelUp && !fCurrent->tunnelStopped)
                    StartAgent(*fCurrent);
            }
            return;

        case Event::Tick:
            if (state == VpnState::Connecting && fCurrent
                && MonotonicNow() - fCurrent->startedAt > kConnectTimeout) {
                Transition(VpnState::Error, VpnEvent::Timeout, "The connection timed out.");
                EnterError();
            }
            return;

        default:
            break;
    }

    // Events from tunnels and agents of connections that are no longer
    // current only matter for their clean-up.
    std::shared_ptr<Connection> connection;
    if (current) {
        connection = fCurrent;
    } else {
        for (auto& retired : fRetired) {
            if (retired->id == event.connectionId)
                connection = retired;
        }
        if (connection && event.kind == Event::TunnelStopped) {
            connection->tunnelStopped = true;
            StopAgent(*connection);
        }
        return;
    }

    switch (event.kind) {
        case Event::TunnelUp:
            connection->tunnelUp = true;
            connection->device = event.device;
            connection->localAddress = event.localAddress;
            connection->pushedDns = event.dns;
            {
                std::lock_guard<std::mutex> lock(fLock);
                fStatus.device = event.device;
                fStatus.localAddress = event.localAddress;
            }
            ApplyDns(*connection);
            StartAgent(*connection);
            // OpenVPN counts as connected once the tunnel is up (as the
            // NetworkManager backend reports it); WireGuard waits for the
            // local agent's "connected".
            if (connection->request.target.protocol != kProtocolWireGuard
                && (state == VpnState::Connecting || state == VpnState::Error)) {
                Transition(VpnState::Connected, VpnEvent::Connected);
                EnterConnected();
            } else {
                Notify();
            }
            break;

        case Event::TunnelReconnecting:
            connection->tunnelUp = false;
            if (state == VpnState::Connected) {
                Transition(VpnState::Error, VpnEvent::DeviceDisconnected, event.message);
                EnterError();
            }
            break;

        case Event::TunnelFailed: {
            VpnEvent error = VpnEvent::UnexpectedError;
            if (event.failure == TunnelFailure::Timeout)
                error = VpnEvent::Timeout;
            else if (event.failure == TunnelFailure::AuthDenied)
                error = VpnEvent::AuthDenied;
            else if (event.failure == TunnelFailure::TunnelSetup)
                error = VpnEvent::TunnelSetupFailed;
            if (state == VpnState::Disconnecting) {
                Log("Error while disconnecting: " + event.message);
            } else if (state != VpnState::Disconnected) {
                Transition(VpnState::Error, error, event.message);
                EnterError();
            }
            break;
        }

        case Event::TunnelStopped:
            connection->tunnelStopped = true;
            connection->tunnelUp = false;
            StopAgent(*connection);
            if (state == VpnState::Disconnecting) {
                Transition(VpnState::Disconnected, VpnEvent::Disconnected);
                EnterDisconnected();
            } else if (state == VpnState::Connected || state == VpnState::Connecting) {
                Transition(VpnState::Error, VpnEvent::UnexpectedError, "The VPN tunnel stopped.");
                EnterError();
            } else if (state == VpnState::Error) {
                if (fSettings.killSwitch == kKillSwitchOff)
                    RestoreDns();
                Notify();
            }
            break;

        case Event::TunnelStats:
            {
                std::lock_guard<std::mutex> lock(fLock);
                fStatus.received = event.received;
                fStatus.sent = event.sent;
            }
            if (state == VpnState::Connected)
                fListener->VpnStatusChanged(Status());
            break;

        case Event::AgentStatus: {
            const AgentStatus& agent = event.agent;
            {
                std::lock_guard<std::mutex> lock(fLock);
                if (!agent.deviceIp.empty())
                    fStatus.deviceIp = agent.deviceIp;
                if (!agent.deviceCountry.empty())
                    fStatus.deviceCountry = agent.deviceCountry;
                fStatus.forwardedPort = agent.features.forwardedPort;
            }
            if (agent.Connected()) {
                if (state == VpnState::Connecting || state == VpnState::Error) {
                    Transition(VpnState::Connected, VpnEvent::Connected);
                    EnterConnected();
                } else {
                    Notify();
                }
            } else if (agent.HardJailed()) {
                VpnEvent error = VpnEvent::UnexpectedError;
                if (agent.reasonCode == kReasonCertificateExpired)
                    error = VpnEvent::ExpiredCertificate;
                else if (agent.TwoFactorRequired())
                    error = VpnEvent::TwoFactorRequired;
                else if (agent.MaxSessions())
                    error = VpnEvent::MaximumSessionsReached;
                bool repeated = state == VpnState::Error && Status().event == error;
                if (state != VpnState::Disconnecting && state != VpnState::Disconnected
                    && !repeated) {
                    Transition(VpnState::Error, error, agent.reasonDescription);
                    EnterError();
                }
            }
            break;
        }

        case Event::AgentFailure:
            if (state == VpnState::Connecting || state == VpnState::Connected) {
                Transition(VpnState::Error, event.errorEvent, event.message);
                EnterError();
            } else {
                Log("Local agent: " + event.message);
            }
            break;

        default:
            break;
    }
}


void Connector::EnterConnecting()
{
    Connection& connection = *fCurrent;
    if (fKillSwitch != nullptr && fSettings.killSwitch != kKillSwitchOff)
        fKillSwitch->Enable(connection.request.target.physical.entryIp,
            fSettings.killSwitch == kKillSwitchAdvanced);
    Notify();
    StartTunnel(connection);
}


void Connector::StartTunnel(Connection& connection)
{
    connection.startedAt = MonotonicNow();
    connection.sink.reset(new TunnelSink(this, connection.id));
    connection.tunnel.reset(Tunnel::Create(connection.request.tunnel, connection.sink.get()));
    connection.tunnelStopped = false;
    connection.tunnel->Start();
}


void Connector::EnterConnected()
{
    if (fKillSwitch != nullptr) {
        if (fSettings.killSwitch == kKillSwitchOff)
            fKillSwitch->Disable();
        else
            fKillSwitch->Enable(fCurrent ? fCurrent->request.target.physical.entryIp : "",
                fSettings.killSwitch == kKillSwitchAdvanced);
    }
    Notify();
}


void Connector::EnterDisconnecting()
{
    Notify();
    if (!fCurrent || fCurrent->tunnelStopped) {
        Transition(VpnState::Disconnected, VpnEvent::Disconnected);
        EnterDisconnected();
        return;
    }
    StopAgent(*fCurrent);
    fCurrent->tunnel->Stop();
}


void Connector::EnterDisconnected()
{
    if (fCurrent) {
        StopAgent(*fCurrent);
        fRetired.push_back(fCurrent);
    }
    std::shared_ptr<Connection> next = fReconnection;
    fReconnection.reset();
    if (next) {
        // Keep traffic blocked on the way to the next server.
        if (fKillSwitch != nullptr && next->request.settings.killSwitch != kKillSwitchOff)
            fKillSwitch->Enable(next->request.target.physical.entryIp,
                next->request.settings.killSwitch == kKillSwitchAdvanced);
        {
            std::lock_guard<std::mutex> lock(fLock);
            fStatus.reconnecting = true;
        }
        Notify();
        fCurrent = next;
        {
            std::lock_guard<std::mutex> lock(fLock);
            fStatus.forwardedPort = 0;
            fStatus.deviceIp.clear();
            fStatus.received = fStatus.sent = 0;
        }
        Transition(VpnState::Connecting, VpnEvent::Up);
        EnterConnecting();
        return;
    }
    RestoreDns();
    if (fKillSwitch != nullptr) {
        if (fSettings.killSwitch == kKillSwitchAdvanced)
            fKillSwitch->Enable("", true);
        else
            fKillSwitch->Disable();
    }
    {
        std::lock_guard<std::mutex> lock(fLock);
        fStatus.forwardedPort = 0;
        fStatus.received = fStatus.sent = 0;
    }
    Notify();
}


void Connector::EnterError()
{
    // A failed attempt stops its tunnel; the kill switch, when on, keeps
    // blocking until the reconnection or a disconnection.
    // Errors the local agent reports leave the tunnel up (the server blocks
    // the traffic): a new certificate or a sign-in elsewhere recovers them
    // in place, as with the GTK app.
    if (fCurrent && fCurrent->tunnel && !fCurrent->tunnelStopped) {
        VpnEvent event = Status().event;
        bool keep = event == VpnEvent::DeviceDisconnected || event == VpnEvent::ExpiredCertificate
            || event == VpnEvent::MaximumSessionsReached || event == VpnEvent::TwoFactorRequired;
        if (!keep) {
            StopAgent(*fCurrent);
            fCurrent->tunnel->Stop();
        }
    }
    Notify();
}


AgentFeatures Connector::FeaturesFor(const Settings& settings, const Connection& connection) const
{
    AgentFeatures features;
    features.netshield = settings.features.netshield;
    features.randomizedNat = settings.features.moderateNat ? 0 : 1;
    features.splitTcp = settings.features.vpnAccelerator ? 1 : 0;
    features.portForwarding = settings.features.portForwarding ? 1 : 0;
    features.bouncing = connection.request.target.physical.label;
    return features;
}


void Connector::StartAgent(Connection& connection)
{
    if (connection.agentThread.joinable()) {
        if (!connection.agentDone && !connection.agentStop)
            return;   // already running
        // Finished, or stopped earlier (the tunnel went down and came back).
        connection.agentThread.join();
    }
    connection.agentStop = false;
    connection.agentDone = false;
    {
        std::lock_guard<std::mutex> lock(connection.agentLock);
        if (fUserTier > kTierFree) {
            connection.pendingFeatures = FeaturesFor(fSettings, connection);
            connection.featuresPending = true;
        }
    }
    std::shared_ptr<Connection> shared;
    if (fCurrent && fCurrent.get() == &connection)
        shared = fCurrent;
    if (!shared)
        return;
    connection.agentThread = std::thread(&Connector::AgentLoop, this, shared);
}


void Connector::StopAgent(Connection& connection)
{
    // Not joined here: the agent may sit in a connect or NAT-PMP timeout.
    // The thread holds its own reference and ends on its own.
    connection.agentStop = true;
}


void Connector::AgentLoop(std::shared_ptr<Connection> connection)
{
    struct Done {
        Connection& connection;
        ~Done() { connection.agentDone = true; }
    } done{*connection};
    int id = connection->id;
    auto post = [this, id](Event event) {
        event.connectionId = id;
        Post(event);
    };
    auto fail = [&](VpnEvent error, const std::string& message) {
        Event event(Event::AgentFailure);
        event.errorEvent = error;
        event.message = message;
        post(event);
    };
    const std::string domain = connection->request.target.physical.domain;
    int drops = 0;
    int connectFailures = 0;
    while (!connection->agentStop) {
        std::string certificate, key;
        {
            std::lock_guard<std::mutex> lock(connection->agentLock);
            certificate = connection->certificatePem;
            key = connection->keyPem;
            connection->credentialsChanged = false;
        }
        LocalAgent agent;
        std::string error;
        AgentError result = agent.Connect(domain, key, certificate, 10, error);
        if (result == AgentError::ExpiredCertificate) {
            fail(VpnEvent::ExpiredCertificate, error);
            return;
        }
        if (result == AgentError::NotYetValidCertificate) {
            fail(VpnEvent::NotYetValidCertificate, error);
            return;
        }
        if (result != AgentError::None) {
            Event log(Event::Log);
            log.message = "Local agent: " + error;
            Post(log);
            if (result == AgentError::Timeout || ++connectFailures >= 3) {
                fail(VpnEvent::Timeout, error);
                return;
            }
            for (int i = 0; i < 20 && !connection->agentStop; i++)
                usleep(100000);
            continue;
        }
        connectFailures = 0;
        {
            Event log(Event::Log);
            log.message = "Local agent connected (" + domain + ")";
            Post(log);
        }
        bool needStatus = true;
        AgentStatus last;
        bool haveLast = false;
        double lastPortRequest = -1e9;
        bool dropped = false;
        while (!connection->agentStop) {
            bool sendFeatures = false;
            AgentFeatures features;
            bool reconnect = false;
            {
                std::lock_guard<std::mutex> lock(connection->agentLock);
                if (connection->featuresPending) {
                    sendFeatures = true;
                    features = connection->pendingFeatures;
                    connection->featuresPending = false;
                }
                reconnect = connection->credentialsChanged;
            }
            if (reconnect)
                break;
            if (sendFeatures) {
                if (!agent.RequestFeatures(features, error)) {
                    dropped = true;
                    break;
                }
                needStatus = false;
            } else if (needStatus) {
                // Free plans may not request features (the agent refuses
                // them); ask for the status instead.
                if (!agent.RequestStatus(error)) {
                    dropped = true;
                    break;
                }
                needStatus = false;
            }
            AgentStatus status;
            int apiCode = 0;
            AgentError read = agent.Read((int)kAgentReadTimeoutMs, status, apiCode, error);
            double now = MonotonicNow();
            if (read == AgentError::None) {
                if (status.features.portForwarding == 1) {
                    std::string portError;
                    int port = RequestPortForwarding(portError, 5, 1);
                    lastPortRequest = now;
                    status.features.forwardedPort = port;
                    if (port == 0) {
                        Event log(Event::Log);
                        log.message = "Port forwarding: " + portError;
                        Post(log);
                    }
                }
                last = status;
                haveLast = true;
                Event event(Event::AgentStatus);
                event.agent = status;
                post(event);
            } else if (read == AgentError::Api) {
                Event log(Event::Log);
                log.message = "Local agent error " + std::to_string(apiCode) + ": " + error;
                Post(log);
            } else if (read == AgentError::Timeout) {
                if (haveLast && last.features.portForwarding == 1
                    && now - lastPortRequest >= kPortForwardingRefresh) {
                    std::string portError;
                    int port = RequestPortForwarding(portError, 5, 1);
                    lastPortRequest = now;
                    if (port != 0 && port != last.features.forwardedPort) {
                        last.features.forwardedPort = port;
                        Event event(Event::AgentStatus);
                        event.agent = last;
                        post(event);
                    }
                }
            } else {
                dropped = true;
                Event log(Event::Log);
                log.message = "Local agent: " + error;
                Post(log);
                break;
            }
        }
        agent.Close();
        if (dropped && !connection->agentStop) {
            drops++;
            double wait = RandomUnit() * 10;
            Event log(Event::Log);
            log.message = "Agent connection dropped (#" + std::to_string(drops) + "); retrying in "
                + std::to_string((int)wait) + " s";
            Post(log);
            for (int i = 0; i < wait * 10 && !connection->agentStop; i++)
                usleep(100000);
        }
    }
}


void Connector::ApplyDns(Connection& connection)
{
    std::vector<std::string> servers;
    const Settings& settings = connection.request.settings;
    if (settings.customDnsEnabled && !settings.customDns.empty()) {
        servers = settings.customDns;
    } else if (connection.request.target.protocol == kProtocolWireGuard) {
        servers.push_back("10.2.0.1");
        if (connection.request.tunnel.ipv6)
            servers.push_back("2a07:b944::2:1");
    } else {
        servers = connection.pushedDns;
        if (servers.empty())
            servers.push_back("10.2.0.1");
    }
    if (ApplyVpnDns(fResolvConf, servers, {}, "Proton VPN"))
        fDnsApplied = true;
    else
        Log("Could not update " + fResolvConf);
    Log("DNS: " + Join(servers, ", "));
}


void Connector::RestoreDns()
{
    if (!fDnsApplied)
        return;
    if (pvpn::RestoreDns(fResolvConf))
        fDnsApplied = false;
}

}  // namespace pvpn
