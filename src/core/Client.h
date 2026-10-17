// The app's core: what the GTK app's Controller, python-proton-vpn-api-core's
// ProtonVPNAPI/VPNSession/refreshers/reconnector do together. It signs in and
// out, keeps the session and VPN account in a secret store, fetches and
// refreshes the server list, loads, client configuration, feature flags and
// certificate, builds connections and reconnects after failures.
//
// The blocking calls (Login, LoadSessionData, Logout, ...) are for worker
// threads; listener callbacks arrive on internal threads.
#pragma once
#include "Account.h"
#include "Api.h"
#include "Connector.h"
#include "KillSwitch.h"
#include "ServerList.h"
#include "Settings.h"
#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace pvpn {

struct ClientPaths {
    std::string settingsDirectory;   // settings.json, app-config.json
    std::string cacheDirectory;      // serverlist.json, clientconfig.json, ...
    std::string runtimeDirectory;    // per-connection scratch space
    std::string openvpnPath;         // proton-openvpn
    std::string wireguardPath;       // proton-wireguard
    std::string resolvConf;          // empty: Haiku's
};

// Where the session tokens and the VPN account (with its private key) live:
// the Haiku key store in the app, a mode 600 file in tests.
class SecretStore {
public:
    virtual ~SecretStore() {}
    virtual bool Load(std::string& data) = 0;
    virtual bool Save(const std::string& data) = 0;
    virtual void Remove() = 0;
};

class FileSecretStore : public SecretStore {
public:
    explicit FileSecretStore(const std::string& path) : fPath(path) {}
    bool Load(std::string& data) override;
    bool Save(const std::string& data) override;
    void Remove() override;

private:
    std::string fPath;
};

enum class LoginStatus {
    Success,
    TwoFactorRequired,
    Failed,
};

struct LoginOutcome {
    LoginStatus status = LoginStatus::Failed;
    ApiResult result;
};

// Dialogs the reconnector and session handling ask the UI to show.
enum class ClientNotice {
    SessionExpired,           // "Invalid Session"
    VpnConnectionError,       // AuthDenied: "VPN connection error"
    TwoFactorRequired,        // "2FA Required"
    UpdateSystemClock,        // "Update system clock"
    SessionLimitReached,      // "Connection error: session limit reached"
    PortForwardChanged,       // "Port forwarding" desktop notification
};

class ClientListener {
public:
    virtual ~ClientListener() {}
    virtual void ServerListChanged() {}
    virtual void AccountChanged() {}
    virtual void ConnectionChanged(const VpnStatus& status) {}
    virtual void Notice(ClientNotice notice, const std::string& detail) {}
    virtual void Log(const std::string& line) {}
};

class Client : private ConnectorListener {
public:
    Client(const ClientPaths& paths, SecretStore* secrets, ClientListener* listener,
        const ApiEnvironment& environment = ApiEnvironment::Default());
    ~Client();

    // --- Session --------------------------------------------------------------
    // Restores a stored session (and the cached data); true if signed in.
    bool RestoreSession();
    bool LoggedIn() const;
    std::string AccountName() const;
    LoginOutcome Login(const std::string& username, const std::string& password);
    LoginOutcome SubmitTwoFactorCode(const std::string& code);
    // Disconnects, revokes the session, forgets the data and the settings.
    ApiResult Logout();
    // Signed in but the session data still needs loading.
    bool SessionDataLoaded() const;
    // Fetches VPN info, certificate, location, client config, feature flags
    // and the server list (VPNSession.fetch_session_data).
    ApiResult LoadSessionData();
    ApiResult RefreshAccountInfo();

    // --- Data -----------------------------------------------------------------
    std::shared_ptr<const ServerList> Servers() const;
    VpnAccount Account() const;
    ClientConfig Config() const;
    FeatureFlags Flags() const;
    int UserTier() const;
    std::string PlanTitle() const;
    // The FreeRescope rules: free users only connect to free countries.
    bool ServerSelectionRequiresUpgrade() const;

    Settings GetSettings() const;
    void SetSettings(const Settings& settings);
    AppConfig GetAppConfig() const;
    void SetAppConfig(const AppConfig& config);

    // Starts and stops the background refresher and the reconnector.
    void StartBackground();
    void StopBackground();

    // --- Connections -----------------------------------------------------------
    // The connect calls return false (with a reason) when no server fits.
    bool ConnectFastest(std::string& error);
    bool ConnectCountry(const std::string& code, std::string& error);
    bool ConnectLocation(const std::string& code, const std::string& location, std::string& error);
    bool ConnectSecureCore(const std::string& exitCountry, std::string& error);
    bool ConnectServer(const std::string& name, std::string& error);
    bool ConnectServerId(const std::string& id, std::string& error);
    // "FASTEST", a server name with '#', or a country code (auto connect and
    // tray pins).
    bool ConnectByCode(const std::string& code, std::string& error);
    void Disconnect();
    bool WaitForDisconnected(double seconds);
    VpnStatus Status() const;

    // The country of the last country-level connection (for Change server).
    std::string LastRequestedCountry() const;

private:
    void VpnStatusChanged(const VpnStatus& status) override;
    void VpnLog(const std::string& line) override;

    void SaveSecrets();
    void LoadCaches();
    void ClearCaches();
    void SaveServerList();
    ApiResult FetchServerList(bool full);
    ApiResult FetchCertificate();
    ApiResult FetchClientConfig();
    ApiResult FetchFeatureFlags();
    ApiResult FetchLocation();
    std::string NetzoneHeader() const;
    bool StartConnection(const LogicalServer& server, std::string& error);
    void HandleApiError(const ApiResult& result);
    void BackgroundLoop();
    void ScheduleReconnect();
    void Emit(const std::string& line);

    ClientPaths fPaths;
    SecretStore* fSecrets;
    ClientListener* fListener;
    ApiSession fApi;
    Connector fConnector;
    std::unique_ptr<RouteKillSwitch> fKillSwitch;

    mutable std::mutex fLock;
    bool fLoaded = false;
    VpnAccount fAccount;
    bool fHaveAccount = false;
    std::shared_ptr<ServerList> fServers;
    ClientConfig fConfig;
    FeatureFlags fFlags;
    mutable Settings fSettings;
    mutable bool fSettingsLoaded = false;
    AppConfig fAppConfig;
    std::string fLastCountry;

    // Background work.
    std::thread fBackground;
    std::condition_variable fWake;
    bool fBackgroundRunning = false;
    bool fStopping = false;
    // Shared by the background thread and the connector's callbacks.
    std::atomic<double> fCertificateRetry{0};
    std::atomic<int> fCertificateFailures{0};
    std::atomic<bool> fForceCertificateRefresh{false};
    double fLocationNext = 0;
    // Reconnector.
    std::atomic<bool> fReconnectEnabled{false};
    std::atomic<int> fRetries{0};
    std::atomic<double> fReconnectAt{0};     // 0: none scheduled
    std::string fReconnectServerId;          // guarded by fLock
    std::string fReconnectProtocol;
    std::atomic<bool> fNetworkUp{true};
    VpnState fLastState = VpnState::Disconnected;   // connector thread only
    int fLastForwardedPort = 0;
};

}  // namespace pvpn
