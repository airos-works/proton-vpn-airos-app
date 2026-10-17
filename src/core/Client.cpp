#include "Client.h"
#include "Network.h"
#include "ProtonCa.h"
#include "ResolvConf.h"
#include "Util.h"
#include <cmath>
#include <future>
#include <sys/utsname.h>
#include <unistd.h>

namespace pvpn {

namespace {

const char kLogicalsEndpoint[] = "/vpn/v1/logicals?SecureCoreFilter=all&WithState=true";
const char kLoadsEndpoint[] = "/vpn/v1/loads";
const char kEpoch[] = "Thu, 01 Jan 1970 00:00:00 GMT";
const int kCertificateDurationMinutes = 7 * 24 * 60;
const double kMaxCertificateBackoff = 7 * 24 * 3600;
const double kNetworkPollSeconds = 5;

std::string TruncatedIp(const std::string& ip)
{
    std::vector<std::string> parts = Split(ip, '.');
    if (parts.size() != 4)
        return std::string();
    return parts[0] + "." + parts[1] + "." + parts[2] + ".0";
}

Json CertificateFeatures(const Features& features)
{
    // VPNSessionFetcher._convert_features
    Json result = Json::object();
    if (!features.moderateNat)
        result["RandomNAT"] = false;
    if (!features.vpnAccelerator)
        result["SplitTCP"] = false;
    if (features.portForwarding)
        result["PortForwarding"] = true;
    if (features.netshield != 0)
        result["NetShieldLevel"] = features.netshield;
    return result;
}

}  // namespace


bool FileSecretStore::Load(std::string& data)
{
    return ReadFile(fPath, data);
}


bool FileSecretStore::Save(const std::string& data)
{
    return WriteFile(fPath, data, 0600);
}


void FileSecretStore::Remove()
{
    unlink(fPath.c_str());
}


Client::Client(const ClientPaths& paths, SecretStore* secrets, ClientListener* listener,
    const ApiEnvironment& environment)
    :
    fPaths(paths),
    fSecrets(secrets),
    fListener(listener),
    fApi(environment),
    fConnector(this),
    fConfig(ClientConfig::Default())
{
    MakeDirectories(fPaths.settingsDirectory, 0700);
    MakeDirectories(fPaths.cacheDirectory, 0700);
    MakeDirectories(fPaths.runtimeDirectory, 0700);
    if (!fPaths.resolvConf.empty())
        fConnector.SetResolvConfPath(fPaths.resolvConf);
    // A crash may have left our name servers behind.
    RestoreDns(fPaths.resolvConf.empty() ? kResolvConfPath : fPaths.resolvConf);
#if defined(__HAIKU__)
    fKillSwitch.reset(new RouteKillSwitch(fPaths.settingsDirectory + "/killswitch"));
    fKillSwitch->Restore();
    fConnector.SetKillSwitch(fKillSwitch.get());
#endif
    fApi.SetTokensChangedHandler([this](const SessionTokens&) { SaveSecrets(); });
    std::string text;
    if (ReadFile(fPaths.settingsDirectory + "/app-config.json", text))
        fAppConfig = AppConfig::FromJson(ParseJson(text));
}


Client::~Client()
{
    StopBackground();
}


void Client::Emit(const std::string& line)
{
    fListener->Log(line);
}


// --- Session -------------------------------------------------------------------

void Client::SaveSecrets()
{
    SessionTokens tokens = fApi.Tokens();
    if (!tokens.Authenticated()) {
        fSecrets->Remove();
        return;
    }
    Json data = {{"tokens", tokens.ToJson()}};
    {
        std::lock_guard<std::mutex> lock(fLock);
        if (fHaveAccount)
            data["vpn"] = fAccount.ToJson();
    }
    if (!fSecrets->Save(data.dump()))
        Emit("Could not store the session.");
}


bool Client::RestoreSession()
{
    std::string text;
    if (!fSecrets->Load(text))
        return false;
    Json data = ParseJson(text);
    if (data.is_discarded())
        return false;
    SessionTokens tokens = SessionTokens::FromJson(JsonObject(data, "tokens"));
    if (!tokens.Authenticated())
        return false;
    fApi.Restore(tokens);
    VpnAccount account;
    if (VpnAccount::FromJson(JsonObject(data, "vpn"), account)) {
        std::lock_guard<std::mutex> lock(fLock);
        fAccount = account;
        fHaveAccount = true;
    }
    LoadCaches();
    return fApi.LoggedIn();
}


bool Client::LoggedIn() const
{
    return fApi.LoggedIn();
}


std::string Client::AccountName() const
{
    return fApi.AccountName();
}


LoginOutcome Client::Login(const std::string& username, const std::string& password)
{
    LoginOutcome outcome;
    outcome.result = fApi.Login(username, password);
    if (!outcome.result.Ok())
        return outcome;
    outcome.status = fApi.NeedsTwoFactor() ? LoginStatus::TwoFactorRequired : LoginStatus::Success;
    Emit("Signed in as " + username
        + (outcome.status == LoginStatus::TwoFactorRequired ? " (two-factor code needed)" : ""));
    return outcome;
}


LoginOutcome Client::SubmitTwoFactorCode(const std::string& code)
{
    LoginOutcome outcome;
    outcome.result = fApi.ProvideTwoFactorCode(code);
    if (outcome.result.Ok())
        outcome.status = fApi.NeedsTwoFactor() ? LoginStatus::TwoFactorRequired : LoginStatus::Success;
    return outcome;
}


ApiResult Client::Logout()
{
    if (fConnector.Status().state != VpnState::Disconnected) {
        fConnector.Disconnect();
        fConnector.WaitForDisconnected(15);
    }
    StopBackground();
    ApiResult result = fApi.Logout();
    if (!result.Ok())
        return result;
    {
        std::lock_guard<std::mutex> lock(fLock);
        fLoaded = false;
        fHaveAccount = false;
        fAccount = VpnAccount();
        fServers.reset();
        fConfig = ClientConfig::Default();
        fFlags = FeatureFlags();
        fSettings = Settings();
        fSettingsLoaded = false;
    }
    ClearCaches();
    // As the Linux app, settings go back to their defaults.
    unlink((fPaths.settingsDirectory + "/settings.json").c_str());
    fSecrets->Remove();
    Emit("Signed out");
    return result;
}


bool Client::SessionDataLoaded() const
{
    std::lock_guard<std::mutex> lock(fLock);
    return fLoaded;
}


void Client::HandleApiError(const ApiResult& result)
{
    if (result.error != ApiError::AuthenticationNeeded)
        return;
    bool notify;
    {
        std::lock_guard<std::mutex> lock(fLock);
        notify = fLoaded;
        fLoaded = false;
    }
    fApi.ClearLocal();
    if (!notify)
        return;   // reported already
    Emit("The session has expired.");
    fListener->Notice(ClientNotice::SessionExpired, result.message);
}


std::string Client::NetzoneHeader() const
{
    std::lock_guard<std::mutex> lock(fLock);
    return TruncatedIp(fAccount.location.ip);
}


ApiResult Client::LoadSessionData()
{
    Ed25519Key key;
    {
        std::lock_guard<std::mutex> lock(fLock);
        if (fHaveAccount && fAccount.key.IsValid())
            key = fAccount.key;
    }
    if (!key.IsValid())
        key = Ed25519Key::Generate();
    Features features = GetSettings().features;

    auto vpnInfo = std::async(std::launch::async, [this] { return fApi.Request("/vpn/v2"); });
    auto certificate = std::async(std::launch::async, [this, &key, features] {
        return fApi.Request("/vpn/v1/certificate", Json{{"ClientPublicKey", key.PublicPem()},
            {"Duration", std::to_string(kCertificateDurationMinutes) + " min"},
            {"Features", CertificateFeatures(features)}});
    });
    auto location = std::async(std::launch::async, [this] { return fApi.Request("/vpn/v1/location"); });
    auto clientConfig = std::async(std::launch::async,
        [this] { return fApi.Request("/vpn/v2/clientconfig"); });
    auto flags = std::async(std::launch::async,
        [this] { return fApi.Request("/feature/v2/frontend"); });

    ApiResult info = vpnInfo.get();
    ApiResult cert = certificate.get();
    ApiResult where = location.get();
    ApiResult config = clientConfig.get();
    ApiResult toggles = flags.get();
    for (ApiResult* result : {&info, &cert, &where}) {
        if (!result->Ok()) {
            HandleApiError(*result);
            return *result;
        }
    }
    VpnAccount account;
    account.key = key;
    if (!VpnInfo::FromJson(info.json, account.info)) {
        info.error = ApiError::Api;
        info.message = "The VPN account information could not be read.";
        return info;
    }
    if (!VpnCertificate::FromJson(cert.json, account.certificate)) {
        cert.error = ApiError::Api;
        cert.message = "The VPN certificate could not be read.";
        return cert;
    }
    CertificateInfo certificateInfo;
    if (!ParseCertificatePem(account.certificate.certificate, certificateInfo)
        || certificateInfo.fingerprint != key.Fingerprint()) {
        cert.error = ApiError::Crypto;
        cert.message = "The VPN certificate does not match the key.";
        return cert;
    }
    Json locationJson = where.json;
    locationJson["ExpirationTime"] = Now() + VpnLocation::kRefreshSeconds;
    account.location = VpnLocation::FromJson(locationJson);
    {
        std::lock_guard<std::mutex> lock(fLock);
        fAccount = account;
        fHaveAccount = true;
        ClientConfig parsed;
        if (config.Ok() && ClientConfig::FromJson(config.json, parsed))
            fConfig = parsed;
        if (toggles.Ok())
            fFlags = FeatureFlags(toggles.json);
    }
    WriteFile(fPaths.cacheDirectory + "/clientconfig.json", Config().ToJson().dump(), 0600);
    WriteFile(fPaths.cacheDirectory + "/featureflags.json", Flags().ToJson().dump(), 0600);
    SaveSecrets();

    ApiResult servers = FetchServerList(true);
    if (!servers.Ok()) {
        HandleApiError(servers);
        return servers;
    }
    {
        std::lock_guard<std::mutex> lock(fLock);
        fLoaded = true;
    }
    Emit("Session data loaded: " + account.info.planTitle + ", tier "
        + std::to_string(account.info.maxTier) + ", " + std::to_string(Servers()->Size())
        + " servers");
    fListener->AccountChanged();
    fListener->ServerListChanged();
    return servers;
}


ApiResult Client::RefreshAccountInfo()
{
    ApiResult result = fApi.Request("/vpn/v2");
    if (!result.Ok()) {
        HandleApiError(result);
        return result;
    }
    VpnInfo info;
    if (VpnInfo::FromJson(result.json, info)) {
        {
            std::lock_guard<std::mutex> lock(fLock);
            fAccount.info = info;
        }
        SaveSecrets();
        fListener->AccountChanged();
    }
    return result;
}


ApiResult Client::RefreshServerList()
{
    ApiResult config = FetchClientConfig();
    if (config.error == ApiError::AuthenticationNeeded)
        return config;
    ApiResult result = FetchServerList(true);
    if (result.Ok())
        fListener->ServerListChanged();
    else
        HandleApiError(result);
    return result;
}


ApiResult Client::SubmitBugReport(const std::string& username, const std::string& email,
    const std::string& description, const std::vector<std::string>& attachments,
    const std::string& clientVersion)
{
    std::string os = "Haiku";
    std::string osVersion;
    std::string text;
#if defined(__HAIKU__)
    os = "air/OS (Haiku)";
#endif
    struct utsname name;
    if (uname(&name) == 0)
        osVersion = std::string(name.release) + " " + name.version;
    std::vector<FormField> fields = {
        {"OS", os, "", ""},
        {"OSVersion", osVersion, "", ""},
        {"Client", "Linux GUI", "", ""},
        {"ClientVersion", clientVersion, "", ""},
        {"ClientType", "2", "", ""},
        {"Title", "Report from Linux app (air/OS port)", "", ""},
        {"Description", description, "", ""},
        {"Username", username, "", ""},
        {"Email", email, "", ""},
    };
    VpnAccount account = Account();
    if (!account.location.isp.empty() || !account.location.country.empty()) {
        fields.push_back({"ISP", account.location.isp, "", ""});
        fields.push_back({"Country", account.location.country, "", ""});
    }
    int index = 0;
    for (const std::string& path : attachments) {
        std::string contents;
        if (!ReadFile(path, contents))
            continue;
        // Keep attachments reasonable: the end of large logs matters most.
        if (contents.size() > 2 * 1024 * 1024)
            contents = contents.substr(contents.size() - 2 * 1024 * 1024);
        std::string filename = path.substr(path.rfind('/') + 1);
        fields.push_back({"Attachment-" + std::to_string(index++), contents, filename, "text/plain"});
    }
    ApiResult result = fApi.RequestForm("/core/v4/reports/bug", fields);
    HandleApiError(result);
    return result;
}


// --- Data ------------------------------------------------------------------------

void Client::LoadCaches()
{
    std::string text;
    std::lock_guard<std::mutex> lock(fLock);
    if (ReadFile(fPaths.cacheDirectory + "/serverlist.json", text)) {
        std::shared_ptr<ServerList> servers = std::make_shared<ServerList>();
        if (servers->LoadCache(ParseJson(text)))
            fServers = servers;
    }
    if (ReadFile(fPaths.cacheDirectory + "/clientconfig.json", text)) {
        ClientConfig config;
        if (ClientConfig::FromJson(ParseJson(text), config))
            fConfig = config;
    }
    if (ReadFile(fPaths.cacheDirectory + "/featureflags.json", text))
        fFlags = FeatureFlags(ParseJson(text));
    fLoaded = fHaveAccount && fServers && !fServers->Empty();
}


void Client::ClearCaches()
{
    for (const char* name : {"serverlist.json", "clientconfig.json", "featureflags.json"})
        unlink((fPaths.cacheDirectory + "/" + name).c_str());
}


void Client::SaveServerList()
{
    std::shared_ptr<const ServerList> servers = Servers();
    if (servers)
        WriteFile(fPaths.cacheDirectory + "/serverlist.json", servers->ToCache().dump(), 0600);
}


std::shared_ptr<const ServerList> Client::Servers() const
{
    std::lock_guard<std::mutex> lock(fLock);
    return fServers;
}


VpnAccount Client::Account() const
{
    std::lock_guard<std::mutex> lock(fLock);
    return fAccount;
}


ClientConfig Client::Config() const
{
    std::lock_guard<std::mutex> lock(fLock);
    return fConfig;
}


FeatureFlags Client::Flags() const
{
    std::lock_guard<std::mutex> lock(fLock);
    return fFlags;
}


int Client::UserTier() const
{
    std::lock_guard<std::mutex> lock(fLock);
    return fHaveAccount ? fAccount.info.maxTier : 0;
}


std::string Client::PlanTitle() const
{
    std::lock_guard<std::mutex> lock(fLock);
    return fHaveAccount && !fAccount.info.planTitle.empty() ? fAccount.info.planTitle : "Free";
}


bool Client::ServerSelectionRequiresUpgrade() const
{
    return UserTier() == kTierFree && Flags().Get("FreeRescope");
}


ApiResult Client::FetchServerList(bool full)
{
    std::shared_ptr<const ServerList> current = Servers();
    std::string netzone = NetzoneHeader();
    std::vector<std::pair<std::string, std::string>> headers;
    if (!netzone.empty())
        headers.push_back({"X-PM-netzone", netzone});
    if (full || !current || current->Empty()) {
        headers.push_back({"If-Modified-Since", current && !current->Empty()
            ? current->LastModified() : std::string(kEpoch)});
        ApiResult result = fApi.Request(kLogicalsEndpoint, Json(), "GET", headers);
        if (!result.Ok())
            return result;
        std::shared_ptr<ServerList> servers = std::make_shared<ServerList>();
        if (result.httpStatus == 304 && current) {
            *servers = *current;
            servers->ResetExpiration();
            servers->ResetLoadsExpiration();
        } else if (!servers->LoadApiReply(result.json, UserTier(), result.Header("last-modified"))) {
            result.error = ApiError::Api;
            result.message = "The server list could not be read.";
            return result;
        }
        servers->SetUserTier(UserTier());
        {
            std::lock_guard<std::mutex> lock(fLock);
            fServers = servers;
        }
        SaveServerList();
        Emit("Server list updated (" + std::to_string(servers->Size()) + " servers)");
        return result;
    }
    headers.push_back({"If-Modified-Since", kEpoch});
    ApiResult result = fApi.Request(kLoadsEndpoint, Json(), "GET", headers);
    if (!result.Ok())
        return result;
    std::shared_ptr<ServerList> servers = std::make_shared<ServerList>(*current);
    servers->UpdateLoads(result.json);
    {
        std::lock_guard<std::mutex> lock(fLock);
        fServers = servers;
    }
    SaveServerList();
    Emit("Server loads updated");
    return result;
}


ApiResult Client::FetchCertificate()
{
    Ed25519Key key;
    {
        std::lock_guard<std::mutex> lock(fLock);
        key = fAccount.key;
    }
    ApiResult result = fApi.Request("/vpn/v1/certificate", Json{{"ClientPublicKey", key.PublicPem()},
        {"Duration", std::to_string(kCertificateDurationMinutes) + " min"},
        {"Features", CertificateFeatures(GetSettings().features)}});
    if (!result.Ok())
        return result;
    VpnCertificate certificate;
    CertificateInfo info;
    if (!VpnCertificate::FromJson(result.json, certificate)
        || !ParseCertificatePem(certificate.certificate, info)
        || info.fingerprint != key.Fingerprint()) {
        result.error = ApiError::Crypto;
        result.message = "The new VPN certificate does not match the key.";
        return result;
    }
    {
        std::lock_guard<std::mutex> lock(fLock);
        fAccount.certificate = certificate;
    }
    SaveSecrets();
    Emit("Certificate refreshed (valid until " + std::to_string(certificate.expirationTime) + ")");
    VpnState state = fConnector.Status().state;
    if (state == VpnState::Connected || state == VpnState::Error)
        fConnector.UpdateCredentials(certificate.certificate, key.PrivatePem());
    return result;
}


ApiResult Client::FetchClientConfig()
{
    ApiResult result = fApi.Request("/vpn/v2/clientconfig");
    HandleApiError(result);
    ClientConfig config;
    if (result.Ok() && ClientConfig::FromJson(result.json, config)) {
        {
            std::lock_guard<std::mutex> lock(fLock);
            fConfig = config;
        }
        WriteFile(fPaths.cacheDirectory + "/clientconfig.json", config.ToJson().dump(), 0600);
    } else {
        std::lock_guard<std::mutex> lock(fLock);
        // Try again in a while; ports keep their previous values.
        fConfig.expirationTime = Now() + ServerList::kLoadsRefreshSeconds;
    }
    return result;
}


ApiResult Client::FetchFeatureFlags()
{
    ApiResult result = fApi.Request("/feature/v2/frontend");
    HandleApiError(result);
    {
        std::lock_guard<std::mutex> lock(fLock);
        if (result.Ok())
            fFlags = FeatureFlags(result.json);
        else
            fFlags = FeatureFlags(Json{{"toggles", JsonArray(fFlags.ToJson(), "toggles")},
                {"ExpirationTime", Now() + ServerList::kLoadsRefreshSeconds}});
    }
    if (result.Ok())
        WriteFile(fPaths.cacheDirectory + "/featureflags.json", Flags().ToJson().dump(), 0600);
    return result;
}


ApiResult Client::FetchLocation()
{
    ApiResult result = fApi.Request("/vpn/v1/location");
    HandleApiError(result);
    if (result.Ok()) {
        Json json = result.json;
        json["ExpirationTime"] = Now() + VpnLocation::kRefreshSeconds;
        {
            std::lock_guard<std::mutex> lock(fLock);
            fAccount.location = VpnLocation::FromJson(json);
        }
        SaveSecrets();
    }
    return result;
}


Settings Client::GetSettings() const
{
    {
        std::lock_guard<std::mutex> lock(fLock);
        if (fSettingsLoaded)
            return fSettings;
    }
    std::string text;
    int tier = UserTier();
    Settings settings = Settings::Default(tier);
    bool exists = ReadFile(fPaths.settingsDirectory + "/settings.json", text);
    if (exists)
        settings = Settings::FromJson(ParseJson(text), tier);
    std::lock_guard<std::mutex> lock(fLock);
    // Defaults depend on the tier, so only a stored file is final.
    if (exists) {
        fSettings = settings;
        fSettingsLoaded = true;
    }
    return settings;
}


void Client::SetSettings(const Settings& settings)
{
    {
        std::lock_guard<std::mutex> lock(fLock);
        fSettings = settings;
        fSettingsLoaded = true;
    }
    WriteFile(fPaths.settingsDirectory + "/settings.json", settings.ToJson().dump(2), 0600);
    fConnector.ApplySettings(settings, UserTier());
}


AppConfig Client::GetAppConfig() const
{
    std::lock_guard<std::mutex> lock(fLock);
    return fAppConfig;
}


void Client::SetAppConfig(const AppConfig& config)
{
    {
        std::lock_guard<std::mutex> lock(fLock);
        fAppConfig = config;
    }
    WriteFile(fPaths.settingsDirectory + "/app-config.json", config.ToJson().dump(2), 0600);
}


// --- Background ------------------------------------------------------------------

void Client::StartBackground()
{
    std::lock_guard<std::mutex> lock(fLock);
    if (fBackgroundRunning)
        return;
    fBackgroundRunning = true;
    fStopping = false;
    fReconnectEnabled = true;
    fRetries = 0;
    fLocationNext = 0;
    fBackground = std::thread(&Client::BackgroundLoop, this);
}


void Client::StopBackground()
{
    {
        std::lock_guard<std::mutex> lock(fLock);
        if (!fBackgroundRunning)
            return;
        fStopping = true;
        fReconnectEnabled = false;
        fReconnectAt = 0;
    }
    fWake.notify_all();
    if (fBackground.joinable())
        fBackground.join();
    std::lock_guard<std::mutex> lock(fLock);
    fBackgroundRunning = false;
}


void Client::BackgroundLoop()
{
    double lastNetworkCheck = 0;
    while (true) {
        {
            std::unique_lock<std::mutex> lock(fLock);
            fWake.wait_for(lock, std::chrono::seconds(1), [this] { return fStopping; });
            if (fStopping)
                return;
        }
        if (!fApi.LoggedIn() || !SessionDataLoaded())
            continue;
        double now = Now();
        double monotonic = MonotonicNow();

        // Server list: the full list every 3 h, loads every 15 min.
        std::shared_ptr<const ServerList> servers = Servers();
        if (servers && (now > servers->ExpirationTime() || now > servers->LoadsExpirationTime())) {
            bool full = now > servers->ExpirationTime();
            ApiResult result = FetchServerList(full);
            if (result.Ok()) {
                fListener->ServerListChanged();
            } else {
                HandleApiError(result);
                Emit("Server list refresh failed: " + result.message);
                std::shared_ptr<ServerList> retry = std::make_shared<ServerList>(*servers);
                retry->ResetLoadsExpiration();
                std::lock_guard<std::mutex> lock(fLock);
                if (fServers.get() == servers.get())
                    fServers = retry;
            }
        }
        if (Config().Expired())
            FetchClientConfig();
        if (now > Flags().ExpirationTime())
            FetchFeatureFlags();

        // Certificate: at its refresh time, or now when it expired on a server.
        VpnAccount account = Account();
        bool due = account.Valid() && (now >= account.certificate.refreshTime
            || fForceCertificateRefresh);
        if (due && monotonic >= fCertificateRetry) {
            ApiResult result = FetchCertificate();
            if (result.Ok()) {
                fForceCertificateRefresh = false;
                fCertificateFailures = 0;
                fCertificateRetry = 0;
            } else {
                HandleApiError(result);
                double backoff = std::min(std::pow(2.0, (int)fCertificateFailures++) * Jitter(0.22),
                    kMaxCertificateBackoff);
                fCertificateRetry = monotonic + backoff;
                Emit("Certificate refresh failed (" + result.message + "); retrying in "
                    + std::to_string((int)backoff) + " s");
            }
        }

        // Location, while not connected (connected, it is the VPN's).
        VpnStatus status = fConnector.Status();
        if (status.state == VpnState::Disconnected && account.location.Expired()
            && monotonic >= fLocationNext) {
            fLocationNext = monotonic + 60;
            FetchLocation();
        }

        // Network monitor.
        if (monotonic - lastNetworkCheck >= kNetworkPollSeconds) {
            lastNetworkCheck = monotonic;
            bool up = HasDefaultRoute() || status.state == VpnState::Connected;
            if (up && !fNetworkUp) {
                Emit("The network is back.");
                fRetries = 0;
                if (status.state == VpnState::Error && fReconnectEnabled
                    && status.event != VpnEvent::AuthDenied
                    && status.event != VpnEvent::MaximumSessionsReached)
                    fReconnectAt = monotonic + 1;
            }
            fNetworkUp = up;
        }

        // Reconnector.
        if (fReconnectAt > 0 && monotonic >= fReconnectAt && fReconnectEnabled) {
            fReconnectAt = 0;
            if (fConnector.Status().state != VpnState::Error)
                continue;
            if (!fNetworkUp) {
                fRetries++;
                ScheduleReconnect();
                continue;
            }
            std::string serverId;
            {
                std::lock_guard<std::mutex> lock(fLock);
                serverId = fReconnectServerId;
            }
            std::shared_ptr<const ServerList> list = Servers();
            const LogicalServer* server = list ? list->ById(serverId) : nullptr;
            if (server == nullptr) {
                Emit("The server to reconnect to is gone.");
                continue;
            }
            Emit("Reconnecting to " + server->name + " (attempt " + std::to_string(fRetries + 1) + ")");
            fRetries++;
            std::string error;
            if (!StartConnection(*server, error))
                Emit("Reconnection failed: " + error);
        }
    }
}


void Client::ScheduleReconnect()
{
    double delay = std::pow(2.0, std::min((int)fRetries, 12)) * (0.9 + 0.2 * RandomUnit());
    fReconnectAt = MonotonicNow() + delay;
    Emit("Reconnecting in " + std::to_string((int)std::ceil(delay)) + " s");
}


// --- Connections -----------------------------------------------------------------

bool Client::StartConnection(const LogicalServer& server, std::string& error)
{
    if (!fApi.LoggedIn()) {
        error = "Log in required before starting VPN connections.";
        return false;
    }
    VpnAccount account = Account();
    if (!account.Valid()) {
        error = "The VPN account is not loaded yet.";
        return false;
    }
    const PhysicalServer* physical = server.PickPhysical();
    if (physical == nullptr) {
        error = "No physical servers could be found";
        return false;
    }
    Settings settings = GetSettings();
    ClientConfig config = Config();
    static int sCounter = 0;

    ConnectionRequest request;
    request.target.logical = server;
    request.target.physical = *physical;
    request.target.protocol = settings.protocol;
    request.settings = settings;
    request.userTier = account.info.maxTier;
    TunnelConfig& tunnel = request.tunnel;
    tunnel.protocol = settings.protocol;
    tunnel.serverIp = physical->entryIp;
    tunnel.domain = physical->domain;
    tunnel.serverPublicKey = physical->x25519PublicKey;
    tunnel.ipv6 = settings.ipv6 && server.Has(kFeatureIPv6);
    if (settings.protocol == kProtocolWireGuard)
        tunnel.ports = config.wireguard.udp;
    else if (settings.protocol == kProtocolOpenVpnTcp)
        tunnel.ports = config.openvpn.tcp;
    else
        tunnel.ports = config.openvpn.udp;
    if (tunnel.ports.empty())
        tunnel.ports.push_back(settings.protocol == kProtocolOpenVpnTcp ? 443 : 51820);
    tunnel.certificatePem = account.certificate.certificate;
    tunnel.privateKeyPem = account.key.PrivatePem();
    tunnel.wireguardPrivateKey = account.key.WireGuardPrivateBase64();
    tunnel.runtimeDirectory = fPaths.runtimeDirectory + "/connection-" + std::to_string(getpid())
        + "-" + std::to_string(++sCounter);
    tunnel.openvpnPath = fPaths.openvpnPath;
    tunnel.wireguardPath = fPaths.wireguardPath;
    tunnel.openvpnCaPem = OpenVpnCaPem();
    Emit("Connecting to " + server.name + " (" + physical->domain + ", " + physical->entryIp + ") over "
        + ProtocolTitle(settings.protocol));
    {
        std::lock_guard<std::mutex> lock(fLock);
        fReconnectServerId = server.id;
        fReconnectProtocol = settings.protocol;
    }
    fConnector.Connect(request);
    return true;
}


bool Client::ConnectFastest(std::string& error)
{
    std::shared_ptr<const ServerList> servers = Servers();
    const LogicalServer* server = servers ? servers->Fastest(UserTier()) : nullptr;
    if (server == nullptr) {
        error = "No server available in the current tier";
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(fLock);
        fLastCountry.clear();
    }
    return StartConnection(*server, error);
}


bool Client::ConnectCountry(const std::string& code, std::string& error)
{
    std::shared_ptr<const ServerList> servers = Servers();
    const LogicalServer* server = servers ? servers->FastestInCountry(code, UserTier()) : nullptr;
    if (server == nullptr) {
        error = "No server available in the current tier";
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(fLock);
        fLastCountry = ToUpper(code);
    }
    return StartConnection(*server, error);
}


bool Client::ConnectLocation(const std::string& code, const std::string& location,
    std::string& error)
{
    std::shared_ptr<const ServerList> servers = Servers();
    const LogicalServer* server = servers
        ? servers->FastestInLocation(code, location, UserTier()) : nullptr;
    if (server == nullptr) {
        error = "No server available in the current tier";
        return false;
    }
    return StartConnection(*server, error);
}


bool Client::ConnectSecureCore(const std::string& exitCountry, std::string& error)
{
    std::shared_ptr<const ServerList> servers = Servers();
    const LogicalServer* server = servers
        ? servers->FastestSecureCore(exitCountry, UserTier()) : nullptr;
    if (server == nullptr) {
        error = "No server available in the current tier";
        return false;
    }
    return StartConnection(*server, error);
}


bool Client::ConnectServer(const std::string& name, std::string& error)
{
    std::shared_ptr<const ServerList> servers = Servers();
    const LogicalServer* server = servers ? servers->ByName(name) : nullptr;
    if (server == nullptr) {
        error = "The server with name='" + name + "' was not found";
        return false;
    }
    return StartConnection(*server, error);
}


bool Client::ConnectServerId(const std::string& id, std::string& error)
{
    std::shared_ptr<const ServerList> servers = Servers();
    const LogicalServer* server = servers ? servers->ById(id) : nullptr;
    if (server == nullptr) {
        error = "The server was not found";
        return false;
    }
    return StartConnection(*server, error);
}


bool Client::ConnectByCode(const std::string& code, std::string& error)
{
    std::string upper = ToUpper(Trim(code));
    if (upper == "FASTEST")
        return ConnectFastest(error);
    if (upper.find('#') != std::string::npos)
        return ConnectServer(upper, error);
    return ConnectCountry(upper, error);
}


void Client::Disconnect()
{
    {
        std::lock_guard<std::mutex> lock(fLock);
        fReconnectAt = 0;
    }
    fConnector.Disconnect();
}


bool Client::WaitForDisconnected(double seconds)
{
    return fConnector.WaitForDisconnected(seconds);
}


VpnStatus Client::Status() const
{
    return fConnector.Status();
}


std::string Client::LastRequestedCountry() const
{
    std::lock_guard<std::mutex> lock(fLock);
    return fLastCountry;
}


void Client::VpnStatusChanged(const VpnStatus& status)
{
    bool entered = status.state != fLastState;
    fLastState = status.state;
    if (status.state == VpnState::Connected) {
        fRetries = 0;
        fReconnectAt = 0;
        if (status.forwardedPort != 0 && status.forwardedPort != fLastForwardedPort)
            fListener->Notice(ClientNotice::PortForwardChanged, std::to_string(status.forwardedPort));
        fLastForwardedPort = status.forwardedPort;
    } else if (status.state == VpnState::Disconnected && !status.reconnecting) {
        fRetries = 0;
        fReconnectAt = 0;
        fLastForwardedPort = 0;
        // Back on the real network: the location may have changed.
        std::lock_guard<std::mutex> lock(fLock);
        fAccount.location.expirationTime = 0;
    } else if (status.state == VpnState::Error && entered) {
        switch (status.event) {
            case VpnEvent::ExpiredCertificate:
                fForceCertificateRefresh = true;
                fCertificateRetry = 0;
                break;
            case VpnEvent::MaximumSessionsReached:
                fListener->Notice(ClientNotice::SessionLimitReached, status.message);
                break;
            case VpnEvent::TwoFactorRequired:
                fListener->Notice(ClientNotice::TwoFactorRequired, status.message);
                break;
            case VpnEvent::NotYetValidCertificate:
                fListener->Notice(ClientNotice::UpdateSystemClock, status.message);
                break;
            case VpnEvent::AuthDenied:
                fListener->Notice(ClientNotice::VpnConnectionError, status.message);
                break;
            default:
                if (fReconnectEnabled)
                    ScheduleReconnect();
                break;
        }
    }
    fListener->ConnectionChanged(status);
    fWake.notify_all();
}


void Client::VpnLog(const std::string& line)
{
    fListener->Log(line);
}

}  // namespace pvpn
