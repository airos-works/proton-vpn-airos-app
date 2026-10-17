#include "Api.h"
#include "Modulus.h"
#include "Srp.h"
#include "Util.h"
#include <chrono>
#include <cstdlib>
#include <thread>

namespace pvpn {

namespace {

// python-proton-vpn-api-core's version: the API recognises clients by
// "linux-vpn-gui@<api core version>".
const char kCoreVersion[] = "5.8.7";

const char* const kProductionPins[] = {
    "CT56BhOTmj5ZIPgb/xD5mH8rY3BLo/MlhP7oPyJUEDo=",
    "35Dx28/uzN3LeltkCBQ8RHK0tlNSa2kCpCRGNp34Gxc=",
    "qYIukVc63DEITct8sFT7ebIq5qsWmuscaIKeJx+5J5A=",
};

std::string Architecture()
{
#if defined(__x86_64__)
    return "x86_64";
#elif defined(__aarch64__)
    return "aarch64";
#elif defined(__riscv)
    return "riscv64";
#else
    return "x86";
#endif
}

std::string Env(const char* name)
{
    const char* value = getenv(name);
    return value != NULL ? value : "";
}

}  // namespace


ApiEnvironment ApiEnvironment::Default()
{
    ApiEnvironment environment;
    for (const char* pin : kProductionPins)
        environment.pins.push_back(pin);
    environment.appVersion = std::string("linux-vpn-gui@") + kCoreVersion + "+" + Architecture();
#if defined(__HAIKU__)
    environment.userAgent = std::string("ProtonVPN/") + kCoreVersion + " (Haiku; air/OS)";
#else
    environment.userAgent = std::string("ProtonVPN/") + kCoreVersion + " (Linux; test)";
#endif
    std::string url = Env("PROTON_VPN_API_URL");
    if (!url.empty()) {
        environment.baseUrl = url;
        environment.pins.clear();
    }
    std::string pins = Env("PROTON_VPN_API_PINS");
    if (pins == "none")
        environment.pins.clear();
    else if (!pins.empty())
        environment.pins = Split(pins, ',');
    environment.caFile = Env("PROTON_VPN_CA_FILE");
    if (Env("PROTON_VPN_INSECURE") == "1")
        environment.verifyPeer = false;
    std::string version = Env("PROTON_VPN_APP_VERSION");
    if (!version.empty())
        environment.appVersion = version;
    return environment;
}


std::string ApiResult::Header(const std::string& lowerName) const
{
    auto it = headers.find(lowerName);
    return it == headers.end() ? std::string() : it->second;
}


bool SessionTokens::NeedsTwoFactor() const
{
    for (const std::string& scope : scopes) {
        if (scope == "twofactor")
            return true;
    }
    return false;
}


Json SessionTokens::ToJson() const
{
    if (uid.empty())
        return Json::object();
    return Json{{"UID", uid}, {"AccessToken", accessToken}, {"RefreshToken", refreshToken},
        {"Scopes", scopes}, {"AccountName", accountName}, {"2FA", twoFactor}};
}


SessionTokens SessionTokens::FromJson(const Json& json)
{
    SessionTokens tokens;
    tokens.uid = JsonString(json, "UID");
    tokens.accessToken = JsonString(json, "AccessToken");
    tokens.refreshToken = JsonString(json, "RefreshToken");
    tokens.accountName = JsonString(json, "AccountName");
    for (const Json& scope : JsonArray(json, "Scopes")) {
        if (scope.is_string())
            tokens.scopes.push_back(scope.get<std::string>());
    }
    if (const Json* twoFactor = JsonMember(json, "2FA"))
        tokens.twoFactor = *twoFactor;
    return tokens;
}


ApiSession::ApiSession(const ApiEnvironment& environment)
    :
    fEnvironment(environment),
    fHttp(HttpOptions{environment.pins, environment.caFile, environment.verifyPeer})
{
}


void ApiSession::SetTokensChangedHandler(std::function<void(const SessionTokens&)> handler)
{
    std::lock_guard<std::mutex> lock(fLock);
    fTokensChanged = handler;
}


void ApiSession::Restore(const SessionTokens& tokens)
{
    std::lock_guard<std::mutex> lock(fLock);
    fTokens = tokens;
    fRevision++;
}


SessionTokens ApiSession::Tokens() const
{
    std::lock_guard<std::mutex> lock(fLock);
    return fTokens;
}


bool ApiSession::Authenticated() const
{
    std::lock_guard<std::mutex> lock(fLock);
    return fTokens.Authenticated();
}


bool ApiSession::LoggedIn() const
{
    std::lock_guard<std::mutex> lock(fLock);
    return fTokens.Authenticated() && !fTokens.NeedsTwoFactor();
}


bool ApiSession::NeedsTwoFactor() const
{
    std::lock_guard<std::mutex> lock(fLock);
    return fTokens.NeedsTwoFactor();
}


std::string ApiSession::AccountName() const
{
    std::lock_guard<std::mutex> lock(fLock);
    return fTokens.accountName;
}


void ApiSession::NotifyTokens()
{
    std::function<void(const SessionTokens&)> handler;
    SessionTokens tokens;
    {
        std::lock_guard<std::mutex> lock(fLock);
        handler = fTokensChanged;
        tokens = fTokens;
    }
    if (handler)
        handler(tokens);
}


void ApiSession::ClearLocal()
{
    {
        std::lock_guard<std::mutex> lock(fLock);
        std::string account = fTokens.accountName;
        fTokens = SessionTokens();
        fRevision++;
    }
    NotifyTokens();
}


ApiResult ApiSession::RawRequest(const std::string& method, const std::string& endpoint,
    const Json& body, const std::vector<std::pair<std::string, std::string>>& headers,
    bool authenticated)
{
    HttpRequest request;
    request.url = fEnvironment.baseUrl + endpoint;
    request.method = !method.empty() ? method : body.is_null() ? "GET" : "POST";
    request.headers.push_back({"x-pm-appversion", fEnvironment.appVersion});
    request.headers.push_back({"User-Agent", fEnvironment.userAgent});
    if (!fEnvironment.locale.empty())
        request.headers.push_back({"x-pm-locale", fEnvironment.locale});
    if (!fEnvironment.timezone.empty())
        request.headers.push_back({"x-pm-timezone", fEnvironment.timezone});
    if (authenticated) {
        std::lock_guard<std::mutex> lock(fLock);
        if (fTokens.Authenticated()) {
            request.headers.push_back({"x-pm-uid", fTokens.uid});
            request.headers.push_back({"Authorization", "Bearer " + fTokens.accessToken});
        }
    }
    if (!body.is_null()) {
        request.headers.push_back({"Content-Type", "application/json"});
        request.body = body.dump();
    }
    for (const auto& header : headers)
        request.headers.push_back(header);

    HttpResponse response = fHttp.Perform(request);
    ApiResult result;
    if (!response.Completed()) {
        result.error = ApiError::NotReachable;
        result.message = response.pinFailure
            ? "TLS pinning verification failed: " + response.error : response.error;
        return result;
    }
    result.httpStatus = response.status;
    result.headers = response.headers;
    result.body = response.body;
    if (response.status == 304)
        return result;
    std::string contentType = response.Header("content-type");
    if (contentType.find("json") == std::string::npos) {
        if (response.status >= 200 && response.status < 300 && !response.body.empty())
            return result;   // binary payloads (e.g. /vpn/v2/status/.../binary)
        result.error = ApiError::NotReachable;
        result.message = "API returned non-JSON results (HTTP " + std::to_string(response.status) + ")";
        return result;
    }
    result.json = ParseJson(response.body);
    if (result.json.is_discarded()) {
        result.json = Json::object();
        result.error = ApiError::Api;
        result.message = "Invalid JSON in the API reply";
        return result;
    }
    result.code = JsonInt(result.json, "Code");
    if (result.code != 1000 && result.code != 1001) {
        result.error = ApiError::Api;
        result.message = JsonString(result.json, "Error", "Unknown API error");
        if (result.httpStatus == 422 && result.code == 9001)
            result.error = ApiError::HumanVerification;
        else if (result.code == 12087)
            result.error = ApiError::HumanVerification;
    }
    return result;
}


void ApiSession::SleepForRetry(const ApiResult& result)
{
    std::string retryAfter = result.Header("retry-after");
    double seconds = 3 + RandomUnit() * 5;
    if (!retryAfter.empty() && retryAfter.find_first_not_of("0123456789") == std::string::npos)
        seconds = std::min(atof(retryAfter.c_str()), 120.0);
    std::this_thread::sleep_for(std::chrono::milliseconds((long)(seconds * 1000)));
}


ApiResult ApiSession::Request(const std::string& endpoint, const Json& body,
    const std::string& method, const std::vector<std::pair<std::string, std::string>>& headers)
{
    ApiResult result;
    for (int attempt = 0; attempt < 3; attempt++) {
        unsigned revision;
        {
            std::lock_guard<std::mutex> lock(fLock);
            revision = fRevision;
        }
        result = RawRequest(method, endpoint, body, headers, true);
        if (result.Ok() || result.error == ApiError::NotReachable
            || result.error == ApiError::HumanVerification)
            return result;
        if (result.httpStatus == 403) {
            result.error = NeedsTwoFactor() ? ApiError::TwoFactorNeeded : ApiError::MissingScope;
            return result;
        }
        if (result.httpStatus == 401) {
            bool refreshed;
            {
                std::lock_guard<std::mutex> lock(fLock);
                // Someone else refreshed while this request was under way.
                refreshed = fRevision != revision;
            }
            if (refreshed || Refresh())
                continue;
            result.error = ApiError::AuthenticationNeeded;
            return result;
        }
        if (result.httpStatus == 408 || result.httpStatus == 502)
            continue;
        if (result.httpStatus == 429 || result.httpStatus == 503) {
            if (attempt < 2)
                SleepForRetry(result);
            continue;
        }
        return result;
    }
    return result;
}


bool ApiSession::Refresh()
{
    std::lock_guard<std::mutex> refreshLock(fRefreshLock);
    std::string refreshToken;
    unsigned revision;
    {
        std::lock_guard<std::mutex> lock(fLock);
        if (!fTokens.Authenticated())
            return false;
        refreshToken = fTokens.refreshToken;
        revision = fRevision;
    }
    for (int attempt = 0; attempt < 3; attempt++) {
        {
            std::lock_guard<std::mutex> lock(fLock);
            if (fRevision != revision)
                return fTokens.Authenticated();
        }
        Json body = {{"ResponseType", "token"}, {"GrantType", "refresh_token"},
            {"RefreshToken", refreshToken}, {"RedirectURI", "http://protonmail.ch"}};
        ApiResult result = RawRequest("POST", "/auth/refresh", body, {}, true);
        if (result.Ok()) {
            {
                std::lock_guard<std::mutex> lock(fLock);
                fTokens.accessToken = JsonString(result.json, "AccessToken");
                fTokens.refreshToken = JsonString(result.json, "RefreshToken");
                fTokens.scopes.clear();
                for (const Json& scope : JsonArray(result.json, "Scopes")) {
                    if (scope.is_string())
                        fTokens.scopes.push_back(scope.get<std::string>());
                }
                fRevision++;
            }
            NotifyTokens();
            return true;
        }
        if (result.httpStatus == 409)
            continue;
        if (result.httpStatus == 429 || result.httpStatus == 503) {
            SleepForRetry(result);
            continue;
        }
        if (result.httpStatus == 400 || result.httpStatus == 422)
            ClearLocal();
        return false;
    }
    return false;
}


ApiResult ApiSession::Login(const std::string& username, const std::string& password)
{
    if (Authenticated())
        Logout();
    std::vector<std::pair<std::string, std::string>> none;
    ApiResult info = RawRequest("POST", "/auth/info", Json{{"Username", username}}, none, false);
    if (!info.Ok())
        return info;
    Bytes modulus;
    std::string error;
    if (!VerifyModulus(JsonString(info.json, "Modulus"), modulus, error)) {
        info.error = ApiError::Crypto;
        info.message = "Invalid modulus: " + error;
        return info;
    }
    int version = (int)JsonInt(info.json, "Version", -1);
    if (version != 3 && version != 4) {
        info.error = ApiError::UnsupportedAuthVersion;
        info.message = "Account auth_version is not supported. Sign in on the Proton web site "
            "once so that it can be updated.";
        return info;
    }
    SrpClient client(password, modulus);
    Bytes proof;
    if (!client.ProcessChallenge(Base64Decode(JsonString(info.json, "Salt")),
            Base64Decode(JsonString(info.json, "ServerEphemeral")), version, proof)) {
        info.error = ApiError::Crypto;
        info.message = "Invalid challenge";
        return info;
    }
    Json body = {{"Username", username}, {"ClientEphemeral", Base64Encode(client.Challenge())},
        {"ClientProof", Base64Encode(proof)}, {"SRPSession", JsonString(info.json, "SRPSession")}};
    ApiResult auth = RawRequest("POST", "/auth", body, none, false);
    if (!auth.Ok()) {
        if (auth.code == 8002)
            auth.error = ApiError::BadCredentials;
        return auth;
    }
    if (!JsonMember(auth.json, "ServerProof")) {
        auth.error = ApiError::BadCredentials;
        return auth;
    }
    if (!client.VerifyServerProof(Base64Decode(JsonString(auth.json, "ServerProof")))) {
        auth.error = ApiError::Crypto;
        auth.message = "Invalid server proof";
        return auth;
    }
    {
        std::lock_guard<std::mutex> lock(fLock);
        fTokens = SessionTokens::FromJson(auth.json);
        fTokens.accountName = username;
        if (const Json* twoFactor = JsonMember(auth.json, "2FA"))
            fTokens.twoFactor = *twoFactor;
        fRevision++;
    }
    NotifyTokens();
    return auth;
}


ApiResult ApiSession::ProvideTwoFactorCode(const std::string& code)
{
    ApiResult result = RawRequest("POST", "/auth/2fa", Json{{"TwoFactorCode", code}}, {}, true);
    if (result.Ok()) {
        {
            std::lock_guard<std::mutex> lock(fLock);
            fTokens.scopes.clear();
            for (const Json& scope : JsonArray(result.json, "Scopes")) {
                if (scope.is_string())
                    fTokens.scopes.push_back(scope.get<std::string>());
            }
            fTokens.twoFactor = Json();
            fRevision++;
        }
        NotifyTokens();
        return result;
    }
    if (result.code == 8002) {
        // Too many attempts: the API dropped the session, sign in again.
        ClearLocal();
        result.error = ApiError::AuthenticationNeeded;
    } else if (result.httpStatus == 401 || result.httpStatus == 422) {
        result.error = ApiError::BadCredentials;
    }
    return result;
}


ApiResult ApiSession::Logout()
{
    ApiResult result;
    if (!Authenticated()) {
        ClearLocal();
        return result;
    }
    result = RawRequest("DELETE", "/auth", Json(), {}, true);
    if (result.Ok() || result.httpStatus == 401) {
        result.error = ApiError::None;
        ClearLocal();
    }
    return result;
}


const char* ApiErrorName(ApiError error)
{
    switch (error) {
        case ApiError::None: return "none";
        case ApiError::NotReachable: return "not reachable";
        case ApiError::Api: return "API error";
        case ApiError::AuthenticationNeeded: return "authentication needed";
        case ApiError::TwoFactorNeeded: return "two-factor authentication needed";
        case ApiError::MissingScope: return "missing scope";
        case ApiError::HumanVerification: return "human verification needed";
        case ApiError::BadCredentials: return "incorrect credentials";
        case ApiError::Crypto: return "cryptographic check failed";
        case ApiError::UnsupportedAuthVersion: return "unsupported auth version";
    }
    return "unknown";
}

}  // namespace pvpn
