// The Proton API session: SRP sign-in, two-factor codes, token refresh and
// sign-out, and authenticated requests with the retry rules of
// python-proton-core's Session.async_api_request.
#pragma once
#include "Http.h"
#include "Json.h"
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace pvpn {

struct ApiEnvironment {
    std::string baseUrl = "https://vpn-api.proton.me";
    std::vector<std::string> pins;      // leaf SPKI pins; empty disables pinning
    std::string caFile;
    bool verifyPeer = true;
    // x-pm-appversion and User-Agent.
    std::string appVersion;
    std::string userAgent;
    std::string locale;                 // "en-US"; omitted when empty
    std::string timezone;               // "Australia/Hobart"; omitted when empty

    // Production values, overridable for tests with PROTON_VPN_API_URL,
    // PROTON_VPN_API_PINS ("none" or comma separated), PROTON_VPN_CA_FILE,
    // PROTON_VPN_APP_VERSION.
    static ApiEnvironment Default();
};

enum class ApiError {
    None,
    NotReachable,           // no connection, timeout, TLS or pinning failure
    Api,                    // the API answered with an error code
    AuthenticationNeeded,   // the session is gone (401 that could not be refreshed)
    TwoFactorNeeded,        // 403 while the session still needs its second factor
    MissingScope,           // other 403
    HumanVerification,      // 422 / 9001 or 12087
    BadCredentials,         // 8002 at sign-in
    Crypto,                 // modulus signature or server proof did not check out
    UnsupportedAuthVersion  // auth version below 3: sign in on the web once
};

struct ApiResult {
    ApiError error = ApiError::None;
    long httpStatus = 0;
    int64_t code = 0;           // the "Code" member of the reply
    std::string message;        // "Error" from the API, or a description
    Json json;
    std::string body;
    std::map<std::string, std::string> headers;

    bool Ok() const { return error == ApiError::None; }
    std::string Header(const std::string& lowerName) const;
};

struct SessionTokens {
    std::string uid;
    std::string accessToken;
    std::string refreshToken;
    std::vector<std::string> scopes;
    std::string accountName;
    Json twoFactor;             // the "2FA" member of the /auth reply

    bool Authenticated() const { return !uid.empty(); }
    bool NeedsTwoFactor() const;
    Json ToJson() const;
    static SessionTokens FromJson(const Json& json);
};

class ApiSession {
public:
    explicit ApiSession(const ApiEnvironment& environment);

    const ApiEnvironment& Environment() const { return fEnvironment; }

    // Called (on the requesting thread) whenever the tokens change, so they
    // can be stored.
    void SetTokensChangedHandler(std::function<void(const SessionTokens&)> handler);
    void Restore(const SessionTokens& tokens);
    SessionTokens Tokens() const;
    bool Authenticated() const;
    bool LoggedIn() const;          // authenticated and no second factor pending
    std::string AccountName() const;

    // GET when body is null, POST otherwise, unless method is given.
    ApiResult Request(const std::string& endpoint, const Json& body = Json(),
        const std::string& method = "",
        const std::vector<std::pair<std::string, std::string>>& headers = {});

    // Signs in. On success error is None; check NeedsTwoFactor afterwards.
    ApiResult Login(const std::string& username, const std::string& password);
    ApiResult ProvideTwoFactorCode(const std::string& code);
    bool NeedsTwoFactor() const;
    // Revokes the session on the API (when reachable) and forgets it.
    ApiResult Logout();
    bool Refresh();
    void ClearLocal();

    // Low-level request without retries or token refresh.
    ApiResult RawRequest(const std::string& method, const std::string& endpoint,
        const Json& body, const std::vector<std::pair<std::string, std::string>>& headers,
        bool authenticated);

private:
    void NotifyTokens();
    void SleepForRetry(const ApiResult& result);

    ApiEnvironment fEnvironment;
    HttpClient fHttp;
    mutable std::mutex fLock;
    std::mutex fRefreshLock;
    SessionTokens fTokens;
    unsigned fRevision = 0;
    std::function<void(const SessionTokens&)> fTokensChanged;
};

const char* ApiErrorName(ApiError error);

}  // namespace pvpn
