// A small blocking HTTPS client on libcurl, with Proton's public key pinning
// (SHA-256 of the leaf certificate's SubjectPublicKeyInfo, as the GTK app's
// aiohttp transport checks).
#pragma once
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace pvpn {

struct HttpRequest {
    std::string method = "GET";
    std::string url;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    long timeoutSeconds = 30;
};

struct HttpResponse {
    long status = 0;
    std::map<std::string, std::string> headers;   // names in lower case
    std::string body;
    // Empty unless the request did not complete (no connection, TLS or pin
    // failure, timeout).
    std::string error;
    bool pinFailure = false;

    bool Completed() const { return error.empty(); }
    std::string Header(const std::string& lowerName) const;
};

struct HttpOptions {
    // base64 SHA-256 SPKI hashes; empty means no pinning.
    std::vector<std::string> pins;
    // A CA bundle; empty uses the system's (Haiku's CARootCertificates.pem).
    std::string caFile;
    bool verifyPeer = true;
};

class HttpClient {
public:
    explicit HttpClient(const HttpOptions& options = HttpOptions());
    HttpResponse Perform(const HttpRequest& request) const;

    // Call once at start-up, before any thread uses libcurl.
    static void GlobalInit();

private:
    HttpOptions fOptions;
};

// application/x-www-form-urlencoded / query escaping.
std::string UrlEscape(const std::string& text);

}  // namespace pvpn
