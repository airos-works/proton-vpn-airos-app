#include "Http.h"
#include "Util.h"
#include <cctype>
#include <curl/curl.h>
#include <unistd.h>

namespace pvpn {

namespace {

size_t WriteBody(char* data, size_t size, size_t count, void* user)
{
    static_cast<std::string*>(user)->append(data, size * count);
    return size * count;
}

size_t WriteHeader(char* data, size_t size, size_t count, void* user)
{
    std::string line(data, size * count);
    size_t colon = line.find(':');
    auto* headers = static_cast<std::map<std::string, std::string>*>(user);
    if (StartsWith(line, "HTTP/")) {
        headers->clear();   // a new response after a redirect or 100-continue
    } else if (colon != std::string::npos) {
        (*headers)[ToLower(Trim(line.substr(0, colon)))] = Trim(line.substr(colon + 1));
    }
    return size * count;
}

const char* SystemCaFile()
{
    static const char* const kCandidates[] = {
        "/boot/system/data/ssl/CARootCertificates.pem",
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
    };
    for (const char* path : kCandidates) {
        if (access(path, R_OK) == 0)
            return path;
    }
    return NULL;
}

}  // namespace


std::string HttpResponse::Header(const std::string& lowerName) const
{
    auto it = headers.find(lowerName);
    return it == headers.end() ? std::string() : it->second;
}


HttpClient::HttpClient(const HttpOptions& options)
    :
    fOptions(options)
{
}


void HttpClient::GlobalInit()
{
    curl_global_init(CURL_GLOBAL_DEFAULT);
}


HttpResponse HttpClient::Perform(const HttpRequest& request) const
{
    HttpResponse response;
    CURL* curl = curl_easy_init();
    if (curl == NULL) {
        response.error = "Could not create an HTTP request.";
        return response;
    }
    char errorBuffer[CURL_ERROR_SIZE] = "";
    curl_easy_setopt(curl, CURLOPT_URL, request.url.c_str());
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorBuffer);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, request.timeoutSeconds);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, std::min(request.timeoutSeconds, 15L));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteBody);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response.body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteHeader);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response.headers);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https,http");
    if (!fOptions.caFile.empty())
        curl_easy_setopt(curl, CURLOPT_CAINFO, fOptions.caFile.c_str());
    else if (const char* ca = SystemCaFile())
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, fOptions.verifyPeer ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, fOptions.verifyPeer ? 2L : 0L);
    std::string pins;
    for (const std::string& pin : fOptions.pins)
        pins += (pins.empty() ? "" : ";") + std::string("sha256//") + pin;
    if (!pins.empty())
        curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, pins.c_str());

    std::string method = ToUpper(request.method);
    if (method == "POST") {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
    } else if (method != "GET") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());
    }
    if (method != "GET") {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)request.body.size());
    }
    struct curl_slist* headers = NULL;
    for (const auto& header : request.headers)
        headers = curl_slist_append(headers, (header.first + ": " + header.second).c_str());
    // libcurl would otherwise add "Expect: 100-continue" to larger bodies.
    headers = curl_slist_append(headers, "Expect:");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode result = curl_easy_perform(curl);
    if (result == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status);
    } else {
        response.pinFailure = result == CURLE_SSL_PINNEDPUBKEYNOTMATCH;
        response.error = errorBuffer[0] != '\0' ? errorBuffer : curl_easy_strerror(result);
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return response;
}


std::string UrlEscape(const std::string& text)
{
    static const char kHex[] = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : text) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out += (char)c;
        } else {
            out += '%';
            out += kHex[c >> 4];
            out += kHex[c & 15];
        }
    }
    return out;
}

}  // namespace pvpn
