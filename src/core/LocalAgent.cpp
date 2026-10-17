#include "LocalAgent.h"
#include "Crypto.h"
#include "ProtonCa.h"
#include "Util.h"
#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace pvpn {

namespace {

const char kDefaultAddress[] = "10.2.0.1:65432";
const char kNatPmpAddress[] = "10.2.0.1";
const int kNatPmpPort = 5351;

bool SplitAddress(const std::string& text, sockaddr_in& address)
{
    size_t colon = text.rfind(':');
    if (colon == std::string::npos)
        return false;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(atoi(text.c_str() + colon + 1));
    return inet_pton(AF_INET, text.substr(0, colon).c_str(), &address.sin_addr) == 1;
}

std::string SslError()
{
    unsigned long code = ERR_get_error();
    if (code == 0)
        return "TLS error";
    char text[256];
    ERR_error_string_n(code, text, sizeof(text));
    return text;
}

bool WaitFor(int fd, short events, int timeoutMs)
{
    pollfd item = {fd, events, 0};
    int ready;
    do {
        ready = poll(&item, 1, timeoutMs);
    } while (ready < 0 && errno == EINTR);
    return ready > 0;
}

int OptionalBool(const Json& json, const char* key)
{
    const Json* value = JsonMember(json, key);
    if (value == nullptr || !value->is_boolean())
        return -1;
    return value->get<bool>() ? 1 : 0;
}

}  // namespace


Json AgentFeatures::ToJson() const
{
    Json json = Json::object();
    if (netshield >= 0)
        json["netshield-level"] = netshield;
    if (randomizedNat >= 0)
        json["randomized-nat"] = randomizedNat == 1;
    if (splitTcp >= 0)
        json["split-tcp"] = splitTcp == 1;
    if (portForwarding >= 0)
        json["port-forwarding"] = portForwarding == 1;
    if (forwardedPort > 0)
        json["forwarded-port"] = forwardedPort;
    if (!bouncing.empty())
        json["bouncing"] = bouncing;
    return json;
}


AgentFeatures AgentFeatures::FromJson(const Json& json)
{
    AgentFeatures features;
    features.netshield = (int)JsonInt(json, "netshield-level", -1);
    features.randomizedNat = OptionalBool(json, "randomized-nat");
    features.splitTcp = OptionalBool(json, "split-tcp");
    features.portForwarding = OptionalBool(json, "port-forwarding");
    features.forwardedPort = (int)JsonInt(json, "forwarded-port", 0);
    features.bouncing = JsonString(json, "bouncing");
    return features;
}


AgentStatus ParseAgentStatus(const Json& json)
{
    AgentStatus status;
    status.state = JsonString(json, "state");
    const Json& reason = JsonObject(json, "reason");
    status.reasonCode = (int)JsonInt(reason, "code");
    status.reasonFinal = JsonBool(reason, "final");
    status.reasonDescription = JsonString(reason, "description");
    status.features = AgentFeatures::FromJson(JsonObject(json, "features"));
    const Json& details = JsonObject(json, "connection-details");
    status.deviceIp = JsonString(details, "device-ip");
    status.deviceCountry = JsonString(details, "device-country");
    status.serverIpv4 = JsonString(details, "server-ipv4");
    return status;
}


std::string LocalAgent::Address()
{
    const char* value = getenv("PROTON_VPN_AGENT_ADDRESS");
    return value != NULL && *value != '\0' ? value : kDefaultAddress;
}


LocalAgent::LocalAgent()
{
}


LocalAgent::~LocalAgent()
{
    Close();
}


void LocalAgent::Close()
{
    if (fSsl != nullptr) {
        SSL_shutdown(fSsl);
        SSL_free(fSsl);
        fSsl = nullptr;
    }
    if (fContext != nullptr) {
        SSL_CTX_free(fContext);
        fContext = nullptr;
    }
    if (fSocket >= 0) {
        close(fSocket);
        fSocket = -1;
    }
    fBuffer.clear();
}


AgentError LocalAgent::Connect(const std::string& domain, const std::string& keyPem,
    const std::string& certificatePem, int timeoutSeconds, std::string& error)
{
    Close();
    // As local-agent-rs, refuse certificates outside their validity first.
    CertificateInfo info;
    if (!ParseCertificatePem(certificatePem, info)) {
        error = "the VPN certificate cannot be read";
        return AgentError::Connection;
    }
    time_t now = time(NULL);
    if (now < info.notBefore) {
        error = "the VPN certificate is not valid yet";
        return AgentError::NotYetValidCertificate;
    }
    if (now > info.notAfter) {
        error = "the VPN certificate has expired";
        return AgentError::ExpiredCertificate;
    }

    sockaddr_in address;
    if (!SplitAddress(Address(), address)) {
        error = "bad local agent address " + Address();
        return AgentError::Connection;
    }
    fSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (fSocket < 0) {
        error = strerror(errno);
        return AgentError::Connection;
    }
    fcntl(fSocket, F_SETFD, FD_CLOEXEC);
    int flags = fcntl(fSocket, F_GETFL);
    fcntl(fSocket, F_SETFL, flags | O_NONBLOCK);
    int on = 1;
    setsockopt(fSocket, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
    if (connect(fSocket, (sockaddr*)&address, sizeof(address)) != 0) {
        if (errno != EINPROGRESS) {
            error = std::string("cannot reach the local agent: ") + strerror(errno);
            Close();
            return AgentError::Connection;
        }
        if (!WaitFor(fSocket, POLLOUT, timeoutSeconds * 1000)) {
            error = "timed out reaching the local agent";
            Close();
            return AgentError::Timeout;
        }
        int result = 0;
        socklen_t length = sizeof(result);
        getsockopt(fSocket, SOL_SOCKET, SO_ERROR, &result, &length);
        if (result != 0) {
            error = std::string("cannot reach the local agent: ") + strerror(result);
            Close();
            return AgentError::Connection;
        }
    }
    fcntl(fSocket, F_SETFL, flags & ~O_NONBLOCK);

    fContext = SSL_CTX_new(TLS_client_method());
    if (fContext == nullptr) {
        error = SslError();
        Close();
        return AgentError::Connection;
    }
    SSL_CTX_set_min_proto_version(fContext, TLS1_2_VERSION);
    X509_STORE* store = SSL_CTX_get_cert_store(fContext);
    std::string ca = LocalAgentCaPem();
    BIO* bio = BIO_new_mem_buf(ca.data(), (int)ca.size());
    X509* certificate;
    while ((certificate = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        X509_STORE_add_cert(store, certificate);
        X509_free(certificate);
    }
    BIO_free(bio);
    ERR_clear_error();
    SSL_CTX_set_verify(fContext, SSL_VERIFY_PEER, NULL);

    bio = BIO_new_mem_buf(certificatePem.data(), (int)certificatePem.size());
    certificate = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    bio = BIO_new_mem_buf(keyPem.data(), (int)keyPem.size());
    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    bool loaded = certificate != NULL && key != NULL
        && SSL_CTX_use_certificate(fContext, certificate) == 1
        && SSL_CTX_use_PrivateKey(fContext, key) == 1;
    X509_free(certificate);
    EVP_PKEY_free(key);
    if (!loaded) {
        error = "cannot load the VPN certificate: " + SslError();
        Close();
        return AgentError::Connection;
    }

    fSsl = SSL_new(fContext);
    SSL_set_fd(fSsl, fSocket);
    SSL_set_tlsext_host_name(fSsl, domain.c_str());
    SSL_set1_host(fSsl, domain.c_str());
    // A bounded handshake: TLS over a non-blocking socket would need a loop,
    // so use the socket's receive timeout instead.
    timeval timeout = {timeoutSeconds, 0};
    setsockopt(fSocket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fSocket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    if (SSL_connect(fSsl) != 1) {
        long verify = SSL_get_verify_result(fSsl);
        error = "TLS with the local agent failed: "
            + (verify != X509_V_OK ? std::string(X509_verify_cert_error_string(verify)) : SslError());
        bool timedOut = errno == EAGAIN || errno == EWOULDBLOCK;
        Close();
        return timedOut ? AgentError::Timeout : AgentError::Connection;
    }
    timeval none = {0, 0};
    setsockopt(fSocket, SOL_SOCKET, SO_RCVTIMEO, &none, sizeof(none));
    return AgentError::None;
}


bool LocalAgent::Send(const Json& message, std::string& error)
{
    if (fSsl == nullptr) {
        error = "not connected to the local agent";
        return false;
    }
    std::string payload = message.dump();
    std::string frame(4, '\0');
    uint32_t size = payload.size();
    frame[0] = size >> 24;
    frame[1] = size >> 16;
    frame[2] = size >> 8;
    frame[3] = size;
    frame += payload;
    if (SSL_write(fSsl, frame.data(), (int)frame.size()) != (int)frame.size()) {
        error = "writing to the local agent failed: " + SslError();
        return false;
    }
    return true;
}


bool LocalAgent::RequestStatus(std::string& error)
{
    return Send(Json{{"status-get", Json::object()}}, error);
}


bool LocalAgent::RequestFeatures(const AgentFeatures& features, std::string& error)
{
    return Send(Json{{"features-set", features.ToJson()}}, error);
}


AgentError LocalAgent::Read(int timeoutMs, AgentStatus& status, int& apiCode, std::string& error)
{
    if (fSsl == nullptr) {
        error = "not connected to the local agent";
        return AgentError::Closed;
    }
    double deadline = MonotonicNow() + timeoutMs / 1000.0;
    while (true) {
        if (fBuffer.size() >= 4) {
            uint32_t size = (uint8_t)fBuffer[0] << 24 | (uint8_t)fBuffer[1] << 16
                | (uint8_t)fBuffer[2] << 8 | (uint8_t)fBuffer[3];
            if (size > (1 << 20)) {
                error = "oversized message from the local agent";
                return AgentError::Protocol;
            }
            if (fBuffer.size() >= 4 + size) {
                Json message = ParseJson(fBuffer.substr(4, size));
                fBuffer.erase(0, 4 + size);
                if (message.is_discarded() || !message.is_object()) {
                    error = "malformed message from the local agent";
                    return AgentError::Protocol;
                }
                if (const Json* problem = JsonMember(message, "error")) {
                    apiCode = (int)JsonInt(*problem, "code");
                    error = JsonString(*problem, "description");
                    return AgentError::Api;
                }
                if (const Json* value = JsonMember(message, "status")) {
                    status = ParseAgentStatus(*value);
                    return AgentError::None;
                }
                error = "the local agent returned no status";
                return AgentError::Protocol;
            }
        }
        if (SSL_pending(fSsl) == 0) {
            int remaining = (int)((deadline - MonotonicNow()) * 1000);
            if (remaining <= 0)
                return AgentError::Timeout;
            if (!WaitFor(fSocket, POLLIN, remaining))
                return AgentError::Timeout;
        }
        char chunk[4096];
        int got = SSL_read(fSsl, chunk, sizeof(chunk));
        if (got <= 0) {
            int code = SSL_get_error(fSsl, got);
            if (code == SSL_ERROR_WANT_READ || code == SSL_ERROR_WANT_WRITE)
                continue;
            error = code == SSL_ERROR_ZERO_RETURN ? "the local agent closed the connection"
                : "reading from the local agent failed: " + SslError();
            return AgentError::Closed;
        }
        fBuffer.append(chunk, got);
    }
}


int RequestPortForwarding(std::string& error, int timeoutSeconds, int retries)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        error = strerror(errno);
        return 0;
    }
    sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(kNatPmpPort);
    const char* override = getenv("PROTON_VPN_NATPMP_ADDRESS");
    inet_pton(AF_INET, override != NULL && *override ? override : kNatPmpAddress, &address.sin_addr);
    if (connect(fd, (sockaddr*)&address, sizeof(address)) != 0) {
        error = std::string("cannot reach the NAT-PMP gateway: ") + strerror(errno);
        close(fd);
        return 0;
    }
    // version 0, opcode 2 (TCP), reserved, internal port 0, external port 0,
    // lifetime 60 s; all big-endian.
    uint8_t request[12] = {0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 60};
    int timeoutMs = timeoutSeconds * 1000;
    for (int attempt = 0; attempt <= retries; attempt++) {
        if (send(fd, request, sizeof(request), 0) != (ssize_t)sizeof(request)) {
            error = std::string("NAT-PMP send failed: ") + strerror(errno);
            break;
        }
        if (!WaitFor(fd, POLLIN, timeoutMs)) {
            timeoutMs *= 2;
            continue;
        }
        uint8_t response[16];
        ssize_t got = recv(fd, response, sizeof(response), 0);
        if (got != 16) {
            error = "malformed NAT-PMP response";
            break;
        }
        int result = response[2] << 8 | response[3];
        if (result != 0 || response[1] != 130) {
            error = "NAT-PMP refused the mapping (" + std::to_string(result) + ")";
            break;
        }
        close(fd);
        return response[8] << 8 | response[9];   // the internal port, as local-agent-rs
    }
    if (error.empty())
        error = "no answer from the NAT-PMP gateway";
    close(fd);
    return 0;
}

}  // namespace pvpn
