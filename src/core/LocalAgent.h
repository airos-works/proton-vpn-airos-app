// Client for the Proton VPN "local agent", a TLS service every VPN server runs
// at 10.2.0.1:65432 inside the tunnel (local-agent-rs). The client presents
// its API certificate; the agent reports the connection state (connected or
// "hard jailed" with a reason: certificate expired, too many sessions, ...)
// and applies features (NetShield, VPN Accelerator, moderate NAT, port
// forwarding). Messages are 4-byte big-endian lengths followed by JSON with
// kebab-case keys. Port forwarding leases come from NAT-PMP at 10.2.0.1:5351.
#pragma once
#include "Json.h"
#include <string>

typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

namespace pvpn {

// Reason codes (local_agent_rs/src/reason_code.rs).
enum AgentReason {
    kReasonCertificateExpired = 86101,
    kReasonCertificateRevoked = 86102,
    kReasonKeyUsedMultipleTimes = 86103,
    kReasonMaxSessionsUnknown = 86110,
    kReasonMaxSessionsFree = 86111,
    kReasonMaxSessionsBasic = 86112,
    kReasonMaxSessionsPlus = 86113,
    kReasonMaxSessionsVisionary = 86114,
    kReasonMaxSessionsPro = 86115,
    kReason2faUnspecified = 86120,
    kReason2faExpired = 86121,
    kReason2faSituationChanged = 86122,
};

struct AgentFeatures {
    int netshield = -1;          // -1: not set
    int randomizedNat = -1;      // -1 unset, 0 false, 1 true
    int splitTcp = -1;
    int portForwarding = -1;
    int forwardedPort = 0;       // 0: none
    std::string bouncing;        // physical server label, empty: unset

    Json ToJson() const;
    static AgentFeatures FromJson(const Json& json);
};

struct AgentStatus {
    std::string state;           // "connected", "hard-jailed"
    int reasonCode = 0;
    bool reasonFinal = false;
    std::string reasonDescription;
    AgentFeatures features;
    std::string deviceIp;
    std::string deviceCountry;
    std::string serverIpv4;

    bool Connected() const { return state == "connected"; }
    bool HardJailed() const { return state == "hard-jailed"; }
    bool MaxSessions() const { return reasonCode >= 86110 && reasonCode <= 86115; }
    bool TwoFactorRequired() const { return reasonCode >= 86120 && reasonCode <= 86122; }
};

enum class AgentError {
    None,
    Timeout,
    ExpiredCertificate,
    NotYetValidCertificate,
    Connection,     // connection or TLS failure
    Protocol,       // malformed message
    Closed,
    Api,            // {"error": {...}} from the agent
};

class LocalAgent {
public:
    LocalAgent();
    ~LocalAgent();

    // domain: the physical server's domain (the agent's certificate name).
    AgentError Connect(const std::string& domain, const std::string& keyPem,
        const std::string& certificatePem, int timeoutSeconds, std::string& error);
    void Close();
    bool Connected() const { return fSsl != nullptr; }

    bool RequestStatus(std::string& error);
    bool RequestFeatures(const AgentFeatures& features, std::string& error);
    // Waits up to timeoutMs for a message. Returns None with status filled,
    // Api with apiCode/error filled, Timeout, or a failure.
    AgentError Read(int timeoutMs, AgentStatus& status, int& apiCode, std::string& error);

    // The agent's address, "10.2.0.1:65432" unless PROTON_VPN_AGENT_ADDRESS
    // says otherwise (tests).
    static std::string Address();

private:
    bool Send(const Json& message, std::string& error);

    int fSocket = -1;
    SSL_CTX* fContext = nullptr;
    SSL* fSsl = nullptr;
    std::string fBuffer;
};

// Asks the VPN gateway's NAT-PMP service for a TCP port mapping (lifetime
// 60 s; renew every minute). Returns the forwarded port or 0.
int RequestPortForwarding(std::string& error, int timeoutSeconds = 10, int retries = 2);

AgentStatus ParseAgentStatus(const Json& status);

}  // namespace pvpn
